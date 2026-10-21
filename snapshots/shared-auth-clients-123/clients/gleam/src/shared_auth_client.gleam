//// Thin, typed Gleam client for the shared-auth HTTP API.
////
//// Guard orchestration, the dual-auth race, and limited HTML remain in
//// shared-auth-lib. This module implements transport verbs only.

import gleam/bool
import gleam/dynamic/decode
import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/httpc
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/uri
import shared_auth_client/model.{
  type Capabilities, type CeremonyStart, type ChallengeKind, type ChallengeStart,
  type ExchangeResponse, type Factor, type Introspection, type Jwks,
  type PasswordlessAccepted, type SessionResponse, type StepUpResponse,
  type TotpEnrollment,
}

pub type ClientError {
  Unauthorized
  MissingServiceCredential
  InvalidRequest
  UnexpectedStatus(status: Int)
  InvalidUrl
  InvalidTimeout
  InvalidResponse(error: json.DecodeError)
  TransportError(error: httpc.HttpError)
}

/// Injectable transport used for deterministic tests and alternate runtimes.
pub type Transport =
  fn(Request(String), Int) -> Result(Response(String), httpc.HttpError)

pub opaque type Client {
  Client(
    base: String,
    service_credential: Option(String),
    timeout_ms: Int,
    transport: Transport,
  )
}

/// Construct a client with TLS verification, redirects disabled, and a
/// ten-second response deadline.
/// Loopback, private/link-local IPs, and in-cluster names — hosts a bearer
/// token may reach over cleartext because the traffic never leaves the trust
/// boundary.
fn internal_host_allowed(host: String) -> Bool {
  let host = string.lowercase(host)
  let octets = string.split(host, ".") |> list.map(int.parse)
  let private_v4 = case octets {
    [Ok(a), Ok(b), Ok(_), Ok(_)] ->
      a == 127
      || a == 10
      || { a == 172 && b >= 16 && b <= 31 }
      || { a == 192 && b == 168 }
      || { a == 169 && b == 254 }
    _ -> False
  }
  host == ""
  || host == "localhost"
  || string.ends_with(host, ".localhost")
  || host == "::1"
  || string.starts_with(host, "fc")
  || string.starts_with(host, "fd")
  || string.starts_with(host, "fe8")
  || private_v4
  || !string.contains(host, ".")
  || string.ends_with(host, ".svc.cluster.local")
  || string.ends_with(host, ".internal")
}

/// True when `base` may carry a bearer token as configured.
fn transport_is_acceptable(base: String) -> Bool {
  case uri.parse(base) {
    Ok(parsed) ->
      case parsed.scheme, parsed.host {
        Some("http"), Some(host) -> internal_host_allowed(host)
        _, _ -> True
      }
    Error(_) -> True
  }
}

pub fn new(base: String) -> Result(Client, ClientError) {
  let base = normalize_base(base)
  use <- bool.guard(
    when: !transport_is_acceptable(base),
    return: Error(InvalidUrl),
  )
  case request.to(base <> "/healthz") {
    Ok(_) ->
      Ok(Client(
        base: base,
        service_credential: None,
        timeout_ms: 10_000,
        transport: default_transport,
      ))
    Error(_) -> Error(InvalidUrl)
  }
}

/// Attach the service bearer used only by protected introspection.
pub fn with_service_credential(client: Client, credential: String) -> Client {
  Client(
    ..client,
    service_credential: credential |> string.trim |> string.to_option,
  )
}

pub fn without_service_credential(client: Client) -> Client {
  Client(..client, service_credential: None)
}

pub fn with_timeout(
  client: Client,
  timeout_ms: Int,
) -> Result(Client, ClientError) {
  case timeout_ms > 0 {
    True -> Ok(Client(..client, timeout_ms: timeout_ms))
    False -> Error(InvalidTimeout)
  }
}

pub fn with_transport(client: Client, transport: Transport) -> Client {
  Client(..client, transport: transport)
}

pub fn has_assurance(value: Introspection, required_acr: String) -> Bool {
  model.has_assurance(value, required_acr)
}

pub fn used_method(value: Introspection, method: String) -> Bool {
  model.used_method(value, method)
}

pub fn has_role(value: Introspection, role: String) -> Bool {
  model.has_role(value, role)
}

/// Supabase access token to shared-auth access token.
pub fn exchange(
  client: Client,
  supabase_token: String,
) -> Result(ExchangeResponse, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/exchange",
    Some(supabase_token),
    None,
    model.exchange_response_decoder(),
  )
}

pub fn register(
  client: Client,
  email: String,
  password: String,
  display_name: Option(String),
) -> Result(SessionResponse, ClientError) {
  use <- bool.guard(
    when: !valid_email(email)
      || !valid_registration_password(password)
      || !valid_display_name(display_name),
    return: Error(InvalidRequest),
  )
  let fields =
    [
      #("email", json.string(email)),
      #("password", json.string(password)),
    ]
    |> list.append(optional_string_field("display_name", display_name))
  request_json(
    client,
    http.Post,
    "/auth/register",
    None,
    Some(json.object(fields)),
    model.session_response_decoder(),
  )
}

pub fn login(
  client: Client,
  email: String,
  password: String,
) -> Result(SessionResponse, ClientError) {
  use <- bool.guard(
    when: !valid_email(email) || !valid_login_password(password),
    return: Error(InvalidRequest),
  )
  request_json(
    client,
    http.Post,
    "/auth/login",
    None,
    Some(json.object([
      #("email", json.string(email)),
      #("password", json.string(password)),
    ])),
    model.session_response_decoder(),
  )
}

pub fn request_passwordless(
  client: Client,
  email: String,
) -> Result(PasswordlessAccepted, ClientError) {
  use <- bool.guard(when: !valid_email(email), return: Error(InvalidRequest))
  request_json(
    client,
    http.Post,
    "/auth/passwordless/request",
    None,
    Some(json.object([#("email", json.string(email))])),
    model.passwordless_accepted_decoder(),
  )
}

pub fn consume_passwordless(
  client: Client,
  email: String,
  otp: String,
) -> Result(SessionResponse, ClientError) {
  use <- bool.guard(
    when: !valid_email(email) || !valid_email_otp(otp),
    return: Error(InvalidRequest),
  )
  request_json(
    client,
    http.Post,
    "/auth/passwordless/consume",
    None,
    Some(json.object([
      #("email", json.string(email)),
      #("otp", json.string(otp)),
    ])),
    model.session_response_decoder(),
  )
}

pub fn refresh(
  client: Client,
  refresh_token: String,
) -> Result(SessionResponse, ClientError) {
  use <- bool.guard(
    when: !valid_credential(refresh_token),
    return: Error(InvalidRequest),
  )
  request_json(
    client,
    http.Post,
    "/auth/refresh",
    None,
    Some(json.object([#("refresh_token", json.string(refresh_token))])),
    model.session_response_decoder(),
  )
}

pub fn logout(client: Client, refresh_token: String) -> Result(Nil, ClientError) {
  use <- bool.guard(
    when: !valid_credential(refresh_token),
    return: Error(InvalidRequest),
  )
  request_empty(
    client,
    http.Post,
    "/auth/logout",
    None,
    Some(json.object([#("refresh_token", json.string(refresh_token))])),
  )
}

/// RFC-7662-shaped protected introspection.
pub fn introspect(
  client: Client,
  token: String,
) -> Result(Introspection, ClientError) {
  introspect_with_requirements(client, token, "oresoftware", [])
}

/// Protected introspection with an exact audience and required scope set.
/// Service authentication is selected before the user-token body is built.
pub fn introspect_with_requirements(
  client: Client,
  token: String,
  audience: String,
  required_scopes: List(String),
) -> Result(Introspection, ClientError) {
  case client.service_credential {
    None -> Error(MissingServiceCredential)
    Some(service_credential) -> {
      use <- bool.guard(
        when: !valid_introspection_token(token)
          || !valid_introspection_value(audience)
          || !valid_required_scopes(required_scopes),
        return: Error(InvalidRequest),
      )
      request_json(
        client,
        http.Post,
        "/auth/introspect",
        Some(service_credential),
        Some(
          json.object([
            #("contract", json.string("IntrospectionRequest")),
            #(
              "payload",
              json.object([
                #("token", json.string(token)),
                #("audience", json.string(audience)),
                #("requiredScopes", json.array(required_scopes, json.string)),
              ]),
            ),
          ]),
        ),
        model.introspection_decoder(),
      )
    }
  }
}

/// Lightweight bearer verification for gateway auth_request integrations.
pub fn verify(client: Client, token: String) -> Result(Bool, ClientError) {
  use req <- result.try(build_request(
    client,
    http.Get,
    "/auth/verify",
    Some(token),
    None,
  ))
  use response <- result.try(send(client, req))
  case response.status {
    200 -> Ok(True)
    401 -> Ok(False)
    status -> Error(UnexpectedStatus(status))
  }
}

pub fn jwks(client: Client) -> Result(Jwks, ClientError) {
  request_json(
    client,
    http.Get,
    "/.well-known/jwks.json",
    None,
    None,
    model.jwks_decoder(),
  )
}

pub fn oauth_discovery(client: Client) -> Result(Nil, ClientError) {
  request_json(
    client,
    http.Get,
    "/.well-known/openid-configuration",
    None,
    None,
    decode.success(Nil),
  )
}

pub fn authorize_decision(
  client: Client,
  access_token: String,
  resource: String,
  action: String,
) -> Result(Nil, ClientError) {
  request_json(
    client,
    http.Post,
    "/authz/decide",
    Some(access_token),
    Some(json.object([
      #("resource", json.string(resource)),
      #("action", json.string(action)),
    ])),
    decode.success(Nil),
  )
}

pub fn saml_metadata(client: Client) -> Result(Nil, ClientError) {
  request_json(client, http.Get, "/saml/metadata", None, None, decode.success(Nil))
}

pub fn saml_sso(client: Client, idp_entity_id: String) -> Result(Nil, ClientError) {
  request_json(
    client,
    http.Get,
    "/saml/sso?idp_entity_id=" <> idp_entity_id,
    None,
    None,
    decode.success(Nil),
  )
}

pub fn saml_acs(client: Client, saml_response: String) -> Result(Nil, ClientError) {
  request_json(
    client,
    http.Post,
    "/saml/acs",
    None,
    Some(json.object([#("SAMLResponse", json.string(saml_response))])),
    decode.success(Nil),
  )
}

pub fn scim_service_provider_config(client: Client) -> Result(Nil, ClientError) {
  request_json(
    client,
    http.Get,
    "/scim/v2/ServiceProviderConfig",
    None,
    None,
    decode.success(Nil),
  )
}

pub fn scim_list_users(client: Client, access_token: String) -> Result(Nil, ClientError) {
  request_json(client, http.Get, "/scim/v2/Users", Some(access_token), None, decode.success(Nil))
}

pub fn scim_create_user(client: Client, access_token: String) -> Result(Nil, ClientError) {
  request_json(client, http.Post, "/scim/v2/Users", Some(access_token), Some(json.object([])), decode.success(Nil))
}

pub fn scim_get_user(client: Client, access_token: String, id: String) -> Result(Nil, ClientError) {
  request_json(client, http.Get, "/scim/v2/Users/" <> id, Some(access_token), None, decode.success(Nil))
}

pub fn scim_replace_user(client: Client, access_token: String, id: String) -> Result(Nil, ClientError) {
  request_json(client, http.Put, "/scim/v2/Users/" <> id, Some(access_token), Some(json.object([])), decode.success(Nil))
}

pub fn scim_patch_user(client: Client, access_token: String, id: String) -> Result(Nil, ClientError) {
  request_json(client, http.Patch, "/scim/v2/Users/" <> id, Some(access_token), Some(json.object([])), decode.success(Nil))
}

pub fn scim_delete_user(client: Client, access_token: String, id: String) -> Result(Nil, ClientError) {
  request_empty(client, http.Delete, "/scim/v2/Users/" <> id, Some(access_token), None)
}

pub fn scim_list_groups(client: Client, access_token: String) -> Result(Nil, ClientError) {
  request_json(client, http.Get, "/scim/v2/Groups", Some(access_token), None, decode.success(Nil))
}

pub fn scim_create_group(client: Client, access_token: String) -> Result(Nil, ClientError) {
  request_json(client, http.Post, "/scim/v2/Groups", Some(access_token), Some(json.object([])), decode.success(Nil))
}

pub fn scim_get_group(client: Client, access_token: String, id: String) -> Result(Nil, ClientError) {
  request_json(client, http.Get, "/scim/v2/Groups/" <> id, Some(access_token), None, decode.success(Nil))
}

pub fn scim_replace_group(client: Client, access_token: String, id: String) -> Result(Nil, ClientError) {
  request_json(client, http.Put, "/scim/v2/Groups/" <> id, Some(access_token), Some(json.object([])), decode.success(Nil))
}

pub fn scim_patch_group(client: Client, access_token: String, id: String) -> Result(Nil, ClientError) {
  request_json(client, http.Patch, "/scim/v2/Groups/" <> id, Some(access_token), Some(json.object([])), decode.success(Nil))
}

pub fn scim_delete_group(client: Client, access_token: String, id: String) -> Result(Nil, ClientError) {
  request_empty(client, http.Delete, "/scim/v2/Groups/" <> id, Some(access_token), None)
}

pub fn capabilities(client: Client) -> Result(Capabilities, ClientError) {
  request_json(
    client,
    http.Get,
    "/auth/capabilities",
    None,
    None,
    model.capabilities_decoder(),
  )
}

pub fn factors(
  client: Client,
  access_token: String,
) -> Result(List(Factor), ClientError) {
  request_json(
    client,
    http.Get,
    "/auth/factors",
    Some(access_token),
    None,
    decode.list(model.factor_decoder()),
  )
}

pub fn enroll_totp(
  client: Client,
  access_token: String,
  label: Option(String),
) -> Result(TotpEnrollment, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/factors/totp/enroll",
    Some(access_token),
    Some(json.object(optional_string_field("label", label))),
    model.totp_enrollment_decoder(),
  )
}

pub fn confirm_totp(
  client: Client,
  access_token: String,
  factor_id: String,
  code: String,
) -> Result(StepUpResponse, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/factors/totp/confirm",
    Some(access_token),
    Some(
      json.object([
        #("factor_id", json.string(factor_id)),
        #("code", json.string(code)),
      ]),
    ),
    model.step_up_response_decoder(),
  )
}

pub fn delete_factor(
  client: Client,
  access_token: String,
  factor_id: String,
) -> Result(Nil, ClientError) {
  let path = "/auth/factors/" <> uri.percent_encode(factor_id)
  request_empty(client, http.Delete, path, Some(access_token), None)
}

pub fn create_challenge(
  client: Client,
  access_token: String,
  kind: ChallengeKind,
) -> Result(ChallengeStart, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/challenges",
    Some(access_token),
    Some(
      json.object([
        #("kind", kind |> model.challenge_kind_to_string |> json.string),
      ]),
    ),
    model.challenge_start_decoder(),
  )
}

pub fn verify_challenge(
  client: Client,
  access_token: String,
  challenge_id: String,
  code: String,
) -> Result(StepUpResponse, ClientError) {
  let path =
    "/auth/challenges/" <> uri.percent_encode(challenge_id) <> "/verify"
  request_json(
    client,
    http.Post,
    path,
    Some(access_token),
    Some(json.object([#("code", json.string(code))])),
    model.step_up_response_decoder(),
  )
}

pub fn start_passkey_registration(
  client: Client,
  access_token: String,
  label: Option(String),
) -> Result(CeremonyStart, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/passkeys/registration/options",
    Some(access_token),
    Some(json.object(optional_string_field("label", label))),
    model.ceremony_start_decoder(),
  )
}

pub fn finish_passkey_registration(
  client: Client,
  access_token: String,
  challenge_id: String,
  credential: json.Json,
  label: Option(String),
) -> Result(Factor, ClientError) {
  let fields =
    [
      #("challenge_id", json.string(challenge_id)),
      #("credential", credential),
    ]
    |> list.append(optional_string_field("label", label))

  request_json(
    client,
    http.Post,
    "/auth/passkeys/registration/verify",
    Some(access_token),
    Some(json.object(fields)),
    model.factor_decoder(),
  )
}

pub fn start_passkey_authentication(
  client: Client,
  access_token: String,
) -> Result(CeremonyStart, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/passkeys/authentication/options",
    Some(access_token),
    Some(json.object([])),
    model.ceremony_start_decoder(),
  )
}

pub fn finish_passkey_authentication(
  client: Client,
  access_token: String,
  challenge_id: String,
  credential: json.Json,
) -> Result(StepUpResponse, ClientError) {
  request_json(
    client,
    http.Post,
    "/auth/passkeys/authentication/verify",
    Some(access_token),
    Some(
      json.object([
        #("challenge_id", json.string(challenge_id)),
        #("credential", credential),
      ]),
    ),
    model.step_up_response_decoder(),
  )
}

fn default_transport(
  req: Request(String),
  timeout_ms: Int,
) -> Result(Response(String), httpc.HttpError) {
  httpc.configure()
  |> httpc.timeout(timeout_ms)
  |> httpc.follow_redirects(False)
  |> httpc.dispatch(req)
}

fn request_json(
  client: Client,
  method: http.Method,
  path: String,
  bearer: Option(String),
  body: Option(json.Json),
  decoder: decode.Decoder(value),
) -> Result(value, ClientError) {
  use req <- result.try(build_request(client, method, path, bearer, body))
  use response <- result.try(send(client, req))
  decode_json_response(response, decoder)
}

fn request_empty(
  client: Client,
  method: http.Method,
  path: String,
  bearer: Option(String),
  body: Option(json.Json),
) -> Result(Nil, ClientError) {
  use req <- result.try(build_request(client, method, path, bearer, body))
  use response <- result.try(send(client, req))
  case response.status {
    401 -> Error(Unauthorized)
    status ->
      case is_success(status) {
        True -> Ok(Nil)
        False -> Error(UnexpectedStatus(status))
      }
  }
}

fn build_request(
  client: Client,
  method: http.Method,
  path: String,
  bearer: Option(String),
  body: Option(json.Json),
) -> Result(Request(String), ClientError) {
  case request.to(client.base <> path) {
    Error(_) -> Error(InvalidUrl)
    Ok(req) -> {
      let req =
        req
        |> request.set_method(method)
        |> request.set_header("accept", "application/json")

      let req = case bearer {
        Some(token) ->
          request.set_header(req, "authorization", "Bearer " <> token)
        None -> req
      }

      let req = case body {
        Some(value) ->
          req
          |> request.set_header("content-type", "application/json")
          |> request.set_body(json.to_string(value))
        None -> req
      }

      Ok(req)
    }
  }
}

fn send(
  client: Client,
  req: Request(String),
) -> Result(Response(String), ClientError) {
  client.transport(req, client.timeout_ms)
  |> result.map_error(TransportError)
}

fn decode_json_response(
  response: Response(String),
  decoder: decode.Decoder(value),
) -> Result(value, ClientError) {
  case response.status {
    401 -> Error(Unauthorized)
    status ->
      case is_success(status) {
        True ->
          response.body
          |> json.parse(decoder)
          |> result.map_error(InvalidResponse)
        False -> Error(UnexpectedStatus(status))
      }
  }
}

fn is_success(status: Int) -> Bool {
  status >= 200 && status < 300
}

fn valid_email(value: String) -> Bool {
  let size = string.byte_size(value)
  size > 0
  && size <= 320
  && value == string.trim(value)
  && string.contains(value, "@")
  && no_control_characters(value)
}

fn valid_registration_password(value: String) -> Bool {
  let size = string.byte_size(value)
  size >= 12 && size <= 1024
}

fn valid_login_password(value: String) -> Bool {
  let size = string.byte_size(value)
  size > 0 && size <= 1024
}

fn valid_display_name(value: Option(String)) -> Bool {
  case value {
    None -> True
    Some(value) -> {
      let normalized = string.trim(value)
      normalized == ""
      || {
        string.byte_size(normalized) <= 160
        && no_control_characters(normalized)
      }
    }
  }
}

fn valid_email_otp(value: String) -> Bool {
  string.byte_size(value) == 6
  && {
    value
    |> string.to_utf_codepoints
    |> list.all(fn(codepoint) {
      let value = string.utf_codepoint_to_int(codepoint)
      value >= 48 && value <= 57
    })
  }
}

fn valid_credential(value: String) -> Bool {
  let size = string.byte_size(value)
  size > 0
  && size <= 16 * 1024
  && value == string.trim(value)
  && {
    value
    |> string.to_utf_codepoints
    |> list.all(fn(codepoint) {
      let value = string.utf_codepoint_to_int(codepoint)
      value > 32 && value != 127
    })
  }
}

fn no_control_characters(value: String) -> Bool {
  value
  |> string.to_utf_codepoints
  |> list.all(fn(codepoint) {
    let value = string.utf_codepoint_to_int(codepoint)
    value >= 32 && value != 127
  })
}

fn valid_introspection_token(value: String) -> Bool {
  let size = string.byte_size(value)
  size > 0
  && size <= 16 * 1024
  && value == string.trim(value)
  && !string.contains(value, "\r")
  && !string.contains(value, "\n")
}

fn valid_introspection_value(value: String) -> Bool {
  let size = string.byte_size(value)
  size > 0
  && size <= 128
  && {
    value
    |> string.to_utf_codepoints
    |> list.all(fn(codepoint) {
      let value = string.utf_codepoint_to_int(codepoint)
      { value >= 48 && value <= 57 }
      || { value >= 65 && value <= 90 }
      || { value >= 97 && value <= 122 }
      || list.contains([46, 95, 58, 47, 45], value)
    })
  }
}

fn valid_required_scopes(scopes: List(String)) -> Bool {
  list.length(scopes) <= 64
  && list.all(scopes, valid_introspection_value)
  && list.length(list.unique(scopes)) == list.length(scopes)
}

fn normalize_base(base: String) -> String {
  base |> string.trim |> trim_trailing_slashes
}

fn trim_trailing_slashes(value: String) -> String {
  case string.ends_with(value, "/") {
    True -> value |> string.remove_suffix("/") |> trim_trailing_slashes
    False -> value
  }
}

fn optional_string_field(
  name: String,
  value: Option(String),
) -> List(#(String, json.Json)) {
  case value {
    Some(value) ->
      case value |> string.trim |> string.to_option {
        Some(value) -> [#(name, json.string(value))]
        None -> []
      }
    None -> []
  }
}
