import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/httpc
import gleam/json
import gleam/option.{None, Some}
import gleeunit
import shared_auth_client
import shared_auth_client/model

pub fn main() {
  gleeunit.main()
}

pub fn exchange_normalizes_base_and_sends_bearer_test() {
  let assert Ok(client) =
    shared_auth_client.new(" https://gateway.example/shared-auth/// ")
  let transport = fn(req: Request(String), timeout_ms: Int) -> Result(
    Response(String),
    httpc.HttpError,
  ) {
    assert timeout_ms == 10_000
    assert req.method == http.Post
    assert req.path == "/shared-auth/auth/exchange"
    assert req.body == ""
    assert request.get_header(req, "authorization")
      == Ok("Bearer supabase-token")

    response.new(200)
    |> response.set_body(
      "{\"access_token\":\"shared-token\",\"token_type\":\"Bearer\",\"expires_at\":42,\"shared_user_id\":\"user-1\",\"provider\":\"supabase\"}",
    )
    |> Ok
  }
  let client = shared_auth_client.with_transport(client, transport)

  let assert Ok(value) = shared_auth_client.exchange(client, "supabase-token")
  assert value.access_token == "shared-token"
  assert value.expires_at == 42
  assert value.shared_user_id == "user-1"
  assert value.provider == Some("supabase")
}

pub fn service_credential_is_introspection_only_test() {
  let assert Ok(client) =
    shared_auth_client.new("https://gateway.example/shared-auth")
  let client =
    client
    |> shared_auth_client.with_service_credential(" service-secret ")
    |> shared_auth_client.with_transport(fn(req, _) {
      case req.path {
        "/shared-auth/auth/introspect" -> {
          assert request.get_header(req, "authorization")
            == Ok("Bearer service-secret")
          assert req.body
            == "{\"contract\":\"IntrospectionRequest\",\"payload\":{\"token\":\"shared-token\",\"audience\":\"oresoftware\",\"requiredScopes\":[]}}"
          response.new(200)
          |> response.set_body(
            "{\"active\":true,\"sub\":\"user-1\",\"roles\":[\"admin\"],\"amr\":[\"passkey\"],\"acr\":\"urn:oresoftware:loa:2\"}",
          )
          |> Ok
        }
        "/shared-auth/auth/exchange" -> {
          assert request.get_header(req, "authorization")
            == Ok("Bearer end-user-token")
          response.new(200)
          |> response.set_body(
            "{\"access_token\":\"shared-token\",\"token_type\":\"Bearer\",\"expires_at\":42,\"shared_user_id\":\"user-1\"}",
          )
          |> Ok
        }
        _ -> panic as "unexpected request"
      }
    })

  let assert Ok(identity) =
    shared_auth_client.introspect(client, "shared-token")
  let assert Ok(_) = shared_auth_client.exchange(client, "end-user-token")
  assert shared_auth_client.has_assurance(identity, "urn:oresoftware:loa:2")
  assert shared_auth_client.used_method(identity, "passkey")
  assert shared_auth_client.has_role(identity, "admin")
}

pub fn verify_and_uniform_errors_test() {
  let assert Ok(client) =
    shared_auth_client.new("https://gateway.example/shared-auth")
  let client =
    shared_auth_client.with_transport(client, fn(req, _) {
      case request.get_header(req, "authorization") {
        Ok("Bearer good") -> response.new(200) |> Ok
        Ok("Bearer bad") -> response.new(401) |> Ok
        Ok("Bearer unavailable") -> response.new(503) |> Ok
        _ -> response.new(401) |> Ok
      }
    })

  assert shared_auth_client.verify(client, "good") == Ok(True)
  assert shared_auth_client.verify(client, "bad") == Ok(False)
  assert shared_auth_client.verify(client, "unavailable")
    == Error(shared_auth_client.UnexpectedStatus(503))

  let unauthorized =
    shared_auth_client.with_transport(client, fn(_, _) {
      response.new(401) |> response.set_body("{}") |> Ok
    })
  assert shared_auth_client.capabilities(unauthorized)
    == Error(shared_auth_client.Unauthorized)
}

pub fn totp_challenge_and_passkey_wire_shapes_test() {
  let assert Ok(client) =
    shared_auth_client.new("https://gateway.example/shared-auth")
  let client =
    shared_auth_client.with_transport(client, fn(req, _) {
      assert request.get_header(req, "authorization")
        == Ok("Bearer access-token")
      case req.path {
        "/shared-auth/auth/factors/totp/enroll" -> {
          assert req.body == "{\"label\":\"phone\"}"
          response.new(200)
          |> response.set_body(
            "{\"factor_id\":\"factor-1\",\"secret_base32\":\"SECRET\",\"otpauth_uri\":\"otpauth://totp/example\",\"threefa_import_uri\":\"threefa://import/example\"}",
          )
          |> Ok
        }
        "/shared-auth/auth/challenges" -> {
          assert req.body == "{\"kind\":\"sms_otp\"}"
          response.new(200)
          |> response.set_body(
            "{\"challenge_id\":\"challenge-1\",\"expires_at\":\"2026-07-30T21:00:00Z\",\"delivery\":\"***-***-1212\"}",
          )
          |> Ok
        }
        "/shared-auth/auth/passkeys/registration/verify" -> {
          assert req.body
            == "{\"challenge_id\":\"challenge-1\",\"credential\":{\"id\":\"credential-1\"},\"label\":\"laptop\"}"
          response.new(200)
          |> response.set_body(
            "{\"factor_id\":\"passkey-1\",\"kind\":\"passkey\",\"label\":\"laptop\",\"enabled\":true,\"created_at\":\"2026-07-30T20:00:00Z\"}",
          )
          |> Ok
        }
        _ -> panic as "unexpected request"
      }
    })

  let assert Ok(enrollment) =
    shared_auth_client.enroll_totp(client, "access-token", Some(" phone "))
  let assert Ok(challenge) =
    shared_auth_client.create_challenge(client, "access-token", model.SmsOtp)
  let assert Ok(factor) =
    shared_auth_client.finish_passkey_registration(
      client,
      "access-token",
      "challenge-1",
      json.object([#("id", json.string("credential-1"))]),
      Some(" laptop "),
    )

  assert enrollment.threefa_import_uri == "threefa://import/example"
  assert challenge.delivery == "***-***-1212"
  assert factor.kind == "passkey"
}

pub fn paths_are_encoded_and_assurance_fails_closed_test() {
  let assert Ok(client) =
    shared_auth_client.new("https://gateway.example/shared-auth")
  let client =
    shared_auth_client.with_transport(client, fn(req, _) {
      assert req.method == http.Delete
      assert req.path == "/shared-auth/auth/factors/a%2Fb%20%3F"
      response.new(204) |> Ok
    })
  assert shared_auth_client.delete_factor(client, "access-token", "a/b ?")
    == Ok(Nil)

  let inactive =
    model.Introspection(
      active: False,
      sub: None,
      sid: None,
      project: None,
      provider: None,
      provider_tenant: None,
      provider_subject: None,
      email: None,
      email_verified: None,
      roles: ["admin"],
      amr: ["passkey"],
      acr: Some("urn:oresoftware:loa:2"),
      exp: None,
    )
  assert !shared_auth_client.has_assurance(inactive, "urn:oresoftware:loa:2")
  assert !shared_auth_client.used_method(inactive, "passkey")
  assert !shared_auth_client.has_role(inactive, "admin")
}
