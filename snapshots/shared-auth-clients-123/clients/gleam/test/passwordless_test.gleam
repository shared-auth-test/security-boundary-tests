import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/httpc
import gleam/option.{None, Some}
import gleam/string
import shared_auth_client

fn session_body(provider: String) -> String {
  "{\"access_token\":\"fixture-access\",\"token_type\":\"Bearer\",\"expires_at\":42,\"refresh_token\":\"fixture-refresh\",\"refresh_expires_at\":84,\"shared_user_id\":\"fixture-user\",\"provider\":\""
  <> provider
  <> "\",\"roles\":[],\"amr\":[\"email\"]}"
}

pub fn passwordless_request_preserves_accepted_response_test() {
  let assert Ok(client) =
    shared_auth_client.new("https://gateway.example/shared-auth")
  let client =
    shared_auth_client.with_transport(client, fn(req: Request(String), _) {
      assert req.method == http.Post
      assert req.path == "/shared-auth/auth/passwordless/request"
      assert req.body == "{\"email\":\"person@example.invalid\"}"
      response.new(202)
      |> response.set_body("{\"accepted\":true}")
      |> Ok
    })

  let assert Ok(result) =
    shared_auth_client.request_passwordless(client, "person@example.invalid")
  assert result.accepted
}

pub fn passwordless_consume_uses_strict_email_and_code_test() {
  let valid_code = string.repeat("0", 6)
  let assert Ok(client) =
    shared_auth_client.new("https://gateway.example/shared-auth")
  let client =
    shared_auth_client.with_transport(client, fn(req: Request(String), _) {
      assert req.method == http.Post
      assert req.path == "/shared-auth/auth/passwordless/consume"
      assert req.body
        == "{\"email\":\"person@example.invalid\",\"otp\":\"" <> valid_code <> "\"}"
      response.new(200)
      |> response.set_body(session_body("magic_link"))
      |> Ok
    })

  let assert Ok(session) =
    shared_auth_client.consume_passwordless(
      client,
      "person@example.invalid",
      valid_code,
    )
  assert session.provider == "magic_link"
}

pub fn session_lifecycle_uses_expected_bodies_test() {
  let assert Ok(client) =
    shared_auth_client.new("https://gateway.example/shared-auth")
  let client =
    shared_auth_client.with_transport(client, fn(req: Request(String), _) {
      case req.path {
        "/shared-auth/auth/register" -> {
          assert req.body
            == "{\"email\":\"person@example.invalid\",\"password\":\"correct horse battery staple\",\"display_name\":\"Test Person\"}"
          response.new(200) |> response.set_body(session_body("local")) |> Ok
        }
        "/shared-auth/auth/login" -> {
          assert req.body
            == "{\"email\":\"person@example.invalid\",\"password\":\"correct horse battery staple\"}"
          response.new(200) |> response.set_body(session_body("local")) |> Ok
        }
        "/shared-auth/auth/refresh" -> {
          assert req.body == "{\"refresh_token\":\"fixture-refresh\"}"
          response.new(200) |> response.set_body(session_body("local")) |> Ok
        }
        "/shared-auth/auth/logout" -> {
          assert req.body == "{\"refresh_token\":\"fixture-refresh\"}"
          response.new(204) |> Ok
        }
        _ -> panic as "unexpected request"
      }
    })

  let assert Ok(_) = shared_auth_client.register(
    client,
    "person@example.invalid",
    "correct horse battery staple",
    Some(" Test Person "),
  )
  let assert Ok(_) = shared_auth_client.login(
    client,
    "person@example.invalid",
    "correct horse battery staple",
  )
  let assert Ok(_) = shared_auth_client.refresh(client, "fixture-refresh")
  let assert Ok(Nil) = shared_auth_client.logout(client, "fixture-refresh")
}

pub fn malformed_passwordless_inputs_fail_before_transport_test() {
  let assert Ok(client) =
    shared_auth_client.new("https://gateway.example/shared-auth")
  let client =
    shared_auth_client.with_transport(client, fn(_: Request(String), _: Int) -> Result(
      Response(String),
      httpc.HttpError,
    ) {
      panic as "transport must not run"
    })

  assert shared_auth_client.request_passwordless(
    client,
    " person@example.invalid",
  ) == Error(shared_auth_client.InvalidRequest)
  assert shared_auth_client.consume_passwordless(
    client,
    "person@example.invalid",
    "12345",
  ) == Error(shared_auth_client.InvalidRequest)
  assert shared_auth_client.consume_passwordless(
    client,
    "person@example.invalid",
    "12a456",
  ) == Error(shared_auth_client.InvalidRequest)
  assert shared_auth_client.register(
    client,
    "person@example.invalid",
    "too-short",
    None,
  ) == Error(shared_auth_client.InvalidRequest)
}
