import assert from "node:assert/strict";
import test from "node:test";

import {
  SharedAuthClient,
  SharedAuthDecodeError,
} from "../dist/index.js";

function capture(responder) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    return responder(String(url), init);
  };
  return { calls, fetchImpl };
}

function sessionResponse(provider = "magic_link") {
  return {
    access_token: "fixture-access",
    token_type: "Bearer",
    expires_at: 42,
    refresh_token: "fixture-refresh",
    refresh_expires_at: 84,
    shared_user_id: "fixture-user",
    provider,
    roles: [],
    amr: provider === "magic_link" ? ["email"] : ["password"],
  };
}

test("session lifecycle uses exact local-auth bodies", async () => {
  const { calls, fetchImpl } = capture((url) => {
    if (url.endsWith("/auth/logout")) {
      return new Response(null, { status: 204 });
    }
    return Response.json(sessionResponse("local"));
  });
  const client = new SharedAuthClient(
    "https://gw.example/shared-auth",
    fetchImpl,
  );

  await client.register(
    "person@example.invalid",
    "correct horse battery staple",
    " Test Person ",
  );
  await client.login(
    "person@example.invalid",
    "correct horse battery staple",
  );
  await client.refresh("fixture-refresh");
  await client.logout("fixture-refresh");

  assert.deepEqual(JSON.parse(calls[0].init.body), {
    email: "person@example.invalid",
    password: "correct horse battery staple",
    display_name: "Test Person",
  });
  assert.deepEqual(JSON.parse(calls[1].init.body), {
    email: "person@example.invalid",
    password: "correct horse battery staple",
  });
  assert.deepEqual(JSON.parse(calls[2].init.body), {
    refresh_token: "fixture-refresh",
  });
  assert.deepEqual(JSON.parse(calls[3].init.body), {
    refresh_token: "fixture-refresh",
  });
});

test("passwordless request preserves enumeration-resistant accepted response", async () => {
  const { calls, fetchImpl } = capture(() =>
    Response.json({ accepted: true }, { status: 202 }),
  );
  const client = new SharedAuthClient(
    "https://gw.example/shared-auth",
    fetchImpl,
  );

  const result = await client.requestPasswordless("person@example.invalid");

  assert.equal(result.accepted, true);
  assert.equal(calls[0].url, "https://gw.example/shared-auth/auth/passwordless/request");
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    email: "person@example.invalid",
  });
});

test("passwordless consume sends only email and strict six-digit code", async () => {
  const validCode = Array.from({ length: 6 }, () => "0").join("");
  const { calls, fetchImpl } = capture(() => Response.json(sessionResponse()));
  const client = new SharedAuthClient(
    "https://gw.example/shared-auth",
    fetchImpl,
  );

  const result = await client.consumePasswordless(
    "person@example.invalid",
    validCode,
  );

  assert.equal(result.provider, "magic_link");
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    email: "person@example.invalid",
    otp: validCode,
  });
  assert.equal(Object.keys(JSON.parse(calls[0].init.body)).length, 2);
});

test("malformed passwordless inputs fail before fetch", async () => {
  const { calls, fetchImpl } = capture(() => Response.json({}));
  const client = new SharedAuthClient(
    "https://gw.example/shared-auth",
    fetchImpl,
  );

  for (const invalidCode of ["", "12345", "1234567", "12a456"]) {
    assert.throws(
      () => client.consumePasswordless("person@example.invalid", invalidCode),
      /exactly six ASCII digits/,
    );
  }
  await assert.rejects(
    client.requestPasswordless(" person@example.invalid"),
    /email is invalid/,
  );
  assert.equal(calls.length, 0);
});

test("passwordless accepted response is runtime checked", async () => {
  const { fetchImpl } = capture(() => Response.json({ accepted: "yes" }));
  const client = new SharedAuthClient(
    "https://gw.example/shared-auth",
    fetchImpl,
  );

  await assert.rejects(
    client.requestPasswordless("person@example.invalid"),
    SharedAuthDecodeError,
  );
});
