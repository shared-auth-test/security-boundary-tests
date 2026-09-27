import assert from "node:assert/strict";
import test from "node:test";

import canonicalEdge, { prepareCanonicalRequest } from "../src/canonical-plus.mjs";

const env = {
  SHARED_AUTH_BASE: "https://app.canonical.plus/shared-auth",
  SHARED_AUTH_JWKS_URL: "https://app.canonical.plus/shared-auth/.well-known/jwks.json",
  AUTH_ISSUER: "https://app.canonical.plus/shared-auth",
  AUTH_AUDIENCE: "canonical-plus-web",
  LOGIN_URL: "https://app.canonical.plus/shared-auth/auth/browser/sign-in",
  SESSION_COOKIE_NAME: "__Host-canonical-customer-auth",
  REFRESH_COOKIE_NAME: "__Host-canonical-customer-auth-refresh",
  PROTECTED_PATH_PREFIXES: "/u/,/api/v1/quotes,/ws/quotes,/v1/quotes,/v1/ws",
  PUBLIC_PATH_PREFIXES: "/shared-auth/,/health,/assets/",
  CANONICAL_API_HOST: "api.canonical.plus",
};

const context = { waitUntil() {} };

test("api.canonical.plus is transformed into a bearer-only request", () => {
  const request = new Request("https://api.canonical.plus/v1/quotes", {
    headers: {
      accept: "text/html",
      authorization: "Bearer shared-auth-token",
      cookie: "__Host-canonical-customer-auth=must-not-cross-hosts",
      "x-supabase-token": "legacy-token",
      "x-canonical-subject": "attacker",
      "x-canonical-internal-token": "attacker-token",
      "x-canonical-attacker-controlled": "must-also-be-removed",
      "x-client-version": "1.2.3",
    },
  });

  const transformed = prepareCanonicalRequest(request, env);
  assert.equal(transformed.headers.get("accept"), "application/json");
  assert.equal(transformed.headers.get("cookie"), null);
  assert.equal(transformed.headers.get("x-supabase-token"), null);
  assert.equal(transformed.headers.get("x-canonical-subject"), null);
  assert.equal(transformed.headers.get("x-canonical-internal-token"), null);
  assert.equal(transformed.headers.get("x-canonical-attacker-controlled"), null);
  assert.equal(transformed.headers.get("authorization"), "Bearer shared-auth-token");
  assert.equal(transformed.headers.get("x-client-version"), "1.2.3");
});

test("app.canonical.plus retains browser request semantics when no internal headers exist", () => {
  const request = new Request("https://app.canonical.plus/u/quote", {
    headers: { accept: "text/html", cookie: "session=value" },
  });
  assert.equal(prepareCanonicalRequest(request, env), request);
});

test("app.canonical.plus strips the complete Canonical internal header namespace", () => {
  const request = new Request("https://app.canonical.plus/u/quote", {
    headers: {
      accept: "text/html",
      cookie: "session=value",
      "x-canonical-subject": "attacker",
      "x-canonical-internal-token": "attacker-token",
      "x-canonical-arbitrary": "attacker-controlled",
      "x-client-version": "1.2.3",
    },
  });

  const transformed = prepareCanonicalRequest(request, env);
  assert.notEqual(transformed, request);
  assert.equal(transformed.headers.get("accept"), "text/html");
  assert.equal(transformed.headers.get("cookie"), "session=value");
  assert.equal(transformed.headers.get("x-canonical-subject"), null);
  assert.equal(transformed.headers.get("x-canonical-internal-token"), null);
  assert.equal(transformed.headers.get("x-canonical-arbitrary"), null);
  assert.equal(transformed.headers.get("x-client-version"), "1.2.3");
});

test("unauthenticated standalone API REST and WebSocket requests receive JSON 401", async () => {
  for (const path of ["/v1/quotes", "/v1/ws"]) {
    const response = await canonicalEdge.fetch(new Request(
      `https://api.canonical.plus${path}`,
      { headers: { accept: "text/html" } },
    ), env, context);

    assert.equal(response.status, 401, path);
    assert.match(response.headers.get("content-type") || "", /application\/json/);
    assert.deepEqual(await response.json(), { error: "unauthorized" });
    assert.equal(response.headers.get("location"), null);
  }
});

test("unauthenticated app pages retain the first-party sign-in redirect", async () => {
  const response = await canonicalEdge.fetch(new Request(
    "https://app.canonical.plus/u/quote?framework=soc2",
    { headers: { accept: "text/html" } },
  ), env, context);

  assert.equal(response.status, 302);
  const location = new URL(response.headers.get("location"));
  assert.equal(location.origin, "https://app.canonical.plus");
  assert.equal(location.pathname, "/shared-auth/auth/browser/sign-in");
  assert.equal(location.searchParams.get("return"), "/u/quote?framework=soc2");
});

test("app quote REST and WebSocket paths remain protected", async () => {
  for (const path of ["/api/v1/quotes", "/ws/quotes"]) {
    const response = await canonicalEdge.fetch(new Request(
      `https://app.canonical.plus${path}`,
      { headers: { accept: "application/json" } },
    ), env, context);
    assert.equal(response.status, 401, path);
  }
});

test("canonical API host configuration rejects URL-shaped values", () => {
  const request = new Request("https://api.canonical.plus/v1/quotes");
  assert.throws(
    () => prepareCanonicalRequest(request, { CANONICAL_API_HOST: "https://api.canonical.plus" }),
    /bare DNS hostname/,
  );
});
