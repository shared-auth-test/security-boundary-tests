import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";
import worker from "../src/index.mjs";

import {
  buildLoginRedirect,
  clearSessionCookies,
  ensureTraceContext,
  loadConfig,
  raceSessionArms,
  sanitizedHeaders,
  sessionCookieHeaders,
  verifyJwt,
} from "../src/index.mjs";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const baseConfig = {
  SHARED_AUTH_BASE: "https://gateway.example/shared-auth",
  AUTH_ISSUER: "https://auth.example",
  AUTH_AUDIENCE: "apps",
};

test("configuration rejects non-TLS authority URLs", () => {
  assert.throws(() => loadConfig({
    ...baseConfig,
    SHARED_AUTH_BASE: "http://auth.example",
  }));
});

test("configuration pins absolute login and distinct host-only cookie namespaces", () => {
  const config = loadConfig({
    ...baseConfig,
    LOGIN_URL: "https://app.canonical.plus/shared-auth/auth/browser/sign-in",
    SESSION_COOKIE_NAME: "__Host-canonical_auth",
    REFRESH_COOKIE_NAME: "__Host-canonical_refresh",
  });
  assert.equal(config.loginUrl, "https://app.canonical.plus/shared-auth/auth/browser/sign-in");
  assert.equal(config.sessionCookie, "__Host-canonical_auth");
  assert.equal(config.refreshCookie, "__Host-canonical_refresh");
  assert.throws(() => loadConfig({
    ...baseConfig,
    SESSION_COOKIE_NAME: "canonical_auth",
  }));
  assert.throws(() => loadConfig({
    ...baseConfig,
    SESSION_COOKIE_NAME: "__Host-same",
    REFRESH_COOKIE_NAME: "__Host-same",
  }));
});

test("login redirect preserves only the requested path and query", () => {
  const config = loadConfig({
    ...baseConfig,
    LOGIN_URL: "https://app.canonical.plus/shared-auth/auth/browser/sign-in?brand=canonical",
  });
  const destination = new URL(buildLoginRedirect(
    new URL("https://app.canonical.plus/u/quote?framework=soc2"),
    config,
  ));
  assert.equal(destination.origin, "https://app.canonical.plus");
  assert.equal(destination.pathname, "/shared-auth/auth/browser/sign-in");
  assert.equal(destination.searchParams.get("brand"), "canonical");
  assert.equal(destination.searchParams.get("return"), "/u/quote?framework=soc2");
});

test("rotated session cookies are host-only, secure, HTTP-only, and bounded", () => {
  const config = loadConfig({
    ...baseConfig,
    SESSION_COOKIE_NAME: "__Host-canonical_auth",
    REFRESH_COOKIE_NAME: "__Host-canonical_refresh",
  });
  const now = Math.floor(Date.now() / 1000);
  const headers = sessionCookieHeaders({
    access_token: "access-token",
    refresh_token: "refresh-token",
    refresh_expires_at: now + 10_000_000,
  }, { exp: now + 600 }, config);
  assert.equal(headers.length, 2);
  for (const header of headers) {
    assert.match(header, /Path=\/;/);
    assert.match(header, /HttpOnly/);
    assert.match(header, /Secure/);
    assert.match(header, /SameSite=Lax/);
    assert.doesNotMatch(header, /Domain=/i);
  }
  assert.match(headers[0], /Max-Age=600/);
  assert.match(headers[1], /Max-Age=2592000/);
  assert.ok(clearSessionCookies(config).every((header) => header.endsWith("Max-Age=0")));
});

test("all caller-supplied identity headers are removed", () => {
  const headers = sanitizedHeaders(new Headers({
    "x-auth-user-id": "attacker",
    "x-auth-email": "spoof@example.com",
    "x-auth-provider": "spoof",
    "x-auth-roles": "admin",
    "x-auth-attacker-controlled": "must-also-be-removed",
    "x-supabase-token": "must-not-reach-origin",
    "x-safe-header": "preserved",
  }));
  assert.equal(headers.get("x-auth-user-id"), null);
  assert.equal(headers.get("x-auth-email"), null);
  assert.equal(headers.get("x-auth-provider"), null);
  assert.equal(headers.get("x-auth-roles"), null);
  assert.equal(headers.get("x-auth-attacker-controlled"), null);
  assert.equal(headers.get("x-supabase-token"), null);
  assert.equal(headers.get("x-safe-header"), "preserved");
});

test("preserves valid W3C trace context and replaces malformed input", () => {
  const valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
  const headers = new Headers({ traceparent: valid });
  assert.equal(ensureTraceContext(headers), valid);
  headers.set("traceparent", "attacker-controlled");
  assert.match(ensureTraceContext(headers), /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
});

test("strict ES256 verification accepts exact kid and rejects algorithm or kid confusion", async () => {
  const pair = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const publicJwk = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
  const jwk = { ...publicJwk, kid: "edge-test", alg: "ES256", use: "sig" };
  const config = { issuer: "https://issuer.example/", audience: "apps" };
  const claims = {
    sub: "user-1",
    iss: config.issuer,
    aud: ["other", "apps"],
    iat: Math.floor(Date.now() / 1000),
    nbf: Math.floor(Date.now() / 1000) - 1,
    exp: Math.floor(Date.now() / 1000) + 300,
    provider: "local",
    provider_tenant: "default",
    provider_subject: "user-1",
    roles: ["user"],
  };
  const token = await sign(pair.privateKey, { alg: "ES256", typ: "JWT", kid: "edge-test" }, claims);
  assert.equal((await verifyJwt(token, config, [jwk])).sub, "user-1");

  const wrongKid = await sign(pair.privateKey, { alg: "ES256", typ: "JWT", kid: "missing" }, claims);
  await assert.rejects(() => verifyJwt(wrongKid, config, [jwk]), /unknown key/);
  const wrongAlg = await sign(pair.privateKey, { alg: "HS256", typ: "JWT", kid: "edge-test" }, claims);
  await assert.rejects(() => verifyJwt(wrongAlg, config, [jwk]), /algorithm/);
});

test("expiry is mandatory", async () => {
  const pair = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
  );
  const publicJwk = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
  const jwk = { ...publicJwk, kid: "k", alg: "ES256" };
  const token = await sign(pair.privateKey, { alg: "ES256", kid: "k" }, {
    sub: "u", iss: "https://issuer.example/", aud: "apps",
    provider: "local", provider_tenant: "default", provider_subject: "u", roles: [],
  });
  await assert.rejects(() => verifyJwt(token, {
    issuer: "https://issuer.example/", audience: "apps",
  }, [jwk]), /expired/);
});

async function sign(privateKey, header, claims) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const protectedHeader = encode(header);
  const payload = encode(claims);
  const signature = await webcrypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(`${protectedHeader}.${payload}`),
  );
  return `${protectedHeader}.${payload}.${Buffer.from(signature).toString("base64url")}`;
}

test("dual-auth race: first successful arm wins and preserves its authority", async () => {
  const slow = () => new Promise((resolve) => setTimeout(
    () => resolve({ claims: { sub: "slow" }, authority: "shared-auth" }), 80));
  const fast = () => new Promise((resolve) => setTimeout(
    () => resolve({ claims: { sub: "fast" }, authority: "supabase" }), 5));
  const winner = await raceSessionArms([slow, fast], 2000);
  assert.equal(winner.authority, "supabase");
  assert.equal(winner.claims.sub, "fast");
});

test("dual-auth race: a failing arm never blocks the survivor", async () => {
  const failing = () => Promise.reject(new Error("authority down"));
  const surviving = () => new Promise((resolve) => setTimeout(
    () => resolve({ claims: { sub: "ok" }, authority: "shared-auth" }), 30));
  const winner = await raceSessionArms([failing, surviving], 2000);
  assert.equal(winner.claims.sub, "ok");
});

test("dual-auth race: all arms failing or deadline exceeded resolves null", async () => {
  assert.equal(await raceSessionArms([
    () => Promise.reject(new Error("a")),
    () => Promise.reject(new Error("b")),
  ], 2000), null);
  assert.equal(await raceSessionArms([
    () => new Promise((resolve) => setTimeout(() => resolve({ claims: {} }), 500)),
  ], 20), null);
  assert.equal(await raceSessionArms([], 100), null);
});

test("configuration validates the optional direct-Supabase arm", () => {
  const withArm = loadConfig({
    ...baseConfig,
    SUPABASE_URL: "https://ref.supabase.co",
    SUPABASE_PROJECT: "fiducia-cloud",
  });
  assert.equal(withArm.supabaseUrl, "https://ref.supabase.co");
  assert.equal(withArm.supabaseProject, "fiducia-cloud");
  assert.equal(withArm.raceDeadlineMs, 1500);

  const without = loadConfig(baseConfig);
  assert.equal(without.supabaseUrl, null);
  assert.throws(() => loadConfig({ ...baseConfig, SUPABASE_URL: "http://insecure.example" }));
});

test("session-creating exchange never races or falls back to direct-provider success", async (t) => {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (input) => {
    const url = String(input);
    calls.push(url);
    if (url.endsWith("/auth/exchange")) {
      return new Response("{}", { status: 403 });
    }
    if (url.endsWith("/auth/v1/user")) {
      return Response.json({ id: "synthetic-provider-user" });
    }
    throw new Error("unexpected origin request");
  });
  const response = await worker.fetch(new Request("https://product.example/private", {
    headers: { "x-supabase-token": "synthetic-provider-token", accept: "application/json" },
  }), { ...baseConfig, SUPABASE_URL: "https://provider.example",
    SUPABASE_PROJECT: "synthetic-project" }, { waitUntil() {} });
  assert.equal(response.status, 401);
  assert.deepEqual(calls, ["https://gateway.example/shared-auth/auth/exchange"]);
});

test("ambiguous exchange network failure is not retried or raced", async (t) => {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (input) => {
    calls.push(String(input));
    throw new Error("response lost after provider received the mutation");
  });
  const response = await worker.fetch(new Request("https://product.example/private", {
    headers: { "x-supabase-token": "synthetic-provider-token" },
  }), { ...baseConfig, SUPABASE_URL: "https://provider.example",
    SUPABASE_PROJECT: "synthetic-project" }, { waitUntil() {} });
  assert.equal(response.status, 401);
  assert.equal(calls.length, 1);
});

test("successful single exchange verifies its JWT and forwards exactly once", async (t) => {
  const pair = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
  );
  const publicJwk = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
  const now = Math.floor(Date.now() / 1000);
  const token = await sign(pair.privateKey, { alg: "ES256", kid: "exchange-regression" }, {
    sub: "canonical-fixture", iss: baseConfig.AUTH_ISSUER, aud: baseConfig.AUTH_AUDIENCE,
    iat: now, exp: now + 300, provider: "supabase", provider_tenant: "fixture", roles: [],
  });
  const calls = [];
  t.mock.method(globalThis, "fetch", async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    calls.push(url);
    if (url.endsWith("/auth/exchange")) {
      assert.equal(init.method, "POST");
      assert.ok(init.signal instanceof AbortSignal);
      return Response.json({ access_token: token, refresh_token: "synthetic-refresh" });
    }
    if (url.endsWith("/.well-known/jwks.json")) {
      return Response.json({ keys: [{ ...publicJwk, kid: "exchange-regression", alg: "ES256" }] });
    }
    assert.equal(input.headers.get("x-auth-user-id"), "canonical-fixture");
    assert.equal(input.headers.get("x-supabase-token"), null);
    return new Response("product-response");
  });
  const response = await worker.fetch(new Request("https://product.example/private", {
    headers: { "x-supabase-token": "synthetic-provider-token" },
  }), { ...baseConfig, SUPABASE_URL: "https://provider.example", SUPABASE_PROJECT: "fixture" },
  { waitUntil() {} });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "product-response");
  assert.deepEqual(calls, ["https://gateway.example/shared-auth/auth/exchange",
    "https://gateway.example/shared-auth/.well-known/jwks.json", "https://product.example/private"]);
  assert.equal(response.headers.getSetCookie().length, 2);
});
