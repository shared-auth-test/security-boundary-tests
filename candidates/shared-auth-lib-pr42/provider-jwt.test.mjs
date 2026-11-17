import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

import {
  JwtVerificationError,
  ProviderJwtVerifier,
  verifyProviderJwtWithJwks,
} from "./provider-jwt.mjs";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const enc = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");

async function rsaFixture(claimOverrides = {}) {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  publicJwk.kid = "k1";
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";

  const now = 1_800_000_000;
  const header = { alg: "RS256", kid: "k1", typ: "JWT" };
  const claims = {
    iss: "https://auth.example.test",
    aud: "product-edge",
    sub: "principal-123",
    iat: now - 10,
    nbf: now - 10,
    exp: now + 300,
    ...claimOverrides,
  };
  const h = enc(header);
  const p = enc(claims);
  const signed = new TextEncoder().encode(`${h}.${p}`);
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    pair.privateKey,
    signed,
  );
  return {
    token: `${h}.${p}.${Buffer.from(signature).toString("base64url")}`,
    publicJwk,
    now,
  };
}

function policy(now) {
  return {
    provider: "shared-auth",
    issuer: "https://auth.example.test",
    audiences: ["product-edge"],
    jwksUrl: "https://auth.example.test/.well-known/jwks.json",
    allowedAlgorithms: ["RS256"],
    requireIssuedAt: true,
    requireNotBefore: true,
    nowSeconds: () => now,
  };
}

test("zero-tooling verifier validates an exact signed provider JWT", async () => {
  const { token, publicJwk, now } = await rsaFixture();
  const verified = await verifyProviderJwtWithJwks(
    token,
    { keys: [publicJwk] },
    policy(now),
  );
  assert.equal(verified.provider, "shared-auth");
  assert.equal(verified.subject, "principal-123");
  assert.equal(verified.algorithm, "RS256");
  assert.equal(verified.keyId, "k1");
  assert.equal(verified.toString(), "VerifiedJwt([claims redacted])");
});

test("wrong audience, expired token, future nbf, and stale iat are invalid", async () => {
  for (const [overrides, patch, reason] of [
    [{ aud: "other" }, {}, /audience rejected/],
    [{ exp: 1_799_999_000 }, {}, /token expired/],
    [{ nbf: 1_800_001_000 }, {}, /token not active/],
    [{ iat: 1_799_000_000 }, { maxTokenAgeSeconds: 60 }, /older than policy/],
  ]) {
    const { token, publicJwk, now } = await rsaFixture(overrides);
    await assert.rejects(
      () => verifyProviderJwtWithJwks(
        token,
        { keys: [publicJwk] },
        { ...policy(now), ...patch },
      ),
      reason,
    );
  }
});

test("tampering is rejected and errors preserve invalid/unavailable distinction", async () => {
  const { token, publicJwk, now } = await rsaFixture();
  const [h, , s] = token.split(".");
  const forged = `${h}.${enc({
    iss: "https://auth.example.test",
    aud: "product-edge",
    sub: "other-principal",
    iat: now,
    nbf: now,
    exp: now + 300,
  })}.${s}`;

  await assert.rejects(
    () => verifyProviderJwtWithJwks(forged, { keys: [publicJwk] }, policy(now)),
    (error) => error instanceof JwtVerificationError &&
      error.kind === "invalid" &&
      /signature rejected/.test(error.message),
  );

  await assert.rejects(
    () => verifyProviderJwtWithJwks(token, { keys: [] }, policy(now)),
    (error) => error instanceof JwtVerificationError &&
      error.kind === "invalid" &&
      /unknown key id/.test(error.message),
  );
});

test("private JWK material is never accepted as a verification set", async () => {
  const { token, publicJwk, now } = await rsaFixture();
  const bad = { ...publicJwk, d: "secret" };
  await assert.rejects(
    () => verifyProviderJwtWithJwks(token, { keys: [bad] }, policy(now)),
    (error) => error instanceof JwtVerificationError &&
      error.kind === "unavailable" &&
      /invalid key/.test(error.message),
  );
});

test("malformed JWKS documents fail with a classified unavailable error", async () => {
  const { token, now } = await rsaFixture();
  for (const jwks of [null, {}, { keys: "not-an-array" }, { keys: [] }]) {
    await assert.rejects(
      () => verifyProviderJwtWithJwks(token, jwks, policy(now)),
      (error) => error instanceof JwtVerificationError &&
        error.kind === "unavailable" &&
        /JWKS contains an invalid/.test(error.message),
    );
  }
});

test("unselected private and duplicate keys invalidate the whole JWKS set", async () => {
  const { token, publicJwk, now } = await rsaFixture();

  await assert.rejects(
    () => verifyProviderJwtWithJwks(
      token,
      {
        keys: [
          publicJwk,
          { ...publicJwk, kid: "other", d: "secret" },
        ],
      },
      policy(now),
    ),
    (error) => error instanceof JwtVerificationError &&
      error.kind === "unavailable" &&
      /invalid key/.test(error.message),
  );

  await assert.rejects(
    () => verifyProviderJwtWithJwks(
      token,
      {
        keys: [
          publicJwk,
          { ...publicJwk, kid: "other" },
          { ...publicJwk, kid: "other" },
        ],
      },
      policy(now),
    ),
    (error) => error instanceof JwtVerificationError &&
      error.kind === "unavailable" &&
      /duplicate key id/.test(error.message),
  );
});

test("network verifier single-flights compatible consumers through the same public interface", async () => {
  const { token, publicJwk, now } = await rsaFixture();
  let calls = 0;
  const verifier = new ProviderJwtVerifier({
    ...policy(now),
    fetchImpl: async () => {
      calls += 1;
      return new Response(JSON.stringify({ keys: [publicJwk] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  const [a, b] = await Promise.all([verifier.verify(token), verifier.verify(token)]);
  assert.equal(a.subject, "principal-123");
  assert.equal(b.subject, "principal-123");
  assert.equal(calls, 1);
});
