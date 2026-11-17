export class JwtVerificationError extends Error {
  constructor(kind, reason) {
    super(`provider JWT ${kind}: ${reason}`);
    this.name = "JwtVerificationError";
    this.kind = kind;
    this.reason = reason;
  }
}

const MAX_CACHE_TTL_MS = 600_000;
const MIN_UNKNOWN_KID_REFRESH_MS = 30_000;
const MAX_JWKS_BYTES = 4 * 1024 * 1024;

export class ProviderJwtVerifier {
  #config;
  #cache = null;
  #refreshInFlight = null;

  constructor(config) {
    this.#config = checkConfig(config);
  }

  static supabase(projectUrl, audiences, allowedAlgorithms = ["ES256", "RS256"]) {
    const base = projectUrl.replace(/\/+$/, "");
    return new ProviderJwtVerifier({
      provider: "supabase",
      issuer: `${base}/auth/v1`,
      audiences,
      jwksUrl: `${base}/auth/v1/.well-known/jwks.json`,
      allowedAlgorithms,
    });
  }

  seed(keys, ageMs = 0) {
    this.#cache = { fetchedAt: Date.now() - ageMs, keys: structuredClone(keys) };
  }

  purgeCache() {
    this.#cache = null;
  }

  async verify(token) {
    const header = parseHeader(token, this.#config);
    const key = await this.#keyFor(header.kid, header.alg);
    return verifyProviderJwtWithKey(token, header, key, this.#config);
  }

  async #keyFor(kid, algorithm) {
    const now = Date.now();
    if (this.#cache && now - this.#cache.fetchedAt < this.#config.cacheTtlMs) {
      const cached = selectKey(this.#cache.keys, kid);
      if (cached) return validateKey(cached, algorithm);
      if (now - this.#cache.fetchedAt < MIN_UNKNOWN_KID_REFRESH_MS) {
        throw new JwtVerificationError("invalid", "unknown key id");
      }
    }

    const keys = await this.#refresh();
    const fresh = selectKey(keys, kid);
    if (!fresh) throw new JwtVerificationError("invalid", "unknown key id");
    return validateKey(fresh, algorithm);
  }

  #refresh() {
    if (this.#refreshInFlight) return this.#refreshInFlight;
    this.#refreshInFlight = this.#fetchJwks().finally(() => {
      this.#refreshInFlight = null;
    });
    return this.#refreshInFlight;
  }

  async #fetchJwks() {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.#config.httpTimeoutMs);
    try {
      const response = await this.#config.fetchImpl(this.#config.jwksUrl, {
        headers: { accept: "application/json" },
        redirect: "error",
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new JwtVerificationError("unavailable", "JWKS endpoint rejected request");
      }
      const bytes = await readBoundedBody(response, this.#config.maxJwksBytes);
      let value;
      try {
        value = JSON.parse(new TextDecoder().decode(bytes));
      } catch {
        throw new JwtVerificationError("unavailable", "JWKS response malformed");
      }
      const keys = validateJwksDocument(value);
      this.#cache = { fetchedAt: Date.now(), keys };
      return keys;
    } catch (error) {
      if (error instanceof JwtVerificationError) throw error;
      throw new JwtVerificationError("unavailable", "JWKS fetch failed");
    } finally {
      clearTimeout(timer);
    }
  }
}

export async function verifyProviderJwtWithJwks(token, jwks, config) {
  const checked = checkConfig(config);
  const header = parseHeader(token, checked);
  const keys = validateJwksDocument(jwks);
  const key = selectKey(keys, header.kid);
  if (!key) throw new JwtVerificationError("invalid", "unknown key id");
  return verifyProviderJwtWithKey(
    token,
    header,
    validateKey(key, header.alg),
    checked,
  );
}

async function verifyProviderJwtWithKey(token, header, key, config) {
  const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
  const algorithm = header.alg;

  let cryptoKey;
  try {
    cryptoKey = await crypto.subtle.importKey(
      "jwk",
      key,
      importAlgorithm(algorithm),
      false,
      ["verify"],
    );
  } catch {
    throw new JwtVerificationError("invalid", "unusable verification key");
  }

  const validSignature = await crypto.subtle.verify(
    operationAlgorithm(algorithm),
    cryptoKey,
    b64urlToBytes(encodedSignature),
    new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`),
  ).catch(() => false);
  if (!validSignature) throw new JwtVerificationError("invalid", "signature rejected");

  let claims;
  try {
    const value = JSON.parse(new TextDecoder().decode(b64urlToBytes(encodedPayload)));
    if (!isRecord(value)) throw new Error("claims");
    claims = value;
  } catch {
    throw new JwtVerificationError("invalid", "claims malformed");
  }
  validateClaims(claims, config);

  return Object.freeze({
    provider: config.provider,
    issuer: config.issuer,
    algorithm,
    keyId: header.kid,
    subject: claims.sub,
    claims: Object.freeze({ ...claims }),
    toString: () => "VerifiedJwt([claims redacted])",
  });
}

function checkConfig(config) {
  const cacheTtlMs = config.cacheTtlMs ?? MAX_CACHE_TTL_MS;
  const httpTimeoutMs = config.httpTimeoutMs ?? 5_000;
  const clockSkewSeconds = config.clockSkewSeconds ?? 30;
  const maxTokenBytes = config.maxTokenBytes ?? 16 * 1024;
  const maxJwksBytes = config.maxJwksBytes ?? 1024 * 1024;

  let url;
  try {
    url = new URL(config.jwksUrl);
  } catch {
    throw new JwtVerificationError("configuration", "invalid JWKS URL");
  }

  if (url.protocol !== "https:" && !(config.allowInsecureHttp && url.protocol === "http:")) {
    throw new JwtVerificationError("configuration", "JWKS URL must use HTTPS");
  }
  if (
    !config.provider?.trim() ||
    !config.issuer?.trim() ||
    !Array.isArray(config.audiences) ||
    config.audiences.length === 0 ||
    config.audiences.some((value) => typeof value !== "string" || !value.trim()) ||
    !Array.isArray(config.allowedAlgorithms) ||
    config.allowedAlgorithms.length === 0 ||
    config.allowedAlgorithms.some((value) => value !== "ES256" && value !== "RS256") ||
    cacheTtlMs <= 0 ||
    cacheTtlMs > MAX_CACHE_TTL_MS ||
    httpTimeoutMs <= 0 ||
    clockSkewSeconds < 0 ||
    maxTokenBytes <= 0 ||
    maxJwksBytes <= 0 ||
    maxJwksBytes > MAX_JWKS_BYTES ||
    (config.maxTokenAgeSeconds !== undefined && config.maxTokenAgeSeconds <= 0)
  ) {
    throw new JwtVerificationError("configuration", "invalid verifier policy");
  }

  return Object.freeze({
    provider: config.provider,
    issuer: config.issuer,
    audiences: [...config.audiences],
    jwksUrl: config.jwksUrl,
    allowedAlgorithms: [...new Set(config.allowedAlgorithms)],
    cacheTtlMs,
    httpTimeoutMs,
    clockSkewSeconds,
    requireIssuedAt: config.requireIssuedAt ?? true,
    requireNotBefore: config.requireNotBefore ?? false,
    maxTokenAgeSeconds: config.maxTokenAgeSeconds,
    maxTokenBytes,
    maxJwksBytes,
    fetchImpl: config.fetchImpl ?? fetch,
    nowSeconds: config.nowSeconds ?? (() => Date.now() / 1000),
  });
}

function parseHeader(token, config) {
  if (typeof token !== "string" || !token || token.length > config.maxTokenBytes) {
    throw new JwtVerificationError("invalid", "malformed compact token");
  }
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) {
    throw new JwtVerificationError("invalid", "malformed compact token");
  }

  let header;
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
  } catch {
    throw new JwtVerificationError("invalid", "invalid header");
  }
  if (!isRecord(header)) throw new JwtVerificationError("invalid", "invalid header");
  if (!config.allowedAlgorithms.includes(header.alg)) {
    throw new JwtVerificationError("invalid", "algorithm not allowed");
  }
  if (typeof header.kid !== "string" || !header.kid) {
    throw new JwtVerificationError("invalid", "missing key id");
  }
  if (header.typ !== undefined && header.typ !== "JWT") {
    throw new JwtVerificationError("invalid", "unexpected token type");
  }
  return header;
}

function validateKey(key, algorithm) {
  if (key.use !== undefined && key.use !== "sig") {
    throw new JwtVerificationError("invalid", "key not allowed for signatures");
  }
  if (key.key_ops !== undefined && (!Array.isArray(key.key_ops) || !key.key_ops.includes("verify"))) {
    throw new JwtVerificationError("invalid", "key not allowed for verification");
  }
  if (key.alg !== undefined && key.alg !== algorithm) {
    throw new JwtVerificationError("invalid", "key algorithm mismatch");
  }
  if (hasPrivateKeyMaterial(key)) {
    throw new JwtVerificationError("unavailable", "JWKS exposes private key material");
  }

  const validShape = algorithm === "ES256"
    ? key.kty === "EC" && key.crv === "P-256" && typeof key.x === "string" && typeof key.y === "string"
    : key.kty === "RSA" && typeof key.n === "string" && typeof key.e === "string";
  if (!validShape) throw new JwtVerificationError("invalid", "key type mismatch");

  if (algorithm === "ES256") {
    if (b64urlToBytes(key.x).byteLength !== 32 || b64urlToBytes(key.y).byteLength !== 32) {
      throw new JwtVerificationError("invalid", "key type mismatch");
    }
  } else {
    const modulus = b64urlToBytes(key.n);
    const exponent = b64urlToBytes(key.e);
    if (modulus.byteLength < 256 || exponent.byteLength === 0 || exponent.byteLength > 4) {
      throw new JwtVerificationError("invalid", "key type mismatch");
    }
  }
  return key;
}

function validateJwksDocument(value) {
  if (!isRecord(value) || !Array.isArray(value.keys)) {
    throw new JwtVerificationError("unavailable", "JWKS contains an invalid key set");
  }
  if (value.keys.length === 0 || value.keys.length > 64) {
    throw new JwtVerificationError("unavailable", "JWKS contains an invalid key count");
  }

  const seenKeyIds = new Set();
  for (const key of value.keys) {
    if (
      !isJsonWebKey(key) ||
      typeof key.kid !== "string" ||
      !key.kid ||
      hasPrivateKeyMaterial(key)
    ) {
      throw new JwtVerificationError("unavailable", "JWKS contains an invalid key");
    }
    if (seenKeyIds.has(key.kid)) {
      throw new JwtVerificationError("unavailable", "JWKS contains a duplicate key id");
    }
    seenKeyIds.add(key.kid);
  }
  return value.keys;
}

function hasPrivateKeyMaterial(key) {
  return ["d", "p", "q", "dp", "dq", "qi", "oth"].some((name) =>
    Object.hasOwn(key, name)
  );
}

function selectKey(keys, keyId) {
  if (!Array.isArray(keys)) {
    throw new JwtVerificationError("unavailable", "JWKS contains an invalid key set");
  }
  const matches = keys.filter((candidate) => candidate?.kid === keyId);
  if (matches.length > 1) {
    throw new JwtVerificationError("unavailable", "JWKS contains a duplicate key id");
  }
  return matches[0];
}

function validateClaims(claims, config) {
  const now = config.nowSeconds();
  const skew = config.clockSkewSeconds;

  if (claims.iss !== config.issuer) throw new JwtVerificationError("invalid", "issuer rejected");
  if (!audienceMatches(claims.aud, config.audiences)) {
    throw new JwtVerificationError("invalid", "audience rejected");
  }
  if (typeof claims.sub !== "string" || !claims.sub || claims.sub.length > 1024) {
    throw new JwtVerificationError("invalid", "subject rejected");
  }

  const exp = numericDate(claims.exp);
  if (exp === null || exp <= now - skew) throw new JwtVerificationError("invalid", "token expired");

  const nbf = numericDate(claims.nbf);
  if (config.requireNotBefore && nbf === null) {
    throw new JwtVerificationError("invalid", "missing not-before claim");
  }
  if (nbf !== null && nbf > now + skew) {
    throw new JwtVerificationError("invalid", "token not active");
  }

  const iat = numericDate(claims.iat);
  if (config.requireIssuedAt && iat === null) {
    throw new JwtVerificationError("invalid", "missing issued-at claim");
  }
  if (iat !== null && iat > now + skew) {
    throw new JwtVerificationError("invalid", "issued-at is in the future");
  }
  if (config.maxTokenAgeSeconds !== undefined) {
    if (iat === null || now - iat > config.maxTokenAgeSeconds + skew) {
      throw new JwtVerificationError("invalid", "token is older than policy");
    }
  }
}

function audienceMatches(value, expected) {
  if (typeof value === "string") return expected.includes(value);
  return Array.isArray(value) &&
    value.some((item) => typeof item === "string" && expected.includes(item));
}

function numericDate(value) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function importAlgorithm(algorithm) {
  return algorithm === "ES256"
    ? { name: "ECDSA", namedCurve: "P-256" }
    : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
}

function operationAlgorithm(algorithm) {
  return algorithm === "ES256"
    ? { name: "ECDSA", hash: "SHA-256" }
    : { name: "RSASSA-PKCS1-v1_5" };
}

async function readBoundedBody(response, maxBytes) {
  const contentLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    throw new JwtVerificationError("unavailable", "JWKS response too large");
  }
  if (!response.body) throw new JwtVerificationError("unavailable", "JWKS body missing");

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        throw new JwtVerificationError("unavailable", "JWKS response too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isJsonWebKey(value) {
  return isRecord(value) && typeof value.kty === "string";
}

export function b64urlToBytes(value) {
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
    const bytes = new Uint8Array(new ArrayBuffer(binary.length));
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    throw new JwtVerificationError("invalid", "invalid base64url");
  }
}
