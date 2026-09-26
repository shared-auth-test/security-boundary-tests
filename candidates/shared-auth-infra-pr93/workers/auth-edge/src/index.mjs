const DEFAULT_SESSION_COOKIE = "__Host-ore_session";
const DEFAULT_REFRESH_COOKIE = "__Host-ore_refresh";
const IDENTITY_HEADERS = Object.freeze([
  "x-auth-user-id",
  "x-auth-email",
  "x-auth-project",
  "x-auth-provider",
  "x-auth-provider-tenant",
  "x-auth-roles",
]);

let memoryJwks = { fetchedAt: 0, keys: [] };

export default {
  async fetch(request, env, context) {
    const startedAt = Date.now();
    let config;
    try {
      config = loadConfig(env);
    } catch {
      return json({ error: "edge_misconfigured" }, 503);
    }

    const url = new URL(request.url);
    const cleanHeaders = sanitizedHeaders(request.headers);
    const traceparent = ensureTraceContext(cleanHeaders);

    if (!isProtected(url.pathname, config) || isPublic(url.pathname, config)) {
      const response = await fetch(new Request(request, { headers: cleanHeaders }));
      recordRequest(context, request, url, response, traceparent, startedAt, false);
      return response;
    }

    const resolved = await resolveSession(request, config, context, traceparent).catch(() => null);
    if (!resolved) {
      const response = unauthorized(request, url, config);
      if (cookie(request.headers, config.sessionCookie)
          || cookie(request.headers, config.refreshCookie)) {
        for (const value of clearSessionCookies(config)) response.headers.append("set-cookie", value);
      }
      recordRequest(context, request, url, response, traceparent, startedAt, false);
      return response;
    }

    cleanHeaders.set("x-auth-user-id", resolved.claims.sub);
    cleanHeaders.set("x-auth-provider", resolved.claims.provider);
    cleanHeaders.set("x-auth-provider-tenant", resolved.claims.provider_tenant);
    cleanHeaders.set("x-auth-roles", (resolved.claims.roles || []).join(","));
    if (resolved.claims.project) cleanHeaders.set("x-auth-project", resolved.claims.project);
    if (resolved.claims.email) cleanHeaders.set("x-auth-email", resolved.claims.email);
    cleanHeaders.delete("x-supabase-token");

    const originResponse = await fetch(new Request(request, { headers: cleanHeaders }));
    recordRequest(context, request, url, originResponse, traceparent, startedAt, true);
    if (!resolved.setCookies?.length) return originResponse;
    const output = new Response(originResponse.body, originResponse);
    for (const value of resolved.setCookies) output.headers.append("set-cookie", value);
    return output;
  },
};

export function loadConfig(env) {
  const authBase = requiredHttpsUrl(env.SHARED_AUTH_BASE, "SHARED_AUTH_BASE");
  const issuer = requiredHttpsUrl(env.AUTH_ISSUER, "AUTH_ISSUER");
  const audience = String(env.AUTH_AUDIENCE || "").trim();
  if (!audience || audience.length > 255) throw new Error("invalid audience");

  const loginUrl = env.LOGIN_URL
    ? requiredHttpsUrl(env.LOGIN_URL, "LOGIN_URL")
    : null;
  const loginPath = normalizePath(env.LOGIN_PATH || "/auth/sign-in");
  const sessionCookie = cookieName(env.SESSION_COOKIE_NAME || DEFAULT_SESSION_COOKIE);
  const refreshCookie = cookieName(env.REFRESH_COOKIE_NAME || DEFAULT_REFRESH_COOKIE);
  if (sessionCookie === refreshCookie) throw new Error("session and refresh cookies must differ");

  return {
    authBase: authBase.replace(/\/$/, ""),
    jwksUrl: requiredHttpsUrl(
      env.SHARED_AUTH_JWKS_URL || `${authBase.replace(/\/$/, "")}/.well-known/jwks.json`,
      "SHARED_AUTH_JWKS_URL",
    ),
    issuer,
    audience,
    loginUrl,
    loginPath,
    sessionCookie,
    refreshCookie,
    refreshPath: normalizePath(env.REFRESH_PATH || "/auth/refresh"),
    protectedPrefixes: prefixes(env.PROTECTED_PATH_PREFIXES || "/"),
    publicPrefixes: prefixes(env.PUBLIC_PATH_PREFIXES || "/shared-auth/,/auth/"),
    jwksTtl: boundedNumber(env.JWKS_TTL_SECONDS, 300, 30, 3600),
    staleGrace: boundedNumber(env.JWKS_STALE_GRACE_SECONDS, 3600, 60, 86_400),
    accessCookieMaxAge: boundedNumber(env.ACCESS_COOKIE_MAX_AGE_SECONDS, 900, 60, 86_400),
    refreshCookieMaxAge: boundedNumber(
      env.REFRESH_COOKIE_MAX_AGE_SECONDS,
      2_592_000,
      300,
      31_536_000,
    ),
    // Compatibility configuration retained for existing deployments. Direct
    // provider fallback is not activated without durable reconciliation.
    supabaseUrl: env.SUPABASE_URL
      ? requiredHttpsUrl(env.SUPABASE_URL, "SUPABASE_URL").replace(/\/$/, "")
      : null,
    supabaseProject: env.SUPABASE_PROJECT ? String(env.SUPABASE_PROJECT).trim() : null,
    supabaseApiKey: env.SUPABASE_API_KEY ? String(env.SUPABASE_API_KEY).trim() : null,
    raceDeadlineMs: boundedNumber(env.RACE_DEADLINE_MS, 1500, 100, 10_000),
  };
}

async function resolveSession(request, config, context, traceparent) {
  const authorization = bearer(request.headers);
  if (authorization) {
    const claims = await verifyAgainstCurrentJwks(authorization, config, context).catch(() => null);
    // A caller-supplied bearer credential is authoritative. Never fall back to
    // cookies when it is malformed, expired, or for another audience.
    return claims ? { claims, authority: "shared-auth-bearer" } : null;
  }

  const accessToken = cookie(request.headers, config.sessionCookie);
  if (accessToken) {
    const claims = await verifyAgainstCurrentJwks(accessToken, config, context).catch(() => null);
    if (claims) return { claims, authority: "shared-auth-cookie" };
  }

  const refreshToken = cookie(request.headers, config.refreshCookie);
  if (refreshToken && refreshToken.length <= 1024) {
    const refreshed = await refreshAtSharedAuth(
      refreshToken,
      config,
      context,
      traceparent,
    ).catch(() => null);
    if (refreshed) return refreshed;
  }

  const supabaseToken = request.headers.get("x-supabase-token")
    || cookie(request.headers, "sb-access-token");
  if (!supabaseToken || supabaseToken.length > 16 * 1024) return null;

  // Exchange creates a session. It must have one execution path, never a
  // losing mutation behind a direct-provider race. Read-only optimistic
  // verification requires the auth-policy contract and durable reconciliation
  // before it can be activated here (infra #63 / DEN-2194).
  return exchangeAtSharedAuth(supabaseToken, config, context, traceparent);
}

async function exchangeAtSharedAuth(supabaseToken, config, context, traceparent) {
  const exchange = await fetch(`${config.authBase}/auth/exchange`, {
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(config.raceDeadlineMs),
    headers: { authorization: `Bearer ${supabaseToken}`, traceparent },
  });
  if (!exchange.ok) throw new Error(`exchange ${exchange.status}`);
  const body = await boundedJson(exchange);
  if (typeof body.access_token !== "string") throw new Error("exchange body");
  const claims = await verifyAgainstCurrentJwks(body.access_token, config, context);
  return {
    claims,
    authority: "shared-auth",
    setCookies: sessionCookieHeaders(body, claims, config),
  };
}

async function refreshAtSharedAuth(refreshToken, config, context, traceparent) {
  const response = await fetch(`${config.authBase}${config.refreshPath}`, {
    method: "POST",
    redirect: "error",
    headers: {
      "content-type": "application/json",
      traceparent,
    },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  if (!response.ok) throw new Error(`refresh ${response.status}`);
  const body = await boundedJson(response);
  if (typeof body.access_token !== "string" || typeof body.refresh_token !== "string") {
    throw new Error("refresh body");
  }
  const claims = await verifyAgainstCurrentJwks(body.access_token, config, context);
  return {
    claims,
    authority: "shared-auth-refresh",
    setCookies: sessionCookieHeaders(body, claims, config),
  };
}

async function boundedJson(response) {
  const length = Number(response.headers.get("content-length") || 0);
  if (length > 64 * 1024) throw new Error("oversized response");
  const text = await response.text();
  if (text.length > 64 * 1024) throw new Error("oversized response");
  return JSON.parse(text);
}

export function sessionCookieHeaders(body, claims, config) {
  const now = Math.floor(Date.now() / 1000);
  const accessMaxAge = Math.max(
    1,
    Math.min(config.accessCookieMaxAge, claims.exp - now),
  );
  const cookies = [secureHostCookie(config.sessionCookie, body.access_token, accessMaxAge)];
  if (typeof body.refresh_token === "string" && body.refresh_token) {
    const refreshExpiry = Number(body.refresh_expires_at || 0);
    const refreshMaxAge = refreshExpiry > now
      ? Math.min(config.refreshCookieMaxAge, refreshExpiry - now)
      : config.refreshCookieMaxAge;
    cookies.push(secureHostCookie(config.refreshCookie, body.refresh_token, refreshMaxAge));
  }
  return cookies;
}

export function clearSessionCookies(config) {
  return [
    secureHostCookie(config.sessionCookie, "", 0),
    secureHostCookie(config.refreshCookie, "", 0),
  ];
}

function secureHostCookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.max(0, Math.floor(maxAge))}`;
}

// Compatibility scheduling utility only; not a proof-policy evaluator and
// deliberately not used by resolveSession for session-creating exchanges.
export function raceSessionArms(arms, deadlineMs) {
  if (!arms.length) return Promise.resolve(null);
  return new Promise((resolve) => {
    let pending = arms.length;
    let settled = false;
    const finish = (value) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(value);
      }
    };
    const timer = setTimeout(() => finish(null), deadlineMs);
    for (const arm of arms) {
      Promise.resolve().then(arm).then(
        (value) => {
          if (value) finish(value);
          else if (--pending === 0) finish(null);
        },
        () => {
          if (--pending === 0) finish(null);
        },
      );
    }
  });
}

async function verifyAgainstCurrentJwks(token, config, context) {
  const keys = await getJwks(config, context);
  return verifyJwt(token, config, keys);
}

export async function verifyJwt(token, config, keys) {
  if (typeof token !== "string" || token.length > 16 * 1024) throw new Error("invalid token");
  const segments = token.split(".");
  if (segments.length !== 3 || segments.some((segment) => !segment)) throw new Error("malformed");
  const [encodedHeader, encodedClaims, encodedSignature] = segments;
  const header = decodeJson(encodedHeader);
  const claims = decodeJson(encodedClaims);
  if (header.alg !== "ES256" || (header.typ && header.typ !== "JWT")) throw new Error("algorithm");
  if (typeof header.kid !== "string" || !header.kid) throw new Error("kid");
  const jwk = keys.find((candidate) => candidate.kid === header.kid);
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256" || jwk.alg !== "ES256") {
    throw new Error("unknown key");
  }
  const now = Math.floor(Date.now() / 1000);
  if (claims.iss !== config.issuer || !audienceContains(claims.aud, config.audience)) {
    throw new Error("issuer or audience");
  }
  if (!Number.isInteger(claims.exp) || claims.exp <= now - 30) throw new Error("expired");
  if (Number.isInteger(claims.nbf) && claims.nbf > now + 30) throw new Error("not active");
  if (Number.isInteger(claims.iat) && claims.iat > now + 30) throw new Error("future token");
  if (typeof claims.sub !== "string" || !claims.sub || claims.sub.length > 512) throw new Error("sub");
  if (typeof claims.provider !== "string" || typeof claims.provider_tenant !== "string") {
    throw new Error("provider provenance");
  }
  if (!Array.isArray(claims.roles) || !claims.roles.every((role) => typeof role === "string")) {
    throw new Error("roles");
  }
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, ext: true },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const verified = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    decodeBase64Url(encodedSignature),
    new TextEncoder().encode(`${encodedHeader}.${encodedClaims}`),
  );
  if (!verified) throw new Error("signature");
  return claims;
}

async function getJwks(config, context) {
  const now = Math.floor(Date.now() / 1000);
  if (memoryJwks.keys.length && now - memoryJwks.fetchedAt < config.jwksTtl) {
    return memoryJwks.keys;
  }
  try {
    const response = await fetch(config.jwksUrl, {
      redirect: "error",
      cf: { cacheTtl: config.jwksTtl, cacheEverything: true },
    });
    if (!response.ok || Number(response.headers.get("content-length") || 0) > 1024 * 1024) {
      throw new Error("JWKS unavailable");
    }
    const body = await boundedJson(response);
    if (!Array.isArray(body.keys) || body.keys.length < 1 || body.keys.length > 16) {
      throw new Error("invalid JWKS");
    }
    memoryJwks = { fetchedAt: now, keys: body.keys };
    return body.keys;
  } catch (error) {
    if (memoryJwks.keys.length && now - memoryJwks.fetchedAt <= config.staleGrace) {
      return memoryJwks.keys;
    }
    throw error;
  }
}

export function sanitizedHeaders(input) {
  const headers = new Headers(input);
  for (const name of headers.keys()) {
    if (name.toLowerCase().startsWith("x-auth-")) headers.delete(name);
  }
  for (const name of IDENTITY_HEADERS) headers.delete(name);
  headers.delete("x-supabase-token");
  return headers;
}

export function ensureTraceContext(headers) {
  const existing = headers.get("traceparent") || "";
  if (/^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/.test(existing)
      && !/^00-0{32}-0{16}-/.test(existing)) {
    return existing;
  }
  const traceId = randomHex(16);
  const spanId = randomHex(8);
  const traceparent = `00-${traceId}-${spanId}-01`;
  headers.set("traceparent", traceparent);
  return traceparent;
}

function randomHex(bytes) {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return [...value].map((item) => item.toString(16).padStart(2, "0")).join("");
}

function recordRequest(context, request, url, response, traceparent, startedAt, authenticated) {
  const traceId = traceparent.split("-")[1];
  const event = {
    timestamp: new Date().toISOString(),
    severity: "INFO",
    service: "shared-auth-edge",
    event: "http.request",
    trace_id: traceId,
    method: request.method,
    path: url.pathname,
    status: response.status,
    duration_ms: Date.now() - startedAt,
    authenticated,
  };
  const emit = Promise.resolve().then(() => console.log(JSON.stringify(event)));
  if (context?.waitUntil) context.waitUntil(emit);
}

function unauthorized(request, url, config) {
  const acceptsHtml = (request.headers.get("accept") || "").includes("text/html");
  if (!acceptsHtml) return json({ error: "unauthorized" }, 401);
  return Response.redirect(buildLoginRedirect(url, config), 302);
}

export function buildLoginRedirect(requestUrl, config) {
  const destination = config.loginUrl
    ? new URL(config.loginUrl)
    : new URL(config.loginPath, requestUrl.origin);
  destination.searchParams.set("return", `${requestUrl.pathname}${requestUrl.search}`);
  return destination.toString();
}

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

function isProtected(path, config) {
  return config.protectedPrefixes.some((prefix) => path.startsWith(prefix));
}

function isPublic(path, config) {
  return path === config.loginPath || config.publicPrefixes.some((prefix) => path.startsWith(prefix));
}

function bearer(headers) {
  const value = headers.get("authorization") || "";
  if (!value.startsWith("Bearer ")) return null;
  const token = value.slice(7).trim();
  return token && token.length <= 16 * 1024 ? token : null;
}

function cookie(headers, name) {
  for (const item of (headers.get("cookie") || "").split(";")) {
    const [key, ...value] = item.trim().split("=");
    if (key === name) return value.join("=") || null;
  }
  return null;
}

function decodeJson(segment) {
  const bytes = decodeBase64Url(segment);
  if (bytes.byteLength > 12 * 1024) throw new Error("oversized claims");
  return JSON.parse(new TextDecoder().decode(bytes));
}

function decodeBase64Url(input) {
  if (!/^[A-Za-z0-9_-]+$/.test(input)) throw new Error("invalid base64url");
  const binary = atob(input.replace(/-/g, "+").replace(/_/g, "/")
    .padEnd(Math.ceil(input.length / 4) * 4, "="));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function audienceContains(actual, expected) {
  return actual === expected || (Array.isArray(actual) && actual.includes(expected));
}

function prefixes(raw) {
  const parsed = String(raw).split(",")
    .map((value) => normalizePath(value.trim()))
    .filter(Boolean);
  if (!parsed.length) throw new Error("empty prefixes");
  return parsed;
}

function normalizePath(value) {
  if (!value.startsWith("/") || value.includes("\\") || value.includes("\0")) {
    throw new Error("invalid path");
  }
  return value;
}

function cookieName(value) {
  const name = String(value || "").trim();
  if (!name.startsWith("__Host-")
      || name.length > 128
      || !/^[A-Za-z0-9_-]+$/.test(name)) {
    throw new Error("invalid __Host- cookie name");
  }
  return name;
}

function requiredHttpsUrl(value, name) {
  const raw = String(value || "").trim();
  const url = new URL(raw);
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw new Error(`${name} must use a credential-free HTTPS URL`);
  }
  return raw;
}

function boundedNumber(raw, fallback, minimum, maximum) {
  const value = raw == null || raw === "" ? fallback : Number(raw);
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error("invalid number");
  }
  return Math.floor(value);
}
