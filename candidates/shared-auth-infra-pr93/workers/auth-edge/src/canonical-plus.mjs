import authEdge from "./index.mjs";

const DEFAULT_API_HOST = "api.canonical.plus";
const INTERNAL_HEADER_PREFIX = "x-canonical-";

export default {
  async fetch(request, env, context) {
    return authEdge.fetch(prepareCanonicalRequest(request, env), env, context);
  },
};

/**
 * Canonical's API hostname is bearer-only. Browser cookies are deliberately
 * host-bound to app.canonical.plus and must never become an alternate API
 * credential, even when a non-browser caller supplies a Cookie header by hand.
 *
 * Canonical's service-to-service header namespace is also origin-controlled.
 * The edge removes every caller-supplied x-canonical-* header on both app and
 * API traffic before the generic Shared Auth Worker processes the request.
 *
 * Forcing a non-HTML Accept value also keeps unauthenticated API traffic on a
 * stable 401 JSON contract rather than redirecting an SDK or WebSocket client
 * to the browser sign-in ceremony.
 */
export function prepareCanonicalRequest(request, env = {}) {
  const url = new URL(request.url);
  const apiHost = canonicalHost(env.CANONICAL_API_HOST || DEFAULT_API_HOST);
  const headers = new Headers(request.headers);
  const strippedInternalHeaders = stripHeaderPrefix(headers, INTERNAL_HEADER_PREFIX);

  if (url.hostname.toLowerCase() !== apiHost) {
    return strippedInternalHeaders ? new Request(request, { headers }) : request;
  }

  headers.set("accept", "application/json");
  headers.delete("cookie");
  headers.delete("x-supabase-token");
  return new Request(request, { headers });
}

function stripHeaderPrefix(headers, prefix) {
  let changed = false;
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith(prefix)) {
      headers.delete(name);
      changed = true;
    }
  }
  return changed;
}

function canonicalHost(raw) {
  const value = String(raw || "").trim().toLowerCase();
  if (!value
      || value.length > 253
      || value.includes("/")
      || value.includes(":")
      || value.startsWith(".")
      || value.endsWith(".")
      || !/^[a-z0-9.-]+$/.test(value)) {
    throw new Error("CANONICAL_API_HOST must be a bare DNS hostname");
  }
  return value;
}
