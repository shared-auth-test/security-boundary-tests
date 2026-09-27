import {
  HOP_BY_HOP_HEADERS,
  ORIGIN_DISCLOSURE_RESPONSE_HEADERS,
  SPOOFABLE_REQUEST_HEADERS,
  normalizedPathPrefix,
  publicHeaders,
} from "./domain-contract.mjs";

export function sanitizedGatewayRequest(request, incoming, route) {
  const headers = dynamicRequestHeaders(request.headers, incoming, route, false);
  return new Request(request, { headers });
}

export function dynamicRequestHeaders(incomingHeaders, incoming, route, preserveUpgrade) {
  const headers = new Headers(incomingHeaders);
  const connectionTokens = connectionHeaderTokens(headers);
  for (const name of [...headers.keys()]) {
    const lower = name.toLowerCase();
    if (
      HOP_BY_HOP_HEADERS.has(lower)
      || connectionTokens.has(lower)
      || SPOOFABLE_REQUEST_HEADERS.has(lower)
      || lower === "content-length"
      || lower === "expect"
      || lower.startsWith("cf-access-")
      || lower.startsWith("x-auth-")
      || lower.startsWith("x-forwarded-")
      || lower.startsWith("x-ores-")
    ) {
      headers.delete(name);
    }
  }

  if (preserveUpgrade) headers.set("upgrade", "websocket");
  headers.set("x-forwarded-host", incoming.hostname.toLowerCase());
  headers.set("x-forwarded-port", "443");
  headers.set("x-forwarded-proto", "https");
  headers.set("x-ores-public-host", incoming.hostname.toLowerCase());
  headers.set("x-ores-public-service", route.service);
  headers.set("x-ores-public-surface", route.surface);
  return headers;
}

export function dynamicResponse(response, incoming, route, selectedOrigin, originName) {
  if (response.status === 101) return response;

  const headers = new Headers(response.headers);
  stripHopByHop(headers);
  for (const name of ORIGIN_DISCLOSURE_RESPONSE_HEADERS) headers.delete(name);
  for (const name of [...headers.keys()]) {
    const lower = name.toLowerCase();
    if (lower.startsWith("x-envoy-") || lower.startsWith("x-upstream-")) {
      headers.delete(name);
    }
  }
  headers.delete("refresh");
  headers.delete("cdn-cache-control");
  headers.delete("cloudflare-cdn-cache-control");
  headers.delete("surrogate-control");
  headers.set("cache-control", "no-store");

  rewriteResponseUrlHeader(headers, "location", selectedOrigin, incoming);
  rewriteResponseUrlHeader(headers, "content-location", selectedOrigin, incoming);
  rewriteLinkHeader(headers, selectedOrigin, incoming);
  rewriteCorsOrigin(headers, selectedOrigin, incoming);
  rewriteSetCookies(headers, incoming.hostname.toLowerCase(), selectedOrigin);

  if (originName) headers.set("x-ores-origin", originName);
  for (const [name, value] of Object.entries(publicHeaders(incoming, route))) {
    headers.set(name, value);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export function originForResponse(response, origins) {
  const name = response.headers.get("x-ores-origin");
  return name ? origins.find((origin) => origin.name === name) : undefined;
}

export function stripHopByHop(headers) {
  const connectionTokens = connectionHeaderTokens(headers);
  for (const name of new Set([...HOP_BY_HOP_HEADERS, ...connectionTokens])) {
    headers.delete(name);
  }
}

export function isWebSocketUpgrade(request) {
  return request.method === "GET"
    && (request.headers.get("upgrade") ?? "").trim().toLowerCase() === "websocket";
}

export function rewriteStaticUrl(raw, target, incoming, route) {
  let resolved;
  try {
    resolved = new URL(raw, target);
  } catch {
    return null;
  }
  if (resolved.protocol !== "https:" || resolved.username || resolved.password) return null;

  const siteOrigin = new URL(target);
  if (resolved.origin !== siteOrigin.origin) return raw;
  const routePrefix = normalizedPathPrefix(route.sitePath);
  const path = resolved.pathname === routePrefix
    ? "/"
    : resolved.pathname.startsWith(`${routePrefix}/`)
      ? resolved.pathname.slice(routePrefix.length)
      : resolved.pathname;
  return `${incoming.origin}${path}${resolved.search}${resolved.hash}`;
}

function rewriteResponseUrlHeader(headers, name, selectedOrigin, incoming) {
  const raw = headers.get(name);
  if (!raw) return;
  const rewritten = rewritePublicUrl(raw, selectedOrigin, incoming);
  if (rewritten === null) headers.delete(name);
  else headers.set(name, rewritten);
}

function rewriteLinkHeader(headers, selectedOrigin, incoming) {
  const raw = headers.get("link");
  if (!raw || !selectedOrigin) return;
  let invalid = false;
  const rewrittenHeader = raw.replace(/<([^>]+)>/g, (_match, value) => {
    const rewritten = rewritePublicUrl(value, selectedOrigin, incoming);
    if (rewritten === null) {
      invalid = true;
      return "";
    }
    return `<${rewritten}>`;
  });
  if (invalid) headers.delete("link");
  else headers.set("link", rewrittenHeader);
}

function rewritePublicUrl(raw, selectedOrigin, incoming) {
  let resolved;
  try {
    resolved = new URL(raw, selectedOrigin ?? incoming.origin);
  } catch {
    return null;
  }
  if (resolved.protocol !== "https:" || resolved.username || resolved.password) return null;
  if (!selectedOrigin) {
    return resolved.origin === incoming.origin ? resolved.toString() : raw;
  }

  const origin = new URL(selectedOrigin);
  if (resolved.origin !== origin.origin) return raw;
  const prefix = normalizedPathPrefix(origin.pathname);
  if (prefix && resolved.pathname !== prefix && !resolved.pathname.startsWith(`${prefix}/`)) {
    return null;
  }
  resolved.protocol = "https:";
  resolved.host = incoming.host;
  resolved.pathname = prefix ? resolved.pathname.slice(prefix.length) || "/" : resolved.pathname;
  return resolved.toString();
}

function rewriteCorsOrigin(headers, selectedOrigin, incoming) {
  if (!selectedOrigin) return;
  const value = headers.get("access-control-allow-origin");
  if (value === new URL(selectedOrigin).origin) {
    headers.set("access-control-allow-origin", incoming.origin);
  }
}

function rewriteSetCookies(headers, publicHostname, selectedOrigin) {
  const getSetCookie = headers.getSetCookie;
  const cookies = typeof getSetCookie === "function"
    ? getSetCookie.call(headers)
    : (headers.get("set-cookie") ? [headers.get("set-cookie")] : []);
  if (cookies.length === 0) return;

  headers.delete("set-cookie");
  const originPrefix = selectedOrigin
    ? normalizedPathPrefix(new URL(selectedOrigin).pathname)
    : "";
  for (const cookie of cookies) {
    const hardened = hardenCookie(cookie, publicHostname, originPrefix);
    if (hardened) headers.append("set-cookie", hardened);
  }
}

function hardenCookie(cookie, publicHostname, originPrefix) {
  const parts = cookie.split(";").map((part) => part.trim()).filter(Boolean);
  if (parts.length === 0 || !parts[0].includes("=") || !publicHostname) return null;

  const cookieName = parts[0].slice(0, parts[0].indexOf("="));
  const hostPrefix = cookieName.startsWith("__Host-");
  const output = [parts[0]];
  let secure = false;
  let sameSite = false;
  let pathWritten = false;

  for (const part of parts.slice(1)) {
    const separator = part.indexOf("=");
    const attribute = (separator === -1 ? part : part.slice(0, separator)).trim().toLowerCase();
    const value = separator === -1 ? "" : part.slice(separator + 1).trim();

    if (attribute === "domain") continue;
    if (attribute === "secure") secure = true;
    if (attribute === "samesite") sameSite = true;
    if (attribute === "path") {
      if (pathWritten) continue;
      output.push(`Path=${hostPrefix ? "/" : rewriteCookiePath(value, originPrefix)}`);
      pathWritten = true;
      continue;
    }
    output.push(part);
  }

  if (hostPrefix && !pathWritten) output.push("Path=/");
  if (!secure) output.push("Secure");
  if (!sameSite) output.push("SameSite=Lax");
  return output.join("; ");
}

function rewriteCookiePath(value, originPrefix) {
  if (!value.startsWith("/")) return "/";
  if (!originPrefix) return value;
  if (value === originPrefix) return "/";
  if (value.startsWith(`${originPrefix}/`)) return value.slice(originPrefix.length) || "/";
  return value;
}

function connectionHeaderTokens(headers) {
  return new Set((headers.get("connection") ?? "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean));
}
