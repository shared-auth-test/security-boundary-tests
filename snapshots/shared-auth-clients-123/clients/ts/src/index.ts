// Thin typed client for the shared-auth server HTTP API (see ../../ENDPOINTS.md).
// Fetch-based: Node 18+, Workers, Deno, Bun, browsers.

export interface ExchangeResponse {
  access_token: string;
  token_type: string;
  expires_at: number;
  shared_user_id: string;
  project?: string | null;
  provider?: string | null;
  provider_tenant?: string | null;
}

export interface SessionResponse {
  access_token: string;
  token_type: string;
  expires_at: number;
  refresh_token: string;
  refresh_expires_at: number;
  shared_user_id: string;
  provider: string;
  roles: string[];
  amr: string[];
  acr?: string | null;
}

export interface PasswordlessAccepted {
  accepted: boolean;
}

export interface DelegateRequest {
  client_id: string;
  audience: string;
  scopes: string[];
}

export interface DelegateResponse {
  access_token: string;
  token_type: string;
  expires_at: number;
  audience: string;
  scope: string;
}

export interface StepUpResponse {
  access_token: string;
  token_type: string;
  expires_at: number;
  amr: string[];
  acr?: string | null;
}

export interface Introspection {
  active: boolean;
  sub?: string;
  iss?: string;
  aud?: string;
  sid?: string;
  project?: string;
  provider?: string;
  provider_tenant?: string;
  provider_subject?: string;
  email?: string;
  email_verified?: boolean;
  roles?: string[];
  aal?: number;
  amr?: string[];
  acr?: string;
  auth_time?: number;
  scope?: string;
  azp?: string;
  parent_jti?: string;
  exp?: number;
  iat?: number;
  nbf?: number;
  [k: string]: unknown;
}

export interface Capabilities {
  mfa_enabled: boolean;
  methods: string[];
  threefa_import_scheme?: string | null;
  biometric_model?: string | null;
}

export interface Factor {
  factor_id: string;
  kind: string;
  label?: string | null;
  enabled: boolean;
  confirmed_at?: string | null;
  last_used_at?: string | null;
  created_at: string;
}

export interface TotpEnrollment {
  factor_id: string;
  secret_base32: string;
  otpauth_uri: string;
  threefa_import_uri: string;
}

export type ChallengeKind = "email_otp" | "sms_otp";

export interface ChallengeStart {
  challenge_id: string;
  expires_at: string;
  delivery: string;
}

export interface CeremonyStart {
  challenge_id: string;
  options: unknown;
  expires_at: string;
}

export interface SharedAuthClientOptions {
  fetch?: typeof fetch;
  /** Backward-compatible alias for `fetch`. */
  fetchImpl?: typeof fetch;
  serviceCredential?: string;
  /** Permit public cleartext only for an explicitly trusted debugging proxy. */
  allowInsecureTransport?: boolean;
  /** End-to-end request deadline, including response-body parsing. */
  timeoutMs?: number;
  /** Maximum encoded request-body size in bytes. */
  maxRequestBytes?: number;
  /** Maximum decoded JSON response size in bytes. */
  maxResponseBytes?: number;
}

export class UnauthorizedError extends Error {
  constructor() {
    super("unauthorized");
    this.name = "UnauthorizedError";
  }
}

export class MissingServiceCredentialError extends Error {
  constructor() {
    super("introspection service credential is required");
    this.name = "MissingServiceCredentialError";
  }
}

export class SharedAuthHttpError extends Error {
  readonly path: string;
  readonly status: number;

  constructor(path: string, status: number) {
    super(`shared-auth ${path}: ${status}`);
    this.name = "SharedAuthHttpError";
    this.path = path;
    this.status = status;
  }
}

export class SharedAuthTransportError extends Error {
  readonly path: string;

  constructor(path: string) {
    super(`shared-auth transport failed at ${path}`);
    this.name = "SharedAuthTransportError";
    this.path = path;
  }
}

export class SharedAuthTimeoutError extends Error {
  readonly path: string;
  readonly timeoutMs: number;

  constructor(path: string, timeoutMs: number) {
    super(`shared-auth request timed out at ${path}`);
    this.name = "SharedAuthTimeoutError";
    this.path = path;
    this.timeoutMs = timeoutMs;
  }
}

export class SharedAuthRequestTooLargeError extends Error {
  readonly path: string;
  readonly maxRequestBytes: number;

  constructor(path: string, maxRequestBytes: number) {
    super(`shared-auth request exceeded ${maxRequestBytes} bytes at ${path}`);
    this.name = "SharedAuthRequestTooLargeError";
    this.path = path;
    this.maxRequestBytes = maxRequestBytes;
  }
}

export class SharedAuthResponseTooLargeError extends Error {
  readonly path: string;
  readonly maxResponseBytes: number;

  constructor(path: string, maxResponseBytes: number) {
    super(`shared-auth response exceeded ${maxResponseBytes} bytes at ${path}`);
    this.name = "SharedAuthResponseTooLargeError";
    this.path = path;
    this.maxResponseBytes = maxResponseBytes;
  }
}

export class SharedAuthDecodeError extends Error {
  readonly path: string;

  constructor(path: string) {
    super(`shared-auth returned invalid JSON at ${path}`);
    this.name = "SharedAuthDecodeError";
    this.path = path;
  }
}

export function hasAssurance(
  introspection: Introspection,
  requiredAcr: string,
): boolean {
  return introspection.active && introspection.acr === requiredAcr;
}

export function usedMethod(
  introspection: Introspection,
  method: string,
): boolean {
  return introspection.active && (introspection.amr?.includes(method) ?? false);
}

export function hasRole(introspection: Introspection, role: string): boolean {
  return introspection.active && (introspection.roles?.includes(role) ?? false);
}

/**
 * The host of `base` when its scheme is cleartext `http://`, else null.
 * Mirrors the check in `3fa-clients`, which is the reference implementation.
 */
function cleartextHttpHost(base: string): string | null {
  if (base.slice(0, 7).toLowerCase() !== "http://") return null;
  const rest = base.slice(7);
  const authority = rest.split(/[/?#]/, 1)[0] ?? "";
  const hostPort = authority.includes("@")
    ? authority.slice(authority.lastIndexOf("@") + 1)
    : authority;
  if (hostPort.startsWith("[")) {
    return hostPort.slice(1, hostPort.indexOf("]")).toLowerCase();
  }
  const colon = hostPort.indexOf(":");
  return (colon === -1 ? hostPort : hostPort.slice(0, colon)).toLowerCase();
}

/** Loopback, private/link-local IPs, and in-cluster names, where TLS may end at a sidecar. */
function cleartextInternalHostAllowed(host: string): boolean {
  if (host === "" || host === "localhost" || host.endsWith(".localhost")) return true;
  if (host === "::1" || /^f[cd]/.test(host) || /^fe[89ab]/.test(host)) return true;
  const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
  }
  // Single-label ("dd-shared-auth") and cluster DNS names never resolve publicly.
  return !host.includes(".") || host.endsWith(".svc.cluster.local") || host.endsWith(".internal");
}


const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_REQUEST_BYTES = 256 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_INTROSPECTION_AUDIENCE = "oresoftware";
const MAX_CREDENTIAL_BYTES = 16 * 1024;
const MAX_TOKEN_BYTES = 16 * 1024;
const MAX_REQUIRED_SCOPES = 64;
const MAX_EMAIL_BYTES = 320;
const MIN_REGISTRATION_PASSWORD_BYTES = 12;
const MAX_PASSWORD_BYTES = 1024;
const MAX_DISPLAY_NAME_BYTES = 160;
const PORTABLE_INTROSPECTION_VALUE = /^[A-Za-z0-9._:/-]+$/;
const EMAIL_OTP = /^[0-9]{6}$/;

export class SharedAuthClient {
  private readonly base: string;
  private readonly doFetch: typeof fetch;
  private readonly timeoutMs: number;
  private readonly maxRequestBytes: number;
  private readonly maxResponseBytes: number;
  private serviceCredential?: string;

  constructor(
    base: string,
    fetchImpl?: typeof fetch | SharedAuthClientOptions,
    serviceCredential?: string,
  );
  constructor(base: string, options?: SharedAuthClientOptions);
  constructor(
    base: string,
    fetchOrOptions?: typeof fetch | SharedAuthClientOptions,
    serviceCredential?: string,
  );
  constructor(base: string, options?: SharedAuthClientOptions);
  constructor(
    base: string,
    fetchOrOptions?: typeof fetch | SharedAuthClientOptions,
    serviceCredential?: string,
  ) {
    const options: SharedAuthClientOptions =
      typeof fetchOrOptions === "function"
        ? { fetch: fetchOrOptions, serviceCredential }
        : (fetchOrOptions ?? {});

    const cleartextHost = cleartextHttpHost(base.trim());
    if (
      cleartextHost !== null &&
      !cleartextInternalHostAllowed(cleartextHost) &&
      !options.allowInsecureTransport
    ) {
      throw new TypeError(
        `shared-auth: refusing cleartext http:// to public host "${cleartextHost}": ` +
          "use an https:// base URL, an in-cluster address, or loopback " +
          "(or opt out explicitly with allowInsecureTransport)",
      );
    }

    this.base = normalizeBase(base, options.allowInsecureTransport ?? false);
    const fetchImpl = options.fetch ?? options.fetchImpl ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new TypeError("a fetch implementation is required");
    }
    this.doFetch = (input, init) => fetchImpl.call(globalThis, input, init);
    this.timeoutMs = positiveInteger(
      options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      "timeoutMs",
    );
    this.maxRequestBytes = positiveInteger(
      options.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES,
      "maxRequestBytes",
    );
    this.maxResponseBytes = positiveInteger(
      options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
      "maxResponseBytes",
    );
    this.serviceCredential = normalizeOptionalCredential(
      options.serviceCredential,
      "serviceCredential",
    );
  }

  /** Configure the service-to-service bearer required by protected introspection. */
  withServiceCredential(credential: string): this {
    return this.copyWithCredential(
      requiredCredential(credential, "serviceCredential"),
    );
  }

  withoutServiceCredential(): this {
    return this.copyWithCredential(undefined);
  }

  /** Return a new client. Never writes [serviceCredential] on `this`. */
  private copyWithCredential(serviceCredential: string | undefined): this {
    return new SharedAuthClient(this.base, {
      fetch: this.doFetch,
      timeoutMs: this.timeoutMs,
      maxRequestBytes: this.maxRequestBytes,
      maxResponseBytes: this.maxResponseBytes,
      serviceCredential,
      allowInsecureTransport: true,
    }) as this;
  }

  /** Provider access token → shared-auth token. Throws UnauthorizedError on 401. */
  async exchange(providerToken: string): Promise<ExchangeResponse> {
    assertToken(providerToken, "invalid provider token");
    return this.requestJson<ExchangeResponse>("/auth/exchange", {
      method: "POST",
      headers: {
        authorization: bearer(providerToken, "providerToken"),
      },
    });
  }

  register(
    email: string,
    password: string,
    displayName?: string,
  ): Promise<SessionResponse> {
    const body: Record<string, unknown> = {
      email: passwordlessEmail(email),
      password: registrationPassword(password),
    };
    const normalizedDisplayName = optionalDisplayName(displayName);
    if (normalizedDisplayName !== undefined) {
      body.display_name = normalizedDisplayName;
    }
    return this.requestJson<SessionResponse>("/auth/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: encodeJson(body),
    });
  }

  login(email: string, password: string): Promise<SessionResponse> {
    return this.requestJson<SessionResponse>("/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: encodeJson({
        email: passwordlessEmail(email),
        password: loginPassword(password),
      }),
    });
  }

  async requestPasswordless(email: string): Promise<PasswordlessAccepted> {
    const path = "/auth/passwordless/request";
    const response = await this.requestJson<PasswordlessAccepted>(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: encodeJson({ email: passwordlessEmail(email) }),
    });
    if (typeof response?.accepted !== "boolean") {
      throw new SharedAuthDecodeError(path);
    }
    return response;
  }

  consumePasswordless(email: string, otp: string): Promise<SessionResponse> {
    return this.requestJson<SessionResponse>("/auth/passwordless/consume", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: encodeJson({
        email: passwordlessEmail(email),
        otp: emailOtp(otp),
      }),
    });
  }

  refresh(refreshToken: string): Promise<SessionResponse> {
    return this.requestJson<SessionResponse>("/auth/refresh", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: encodeJson({
        refresh_token: requiredCredential(refreshToken, "refreshToken"),
      }),
    });
  }

  async logout(refreshToken: string): Promise<void> {
    await this.requestJson<unknown>(
      "/auth/logout",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: encodeJson({
          refresh_token: requiredCredential(refreshToken, "refreshToken"),
        }),
      },
      true,
    );
  }

  /** Missing service credentials fail locally before request fields are parsed. */
  async introspect(
    token: string,
    audience = DEFAULT_INTROSPECTION_AUDIENCE,
    requiredScopes: readonly string[] = [],
  ): Promise<Introspection> {
    const serviceCredential = this.serviceCredential;
    if (serviceCredential === undefined) {
      throw new MissingServiceCredentialError();
    }
    const payload = {
      token: requiredCredential(token, "token"),
      audience: requiredIntrospectionIdentifier(audience, "audience"),
      requiredScopes: validateRequiredScopes(requiredScopes),
    };
    return this.requestJson<Introspection>("/auth/introspect", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${serviceCredential}`,
      },
      body: encodeJson({ contract: "IntrospectionRequest", payload }),
    });
  }

  /** Lightweight bearer check: true (200) / false (401). */
  async verify(token: string): Promise<boolean> {
    const path = "/auth/verify";
    return this.withDeadline(path, async (signal) => {
      const resp = await this.fetchResponse(path, {
        headers: { authorization: bearer(token, "token") },
        signal,
      });
      if (resp.status === 200) return true;
      if (resp.status === 401) return false;
      throw new SharedAuthHttpError(path, resp.status);
    });
  }

  /** The server's public JWKS. */
  jwks(): Promise<{ keys: unknown[] }> {
    return this.requestJson<{ keys: unknown[] }>("/.well-known/jwks.json");
  }

  oauthDiscovery(): Promise<Record<string, unknown>> {
    return this.requestJson("/.well-known/openid-configuration");
  }

  authorizeDecision(
    accessToken: string,
    resource: string,
    action: string,
  ): Promise<Record<string, unknown>> {
    return this.authedJson("/authz/decide", accessToken, "POST", {
      resource,
      action,
    });
  }

  samlMetadata(): Promise<unknown> {
    return this.requestJson("/saml/metadata");
  }

  samlSso(idpEntityId: string): Promise<unknown> {
    return this.requestJson(
      `/saml/sso?idp_entity_id=${encodeURIComponent(idpEntityId)}`,
    );
  }

  samlAcs(
    samlResponse: string,
    relayState?: string,
  ): Promise<Record<string, unknown>> {
    return this.requestJson("/saml/acs", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: encodeJson({
        SAMLResponse: samlResponse,
        ...(relayState ? { RelayState: relayState } : {}),
      }),
    });
  }

  scimServiceProviderConfig(): Promise<Record<string, unknown>> {
    return this.requestJson("/scim/v2/ServiceProviderConfig");
  }

  scimListUsers(accessToken: string): Promise<Record<string, unknown>> {
    return this.authedJson("/scim/v2/Users", accessToken);
  }

  scimCreateUser(
    accessToken: string,
    user: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.authedJson("/scim/v2/Users", accessToken, "POST", user);
  }

  scimGetUser(accessToken: string, id: string): Promise<Record<string, unknown>> {
    return this.authedJson(`/scim/v2/Users/${encodeURIComponent(id)}`, accessToken);
  }

  scimReplaceUser(
    accessToken: string,
    id: string,
    user: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.authedJson(
      `/scim/v2/Users/${encodeURIComponent(id)}`,
      accessToken,
      "PUT",
      user,
    );
  }

  scimPatchUser(
    accessToken: string,
    id: string,
    patch: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.authedJson(
      `/scim/v2/Users/${encodeURIComponent(id)}`,
      accessToken,
      "PATCH",
      patch,
    );
  }

  scimDeleteUser(accessToken: string, id: string): Promise<void> {
    return this.authedJson(
      `/scim/v2/Users/${encodeURIComponent(id)}`,
      accessToken,
      "DELETE",
    );
  }

  scimListGroups(accessToken: string): Promise<Record<string, unknown>> {
    return this.authedJson("/scim/v2/Groups", accessToken);
  }

  scimCreateGroup(
    accessToken: string,
    group: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.authedJson("/scim/v2/Groups", accessToken, "POST", group);
  }

  scimGetGroup(accessToken: string, id: string): Promise<Record<string, unknown>> {
    return this.authedJson(`/scim/v2/Groups/${encodeURIComponent(id)}`, accessToken);
  }

  scimReplaceGroup(
    accessToken: string,
    id: string,
    group: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.authedJson(
      `/scim/v2/Groups/${encodeURIComponent(id)}`,
      accessToken,
      "PUT",
      group,
    );
  }

  scimPatchGroup(
    accessToken: string,
    id: string,
    patch: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.authedJson(
      `/scim/v2/Groups/${encodeURIComponent(id)}`,
      accessToken,
      "PATCH",
      patch,
    );
  }

  scimDeleteGroup(accessToken: string, id: string): Promise<void> {
    return this.authedJson(
      `/scim/v2/Groups/${encodeURIComponent(id)}`,
      accessToken,
      "DELETE",
    );
  }

  capabilities(): Promise<Capabilities> {
    return this.requestJson<Capabilities>("/auth/capabilities");
  }

  factors(accessToken: string): Promise<Factor[]> {
    return this.authedJson<Factor[]>("/auth/factors", accessToken);
  }

  enrollTotp(
    accessToken: string,
    label?: string,
  ): Promise<TotpEnrollment> {
    return this.authedJson<TotpEnrollment>(
      "/auth/factors/totp/enroll",
      accessToken,
      "POST",
      { label },
    );
  }

  confirmTotp(
    accessToken: string,
    factorId: string,
    code: string,
  ): Promise<StepUpResponse> {
    return this.authedJson<StepUpResponse>(
      "/auth/factors/totp/confirm",
      accessToken,
      "POST",
      {
        factor_id: requiredField(factorId, "factorId"),
        code: requiredField(code, "code"),
      },
    );
  }

  async deleteFactor(accessToken: string, factorId: string): Promise<void> {
    const encodedFactorId = encodeURIComponent(
      requiredField(factorId, "factorId"),
    );
    await this.requestJson<unknown>(
      `/auth/factors/${encodedFactorId}`,
      {
        method: "DELETE",
        headers: { authorization: bearer(accessToken, "accessToken") },
      },
      true,
    );
  }

  createChallenge(
    accessToken: string,
    kind: ChallengeKind,
  ): Promise<ChallengeStart> {
    if (kind !== "email_otp" && kind !== "sms_otp") {
      throw new TypeError("kind must be email_otp or sms_otp");
    }
    return this.authedJson<ChallengeStart>(
      "/auth/challenges",
      accessToken,
      "POST",
      { kind },
    );
  }

  verifyChallenge(
    accessToken: string,
    challengeId: string,
    code: string,
  ): Promise<StepUpResponse> {
    const encodedChallengeId = encodeURIComponent(
      requiredField(challengeId, "challengeId"),
    );
    return this.authedJson<StepUpResponse>(
      `/auth/challenges/${encodedChallengeId}/verify`,
      accessToken,
      "POST",
      { code: requiredField(code, "code") },
    );
  }

  startPasskeyRegistration(
    accessToken: string,
    label?: string,
  ): Promise<CeremonyStart> {
    return this.authedJson<CeremonyStart>(
      "/auth/passkeys/registration/options",
      accessToken,
      "POST",
      { label },
    );
  }

  finishPasskeyRegistration(
    accessToken: string,
    challengeId: string,
    credential: unknown,
    label?: string,
  ): Promise<Factor> {
    return this.authedJson<Factor>(
      "/auth/passkeys/registration/verify",
      accessToken,
      "POST",
      {
        challenge_id: requiredField(challengeId, "challengeId"),
        credential,
        label,
      },
    );
  }

  startPasskeyAuthentication(accessToken: string): Promise<CeremonyStart> {
    return this.authedJson<CeremonyStart>(
      "/auth/passkeys/authentication/options",
      accessToken,
      "POST",
      {},
    );
  }

  finishPasskeyAuthentication(
    accessToken: string,
    challengeId: string,
    credential: unknown,
  ): Promise<StepUpResponse> {
    return this.authedJson<StepUpResponse>(
      "/auth/passkeys/authentication/verify",
      accessToken,
      "POST",
      {
        challenge_id: requiredField(challengeId, "challengeId"),
        credential,
      },
    );
  }

  private authedJson<T>(
    path: string,
    accessToken: string,
    method: "GET" | "POST" = "GET",
    body?: unknown,
  ): Promise<T> {
    const headers: Record<string, string> = {
      authorization: bearer(accessToken, "accessToken"),
    };
    if (body !== undefined) headers["content-type"] = "application/json";
    return this.requestJson<T>(path, {
      method,
      headers,
      body: body === undefined ? undefined : encodeJson(body),
    });
  }

  private async requestJson<T>(
    path: string,
    init: RequestInit = {},
    allowEmpty = false,
  ): Promise<T> {
    return this.withDeadline(path, async (signal) => {
      const resp = await this.fetchResponse(path, { ...init, signal });
      if (resp.status === 401) throw new UnauthorizedError();
      if (!resp.ok) throw new SharedAuthHttpError(path, resp.status);
      if (allowEmpty || resp.status === 204) return undefined as T;
      return this.readJson<T>(path, resp);
    });
  }

  private async fetchResponse(
    path: string,
    init: RequestInit,
  ): Promise<Response> {
    this.assertRequestBodySize(path, init.body);
    const headers = new Headers(init.headers);
    if (!headers.has("accept")) headers.set("accept", "application/json");

    try {
      return await this.doFetch(`${this.base}${path}`, {
        ...init,
        headers,
        credentials: "omit",
        redirect: "error",
        referrerPolicy: "no-referrer",
      });
    } catch (error) {
      if (init.signal?.aborted) throw error;
      throw new SharedAuthTransportError(path);
    }
  }

  private assertRequestBodySize(
    path: string,
    body: BodyInit | null | undefined,
  ): void {
    if (typeof body !== "string") return;
    if (utf8Length(body) > this.maxRequestBytes) {
      throw new SharedAuthRequestTooLargeError(path, this.maxRequestBytes);
    }
  }

  private async withDeadline<T>(
    path: string,
    operation: (signal: AbortSignal) => Promise<T>,
  ): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await operation(controller.signal);
    } catch (error) {
      if (controller.signal.aborted) {
        throw new SharedAuthTimeoutError(path, this.timeoutMs);
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  private async readJson<T>(path: string, response: Response): Promise<T> {
    const declaredLength = response.headers.get("content-length");
    if (declaredLength !== null) {
      const parsedLength = Number(declaredLength);
      if (
        Number.isFinite(parsedLength) &&
        parsedLength > this.maxResponseBytes
      ) {
        throw new SharedAuthResponseTooLargeError(
          path,
          this.maxResponseBytes,
        );
      }
    }

    const body = response.body;
    if (body === null) throw new SharedAuthDecodeError(path);

    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > this.maxResponseBytes) {
          await reader.cancel();
          throw new SharedAuthResponseTooLargeError(
            path,
            this.maxResponseBytes,
          );
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }

    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }

    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new SharedAuthDecodeError(path);
    }

    try {
      return JSON.parse(text) as T;
    } catch {
      throw new SharedAuthDecodeError(path);
    }
  }
}

function normalizeBase(input: string, allowInsecureTransport = false): string {
  const trimmed = input.trim();
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new TypeError("shared-auth base URL must be absolute HTTP(S)");
  }

  if (
    (url.protocol !== "https:" && url.protocol !== "http:") ||
    url.hostname.length === 0 ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.search.length > 0 ||
    url.hash.length > 0
  ) {
    throw new TypeError(
      "shared-auth base URL must be credential-free HTTP(S) without query or fragment",
    );
  }

  if (
    url.protocol === "http:" &&
    !cleartextInternalHostAllowed(url.hostname.toLowerCase()) &&
    !allowInsecureTransport
  ) {
    throw new TypeError(
      `shared-auth: refusing cleartext http:// to public host "${url.hostname.toLowerCase()}": ` +
        "use an https:// base URL, an in-cluster address, or loopback " +
        "(or opt out explicitly with allowInsecureTransport)",
    );
  }

  const pathname = url.pathname.replace(/\/+$/, "");
  return `${url.origin}${pathname}`;
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive safe integer`);
  }
  return value;
}

function normalizeOptionalCredential(
  value: string | undefined,
  name: string,
): string | undefined {
  return value === undefined ? undefined : requiredCredential(value, name);
}

function requiredCredential(value: string, name: string): string {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    throw new TypeError(
      `${name} must be a non-empty credential without surrounding whitespace`,
    );
  }
  if (containsControlCharacters(value)) {
    throw new TypeError(`${name} must not contain control characters`);
  }
  if (utf8Length(value) > MAX_CREDENTIAL_BYTES) {
    throw new TypeError(`${name} exceeds the credential size limit`);
  }
  return value;
}

function passwordlessEmail(value: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.trim() !== value ||
    utf8Length(value) > MAX_EMAIL_BYTES ||
    containsControlCharacters(value) ||
    !value.includes("@")
  ) {
    throw new TypeError("email is invalid");
  }
  return value;
}

function registrationPassword(value: string): string {
  const size = utf8Length(value);
  if (
    typeof value !== "string" ||
    size < MIN_REGISTRATION_PASSWORD_BYTES ||
    size > MAX_PASSWORD_BYTES
  ) {
    throw new TypeError("password is invalid");
  }
  return value;
}

function loginPassword(value: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    utf8Length(value) > MAX_PASSWORD_BYTES
  ) {
    throw new TypeError("password is invalid");
  }
  return value;
}

function optionalDisplayName(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const normalized = value.trim();
  if (normalized.length === 0) return undefined;
  if (
    utf8Length(normalized) > MAX_DISPLAY_NAME_BYTES ||
    containsControlCharacters(normalized)
  ) {
    throw new TypeError("displayName is invalid");
  }
  return normalized;
}

function emailOtp(value: string): string {
  if (typeof value !== "string" || !EMAIL_OTP.test(value)) {
    throw new TypeError("email OTP must be exactly six ASCII digits");
  }
  return value;
}

function requiredField(value: string, name: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  if (containsControlCharacters(normalized)) {
    throw new TypeError(`${name} must not contain control characters`);
  }
  return normalized;
}

function requiredIntrospectionIdentifier(value: string, name: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 128 ||
    !PORTABLE_INTROSPECTION_VALUE.test(value)
  ) {
    throw new TypeError(`${name} is invalid`);
  }
  return value;
}

function validateRequiredScopes(scopes: readonly string[]): string[] {
  if (!Array.isArray(scopes) || scopes.length > MAX_REQUIRED_SCOPES) {
    throw new TypeError("requiredScopes is invalid");
  }
  const validated = scopes.map((scope) =>
    requiredIntrospectionIdentifier(scope, "required scope")
  );
  if (new Set(validated).size !== validated.length) {
    throw new TypeError("requiredScopes contains a duplicate scope");
  }
  return validated;
}

function bearer(value: string, name: string): string {
  return `Bearer ${requiredCredential(value, name)}`;
}

function encodeJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    throw new TypeError("shared-auth request body is not JSON-serializable");
  }
}

function containsControlCharacters(value: string): boolean {
  return /[\u0000-\u001f\u007f]/.test(value);
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function normalizeBaseUrl(value: string): string {
  const trimmed = value.trim().replace(/\/+$/, "");
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error("shared-auth base URL is invalid");
  }
  const local = parsed.hostname === "localhost" ||
    parsed.hostname === "127.0.0.1" ||
    parsed.hostname === "[::1]" ||
    parsed.hostname === "::1";
  if (parsed.username || parsed.password || parsed.search || parsed.hash ||
      (parsed.protocol !== "https:" && !(local && parsed.protocol === "http:"))) {
    throw new Error("shared-auth base URL must use HTTPS outside localhost");
  }
  return trimmed;
}

function assertPathIdentifier(value: string, message: string): void {
  if (typeof value !== "string" || value.length === 0 || value.length > 256 ||
      /[\r\n]/.test(value)) {
    throw new Error(message);
  }
}

function assertToken(value: string, message: string): void {
  if (typeof value !== "string" || value.length === 0 ||
      value.length > MAX_TOKEN_BYTES || value !== value.trim() ||
      /[\r\n]/.test(value)) {
    throw new Error(message);
  }
}

async function readBounded(response: Response, maximum: number): Promise<string> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maximum) {
    throw new Error("shared-auth response too large");
  }
  const text = await response.text();
  if (text.length > maximum) throw new Error("shared-auth response too large");
  return text;
}

async function discardBounded(response: Response, maximum: number): Promise<void> {
  await readBounded(response, maximum);
}
