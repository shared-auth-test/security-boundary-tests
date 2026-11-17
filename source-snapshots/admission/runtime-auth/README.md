# Shared runtime admission (DEN-2194, DEN-2843)

Reviewable pilot, not a production rollout. Common Erlang code belongs here;
Scintilla and BeamScale infra pin this source at build time. No sibling checkout
is required at runtime. Runtime owners must wire the gate before route admission,
function allocation, tenant execution, or quota/billing mutation.

## Erlang: trusted admission beneath the granddaddy

OTP 27+ is required for native `json`. Start an isolated `httpc` profile once at
application boot (`inets:start(httpc, [{profile, shared_auth}])`). Supply a trusted
policy with exact `issuer`, `audience`, `project`, `realm`, `providers`,
`required_scopes`, and `min_aal`. Inject `service_credential` from the secret
manager; never put it in tenant environment variables. Use a separate loopback
port/tunnel/profile and service credential for each realm. The authority behind
that port MUST have authoritative session storage enabled; offline verification
does not meet this contract. Do not derive policy or the destination from HTTP
headers, tenant code, or a token's unverified issuer.

```erlang
Verify = fun(Token, Policy) ->
    shared_auth_introspection:verify(Token, Policy, TrustedTransport)
end,
case shared_auth_gate:authorize(RequestHeaders, TrustedPolicy, Verify, 1000) of
    {ok, Principal} ->
        %% Product authorization / proof policy MUST still run before invocation.
        authorize_product_and_invoke(Principal,
            shared_auth_gate:application_headers(RequestHeaders));
    {error, invalid} -> reply(401);
    {error, forbidden} -> reply(403);
    {error, unavailable} -> reply(503)
end.
```

Run this in a bounded trusted per-request admission process. Configure admission
concurrency upstream; the module does not create an unbounded request queue.
BeamScale's `bmscl_sup` outer granddaddy remains a static one-child supervisor.
Its replaceable inner runtime owns the admission service. Scintilla's runner
must check before handing a request to the tenant process. Never put network I/O
in supervisor callbacks or grant tenant code direct access to service credentials.
The caller's outer request deadline must also bound admission and invocation.

The gate rejects duplicate/case-varied Authorization, malformed or oversized
bearers, inactive/expired sessions, wrong issuer/audience/project/provider,
missing session/epoch, low assurance, missing scopes, and sandbox credentials.
The result contains only the canonical principal and request-scoped context;
email, provider subjects, roles, and raw tokens are not copied to tenant headers.
No cache, login, refresh, token exchange, or provider race occurs here.

This is authentication plus minimum scope/assurance enforcement. It does NOT
prove tenant enrollment, object ownership, strict provider-pair agreement, or
independent subsystem proofs. Products must enforce those policies separately,
including Okla–Quaestor ledger writes. `realm` is deployment context bound to the
configured authority, not a claim manufactured from an incoming header.

The existing server's introspection endpoint returns HTTP 200 with `active:false`
for invalid tokens and can also collapse authoritative-store errors to inactive.
Both deny here; that server contract currently prevents distinguishing these
cases. Transport/protocol failures remain unavailable. Redirects are disabled.
The transport's response-size check occurs after receipt; use a trusted local
authority and upstream connection/response limits, not an arbitrary Internet URL.

## Nginx, Caddy, HAProxy

`proxies/` contains complete loopback acceptance configurations. They listen on
9080, call a dedicated realm/audience verifier on 9081 at **GET /auth/verify**,
and forward allowed requests to a trusted application on 9082. Do not point
them at `/auth/introspect`: its HTTP 200 is not an admission decision. The
verifier must enforce its configured issuer/audience and online session state.
Nginx requires `http_auth_request_module`; HAProxy requires 3.2 with Lua support.

These are bearer-only configurations. They forward a narrow header allowlist,
preserve Authorization for the trusted application's final verification and
authorization, and do not copy verifier identity headers. Cookies and arbitrary
forwarded identity headers are excluded. The application must never treat header
presence as identity. Proxy success is not strict-proof or product authorization.
Do not expose the application or local verifier to tenant processes or external
traffic; enforce network/process isolation as well as the request gate.

No auth response caching, provider fallback, application retries, body forwarding
to the verifier, query forwarding to the verifier, or credential logging is used.
An auth outage denies admission. Ingress TLS, production hostnames, exact audience
assignment, and network isolation are deployment responsibilities; these fixture
listeners must not be promoted as public production listeners.

## Verification

```sh
bash runtime-auth/erlang/check.sh
python3 runtime-auth/test/proxy_acceptance.py nginx
python3 runtime-auth/test/proxy_acceptance.py caddy
python3 runtime-auth/test/proxy_acceptance.py haproxy
```

The acceptance fixture uses synthetic tokens and counts verifier/application
requests. It checks denial, outages, header spoofing, request-body preservation,
and repeated revocation checks. Passing it is necessary but not sufficient for
promotion: also exercise real issuer/audience/realm mismatch, revocation, strict
proof policies, process isolation, and the product's tenant authorization.

References: [Nginx auth_request](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html),
[Caddy forward_auth](https://caddyserver.com/docs/caddyfile/directives/forward_auth),
[HAProxy Lua HTTPClient](https://www.arpalert.org/src/haproxy-lua-api/3.2/index.html),
[OTP httpc](https://www.erlang.org/doc/apps/inets/httpc.html).
