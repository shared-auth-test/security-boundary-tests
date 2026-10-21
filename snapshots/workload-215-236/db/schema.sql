-- shared_auth — declarative schema for the OreSoftware shared auth server.
--
-- Owned by pg-defs and applied with dpm (declarative; no migration files). The
-- server connects with search_path=shared_auth and runs NO DDL. One namespace
-- per app, per the org convention (see the pg-defs + dpm memory).
--
-- Postgres is the authoritative shared-auth store. External identity providers
-- (Supabase today; Clerk/Cognito may be added later) are linked through
-- provider_identities rather than being baked into the principals table. Passwords
-- are never stored: local_credentials contains Argon2id PHC strings only.

create schema if not exists shared_auth;

create table if not exists shared_auth.principals (
    shared_user_id    uuid        primary key default gen_random_uuid(),
    email             text,
    email_verified    boolean     not null default false,
    phone             text,
    phone_verified    boolean     not null default false,
    display_name      text,
    status            text        not null default 'active'
                                  check (status in ('active', 'disabled', 'deleted')),
    profile           jsonb       not null default '{}'::jsonb,
    -- Monotonic central revocation fence. Every session records the epoch it
    -- was created under; a global commit advances this value transactionally
    -- before any best-effort provider/cache fan-out begins.
    auth_epoch        bigint      not null default 0 check (auth_epoch >= 0),
    auth_not_before   timestamptz not null default 'epoch'::timestamptz,
    created_at        timestamptz not null default now(),
    updated_at        timestamptz not null default now(),
    last_seen_at      timestamptz not null default now(),
    check (email is null or (length(email) between 3 and 320)),
    check (phone is null or length(phone) <= 64),
    check (display_name is null or length(display_name) <= 160)
);

create unique index if not exists users_email_unique_idx
    on shared_auth.principals (lower(email))
    where email is not null and status <> 'deleted';

create index if not exists users_status_idx
    on shared_auth.principals (status);

-- Directory administration is authorized from this Postgres ledger, never
-- from provider tenancy, an email alias, or a flat organization list in a
-- bearer token. `principal_ref` is the only subject identifier emitted to the
-- dashboard; the global shared_user_id remains inside this authority.
create table if not exists shared_auth.admin_principal_refs (
    shared_user_id uuid        primary key references shared_auth.principals(shared_user_id),
    principal_ref  uuid        not null unique default gen_random_uuid(),
    created_at     timestamptz not null default now()
);

create table if not exists shared_auth.admin_provider_tenant_refs (
    provider             text        not null,
    provider_tenant      text        not null,
    provider_tenant_ref  uuid        not null unique default gen_random_uuid(),
    created_at           timestamptz not null default now(),
    primary key (provider, provider_tenant),
    check (length(provider) between 1 and 64),
    check (length(provider_tenant) between 1 and 255)
);

create or replace function shared_auth.array_has_unique_text_values(input_values text[])
returns boolean
language sql
immutable
parallel safe
as $$
    select count(*) = count(distinct value) from unnest(input_values) as item(value)
$$;

create or replace function shared_auth.array_has_unique_uuid_values(input_values uuid[])
returns boolean
language sql
immutable
parallel safe
as $$
    select count(*) = count(distinct value) from unnest(input_values) as item(value)
$$;

-- Cross-product organization/project inventory is synchronized by a trusted
-- directory job. A numeric zero is authoritative only when this per-principal
-- snapshot says complete; otherwise revocation previews emit null/unknown and
-- principal search fails closed instead of fabricating zero membership.
create table if not exists shared_auth.principal_directory_inventory_state (
    shared_user_id       uuid        primary key references shared_auth.principals(shared_user_id) on delete cascade,
    inventory_complete   boolean     not null default false,
    source_snapshot_hash text        not null check (length(source_snapshot_hash) = 43),
    observed_at          timestamptz not null,
    updated_at           timestamptz not null default now()
);

create table if not exists shared_auth.principal_organization_memberships (
    shared_user_id       uuid        not null references shared_auth.principals(shared_user_id) on delete cascade,
    organization_id      uuid        not null,
    project_ids          uuid[],
    source_snapshot_hash text        not null check (length(source_snapshot_hash) = 43),
    observed_at          timestamptz not null,
    primary key (shared_user_id, organization_id),
    check (organization_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    check (
        project_ids is null or (
            cardinality(project_ids) between 1 and 200
            and array_position(project_ids, '00000000-0000-0000-0000-000000000000'::uuid) is null
            and shared_auth.array_has_unique_uuid_values(project_ids)
        )
    )
);

-- Grants are append-only authorization facts. Scope/project/role changes must
-- revoke the old grant and issue a new grant id so audit history stays exact.
-- NULL project_ids means organization-wide; an explicit array is non-empty.
create table if not exists shared_auth.directory_admin_grants (
    grant_id                    uuid        primary key,
    shared_user_id              uuid        not null references shared_auth.admin_principal_refs(shared_user_id),
    organization_id             uuid        not null,
    project_ids                 uuid[],
    scopes                      text[]      not null,
    roles                       text[]      not null,
    granted_at                  timestamptz not null,
    expires_at                  timestamptz,
    revoked_at                  timestamptz,
    granted_by_ref_hash         text        not null check (length(granted_by_ref_hash) = 43),
    grant_provenance_kind       text        not null check (grant_provenance_kind in (
                                                'github_sync', 'manual_admin',
                                                'bootstrap_migration', 'incident_response'
                                            )),
    grant_provenance_ref_hash   text        not null check (length(grant_provenance_ref_hash) = 43),
    revoked_by_ref_hash         text,
    revoke_provenance_kind      text        check (revoke_provenance_kind in (
                                                'github_sync', 'manual_admin',
                                                'bootstrap_migration', 'incident_response'
                                            )),
    revoke_provenance_ref_hash  text,
    created_at                  timestamptz not null default now(),
    updated_at                  timestamptz not null default now(),
    check (organization_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    check (
        project_ids is null or (
            cardinality(project_ids) between 1 and 200
            and array_position(project_ids, '00000000-0000-0000-0000-000000000000'::uuid) is null
            and shared_auth.array_has_unique_uuid_values(project_ids)
        )
    ),
    check (cardinality(scopes) between 1 and 6),
    check (shared_auth.array_has_unique_text_values(scopes)),
    check (scopes <@ array[
        'directory.dashboard.read',
        'directory.users.read',
        'directory.sessions.read',
        'directory.roles.read',
        'directory.revocations.read',
        'directory.revocations.execute'
    ]::text[]),
    check (cardinality(roles) between 1 and 3),
    check (shared_auth.array_has_unique_text_values(roles)),
    check (roles <@ array[
        'directory_admin', 'directory_security_operator', 'directory_auditor'
    ]::text[]),
    check (roles @> array['directory_admin']::text[]),
    check (expires_at is null or expires_at > granted_at),
    check (revoked_at is null or revoked_at >= granted_at),
    check (
        (revoked_at is null and revoked_by_ref_hash is null
            and revoke_provenance_kind is null and revoke_provenance_ref_hash is null)
        or
        (revoked_at is not null and revoked_by_ref_hash is not null
            and length(revoked_by_ref_hash) = 43
            and revoke_provenance_kind is not null
            and revoke_provenance_ref_hash is not null
            and length(revoke_provenance_ref_hash) = 43)
    )
);

create index if not exists directory_admin_grants_active_subject_idx
    on shared_auth.directory_admin_grants (shared_user_id, organization_id, granted_at desc)
    where revoked_at is null;

-- Audit events contain only the per-dashboard principal ref, organization,
-- counts/enums, and opaque provenance hashes. They never contain email,
-- provider subjects, bearer tokens, or the authority's shared_user_id.
create table if not exists shared_auth.directory_admin_grant_audit_events (
    sequence_id       bigserial   primary key,
    event_id          uuid        not null unique,
    grant_id          uuid        not null,
    principal_ref     uuid        not null,
    event_type        text        not null check (event_type in ('grant_issued', 'grant_revoked')),
    redacted_payload  jsonb       not null check (jsonb_typeof(redacted_payload) = 'object'),
    created_at        timestamptz not null default now()
);

create or replace function shared_auth.reject_directory_admin_grant_audit_mutation()
returns trigger
language plpgsql
as $$
begin
    raise exception 'directory admin grant audit events are immutable';
end;
$$;

drop trigger if exists directory_admin_grant_audit_immutable
    on shared_auth.directory_admin_grant_audit_events;
create trigger directory_admin_grant_audit_immutable
    before update or delete on shared_auth.directory_admin_grant_audit_events
    for each row execute function shared_auth.reject_directory_admin_grant_audit_mutation();

create or replace function shared_auth.audit_directory_admin_grant_change()
returns trigger
language plpgsql
as $$
declare
    opaque_principal_ref uuid;
begin
    select principal_ref into strict opaque_principal_ref
      from shared_auth.admin_principal_refs
     where shared_user_id = new.shared_user_id;

    -- Any authorization change fences every pre-change bearer. The strict
    -- introspection query takes a principal share lock, which makes the grant
    -- read and this epoch change one linearizable boundary.
    update shared_auth.principals
       set auth_epoch = auth_epoch + 1,
           auth_not_before = clock_timestamp(),
           updated_at = clock_timestamp()
     where shared_user_id = new.shared_user_id and status = 'active';
    update shared_auth.sessions
       set revoked_at = coalesce(revoked_at, clock_timestamp()),
           updated_at = clock_timestamp()
     where shared_user_id = new.shared_user_id and revoked_at is null;

    if tg_op = 'INSERT' then
        insert into shared_auth.directory_admin_grant_audit_events
            (event_id, grant_id, principal_ref, event_type, redacted_payload)
        values (
            gen_random_uuid(), new.grant_id, opaque_principal_ref, 'grant_issued',
            jsonb_build_object(
                'organization_id', new.organization_id,
                'project_count', coalesce(cardinality(new.project_ids), 0),
                'org_wide', new.project_ids is null,
                'scopes', new.scopes,
                'roles', new.roles,
                'granted_at', new.granted_at,
                'expires_at', new.expires_at,
                'granted_by_ref_hash', new.granted_by_ref_hash,
                'provenance_kind', new.grant_provenance_kind,
                'provenance_ref_hash', new.grant_provenance_ref_hash
            )
        );
        return new;
    end if;

    if row(
        old.grant_id, old.shared_user_id, old.organization_id, old.project_ids,
        old.scopes, old.roles, old.granted_at, old.expires_at,
        old.granted_by_ref_hash, old.grant_provenance_kind,
        old.grant_provenance_ref_hash, old.created_at
    ) is distinct from row(
        new.grant_id, new.shared_user_id, new.organization_id, new.project_ids,
        new.scopes, new.roles, new.granted_at, new.expires_at,
        new.granted_by_ref_hash, new.grant_provenance_kind,
        new.grant_provenance_ref_hash, new.created_at
    ) then
        raise exception 'directory admin grants are immutable; revoke and reissue';
    end if;
    if old.revoked_at is not null then
        raise exception 'revoked directory admin grants are immutable';
    end if;
    if new.revoked_at is null then
        raise exception 'directory admin grant updates may only revoke';
    end if;

    insert into shared_auth.directory_admin_grant_audit_events
        (event_id, grant_id, principal_ref, event_type, redacted_payload)
    values (
        gen_random_uuid(), new.grant_id, opaque_principal_ref, 'grant_revoked',
        jsonb_build_object(
            'organization_id', new.organization_id,
            'revoked_at', new.revoked_at,
            'revoked_by_ref_hash', new.revoked_by_ref_hash,
            'provenance_kind', new.revoke_provenance_kind,
            'provenance_ref_hash', new.revoke_provenance_ref_hash
        )
    );
    return new;
end;
$$;

drop trigger if exists directory_admin_grant_audit
    on shared_auth.directory_admin_grants;
create trigger directory_admin_grant_audit
    after insert or update on shared_auth.directory_admin_grants
    for each row execute function shared_auth.audit_directory_admin_grant_change();

create table if not exists shared_auth.provider_identities (
    provider_identity_id uuid        primary key default gen_random_uuid(),
    shared_user_id       uuid        not null references shared_auth.principals(shared_user_id) on delete cascade,
    provider             text        not null,
    provider_tenant      text        not null default 'default',
    provider_subject     text        not null,
    email                text,
    email_verified       boolean     not null default false,
    email_search_key_hash text,
    email_search_key_id   text,
    metadata             jsonb       not null default '{}'::jsonb,
    created_at           timestamptz not null default now(),
    updated_at           timestamptz not null default now(),
    last_seen_at         timestamptz not null default now(),
    unique (provider, provider_tenant, provider_subject),
    check (length(provider) between 1 and 64),
    check (length(provider_tenant) between 1 and 255),
    check (length(provider_subject) between 1 and 512),
    check (email_search_key_hash is null or length(email_search_key_hash) = 43),
    check (email_search_key_id is null or length(email_search_key_id) = 43),
    check ((email_search_key_hash is null) = (email_search_key_id is null)),
    check (email_verified or email_search_key_hash is null)
);

-- pg-defs applies this file to both new and already-materialized disposable
-- databases. Keep the additive columns explicit for the latter case.
alter table shared_auth.provider_identities
    add column if not exists email_search_key_hash text;
alter table shared_auth.provider_identities
    add column if not exists email_search_key_id text;

create index if not exists provider_identities_user_idx
    on shared_auth.provider_identities (shared_user_id);
create index if not exists provider_identities_verified_email_idx
    on shared_auth.provider_identities (lower(email))
    where email_verified = true and email is not null;
create index if not exists provider_identities_admin_email_search_idx
    on shared_auth.provider_identities (email_search_key_id, email_search_key_hash)
    where email_verified = true and email_search_key_hash is not null;

-- One non-secret generation marker proves that every verified identity was
-- re-indexed under the configured search key before the admin surface starts.
create table if not exists shared_auth.admin_email_search_index_state (
    singleton               boolean     primary key default true check (singleton),
    email_search_key_id     text        not null check (length(email_search_key_id) = 43),
    verified_identity_count bigint      not null check (verified_identity_count >= 0),
    materialized_at         timestamptz not null default now()
);

create table if not exists shared_auth.local_credentials (
    shared_user_id       uuid        primary key references shared_auth.principals(shared_user_id) on delete cascade,
    password_hash        text        not null,
    password_changed_at  timestamptz not null default now(),
    failed_attempts      integer     not null default 0 check (failed_attempts >= 0),
    locked_until         timestamptz,
    created_at           timestamptz not null default now(),
    updated_at           timestamptz not null default now(),
    check (length(password_hash) between 40 and 512)
);

create table if not exists shared_auth.sessions (
    session_id          uuid        primary key default gen_random_uuid(),
    shared_user_id      uuid        not null references shared_auth.principals(shared_user_id) on delete cascade,
    refresh_token_hash  text        not null unique,
    provider            text        not null,
    provider_tenant     text        not null default 'default',
    provider_subject    text        not null,
    auth_level          smallint    not null default 1 check (auth_level in (1, 2)),
    auth_methods        jsonb       not null default '[]'::jsonb,
    auth_epoch          bigint      not null default 0 check (auth_epoch >= 0),
    created_at          timestamptz not null default now(),
    updated_at          timestamptz not null default now(),
    last_seen_at        timestamptz not null default now(),
    expires_at          timestamptz not null,
    revoked_at          timestamptz,
    rotated_from        uuid        references shared_auth.sessions(session_id) on delete set null,
    check (length(refresh_token_hash) = 43),
    check (jsonb_typeof(auth_methods) = 'array'),
    check (expires_at > created_at)
);

create index if not exists sessions_user_idx
    on shared_auth.sessions (shared_user_id);
create index if not exists sessions_active_expiry_idx
    on shared_auth.sessions (expires_at)
    where revoked_at is null;

create index if not exists sessions_user_epoch_idx
    on shared_auth.sessions (shared_user_id, auth_epoch);

-- Passwordless email tokens are opaque, single-use, short-lived credentials.
-- Only the SHA-256 hash is persisted; the plaintext exists only long enough to
-- be placed in the SendGrid message.
create table if not exists shared_auth.magic_link_tokens (
    token_hash          text        primary key check (length(token_hash) = 43),
    otp_hash            text        not null check (length(otp_hash) = 43),
    shared_user_id      uuid        not null references shared_auth.principals(shared_user_id) on delete cascade,
    identifier_hash     text        not null check (length(identifier_hash) = 43),
    failed_attempts     integer     not null default 0 check (failed_attempts between 0 and 5),
    created_at          timestamptz not null default now(),
    expires_at          timestamptz not null,
    consumed_at         timestamptz,
    check (expires_at > created_at)
);

create index if not exists magic_link_tokens_user_idx
    on shared_auth.magic_link_tokens (shared_user_id);
create index if not exists magic_link_tokens_active_expiry_idx
    on shared_auth.magic_link_tokens (expires_at)
    where consumed_at is null;
create index if not exists magic_link_tokens_identifier_created_idx
    on shared_auth.magic_link_tokens (identifier_hash, created_at desc);

create table if not exists shared_auth.mfa_sms_challenges (
    challenge_id        uuid        primary key default gen_random_uuid(),
    shared_user_id      uuid        not null references shared_auth.principals(shared_user_id) on delete cascade,
    phone_e164          text        not null check (phone_e164 ~ '^\+[1-9][0-9]{7,14}$'),
    created_at          timestamptz not null default now(),
    expires_at          timestamptz not null,
    verified_at         timestamptz,
    check (expires_at > created_at)
);

create index if not exists mfa_sms_challenges_user_idx
    on shared_auth.mfa_sms_challenges (shared_user_id, created_at desc);
create index if not exists mfa_sms_challenges_active_expiry_idx
    on shared_auth.mfa_sms_challenges (expires_at)
    where verified_at is null;

create table if not exists shared_auth.roles (
    role_id           uuid        primary key default gen_random_uuid(),
    shared_user_id    uuid        not null references shared_auth.principals(shared_user_id) on delete cascade,
    role_name         text        not null check (role_name ~ '^[a-z][a-z0-9:_-]{0,63}$'),
    granted_at        timestamptz not null default now(),
    granted_by        uuid        references shared_auth.principals(shared_user_id) on delete set null,
    unique (shared_user_id, role_name)
);

create index if not exists roles_user_idx
    on shared_auth.roles (shared_user_id);

-- The customer realm owns one global principal and a separate enrollment in
-- each first-party application. SSO reuses the central login ceremony, but each
-- application receives its own audience-scoped token and may deny enrollment.
-- Product authorization remains in each application database; these tables do
-- not own organization membership, billing authority, or resource permissions.
create table if not exists shared_auth.applications (
    application_id     uuid        primary key default gen_random_uuid(),
    application_key    text        not null unique
                                  check (application_key ~ '^[a-z][a-z0-9-]{1,63}$'),
    display_name       text        not null check (length(display_name) between 1 and 160),
    status             text        not null default 'active'
                                  check (status in ('active', 'disabled')),
    enrollment_policy  text        not null default 'automatic'
                                  check (enrollment_policy in ('automatic', 'invite', 'disabled')),
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now()
);

create table if not exists shared_auth.application_accounts (
    application_id       uuid        not null references shared_auth.applications(application_id) on delete cascade,
    shared_user_id       uuid        not null references shared_auth.principals(shared_user_id) on delete cascade,
    status               text        not null default 'active'
                                     check (status in ('active', 'suspended', 'deleted')),
    profile              jsonb       not null default '{}'::jsonb,
    created_at           timestamptz not null default now(),
    updated_at           timestamptz not null default now(),
    last_authenticated_at timestamptz,
    primary key (application_id, shared_user_id),
    check (jsonb_typeof(profile) = 'object')
);

create index if not exists application_accounts_user_idx
    on shared_auth.application_accounts (shared_user_id, status);

create table if not exists shared_auth.oauth_clients (
    client_id           text        primary key
                                  check (client_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$'),
    application_id      uuid        not null references shared_auth.applications(application_id) on delete cascade,
    audience            text        not null unique
                                  check (audience ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{2,127}$'),
    client_type         text        not null default 'public'
                                  check (client_type in ('public', 'confidential')),
    client_secret_hash  text,
    redirect_uris       jsonb       not null default '[]'::jsonb,
    allowed_scopes      jsonb       not null default '[]'::jsonb,
    require_pkce        boolean     not null default true,
    status              text        not null default 'active'
                                  check (status in ('active', 'disabled')),
    created_at          timestamptz not null default now(),
    updated_at          timestamptz not null default now(),
    unique (application_id, client_id),
    check (jsonb_typeof(redirect_uris) = 'array'),
    check (jsonb_typeof(allowed_scopes) = 'array'),
    check (
        (client_type = 'public' and client_secret_hash is null and require_pkce)
        or
        (client_type = 'confidential' and client_secret_hash is not null
         and length(client_secret_hash) between 43 and 512)
    )
);

create index if not exists oauth_clients_application_idx
    on shared_auth.oauth_clients (application_id, status);

create table if not exists shared_auth.application_consents (
    application_id     uuid        not null references shared_auth.applications(application_id) on delete cascade,
    shared_user_id     uuid        not null references shared_auth.principals(shared_user_id) on delete cascade,
    scopes             jsonb       not null default '[]'::jsonb,
    granted_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now(),
    revoked_at         timestamptz,
    primary key (application_id, shared_user_id),
    check (jsonb_typeof(scopes) = 'array')
);

create index if not exists application_consents_user_idx
    on shared_auth.application_consents (shared_user_id, revoked_at);

-- A central browser session can authorize several applications without sharing
-- cookies or bearer tokens between them. Each grant names the exact registered
-- client; revoking one grant need not terminate unrelated application sessions.
create table if not exists shared_auth.session_application_grants (
    session_id         uuid        not null references shared_auth.sessions(session_id) on delete cascade,
    application_id     uuid        not null,
    client_id          text        not null,
    granted_at         timestamptz not null default now(),
    last_used_at       timestamptz not null default now(),
    revoked_at         timestamptz,
    primary key (session_id, application_id, client_id),
    foreign key (application_id, client_id)
        references shared_auth.oauth_clients(application_id, client_id) on delete cascade
);

create index if not exists session_application_grants_active_idx
    on shared_auth.session_application_grants (application_id, client_id, last_used_at desc)
    where revoked_at is null;

-- Browser authorization codes are opaque, PKCE-bound and single-use. Supabase
-- token bundles are AES-256-GCM ciphertext; plaintext tokens never enter URLs.
create table if not exists shared_auth.browser_authorization_codes (
    code_hash           text        primary key check (length(code_hash) = 43),
    client_id           text        not null check (length(client_id) between 1 and 128),
    redirect_uri        text        not null check (length(redirect_uri) between 1 and 512),
    return_path         text        not null check (length(return_path) between 1 and 512),
    supabase_project    text        not null check (length(supabase_project) between 1 and 128),
    code_challenge      text        not null check (length(code_challenge) = 43),
    encrypted_tokens    text        not null check (length(encrypted_tokens) between 64 and 65536),
    created_at          timestamptz not null default now(),
    expires_at          timestamptz not null,
    consumed_at         timestamptz,
    check (expires_at > created_at),
    check (consumed_at is null or consumed_at >= created_at)
);

create index if not exists browser_authorization_codes_active_expiry_idx
    on shared_auth.browser_authorization_codes (expires_at)
    where consumed_at is null;

-- Enrolled MFA factors. TOTP seeds are AES-256-GCM ciphertext and nonce; passkeys
-- contain only the serialised public credential returned by webauthn-rs. Raw
-- fingerprint/face material is never accepted or stored.
create table if not exists shared_auth.auth_factors (
    factor_id          uuid        primary key default gen_random_uuid(),
    shared_user_id     uuid        not null references shared_auth.principals(shared_user_id) on delete cascade,
    kind               text        not null check (kind in ('totp', 'passkey')),
    label              text,
    secret_ciphertext  bytea,
    secret_nonce       bytea,
    public_data        jsonb       not null default '{}'::jsonb,
    external_id        text,
    enabled            boolean     not null default false,
    confirmed_at       timestamptz,
    last_used_at       timestamptz,
    totp_failed_attempts integer    not null default 0 check (totp_failed_attempts >= 0),
    totp_attempt_window_started_at timestamptz,
    totp_locked_until  timestamptz,
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now(),
    check (label is null or length(label) <= 160),
    check (external_id is null or length(external_id) <= 2048),
    check (
        (kind = 'totp' and secret_ciphertext is not null and secret_nonce is not null)
        or
        (kind = 'passkey' and secret_ciphertext is null and secret_nonce is null and external_id is not null)
    )
);

alter table shared_auth.auth_factors
    add column if not exists totp_failed_attempts integer not null default 0
        check (totp_failed_attempts >= 0);
alter table shared_auth.auth_factors
    add column if not exists totp_attempt_window_started_at timestamptz;
alter table shared_auth.auth_factors
    add column if not exists totp_locked_until timestamptz;

create index if not exists auth_factors_user_idx
    on shared_auth.auth_factors (shared_user_id, kind, enabled);
create unique index if not exists auth_factors_external_id_unique_idx
    on shared_auth.auth_factors (kind, external_id)
    where external_id is not null;

-- Short-lived server-side challenge state. OTP codes are represented only by a
-- keyed tag; WebAuthn registration/authentication state is JSON owned by the
-- server and consumed exactly once.
create table if not exists shared_auth.auth_challenges (
    challenge_id       uuid        primary key default gen_random_uuid(),
    shared_user_id     uuid        not null references shared_auth.principals(shared_user_id) on delete cascade,
    session_id         uuid        not null references shared_auth.sessions(session_id) on delete cascade,
    kind               text        not null check (kind in ('email_otp', 'sms_otp', 'passkey_register', 'passkey_auth')),
    destination_hint   text,
    destination_binding_tag bytea check (
        destination_binding_tag is null or octet_length(destination_binding_tag) = 32
    ),
    destination_budget_key bytea check (
        destination_budget_key is null or octet_length(destination_budget_key) = 32
    ),
    code_tag           bytea,
    state              jsonb       not null default '{}'::jsonb,
    attempts           integer     not null default 0 check (attempts >= 0),
    max_attempts       integer     not null check (max_attempts between 1 and 20),
    expires_at         timestamptz not null,
    consumed_at        timestamptz,
    created_at         timestamptz not null default now(),
    check (expires_at > created_at),
    check (
        (kind in ('email_otp', 'sms_otp') and code_tag is not null)
        or
        (kind in ('passkey_register', 'passkey_auth') and code_tag is null)
    )
);

alter table shared_auth.auth_challenges
    add column if not exists destination_binding_tag bytea
        check (destination_binding_tag is null or octet_length(destination_binding_tag) = 32);
alter table shared_auth.auth_challenges
    add column if not exists destination_budget_key bytea
        check (destination_budget_key is null or octet_length(destination_budget_key) = 32);

-- A deployment that predates destination binding cannot safely verify an
-- already-issued OTP after the migration because its exact destination was
-- deliberately never stored. Burn only those outstanding legacy challenges;
-- callers can request a newly bound challenge immediately.
update shared_auth.auth_challenges
set consumed_at = now()
where kind in ('email_otp', 'sms_otp')
  and consumed_at is null
  and (destination_binding_tag is null or destination_budget_key is null);

do $$
begin
    if not exists (
        select 1 from pg_constraint
        where conname = 'auth_challenges_active_otp_destination_binding'
          and conrelid = 'shared_auth.auth_challenges'::regclass
    ) then
        alter table shared_auth.auth_challenges
            add constraint auth_challenges_active_otp_destination_binding
            check (
                kind not in ('email_otp', 'sms_otp')
                or consumed_at is not null
                or (destination_binding_tag is not null and destination_budget_key is not null)
            );
    end if;
end
$$;

do $$
begin
    if not exists (
        select 1 from pg_constraint
        where conname = 'auth_challenges_destination_tag_lengths'
          and conrelid = 'shared_auth.auth_challenges'::regclass
    ) then
        alter table shared_auth.auth_challenges
            add constraint auth_challenges_destination_tag_lengths
            check (
                (destination_binding_tag is null or octet_length(destination_binding_tag) = 32)
                and
                (destination_budget_key is null or octet_length(destination_budget_key) = 32)
            );
    end if;
end
$$;

create index if not exists auth_challenges_active_idx
    on shared_auth.auth_challenges (shared_user_id, session_id, kind, expires_at)
    where consumed_at is null;
create index if not exists auth_challenges_principal_send_budget_idx
    on shared_auth.auth_challenges (shared_user_id, kind, created_at desc)
    where kind in ('email_otp', 'sms_otp');
create index if not exists auth_challenges_destination_send_budget_idx
    on shared_auth.auth_challenges (kind, destination_budget_key, created_at desc)
    where kind in ('email_otp', 'sms_otp') and destination_budget_key is not null;

create or replace function shared_auth.consume_principal_otp_challenges_on_binding_change()
returns trigger language plpgsql as $$
begin
    if old.status is distinct from new.status
       or old.email is distinct from new.email
       or old.email_verified is distinct from new.email_verified
       or old.phone is distinct from new.phone
       or old.phone_verified is distinct from new.phone_verified then
        update shared_auth.auth_challenges
        set consumed_at = coalesce(consumed_at, now())
        where shared_user_id = new.shared_user_id
          and kind in ('email_otp', 'sms_otp')
          and consumed_at is null;
    end if;
    return new;
end
$$;

drop trigger if exists auth_challenges_principal_binding_change
    on shared_auth.principals;
create trigger auth_challenges_principal_binding_change
after update of status, email, email_verified, phone, phone_verified
on shared_auth.principals
for each row execute function shared_auth.consume_principal_otp_challenges_on_binding_change();

create or replace function shared_auth.consume_provider_otp_challenges_on_binding_change()
returns trigger language plpgsql as $$
begin
    if tg_op = 'DELETE'
       or old.email is distinct from new.email
       or old.email_verified is distinct from new.email_verified
       or old.shared_user_id is distinct from new.shared_user_id then
        update shared_auth.auth_challenges
        set consumed_at = coalesce(consumed_at, now())
        where shared_user_id = old.shared_user_id
          and kind in ('email_otp', 'sms_otp')
          and consumed_at is null;
    end if;
    return coalesce(new, old);
end
$$;

drop trigger if exists auth_challenges_provider_binding_change
    on shared_auth.provider_identities;
create trigger auth_challenges_provider_binding_change
after update of shared_user_id, email, email_verified or delete
on shared_auth.provider_identities
for each row execute function shared_auth.consume_provider_otp_challenges_on_binding_change();

-- HMAC-authenticated sync events are recorded before they are applied. The
-- primary key makes webhook retries idempotent across all replicas.
create table if not exists shared_auth.webhook_events (
    event_id           uuid        primary key,
    provider           text        not null,
    event_type         text        not null,
    received_at        timestamptz not null default now(),
    payload_sha256     text        not null check (length(payload_sha256) = 43)
);

create index if not exists webhook_events_received_idx
    on shared_auth.webhook_events (received_at);

-- Short-lived search state contains only exact provider-identity snapshots and
-- a hash of a high-entropy selection token. The transient email alias is never
-- persisted, not even as an enumerable unkeyed digest.
create table if not exists shared_auth.global_revocation_searches (
    operation_id         uuid        primary key,
    requested_by         uuid        not null references shared_auth.principals(shared_user_id),
    requested_by_principal_ref uuid   not null references shared_auth.admin_principal_refs(principal_ref),
    request_id           text        not null unique check (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    email_search_key_hash text       not null check (length(email_search_key_hash) = 43),
    created_at           timestamptz not null default now(),
    expires_at           timestamptz not null,
    check (expires_at > created_at)
);

create index if not exists global_revocation_searches_actor_idx
    on shared_auth.global_revocation_searches (requested_by, created_at desc);
create index if not exists global_revocation_searches_expiry_idx
    on shared_auth.global_revocation_searches (expires_at);

create table if not exists shared_auth.global_revocation_search_candidates (
    operation_id         uuid        not null references shared_auth.global_revocation_searches(operation_id) on delete cascade,
    provider_identity_id uuid        not null,
    shared_user_id       uuid        not null references shared_auth.principals(shared_user_id),
    principal_ref        uuid        not null references shared_auth.admin_principal_refs(principal_ref),
    provider             text        not null,
    provider_tenant      text        not null,
    provider_tenant_ref  uuid        not null references shared_auth.admin_provider_tenant_refs(provider_tenant_ref),
    provider_subject     text        not null,
    primary key (operation_id, provider_identity_id),
    check (length(provider) between 1 and 64),
    check (length(provider_tenant) between 1 and 255),
    check (length(provider_subject) between 1 and 512)
);

create table if not exists shared_auth.global_revocation_selections (
    selection_id_hash      text        primary key check (length(selection_id_hash) = 43),
    operation_id           uuid        not null references shared_auth.global_revocation_searches(operation_id) on delete cascade,
    request_id             text        not null check (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    selected_by            uuid        not null references shared_auth.principals(shared_user_id),
    selected_by_principal_ref uuid     not null references shared_auth.admin_principal_refs(principal_ref),
    target_shared_user_id  uuid        not null references shared_auth.principals(shared_user_id),
    target_principal_ref   uuid        not null references shared_auth.admin_principal_refs(principal_ref),
    target_provider        text        not null,
    target_provider_tenant text        not null,
    target_provider_subject text       not null,
    selected_at            timestamptz not null default now(),
    expires_at             timestamptz not null,
    preview_id             uuid        unique,
    unique (operation_id, selected_by, target_principal_ref),
    check (expires_at > selected_at)
);

-- Operator previews bind a short-lived search selection to one immutable
-- identity. Neither raw email nor an enumerable email digest is retained.
create table if not exists shared_auth.global_revocation_previews (
    preview_id              uuid        primary key,
    selection_id_hash       text        not null unique references shared_auth.global_revocation_selections(selection_id_hash),
    request_id              text        not null check (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    previewed_by            uuid        not null references shared_auth.principals(shared_user_id),
    previewed_by_principal_ref uuid     not null references shared_auth.admin_principal_refs(principal_ref),
    target_shared_user_id   uuid        not null references shared_auth.principals(shared_user_id),
    target_principal_ref    uuid        not null references shared_auth.admin_principal_refs(principal_ref),
    target_provider         text        not null,
    target_provider_tenant  text        not null,
    target_provider_subject text        not null,
    requested_scopes        jsonb       not null,
    blast_radius            jsonb       not null,
    created_at              timestamptz not null default now(),
    expires_at              timestamptz not null,
    committed_job_id        uuid,
    check (jsonb_typeof(requested_scopes) = 'array'),
    check (jsonb_typeof(blast_radius) = 'object'),
    check (expires_at > created_at),
    check (length(target_provider) between 1 and 64),
    check (length(target_provider_tenant) between 1 and 255),
    check (length(target_provider_subject) between 1 and 512)
);

alter table shared_auth.global_revocation_previews
    drop column if exists search_alias_hash;

create index if not exists global_revocation_previews_target_idx
    on shared_auth.global_revocation_previews (target_shared_user_id, created_at desc);

alter table shared_auth.global_revocation_selections
    drop constraint if exists global_revocation_selections_preview_id_fkey;
alter table shared_auth.global_revocation_selections
    add constraint global_revocation_selections_preview_id_fkey
    foreign key (preview_id) references shared_auth.global_revocation_previews(preview_id);

create table if not exists shared_auth.global_revocation_commit_authorizations (
    commit_authorization_id_hash text primary key check (length(commit_authorization_id_hash) = 43),
    preview_id              uuid        not null references shared_auth.global_revocation_previews(preview_id),
    target_shared_user_id   uuid        not null references shared_auth.principals(shared_user_id),
    target_principal_ref    uuid        not null references shared_auth.admin_principal_refs(principal_ref),
    selected_scopes         jsonb       not null check (jsonb_typeof(selected_scopes) = 'array'),
    authorized_by           uuid        not null references shared_auth.principals(shared_user_id),
    authorized_by_principal_ref uuid    not null references shared_auth.admin_principal_refs(principal_ref),
    authorized_by_session_id_hash text  not null check (length(authorized_by_session_id_hash) = 43),
    evidence_id_hash        text        not null check (length(evidence_id_hash) = 43),
    verified_at             timestamptz not null,
    fresh_until             timestamptz not null,
    issued_at               timestamptz not null default now(),
    expires_at              timestamptz not null,
    consumed_job_id         uuid        unique,
    check (fresh_until > verified_at),
    check (expires_at > issued_at and expires_at <= fresh_until)
);

create table if not exists shared_auth.global_revocation_jobs (
    job_id                  uuid        primary key,
    preview_id              uuid        not null unique references shared_auth.global_revocation_previews(preview_id),
    committed_by            uuid        not null references shared_auth.principals(shared_user_id),
    committed_by_principal_ref uuid     not null references shared_auth.admin_principal_refs(principal_ref),
    commit_authorization_id_hash text   not null unique references shared_auth.global_revocation_commit_authorizations(commit_authorization_id_hash),
    idempotency_key_hash    text        not null check (length(idempotency_key_hash) = 43),
    target_shared_user_id   uuid        not null references shared_auth.principals(shared_user_id),
    target_principal_ref    uuid        not null references shared_auth.admin_principal_refs(principal_ref),
    target_provider         text        not null,
    target_provider_tenant  text        not null,
    target_provider_subject text        not null,
    requested_scopes        jsonb       not null,
    previous_auth_epoch     bigint      not null check (previous_auth_epoch >= 0),
    auth_epoch              bigint      not null check (auth_epoch >= 1),
    auth_not_before         timestamptz not null,
    actual_impact           jsonb       not null,
    requested_at            timestamptz not null,
    request_id              text        not null check (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    trace_id                text        not null check (trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    reason_code             text        not null check (reason_code ~ '^[a-z][a-z0-9._:-]{0,127}$'),
    ticket_reference_hash   text        check (ticket_reference_hash is null or length(ticket_reference_hash) between 16 and 128),
    actor_session_id_hash   text        not null check (length(actor_session_id_hash) = 43),
    audit_event_id          uuid        not null unique,
    correlation_id          uuid        not null unique,
    status                  text        not null
                                        check (status in (
                                            'committed_local_queued_fanout',
                                            'complete', 'partial', 'failed'
                                        )),
    created_at              timestamptz not null default now(),
    updated_at              timestamptz not null default now(),
    completed_at            timestamptz,
    unique (committed_by, idempotency_key_hash),
    check (jsonb_typeof(requested_scopes) = 'array'),
    check (jsonb_typeof(actual_impact) = 'object'),
    check (length(target_provider) between 1 and 64),
    check (length(target_provider_tenant) between 1 and 255),
    check (length(target_provider_subject) between 1 and 512)
);

alter table shared_auth.global_revocation_previews
    drop constraint if exists global_revocation_previews_committed_job_id_fkey;
alter table shared_auth.global_revocation_previews
    add constraint global_revocation_previews_committed_job_id_fkey
    foreign key (committed_job_id) references shared_auth.global_revocation_jobs(job_id);
alter table shared_auth.global_revocation_commit_authorizations
    drop constraint if exists global_revocation_commit_authorizations_consumed_job_id_fkey;
alter table shared_auth.global_revocation_commit_authorizations
    add constraint global_revocation_commit_authorizations_consumed_job_id_fkey
    foreign key (consumed_job_id) references shared_auth.global_revocation_jobs(job_id);

-- Targets expose truthful propagation state. Missing external adapters are
-- terminally unsupported; they are never reported as successful merely
-- because the Postgres fence committed.
create table if not exists shared_auth.global_revocation_targets (
    job_id             uuid        not null references shared_auth.global_revocation_jobs(job_id) on delete cascade,
    target_id_hash     text        not null check (length(target_id_hash) = 43),
    provider_id        text        not null,
    provider_tenant_id text        not null,
    opaque_identity_handle text    not null,
    scope               text       not null check (scope in (
                                    'interactive_sessions', 'refresh_token_families',
                                    'offline_grants', 'downstream_sessions',
                                    'impersonation_sessions', 'user_api_credentials',
                                    'registered_device_sessions')),
    status             text        not null default 'pending'
                                   check (status in ('pending', 'running', 'retry_scheduled',
                                                     'succeeded', 'failed', 'skipped', 'unsupported')),
    attempts           integer     not null default 0 check (attempts >= 0),
    last_error_code    text,
    retryable          boolean     not null default false,
    last_attempt_at    timestamptz,
    next_attempt_at    timestamptz,
    retry_after_seconds integer    check (retry_after_seconds between 1 and 86400),
    completed_at       timestamptz,
    provider_request_id_hash text,
    residual_access_token_max_seconds integer check (residual_access_token_max_seconds between 0 and 86400),
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now(),
    primary key (job_id, target_id_hash),
    check (length(provider_id) between 1 and 128),
    check (length(provider_tenant_id) between 1 and 128),
    check (length(opaque_identity_handle) between 16 and 128),
    check (last_error_code is null or length(last_error_code) <= 64)
);

-- Exact provider identities are snapshotted at the central fence. Delayed
-- workers consume this table rather than re-querying live identity links,
-- preventing both missed removed links and accidental revocation of identities
-- added after the operation linearized. API/audit responses expose only the
-- opaque target key from global_revocation_targets.
create table if not exists shared_auth.global_revocation_provider_snapshots (
    job_id                  uuid        not null references shared_auth.global_revocation_jobs(job_id) on delete cascade,
    provider_identity_id    uuid        not null,
    provider                text        not null,
    provider_tenant         text        not null,
    provider_subject        text        not null,
    opaque_target_key       text        not null check (length(opaque_target_key) = 43),
    created_at              timestamptz not null default now(),
    primary key (job_id, provider_identity_id),
    unique (job_id, provider, provider_tenant, provider_subject),
    unique (job_id, opaque_target_key),
    check (length(provider) between 1 and 64),
    check (length(provider_tenant) between 1 and 255),
    check (length(provider_subject) between 1 and 512)
);

-- Audit payloads contain opaque ids, scopes, counts, epochs, and status only.
-- Provider subjects and raw email aliases are deliberately kept out.
create table if not exists shared_auth.global_revocation_audit_events (
    sequence_id        bigserial   primary key,
    event_id           uuid        not null unique,
    job_id             uuid        references shared_auth.global_revocation_jobs(job_id),
    actor_id            uuid        not null references shared_auth.principals(shared_user_id),
    target_principal_id uuid        not null references shared_auth.principals(shared_user_id),
    event_type         text        not null,
    redacted_payload   jsonb       not null,
    created_at         timestamptz not null default now(),
    check (length(event_type) between 1 and 64),
    check (jsonb_typeof(redacted_payload) = 'object')
);

create or replace function shared_auth.reject_global_revocation_audit_mutation()
returns trigger
language plpgsql
as $$
begin
    raise exception 'global revocation audit events are immutable';
end;
$$;

drop trigger if exists global_revocation_audit_immutable
    on shared_auth.global_revocation_audit_events;
create trigger global_revocation_audit_immutable
    before update or delete on shared_auth.global_revocation_audit_events
    for each row execute function shared_auth.reject_global_revocation_audit_mutation();

-- Transactional outbox: workers may retry these opaque references, but no
-- provider call, email delivery, or WebSocket acknowledgement is fabricated by
-- the request handler.
create table if not exists shared_auth.global_revocation_outbox (
    outbox_id          uuid        primary key,
    job_id             uuid        not null references shared_auth.global_revocation_jobs(job_id) on delete cascade,
    event_type         text        not null,
    payload            jsonb       not null,
    status             text        not null default 'queued'
                                   check (status in ('queued', 'processing', 'complete', 'failed')),
    attempts           integer     not null default 0 check (attempts >= 0),
    next_attempt_at    timestamptz not null default now(),
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now(),
    unique (job_id, event_type),
    check (length(event_type) between 1 and 64),
    check (jsonb_typeof(payload) = 'object')
);

create index if not exists global_revocation_outbox_ready_idx
    on shared_auth.global_revocation_outbox (next_attempt_at, created_at)
    where status in ('queued', 'failed');

-- Risk, QR, and third-party IDV. Raw IP, client hints, ID photos, and face
-- templates are never stored. Only HMAC digests, challenge hashes, vendor
-- inquiry ids, and age-over-N verdicts persist.
create table if not exists shared_auth.risk_signals (
    signal_id          uuid        primary key default gen_random_uuid(),
    shared_user_id     uuid        references shared_auth.principals(shared_user_id),
    ip_hash            text        not null check (length(ip_hash) = 43),
    ip_class           text        not null check (ip_class in (
                                    'public', 'private', 'loopback', 'link_local',
                                    'unspecified', 'invalid')),
    fingerprint_hash   text        check (fingerprint_hash is null or length(fingerprint_hash) = 43),
    decision           text        not null check (decision in ('allow', 'warn', 'step_up', 'deny')),
    score              smallint    not null check (score between 0 and 100),
    signals            text[]      not null default '{}',
    embedding_similarity double precision check (embedding_similarity is null or (
                                    embedding_similarity >= 0 and embedding_similarity <= 1)),
    created_at         timestamptz not null default now()
);

create index if not exists risk_signals_principal_idx
    on shared_auth.risk_signals (shared_user_id, created_at desc);

create table if not exists shared_auth.qr_challenges (
    challenge_id       uuid        primary key,
    purpose            text        not null check (purpose in ('login', 'device_bind')),
    nonce_hash         text        not null check (length(nonce_hash) = 43),
    created_for        uuid        references shared_auth.principals(shared_user_id),
    approved_by        uuid        references shared_auth.principals(shared_user_id),
    consumed_at        timestamptz,
    expires_at         timestamptz not null,
    created_at         timestamptz not null default now(),
    check (expires_at > created_at)
);

create index if not exists qr_challenges_open_idx
    on shared_auth.qr_challenges (expires_at)
    where consumed_at is null;

create table if not exists shared_auth.idv_sessions (
    session_id         uuid        primary key,
    shared_user_id     uuid        not null references shared_auth.principals(shared_user_id),
    provider           text        not null check (length(provider) between 1 and 64),
    provider_session_id text       not null check (length(provider_session_id) between 8 and 128),
    status             text        not null check (status in (
                                    'pending', 'passed', 'failed', 'review', 'expired')),
    document_verified  boolean,
    face_match         boolean,
    face_liveness      boolean,
    age_over_18        boolean,
    age_over_21        boolean,
    estimated_age_years smallint   check (estimated_age_years is null or estimated_age_years between 0 and 120),
    document_type      text        check (document_type is null or length(document_type) between 1 and 32),
    stores_raw_media   boolean     not null default false check (stores_raw_media = false),
    expires_at         timestamptz not null,
    created_at         timestamptz not null default now(),
    completed_at       timestamptz
);

create index if not exists idv_sessions_principal_idx
    on shared_auth.idv_sessions (shared_user_id, created_at desc);
