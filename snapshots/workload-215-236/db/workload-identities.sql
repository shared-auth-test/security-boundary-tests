-- First-class Shared Auth workload identities.
--
-- This plane is deliberately separate from shared_auth.principals and
-- shared_auth.sessions. OAuth clients authenticate software; they must never be
-- coerced into fake human principals merely to reuse human-session revocation.
--
-- Parent issues:
--   shared-auth/shared-auth-server.rs#210 -- workload/service identities
--   shared-auth/shared-auth-server.rs#209 -- OAuth client_credentials consumer

CREATE SCHEMA IF NOT EXISTS shared_auth;

CREATE TABLE IF NOT EXISTS shared_auth.service_accounts (
    service_account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL
        REFERENCES shared_auth.applications(application_id) ON DELETE CASCADE,
    service_account_key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    auth_epoch BIGINT NOT NULL DEFAULT 0,
    auth_not_before TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT service_accounts_key_shape CHECK (
        service_account_key ~ '^[A-Za-z0-9._:-]{3,128}$'
    ),
    CONSTRAINT service_accounts_display_name_bound CHECK (
        char_length(display_name) BETWEEN 1 AND 200
    ),
    CONSTRAINT service_accounts_status_check CHECK (
        status IN ('active', 'disabled')
    ),
    CONSTRAINT service_accounts_auth_epoch_nonnegative CHECK (
        auth_epoch >= 0
    ),
    CONSTRAINT service_accounts_application_key_unique UNIQUE (
        application_id,
        service_account_key
    )
);

CREATE TABLE IF NOT EXISTS shared_auth.oauth_client_workload_bindings (
    client_id TEXT PRIMARY KEY
        REFERENCES shared_auth.oauth_clients(client_id) ON DELETE CASCADE,
    service_account_id UUID NOT NULL
        REFERENCES shared_auth.service_accounts(service_account_id) ON DELETE CASCADE,
    allowed_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    default_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'active',
    credential_epoch BIGINT NOT NULL DEFAULT 0,
    credential_not_before TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT oauth_client_workload_binding_pair_unique UNIQUE (
        client_id,
        service_account_id
    ),
    CONSTRAINT oauth_client_workload_allowed_scopes_array CHECK (
        jsonb_typeof(allowed_scopes) = 'array'
        AND jsonb_array_length(allowed_scopes) <= 16
    ),
    CONSTRAINT oauth_client_workload_default_scopes_array CHECK (
        jsonb_typeof(default_scopes) = 'array'
        AND jsonb_array_length(default_scopes) <= 16
    ),
    CONSTRAINT oauth_client_workload_status_check CHECK (
        status IN ('active', 'disabled')
    ),
    CONSTRAINT oauth_client_workload_credential_epoch_nonnegative CHECK (
        credential_epoch >= 0
    )
);

CREATE TABLE IF NOT EXISTS shared_auth.workload_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_account_id UUID NOT NULL,
    client_id TEXT NOT NULL,
    service_account_auth_epoch BIGINT NOT NULL,
    credential_epoch BIGINT NOT NULL,
    audience TEXT NOT NULL,
    scopes JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT workload_sessions_binding_fk FOREIGN KEY (
        client_id,
        service_account_id
    ) REFERENCES shared_auth.oauth_client_workload_bindings(
        client_id,
        service_account_id
    ) ON DELETE CASCADE,
    CONSTRAINT workload_sessions_service_epoch_nonnegative CHECK (
        service_account_auth_epoch >= 0
    ),
    CONSTRAINT workload_sessions_credential_epoch_nonnegative CHECK (
        credential_epoch >= 0
    ),
    CONSTRAINT workload_sessions_audience_bound CHECK (
        char_length(audience) BETWEEN 1 AND 256
    ),
    CONSTRAINT workload_sessions_scopes_array CHECK (
        jsonb_typeof(scopes) = 'array'
        AND jsonb_array_length(scopes) BETWEEN 1 AND 16
    ),
    CONSTRAINT workload_sessions_expiry_order CHECK (
        expires_at > created_at
    ),
    CONSTRAINT workload_sessions_revocation_order CHECK (
        revoked_at IS NULL OR revoked_at >= created_at
    )
);

CREATE INDEX IF NOT EXISTS workload_sessions_active_service_idx
    ON shared_auth.workload_sessions(service_account_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS workload_sessions_active_client_idx
    ON shared_auth.workload_sessions(client_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE OR REPLACE FUNCTION shared_auth.workload_scope_array_is_valid(value JSONB)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT
        jsonb_typeof(value) = 'array'
        AND jsonb_array_length(value) BETWEEN 0 AND 16
        AND NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements(value) AS item(element)
            WHERE jsonb_typeof(element) <> 'string'
               OR char_length(element #>> '{}') NOT BETWEEN 1 AND 128
               OR (element #>> '{}') !~ '^[A-Za-z0-9:_.-]+$'
               OR (element #>> '{}') IN ('openid', 'offline_access')
        )
        AND (
            SELECT count(*)
            FROM jsonb_array_elements_text(value)
        ) = (
            SELECT count(DISTINCT item.scope)
            FROM jsonb_array_elements_text(value) AS item(scope)
        );
$$;

CREATE OR REPLACE FUNCTION shared_auth.workload_scope_array_is_subset(
    candidate JSONB,
    allowed JSONB
)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
AS $$
    SELECT NOT EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text(candidate) AS requested(scope)
        WHERE NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements_text(allowed) AS permitted(scope)
            WHERE permitted.scope = requested.scope
        )
    );
$$;

CREATE OR REPLACE FUNCTION shared_auth.enforce_service_account_epoch()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.application_id IS DISTINCT FROM OLD.application_id THEN
        RAISE EXCEPTION 'service account application_id is immutable';
    END IF;

    IF NEW.service_account_key IS DISTINCT FROM OLD.service_account_key THEN
        RAISE EXCEPTION 'service account key is immutable';
    END IF;

    IF NEW.auth_epoch < OLD.auth_epoch THEN
        RAISE EXCEPTION 'service account auth_epoch cannot decrease';
    END IF;

    IF NEW.status IS DISTINCT FROM OLD.status AND NEW.auth_epoch <= OLD.auth_epoch THEN
        NEW.auth_epoch := OLD.auth_epoch + 1;
        NEW.auth_not_before := now();
    END IF;

    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS service_account_epoch_guard
    ON shared_auth.service_accounts;
CREATE TRIGGER service_account_epoch_guard
BEFORE UPDATE ON shared_auth.service_accounts
FOR EACH ROW
EXECUTE FUNCTION shared_auth.enforce_service_account_epoch();

CREATE OR REPLACE FUNCTION shared_auth.validate_workload_client_binding()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    oauth_application_id UUID;
    oauth_client_type TEXT;
    oauth_status TEXT;
    oauth_allowed_scopes JSONB;
    service_application_id UUID;
BEGIN
    SELECT application_id, client_type, status, allowed_scopes
      INTO STRICT oauth_application_id, oauth_client_type, oauth_status, oauth_allowed_scopes
      FROM shared_auth.oauth_clients
     WHERE client_id = NEW.client_id;

    SELECT application_id
      INTO STRICT service_application_id
      FROM shared_auth.service_accounts
     WHERE service_account_id = NEW.service_account_id;

    IF oauth_client_type <> 'confidential' THEN
        RAISE EXCEPTION 'workload identity requires a confidential OAuth client';
    END IF;

    IF oauth_application_id IS DISTINCT FROM service_application_id THEN
        RAISE EXCEPTION 'OAuth client and service account must belong to the same application';
    END IF;

    IF NEW.status = 'active' AND oauth_status <> 'active' THEN
        RAISE EXCEPTION 'active workload binding requires an active OAuth client';
    END IF;

    IF NEW.status = 'active' AND NOT shared_auth.workload_scope_array_is_subset(
        NEW.allowed_scopes,
        oauth_allowed_scopes
    ) THEN
        RAISE EXCEPTION 'active workload scopes exceed OAuth client registration';
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF NEW.client_id IS DISTINCT FROM OLD.client_id
           OR NEW.service_account_id IS DISTINCT FROM OLD.service_account_id THEN
            RAISE EXCEPTION 'workload binding identity is immutable';
        END IF;

        IF NEW.credential_epoch < OLD.credential_epoch THEN
            RAISE EXCEPTION 'workload credential_epoch cannot decrease';
        END IF;

        IF (
            NEW.status IS DISTINCT FROM OLD.status
            OR NEW.allowed_scopes IS DISTINCT FROM OLD.allowed_scopes
            OR NEW.default_scopes IS DISTINCT FROM OLD.default_scopes
        ) AND NEW.credential_epoch <= OLD.credential_epoch THEN
            NEW.credential_epoch := OLD.credential_epoch + 1;
            NEW.credential_not_before := now();
        END IF;
    END IF;

    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS workload_client_binding_guard
    ON shared_auth.oauth_client_workload_bindings;
CREATE TRIGGER workload_client_binding_guard
BEFORE INSERT OR UPDATE ON shared_auth.oauth_client_workload_bindings
FOR EACH ROW
EXECUTE FUNCTION shared_auth.validate_workload_client_binding();

CREATE OR REPLACE FUNCTION shared_auth.enforce_bound_oauth_client_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    bound_service_application_id UUID;
BEGIN
    SELECT service_account.application_id
      INTO bound_service_application_id
      FROM shared_auth.oauth_client_workload_bindings AS binding
      JOIN shared_auth.service_accounts AS service_account
        ON service_account.service_account_id = binding.service_account_id
     WHERE binding.client_id = OLD.client_id;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF NEW.client_type <> 'confidential' THEN
        RAISE EXCEPTION 'bound workload OAuth client must remain confidential';
    END IF;

    IF NEW.application_id IS DISTINCT FROM bound_service_application_id THEN
        RAISE EXCEPTION 'bound workload OAuth client cannot move applications';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS bound_oauth_client_identity_guard
    ON shared_auth.oauth_clients;
CREATE TRIGGER bound_oauth_client_identity_guard
BEFORE UPDATE OF client_type, application_id ON shared_auth.oauth_clients
FOR EACH ROW
EXECUTE FUNCTION shared_auth.enforce_bound_oauth_client_identity();

CREATE OR REPLACE FUNCTION shared_auth.bump_workload_binding_for_oauth_client_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE shared_auth.oauth_client_workload_bindings
       SET credential_epoch = credential_epoch + 1,
           credential_not_before = now(),
           status = CASE
               WHEN NEW.status <> 'active' THEN 'disabled'
               WHEN OLD.allowed_scopes IS DISTINCT FROM NEW.allowed_scopes
                    AND NOT shared_auth.workload_scope_array_is_subset(
                        allowed_scopes,
                        NEW.allowed_scopes
                    ) THEN 'disabled'
               ELSE status
           END,
           updated_at = now()
     WHERE client_id = NEW.client_id;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS workload_binding_oauth_client_change
    ON shared_auth.oauth_clients;
CREATE TRIGGER workload_binding_oauth_client_change
AFTER UPDATE OF client_secret_hash, status, allowed_scopes, audience
ON shared_auth.oauth_clients
FOR EACH ROW
WHEN (
    OLD.client_secret_hash IS DISTINCT FROM NEW.client_secret_hash
    OR OLD.status IS DISTINCT FROM NEW.status
    OR OLD.allowed_scopes IS DISTINCT FROM NEW.allowed_scopes
    OR OLD.audience IS DISTINCT FROM NEW.audience
)
EXECUTE FUNCTION shared_auth.bump_workload_binding_for_oauth_client_change();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'oauth_client_workload_allowed_scopes_valid'
          AND conrelid = 'shared_auth.oauth_client_workload_bindings'::regclass
    ) THEN
        ALTER TABLE shared_auth.oauth_client_workload_bindings
            ADD CONSTRAINT oauth_client_workload_allowed_scopes_valid CHECK (
                shared_auth.workload_scope_array_is_valid(allowed_scopes)
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'oauth_client_workload_default_scopes_valid'
          AND conrelid = 'shared_auth.oauth_client_workload_bindings'::regclass
    ) THEN
        ALTER TABLE shared_auth.oauth_client_workload_bindings
            ADD CONSTRAINT oauth_client_workload_default_scopes_valid CHECK (
                shared_auth.workload_scope_array_is_valid(default_scopes)
                AND shared_auth.workload_scope_array_is_subset(
                    default_scopes,
                    allowed_scopes
                )
            );
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'workload_sessions_scopes_valid'
          AND conrelid = 'shared_auth.workload_sessions'::regclass
    ) THEN
        ALTER TABLE shared_auth.workload_sessions
            ADD CONSTRAINT workload_sessions_scopes_valid CHECK (
                shared_auth.workload_scope_array_is_valid(scopes)
            );
    END IF;
END;
$$;
