\set ON_ERROR_STOP on

BEGIN;

INSERT INTO shared_auth.applications (
    application_id, application_key, display_name
) VALUES
    ('00000000-0000-0000-0000-0000000000a1', 'workload-a', 'Workload A'),
    ('00000000-0000-0000-0000-0000000000b1', 'workload-b', 'Workload B');

INSERT INTO shared_auth.oauth_clients (
    client_id, application_id, audience, client_type, client_secret_hash,
    allowed_scopes, status
) VALUES
    (
        'svc-a',
        '00000000-0000-0000-0000-0000000000a1',
        'workload-api-a',
        'confidential',
        repeat('a', 43),
        '["svc:read","svc:write"]'::jsonb,
        'active'
    ),
    (
        'svc-public',
        '00000000-0000-0000-0000-0000000000a1',
        'workload-public-a',
        'public',
        NULL,
        '["svc:read"]'::jsonb,
        'active'
    ),
    (
        'svc-b',
        '00000000-0000-0000-0000-0000000000b1',
        'workload-api-b',
        'confidential',
        repeat('c', 43),
        '["svc:read"]'::jsonb,
        'active'
    );

INSERT INTO shared_auth.service_accounts (
    service_account_id, application_id, service_account_key, display_name
) VALUES
    (
        '10000000-0000-0000-0000-0000000000a1',
        '00000000-0000-0000-0000-0000000000a1',
        'build-a',
        'Build A'
    ),
    (
        '10000000-0000-0000-0000-0000000000b1',
        '00000000-0000-0000-0000-0000000000b1',
        'build-b',
        'Build B'
    );

INSERT INTO shared_auth.oauth_client_workload_bindings (
    client_id, service_account_id, allowed_scopes, default_scopes
) VALUES (
    'svc-a',
    '10000000-0000-0000-0000-0000000000a1',
    '["svc:read","svc:write"]'::jsonb,
    '["svc:read"]'::jsonb
);

DO $$
BEGIN
    BEGIN
        INSERT INTO shared_auth.oauth_client_workload_bindings (
            client_id, service_account_id, allowed_scopes, default_scopes
        ) VALUES (
            'svc-b',
            '10000000-0000-0000-0000-0000000000a1',
            '["svc:read"]'::jsonb,
            '["svc:read"]'::jsonb
        );
        RAISE EXCEPTION 'cross-application workload binding unexpectedly succeeded';
    EXCEPTION
        WHEN raise_exception THEN
            IF SQLERRM = 'cross-application workload binding unexpectedly succeeded' THEN
                RAISE;
            END IF;
    END;

    BEGIN
        INSERT INTO shared_auth.oauth_client_workload_bindings (
            client_id, service_account_id, allowed_scopes, default_scopes
        ) VALUES (
            'svc-public',
            '10000000-0000-0000-0000-0000000000a1',
            '["svc:read"]'::jsonb,
            '["svc:read"]'::jsonb
        );
        RAISE EXCEPTION 'public OAuth client workload binding unexpectedly succeeded';
    EXCEPTION
        WHEN raise_exception THEN
            IF SQLERRM = 'public OAuth client workload binding unexpectedly succeeded' THEN
                RAISE;
            END IF;
    END;
END;
$$;

UPDATE shared_auth.service_accounts
SET status = 'disabled'
WHERE service_account_id = '10000000-0000-0000-0000-0000000000a1';

DO $$
DECLARE
    current_epoch BIGINT;
BEGIN
    SELECT auth_epoch INTO current_epoch
    FROM shared_auth.service_accounts
    WHERE service_account_id = '10000000-0000-0000-0000-0000000000a1';

    IF current_epoch <> 1 THEN
        RAISE EXCEPTION 'service-account disable did not advance auth_epoch: %', current_epoch;
    END IF;
END;
$$;

UPDATE shared_auth.service_accounts
SET status = 'active'
WHERE service_account_id = '10000000-0000-0000-0000-0000000000a1';

DO $$
DECLARE
    current_epoch BIGINT;
BEGIN
    SELECT auth_epoch INTO current_epoch
    FROM shared_auth.service_accounts
    WHERE service_account_id = '10000000-0000-0000-0000-0000000000a1';

    IF current_epoch <> 2 THEN
        RAISE EXCEPTION 'service-account re-enable resurrected old epoch: %', current_epoch;
    END IF;
END;
$$;

UPDATE shared_auth.oauth_clients
SET client_secret_hash = repeat('b', 43)
WHERE client_id = 'svc-a';

DO $$
DECLARE
    current_epoch BIGINT;
    current_status TEXT;
BEGIN
    SELECT credential_epoch, status
      INTO current_epoch, current_status
      FROM shared_auth.oauth_client_workload_bindings
     WHERE client_id = 'svc-a';

    IF current_epoch <> 1 OR current_status <> 'active' THEN
        RAISE EXCEPTION 'secret rotation did not invalidate workload epoch correctly: %, %',
            current_epoch, current_status;
    END IF;
END;
$$;

-- Narrowing the OAuth registration below the workload binding must revoke the
-- binding instead of blocking the registration update or silently narrowing a
-- live machine token.
UPDATE shared_auth.oauth_clients
SET allowed_scopes = '["svc:read"]'::jsonb
WHERE client_id = 'svc-a';

DO $$
DECLARE
    current_epoch BIGINT;
    current_status TEXT;
BEGIN
    SELECT credential_epoch, status
      INTO current_epoch, current_status
      FROM shared_auth.oauth_client_workload_bindings
     WHERE client_id = 'svc-a';

    IF current_epoch <> 2 OR current_status <> 'disabled' THEN
        RAISE EXCEPTION 'scope narrowing did not disable workload binding: %, %',
            current_epoch, current_status;
    END IF;
END;
$$;

-- Re-expanding the OAuth registration is not enough to reactivate workload
-- authority; the binding itself must be reviewed/re-enabled.
UPDATE shared_auth.oauth_clients
SET allowed_scopes = '["svc:read","svc:write"]'::jsonb
WHERE client_id = 'svc-a';

DO $$
DECLARE
    current_status TEXT;
BEGIN
    SELECT status INTO current_status
    FROM shared_auth.oauth_client_workload_bindings
    WHERE client_id = 'svc-a';

    IF current_status <> 'disabled' THEN
        RAISE EXCEPTION 'OAuth scope re-expansion silently re-enabled workload binding';
    END IF;
END;
$$;

UPDATE shared_auth.oauth_client_workload_bindings
SET allowed_scopes = '["svc:read"]'::jsonb,
    default_scopes = '["svc:read"]'::jsonb,
    status = 'active'
WHERE client_id = 'svc-a';

DO $$
DECLARE
    current_epoch BIGINT;
    current_status TEXT;
BEGIN
    SELECT credential_epoch, status
      INTO current_epoch, current_status
      FROM shared_auth.oauth_client_workload_bindings
     WHERE client_id = 'svc-a';

    IF current_epoch <= 2 OR current_status <> 'active' THEN
        RAISE EXCEPTION 'explicit reviewed reactivation did not advance epoch: %, %',
            current_epoch, current_status;
    END IF;
END;
$$;

-- Create one issuance lineage at the current epochs.
INSERT INTO shared_auth.workload_sessions (
    session_id,
    service_account_id,
    client_id,
    service_account_auth_epoch,
    credential_epoch,
    audience,
    scopes,
    expires_at
)
SELECT
    '20000000-0000-0000-0000-0000000000a1',
    sa.service_account_id,
    b.client_id,
    sa.auth_epoch,
    b.credential_epoch,
    c.audience,
    '["svc:read"]'::jsonb,
    now() + interval '5 minutes'
FROM shared_auth.service_accounts sa
JOIN shared_auth.oauth_client_workload_bindings b
  ON b.service_account_id = sa.service_account_id
JOIN shared_auth.oauth_clients c
  ON c.client_id = b.client_id
WHERE b.client_id = 'svc-a';

-- Client disable invalidates the credential epoch and disables the binding.
UPDATE shared_auth.oauth_clients
SET status = 'disabled'
WHERE client_id = 'svc-a';

DO $$
DECLARE
    still_matches BOOLEAN;
    current_status TEXT;
BEGIN
    SELECT (
        ws.credential_epoch = b.credential_epoch
        AND ws.service_account_auth_epoch = sa.auth_epoch
    ), b.status
      INTO still_matches, current_status
      FROM shared_auth.workload_sessions ws
      JOIN shared_auth.oauth_client_workload_bindings b
        ON b.client_id = ws.client_id
       AND b.service_account_id = ws.service_account_id
      JOIN shared_auth.service_accounts sa
        ON sa.service_account_id = ws.service_account_id
     WHERE ws.session_id = '20000000-0000-0000-0000-0000000000a1';

    IF still_matches OR current_status <> 'disabled' THEN
        RAISE EXCEPTION 'OAuth client disable did not invalidate workload session';
    END IF;
END;
$$;

UPDATE shared_auth.oauth_clients
SET status = 'active'
WHERE client_id = 'svc-a';

DO $$
DECLARE
    current_status TEXT;
BEGIN
    SELECT status INTO current_status
    FROM shared_auth.oauth_client_workload_bindings
    WHERE client_id = 'svc-a';

    IF current_status <> 'disabled' THEN
        RAISE EXCEPTION 'OAuth client re-enable silently reactivated workload binding';
    END IF;
END;
$$;

ROLLBACK;
