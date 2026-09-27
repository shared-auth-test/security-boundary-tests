impl FactorService {
    async fn lock_active_principal_session(
        &self,
        transaction: &DatabaseTransaction,
        claims: &OreClaims,
    ) -> Result<(Uuid, Uuid), AuthError> {
        let user_id = claim_user_id(claims)?;
        let session_id = claim_session_id(claims)?;
        transaction
            .query_one_raw(statement(
                "SELECT p.shared_user_id \
                 FROM shared_auth.principals p \
                 JOIN shared_auth.sessions s ON s.shared_user_id = p.shared_user_id \
                 WHERE p.shared_user_id = $1 AND p.status = 'active' \
                   AND s.session_id = $2 AND s.revoked_at IS NULL AND s.expires_at > now() \
                   AND s.provider = $3 AND s.provider_tenant = $4 AND s.provider_subject = $5 \
                 FOR UPDATE OF p, s",
                vec![
                    user_id.into(),
                    session_id.into(),
                    claims.provider.clone().into(),
                    claims.provider_tenant.clone().into(),
                    claims.provider_subject.clone().into(),
                ],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        Ok((user_id, session_id))
    }

    async fn authoritative_destination(
        &self,
        transaction: &DatabaseTransaction,
        claims: &OreClaims,
        user_id: Uuid,
        kind: &str,
    ) -> Result<String, AuthError> {
        let destination: String = match kind {
            "email_otp" if claims.provider == "local" => {
                let row = transaction
                    .query_one_raw(statement(
                        "SELECT email FROM shared_auth.principals \
                         WHERE shared_user_id = $1 AND status = 'active' \
                           AND email_verified = true AND email IS NOT NULL",
                        vec![user_id.into()],
                    ))
                    .await
                    .map_err(db_error)?
                    .ok_or(AuthError::BadRequest("verified email is required"))?;
                row.try_get("", "email").map_err(db_error)?
            }
            "email_otp" => {
                let row = transaction
                    .query_one_raw(statement(
                        "SELECT email FROM shared_auth.provider_identities \
                         WHERE shared_user_id = $1 AND provider = $2 \
                           AND provider_tenant = $3 AND provider_subject = $4 \
                           AND email_verified = true AND email IS NOT NULL FOR UPDATE",
                        vec![
                            user_id.into(),
                            claims.provider.clone().into(),
                            claims.provider_tenant.clone().into(),
                            claims.provider_subject.clone().into(),
                        ],
                    ))
                    .await
                    .map_err(db_error)?
                    .ok_or(AuthError::BadRequest("verified email is required"))?;
                row.try_get("", "email").map_err(db_error)?
            }
            "sms_otp" => {
                let row = transaction
                    .query_one_raw(statement(
                        "SELECT phone FROM shared_auth.principals \
                         WHERE shared_user_id = $1 AND status = 'active' \
                           AND phone_verified = true AND phone IS NOT NULL",
                        vec![user_id.into()],
                    ))
                    .await
                    .map_err(db_error)?
                    .ok_or(AuthError::BadRequest("verified phone is required"))?;
                row.try_get("", "phone").map_err(db_error)?
            }
            _ => return Err(AuthError::Unauthorized),
        };
        canonical_destination(kind, &destination)
    }

    async fn create_otp_challenge(
        &self,
        claims: &OreClaims,
        kind: ChallengeKind,
        pepper: &[u8],
    ) -> Result<(ChallengeStart, String, String), AuthError> {
        let code = generate_code()?;
        let expires_at = Utc::now().fixed_offset() + TimeDelta::minutes(OTP_TTL_MINUTES);
        let (db_kind, delivery) = match kind {
            ChallengeKind::EmailOtp => ("email_otp", "email"),
            ChallengeKind::SmsOtp => ("sms_otp", "sms"),
        };
        let challenge_id = Uuid::new_v4();
        let transaction = self.db.begin().await.map_err(db_error)?;
        // The principal/session lock serializes starts across every session for
        // one principal and rejects stale identity-bearing tokens. Destination
        // data is reloaded from the exact local/provider row, never trusted from
        // a JWT that may outlive an email or phone change.
        let (user_id, session_id) = self
            .lock_active_principal_session(&transaction, claims)
            .await?;
        let destination = self
            .authoritative_destination(&transaction, claims, user_id, db_kind)
            .await?;
        let binding_tag =
            destination_binding_tag(pepper, challenge_id, db_kind, &destination)?;
        let budget_key = destination_budget_key(pepper, db_kind, &destination)?;
        let code_tag = otp_tag(pepper, challenge_id, &code)?;

        // Serialize the stable, keyed destination budget even when two
        // different principals target the same destination concurrently. The
        // advisory key is derived inside PostgreSQL from a non-reversible HMAC;
        // no raw email or phone enters a lock name or database index.
        transaction
            .query_one_raw(statement(
                "SELECT pg_advisory_xact_lock(hashtextextended(encode($1::bytea, 'hex'), 0))",
                vec![budget_key.clone().into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Internal)?;
        transaction
            .execute_raw(statement(
                "UPDATE shared_auth.auth_challenges SET consumed_at = now() \
                 WHERE shared_user_id = $1 AND kind = $2 \
                   AND consumed_at IS NULL AND expires_at <= now()",
                vec![user_id.into(), db_kind.to_owned().into()],
            ))
            .await
            .map_err(db_error)?;
        let budget = transaction
            .query_one_raw(statement(
                "SELECT \
                    count(*) FILTER (WHERE shared_user_id = $1 AND consumed_at IS NULL \
                        AND expires_at > now())::bigint AS active_count, \
                    count(*) FILTER (WHERE shared_user_id = $1)::bigint AS principal_sends, \
                    count(*) FILTER (WHERE destination_budget_key = $2)::bigint AS destination_sends, \
                    max(created_at) FILTER (WHERE shared_user_id = $1 \
                        AND destination_budget_key = $2) AS latest_created_at \
                 FROM shared_auth.auth_challenges \
                 WHERE kind = $3 \
                   AND created_at > now() - ($4::bigint * interval '1 minute')",
                vec![
                    user_id.into(),
                    budget_key.clone().into(),
                    db_kind.to_owned().into(),
                    OTP_SEND_BUDGET_WINDOW_MINUTES.into(),
                ],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Internal)?;
        let active_count: i64 = budget.try_get("", "active_count").map_err(db_error)?;
        let principal_sends: i64 = budget.try_get("", "principal_sends").map_err(db_error)?;
        let destination_sends: i64 = budget
            .try_get("", "destination_sends")
            .map_err(db_error)?;
        let latest_created_at: Option<DateTime<FixedOffset>> =
            budget.try_get("", "latest_created_at").map_err(db_error)?;
        let resend_cutoff = Utc::now().fixed_offset()
            - TimeDelta::seconds(OTP_RESEND_INTERVAL_SECONDS);
        if active_count >= MAX_ACTIVE_OTP_CHALLENGES
            || principal_sends >= MAX_PRINCIPAL_OTP_SENDS_PER_WINDOW
            || destination_sends >= MAX_DESTINATION_OTP_SENDS_PER_WINDOW
            || latest_created_at.is_some_and(|created_at| created_at > resend_cutoff)
        {
            return Err(AuthError::RateLimited);
        }

        transaction
            .execute_raw(statement(
                "INSERT INTO shared_auth.auth_challenges \
                    (challenge_id, shared_user_id, session_id, kind, destination_hint, \
                     destination_binding_tag, destination_budget_key, code_tag, state, max_attempts, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, '{}'::jsonb, $9, $10)",
                vec![
                    challenge_id.into(),
                    user_id.into(),
                    session_id.into(),
                    db_kind.to_owned().into(),
                    mask_destination(&destination).into(),
                    binding_tag.into(),
                    budget_key.into(),
                    code_tag.into(),
                    MAX_OTP_ATTEMPTS.into(),
                    expires_at.into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        transaction.commit().await.map_err(db_error)?;

        Ok((
            ChallengeStart {
                challenge_id: challenge_id.to_string(),
                expires_at: expires_at.to_rfc3339(),
                delivery: delivery.to_owned(),
            },
            destination,
            code,
        ))
    }

    async fn bound_challenge_destination(
        &self,
        claims: &OreClaims,
        challenge_id: Uuid,
        pepper: &[u8],
    ) -> Result<(String, String), AuthError> {
        let transaction = self.db.begin().await.map_err(db_error)?;
        let (user_id, session_id) = self
            .lock_active_principal_session(&transaction, claims)
            .await?;
        let row = transaction
            .query_one_raw(statement(
                "SELECT kind, destination_binding_tag \
                 FROM shared_auth.auth_challenges \
                 WHERE challenge_id = $1 AND shared_user_id = $2 AND session_id = $3 \
                   AND kind IN ('email_otp', 'sms_otp') AND consumed_at IS NULL \
                   AND expires_at > now() AND attempts < max_attempts FOR UPDATE",
                vec![challenge_id.into(), user_id.into(), session_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        let kind: String = row.try_get("", "kind").map_err(db_error)?;
        let expected: Option<Vec<u8>> = row
            .try_get("", "destination_binding_tag")
            .map_err(db_error)?;
        let destination = self
            .authoritative_destination(&transaction, claims, user_id, &kind)
            .await?;
        let binding_matches = expected.as_deref().is_some_and(|expected| {
            destination_binding_matches(
                pepper,
                challenge_id,
                &kind,
                &destination,
                expected,
            )
        });
        if !binding_matches {
            transaction
                .execute_raw(statement(
                    "UPDATE shared_auth.auth_challenges \
                     SET consumed_at = coalesce(consumed_at, now()), attempts = max_attempts \
                     WHERE challenge_id = $1 AND shared_user_id = $2 AND session_id = $3",
                    vec![challenge_id.into(), user_id.into(), session_id.into()],
                ))
                .await
                .map_err(db_error)?;
            transaction.commit().await.map_err(db_error)?;
            return Err(AuthError::Unauthorized);
        }
        transaction.commit().await.map_err(db_error)?;
        Ok((kind, destination))
    }

    async fn record_failed_otp_attempt(
        &self,
        claims: &OreClaims,
        challenge_id: Uuid,
        expected_kind: &str,
    ) -> Result<(), AuthError> {
        if expected_kind != "sms_otp" {
            return Err(AuthError::Unauthorized);
        }
        let result = self
            .db
            .execute_raw(statement(
                "UPDATE shared_auth.auth_challenges SET attempts = attempts + 1 \
                 WHERE challenge_id = $1 AND shared_user_id = $2 AND session_id = $3 \
                   AND kind = $4 AND consumed_at IS NULL AND expires_at > now() \
                   AND attempts < max_attempts",
                vec![
                    challenge_id.into(),
                    claim_user_id(claims)?.into(),
                    claim_session_id(claims)?.into(),
                    expected_kind.to_owned().into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(AuthError::Unauthorized)
        }
    }

    async fn verify_otp_challenge(
        &self,
        claims: &OreClaims,
        challenge_id: Uuid,
        code: &str,
        pepper: &[u8],
        externally_verified: bool,
    ) -> Result<&'static str, AuthError> {
        validate_otp(code)?;
        let transaction = self.db.begin().await.map_err(db_error)?;
        let (user_id, session_id) = self
            .lock_active_principal_session(&transaction, claims)
            .await?;
        // Lock before checking the tag, expiry, or attempt count. A concurrent
        // verifier can therefore never consume the same challenge twice or
        // succeed after another request exhausted its attempts. The exact
        // authoritative destination is reloaded and HMAC-compared again after
        // any external provider call.
        let row = transaction
            .query_one_raw(statement(
                "SELECT kind, code_tag, destination_binding_tag \
                 FROM shared_auth.auth_challenges \
                 WHERE challenge_id = $1 AND shared_user_id = $2 AND session_id = $3 \
                   AND kind IN ('email_otp', 'sms_otp') AND consumed_at IS NULL \
                   AND expires_at > now() AND attempts < max_attempts FOR UPDATE",
                vec![challenge_id.into(), user_id.into(), session_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Unauthorized)?;
        let kind: String = row.try_get("", "kind").map_err(db_error)?;
        let expected_code: Vec<u8> = row.try_get("", "code_tag").map_err(db_error)?;
        let expected_binding: Option<Vec<u8>> = row
            .try_get("", "destination_binding_tag")
            .map_err(db_error)?;
        let destination = self
            .authoritative_destination(&transaction, claims, user_id, &kind)
            .await?;
        let binding_matches = expected_binding.as_deref().is_some_and(|expected| {
            destination_binding_matches(
                pepper,
                challenge_id,
                &kind,
                &destination,
                expected,
            )
        });
        if !binding_matches {
            transaction
                .execute_raw(statement(
                    "UPDATE shared_auth.auth_challenges \
                     SET consumed_at = coalesce(consumed_at, now()), attempts = max_attempts \
                     WHERE challenge_id = $1 AND shared_user_id = $2 AND session_id = $3",
                    vec![challenge_id.into(), user_id.into(), session_id.into()],
                ))
                .await
                .map_err(db_error)?;
            transaction.commit().await.map_err(db_error)?;
            return Err(AuthError::Unauthorized);
        }
        if externally_verified && kind != "sms_otp" {
            return Err(AuthError::Unauthorized);
        }
        let valid = externally_verified
            || otp_tag_matches(pepper, challenge_id, code, &expected_code);
        if !valid {
            let result = transaction
                .execute_raw(statement(
                    "UPDATE shared_auth.auth_challenges SET attempts = attempts + 1 \
                     WHERE challenge_id = $1 AND shared_user_id = $2 AND session_id = $3 \
                       AND consumed_at IS NULL AND expires_at > now() AND attempts < max_attempts",
                    vec![challenge_id.into(), user_id.into(), session_id.into()],
                ))
                .await
                .map_err(db_error)?;
            if result.rows_affected() != 1 {
                return Err(AuthError::Unauthorized);
            }
            transaction.commit().await.map_err(db_error)?;
            return Err(AuthError::Unauthorized);
        }

        let result = transaction
            .execute_raw(statement(
                "UPDATE shared_auth.auth_challenges \
                 SET consumed_at = now(), attempts = attempts + 1 \
                 WHERE challenge_id = $1 AND shared_user_id = $2 AND session_id = $3 \
                   AND kind = $4 AND consumed_at IS NULL AND expires_at > now() \
                   AND attempts < max_attempts",
                vec![
                    challenge_id.into(),
                    user_id.into(),
                    session_id.into(),
                    kind.clone().into(),
                ],
            ))
            .await
            .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AuthError::Unauthorized);
        }
        transaction.commit().await.map_err(db_error)?;
        match kind.as_str() {
            "email_otp" => Ok("email_otp"),
            "sms_otp" => Ok("sms_otp"),
            _ => Err(AuthError::Unauthorized),
        }
    }
}
