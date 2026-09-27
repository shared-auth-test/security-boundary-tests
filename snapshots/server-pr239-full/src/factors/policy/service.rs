impl FactorService {
    /// Authorize creation of a TOTP seed or start/finish of passkey registration.
    ///
    /// The first factor is a bootstrap operation: there is no existing second
    /// factor with which to step up, so a fresh non-refresh base login is the
    /// strongest available proof. After any factor is enabled, fresh AAL2 is
    /// mandatory. Pending factor rows block a second bootstrap enrollment.
    async fn authorize_factor_enrollment(
        &self,
        state: &AppState,
        claims: &OreClaims,
    ) -> Result<(), AuthError> {
        let user_id = claim_user_id(claims)?;
        let security = self.factor_security_state(user_id).await?;
        if security.total >= MAX_FACTORS_PER_USER {
            return Err(AuthError::Conflict);
        }
        if security.has_usable_factor(state) {
            require_fresh_factor_management_loa2(claims)
        } else if security.total == 0 {
            require_fresh_factor_bootstrap(claims)
        } else {
            // There is already an unconfirmed bootstrap factor. The caller can
            // list and delete it, then restart.
            Err(AuthError::Conflict)
        }
    }

    /// Deletion changes the account's future authentication surface. Enabled
    /// factors require fresh AAL2. An unconfirmed factor may be deleted with the
    /// same fresh bootstrap session that was allowed to create it.
    async fn authorize_factor_deletion(
        &self,
        state: &AppState,
        claims: &OreClaims,
        factor_id: Uuid,
    ) -> Result<(), AuthError> {
        let user_id = claim_user_id(claims)?;
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT f.enabled, \
                        (SELECT count(*)::bigint FROM shared_auth.auth_factors e \
                         WHERE e.shared_user_id = $2 AND e.enabled = true) AS enabled_count, \
                        p.email_verified, p.phone_verified \
                 FROM shared_auth.auth_factors f \
                 JOIN shared_auth.principals p ON p.shared_user_id = f.shared_user_id \
                 WHERE f.factor_id = $1 AND f.shared_user_id = $2",
                vec![factor_id.into(), user_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::BadRequest("unknown factor"))?;
        let target_enabled: bool = row.try_get("", "enabled").map_err(db_error)?;
        let enabled_count: i64 = row.try_get("", "enabled_count").map_err(db_error)?;
        let security = FactorSecurityState {
            total: 1,
            enabled: enabled_count,
            email_verified: row.try_get("", "email_verified").map_err(db_error)?,
            phone_verified: row.try_get("", "phone_verified").map_err(db_error)?,
        };
        if target_enabled || security.has_usable_factor(state) {
            require_fresh_factor_management_loa2(claims)
        } else {
            require_fresh_factor_bootstrap(claims)
        }
    }

    async fn factor_security_state(
        &self,
        user_id: Uuid,
    ) -> Result<FactorSecurityState, AuthError> {
        let row = self
            .db
            .query_one_raw(statement(
                "SELECT p.email_verified, p.phone_verified, \
                        (SELECT count(*)::bigint FROM shared_auth.auth_factors f \
                         WHERE f.shared_user_id = p.shared_user_id) AS total_count, \
                        (SELECT count(*)::bigint FROM shared_auth.auth_factors f \
                         WHERE f.shared_user_id = p.shared_user_id AND f.enabled = true) AS enabled_count \
                 FROM shared_auth.principals p \
                 WHERE p.shared_user_id = $1 AND p.status = 'active'",
                vec![user_id.into()],
            ))
            .await
            .map_err(db_error)?
            .ok_or(AuthError::Internal)?;
        Ok(FactorSecurityState {
            total: row.try_get("", "total_count").map_err(db_error)?,
            enabled: row.try_get("", "enabled_count").map_err(db_error)?,
            email_verified: row.try_get("", "email_verified").map_err(db_error)?,
            phone_verified: row.try_get("", "phone_verified").map_err(db_error)?,
        })
    }
}
