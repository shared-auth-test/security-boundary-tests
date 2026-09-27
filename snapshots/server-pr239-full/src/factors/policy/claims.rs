fn require_fresh_factor_management_loa2(claims: &OreClaims) -> Result<(), AuthError> {
    require_interactive_factor_token(claims)?;
    if claims.aal != 2 || !claims.has_acr(ACR_LOA2) {
        return Err(AuthError::Forbidden);
    }
    let auth_time = claims.auth_time.ok_or(AuthError::Forbidden)?;
    require_recent_timestamp(auth_time, FACTOR_MANAGEMENT_MAX_AUTH_AGE_SECS)
}

fn require_fresh_factor_bootstrap(claims: &OreClaims) -> Result<(), AuthError> {
    require_interactive_factor_token(claims)?;
    if claims.aal == 2 && claims.has_acr(ACR_LOA2) {
        return require_fresh_factor_management_loa2(claims);
    }
    if claims.aal != 1
        || !claims.has_acr(ACR_LOA1)
        || claims.amr.is_empty()
        || claims.used_method("refresh_token")
    {
        return Err(AuthError::Forbidden);
    }
    // AAL1 does not advertise `auth_time` as a step-up ceremony. For the
    // no-factor bootstrap only, use the token issue time and require a
    // non-refresh authentication method.
    require_recent_timestamp(claims.iat, FACTOR_BOOTSTRAP_MAX_TOKEN_AGE_SECS)
}

fn require_interactive_factor_token(claims: &OreClaims) -> Result<(), AuthError> {
    if claims.is_sandboxed()
        || claims.is_delegated()
        || claims.sid.as_deref().is_none_or(str::is_empty)
    {
        Err(AuthError::Forbidden)
    } else {
        Ok(())
    }
}

fn require_recent_timestamp(timestamp: u64, max_age_secs: u64) -> Result<(), AuthError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    if now == 0
        || timestamp > now.saturating_add(FACTOR_MANAGEMENT_CLOCK_SKEW_SECS)
        || now.saturating_sub(timestamp) > max_age_secs
    {
        Err(AuthError::Forbidden)
    } else {
        Ok(())
    }
}
