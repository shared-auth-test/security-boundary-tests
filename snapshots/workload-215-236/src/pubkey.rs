pub fn validate_sandbox_scopes(scopes: &[String]) -> Result<(), &'static str> {
    if scopes.is_empty() {
        return Err("empty scope set");
    }
    for scope in scopes {
        if scope.contains(":admin:") || scope.contains(":keys:") || scope.starts_with("shared-auth:") {
            return Err("control-plane scope");
        }
    }
    Ok(())
}
