pub const MAX_SCOPE_ENTRIES: usize = 16;
pub const MAX_SCOPE_LEN: usize = 128;
pub const MAX_SCOPE_BYTES: usize = 2048;
pub const PROTOCOL_SCOPE: &str = "openid";
pub const OFFLINE_ACCESS_SCOPE: &str = "offline_access";

pub fn scope_is_wellformed(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= MAX_SCOPE_LEN
        && scope.bytes().all(|b| b.is_ascii_alphanumeric() || b":_.-".contains(&b))
}
