#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    Unauthorized,
    Forbidden,
    Internal,
    Upstream,
}
