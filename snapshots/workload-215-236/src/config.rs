#[derive(Clone, Debug)]
pub struct SigningConfig {
    pub ec_private_pem: String,
    pub key_id: String,
    pub issuer: String,
    pub audience: String,
    pub ttl_secs: u64,
}
