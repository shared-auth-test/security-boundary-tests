//! Optional Redis/Valkey acceleration.
//!
//! The cache is deliberately non-authoritative. Postgres owns sessions and
//! roles; Redis provides distributed rate-limit counters and fast revocation
//! markers. Cache errors are observable and each route class decides whether a
//! cache outage is fail-closed or may fall back to Postgres.

use redis::AsyncCommands;
use uuid::Uuid;

use crate::config::RedisConfig;

/// One atomic fixed-window rate-limit result.
///
/// Callers can preserve the existing boolean behavior through [`Cache::allow`]
/// or use this richer contract to emit stable `429` responses and
/// `Retry-After` metadata. The key itself contains only a caller-supplied hash;
/// raw email, phone, IP, token, or session material must never be supplied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub limit: u64,
    pub current: u64,
    pub remaining: u64,
    pub reset_after_secs: u64,
}

impl RateLimitDecision {
    /// The value suitable for an HTTP `Retry-After` header when denied.
    pub fn retry_after_secs(self) -> Option<u64> {
        (!self.allowed).then_some(self.reset_after_secs.max(1))
    }
}

/// Atomically increments the bucket, attaches or repairs its expiry, and
/// returns the complete decision. Redis executes scripts without interleaving,
/// so concurrent pods cannot observe the old `INCR`/`EXPIRE` race.
const FIXED_WINDOW_RATE_LIMIT_LUA: &str = r#"
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local current = redis.call('INCR', KEYS[1])
local ttl = redis.call('TTL', KEYS[1])

if current == 1 or ttl < 0 then
  redis.call('EXPIRE', KEYS[1], window)
  ttl = window
end

local allowed = 0
if current <= limit then
  allowed = 1
end

return {allowed, current, ttl}
"#;

#[derive(Clone)]
pub struct Cache {
    connection: redis::aio::ConnectionManager,
    prefix: String,
}

impl Cache {
    pub async fn connect(config: &RedisConfig) -> anyhow::Result<Self> {
        let client = redis::Client::open(config.url.as_str())?;
        let connection = client.get_connection_manager().await?;
        Ok(Self {
            connection,
            prefix: config.key_prefix.trim_end_matches(':').to_owned(),
        })
    }

    pub async fn ping(&self) -> redis::RedisResult<()> {
        let mut connection = self.connection.clone();
        let _: String = redis::cmd("PING").query_async(&mut connection).await?;
        Ok(())
    }

    pub async fn mark_revoked(&self, session_id: Uuid, ttl_secs: u64) -> redis::RedisResult<()> {
        let mut connection = self.connection.clone();
        let key = format!("{}:revoked:{session_id}", self.prefix);
        connection.set_ex(key, "1", ttl_secs.max(60)).await
    }

    pub async fn is_revoked(&self, session_id: Uuid) -> redis::RedisResult<bool> {
        let mut connection = self.connection.clone();
        let key = format!("{}:revoked:{session_id}", self.prefix);
        connection.exists(key).await
    }

    /// Atomically evaluates one fixed-window bucket.
    ///
    /// `bucket` is a bounded policy identifier such as `login-email`; the
    /// `identifier_hash` must already be a realm-scoped, domain-separated HMAC
    /// or equivalent one-way identifier. The window is clamped to at least one
    /// second so a malformed zero value cannot create a non-expiring counter.
    pub async fn check_rate_limit(
        &self,
        bucket: &str,
        identifier_hash: &str,
        limit: u64,
        window_secs: u64,
    ) -> redis::RedisResult<RateLimitDecision> {
        let mut connection = self.connection.clone();
        let key = format!("{}:limit:{bucket}:{identifier_hash}", self.prefix);
        let window_secs = window_secs.max(1);
        let (allowed, current, reset_after_secs): (i64, i64, i64) = redis::cmd("EVAL")
            .arg(FIXED_WINDOW_RATE_LIMIT_LUA)
            .arg(1)
            .arg(key)
            .arg(limit)
            .arg(window_secs)
            .query_async(&mut connection)
            .await?;

        let current = current.max(0) as u64;
        let reset_after_secs = reset_after_secs.max(1) as u64;
        Ok(RateLimitDecision {
            allowed: allowed == 1,
            limit,
            current,
            remaining: limit.saturating_sub(current),
            reset_after_secs,
        })
    }

    /// Backward-compatible boolean wrapper for existing call sites.
    ///
    /// New HTTP handlers should prefer [`Cache::check_rate_limit`] so they can
    /// propagate retry metadata and apply an explicit route-specific failure
    /// mode when Redis/Valkey is unavailable.
    pub async fn allow(
        &self,
        bucket: &str,
        identifier_hash: &str,
        limit: u64,
        window_secs: u64,
    ) -> redis::RedisResult<bool> {
        Ok(self
            .check_rate_limit(bucket, identifier_hash, limit, window_secs)
            .await?
            .allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_is_only_exposed_for_denials() {
        let allowed = RateLimitDecision {
            allowed: true,
            limit: 5,
            current: 1,
            remaining: 4,
            reset_after_secs: 60,
        };
        assert_eq!(allowed.retry_after_secs(), None);

        let denied = RateLimitDecision {
            allowed: false,
            limit: 5,
            current: 6,
            remaining: 0,
            reset_after_secs: 42,
        };
        assert_eq!(denied.retry_after_secs(), Some(42));
    }

    #[tokio::test]
    async fn redis_decision_is_atomic_across_concurrent_clients() {
        let Ok(url) = std::env::var("TEST_REDIS_URL") else {
            return;
        };
        let prefix = format!("shared-auth:test:{}", Uuid::new_v4());
        let cache = Cache::connect(&RedisConfig {
            url,
            key_prefix: prefix,
        })
        .await
        .expect("connect to test Redis/Valkey");

        let identifier = Uuid::new_v4().simple().to_string();
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let cache = cache.clone();
            let identifier = identifier.clone();
            tasks.push(tokio::spawn(async move {
                cache
                    .check_rate_limit("atomic", &identifier, 5, 60)
                    .await
                    .expect("evaluate rate limit")
            }));
        }

        let mut allowed = 0;
        let mut highest_current = 0;
        for task in tasks {
            let decision = task.await.expect("join rate-limit task");
            allowed += usize::from(decision.allowed);
            highest_current = highest_current.max(decision.current);
            assert!(decision.reset_after_secs > 0);
            assert!(decision.reset_after_secs <= 60);
        }

        assert_eq!(allowed, 5);
        assert_eq!(highest_current, 32);

        let denied = cache
            .check_rate_limit("atomic", &identifier, 5, 60)
            .await
            .expect("evaluate denied rate limit");
        assert!(!denied.allowed);
        assert_eq!(denied.remaining, 0);
        assert_eq!(denied.retry_after_secs(), Some(denied.reset_after_secs));
    }
}
