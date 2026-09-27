use uuid::Uuid;

use crate::error::AuthError;
use super::WorkloadSessionSnapshot;

#[derive(Clone, Debug, Default)]
pub struct WorkloadStore;

impl WorkloadStore {
    pub async fn active_session(
        &self,
        _session_id: Uuid,
        _client_id: &str,
    ) -> Result<Option<WorkloadSessionSnapshot>, AuthError> {
        Ok(None)
    }
}
