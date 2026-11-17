use std::sync::Arc;
use sea_orm::DatabaseConnection;

pub struct DbStore;

impl DbStore {
    pub fn connection(&self) -> Arc<DatabaseConnection> {
        unimplemented!("harness-only database connection shim")
    }
}
