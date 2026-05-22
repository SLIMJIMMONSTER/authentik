use eyre::Result;
use sqlx::PgPool;
use tracing::{debug, trace};

use super::session::{SessionData, SessionStore};
use super::types::Claims;

/// PostgreSQL-backed session store for embedded outpost deployments.
///
/// Sessions are stored in the `authentik_providers_proxy_proxysession` table
/// (managed by the authentik Django ORM). This store is selected when the
/// outpost runs in embedded mode.
///
/// Go reference: `postgresstore/postgresstore.go`.
#[derive(Debug, Clone)]
pub(crate) struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Remove expired sessions from the database.
    ///
    /// Go reference: `CleanupExpired` in `postgresstore.go`.
    pub(crate) async fn cleanup_expired(&self) -> Result<()> {
        let result = sqlx::query(
            "DELETE FROM authentik_providers_proxy_proxysession WHERE expires < NOW()",
        )
        .execute(&self.pool)
        .await?;
        let count = result.rows_affected();
        if count > 0 {
            debug!(count, "cleaned up expired postgres sessions");
        }
        Ok(())
    }
}

impl SessionStore for PostgresStore {
    async fn load(&self, session_id: &str) -> Result<Option<SessionData>> {
        let row: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT session_data FROM authentik_providers_proxy_proxysession \
             WHERE session_key = $1 AND expires > NOW()",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            None => Ok(None),
            Some((data,)) => {
                let session_data: SessionData = serde_json::from_value(data)?;
                trace!(session_id, "loaded session from postgres");
                Ok(Some(session_data))
            }
        }
    }

    async fn save(&self, session_id: &str, data: &SessionData, max_age: i64) -> Result<()> {
        let session_data = serde_json::to_value(data)?;
        let user_id: Option<uuid::Uuid> =
            data.claims.as_ref().and_then(|c| c.sub.parse().ok());

        sqlx::query(
            "INSERT INTO authentik_providers_proxy_proxysession \
             (session_key, user_id, session_data, expires, expiring) \
             VALUES ($1, $2, $3, NOW() + make_interval(secs => $4::float8), true) \
             ON CONFLICT (session_key) DO UPDATE SET \
             user_id = EXCLUDED.user_id, \
             session_data = EXCLUDED.session_data, \
             expires = EXCLUDED.expires",
        )
        .bind(session_id)
        .bind(user_id)
        .bind(&session_data)
        .bind(max_age)
        .execute(&self.pool)
        .await?;

        trace!(session_id, "saved session to postgres");
        Ok(())
    }

    async fn delete(&self, session_id: &str) -> Result<()> {
        sqlx::query(
            "DELETE FROM authentik_providers_proxy_proxysession WHERE session_key = $1",
        )
        .bind(session_id)
        .execute(&self.pool)
        .await?;
        trace!(session_id, "deleted session from postgres");
        Ok(())
    }

    async fn delete_matching(
        &self,
        predicate: &(dyn Fn(&Claims) -> bool + Send + Sync),
    ) -> Result<()> {
        // Step 1: Fetch sessions that have a "claims" key in their session_data JSONB.
        // Go reference: `s.db.Where("session_data::jsonb ? 'claims'").Find(&sessions)`
        let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
            "SELECT session_key, session_data FROM authentik_providers_proxy_proxysession \
             WHERE session_data::jsonb ? 'claims'",
        )
        .fetch_all(&self.pool)
        .await?;

        // Step 2: Client-side filter on deserialized claims.
        let mut keys_to_delete: Vec<String> = Vec::new();
        for (session_key, session_data) in &rows {
            let Ok(data) = serde_json::from_value::<SessionData>(session_data.clone()) else {
                continue;
            };
            if let Some(claims) = &data.claims {
                if predicate(claims) {
                    keys_to_delete.push(session_key.clone());
                }
            }
        }

        // Step 3: Batch delete matching sessions.
        // Go reference: `s.db.Delete(&ProxySession{}, "session_key IN ?", keysToDelete)`
        if !keys_to_delete.is_empty() {
            sqlx::query(
                "DELETE FROM authentik_providers_proxy_proxysession \
                 WHERE session_key = ANY($1)",
            )
            .bind(&keys_to_delete)
            .execute(&self.pool)
            .await?;
            debug!(
                count = keys_to_delete.len(),
                "deleted matching sessions from postgres"
            );
        }

        Ok(())
    }
}
