use std::path::PathBuf;

use eyre::{Result, eyre};
use tracing::{debug, info, trace, warn};

use super::session::{SessionData, SessionStore};
use super::types::Claims;

const SESSION_FILE_PREFIX: &str = "session_";

/// Filesystem-backed session store for standalone outpost deployments.
///
/// Session data is stored as JSON files named `session_<id>` in a configured
/// directory (typically `/tmp`). The file modification time is used for
/// expiry checks during cleanup.
#[derive(Debug)]
pub(crate) struct FilesystemStore {
    path: PathBuf,
    max_age: i64,
}

impl FilesystemStore {
    /// Create a new filesystem store rooted at `path`.
    ///
    /// Verifies that the directory exists and is writable.
    pub(crate) fn new(path: PathBuf, max_age: i64) -> Result<Self> {
        if !path.is_dir() {
            return Err(eyre!("session store path does not exist: {}", path.display()));
        }

        // Verify the directory is writable.
        let test_path = path.join(format!("{SESSION_FILE_PREFIX}write_test"));
        std::fs::File::create(&test_path)
            .map_err(|e| eyre!("session store path is not writable: {e}"))?;
        std::fs::remove_file(&test_path).ok();

        Ok(Self { path, max_age })
    }

    fn session_path(&self, session_id: &str) -> PathBuf {
        self.path.join(format!("{SESSION_FILE_PREFIX}{session_id}"))
    }

    /// Remove expired session files.
    ///
    /// A session file is expired when its modification time is older than
    /// `max_age` seconds. This is equivalent to the Go `sessionCleanup`.
    pub(crate) fn cleanup_expired(&self) -> Result<()> {
        let entries = std::fs::read_dir(&self.path)?;
        let max_age = std::time::Duration::from_secs(self.max_age.unsigned_abs());

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    warn!(?err, "failed to read directory entry during cleanup");
                    continue;
                }
            };

            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with(SESSION_FILE_PREFIX) {
                continue;
            }

            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(err) => {
                    warn!(?err, path = %entry.path().display(), "failed to stat session file");
                    continue;
                }
            };

            let modified = match metadata.modified() {
                Ok(t) => t,
                Err(err) => {
                    warn!(?err, path = %entry.path().display(), "failed to get mtime");
                    continue;
                }
            };

            let age = modified.elapsed().unwrap_or_default();
            if age <= max_age {
                debug!(
                    path = %entry.path().display(),
                    age_secs = age.as_secs(),
                    "session still valid"
                );
                continue;
            }

            info!(path = %entry.path().display(), "removing expired session");
            if let Err(err) = std::fs::remove_file(entry.path()) {
                warn!(?err, path = %entry.path().display(), "failed to delete expired session");
            }
        }
        Ok(())
    }
}

impl SessionStore for FilesystemStore {
    async fn load(&self, session_id: &str) -> Result<Option<SessionData>> {
        let path = self.session_path(session_id);
        let data = match tokio::fs::read(&path).await {
            Ok(d) => d,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let session_data: SessionData = serde_json::from_slice(&data)?;
        trace!(session_id, "loaded session from filesystem");
        Ok(Some(session_data))
    }

    async fn save(&self, session_id: &str, data: &SessionData, _max_age: i64) -> Result<()> {
        let path = self.session_path(session_id);
        let json = serde_json::to_vec(data)?;
        tokio::fs::write(&path, &json).await?;
        trace!(session_id, "saved session to filesystem");
        Ok(())
    }

    async fn delete(&self, session_id: &str) -> Result<()> {
        let path = self.session_path(session_id);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => trace!(session_id, "deleted session file"),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        Ok(())
    }

    async fn delete_matching(
        &self,
        predicate: &(dyn Fn(&Claims) -> bool + Send + Sync),
    ) -> Result<()> {
        let dir = &self.path;
        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with(SESSION_FILE_PREFIX) {
                continue;
            }

            let data = match tokio::fs::read(entry.path()).await {
                Ok(d) => d,
                Err(err) => {
                    warn!(?err, path = %entry.path().display(), "failed to read session file");
                    continue;
                }
            };
            let session_data: SessionData = match serde_json::from_slice(&data) {
                Ok(d) => d,
                Err(err) => {
                    trace!(?err, path = %entry.path().display(), "failed to decode session file");
                    continue;
                }
            };

            if let Some(claims) = &session_data.claims {
                if predicate(claims) {
                    trace!(path = %entry.path().display(), "deleting matching session");
                    if let Err(err) = tokio::fs::remove_file(entry.path()).await {
                        warn!(?err, path = %entry.path().display(), "failed to delete session");
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, FilesystemStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemStore::new(dir.path().to_owned(), 3600).unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn save_and_load() {
        let (_dir, store) = temp_store();
        let data = SessionData {
            claims: Some(Claims {
                sub: "user-123".to_owned(),
                ..Default::default()
            }),
            redirect: Some("https://example.com".to_owned()),
        };

        store.save("sess-1", &data, 3600).await.unwrap();

        let loaded = store.load("sess-1").await.unwrap().unwrap();
        assert_eq!(loaded.claims.unwrap().sub, "user-123");
        assert_eq!(loaded.redirect.unwrap(), "https://example.com");
    }

    #[tokio::test]
    async fn load_missing_returns_none() {
        let (_dir, store) = temp_store();
        assert!(store.load("nonexistent").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_removes_file() {
        let (_dir, store) = temp_store();
        let data = SessionData::default();
        store.save("sess-del", &data, 3600).await.unwrap();
        assert!(store.load("sess-del").await.unwrap().is_some());

        store.delete("sess-del").await.unwrap();
        assert!(store.load("sess-del").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_missing_is_ok() {
        let (_dir, store) = temp_store();
        store.delete("no-such-session").await.unwrap();
    }

    #[tokio::test]
    async fn delete_matching_filters_by_sub() {
        let (_dir, store) = temp_store();

        let data_a = SessionData {
            claims: Some(Claims {
                sub: "user-a".to_owned(),
                ..Default::default()
            }),
            redirect: None,
        };
        let data_b = SessionData {
            claims: Some(Claims {
                sub: "user-b".to_owned(),
                ..Default::default()
            }),
            redirect: None,
        };
        store.save("sess-a", &data_a, 3600).await.unwrap();
        store.save("sess-b", &data_b, 3600).await.unwrap();

        store
            .delete_matching(&|c: &Claims| c.sub == "user-a")
            .await
            .unwrap();

        assert!(store.load("sess-a").await.unwrap().is_none());
        assert!(store.load("sess-b").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn delete_matching_filters_by_sid() {
        let (_dir, store) = temp_store();

        let data_a = SessionData {
            claims: Some(Claims {
                sub: "user-a".to_owned(),
                sid: "session-123".to_owned(),
                ..Default::default()
            }),
            redirect: None,
        };
        let data_b = SessionData {
            claims: Some(Claims {
                sub: "user-a".to_owned(),
                sid: "session-456".to_owned(),
                ..Default::default()
            }),
            redirect: None,
        };
        store.save("sess-a", &data_a, 3600).await.unwrap();
        store.save("sess-b", &data_b, 3600).await.unwrap();

        // Delete only the session with sid "session-123" (same filter as end_session uses).
        store
            .delete_matching(&|c: &Claims| c.sid == "session-123")
            .await
            .unwrap();

        assert!(store.load("sess-a").await.unwrap().is_none());
        assert!(store.load("sess-b").await.unwrap().is_some());
    }

    #[test]
    fn cleanup_expired_removes_old_files() {
        let dir = tempfile::tempdir().unwrap();
        // max_age=0 means everything is immediately expired
        let store = FilesystemStore::new(dir.path().to_owned(), 0).unwrap();

        let path = dir.path().join(format!("{SESSION_FILE_PREFIX}old-sess"));
        std::fs::write(&path, b"{}").unwrap();
        // Set mtime to 10 seconds ago so it's definitely expired with max_age=0.
        let old_time = std::time::SystemTime::now() - std::time::Duration::from_secs(10);
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(old_time))
            .unwrap();
        drop(file);

        store.cleanup_expired().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn cleanup_expired_keeps_fresh_files() {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemStore::new(dir.path().to_owned(), 3600).unwrap();

        let path = dir.path().join(format!("{SESSION_FILE_PREFIX}fresh-sess"));
        std::fs::write(&path, b"{}").unwrap();

        store.cleanup_expired().unwrap();
        assert!(path.exists());
    }

    #[test]
    fn rejects_nonexistent_path() {
        let result = FilesystemStore::new(PathBuf::from("/nonexistent/path/12345"), 3600);
        assert!(result.is_err());
    }
}
