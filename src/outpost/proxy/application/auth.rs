use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, header::AUTHORIZATION};
use eyre::Result;
use tracing::{trace, warn};

use super::Application;
use super::session::{
    SessionData, SessionStore as _, build_set_cookie, session_id_from_cookies,
};
use super::types::Claims;

/// TTL for cached Authorization header → Claims mappings.
const CACHE_TTL: Duration = Duration::from_secs(60);

/// In-memory TTL cache mapping `Authorization` header values to [`Claims`].
///
/// Used to avoid repeated token introspection / basic auth round-trips for the
/// same bearer or basic credential within a short window.
///
/// Go reference: `authHeaderCache` field on `Application`.
pub(super) struct AuthHeaderCache {
    entries: RwLock<HashMap<String, (Claims, Instant)>>,
}

impl std::fmt::Debug for AuthHeaderCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.entries.read().map(|e| e.len()).unwrap_or(0);
        f.debug_struct("AuthHeaderCache")
            .field("len", &count)
            .finish()
    }
}

impl AuthHeaderCache {
    pub(super) fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Look up claims for the given Authorization header value.
    /// Returns `None` if not cached or expired.
    pub(super) fn get(&self, key: &str) -> Option<Claims> {
        let entries = self.entries.read().ok()?;
        let (claims, inserted_at) = entries.get(key)?;
        if inserted_at.elapsed() > CACHE_TTL {
            return None;
        }
        Some(claims.clone())
    }

    /// Cache claims for the given Authorization header value.
    /// Does nothing if the key is already present (matches Go behavior).
    pub(super) fn set(&self, key: String, claims: Claims) {
        let Ok(mut entries) = self.entries.write() else {
            return;
        };
        if entries.contains_key(&key) {
            return;
        }
        entries.insert(key, (claims, Instant::now()));
        // Lazily prune expired entries.
        entries.retain(|_, (_, inserted_at)| inserted_at.elapsed() <= CACHE_TTL);
    }
}

impl Application {
    /// Load claims from the session identified by the request's session cookie.
    ///
    /// Returns `(Some(claims), false)` on success.
    /// Returns `(None, true)` when a session cookie was present but the session
    /// is invalid or missing — the caller should send a delete-cookie header.
    /// Returns `(None, false)` when there is no session cookie at all.
    ///
    /// Go reference: `getClaimsFromSession` in `application/auth.go`.
    pub(super) async fn get_claims_from_session(
        &self,
        headers: &HeaderMap,
    ) -> (Option<Claims>, bool) {
        let Some(session_id) = session_id_from_cookies(headers, &self.session_name) else {
            return (None, false);
        };

        match self.session_store.load(&session_id).await {
            Ok(Some(data)) => match data.claims {
                Some(claims) => (Some(claims), false),
                // Session exists but has no claims yet (e.g. mid-OAuth flow).
                None => (None, false),
            },
            Ok(None) => {
                // Cookie references a session that no longer exists in the store.
                (None, true)
            }
            Err(err) => {
                warn!(?err, session_id, "failed to load session");
                (None, true)
            }
        }
    }

    /// Check the TTL cache for claims matching the Authorization header.
    ///
    /// Go reference: `getClaimsFromCache` in `application/auth.go`.
    pub(super) fn get_claims_from_cache(&self, headers: &HeaderMap) -> Option<Claims> {
        let auth = headers.get(AUTHORIZATION)?.to_str().ok()?;
        self.auth_header_cache.get(auth)
    }

    /// Save claims to both the session store and the auth header cache.
    ///
    /// If a session cookie already exists, reuses that session ID.
    /// Otherwise, generates a new session ID and returns the `Set-Cookie`
    /// header that the caller must add to the response.
    ///
    /// Go reference: `saveAndCacheClaims` in `application/auth.go`.
    pub(super) async fn save_and_cache_claims(
        &self,
        headers: &HeaderMap,
        claims: Claims,
    ) -> Result<(Claims, Option<String>)> {
        // Reuse existing session or create a new one.
        let (session_id, is_new) = match session_id_from_cookies(headers, &self.session_name) {
            Some(id) => (id, false),
            None => (generate_session_id(), true),
        };

        let data = SessionData {
            claims: Some(claims.clone()),
            redirect: None,
        };
        self.session_store
            .save(&session_id, &data, self.cookie_options.max_age)
            .await?;

        // Cache by Authorization header (only if not already cached).
        if let Some(Ok(auth)) = headers.get(AUTHORIZATION).map(|v| v.to_str()) {
            self.auth_header_cache.set(auth.to_owned(), claims.clone());
        }

        let set_cookie = if is_new {
            Some(build_set_cookie(
                &session_id,
                &self.cookie_options,
                Some(self.cookie_options.max_age),
            ))
        } else {
            None
        };

        trace!(session_id, is_new, "saved claims to session and cache");
        Ok((claims, set_cookie))
    }
}

/// Generate a random session ID (32 hex characters).
fn generate_session_id() -> String {
    use rand::RngExt as _;
    let bytes: [u8; 16] = rand::rng().random();
    bytes.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use axum::http::header::COOKIE;

    use super::*;
    use crate::outpost::proxy::application::session::SessionStore;
    use crate::outpost::proxy::application::session_filesystem::FilesystemStore;

    fn make_headers(cookie_name: &str, session_id: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("{cookie_name}={session_id}").parse().unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn returns_claims_from_valid_session() {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemStore::new(dir.path().to_owned(), 3600).unwrap();

        let data = SessionData {
            claims: Some(Claims {
                sub: "user-42".to_owned(),
                preferred_username: "alice".to_owned(),
                ..Default::default()
            }),
            redirect: None,
        };
        store.save("sess-1", &data, 3600).await.unwrap();

        let headers = make_headers("authentik_proxy_abc", "sess-1");

        let app = test_app(dir.path(), "authentik_proxy_abc");
        let (claims, delete) = app.get_claims_from_session(&headers).await;

        assert!(!delete);
        let claims = claims.unwrap();
        assert_eq!(claims.sub, "user-42");
        assert_eq!(claims.preferred_username, "alice");
    }

    #[tokio::test]
    async fn returns_none_when_no_cookie() {
        let dir = tempfile::tempdir().unwrap();
        let headers = HeaderMap::new();

        let app = test_app(dir.path(), "authentik_proxy_abc");
        let (claims, delete) = app.get_claims_from_session(&headers).await;

        assert!(claims.is_none());
        assert!(!delete);
    }

    #[tokio::test]
    async fn signals_delete_for_stale_cookie() {
        let dir = tempfile::tempdir().unwrap();
        // Cookie references a session that doesn't exist in the store.
        let headers = make_headers("authentik_proxy_abc", "nonexistent");

        let app = test_app(dir.path(), "authentik_proxy_abc");
        let (claims, delete) = app.get_claims_from_session(&headers).await;

        assert!(claims.is_none());
        assert!(delete);
    }

    #[tokio::test]
    async fn returns_none_for_session_without_claims() {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemStore::new(dir.path().to_owned(), 3600).unwrap();

        let data = SessionData {
            claims: None,
            redirect: Some("https://example.com".to_owned()),
        };
        store.save("sess-no-claims", &data, 3600).await.unwrap();

        let headers = make_headers("authentik_proxy_abc", "sess-no-claims");

        let app = test_app(dir.path(), "authentik_proxy_abc");
        let (claims, delete) = app.get_claims_from_session(&headers).await;

        assert!(claims.is_none());
        assert!(!delete); // session exists, just no claims
    }

    /// Build a minimal Application for testing `get_claims_from_session`.
    fn test_app(store_dir: &std::path::Path, session_name: &str) -> Application {
        use crate::outpost::proxy::application::endpoint::OIDCEndpoint;
        use crate::outpost::proxy::application::session::{CookieOptions, SameSite};

        Application {
            host: "test.example.com".to_owned(),
            provider: ak_client::models::ProxyOutpostConfig::new(
                1,
                "test".to_owned(),
                "https://test.example.com".to_owned(),
                ak_client::models::OpenIdConnectConfiguration::new(
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                None,
                Vec::new(),
                "test-app".to_owned(),
                "Test App".to_owned(),
            ),
            router: axum::Router::new(),
            cert: None,
            endpoint: OIDCEndpoint {
                authorization_url: String::new(),
                token_url: String::new(),
                token_introspection: String::new(),
                end_session: String::new(),
                jwks_uri: String::new(),
                issuer: String::new(),
            },
            redirect_uri: String::new(),
            session_name: session_name.to_owned(),
            outpost_name: "test-outpost".to_owned(),
            unauthenticated_regex: Vec::new(),
            http_client: reqwest_middleware::ClientWithMiddleware::default(),
            session_store: FilesystemStore::new(store_dir.to_owned(), 3600).unwrap(),
            cookie_options: CookieOptions {
                name: session_name.to_owned(),
                domain: String::new(),
                path: "/".to_owned(),
                secure: true,
                http_only: true,
                same_site: SameSite::Lax,
                max_age: 3600,
            },
            auth_header_cache: AuthHeaderCache::new(),
        }
    }

    // -- AuthHeaderCache unit tests --

    #[test]
    fn cache_get_returns_none_when_empty() {
        let cache = AuthHeaderCache::new();
        assert!(cache.get("Bearer xyz").is_none());
    }

    #[test]
    fn cache_set_and_get_round_trip() {
        let cache = AuthHeaderCache::new();
        let claims = Claims {
            sub: "user-1".to_owned(),
            ..Default::default()
        };
        cache.set("Bearer tok1".to_owned(), claims.clone());
        let got = cache.get("Bearer tok1").unwrap();
        assert_eq!(got.sub, "user-1");
    }

    #[test]
    fn cache_set_does_not_overwrite_existing() {
        let cache = AuthHeaderCache::new();
        let claims1 = Claims {
            sub: "first".to_owned(),
            ..Default::default()
        };
        let claims2 = Claims {
            sub: "second".to_owned(),
            ..Default::default()
        };
        cache.set("Bearer tok".to_owned(), claims1);
        cache.set("Bearer tok".to_owned(), claims2);
        let got = cache.get("Bearer tok").unwrap();
        assert_eq!(got.sub, "first");
    }

    // -- get_claims_from_cache tests --

    #[test]
    fn get_claims_from_cache_returns_none_without_header() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), "authentik_proxy_test");
        let headers = HeaderMap::new();
        assert!(app.get_claims_from_cache(&headers).is_none());
    }

    #[test]
    fn get_claims_from_cache_returns_cached_claims() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), "authentik_proxy_test");

        let claims = Claims {
            sub: "cached-user".to_owned(),
            ..Default::default()
        };
        app.auth_header_cache
            .set("Bearer my-token".to_owned(), claims);

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer my-token".parse().unwrap());

        let got = app.get_claims_from_cache(&headers).unwrap();
        assert_eq!(got.sub, "cached-user");
    }

    // -- save_and_cache_claims tests --

    #[tokio::test]
    async fn save_and_cache_creates_new_session() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), "authentik_proxy_test");

        let claims = Claims {
            sub: "new-user".to_owned(),
            ..Default::default()
        };
        // No cookie → new session
        let headers = HeaderMap::new();
        let (returned, set_cookie) = app
            .save_and_cache_claims(&headers, claims)
            .await
            .unwrap();

        assert_eq!(returned.sub, "new-user");
        let cookie_val = set_cookie.expect("should get Set-Cookie for new session");
        assert!(cookie_val.contains("authentik_proxy_test="));
    }

    #[tokio::test]
    async fn save_and_cache_reuses_existing_session() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), "authentik_proxy_test");

        let claims = Claims {
            sub: "existing-user".to_owned(),
            ..Default::default()
        };
        // Pre-create a session
        let store = &app.session_store;
        let data = SessionData {
            claims: None,
            redirect: None,
        };
        store.save("existing-sess", &data, 3600).await.unwrap();

        let headers = make_headers("authentik_proxy_test", "existing-sess");
        let (returned, set_cookie) = app
            .save_and_cache_claims(&headers, claims)
            .await
            .unwrap();

        assert_eq!(returned.sub, "existing-user");
        assert!(
            set_cookie.is_none(),
            "should not send Set-Cookie for existing session"
        );
    }

    #[tokio::test]
    async fn save_and_cache_populates_auth_header_cache() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), "authentik_proxy_test");

        let claims = Claims {
            sub: "bearer-user".to_owned(),
            ..Default::default()
        };

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer my-token".parse().unwrap());

        let _ = app
            .save_and_cache_claims(&headers, claims)
            .await
            .unwrap();

        let cached = app.auth_header_cache.get("Bearer my-token").unwrap();
        assert_eq!(cached.sub, "bearer-user");
    }

    // -- generate_session_id tests --

    #[test]
    fn session_id_is_32_hex_chars() {
        let id = generate_session_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn session_ids_are_unique() {
        let a = generate_session_id();
        let b = generate_session_id();
        assert_ne!(a, b);
    }
}
