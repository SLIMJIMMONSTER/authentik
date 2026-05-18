use axum::http::HeaderMap;
use tracing::warn;

use super::Application;
use super::session::{SessionStore as _, session_id_from_cookies};
use super::types::Claims;

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
}

#[cfg(test)]
mod tests {
    use axum::http::header::COOKIE;

    use super::*;
    use crate::outpost::proxy::application::session::{SessionData, SessionStore};
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
        }
    }
}
