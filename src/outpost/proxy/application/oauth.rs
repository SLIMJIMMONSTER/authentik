use ak_client::models::ProxyMode;
use axum::http::HeaderMap;
use tracing::warn;
use url::Url;

use super::Application;
use super::oauth_state::OAuthState;
use super::session::{
    SessionData, SessionStore as _, build_delete_cookie, build_set_cookie,
    session_id_from_cookies,
};

use crate::outpost::proxy::application::auth::generate_session_id;

/// Result of [`Application::handle_auth_start`].
///
/// The caller must issue a `302 Found` redirect to `redirect_url` and include
/// any `set_cookie` headers in the response.
#[derive(Debug)]
pub(super) struct AuthStartResult {
    /// Authorization endpoint URL with `state`, `client_id`, etc.
    pub(super) redirect_url: String,
    /// `Set-Cookie` headers to include in the redirect response.
    pub(super) cookies: Vec<String>,
}

/// Result of [`Application::redirect_to_start`].
///
/// The caller should issue a `302 Found` redirect to `redirect_url`, or
/// return a `401` when `intercept_header_auth` blocked the redirect.
#[derive(Debug)]
pub(super) enum RedirectToStartResult {
    /// Redirect the user to the `/start` endpoint.
    Redirect {
        redirect_url: String,
        cookies: Vec<String>,
    },
    /// Don't redirect — return 401 because `intercept_header_auth` is set
    /// and the request included an Authorization header.
    Unauthorized,
}

impl Application {
    /// Build the OAuth2 authorization URL with the given state parameter.
    ///
    /// Produces: `<authorization_endpoint>?client_id=X&redirect_uri=Y&response_type=code&scope=Z&state=<state>`
    fn build_auth_code_url(&self, state: &str) -> String {
        let client_id = self.provider.client_id.as_deref().unwrap_or_default();
        let scopes = self.provider.scopes_to_request.join(" ");

        let mut url = Url::parse(&self.endpoint.authorization_url)
            .unwrap_or_else(|_| Url::parse("https://invalid").expect("static URL"));

        url.query_pairs_mut()
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &scopes)
            .append_pair("state", state);

        url.to_string()
    }

    /// Validate the `rd` (redirect) query parameter.
    ///
    /// For proxy / forward_single modes: the redirect URL's host must match the
    /// external host (or be empty, i.e. a path-only redirect).
    /// For forward_domain: the redirect URL's host must end with the cookie domain.
    ///
    /// Go reference: `checkRedirectParam` in `application/oauth_state.go`.
    pub(super) fn check_redirect_param(&self, rd: &str) -> Option<String> {
        if rd.is_empty() {
            return None;
        }
        let mut u = match Url::parse(rd) {
            Ok(u) => u,
            Err(_) => {
                // Might be a path-only redirect like "/dashboard". Try with a base.
                match Url::parse(&self.provider.external_host).and_then(|base| base.join(rd)) {
                    Ok(u) => u,
                    Err(err) => {
                        warn!(?err, rd, "failed to parse redirect URL");
                        return None;
                    }
                }
            }
        };

        match self.provider.mode {
            Some(ProxyMode::Proxy | ProxyMode::ForwardSingle) => {
                let ext = match Url::parse(&self.provider.external_host) {
                    Ok(e) => e,
                    Err(_) => return None,
                };
                // If no host given, inherit from external host
                if u.host_str().is_none() || u.host_str() == Some("") {
                    let _ = u.set_host(ext.host_str());
                    let _ = u.set_scheme(ext.scheme());
                }
                if u.host_str() != ext.host_str() {
                    warn!(
                        url = u.as_str(),
                        ext = ext.as_str(),
                        "redirect URI did not contain external host"
                    );
                    return None;
                }
            }
            Some(ProxyMode::ForwardDomain) => {
                let domain = self
                    .provider
                    .cookie_domain
                    .as_deref()
                    .unwrap_or_default()
                    .trim_start_matches('.');
                let host = u.host_str().unwrap_or_default();
                if !host.ends_with(domain) {
                    warn!(
                        host,
                        domain, "redirect URI hostname was not in cookie domain"
                    );
                    return None;
                }
            }
            None => return None,
        }

        Some(u.to_string())
    }

    /// Start the OAuth2 authorization flow.
    ///
    /// Creates (or reuses) a session, generates a state JWT, and returns the
    /// authorization URL for the caller to redirect to.
    ///
    /// `redirect` is the URL the user was originally trying to reach.
    ///
    /// Go reference: `handleAuthStart` in `application/oauth.go`.
    pub(super) async fn handle_auth_start(
        &self,
        headers: &HeaderMap,
        redirect: &str,
    ) -> Result<AuthStartResult, axum::http::StatusCode> {
        let client_id = self.provider.client_id.as_deref().unwrap_or_default();
        let cookie_secret = self.provider.cookie_secret.as_deref().unwrap_or_default();

        let mut cookies = Vec::new();

        // Get or create session ID
        let session_id = match session_id_from_cookies(headers, &self.session_name) {
            Some(id) => {
                // Verify the session actually exists in the store
                match self.session_store.load(&id).await {
                    Ok(Some(_)) => id,
                    _ => {
                        // Stale cookie — delete it and create fresh session
                        cookies.push(build_delete_cookie(&self.cookie_options));
                        let new_id = generate_session_id();
                        let data = SessionData {
                            claims: None,
                            redirect: None,
                        };
                        self.session_store
                            .save(&new_id, &data, self.cookie_options.max_age)
                            .await
                            .map_err(|err| {
                                warn!(?err, "failed to save new session");
                                axum::http::StatusCode::BAD_REQUEST
                            })?;
                        cookies.push(build_set_cookie(
                            &new_id,
                            &self.cookie_options,
                            Some(self.cookie_options.max_age),
                        ));
                        new_id
                    }
                }
            }
            None => {
                let new_id = generate_session_id();
                let data = SessionData {
                    claims: None,
                    redirect: None,
                };
                self.session_store
                    .save(&new_id, &data, self.cookie_options.max_age)
                    .await
                    .map_err(|err| {
                        warn!(?err, "failed to save new session");
                        axum::http::StatusCode::BAD_REQUEST
                    })?;
                cookies.push(build_set_cookie(
                    &new_id,
                    &self.cookie_options,
                    Some(self.cookie_options.max_age),
                ));
                new_id
            }
        };

        let state = OAuthState::create(&session_id, redirect, client_id, cookie_secret)
            .map_err(|err| {
                warn!(?err, "failed to create state JWT");
                axum::http::StatusCode::BAD_REQUEST
            })?;

        let redirect_url = self.build_auth_code_url(&state);

        Ok(AuthStartResult {
            redirect_url,
            cookies,
        })
    }

    /// Redirect the user to `/outpost.goauthentik.io/start` to begin the OAuth
    /// flow.
    ///
    /// Saves the current URL to the session so the callback can redirect back.
    /// If `intercept_header_auth` is enabled and the request has an
    /// Authorization header, returns `Unauthorized` instead of redirecting.
    ///
    /// Go reference: `redirectToStart` in `application/oauth.go`.
    pub(super) async fn redirect_to_start(
        &self,
        headers: &HeaderMap,
        request_url: &Url,
    ) -> RedirectToStartResult {
        // If intercept_header_auth is set and the request has an Authorization
        // header, return 401 instead of redirecting.
        let intercept = self
            .provider
            .intercept_header_auth
            .unwrap_or_default();
        if intercept && headers.get(axum::http::header::AUTHORIZATION).is_some() {
            return RedirectToStartResult::Unauthorized;
        }

        let mut cookies = Vec::new();

        // Determine redirect URL
        let redirect_url = match self.provider.mode {
            Some(ProxyMode::ForwardDomain) => {
                let domain = self
                    .provider
                    .cookie_domain
                    .as_deref()
                    .unwrap_or_default()
                    .trim_start_matches('.');
                let host = request_url.host_str().unwrap_or_default();
                if !host.ends_with(domain) {
                    warn!(
                        url = request_url.as_str(),
                        domain, "invalid redirect found"
                    );
                    self.provider.external_host.clone()
                } else {
                    request_url.to_string()
                }
            }
            _ => {
                // For proxy / forward_single, join external host with the request path.
                let mut u = Url::parse(&self.provider.external_host)
                    .unwrap_or_else(|_| request_url.clone());
                u.set_path(request_url.path());
                u.set_query(request_url.query());
                u.to_string()
            }
        };

        // Save redirect to session (if not already set)
        let session_id = session_id_from_cookies(headers, &self.session_name);
        if let Some(ref sid) = session_id {
            match self.session_store.load(sid).await {
                Ok(Some(data)) if data.redirect.is_some() => {
                    // Redirect already stored — don't overwrite.
                }
                Ok(Some(mut data)) => {
                    data.redirect = Some(redirect_url.clone());
                    if let Err(err) = self
                        .session_store
                        .save(sid, &data, self.cookie_options.max_age)
                        .await
                    {
                        warn!(?err, "failed to save session before redirect");
                    }
                }
                _ => {
                    // No session yet — create one
                    let new_id = generate_session_id();
                    let data = SessionData {
                        claims: None,
                        redirect: Some(redirect_url.clone()),
                    };
                    if let Err(err) = self
                        .session_store
                        .save(&new_id, &data, self.cookie_options.max_age)
                        .await
                    {
                        warn!(?err, "failed to save new session before redirect");
                    }
                    cookies.push(build_set_cookie(
                        &new_id,
                        &self.cookie_options,
                        Some(self.cookie_options.max_age),
                    ));
                }
            }
        } else {
            let new_id = generate_session_id();
            let data = SessionData {
                claims: None,
                redirect: Some(redirect_url.clone()),
            };
            if let Err(err) = self
                .session_store
                .save(&new_id, &data, self.cookie_options.max_age)
                .await
            {
                warn!(?err, "failed to save new session before redirect");
            }
            cookies.push(build_set_cookie(
                &new_id,
                &self.cookie_options,
                Some(self.cookie_options.max_age),
            ));
        }

        // Build the start URL: <external_host>/outpost.goauthentik.io/start?rd=<redirect_url>
        let mut start_url = Url::parse(&self.provider.external_host)
            .unwrap_or_else(|_| request_url.clone());
        start_url.set_path(
            &format!(
                "{}/outpost.goauthentik.io/start",
                start_url.path().trim_end_matches('/')
            ),
        );
        start_url
            .query_pairs_mut()
            .append_pair("rd", &redirect_url);

        RedirectToStartResult::Redirect {
            redirect_url: start_url.to_string(),
            cookies,
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::header::AUTHORIZATION;

    use super::*;
    use crate::outpost::proxy::application::auth::AuthHeaderCache;
    use crate::outpost::proxy::application::endpoint::OIDCEndpoint;
    use crate::outpost::proxy::application::session::{CookieOptions, SameSite, SessionStore};
    use crate::outpost::proxy::application::session_filesystem::FilesystemStore;

    fn test_app(store_dir: &std::path::Path, mode: ProxyMode) -> Application {
        let mut provider = ak_client::models::ProxyOutpostConfig::new(
            1,
            "test".to_owned(),
            "https://app.example.com".to_owned(),
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
        );
        provider.client_id = Some("my-client-id".to_owned());
        provider.client_secret = Some("my-secret".to_owned());
        provider.cookie_secret = Some("cookie-signing-key".to_owned());
        provider.cookie_domain = Some(".example.com".to_owned());
        provider.mode = Some(mode);
        provider.intercept_header_auth = Some(false);

        Application {
            host: "app.example.com".to_owned(),
            provider,
            router: axum::Router::new(),
            cert: None,
            endpoint: OIDCEndpoint {
                authorization_url: "https://auth.example.com/authorize".to_owned(),
                token_url: String::new(),
                token_introspection: String::new(),
                end_session: String::new(),
                jwks_uri: String::new(),
                issuer: String::new(),
            },
            redirect_uri: "https://app.example.com/outpost.goauthentik.io/callback?X-authentik-auth-callback=true".to_owned(),
            session_name: "authentik_proxy_test".to_owned(),
            outpost_name: "test-outpost".to_owned(),
            unauthenticated_regex: Vec::new(),
            http_client: reqwest_middleware::ClientWithMiddleware::default(),
            session_store: FilesystemStore::new(store_dir.to_owned(), 3600).unwrap(),
            cookie_options: CookieOptions {
                name: "authentik_proxy_test".to_owned(),
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

    // -- check_redirect_param tests --

    #[test]
    fn redirect_param_empty_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::Proxy);
        assert!(app.check_redirect_param("").is_none());
    }

    #[test]
    fn redirect_param_matching_host_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::Proxy);
        let result = app.check_redirect_param("https://app.example.com/dashboard");
        assert_eq!(
            result.as_deref(),
            Some("https://app.example.com/dashboard")
        );
    }

    #[test]
    fn redirect_param_path_only_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::Proxy);
        let result = app.check_redirect_param("/dashboard");
        assert!(result.is_some());
        assert!(result.unwrap().contains("/dashboard"));
    }

    #[test]
    fn redirect_param_wrong_host_proxy() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::Proxy);
        assert!(
            app.check_redirect_param("https://evil.com/steal")
                .is_none()
        );
    }

    #[test]
    fn redirect_param_matching_domain_forward_domain() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::ForwardDomain);
        let result = app.check_redirect_param("https://sub.example.com/page");
        assert_eq!(
            result.as_deref(),
            Some("https://sub.example.com/page")
        );
    }

    #[test]
    fn redirect_param_wrong_domain_forward_domain() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::ForwardDomain);
        assert!(
            app.check_redirect_param("https://other.org/page")
                .is_none()
        );
    }

    // -- handle_auth_start tests --

    fn init_crypto() {
        let _ = jsonwebtoken::crypto::CryptoProvider::install_default(
            &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER,
        );
    }

    #[tokio::test]
    async fn auth_start_creates_session_and_redirects() {
        init_crypto();
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::Proxy);

        let headers = HeaderMap::new();
        let result = app
            .handle_auth_start(&headers, "https://app.example.com/page")
            .await
            .unwrap();

        assert!(result.redirect_url.starts_with("https://auth.example.com/authorize?"));
        assert!(result.redirect_url.contains("client_id=my-client-id"));
        assert!(result.redirect_url.contains("response_type=code"));
        assert!(result.redirect_url.contains("state="));
        assert!(!result.cookies.is_empty(), "should set session cookie");
    }

    #[tokio::test]
    async fn auth_start_reuses_valid_session() {
        init_crypto();
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::Proxy);

        // Pre-create a session
        let data = SessionData {
            claims: None,
            redirect: None,
        };
        app.session_store.save("existing", &data, 3600).await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "authentik_proxy_test=existing".parse().unwrap(),
        );

        let result = app
            .handle_auth_start(&headers, "https://app.example.com/page")
            .await
            .unwrap();

        assert!(result.redirect_url.contains("state="));
        // No new cookie needed — session already exists
        assert!(result.cookies.is_empty());
    }

    #[tokio::test]
    async fn auth_start_clears_stale_session() {
        init_crypto();
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::Proxy);

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "authentik_proxy_test=gone".parse().unwrap(),
        );

        let result = app
            .handle_auth_start(&headers, "https://app.example.com/page")
            .await
            .unwrap();

        assert!(result.redirect_url.contains("state="));
        // Should have a delete cookie + new cookie
        assert!(result.cookies.len() >= 2);
        assert!(result.cookies[0].contains("Max-Age=-1"));
    }

    // -- redirect_to_start tests --

    #[tokio::test]
    async fn redirect_to_start_builds_start_url() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::Proxy);

        let headers = HeaderMap::new();
        let request_url = Url::parse("https://app.example.com/protected").unwrap();

        let result = app.redirect_to_start(&headers, &request_url).await;
        match result {
            RedirectToStartResult::Redirect {
                redirect_url,
                cookies,
            } => {
                assert!(redirect_url.contains("/outpost.goauthentik.io/start"));
                assert!(redirect_url.contains("rd="));
                assert!(!cookies.is_empty(), "should create session");
            }
            RedirectToStartResult::Unauthorized => panic!("expected redirect"),
        }
    }

    #[tokio::test]
    async fn redirect_to_start_returns_401_with_intercept_header_auth() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), ProxyMode::Proxy);
        app.provider.intercept_header_auth = Some(true);

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer token".parse().unwrap());

        let request_url = Url::parse("https://app.example.com/api").unwrap();
        let result = app.redirect_to_start(&headers, &request_url).await;

        assert!(matches!(result, RedirectToStartResult::Unauthorized));
    }

    #[tokio::test]
    async fn redirect_to_start_saves_redirect_to_session() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::Proxy);

        // Pre-create a session without redirect
        let data = SessionData {
            claims: None,
            redirect: None,
        };
        app.session_store.save("sess-1", &data, 3600).await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "authentik_proxy_test=sess-1".parse().unwrap(),
        );

        let request_url = Url::parse("https://app.example.com/target").unwrap();
        let _ = app.redirect_to_start(&headers, &request_url).await;

        // Verify redirect was saved to session
        let loaded = app.session_store.load("sess-1").await.unwrap().unwrap();
        assert!(loaded.redirect.is_some());
        assert!(loaded.redirect.unwrap().contains("/target"));
    }

    #[tokio::test]
    async fn redirect_to_start_does_not_overwrite_existing_redirect() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::Proxy);

        let data = SessionData {
            claims: None,
            redirect: Some("https://app.example.com/original".to_owned()),
        };
        app.session_store.save("sess-2", &data, 3600).await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "authentik_proxy_test=sess-2".parse().unwrap(),
        );

        let request_url = Url::parse("https://app.example.com/new-page").unwrap();
        let _ = app.redirect_to_start(&headers, &request_url).await;

        let loaded = app.session_store.load("sess-2").await.unwrap().unwrap();
        assert_eq!(
            loaded.redirect.as_deref(),
            Some("https://app.example.com/original")
        );
    }
}
