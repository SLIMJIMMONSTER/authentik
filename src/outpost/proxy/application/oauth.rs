use ak_client::models::ProxyMode;
use axum::http::{HeaderMap, StatusCode};
use eyre::{Result, eyre};
use serde::Deserialize;
use tracing::{trace, warn};
use url::Url;

use super::Application;
use super::oauth_state::OAuthState;
use super::session::{
    SessionData, SessionStore as _, build_delete_cookie, build_set_cookie,
    session_id_from_cookies,
};
use super::types::{Claims, ProxyClaims};

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
    ) -> Result<AuthStartResult, StatusCode> {
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
                                StatusCode::BAD_REQUEST
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
                        StatusCode::BAD_REQUEST
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
                StatusCode::BAD_REQUEST
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

    /// Exchange the authorization code for tokens and extract claims.
    ///
    /// Posts `grant_type=authorization_code` to the token endpoint, then
    /// verifies the returned access token (which is a JWT in authentik) and
    /// extracts claims.
    ///
    /// Go reference: `redeemCallback` in `application/oauth_callback.go`.
    pub(super) async fn redeem_callback(&self, callback_url: &Url) -> Result<Claims> {
        let code = callback_url
            .query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.into_owned())
            .ok_or_else(|| eyre!("blank code"))?;

        let client_id = self.provider.client_id.as_deref().unwrap_or_default();
        let client_secret = self.provider.client_secret.as_deref().unwrap_or_default();

        let res = self
            .http_client
            .post(&self.endpoint.token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("redirect_uri", &self.redirect_uri),
            ])
            .send()
            .await?;

        if res.status() != StatusCode::OK {
            let body = res.text().await.unwrap_or_default();
            return Err(eyre!("token exchange returned {}: {body}", body.len()));
        }

        #[derive(Deserialize)]
        struct TokenExchangeResponse {
            access_token: String,
        }

        let token_resp: TokenExchangeResponse = res.json().await?;

        trace!("received access_token from code exchange");

        // Verify the access token as a JWT (in authentik it's a signed JWT).
        let mut claims = self
            .verify_id_token(&token_resp.access_token)
            .await
            .ok_or_else(|| eyre!("failed to verify access token from code exchange"))?;

        if claims.ak_proxy.is_none() {
            claims.ak_proxy = Some(ProxyClaims::default());
        }
        claims.raw_token = token_resp.access_token;

        Ok(claims)
    }

    /// Handle the OAuth2 callback: validate state, exchange code, save claims,
    /// and determine the redirect URL.
    ///
    /// Returns the redirect URL and any cookies to set on the response.
    ///
    /// Go reference: `handleAuthCallback` + `redirect` in
    /// `application/oauth_callback.go` and `application/utils.go`.
    pub(super) async fn handle_auth_callback(
        &self,
        headers: &HeaderMap,
        callback_url: &Url,
    ) -> CallbackResult {
        let client_id = self.provider.client_id.as_deref().unwrap_or_default();
        let cookie_secret = self.provider.cookie_secret.as_deref().unwrap_or_default();
        let fallback_redirect = self.provider.external_host.clone();

        // Get session ID
        let session_id = match session_id_from_cookies(headers, &self.session_name) {
            Some(id) => id,
            None => {
                warn!("no session cookie on callback");
                return CallbackResult {
                    redirect_url: fallback_redirect,
                    cookies: Vec::new(),
                };
            }
        };

        // Validate state JWT
        let state_jwt = callback_url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();

        let state =
            match OAuthState::from_request(&state_jwt, &session_id, client_id, cookie_secret) {
                Some(s) => s,
                None => {
                    warn!("invalid state");
                    return CallbackResult {
                        redirect_url: fallback_redirect,
                        cookies: Vec::new(),
                    };
                }
            };

        // Exchange code for tokens
        let claims = match self.redeem_callback(callback_url).await {
            Ok(c) => c,
            Err(err) => {
                warn!(?err, "failed to redeem code");
                let redirect = if state.redirect.is_empty() {
                    fallback_redirect
                } else {
                    state.redirect
                };
                return CallbackResult {
                    redirect_url: redirect,
                    cookies: Vec::new(),
                };
            }
        };

        // Compute session max_age from token expiry
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "exp is a Unix timestamp, max_age is seconds — both fit in i64"
        )]
        let max_age = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            (claims.exp - now).max(0)
        };

        // Save claims to session
        let data = SessionData {
            claims: Some(claims),
            redirect: None,
        };
        let mut cookies = Vec::new();
        if let Err(err) = self.session_store.save(&session_id, &data, max_age).await {
            warn!(?err, "failed to save session after callback");
            return CallbackResult {
                redirect_url: fallback_redirect,
                cookies: Vec::new(),
            };
        }
        // Update session cookie max_age to match token expiry
        cookies.push(build_set_cookie(
            &session_id,
            &self.cookie_options,
            Some(max_age),
        ));

        let redirect = if state.redirect.is_empty() {
            fallback_redirect
        } else {
            state.redirect
        };
        trace!(redirect, "callback complete, redirecting");

        CallbackResult {
            redirect_url: redirect,
            cookies,
        }
    }

    /// Sign out: delete matching sessions and redirect to the OIDC end-session
    /// endpoint.
    ///
    /// Returns [`SignOutResult::NoSession`] if there are no claims in the
    /// current session (caller should redirect to start instead).
    ///
    /// Go reference: `handleSignOut` in `application/application.go`.
    pub(super) async fn handle_sign_out(&self, headers: &HeaderMap) -> SignOutResult {
        let (claims, delete_cookie) = self.get_claims_from_session(headers).await;

        let mut cookies = Vec::new();
        if delete_cookie {
            cookies.push(build_delete_cookie(&self.cookie_options));
        }

        let Some(claims) = claims else {
            return SignOutResult::NoSession;
        };

        // Build end-session redirect URL with id_token_hint
        let mut redirect = self.endpoint.end_session.clone();
        let mut end_session_url = Url::parse(&redirect).ok();
        if let Some(ref mut u) = end_session_url {
            u.query_pairs_mut()
                .append_pair("id_token_hint", &claims.raw_token);
            redirect = u.to_string();
        } else {
            // Fallback: append as query string manually
            if redirect.contains('?') {
                redirect.push_str(&format!("&id_token_hint={}", &claims.raw_token));
            } else {
                redirect.push_str(&format!("?id_token_hint={}", &claims.raw_token));
            }
        }

        // Delete all sessions for this subject
        let sub = claims.sub.clone();
        if let Err(err) = self
            .session_store
            .delete_matching(&|c| c.sub == sub)
            .await
        {
            warn!(?err, "failed to logout of other sessions");
        }

        // Also send a delete cookie for the current session
        cookies.push(build_delete_cookie(&self.cookie_options));

        SignOutResult::Redirect {
            redirect_url: redirect,
            cookies,
        }
    }
}

/// Result of [`Application::handle_sign_out`].
#[derive(Debug)]
pub(super) enum SignOutResult {
    /// Redirect to the end-session endpoint (with id_token_hint).
    Redirect {
        redirect_url: String,
        cookies: Vec<String>,
    },
    /// No claims in session — caller should redirect to start instead.
    NoSession,
}

/// Result of [`Application::handle_auth_callback`].
#[derive(Debug)]
pub(super) struct CallbackResult {
    /// URL to redirect the user to after callback processing.
    pub(super) redirect_url: String,
    /// `Set-Cookie` headers to include in the redirect response.
    pub(super) cookies: Vec<String>,
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
            api_config: ak_client::apis::configuration::Configuration::default(),
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
            upstream_client: reqwest::Client::new(),
            jwks_key_set: crate::outpost::proxy::application::jwks::RemoteJwksKeySet::new(
                String::new(),
                reqwest_middleware::ClientWithMiddleware::default(),
            ),
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

    // -- handle_auth_callback tests --

    #[tokio::test]
    async fn callback_no_session_cookie_redirects_to_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::Proxy);

        let headers = HeaderMap::new();
        let callback_url =
            Url::parse("https://app.example.com/outpost.goauthentik.io/callback?state=foo&code=bar")
                .unwrap();

        let result = app.handle_auth_callback(&headers, &callback_url).await;
        assert_eq!(result.redirect_url, "https://app.example.com");
        assert!(result.cookies.is_empty());
    }

    #[tokio::test]
    async fn callback_invalid_state_redirects_to_fallback() {
        init_crypto();
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::Proxy);

        // Create a session
        let data = SessionData {
            claims: None,
            redirect: None,
        };
        app.session_store
            .save("cb-sess", &data, 3600)
            .await
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "authentik_proxy_test=cb-sess".parse().unwrap(),
        );

        let callback_url = Url::parse(
            "https://app.example.com/outpost.goauthentik.io/callback?state=invalid-jwt&code=bar",
        )
        .unwrap();

        let result = app.handle_auth_callback(&headers, &callback_url).await;
        assert_eq!(result.redirect_url, "https://app.example.com");
    }

    #[tokio::test]
    async fn callback_valid_state_but_no_code_exchange_redirects() {
        init_crypto();
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::Proxy);

        // Create a session
        let data = SessionData {
            claims: None,
            redirect: None,
        };
        app.session_store
            .save("cb-sess-2", &data, 3600)
            .await
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "authentik_proxy_test=cb-sess-2".parse().unwrap(),
        );

        // Create a valid state JWT
        let state_jwt = OAuthState::create(
            "cb-sess-2",
            "https://app.example.com/original",
            "my-client-id",
            "cookie-signing-key",
        )
        .unwrap();

        let callback_url = Url::parse(&format!(
            "https://app.example.com/outpost.goauthentik.io/callback?state={state_jwt}&code=test-code"
        ))
        .unwrap();

        // This will fail at the HTTP call (no real token endpoint), but should
        // gracefully redirect to the state's redirect URL.
        let result = app.handle_auth_callback(&headers, &callback_url).await;
        assert_eq!(result.redirect_url, "https://app.example.com/original");
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

    // -- handle_sign_out tests --

    fn make_headers_with_cookie(cookie_name: &str, session_id: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("{cookie_name}={session_id}").parse().unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn sign_out_no_session_returns_no_session() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path(), ProxyMode::Proxy);

        let headers = HeaderMap::new();
        let result = app.handle_sign_out(&headers).await;
        assert!(matches!(result, SignOutResult::NoSession));
    }

    #[tokio::test]
    async fn sign_out_with_claims_redirects_to_end_session() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), ProxyMode::Proxy);
        app.endpoint.end_session =
            "https://auth.example.com/application/o/test/end-session/".to_owned();

        let data = SessionData {
            claims: Some(Claims {
                sub: "user-1".to_owned(),
                raw_token: "my-jwt-token".to_owned(),
                ..Default::default()
            }),
            redirect: None,
        };
        app.session_store
            .save("sign-out-sess", &data, 3600)
            .await
            .unwrap();

        let headers = make_headers_with_cookie("authentik_proxy_test", "sign-out-sess");
        let result = app.handle_sign_out(&headers).await;

        match result {
            SignOutResult::Redirect {
                redirect_url,
                cookies,
            } => {
                assert!(redirect_url.contains("end-session"));
                assert!(redirect_url.contains("id_token_hint=my-jwt-token"));
                assert!(!cookies.is_empty(), "should have delete cookie");
                assert!(cookies.iter().any(|c| c.contains("Max-Age=-1")));
            }
            SignOutResult::NoSession => panic!("expected redirect"),
        }
    }

    #[tokio::test]
    async fn sign_out_deletes_matching_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path(), ProxyMode::Proxy);
        app.endpoint.end_session = "https://auth.example.com/end-session/".to_owned();

        // Create two sessions for the same sub
        let data1 = SessionData {
            claims: Some(Claims {
                sub: "user-42".to_owned(),
                ..Default::default()
            }),
            redirect: None,
        };
        let data2 = SessionData {
            claims: Some(Claims {
                sub: "user-42".to_owned(),
                ..Default::default()
            }),
            redirect: None,
        };
        // And one for a different user
        let data3 = SessionData {
            claims: Some(Claims {
                sub: "other-user".to_owned(),
                ..Default::default()
            }),
            redirect: None,
        };
        app.session_store.save("s1", &data1, 3600).await.unwrap();
        app.session_store.save("s2", &data2, 3600).await.unwrap();
        app.session_store.save("s3", &data3, 3600).await.unwrap();

        let headers = make_headers_with_cookie("authentik_proxy_test", "s1");
        let _ = app.handle_sign_out(&headers).await;

        // Both user-42 sessions should be deleted
        assert!(app.session_store.load("s1").await.unwrap().is_none());
        assert!(app.session_store.load("s2").await.unwrap().is_none());
        // Other user's session should remain
        assert!(app.session_store.load("s3").await.unwrap().is_some());
    }
}
