use std::sync::Arc;

use ak_axum::error::Result;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
};
use tracing::{debug, instrument, trace, warn};
use url::Url;

use crate::outpost::proxy::application::Application;
use crate::outpost::proxy::application::session::{
    SessionStore as _, build_delete_cookie, session_id_from_cookies,
};

/// Query parameter names that signal OAuth callback / logout in the forwarded URL.
const CALLBACK_SIGNATURE: &str = "X-authentik-auth-callback";
const LOGOUT_SIGNATURE: &str = "X-authentik-logout";

/// Parse the forwarded URL from Traefik/Caddy forward-auth headers.
///
/// Builds `<X-Forwarded-Proto>://<X-Forwarded-Host><X-Forwarded-Uri>`.
///
/// Go reference: `getTraefikForwardUrl` in `application/mode_common.go`.
pub(super) fn get_traefik_forward_url(headers: &HeaderMap) -> Option<Url> {
    let proto = headers
        .get("X-Forwarded-Proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let host = headers
        .get("X-Forwarded-Host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let uri = headers
        .get("X-Forwarded-Uri")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    if proto.is_empty() || host.is_empty() {
        warn!(proto, host, uri, "missing traefik forward headers");
        return None;
    }

    let raw = format!("{proto}://{host}{uri}");
    match Url::parse(&raw) {
        Ok(u) => {
            trace!(url = u.as_str(), "traefik forwarded url");
            Some(u)
        }
        Err(err) => {
            warn!(?err, raw, "failed to parse traefik forward URL");
            None
        }
    }
}

/// Parse the forwarded URL from nginx `X-Original-URL` header.
///
/// Go reference: `getNginxForwardUrl` in `application/mode_common.go`.
pub(super) fn get_nginx_forward_url(headers: &HeaderMap) -> Option<Url> {
    let original = headers
        .get("X-Original-URL")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())?;

    match Url::parse(original) {
        Ok(u) => {
            trace!(url = u.as_str(), "nginx forwarded url");
            Some(u)
        }
        Err(err) => {
            warn!(?err, original, "failed to parse URL from nginx");
            None
        }
    }
}

/// Parse the forwarded URL for envoy.
///
/// Envoy sends the original path appended after the ext_authz prefix.
/// We strip `/outpost.goauthentik.io/auth/envoy` and use the `Host`
/// header to reconstruct the full URL.
///
/// Go reference: `forwardHandleEnvoy` URL construction in `application/mode_forward.go`.
pub(super) fn get_envoy_forward_url(request: &Request) -> Option<Url> {
    let uri = request.uri();
    let path = uri.path();
    const PREFIX: &str = "/outpost.goauthentik.io/auth/envoy";
    let stripped = path.strip_prefix(PREFIX).unwrap_or(path);

    let host = request
        .headers()
        .get("Host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    if host.is_empty() {
        warn!("missing Host header for envoy forward URL");
        return None;
    }

    // Use https by default; envoy typically terminates TLS upstream.
    let raw = match uri.query() {
        Some(q) => format!("https://{host}{stripped}?{q}"),
        None => format!("https://{host}{stripped}"),
    };
    match Url::parse(&raw) {
        Ok(u) => {
            trace!(url = u.as_str(), "envoy forwarded url");
            Some(u)
        }
        Err(err) => {
            warn!(?err, raw, "failed to parse envoy forward URL");
            None
        }
    }
}

/// Check if the forwarded URL contains a callback or logout signature.
/// Returns `true` if the signature was handled (caller should return the response).
fn has_query_flag(url: &Url, param: &str) -> bool {
    url.query_pairs()
        .any(|(k, v)| k == param && v.eq_ignore_ascii_case("true"))
}

/// Build a 200 OK response with the given headers and cookies applied.
fn ok_with_headers(
    app: &Application,
    claims: &crate::outpost::proxy::application::types::Claims,
    request_headers: &HeaderMap,
    cookies: Vec<String>,
    delete_cookie: bool,
) -> Response {
    let mut resp_headers = HeaderMap::new();
    app.add_headers(&mut resp_headers, claims);

    // Forward the User-Agent from the original request.
    if let Some(ua) = request_headers.get("User-Agent") {
        resp_headers.insert("User-Agent", ua.clone());
    }

    let mut response = StatusCode::OK.into_response();
    let rh = response.headers_mut();
    rh.extend(resp_headers);

    for cookie in &cookies {
        if let Ok(val) = cookie.parse() {
            rh.append(SET_COOKIE, val);
        }
    }
    if delete_cookie {
        if let Ok(val) = build_delete_cookie(&app.cookie_options).parse() {
            rh.append(SET_COOKIE, val);
        }
    }
    response
}

/// Build a redirect-to-auth-start response.
async fn redirect_to_auth_start(
    app: &Application,
    headers: &HeaderMap,
    redirect: &str,
) -> Response {
    match app.handle_auth_start(headers, redirect).await {
        Ok(result) => {
            let mut response =
                axum::response::Redirect::to(&result.redirect_url).into_response();
            let rh = response.headers_mut();
            for cookie in &result.cookies {
                if let Ok(val) = cookie.parse() {
                    rh.append(SET_COOKIE, val);
                }
            }
            response
        }
        Err(status) => status.into_response(),
    }
}

/// Shared logic for traefik and caddy forward auth handlers.
///
/// Go reference: `forwardHandleTraefik` / `forwardHandleCaddy` in `application/mode_forward.go`.
async fn handle_traefik_caddy(app: &Application, headers: HeaderMap) -> Response {
    let Some(fwd) = get_traefik_forward_url(&headers) else {
        let msg = format!(
            "Outpost {} (Provider {}) failed to detect a forward URL from Traefik/Caddy",
            app.outpost_name, app.provider.name,
        );
        app.report_misconfiguration(&msg, &headers, "").await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    // Check callback/logout signatures in forwarded URL
    if has_query_flag(&fwd, CALLBACK_SIGNATURE) {
        debug!("handling OAuth Callback from querystring signature");
        let result = app.handle_auth_callback(&headers, &fwd).await;
        let mut response =
            axum::response::Redirect::to(&result.redirect_url).into_response();
        for cookie in &result.cookies {
            if let Ok(val) = cookie.parse() {
                response.headers_mut().append(SET_COOKIE, val);
            }
        }
        return response;
    }
    if has_query_flag(&fwd, LOGOUT_SIGNATURE) {
        debug!("handling OAuth Logout from querystring signature");
        return handle_sign_out_inner(app, &headers).await;
    }

    // Check auth
    let auth = app.check_auth(&headers).await;
    if let Some(ref claims) = auth.claims {
        return ok_with_headers(app, claims, &headers, auth.set_cookie.into_iter().collect(), auth.delete_cookie);
    }
    if app.is_allowlisted(&fwd) {
        trace!("path can be accessed without authentication");
        return StatusCode::OK.into_response();
    }

    redirect_to_auth_start(app, &headers, fwd.as_str()).await
}

/// Handle sign-out and return a redirect response.
async fn handle_sign_out_inner(app: &Application, headers: &HeaderMap) -> Response {
    use crate::outpost::proxy::application::oauth::SignOutResult;

    let result = app.handle_sign_out(headers).await;
    match result {
        SignOutResult::Redirect {
            redirect_url,
            cookies,
        } => {
            let mut response =
                axum::response::Redirect::to(&redirect_url).into_response();
            for cookie in &cookies {
                if let Ok(val) = cookie.parse() {
                    response.headers_mut().append(SET_COOKIE, val);
                }
            }
            response
        }
        SignOutResult::NoSession => StatusCode::BAD_REQUEST.into_response(),
    }
}

#[instrument(skip_all)]
pub(crate) async fn handle_caddy(
    State(app): State<Arc<Application>>,
    request: Request,
) -> Result<Response> {
    Ok(handle_traefik_caddy(&app, request.headers().clone()).await)
}

#[instrument(skip_all)]
pub(crate) async fn handle_traefik(
    State(app): State<Arc<Application>>,
    request: Request,
) -> Result<Response> {
    Ok(handle_traefik_caddy(&app, request.headers().clone()).await)
}

/// Envoy forward auth handler.
///
/// Strips the `/outpost.goauthentik.io/auth/envoy` prefix, reconstructs the
/// URL from the `Host` header, checks auth, and returns 200 + headers or
/// redirects to start the OAuth flow.
///
/// Go reference: `forwardHandleEnvoy` in `application/mode_forward.go`.
#[instrument(skip_all)]
pub(crate) async fn handle_envoy(
    State(app): State<Arc<Application>>,
    request: Request,
) -> Result<Response> {
    let headers = request.headers().clone();

    let Some(fwd) = get_envoy_forward_url(&request) else {
        let msg = format!(
            "Outpost {} (Provider {}) failed to detect a forward URL from Envoy",
            app.outpost_name, app.provider.name,
        );
        app.report_misconfiguration(&msg, &headers, request.uri().to_string().as_str())
            .await;
        return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    };

    let auth = app.check_auth(&headers).await;
    if let Some(ref claims) = auth.claims {
        return Ok(ok_with_headers(&app, claims, &headers, auth.set_cookie.into_iter().collect(), auth.delete_cookie));
    }
    if app.is_allowlisted(&fwd) {
        trace!("path can be accessed without authentication");
        return Ok(StatusCode::OK.into_response());
    }

    Ok(redirect_to_auth_start(&app, &headers, fwd.as_str()).await)
}

/// Nginx forward auth handler.
///
/// Parses `X-Original-URL`, checks auth, and returns 200 + headers or 401.
/// Unlike traefik/caddy, nginx doesn't follow redirects from auth endpoints,
/// so we return 401 instead of redirecting.
///
/// Go reference: `forwardHandleNginx` in `application/mode_forward.go`.
#[instrument(skip_all)]
pub(crate) async fn handle_nginx(
    State(app): State<Arc<Application>>,
    request: Request,
) -> Result<Response> {
    let headers = request.headers();

    let Some(fwd) = get_nginx_forward_url(headers) else {
        let msg = format!(
            "Outpost {} (Provider {}) failed to detect a forward URL from nginx",
            app.outpost_name, app.provider.name,
        );
        app.report_misconfiguration(&msg, headers, request.uri().to_string().as_str())
            .await;
        return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    };

    let auth = app.check_auth(headers).await;
    if let Some(ref claims) = auth.claims {
        return Ok(ok_with_headers(&app, claims, headers, auth.set_cookie.into_iter().collect(), auth.delete_cookie));
    }
    if app.is_allowlisted(&fwd) {
        trace!("path can be accessed without authentication");
        return Ok(StatusCode::OK.into_response());
    }

    // Save redirect to session if not already set
    let session_id = session_id_from_cookies(headers, &app.session_name);
    if let Some(ref sid) = session_id {
        if let Ok(Some(mut data)) = app.session_store.load(sid).await {
            if data.redirect.is_none() {
                data.redirect = Some(fwd.to_string());
                if let Err(err) = app
                    .session_store
                    .save(sid, &data, app.cookie_options.max_age)
                    .await
                {
                    warn!(?err, "failed to save session before redirect");
                }
            }
        }
    }

    // Allow access to outpost paths (nginx sends auth_request for all paths)
    if fwd.path().starts_with("/outpost.goauthentik.io") {
        trace!("path begins with /outpost.goauthentik.io, allowing access");
        return Ok(StatusCode::OK.into_response());
    }

    Ok((StatusCode::UNAUTHORIZED, "unauthorized request").into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outpost::proxy::application::auth::AuthHeaderCache;
    use crate::outpost::proxy::application::endpoint::OIDCEndpoint;
    use crate::outpost::proxy::application::session::{
        CookieOptions, SameSite, SessionData, SessionStore,
    };
    use crate::outpost::proxy::application::session_filesystem::FilesystemStore;
    use crate::outpost::proxy::application::types::Claims;

    fn test_app(store_dir: &std::path::Path) -> Application {
        let mut provider = ak_client::models::ProxyOutpostConfig::new(
            1,
            "test-provider".to_owned(),
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
        provider.cookie_secret = Some("cookie-secret".to_owned());
        provider.mode = Some(ak_client::models::ProxyMode::ForwardSingle);

        Application {
            host: "app.example.com".to_owned(),
            provider,
            router: axum::Router::new(),
            cert: None,
            endpoint: OIDCEndpoint {
                authorization_url: "https://auth.example.com/authorize".to_owned(),
                token_url: String::new(),
                token_introspection: String::new(),
                end_session: "https://auth.example.com/end-session".to_owned(),
                jwks_uri: String::new(),
                issuer: String::new(),
            },
            redirect_uri: "https://app.example.com/outpost.goauthentik.io/callback?X-authentik-auth-callback=true".to_owned(),
            session_name: "authentik_proxy_test".to_owned(),
            outpost_name: "test-outpost".to_owned(),
            unauthenticated_regex: vec![regex::Regex::new("/health").unwrap()],
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
        }
    }

    fn make_session_headers(session_id: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            format!("authentik_proxy_test={session_id}").parse().unwrap(),
        );
        headers
    }

    // -- URL parsing tests --

    #[test]
    fn traefik_url_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-Proto", "https".parse().unwrap());
        headers.insert("X-Forwarded-Host", "app.example.com".parse().unwrap());
        headers.insert("X-Forwarded-Uri", "/dashboard?tab=1".parse().unwrap());

        let url = get_traefik_forward_url(&headers).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("app.example.com"));
        assert_eq!(url.path(), "/dashboard");
        assert_eq!(url.query(), Some("tab=1"));
    }

    #[test]
    fn traefik_url_missing_proto() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-Host", "app.example.com".parse().unwrap());
        headers.insert("X-Forwarded-Uri", "/path".parse().unwrap());

        assert!(get_traefik_forward_url(&headers).is_none());
    }

    #[test]
    fn traefik_url_missing_host() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-Proto", "https".parse().unwrap());
        headers.insert("X-Forwarded-Uri", "/path".parse().unwrap());

        assert!(get_traefik_forward_url(&headers).is_none());
    }

    #[test]
    fn traefik_url_empty_uri() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-Proto", "https".parse().unwrap());
        headers.insert("X-Forwarded-Host", "app.example.com".parse().unwrap());

        let url = get_traefik_forward_url(&headers).unwrap();
        assert_eq!(url.host_str(), Some("app.example.com"));
        assert_eq!(url.path(), "/");
    }

    #[test]
    fn nginx_url_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Original-URL",
            "https://app.example.com/protected?q=1".parse().unwrap(),
        );

        let url = get_nginx_forward_url(&headers).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("app.example.com"));
        assert_eq!(url.path(), "/protected");
        assert_eq!(url.query(), Some("q=1"));
    }

    #[test]
    fn nginx_url_missing_header() {
        let headers = HeaderMap::new();
        assert!(get_nginx_forward_url(&headers).is_none());
    }

    #[test]
    fn nginx_url_empty_header() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Original-URL", "".parse().unwrap());
        assert!(get_nginx_forward_url(&headers).is_none());
    }

    #[test]
    fn envoy_url_strips_prefix() {
        let request = Request::builder()
            .uri("/outpost.goauthentik.io/auth/envoy/api/resource?key=val")
            .header("Host", "app.example.com")
            .body(axum::body::Body::empty())
            .unwrap();

        let url = get_envoy_forward_url(&request).unwrap();
        assert_eq!(url.path(), "/api/resource");
        assert_eq!(url.query(), Some("key=val"));
        assert_eq!(url.host_str(), Some("app.example.com"));
    }

    #[test]
    fn envoy_url_no_extra_path() {
        let request = Request::builder()
            .uri("/outpost.goauthentik.io/auth/envoy")
            .header("Host", "app.example.com")
            .body(axum::body::Body::empty())
            .unwrap();

        let url = get_envoy_forward_url(&request).unwrap();
        assert_eq!(url.path(), "/");
    }

    #[test]
    fn envoy_url_missing_host() {
        let request = Request::builder()
            .uri("/outpost.goauthentik.io/auth/envoy/path")
            .body(axum::body::Body::empty())
            .unwrap();

        assert!(get_envoy_forward_url(&request).is_none());
    }

    // -- has_query_flag tests --

    #[test]
    fn query_flag_present() {
        let url = Url::parse("https://example.com/path?X-authentik-auth-callback=true").unwrap();
        assert!(has_query_flag(&url, CALLBACK_SIGNATURE));
    }

    #[test]
    fn query_flag_absent() {
        let url = Url::parse("https://example.com/path?other=true").unwrap();
        assert!(!has_query_flag(&url, CALLBACK_SIGNATURE));
    }

    #[test]
    fn query_flag_case_insensitive() {
        let url = Url::parse("https://example.com/path?X-authentik-auth-callback=True").unwrap();
        assert!(has_query_flag(&url, CALLBACK_SIGNATURE));
    }

    // -- handle_traefik_caddy integration tests --

    #[tokio::test]
    async fn traefik_authenticated_returns_200_with_headers() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());

        // Create a session with claims
        let data = SessionData {
            claims: Some(Claims {
                sub: "user-1".to_owned(),
                preferred_username: "alice".to_owned(),
                ..Default::default()
            }),
            redirect: None,
        };
        app.session_store.save("sess-ok", &data, 3600).await.unwrap();

        let mut headers = make_session_headers("sess-ok");
        headers.insert("X-Forwarded-Proto", "https".parse().unwrap());
        headers.insert("X-Forwarded-Host", "app.example.com".parse().unwrap());
        headers.insert("X-Forwarded-Uri", "/protected".parse().unwrap());

        let response = handle_traefik_caddy(&app, headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("X-authentik-username"));
    }

    #[tokio::test]
    async fn traefik_unauthenticated_allowlisted_returns_200() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());

        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-Proto", "https".parse().unwrap());
        headers.insert("X-Forwarded-Host", "app.example.com".parse().unwrap());
        headers.insert("X-Forwarded-Uri", "/health".parse().unwrap());

        let response = handle_traefik_caddy(&app, headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("X-authentik-username"));
    }

    #[tokio::test]
    async fn traefik_unauthenticated_redirects() {
        let _ = jsonwebtoken::crypto::CryptoProvider::install_default(
            &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER,
        );
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());

        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-Proto", "https".parse().unwrap());
        headers.insert("X-Forwarded-Host", "app.example.com".parse().unwrap());
        headers.insert("X-Forwarded-Uri", "/protected".parse().unwrap());

        let response = handle_traefik_caddy(&app, headers).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("auth.example.com/authorize"));
    }

    #[tokio::test]
    async fn traefik_missing_headers_returns_500() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());

        let response = handle_traefik_caddy(&app, HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // -- nginx tests --

    #[tokio::test]
    async fn nginx_authenticated_returns_200_with_headers() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());

        let data = SessionData {
            claims: Some(Claims {
                sub: "user-1".to_owned(),
                preferred_username: "alice".to_owned(),
                ..Default::default()
            }),
            redirect: None,
        };
        app.session_store.save("nginx-sess", &data, 3600).await.unwrap();

        let request = Request::builder()
            .uri("/outpost.goauthentik.io/auth/nginx")
            .header("X-Original-URL", "https://app.example.com/protected")
            .header("Cookie", "authentik_proxy_test=nginx-sess")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = handle_nginx(State(Arc::new(app)), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("X-authentik-username"));
    }

    #[tokio::test]
    async fn nginx_unauthenticated_returns_401() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());

        let request = Request::builder()
            .uri("/outpost.goauthentik.io/auth/nginx")
            .header("X-Original-URL", "https://app.example.com/secret")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = handle_nginx(State(Arc::new(app)), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn nginx_outpost_path_returns_200() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());

        let request = Request::builder()
            .uri("/outpost.goauthentik.io/auth/nginx")
            .header("X-Original-URL", "https://app.example.com/outpost.goauthentik.io/start?rd=foo")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = handle_nginx(State(Arc::new(app)), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn nginx_allowlisted_returns_200() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());

        let request = Request::builder()
            .uri("/outpost.goauthentik.io/auth/nginx")
            .header("X-Original-URL", "https://app.example.com/health")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = handle_nginx(State(Arc::new(app)), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
