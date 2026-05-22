use std::sync::Arc;
use std::time::Instant;

use ak_axum::error::Result;
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
};
use metrics::histogram;
use tracing::{instrument, trace, warn};
use url::Url;

use crate::outpost::proxy::application::Application;
use crate::outpost::proxy::application::session::build_delete_cookie;

/// Headers that must not be forwarded between client and upstream (hop-by-hop).
///
/// Go's `httputil.ReverseProxy` strips these automatically; we must do it
/// manually.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    HOP_BY_HOP_HEADERS.contains(&lower.as_str())
}

/// Build the upstream URL by combining `internal_host` with the path and query
/// from the incoming request URI.
///
/// Go reference: the `Director` closure in `configureProxy` rewrites
/// `r.URL.Scheme` and `r.URL.Host` to the upstream URL, keeping the original
/// path and query.
fn build_upstream_url(internal_host: &str, uri: &axum::http::Uri) -> Option<Url> {
    let base = Url::parse(internal_host).ok()?;
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    base.join(path_and_query).ok()
}

/// Reverse proxy handler.
///
/// Checks authentication, injects `X-authentik-*` headers, forwards the request
/// to `internal_host`, and streams the response back with `X-Powered-By` set.
///
/// Go reference: the handler registered on `mux.PathPrefix("/")` in
/// `configureProxy` (`application/mode_proxy.go`).
#[instrument(skip_all)]
pub(crate) async fn handle(
    State(app): State<Arc<Application>>,
    request: Request,
) -> Result<Response> {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    let body = request.into_body();

    // Build the request URL for allowlist checking.
    let request_url = {
        let base = Url::parse(&app.provider.external_host)
            .unwrap_or_else(|_| Url::parse("https://localhost").expect("static URL"));
        base.join(&uri.to_string()).unwrap_or(base)
    };

    // Auth check.
    // Go reference: checkAuth in application/auth.go
    let auth = app.check_auth(&headers).await;

    // Prepare forwarded headers: copy originals, strip hop-by-hop.
    let mut fwd_headers = HeaderMap::new();
    for (name, value) in &headers {
        if !is_hop_by_hop(name.as_str()) {
            fwd_headers.append(name.clone(), value.clone());
        }
    }

    // Set X-Forwarded-Host to the original Host.
    // Go reference: Director closure in configureProxy sets X-Forwarded-Host = r.Host
    let original_host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&app.host);
    if let Ok(val) = original_host.parse() {
        fwd_headers.insert("X-Forwarded-Host", val);
    }

    // Dispatch on auth result.
    let mut response_cookies: Vec<String> = Vec::new();
    let delete_cookie = auth.delete_cookie;

    if let Some(ref claims) = auth.claims {
        // Authenticated → inject X-authentik-* headers into the forwarded request.
        app.add_headers(&mut fwd_headers, claims);
        if let Some(cookie) = auth.set_cookie {
            response_cookies.push(cookie);
        }
    } else if app.is_allowlisted(&request_url) {
        // Allowlisted → proxy without auth headers.
        trace!("path can be accessed without authentication");
    } else {
        // Unauthenticated and not allowlisted → redirect to start.
        use crate::outpost::proxy::application::oauth::RedirectToStartResult;

        let result = app.redirect_to_start(&headers, &request_url).await;
        return match result {
            RedirectToStartResult::Redirect {
                redirect_url,
                cookies,
            } => {
                let mut resp =
                    axum::response::Redirect::to(&redirect_url).into_response();
                let rh = resp.headers_mut();
                for c in &cookies {
                    if let Ok(v) = c.parse() {
                        rh.append(SET_COOKIE, v);
                    }
                }
                if delete_cookie {
                    if let Ok(v) = build_delete_cookie(&app.cookie_options).parse() {
                        rh.append(SET_COOKIE, v);
                    }
                }
                Ok(resp)
            }
            RedirectToStartResult::Unauthorized => {
                Ok(StatusCode::UNAUTHORIZED.into_response())
            }
        };
    }

    // Build upstream URL from internal_host.
    let internal_host = app.provider.internal_host.as_deref().unwrap_or_default();
    let Some(mut upstream_url) = build_upstream_url(internal_host, &uri) else {
        warn!(internal_host, "failed to build upstream URL");
        return Ok(StatusCode::BAD_GATEWAY.into_response());
    };

    // Per-user backend override: replace the upstream scheme + host.
    // Go reference: proxyModifyRequest in application/mode_proxy.go
    if let Some(ref claims) = auth.claims {
        if let Some(ref proxy) = claims.ak_proxy {
            if !proxy.backend_override.is_empty() {
                match Url::parse(&proxy.backend_override) {
                    Ok(override_url) => {
                        trace!(
                            backend_override = proxy.backend_override,
                            "applying per-user backend override"
                        );
                        upstream_url
                            .set_scheme(override_url.scheme())
                            .unwrap_or(());
                        upstream_url
                            .set_host(override_url.host_str())
                            .unwrap_or(());
                        upstream_url.set_port(override_url.port()).unwrap_or(());
                    }
                    Err(err) => {
                        warn!(
                            ?err,
                            backend_override = proxy.backend_override,
                            "failed to parse backend override URL"
                        );
                    }
                }
            }

            // Per-user Host header override.
            // Go reference: proxyModifyRequest sets r.Host = claims.Proxy.HostHeader
            if !proxy.host_header.is_empty() {
                if let Ok(val) = proxy.host_header.parse() {
                    fwd_headers.insert("host", val);
                }
            }
        }
    }

    // Forward request body as a stream.
    let body_stream = body.into_data_stream();
    let upstream_body = reqwest::Body::wrap_stream(body_stream);

    // Build and send upstream request.
    let method_str = method.to_string();
    let mut upstream_req = app
        .upstream_client
        .request(method, upstream_url.as_str());
    for (name, value) in &fwd_headers {
        upstream_req = upstream_req.header(name.clone(), value.clone());
    }
    upstream_req = upstream_req.body(upstream_body);

    // Time the upstream request for metrics.
    // Go reference: mode_proxy.go records authentik_outpost_proxy_upstream_response_duration_seconds
    let upstream_start = Instant::now();
    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(err) => {
            warn!(?err, upstream = upstream_url.as_str(), "upstream request failed");
            let detail = format!("Error proxying to upstream server: {err}");
            return Ok(app.error_page(auth.claims.as_ref(), &detail));
        }
    };
    histogram!(
        "authentik_outpost_proxy_upstream_response_duration_seconds",
        "outpost_name" => app.outpost_name.clone(),
        "method" => method_str,
        "scheme" => upstream_url.scheme().to_owned(),
        "host" => original_host.to_owned(),
        "upstream_host" => upstream_url.host_str().unwrap_or_default().to_owned(),
    )
    .record(upstream_start.elapsed().as_secs_f64());

    // Stream upstream response back to client.
    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_body = axum::body::Body::from_stream(upstream_resp.bytes_stream());

    let mut builder = axum::http::Response::builder().status(status);
    for (name, value) in &resp_headers {
        if !is_hop_by_hop(name.as_str()) {
            builder = builder.header(name.clone(), value.clone());
        }
    }
    // Go reference: proxyModifyResponse sets X-Powered-By.
    builder = builder.header("X-Powered-By", "goauthentik.io");

    let mut response = builder
        .body(resp_body)
        .expect("response builder should not fail");

    // Apply auth-related cookies.
    let rh = response.headers_mut();
    for c in &response_cookies {
        if let Ok(v) = c.parse() {
            rh.append(SET_COOKIE, v);
        }
    }
    if delete_cookie {
        if let Ok(v) = build_delete_cookie(&app.cookie_options).parse() {
            rh.append(SET_COOKIE, v);
        }
    }

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- build_upstream_url tests --

    #[test]
    fn upstream_url_basic() {
        let url =
            build_upstream_url("http://backend:8080", &"/api/data".parse().unwrap()).unwrap();
        assert_eq!(url.as_str(), "http://backend:8080/api/data");
    }

    #[test]
    fn upstream_url_with_query() {
        let url = build_upstream_url(
            "http://backend:8080",
            &"/search?q=hello&page=2".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(url.as_str(), "http://backend:8080/search?q=hello&page=2");
    }

    #[test]
    fn upstream_url_preserves_trailing_slash() {
        let url =
            build_upstream_url("https://internal.svc", &"/app/".parse().unwrap()).unwrap();
        assert_eq!(url.as_str(), "https://internal.svc/app/");
    }

    #[test]
    fn upstream_url_root_path() {
        let url = build_upstream_url("http://backend:3000", &"/".parse().unwrap()).unwrap();
        assert_eq!(url.as_str(), "http://backend:3000/");
    }

    #[test]
    fn upstream_url_internal_host_with_path() {
        // internal_host might have a base path (unusual but possible).
        let url =
            build_upstream_url("http://backend:8080/base", &"/sub/path".parse().unwrap())
                .unwrap();
        // Url::join replaces the path when the joined path starts with '/'.
        assert_eq!(url.as_str(), "http://backend:8080/sub/path");
    }

    #[test]
    fn upstream_url_invalid_internal_host() {
        assert!(build_upstream_url("not-a-url", &"/path".parse().unwrap()).is_none());
    }

    #[test]
    fn upstream_url_empty_internal_host() {
        assert!(build_upstream_url("", &"/path".parse().unwrap()).is_none());
    }

    // -- is_hop_by_hop tests --

    #[test]
    fn hop_by_hop_detected() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(is_hop_by_hop("Keep-Alive"));
        assert!(is_hop_by_hop("TE"));
        assert!(is_hop_by_hop("Upgrade"));
    }

    #[test]
    fn regular_headers_not_hop_by_hop() {
        assert!(!is_hop_by_hop("Content-Type"));
        assert!(!is_hop_by_hop("Authorization"));
        assert!(!is_hop_by_hop("X-Custom-Header"));
        assert!(!is_hop_by_hop("Host"));
    }

    // -- Integration tests with a mock upstream --

    use crate::outpost::proxy::application::auth::AuthHeaderCache;
    use crate::outpost::proxy::application::endpoint::OIDCEndpoint;
    use crate::outpost::proxy::application::session::{
        CookieOptions, SameSite, SessionData, SessionStore,
    };
    use crate::outpost::proxy::application::session_filesystem::FilesystemStore;
    use crate::outpost::proxy::application::types::{Claims, ProxyClaims};

    fn test_app(store_dir: &std::path::Path, internal_host: &str) -> Application {
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
        provider.mode = Some(ak_client::models::ProxyMode::Proxy);
        provider.internal_host = Some(internal_host.to_owned());

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
            upstream_client: reqwest::Client::new(),
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

    /// Start a mock upstream server that echoes request info back in response
    /// headers.
    async fn start_echo_server() -> (tokio::net::TcpListener, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");
        (listener, base_url)
    }

    async fn echo_handler(request: Request) -> Response {
        let mut resp = StatusCode::OK.into_response();
        let rh = resp.headers_mut();
        // Echo back some request info so tests can verify forwarding.
        if let Some(v) = request.headers().get("X-Forwarded-Host") {
            rh.insert("X-Test-Forwarded-Host", v.clone());
        }
        if let Some(v) = request.headers().get("X-authentik-username") {
            rh.insert("X-Test-Auth-Username", v.clone());
        }
        if let Some(v) = request.headers().get("host") {
            rh.insert("X-Test-Host", v.clone());
        }
        // Echo the request path via a custom header.
        rh.insert(
            "X-Test-Path",
            request.uri().path().parse().unwrap(),
        );
        if let Some(q) = request.uri().query() {
            rh.insert("X-Test-Query", q.parse().unwrap());
        }
        resp
    }

    #[tokio::test]
    async fn proxy_authenticated_forwards_to_upstream() {
        let dir = tempfile::tempdir().unwrap();
        let (listener, base_url) = start_echo_server().await;
        let app = Arc::new(test_app(dir.path(), &base_url));

        // Save a session with claims.
        let data = SessionData {
            claims: Some(Claims {
                sub: "user-1".to_owned(),
                preferred_username: "alice".to_owned(),
                ..Default::default()
            }),
            redirect: None,
        };
        app.session_store
            .save("proxy-sess", &data, 3600)
            .await
            .unwrap();

        // Spawn the echo server.
        tokio::spawn({
            let router = axum::Router::new().fallback(echo_handler);
            async move { axum::serve(listener, router).await.unwrap() }
        });

        let request = Request::builder()
            .uri("/api/data?key=val")
            .header("Cookie", "authentik_proxy_test=proxy-sess")
            .header("Host", "app.example.com")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = handle(State(app), request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("X-Powered-By").unwrap(),
            "goauthentik.io"
        );
        assert_eq!(
            response.headers().get("X-Test-Forwarded-Host").unwrap(),
            "app.example.com"
        );
        assert_eq!(
            response.headers().get("X-Test-Auth-Username").unwrap(),
            "alice"
        );
        assert_eq!(response.headers().get("X-Test-Path").unwrap(), "/api/data");
        assert_eq!(response.headers().get("X-Test-Query").unwrap(), "key=val");
    }

    #[tokio::test]
    async fn proxy_allowlisted_forwards_without_auth_headers() {
        let dir = tempfile::tempdir().unwrap();
        let (listener, base_url) = start_echo_server().await;
        let app = Arc::new(test_app(dir.path(), &base_url));

        tokio::spawn({
            let router = axum::Router::new().fallback(echo_handler);
            async move { axum::serve(listener, router).await.unwrap() }
        });

        let request = Request::builder()
            .uri("/health")
            .header("Host", "app.example.com")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = handle(State(app), request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("X-Powered-By").unwrap(),
            "goauthentik.io"
        );
        // No auth headers should be present.
        assert!(response.headers().get("X-Test-Auth-Username").is_none());
        assert_eq!(response.headers().get("X-Test-Path").unwrap(), "/health");
    }

    #[tokio::test]
    async fn proxy_unauthenticated_redirects_to_start() {
        let dir = tempfile::tempdir().unwrap();
        let app = Arc::new(test_app(dir.path(), "http://localhost:1"));

        let request = Request::builder()
            .uri("/protected")
            .header("Host", "app.example.com")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = handle(State(app), request).await.unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        // redirect_to_start sends users to /outpost.goauthentik.io/start,
        // not directly to the authorization endpoint.
        assert!(location.contains("/outpost.goauthentik.io/start"));
        assert!(location.contains("rd="));
    }

    #[tokio::test]
    async fn proxy_upstream_failure_returns_502() {
        let dir = tempfile::tempdir().unwrap();
        // Point to a port that is not listening.
        let app = Arc::new(test_app(dir.path(), "http://127.0.0.1:1"));

        let data = SessionData {
            claims: Some(Claims {
                sub: "user-1".to_owned(),
                preferred_username: "alice".to_owned(),
                ..Default::default()
            }),
            redirect: None,
        };
        app.session_store
            .save("fail-sess", &data, 3600)
            .await
            .unwrap();

        let request = Request::builder()
            .uri("/api/data")
            .header("Cookie", "authentik_proxy_test=fail-sess")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = handle(State(app), request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn proxy_invalid_internal_host_returns_502() {
        let dir = tempfile::tempdir().unwrap();
        let app = Arc::new(test_app(dir.path(), "not-a-url"));

        let data = SessionData {
            claims: Some(Claims {
                sub: "user-1".to_owned(),
                ..Default::default()
            }),
            redirect: None,
        };
        app.session_store
            .save("bad-host-sess", &data, 3600)
            .await
            .unwrap();

        let request = Request::builder()
            .uri("/anything")
            .header("Cookie", "authentik_proxy_test=bad-host-sess")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = handle(State(app), request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    // -- Per-user override tests --

    #[tokio::test]
    async fn proxy_backend_override_changes_upstream() {
        let dir = tempfile::tempdir().unwrap();
        // Default backend (should NOT be used).
        let (_, default_url) = start_echo_server().await;
        // Override backend (should be used).
        let (override_listener, override_url) = start_echo_server().await;
        let app = Arc::new(test_app(dir.path(), &default_url));

        tokio::spawn({
            let router = axum::Router::new().fallback(echo_handler);
            async move { axum::serve(override_listener, router).await.unwrap() }
        });

        let data = SessionData {
            claims: Some(Claims {
                sub: "user-1".to_owned(),
                preferred_username: "alice".to_owned(),
                ak_proxy: Some(ProxyClaims {
                    backend_override: override_url.clone(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            redirect: None,
        };
        app.session_store
            .save("override-sess", &data, 3600)
            .await
            .unwrap();

        let request = Request::builder()
            .uri("/api/check")
            .header("Cookie", "authentik_proxy_test=override-sess")
            .header("Host", "app.example.com")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = handle(State(app), request).await.unwrap();

        // The request should have reached the override server, not the default.
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("X-Test-Path").unwrap(), "/api/check");
    }

    #[tokio::test]
    async fn proxy_host_header_override() {
        let dir = tempfile::tempdir().unwrap();
        let (listener, base_url) = start_echo_server().await;
        let app = Arc::new(test_app(dir.path(), &base_url));

        tokio::spawn({
            let router = axum::Router::new().fallback(echo_handler);
            async move { axum::serve(listener, router).await.unwrap() }
        });

        let data = SessionData {
            claims: Some(Claims {
                sub: "user-1".to_owned(),
                preferred_username: "bob".to_owned(),
                ak_proxy: Some(ProxyClaims {
                    host_header: "custom-backend.internal".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            redirect: None,
        };
        app.session_store
            .save("host-sess", &data, 3600)
            .await
            .unwrap();

        let request = Request::builder()
            .uri("/test")
            .header("Cookie", "authentik_proxy_test=host-sess")
            .header("Host", "app.example.com")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = handle(State(app), request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        // The X-Forwarded-Host should still be the original host.
        assert_eq!(
            response.headers().get("X-Test-Forwarded-Host").unwrap(),
            "app.example.com"
        );
        // The Host header sent to the upstream should be the override.
        assert_eq!(
            response.headers().get("X-Test-Host").unwrap(),
            "custom-backend.internal"
        );
    }

    #[tokio::test]
    async fn proxy_invalid_backend_override_uses_default() {
        let dir = tempfile::tempdir().unwrap();
        let (listener, base_url) = start_echo_server().await;
        let app = Arc::new(test_app(dir.path(), &base_url));

        tokio::spawn({
            let router = axum::Router::new().fallback(echo_handler);
            async move { axum::serve(listener, router).await.unwrap() }
        });

        let data = SessionData {
            claims: Some(Claims {
                sub: "user-1".to_owned(),
                preferred_username: "charlie".to_owned(),
                ak_proxy: Some(ProxyClaims {
                    backend_override: "not-a-valid-url".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            redirect: None,
        };
        app.session_store
            .save("bad-override-sess", &data, 3600)
            .await
            .unwrap();

        let request = Request::builder()
            .uri("/fallback")
            .header("Cookie", "authentik_proxy_test=bad-override-sess")
            .header("Host", "app.example.com")
            .body(axum::body::Body::empty())
            .unwrap();

        let response = handle(State(app), request).await.unwrap();

        // Should still work — falls back to default internal_host.
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("X-Test-Path").unwrap(),
            "/fallback"
        );
    }
}
