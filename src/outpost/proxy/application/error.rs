use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

use super::Application;
use super::types::Claims;

/// Raw HTML template embedded at compile time.
///
/// Go reference: `templates/error.html` loaded via `//go:embed`.
const ERROR_TEMPLATE: &str = include_str!("templates/error.html");

/// Render the error page HTML with the given title and message.
///
/// Uses simple string replacement on the embedded template—no runtime
/// template engine needed since there are only two placeholders.
fn render_error_html(title: &str, message: &str) -> String {
    // HTML-escape the dynamic values to prevent XSS.
    let title = html_escape(title);
    let message = html_escape(message);
    ERROR_TEMPLATE
        .replace("{title}", &title)
        .replace("{message}", &message)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Render an error page response with a given status code, title, and message.
pub(super) fn render_error_response(
    status: StatusCode,
    title: &str,
    message: &str,
) -> Response {
    let html = render_error_html(title, message);
    (status, Html(html)).into_response()
}

impl Application {
    /// Return an error page response.
    ///
    /// Superusers see the detailed `err` message; regular users see a generic
    /// "Failed to connect to backend." message.
    ///
    /// Go reference: `ErrorPage` in `application/error.go`.
    pub(super) fn error_page(&self, claims: Option<&Claims>, err: &str) -> Response {
        let is_superuser = claims
            .and_then(|c| c.ak_proxy.as_ref())
            .is_some_and(|p| p.is_superuser);

        let message = if is_superuser {
            err.to_owned()
        } else {
            "Failed to connect to backend.".to_owned()
        };

        render_error_response(StatusCode::BAD_GATEWAY, "Bad Gateway", &message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_error_html_substitutes_title_and_message() {
        let html = render_error_html("Bad Gateway", "Failed to connect to backend.");
        assert!(html.contains("<title>Bad Gateway</title>"));
        assert!(html.contains("<h1>Bad Gateway</h1>"));
        assert!(html.contains("<p>Failed to connect to backend.</p>"));
    }

    #[test]
    fn render_error_html_escapes_xss() {
        let html = render_error_html("<script>alert(1)</script>", "msg with <b>html</b>");
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&lt;b&gt;html&lt;/b&gt;"));
    }

    #[test]
    fn html_escape_covers_all_chars() {
        assert_eq!(html_escape("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&#x27;f");
    }

    // Integration tests using the Application method.

    use crate::outpost::proxy::application::auth::AuthHeaderCache;
    use crate::outpost::proxy::application::endpoint::OIDCEndpoint;
    use crate::outpost::proxy::application::session::{CookieOptions, SameSite};
    use crate::outpost::proxy::application::session_filesystem::FilesystemStore;
    use crate::outpost::proxy::application::types::ProxyClaims;

    fn test_app(store_dir: &std::path::Path) -> Application {
        let provider = ak_client::models::ProxyOutpostConfig::new(
            1,
            "my-provider".to_owned(),
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

        Application {
            host: "app.example.com".to_owned(),
            provider,
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
            session_name: "authentik_proxy_test".to_owned(),
            outpost_name: "my-outpost".to_owned(),
            unauthenticated_regex: Vec::new(),
            http_client: reqwest_middleware::ClientWithMiddleware::default(),
            public_http_client: reqwest_middleware::ClientWithMiddleware::default(),
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
            jwks_key_set: crate::outpost::proxy::application::jwks::RemoteJwksKeySet::new(
                String::new(),
                reqwest_middleware::ClientWithMiddleware::default(),
            ),
        }
    }

    #[test]
    fn error_page_generic_for_regular_user() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());

        let claims = Claims {
            sub: "user-1".to_owned(),
            ak_proxy: Some(ProxyClaims {
                is_superuser: false,
                ..Default::default()
            }),
            ..Default::default()
        };

        let resp = app.error_page(Some(&claims), "connection refused (os error 111)");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn error_page_detailed_for_superuser() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());

        let claims = Claims {
            sub: "admin-1".to_owned(),
            ak_proxy: Some(ProxyClaims {
                is_superuser: true,
                ..Default::default()
            }),
            ..Default::default()
        };

        let resp = app.error_page(
            Some(&claims),
            "Error proxying to upstream server: connection refused",
        );
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn error_page_generic_when_no_claims() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());

        let resp = app.error_page(None, "secret error details");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn error_page_generic_when_no_proxy_claims() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());

        let claims = Claims {
            sub: "user-1".to_owned(),
            ak_proxy: None,
            ..Default::default()
        };

        let resp = app.error_page(Some(&claims), "secret error details");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
