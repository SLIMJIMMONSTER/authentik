use http::Extensions;
use reqwest::{Request, Response, header::HOST};
use reqwest_middleware::{Middleware, Next, Result};
use tracing::trace;

/// Middleware that rewrites the `Host` header and sets `X-Forwarded-Proto`
/// on outgoing requests.
///
/// This is used for token endpoint requests so that the `Host` header matches
/// the authentik issuer even when the outpost makes requests to an internal
/// URL (e.g., embedded outposts hitting localhost).
///
/// Go reference: `hostInterceptor` in `internal/utils/web/http_host_interceptor.go`.
#[derive(Debug)]
pub(super) struct HostInterceptorMiddleware {
    host: String,
    scheme: String,
}

impl HostInterceptorMiddleware {
    /// Create a new host interceptor from a full URL (e.g. `https://authentik.company.tld`).
    ///
    /// Extracts the host and scheme from the URL. If the URL is invalid,
    /// returns a no-op interceptor with empty values (no rewriting).
    pub(super) fn from_url(url: &str) -> Self {
        match url::Url::parse(url) {
            Ok(parsed) => Self {
                host: parsed
                    .host_str()
                    .map(|h| {
                        if let Some(port) = parsed.port() {
                            format!("{h}:{port}")
                        } else {
                            h.to_owned()
                        }
                    })
                    .unwrap_or_default(),
                scheme: parsed.scheme().to_owned(),
            },
            Err(_) => Self {
                host: String::new(),
                scheme: String::new(),
            },
        }
    }
}

#[async_trait::async_trait]
impl Middleware for HostInterceptorMiddleware {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response> {
        if !self.host.is_empty() {
            // Only rewrite if the request's host differs from the target.
            let current_host = req.url().host_str().unwrap_or_default();
            if current_host != self.host {
                trace!(
                    from = current_host,
                    to = self.host,
                    "rewriting Host header for token request"
                );
                if let Ok(val) = self.host.parse() {
                    req.headers_mut().insert(HOST, val);
                }
                if let Ok(val) = self.scheme.parse() {
                    req.headers_mut()
                        .insert("X-Forwarded-Proto", val);
                }
            }
        }
        next.run(req, extensions).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_url_extracts_host_and_scheme() {
        let m = HostInterceptorMiddleware::from_url("https://authentik.company.tld");
        assert_eq!(m.host, "authentik.company.tld");
        assert_eq!(m.scheme, "https");
    }

    #[test]
    fn from_url_with_port() {
        let m = HostInterceptorMiddleware::from_url("https://authentik.company.tld:9443");
        assert_eq!(m.host, "authentik.company.tld:9443");
        assert_eq!(m.scheme, "https");
    }

    #[test]
    fn from_url_http() {
        let m = HostInterceptorMiddleware::from_url("http://localhost:9000");
        assert_eq!(m.host, "localhost:9000");
        assert_eq!(m.scheme, "http");
    }

    #[test]
    fn from_url_invalid() {
        let m = HostInterceptorMiddleware::from_url("not a url");
        assert!(m.host.is_empty());
        assert!(m.scheme.is_empty());
    }

    #[test]
    fn from_url_empty() {
        let m = HostInterceptorMiddleware::from_url("");
        assert!(m.host.is_empty());
        assert!(m.scheme.is_empty());
    }
}
