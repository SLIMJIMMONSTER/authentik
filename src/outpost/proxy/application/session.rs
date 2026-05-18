use axum::http::{HeaderMap, header::COOKIE};
use eyre::Result;
use serde::{Deserialize, Serialize};

use super::types::Claims;

/// Data stored in a session.
///
/// Mirrors the two values the Go implementation stores:
/// - `claims` (constants.SessionClaims): the authenticated user's OIDC claims
/// - `redirect` (constants.SessionRedirect): the URL to redirect to after login
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct SessionData {
    pub(crate) claims: Option<Claims>,
    pub(crate) redirect: Option<String>,
}

/// A loaded session, containing server-side data and metadata needed to
/// persist changes back.
#[derive(Debug, Clone)]
pub(crate) struct Session {
    /// Unique session identifier (stored in the cookie, used as storage key).
    pub(crate) id: String,
    /// Whether this session existed in the store before this request.
    pub(crate) is_new: bool,
    /// The session payload.
    pub(crate) data: SessionData,
}

impl Session {
    pub(crate) fn new(id: String) -> Self {
        Self {
            id,
            is_new: true,
            data: SessionData::default(),
        }
    }
}

/// Cookie configuration for the session.
#[derive(Debug, Clone)]
pub(crate) struct CookieOptions {
    pub(crate) name: String,
    pub(crate) domain: String,
    pub(crate) path: String,
    pub(crate) secure: bool,
    pub(crate) http_only: bool,
    pub(crate) same_site: SameSite,
    /// Default max-age in seconds. Can be overridden per-save.
    pub(crate) max_age: i64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SameSite {
    Lax,
    Strict,
    None,
}

impl std::fmt::Display for SameSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SameSite::Lax => write!(f, "Lax"),
            SameSite::Strict => write!(f, "Strict"),
            SameSite::None => write!(f, "None"),
        }
    }
}

/// Server-side session store abstraction.
///
/// Implementations handle persistence (filesystem, PostgreSQL, etc.).
/// Cookie reading/writing is handled by the common helpers below.
pub(crate) trait SessionStore: Send + Sync + std::fmt::Debug {
    /// Load a session by its ID. Returns `None` if the session doesn't exist
    /// or has expired.
    fn load(&self, session_id: &str) -> impl Future<Output = Result<Option<SessionData>>> + Send;

    /// Persist session data under the given ID.
    /// `max_age` is the TTL in seconds for this specific save.
    fn save(
        &self,
        session_id: &str,
        data: &SessionData,
        max_age: i64,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Delete a session by its ID.
    fn delete(&self, session_id: &str) -> impl Future<Output = Result<()>> + Send;

    /// Delete all sessions matching a predicate on their claims.
    /// Used for logout (e.g., delete all sessions for a given `sub`).
    fn delete_matching(
        &self,
        predicate: &(dyn Fn(&Claims) -> bool + Send + Sync),
    ) -> impl Future<Output = Result<()>> + Send;
}

/// Extract the session ID from the request cookies.
pub(crate) fn session_id_from_cookies(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some((name, value)) = pair.split_once('=') {
            if name.trim() == cookie_name {
                let v = value.trim();
                if !v.is_empty() {
                    return Some(v.to_owned());
                }
            }
        }
    }
    None
}

/// Build a `Set-Cookie` header value for the session.
pub(crate) fn build_set_cookie(
    session_id: &str,
    opts: &CookieOptions,
    max_age: Option<i64>,
) -> String {
    let max_age = max_age.unwrap_or(opts.max_age);

    let mut cookie = format!("{}={}", opts.name, session_id);
    if !opts.domain.is_empty() {
        cookie.push_str(&format!("; Domain={}", opts.domain));
    }
    cookie.push_str(&format!("; Path={}", opts.path));
    cookie.push_str(&format!("; Max-Age={max_age}"));
    if opts.http_only {
        cookie.push_str("; HttpOnly");
    }
    if opts.secure {
        cookie.push_str("; Secure");
    }
    cookie.push_str(&format!("; SameSite={}", opts.same_site));
    cookie
}

/// Build a `Set-Cookie` header value that deletes the session cookie.
pub(crate) fn build_delete_cookie(opts: &CookieOptions) -> String {
    build_set_cookie("", opts, Some(-1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_session_id_from_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            "other=foo; authentik_proxy_abc12345=my-session-id; bar=baz"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            session_id_from_cookies(&headers, "authentik_proxy_abc12345"),
            Some("my-session-id".to_owned()),
        );
    }

    #[test]
    fn extract_session_id_missing() {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, "other=foo".parse().unwrap());
        assert_eq!(
            session_id_from_cookies(&headers, "authentik_proxy_abc12345"),
            None,
        );
    }

    #[test]
    fn extract_session_id_no_cookie_header() {
        let headers = HeaderMap::new();
        assert_eq!(
            session_id_from_cookies(&headers, "authentik_proxy_abc12345"),
            None,
        );
    }

    #[test]
    fn build_set_cookie_all_options() {
        let opts = CookieOptions {
            name: "authentik_proxy_abc12345".to_owned(),
            domain: "example.com".to_owned(),
            path: "/".to_owned(),
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            max_age: 3600,
        };
        let cookie = build_set_cookie("session-id-123", &opts, None);
        assert!(cookie.starts_with("authentik_proxy_abc12345=session-id-123"));
        assert!(cookie.contains("Domain=example.com"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Max-Age=3600"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Lax"));
    }

    #[test]
    fn build_delete_cookie_sets_negative_max_age() {
        let opts = CookieOptions {
            name: "authentik_proxy_abc12345".to_owned(),
            domain: "example.com".to_owned(),
            path: "/".to_owned(),
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            max_age: 3600,
        };
        let cookie = build_delete_cookie(&opts);
        assert!(cookie.contains("Max-Age=-1"));
        assert!(cookie.starts_with("authentik_proxy_abc12345=;"));
    }
}
