use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use serde::Deserialize;
use tracing::{trace, warn};

use super::Application;
use super::types::Claims;

/// Extract a bearer token from the `Authorization` header.
///
/// Returns `None` if the header is missing, empty, or doesn't start with
/// `Bearer ` (case-insensitive).
///
/// Go reference: `checkAuthHeaderBearer` in `application/auth_bearer.go`.
pub(super) fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let auth = headers.get(AUTHORIZATION)?.to_str().ok()?;
    const PREFIX: &str = "Bearer ";
    if auth.len() < PREFIX.len() || !auth[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let token = &auth[PREFIX.len()..];
    if token.is_empty() {
        return None;
    }
    Some(token)
}

/// Response from the OIDC token introspection endpoint.
///
/// Go reference: `TokenIntrospectionResponse` in `application/auth_bearer.go`.
#[derive(Debug, Deserialize)]
struct TokenIntrospectionResponse {
    #[serde(flatten)]
    claims: Claims,
    #[serde(default)]
    active: bool,
}

impl Application {
    /// Introspect a bearer token against the OIDC token introspection endpoint.
    ///
    /// Returns the claims on success (with `raw_token` set to the bearer value).
    /// Returns `None` on network error, non-200 status, parse failure, or
    /// inactive token.
    ///
    /// Go reference: `attemptBearerAuth` in `application/auth_bearer.go`.
    pub(super) async fn attempt_bearer_auth(&self, token: &str) -> Option<Claims> {
        let client_id = self.provider.client_id.as_deref().unwrap_or_default();
        let client_secret = self.provider.client_secret.as_deref().unwrap_or_default();

        let res = self
            .public_http_client
            .post(&self.endpoint.token_introspection)
            .form(&[
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("token", token),
            ])
            .send()
            .await
            .inspect_err(|err| warn!(?err, "failed to send introspection request"))
            .ok()?;

        if res.status() != StatusCode::OK {
            warn!(status = %res.status(), "introspection request returned non-200");
            return None;
        }

        let intro: TokenIntrospectionResponse = res
            .json()
            .await
            .inspect_err(|err| warn!(?err, "failed to parse introspection response"))
            .ok()?;

        if !intro.active {
            warn!("introspected token is not active");
            return None;
        }

        let mut claims = intro.claims;
        claims.raw_token = token.to_owned();
        trace!("successfully introspected bearer token");
        Some(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_bearer_token() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer my-token-123".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), Some("my-token-123"));
    }

    #[test]
    fn bearer_prefix_is_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "bearer lower-case".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), Some("lower-case"));

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "BEARER UPPER-CASE".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), Some("UPPER-CASE"));
    }

    #[test]
    fn returns_none_for_missing_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn returns_none_for_non_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Basic dXNlcjpwYXNz".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn returns_none_for_empty_token() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer ".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn returns_none_for_short_header() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bear".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn introspection_response_deserializes() {
        let json = r#"{
            "active": true,
            "sub": "user-1",
            "email": "user@example.com",
            "preferred_username": "alice",
            "scope": "openid profile email",
            "client_id": "my-client"
        }"#;
        let resp: TokenIntrospectionResponse = serde_json::from_str(json).unwrap();
        assert!(resp.active);
        assert_eq!(resp.claims.sub, "user-1");
        assert_eq!(resp.claims.email, "user@example.com");
        assert_eq!(resp.claims.preferred_username, "alice");
    }

    #[test]
    fn introspection_response_inactive() {
        let json = r#"{"active": false}"#;
        let resp: TokenIntrospectionResponse = serde_json::from_str(json).unwrap();
        assert!(!resp.active);
    }
}
