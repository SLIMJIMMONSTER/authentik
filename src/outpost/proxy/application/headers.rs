use axum::http::HeaderMap;
use base64::Engine as _;
use tracing::trace;

use super::Application;
use super::types::Claims;

impl Application {
    /// Build the map of `X-authentik-*` headers and any additional headers
    /// derived from the claims.
    ///
    /// Go reference: `getHeaders` in `application/mode_common.go`.
    pub(super) fn get_headers(&self, claims: &Claims) -> Vec<(String, String)> {
        let mut headers = Vec::with_capacity(16);

        // User info headers
        headers.push(("X-authentik-username".to_owned(), claims.preferred_username.clone()));
        headers.push(("X-authentik-groups".to_owned(), claims.groups.join("|")));
        headers.push(("X-authentik-entitlements".to_owned(), claims.entitlements.join("|")));
        headers.push(("X-authentik-email".to_owned(), claims.email.clone()));
        headers.push(("X-authentik-name".to_owned(), claims.name.clone()));
        headers.push(("X-authentik-uid".to_owned(), claims.sub.clone()));
        headers.push(("X-authentik-jwt".to_owned(), claims.raw_token.clone()));

        // System / meta headers
        headers.push(("X-authentik-meta-jwks".to_owned(), self.endpoint.jwks_uri.clone()));
        headers.push(("X-authentik-meta-outpost".to_owned(), self.outpost_name.clone()));
        headers.push(("X-authentik-meta-provider".to_owned(), self.provider.name.clone()));
        headers.push((
            "X-authentik-meta-app".to_owned(),
            self.provider.assigned_application_slug.clone(),
        ));
        headers.push((
            "X-authentik-meta-version".to_owned(),
            format!("goauthentik.io/outpost/{}", ak_common::VERSION),
        ));

        let Some(ref proxy_claims) = claims.ak_proxy else {
            return headers;
        };

        // Basic auth injection
        if let Some(authz) = self.build_authorization_header(claims) {
            headers.push(("Authorization".to_owned(), authz));
        }

        // Additional headers from user attributes
        if let Some(additional) = proxy_claims.user_attributes.get("additionalHeaders") {
            if let Some(map) = additional.as_object() {
                trace!(?map, "setting additional headers");
                for (key, value) in map {
                    let val = match value {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        _ => continue,
                    };
                    headers.push((key.clone(), val));
                }
            }
        }

        headers
    }

    /// Set all `X-authentik-*` headers on the given header map, then remove
    /// headers that have an underscore duplicate (same name with underscores
    /// replaced by hyphens).
    ///
    /// Go reference: `addHeaders` in `application/mode_common.go`.
    pub(super) fn add_headers(&self, header_map: &mut HeaderMap, claims: &Claims) {
        let new_headers = self.get_headers(claims);
        for (key, val) in &new_headers {
            if let (Ok(name), Ok(value)) = (
                axum::http::HeaderName::try_from(key.as_str()),
                axum::http::HeaderValue::try_from(val.as_str()),
            ) {
                header_map.insert(name, value);
            }
        }
        remove_duplicate_underscore_headers(header_map);
    }

    /// Attempt to build a Basic `Authorization` header from user attributes.
    ///
    /// Returns `None` if basic auth is disabled, or no password attribute is set.
    ///
    /// Go reference: `setAuthorizationHeader` in `application/mode_common.go`.
    fn build_authorization_header(&self, claims: &Claims) -> Option<String> {
        if !self.provider.basic_auth_enabled.unwrap_or(false) {
            return None;
        }

        let proxy = claims.ak_proxy.as_ref()?;
        let attrs = &proxy.user_attributes;

        let password_attr = self
            .provider
            .basic_auth_password_attribute
            .as_deref()
            .unwrap_or_default();
        let password = attrs
            .get(password_attr)
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        if password.is_empty() {
            return None;
        }

        let user_attr = self
            .provider
            .basic_auth_user_attribute
            .as_deref()
            .unwrap_or_default();
        let username = attrs
            .get(user_attr)
            .and_then(|v| v.as_str())
            .unwrap_or(&claims.email);

        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        trace!(username, "setting http basic auth");
        Some(format!("Basic {encoded}"))
    }
}

/// For every header, compute the hyphenated equivalent (underscores → hyphens).
/// If that hyphenated key does NOT exist in the map, delete the original.
///
/// This effectively removes underscore-based headers that don't have a
/// matching hyphenated counterpart, preventing header spoofing via
/// underscore variants.
///
/// Go reference: `removeDuplicateUnderscoreHeader` in `application/mode_common.go`.
fn remove_duplicate_underscore_headers(headers: &mut HeaderMap) {
    let keys_to_remove: Vec<_> = headers
        .keys()
        .filter(|k| {
            let hyphenated = k.as_str().replace('_', "-");
            // If the hyphenated form is different and doesn't exist, remove
            hyphenated != k.as_str() && !headers.contains_key(&*hyphenated)
        })
        .cloned()
        .collect();

    for key in keys_to_remove {
        headers.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outpost::proxy::application::auth::AuthHeaderCache;
    use crate::outpost::proxy::application::endpoint::OIDCEndpoint;
    use crate::outpost::proxy::application::session::{AnySessionStore, CookieOptions, SameSite};
    use crate::outpost::proxy::application::session_filesystem::FilesystemStore;
    use crate::outpost::proxy::application::types::ProxyClaims;

    fn test_app(store_dir: &std::path::Path) -> Application {
        let mut provider = ak_client::models::ProxyOutpostConfig::new(
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
        provider.client_id = Some("my-client-id".to_owned());
        provider.basic_auth_enabled = Some(false);

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
                jwks_uri: "https://auth.example.com/jwks".to_owned(),
                issuer: String::new(),
            },
            redirect_uri: String::new(),
            session_name: "authentik_proxy_test".to_owned(),
            outpost_name: "my-outpost".to_owned(),
            unauthenticated_regex: Vec::new(),
            http_client: reqwest_middleware::ClientWithMiddleware::default(),
            public_http_client: reqwest_middleware::ClientWithMiddleware::default(),
            api_config: ak_client::apis::configuration::Configuration::default(),
            session_store: AnySessionStore::Filesystem(FilesystemStore::new(store_dir.to_owned(), 3600).unwrap()),
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

    fn sample_claims() -> Claims {
        Claims {
            sub: "user-123".to_owned(),
            email: "alice@example.com".to_owned(),
            name: "Alice".to_owned(),
            preferred_username: "alice".to_owned(),
            groups: vec!["admins".to_owned(), "users".to_owned()],
            entitlements: vec!["read".to_owned(), "write".to_owned()],
            raw_token: "jwt-token-here".to_owned(),
            ak_proxy: Some(ProxyClaims::default()),
            ..Default::default()
        }
    }

    #[test]
    fn get_headers_includes_user_info() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());
        let claims = sample_claims();

        let headers = app.get_headers(&claims);
        let find = |k: &str| headers.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str());

        assert_eq!(find("X-authentik-username"), Some("alice"));
        assert_eq!(find("X-authentik-uid"), Some("user-123"));
        assert_eq!(find("X-authentik-name"), Some("Alice"));
        assert_eq!(find("X-authentik-email"), Some("alice@example.com"));
        assert_eq!(find("X-authentik-groups"), Some("admins|users"));
        assert_eq!(find("X-authentik-entitlements"), Some("read|write"));
        assert_eq!(find("X-authentik-jwt"), Some("jwt-token-here"));
    }

    #[test]
    fn get_headers_includes_meta() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());
        let claims = sample_claims();

        let headers = app.get_headers(&claims);
        let find = |k: &str| headers.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str());

        assert_eq!(find("X-authentik-meta-jwks"), Some("https://auth.example.com/jwks"));
        assert_eq!(find("X-authentik-meta-outpost"), Some("my-outpost"));
        assert_eq!(find("X-authentik-meta-provider"), Some("my-provider"));
        assert_eq!(find("X-authentik-meta-app"), Some("test-app"));
        assert!(find("X-authentik-meta-version").unwrap().starts_with("goauthentik.io/outpost/"));
    }

    #[test]
    fn get_headers_no_authorization_when_basic_auth_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());
        let claims = sample_claims();

        let headers = app.get_headers(&claims);
        let has_auth = headers.iter().any(|(k, _)| k == "Authorization");
        assert!(!has_auth);
    }

    #[test]
    fn get_headers_sets_authorization_when_basic_auth_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path());
        app.provider.basic_auth_enabled = Some(true);
        app.provider.basic_auth_password_attribute = Some("pw".to_owned());
        app.provider.basic_auth_user_attribute = Some("user".to_owned());

        let mut claims = sample_claims();
        let proxy = claims.ak_proxy.as_mut().unwrap();
        proxy
            .user_attributes
            .insert("pw".to_owned(), serde_json::json!("secret"));
        proxy
            .user_attributes
            .insert("user".to_owned(), serde_json::json!("bob"));

        let headers = app.get_headers(&claims);
        let authz = headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .map(|(_, v)| v.as_str());

        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("bob:secret")
        );
        assert_eq!(authz, Some(expected.as_str()));
    }

    #[test]
    fn get_headers_falls_back_to_email_for_username() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path());
        app.provider.basic_auth_enabled = Some(true);
        app.provider.basic_auth_password_attribute = Some("pw".to_owned());
        // No user attribute set or no value in claims → falls back to email
        app.provider.basic_auth_user_attribute = Some("nonexistent".to_owned());

        let mut claims = sample_claims();
        let proxy = claims.ak_proxy.as_mut().unwrap();
        proxy
            .user_attributes
            .insert("pw".to_owned(), serde_json::json!("pass123"));

        let headers = app.get_headers(&claims);
        let authz = headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .map(|(_, v)| v.as_str())
            .unwrap();

        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("alice@example.com:pass123")
        );
        assert_eq!(authz, expected);
    }

    #[test]
    fn get_headers_no_authorization_when_password_empty() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = test_app(dir.path());
        app.provider.basic_auth_enabled = Some(true);
        app.provider.basic_auth_password_attribute = Some("pw".to_owned());

        // No pw attribute in claims
        let claims = sample_claims();
        let headers = app.get_headers(&claims);
        let has_auth = headers.iter().any(|(k, _)| k == "Authorization");
        assert!(!has_auth);
    }

    #[test]
    fn get_headers_includes_additional_headers() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());

        let mut claims = sample_claims();
        let proxy = claims.ak_proxy.as_mut().unwrap();
        proxy.user_attributes.insert(
            "additionalHeaders".to_owned(),
            serde_json::json!({
                "X-Custom-Header": "custom-value",
                "X-Numeric": 42
            }),
        );

        let headers = app.get_headers(&claims);
        let find = |k: &str| headers.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str());

        assert_eq!(find("X-Custom-Header"), Some("custom-value"));
        assert_eq!(find("X-Numeric"), Some("42"));
    }

    #[test]
    fn get_headers_without_proxy_claims() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());

        let claims = Claims {
            sub: "user-1".to_owned(),
            ak_proxy: None,
            ..Default::default()
        };

        let headers = app.get_headers(&claims);
        // Should still have user info and meta headers, just no Authorization or additional
        let has_auth = headers.iter().any(|(k, _)| k == "Authorization");
        assert!(!has_auth);
        assert!(headers.iter().any(|(k, _)| k == "X-authentik-uid"));
    }

    #[test]
    fn add_headers_sets_on_header_map() {
        let dir = tempfile::tempdir().unwrap();
        let app = test_app(dir.path());
        let claims = sample_claims();

        let mut header_map = HeaderMap::new();
        app.add_headers(&mut header_map, &claims);

        assert_eq!(
            header_map.get("X-authentik-username").unwrap(),
            "alice"
        );
        assert_eq!(
            header_map.get("X-authentik-uid").unwrap(),
            "user-123"
        );
    }

    #[test]
    fn remove_duplicate_underscore_headers_keeps_when_hyphen_exists() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "1.2.3.4".parse().unwrap());
        headers.insert("X_Forwarded_For", "5.6.7.8".parse().unwrap());
        headers.insert("X-Unique-Header", "keep".parse().unwrap());

        remove_duplicate_underscore_headers(&mut headers);

        // Hyphenated version stays
        assert!(headers.contains_key("X-Forwarded-For"));
        // Underscore kept because hyphen equivalent exists
        assert!(headers.contains_key("X_Forwarded_For"));
        // Unique stays
        assert!(headers.contains_key("X-Unique-Header"));
    }

    #[test]
    fn remove_duplicate_underscore_headers_removes_orphan_underscore() {
        let mut headers = HeaderMap::new();
        // Only underscore variant, no hyphen equivalent
        headers.insert("X_Only_Underscore", "value".parse().unwrap());

        remove_duplicate_underscore_headers(&mut headers);

        // Should be removed since hyphenated form doesn't exist
        assert!(!headers.contains_key("X_Only_Underscore"));
    }
}
