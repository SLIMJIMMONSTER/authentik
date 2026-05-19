use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
use base64::Engine as _;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::Deserialize;
use tracing::warn;

use super::Application;
use super::types::{Claims, ProxyClaims};

/// Magic username that signals the password should be treated as a bearer token.
///
/// Go reference: `JWTUsername` constant in `application/auth_basic.go`.
const JWT_USERNAME: &str = "goauthentik.io/token";

/// Token endpoint response containing access and ID tokens.
///
/// Go reference: `TokenResponse` in `application/auth_basic.go`.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    id_token: String,
}

/// Extract username and password from an HTTP Basic `Authorization` header.
///
/// Returns `None` if the header is missing, not Basic auth, or malformed.
pub(super) fn extract_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let auth = headers.get(AUTHORIZATION)?.to_str().ok()?;
    const PREFIX: &str = "Basic ";
    if auth.len() < PREFIX.len() || !auth[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let encoded = &auth[PREFIX.len()..];
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_owned(), password.to_owned()))
}

impl Application {
    /// Authenticate via HTTP Basic auth using a client_credentials grant.
    ///
    /// If the username is `goauthentik.io/token`, the password is treated as a
    /// bearer token and delegated to [`attempt_bearer_auth`](Self::attempt_bearer_auth).
    ///
    /// Otherwise, a `client_credentials` POST is sent to the token endpoint.
    /// The returned ID token is verified and its claims extracted.
    ///
    /// Go reference: `attemptBasicAuth` in `application/auth_basic.go`.
    pub(super) async fn attempt_basic_auth(
        &self,
        username: &str,
        password: &str,
    ) -> Option<Claims> {
        // Special case: treat password as bearer token
        if username == JWT_USERNAME {
            return self.attempt_bearer_auth(password).await;
        }

        let client_id = self.provider.client_id.as_deref().unwrap_or_default();
        let scopes = self.provider.scopes_to_request.join(" ");

        let res = self
            .http_client
            .post(&self.endpoint.token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("username", username),
                ("password", password),
                ("scope", &*scopes),
            ])
            .send()
            .await
            .inspect_err(|err| warn!(?err, "failed to send token request"))
            .ok()?;

        if res.status() != StatusCode::OK {
            let body = res.text().await.unwrap_or_default();
            warn!(body, "token request returned non-200");
            return None;
        }

        let token: TokenResponse = res
            .json()
            .await
            .inspect_err(|err| warn!(?err, "failed to parse token response"))
            .ok()?;

        self.verify_id_token(&token.id_token)
    }

    /// Verify an ID token JWT and extract claims.
    ///
    /// Uses HS256 with the client secret when the provider advertises HS256
    /// support, otherwise falls back to RS256 (TODO: JWKS not yet implemented).
    ///
    /// Validates the issuer and audience (client_id).
    pub(super) fn verify_id_token(&self, id_token: &str) -> Option<Claims> {
        let client_id = self.provider.client_id.as_deref().unwrap_or_default();
        let client_secret = self.provider.client_secret.as_deref().unwrap_or_default();

        let algs = &self
            .provider
            .oidc_configuration
            .id_token_signing_alg_values_supported;
        let uses_hs256 = algs.iter().any(|a| a == "HS256");

        if !uses_hs256 {
            // TODO: implement JWKS-based RS256 verification
            warn!("RS256/JWKS verification not yet implemented, only HS256 is supported");
            return None;
        }

        let key = DecodingKey::from_secret(client_secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[client_id]);
        validation.set_issuer(&[&self.endpoint.issuer]);

        let token_data = decode::<Claims>(id_token, &key, &validation)
            .inspect_err(|err| warn!(?err, "failed to verify ID token"))
            .ok()?;

        let mut claims = token_data.claims;
        if claims.ak_proxy.is_none() {
            claims.ak_proxy = Some(ProxyClaims::default());
        }
        claims.raw_token = id_token.to_owned();
        Some(claims)
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{EncodingKey, Header};

    use super::*;

    // -- extract_basic_auth tests --

    #[test]
    fn extracts_valid_basic_auth() {
        let mut headers = HeaderMap::new();
        // "alice:secret123" base64 → "YWxpY2U6c2VjcmV0MTIz"
        headers.insert(AUTHORIZATION, "Basic YWxpY2U6c2VjcmV0MTIz".parse().unwrap());

        let (user, pass) = extract_basic_auth(&headers).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(pass, "secret123");
    }

    #[test]
    fn basic_prefix_is_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "basic YWxpY2U6c2VjcmV0MTIz".parse().unwrap());
        assert!(extract_basic_auth(&headers).is_some());
    }

    #[test]
    fn returns_none_for_missing_header() {
        let headers = HeaderMap::new();
        assert!(extract_basic_auth(&headers).is_none());
    }

    #[test]
    fn returns_none_for_bearer_header() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer token".parse().unwrap());
        assert!(extract_basic_auth(&headers).is_none());
    }

    #[test]
    fn returns_none_for_invalid_base64() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Basic !!!not-base64!!!".parse().unwrap());
        assert!(extract_basic_auth(&headers).is_none());
    }

    #[test]
    fn returns_none_for_missing_colon() {
        let mut headers = HeaderMap::new();
        // "nocolon" base64 → "bm9jb2xvbg=="
        headers.insert(AUTHORIZATION, "Basic bm9jb2xvbg==".parse().unwrap());
        assert!(extract_basic_auth(&headers).is_none());
    }

    #[test]
    fn handles_password_with_colons() {
        let mut headers = HeaderMap::new();
        // "user:pass:word" base64 → "dXNlcjpwYXNzOndvcmQ="
        headers.insert(AUTHORIZATION, "Basic dXNlcjpwYXNzOndvcmQ=".parse().unwrap());

        let (user, pass) = extract_basic_auth(&headers).unwrap();
        assert_eq!(user, "user");
        assert_eq!(pass, "pass:word");
    }

    // -- verify_id_token tests --

    fn init_crypto() {
        let _ = jsonwebtoken::crypto::CryptoProvider::install_default(
            &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER,
        );
    }

    /// Create a signed HS256 JWT with the given claims, secret, issuer, and audience.
    fn make_hs256_token(claims: &Claims, secret: &str, issuer: &str, audience: &str) -> String {
        use serde_json::json;

        let payload = json!({
            "sub": claims.sub,
            "exp": claims.exp,
            "email": claims.email,
            "preferred_username": claims.preferred_username,
            "iss": issuer,
            "aud": audience,
        });

        jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &payload,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    fn test_app_for_verification(secret: &str, issuer: &str, client_id: &str) -> Application {
        use crate::outpost::proxy::application::auth::AuthHeaderCache;
        use crate::outpost::proxy::application::endpoint::OIDCEndpoint;
        use crate::outpost::proxy::application::session::{CookieOptions, SameSite};
        use crate::outpost::proxy::application::session_filesystem::FilesystemStore;

        let dir = std::env::temp_dir();

        let mut provider = ak_client::models::ProxyOutpostConfig::new(
            1,
            "test".to_owned(),
            "https://test.example.com".to_owned(),
            ak_client::models::OpenIdConnectConfiguration::new(
                issuer.to_owned(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                Vec::new(),
                vec!["HS256".to_owned()],
                Vec::new(),
                Vec::new(),
            ),
            None,
            Vec::new(),
            "test-app".to_owned(),
            "Test App".to_owned(),
        );
        provider.client_id = Some(client_id.to_owned());
        provider.client_secret = Some(secret.to_owned());

        Application {
            host: "test.example.com".to_owned(),
            provider,
            router: axum::Router::new(),
            cert: None,
            endpoint: OIDCEndpoint {
                authorization_url: String::new(),
                token_url: String::new(),
                token_introspection: String::new(),
                end_session: String::new(),
                jwks_uri: String::new(),
                issuer: issuer.to_owned(),
            },
            redirect_uri: String::new(),
            session_name: "authentik_proxy_test".to_owned(),
            outpost_name: "test-outpost".to_owned(),
            unauthenticated_regex: Vec::new(),
            http_client: reqwest_middleware::ClientWithMiddleware::default(),
            session_store: FilesystemStore::new(dir, 3600).unwrap(),
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

    #[test]
    fn verify_valid_hs256_token() {
        init_crypto();

        let secret = "my-client-secret";
        let issuer = "https://auth.example.com/application/o/test/";
        let client_id = "my-client-id";

        let claims = Claims {
            sub: "user-1".to_owned(),
            exp: jsonwebtoken::get_current_timestamp() as i64 + 3600,
            email: "user@example.com".to_owned(),
            preferred_username: "alice".to_owned(),
            ..Default::default()
        };

        let token = make_hs256_token(&claims, secret, issuer, client_id);
        let app = test_app_for_verification(secret, issuer, client_id);

        let result = app.verify_id_token(&token).unwrap();
        assert_eq!(result.sub, "user-1");
        assert_eq!(result.email, "user@example.com");
        assert_eq!(result.raw_token, token);
        assert!(result.ak_proxy.is_some());
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        init_crypto();

        let issuer = "https://auth.example.com/application/o/test/";
        let client_id = "my-client-id";

        let claims = Claims {
            sub: "user-1".to_owned(),
            exp: jsonwebtoken::get_current_timestamp() as i64 + 3600,
            ..Default::default()
        };

        let token = make_hs256_token(&claims, "wrong-secret", issuer, client_id);
        let app = test_app_for_verification("correct-secret", issuer, client_id);

        assert!(app.verify_id_token(&token).is_none());
    }

    #[test]
    fn verify_rejects_wrong_issuer() {
        init_crypto();

        let secret = "my-secret";
        let client_id = "my-client-id";

        let claims = Claims {
            sub: "user-1".to_owned(),
            exp: jsonwebtoken::get_current_timestamp() as i64 + 3600,
            ..Default::default()
        };

        let token = make_hs256_token(&claims, secret, "https://wrong-issuer.com/", client_id);
        let app = test_app_for_verification(secret, "https://correct-issuer.com/", client_id);

        assert!(app.verify_id_token(&token).is_none());
    }

    #[test]
    fn verify_rejects_expired_token() {
        init_crypto();

        let secret = "my-secret";
        let issuer = "https://auth.example.com/";
        let client_id = "my-client-id";

        let claims = Claims {
            sub: "user-1".to_owned(),
            exp: 1000, // long expired
            ..Default::default()
        };

        let token = make_hs256_token(&claims, secret, issuer, client_id);
        let app = test_app_for_verification(secret, issuer, client_id);

        assert!(app.verify_id_token(&token).is_none());
    }
}
