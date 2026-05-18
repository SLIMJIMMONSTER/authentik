use eyre::Result;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use tracing::warn;

/// JWT payload for the OAuth2 state parameter.
///
/// Signed with HS256 using the provider's `cookie_secret`. Carries the
/// original redirect URL, a CSRF token, and the session ID so that the
/// callback handler can verify continuity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OAuthState {
    /// `goauthentik.io/outpost/<client_id>`
    pub(crate) iss: String,
    /// Session ID — must match the session on callback.
    pub(crate) sid: String,
    /// Random CSRF token.
    pub(crate) state: String,
    /// URL to redirect to after successful authentication.
    pub(crate) redirect: String,
}

impl OAuthState {
    /// Create a new state and sign it as a JWT.
    ///
    /// `session_id` is the current session's ID (created if it didn't exist
    /// yet by the caller). `redirect` is the URL the user was trying to
    /// reach. `client_id` and `cookie_secret` come from the provider config.
    pub(crate) fn create(
        session_id: &str,
        redirect: &str,
        client_id: &str,
        cookie_secret: &str,
    ) -> Result<String> {
        let random_bytes: [u8; 32] = rand::rng().random();
        let state_value = random_bytes
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            });

        let claims = OAuthState {
            iss: format!("goauthentik.io/outpost/{client_id}"),
            sid: session_id.to_owned(),
            state: state_value,
            redirect: redirect.to_owned(),
        };

        let key = EncodingKey::from_secret(cookie_secret.as_bytes());
        let token = encode(&Header::new(Algorithm::HS256), &claims, &key)?;
        Ok(token)
    }

    /// Parse and validate the state JWT from a callback request's `?state=`
    /// query parameter.
    ///
    /// Returns `None` (with a warning log) if:
    /// - the JWT cannot be parsed or the signature is invalid
    /// - the issuer doesn't match the expected `goauthentik.io/outpost/<client_id>`
    /// - the session ID doesn't match the current session
    pub(crate) fn from_request(
        state_jwt: &str,
        session_id: &str,
        client_id: &str,
        cookie_secret: &str,
    ) -> Option<Self> {
        let key = DecodingKey::from_secret(cookie_secret.as_bytes());

        let mut validation = Validation::new(Algorithm::HS256);
        // The Go implementation doesn't validate exp/iat/nbf on the state JWT.
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.set_issuer(&[format!("goauthentik.io/outpost/{client_id}")]);

        let token_data = match decode::<OAuthState>(state_jwt, &key, &validation) {
            Ok(data) => data,
            Err(err) => {
                warn!(?err, "failed to parse state JWT");
                return None;
            }
        };

        let claims = token_data.claims;

        if claims.sid != session_id {
            warn!(
                got = claims.sid,
                expected = session_id,
                "mismatched session ID in state JWT"
            );
            return None;
        }

        Some(claims)
    }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::crypto::CryptoProvider;

    use super::*;

    const CLIENT_ID: &str = "test-client-id";
    const COOKIE_SECRET: &str = "super-secret-cookie-key";
    const SESSION_ID: &str = "test-session-123";
    const REDIRECT: &str = "https://app.example.com/dashboard";

    fn init_crypto() {
        let _ = CryptoProvider::install_default(&jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER);
    }

    #[test]
    fn roundtrip() {
        init_crypto();
        let token =
            OAuthState::create(SESSION_ID, REDIRECT, CLIENT_ID, COOKIE_SECRET).unwrap();

        let state =
            OAuthState::from_request(&token, SESSION_ID, CLIENT_ID, COOKIE_SECRET).unwrap();

        assert_eq!(state.iss, format!("goauthentik.io/outpost/{CLIENT_ID}"));
        assert_eq!(state.sid, SESSION_ID);
        assert_eq!(state.redirect, REDIRECT);
        assert!(!state.state.is_empty());
    }

    #[test]
    fn rejects_wrong_secret() {
        init_crypto();
        let token =
            OAuthState::create(SESSION_ID, REDIRECT, CLIENT_ID, COOKIE_SECRET).unwrap();

        let result =
            OAuthState::from_request(&token, SESSION_ID, CLIENT_ID, "wrong-secret");

        assert!(result.is_none());
    }

    #[test]
    fn rejects_wrong_client_id() {
        init_crypto();
        let token =
            OAuthState::create(SESSION_ID, REDIRECT, CLIENT_ID, COOKIE_SECRET).unwrap();

        let result =
            OAuthState::from_request(&token, SESSION_ID, "other-client", COOKIE_SECRET);

        assert!(result.is_none());
    }

    #[test]
    fn rejects_wrong_session_id() {
        init_crypto();
        let token =
            OAuthState::create(SESSION_ID, REDIRECT, CLIENT_ID, COOKIE_SECRET).unwrap();

        let result =
            OAuthState::from_request(&token, "wrong-session", CLIENT_ID, COOKIE_SECRET);

        assert!(result.is_none());
    }

    #[test]
    fn unique_state_per_call() {
        init_crypto();
        let token1 =
            OAuthState::create(SESSION_ID, REDIRECT, CLIENT_ID, COOKIE_SECRET).unwrap();
        let token2 =
            OAuthState::create(SESSION_ID, REDIRECT, CLIENT_ID, COOKIE_SECRET).unwrap();

        let s1 =
            OAuthState::from_request(&token1, SESSION_ID, CLIENT_ID, COOKIE_SECRET).unwrap();
        let s2 =
            OAuthState::from_request(&token2, SESSION_ID, CLIENT_ID, COOKIE_SECRET).unwrap();

        assert_ne!(s1.state, s2.state, "each state token should have a unique CSRF value");
    }
}
