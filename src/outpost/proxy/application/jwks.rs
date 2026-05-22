use std::sync::Arc;

use arc_swap::ArcSwap;
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::JwkSet,
};
use tracing::{debug, warn};

use super::types::{Claims, ProxyClaims};

/// Remote JWKS key set that fetches and caches keys from a JWKS URI.
///
/// Mirrors the behaviour of Go's `oidc.NewRemoteKeySet`: keys are fetched
/// lazily on first use and cached. If a `kid` is not found in the cache,
/// the JWKS is re-fetched once before giving up.
///
/// Go reference: `NewApplication` in `application/application.go` — the
/// `oidc.NewRemoteKeySet(ctx, p.OidcConfiguration.JwksUri)` branch.
#[derive(Debug)]
pub(super) struct RemoteJwksKeySet {
    jwks_uri: String,
    http_client: reqwest_middleware::ClientWithMiddleware,
    cached: ArcSwap<JwkSet>,
}

impl RemoteJwksKeySet {
    pub(super) fn new(
        jwks_uri: String,
        http_client: reqwest_middleware::ClientWithMiddleware,
    ) -> Self {
        Self {
            jwks_uri,
            http_client,
            cached: ArcSwap::from_pointee(JwkSet { keys: Vec::new() }),
        }
    }

    /// Verify an RS256 JWT using keys from the remote JWKS.
    ///
    /// 1. Decode the token header to extract the `kid`.
    /// 2. Look up the key in the cache; if missing, fetch fresh JWKS.
    /// 3. Verify signature and validate issuer + audience.
    pub(super) async fn verify(
        &self,
        token: &str,
        issuer: &str,
        client_id: &str,
    ) -> Option<Claims> {
        let header = decode_header(token)
            .inspect_err(|err| warn!(?err, "failed to decode JWT header"))
            .ok()?;

        let kid = header.kid.as_deref().unwrap_or_default();
        if kid.is_empty() {
            warn!("JWT has no kid, cannot look up JWKS key");
            return None;
        }

        // Try cached keys first.
        if let Some(claims) = self.try_verify(token, kid, issuer, client_id) {
            return Some(claims);
        }

        // Cache miss — fetch fresh JWKS and retry.
        debug!(kid, "key not found in cache, fetching JWKS");
        self.fetch().await;
        self.try_verify(token, kid, issuer, client_id)
    }

    /// Attempt to verify the token with a cached key matching `kid`.
    fn try_verify(
        &self,
        token: &str,
        kid: &str,
        issuer: &str,
        client_id: &str,
    ) -> Option<Claims> {
        let jwks = self.cached.load();
        let jwk = jwks.find(kid)?;

        let key = DecodingKey::from_jwk(jwk)
            .inspect_err(|err| warn!(?err, kid, "failed to build decoding key from JWK"))
            .ok()?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[client_id]);
        validation.set_issuer(&[issuer]);

        let token_data = decode::<Claims>(token, &key, &validation)
            .inspect_err(|err| warn!(?err, "failed to verify RS256 ID token"))
            .ok()?;

        let mut claims = token_data.claims;
        if claims.ak_proxy.is_none() {
            claims.ak_proxy = Some(ProxyClaims::default());
        }
        claims.raw_token = token.to_owned();
        Some(claims)
    }

    /// Fetch the JWKS from the remote URI and update the cache.
    async fn fetch(&self) {
        let resp = match self
            .http_client
            .get(&self.jwks_uri)
            .send()
            .await
        {
            Ok(r) => r,
            Err(err) => {
                warn!(?err, uri = self.jwks_uri, "failed to fetch JWKS");
                return;
            }
        };

        match resp.json::<JwkSet>().await {
            Ok(jwks) => {
                debug!(keys = jwks.keys.len(), "fetched JWKS");
                self.cached.store(Arc::new(jwks));
            }
            Err(err) => {
                warn!(?err, "failed to parse JWKS response");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use jsonwebtoken::{EncodingKey, Header};

    fn init_crypto() {
        let _ = jsonwebtoken::crypto::CryptoProvider::install_default(
            &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER,
        );
    }

    /// Generate an RSA key pair and return (EncodingKey, JwkSet with the public key).
    ///
    /// Extracts RSA n and e from the PKCS#1 DER public key and constructs a
    /// JWK JSON that `jsonwebtoken` can consume.
    fn generate_rsa_keypair(kid: &str) -> (EncodingKey, JwkSet) {
        use aws_lc_rs::encoding::AsDer as _;
        use aws_lc_rs::signature::{KeyPair as _, RsaKeyPair};

        let key_pair =
            RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).expect("RSA key generation");
        let private_pkcs8 = key_pair.as_der().expect("PKCS#8 export");

        // jsonwebtoken's `from_rsa_der` feeds the bytes to
        // `aws_lc_rs::signature::RsaKeyPair::from_der` which expects PKCS#1
        // (RFC 8017) DER, not PKCS#8. Extract the inner PKCS#1 private key.
        let pkcs1_private = extract_pkcs1_from_pkcs8(private_pkcs8.as_ref());
        let encoding_key = EncodingKey::from_rsa_der(&pkcs1_private);

        // The public key (via KeyPair::public_key().as_ref()) is in PKCS#1 DER
        // format (RFC 8017): SEQUENCE { INTEGER n, INTEGER e }.
        let public_der = key_pair.public_key().as_ref();
        let (n_bytes, e_bytes) = parse_pkcs1_rsa_public_key(public_der);

        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let n = b64.encode(n_bytes);
        let e = b64.encode(e_bytes);

        let jwks_json = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "n": n,
                "e": e,
            }]
        });

        let jwk_set: JwkSet = serde_json::from_value(jwks_json).expect("valid JWKS JSON");
        (encoding_key, jwk_set)
    }

    /// Extract the inner PKCS#1 RSAPrivateKey from a PKCS#8 PrivateKeyInfo DER.
    ///
    /// PKCS#8 layout:
    /// ```text
    /// SEQUENCE {
    ///   INTEGER version,
    ///   SEQUENCE { OID algorithm, ... },
    ///   OCTET STRING { <PKCS#1 RSAPrivateKey> }
    /// }
    /// ```
    fn extract_pkcs1_from_pkcs8(pkcs8: &[u8]) -> Vec<u8> {
        // Skip outer SEQUENCE tag + length
        assert_eq!(pkcs8[0], 0x30);
        let (_, rest) = read_der_length(&pkcs8[1..]);

        // Skip INTEGER (version)
        assert_eq!(rest[0], 0x02);
        let (ver_len, after_ver) = read_der_length(&rest[1..]);
        let after_ver = &after_ver[ver_len..];

        // Skip SEQUENCE (algorithmIdentifier)
        assert_eq!(after_ver[0], 0x30);
        let (alg_len, after_alg) = read_der_length(&after_ver[1..]);
        let after_alg = &after_alg[alg_len..];

        // OCTET STRING contains the PKCS#1 RSAPrivateKey
        assert_eq!(after_alg[0], 0x04);
        let (oct_len, oct_data) = read_der_length(&after_alg[1..]);
        oct_data[..oct_len].to_vec()
    }

    /// Parse a PKCS#1 RSAPublicKey DER encoding to extract (n, e) byte slices.
    ///
    /// Format: SEQUENCE { INTEGER n, INTEGER e }
    fn parse_pkcs1_rsa_public_key(der: &[u8]) -> (&[u8], &[u8]) {
        // This is a minimal DER parser for the RSA public key structure.
        // SEQUENCE tag = 0x30
        assert_eq!(der[0], 0x30, "expected SEQUENCE tag");
        let (_, rest) = read_der_length(&der[1..]);

        // First INTEGER: n (modulus)
        assert_eq!(rest[0], 0x02, "expected INTEGER tag for n");
        let (n_len, n_start) = read_der_length(&rest[1..]);
        let n_bytes = &n_start[..n_len];
        let after_n = &n_start[n_len..];

        // Strip leading zero byte if present (DER uses it for positive sign).
        let n_bytes = if n_bytes.first() == Some(&0) && n_bytes.len() > 1 {
            &n_bytes[1..]
        } else {
            n_bytes
        };

        // Second INTEGER: e (exponent)
        assert_eq!(after_n[0], 0x02, "expected INTEGER tag for e");
        let (e_len, e_start) = read_der_length(&after_n[1..]);
        let e_bytes = &e_start[..e_len];

        let e_bytes = if e_bytes.first() == Some(&0) && e_bytes.len() > 1 {
            &e_bytes[1..]
        } else {
            e_bytes
        };

        (n_bytes, e_bytes)
    }

    /// Read a DER length field. Returns (length_value, rest_of_slice_after_length).
    fn read_der_length(data: &[u8]) -> (usize, &[u8]) {
        if data[0] & 0x80 == 0 {
            // Short form: length in a single byte
            (data[0] as usize, &data[1..])
        } else {
            // Long form: first byte's low 7 bits = number of length bytes
            let num_bytes = (data[0] & 0x7f) as usize;
            let mut length = 0_usize;
            for &b in &data[1..1 + num_bytes] {
                length = (length << 8) | b as usize;
            }
            (length, &data[1 + num_bytes..])
        }
    }

    fn make_rs256_token(
        encoding_key: &EncodingKey,
        kid: &str,
        issuer: &str,
        audience: &str,
        sub: &str,
        exp: i64,
    ) -> String {
        let payload = serde_json::json!({
            "sub": sub,
            "exp": exp,
            "email": format!("{sub}@example.com"),
            "iss": issuer,
            "aud": audience,
        });
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_owned());
        jsonwebtoken::encode(&header, &payload, encoding_key).unwrap()
    }

    #[test]
    fn try_verify_with_cached_rs256_key() {
        init_crypto();

        let kid = "test-kid-1";
        let issuer = "https://auth.example.com/";
        let client_id = "my-client";
        let (encoding_key, jwk_set) = generate_rsa_keypair(kid);

        let token = make_rs256_token(
            &encoding_key,
            kid,
            issuer,
            client_id,
            "user-1",
            jsonwebtoken::get_current_timestamp() as i64 + 3600,
        );

        let key_set = RemoteJwksKeySet {
            jwks_uri: String::new(),
            http_client: reqwest_middleware::ClientWithMiddleware::default(),
            cached: ArcSwap::from_pointee(jwk_set),
        };

        let claims = key_set
            .try_verify(&token, kid, issuer, client_id)
            .expect("should verify successfully");
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.email, "user-1@example.com");
        assert!(claims.ak_proxy.is_some());
        assert_eq!(claims.raw_token, token);
    }

    #[test]
    fn try_verify_returns_none_for_wrong_kid() {
        init_crypto();

        let (encoding_key, jwk_set) = generate_rsa_keypair("correct-kid");

        let token = make_rs256_token(
            &encoding_key,
            "wrong-kid",
            "https://auth.example.com/",
            "my-client",
            "user-1",
            jsonwebtoken::get_current_timestamp() as i64 + 3600,
        );

        let key_set = RemoteJwksKeySet {
            jwks_uri: String::new(),
            http_client: reqwest_middleware::ClientWithMiddleware::default(),
            cached: ArcSwap::from_pointee(jwk_set),
        };

        assert!(key_set
            .try_verify(&token, "wrong-kid", "https://auth.example.com/", "my-client")
            .is_none());
    }

    #[test]
    fn try_verify_rejects_wrong_issuer() {
        init_crypto();

        let kid = "kid-1";
        let (encoding_key, jwk_set) = generate_rsa_keypair(kid);

        let token = make_rs256_token(
            &encoding_key,
            kid,
            "https://wrong-issuer.com/",
            "my-client",
            "user-1",
            jsonwebtoken::get_current_timestamp() as i64 + 3600,
        );

        let key_set = RemoteJwksKeySet {
            jwks_uri: String::new(),
            http_client: reqwest_middleware::ClientWithMiddleware::default(),
            cached: ArcSwap::from_pointee(jwk_set),
        };

        assert!(key_set
            .try_verify(&token, kid, "https://correct-issuer.com/", "my-client")
            .is_none());
    }

    #[test]
    fn try_verify_rejects_expired_token() {
        init_crypto();

        let kid = "kid-1";
        let issuer = "https://auth.example.com/";
        let client_id = "my-client";
        let (encoding_key, jwk_set) = generate_rsa_keypair(kid);

        let token = make_rs256_token(&encoding_key, kid, issuer, client_id, "user-1", 1000);

        let key_set = RemoteJwksKeySet {
            jwks_uri: String::new(),
            http_client: reqwest_middleware::ClientWithMiddleware::default(),
            cached: ArcSwap::from_pointee(jwk_set),
        };

        assert!(key_set.try_verify(&token, kid, issuer, client_id).is_none());
    }

    #[test]
    fn try_verify_rejects_token_without_kid() {
        init_crypto();

        let (encoding_key, jwk_set) = generate_rsa_keypair("kid-1");

        // Create token without kid in header.
        let payload = serde_json::json!({
            "sub": "user-1",
            "exp": jsonwebtoken::get_current_timestamp() as i64 + 3600,
            "iss": "https://auth.example.com/",
            "aud": "my-client",
        });
        let header = Header::new(Algorithm::RS256); // no kid
        let token = jsonwebtoken::encode(&header, &payload, &encoding_key).unwrap();

        let key_set = RemoteJwksKeySet {
            jwks_uri: String::new(),
            http_client: reqwest_middleware::ClientWithMiddleware::default(),
            cached: ArcSwap::from_pointee(jwk_set),
        };

        // verify() checks for kid, should return None.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(rt.block_on(key_set.verify(&token, "https://auth.example.com/", "my-client")).is_none());
    }
}
