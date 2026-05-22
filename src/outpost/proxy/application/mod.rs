use std::sync::Arc;

use ak_client::models::{ProxyMode, ProxyOutpostConfig};
use ak_common::tls::store::Certificate;
use axum::{Router, routing::any};
use eyre::{Result, eyre};
use regex::Regex;
use tracing::{instrument, warn};
use url::Url;

use crate::outpost::proxy::ProxyOutpost;

use self::auth::AuthHeaderCache;
use self::endpoint::{OIDCEndpoint, get_oidc_endpoint};
use self::session::{CookieOptions, SameSite};
use self::session_filesystem::FilesystemStore;

pub(super) mod auth;
pub(super) mod auth_basic;
pub(super) mod auth_bearer;
pub(crate) mod endpoint;
pub(super) mod error;
pub(super) mod handlers;
pub(super) mod headers;
pub(super) mod misconfiguration;
pub(super) mod oauth;
pub(crate) mod oauth_state;
pub(crate) mod session;
pub(crate) mod session_filesystem;
pub(crate) mod types;

#[derive(Debug)]
pub(super) struct Application {
    pub(super) host: String,
    pub(super) provider: ProxyOutpostConfig,
    pub(super) router: Router<Arc<Self>>,
    pub(super) cert: Option<Arc<Certificate>>,

    /// Resolved OIDC endpoints (with host overrides applied).
    pub(super) endpoint: OIDCEndpoint,
    /// OAuth2 redirect URI (`<external_host>/outpost.goauthentik.io/callback?X-authentik-auth-callback=true`).
    pub(super) redirect_uri: String,
    /// Session cookie name: `authentik_proxy_<first 8 hex chars of SHA256(client_id)>`.
    pub(super) session_name: String,
    /// Display name of the outpost (for headers / metrics).
    pub(super) outpost_name: String,
    /// Compiled regexes from `skip_path_regex`; paths matching any of these
    /// bypass authentication.
    pub(super) unauthenticated_regex: Vec<Regex>,

    /// HTTP client for backchannel requests (token introspection, token exchange).
    /// Reused from the outpost controller's API configuration.
    pub(super) http_client: reqwest_middleware::ClientWithMiddleware,
    /// Full API configuration for calling the authentik API (e.g. event creation).
    pub(super) api_config: ak_client::apis::configuration::Configuration,
    /// HTTP client for upstream proxy requests.
    /// Separate from `http_client` so it doesn't carry API middleware and can
    /// have its own TLS validation settings (`internal_host_ssl_validation`).
    pub(super) upstream_client: reqwest::Client,
    /// Server-side session store.
    pub(super) session_store: FilesystemStore,
    /// Cookie options for the session cookie.
    pub(super) cookie_options: CookieOptions,
    /// In-memory TTL cache for Authorization header → Claims.
    pub(super) auth_header_cache: AuthHeaderCache,
}

impl Application {
    #[instrument(skip_all)]
    pub(super) async fn new(outpost: &ProxyOutpost, provider: ProxyOutpostConfig) -> Result<Self> {
        let external_url = Url::parse(&provider.external_host)?;
        if !external_url.has_authority() {
            return Err(eyre!("no host in external host"));
        }
        let external_host = external_url.authority();

        let _old_app = outpost.apps.load().get(external_host);

        let cert = if let Some(Some(kp_uuid)) = provider.certificate {
            Some(
                outpost
                    .certificate_store
                    .ensure_keypair(&outpost.controller.api_config, kp_uuid)
                    .await?,
            )
        } else {
            None
        };

        // OIDC endpoint resolution
        let outpost_model = outpost.controller.outpost.load();
        let authentik_host = outpost_model
            .config
            .get("authentik_host")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let host_browser = std::env::var("AUTHENTIK_HOST_BROWSER").unwrap_or_default();
        let endpoint = get_oidc_endpoint(
            &provider,
            authentik_host,
            outpost.controller.is_embedded(),
            &host_browser,
        );

        // Redirect URI: <external_host>/outpost.goauthentik.io/callback?X-authentik-auth-callback=true
        let mut redirect_url = external_url.clone();
        redirect_url.set_path(
            &format!(
                "{}/outpost.goauthentik.io/callback",
                redirect_url.path().trim_end_matches('/')
            ),
        );
        redirect_url.set_query(Some("X-authentik-auth-callback=true"));
        let redirect_uri = redirect_url.to_string();

        // Session cookie name: authentik_proxy_<SHA256(client_id)[:8]>
        let client_id = provider.client_id.as_deref().unwrap_or_default();
        let session_name = {
            let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, client_id.as_bytes());
            let hex: String = digest.as_ref().iter().fold(
                String::with_capacity(64),
                |mut s, b| {
                    use std::fmt::Write as _;
                    let _ = write!(s, "{b:02x}");
                    s
                },
            );
            format!("authentik_proxy_{}", &hex[..8])
        };

        let outpost_name = outpost_model.name.clone();

        // Compile skip_path_regex
        let unauthenticated_regex = compile_skip_path_regex(provider.skip_path_regex.as_deref());

        // Session store and cookie options.
        // Go reference: getStore() in session.go
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "access_token_validity is always a small positive integer"
        )]
        let max_age = provider
            .access_token_validity
            .map(|v| v as i64 + 1)
            .unwrap_or(0);
        let session_store = FilesystemStore::new(std::env::temp_dir(), max_age)?;
        let external_secure = external_url.scheme() == "https";
        let cookie_options = CookieOptions {
            name: session_name.clone(),
            domain: provider.cookie_domain.clone().unwrap_or_default(),
            path: "/".to_owned(),
            secure: external_secure,
            http_only: true,
            same_site: SameSite::Lax,
            max_age,
        };

        // Upstream HTTP client for proxy mode.
        // Go reference: getUpstreamTransport() in mode_proxy.go
        let ssl_validate = provider.internal_host_ssl_validation.unwrap_or(true);
        let upstream_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(!ssl_validate)
            .build()?;

        let router = Router::new()
            .route(
                "/outpost.goauthentik.io/start",
                any(handlers::handle_auth_start),
            )
            .route(
                "/outpost.goauthentik.io/callback",
                any(handlers::handle_auth_callback),
            )
            .route(
                "/outpost.goauthentik.io/sign_out",
                any(handlers::handle_sign_out),
            );

        let router = match provider.mode {
            Some(ProxyMode::ForwardSingle | ProxyMode::ForwardDomain) => router
                .route(
                    "/outpost.goauthentik.io/auth/caddy",
                    any(handlers::forward::handle_caddy),
                )
                .route(
                    "/outpost.goauthentik.io/auth/envoy",
                    any(handlers::forward::handle_envoy),
                )
                .route(
                    "/outpost.goauthentik.io/auth/nginx",
                    any(handlers::forward::handle_nginx),
                )
                .route(
                    "/outpost.goauthentik.io/auth/traefik",
                    any(handlers::forward::handle_traefik),
                ),
            Some(ProxyMode::Proxy) => router.fallback(handlers::proxy::handle),
            None => return Err(eyre!("no provider mode set")),
        };

        Ok(Self {
            host: external_host.to_owned(),
            provider,
            router,
            cert,
            endpoint,
            redirect_uri,
            session_name,
            outpost_name,
            unauthenticated_regex,
            http_client: outpost.controller.api_config.client.clone(),
            api_config: outpost.controller.api_config.clone(),
            upstream_client,
            session_store,
            cookie_options,
            auth_header_cache: AuthHeaderCache::new(),
        })
    }

    /// Check whether the given URL is on the unauthenticated allowlist.
    ///
    /// For proxy / forward_single modes, only the path is tested.
    /// For forward_domain, the full URL string is tested.
    pub(super) fn is_allowlisted(&self, url: &Url) -> bool {
        let test_string = match self.provider.mode {
            Some(ProxyMode::Proxy | ProxyMode::ForwardSingle) => url.path().to_owned(),
            _ => url.to_string(),
        };
        self.unauthenticated_regex
            .iter()
            .any(|re| re.is_match(&test_string))
    }
}

fn compile_skip_path_regex(skip_path_regex: Option<&str>) -> Vec<Regex> {
    let Some(raw) = skip_path_regex else {
        return Vec::new();
    };
    if raw.is_empty() {
        return Vec::new();
    }
    raw.lines()
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            Regex::new(line)
                .inspect_err(|err| warn!(?err, regex = line, "failed to compile skip_path_regex"))
                .ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_name_derivation() {
        // Verify the session name matches the Go implementation's logic:
        // SHA256("test-client-id") = hex, take first 8 chars, prefix with "authentik_proxy_"
        let client_id = "test-client-id";
        let digest =
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, client_id.as_bytes());
        let hex: String = digest.as_ref().iter().fold(
            String::with_capacity(64),
            |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            },
        );
        let name = format!("authentik_proxy_{}", &hex[..8]);
        assert!(name.starts_with("authentik_proxy_"));
        assert_eq!(name.len(), "authentik_proxy_".len() + 8);
    }

    #[test]
    fn compile_skip_path_regex_empty() {
        assert!(compile_skip_path_regex(None).is_empty());
        assert!(compile_skip_path_regex(Some("")).is_empty());
    }

    #[test]
    fn compile_skip_path_regex_valid() {
        let regexes = compile_skip_path_regex(Some("/health\n/ready\n"));
        assert_eq!(regexes.len(), 2);
        assert!(regexes[0].is_match("/health"));
        assert!(regexes[1].is_match("/ready"));
    }

    #[test]
    fn compile_skip_path_regex_skips_invalid() {
        let regexes = compile_skip_path_regex(Some("/valid\n[invalid\n/also-valid"));
        assert_eq!(regexes.len(), 2);
    }
}
