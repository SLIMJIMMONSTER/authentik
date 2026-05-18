use tracing::warn;
use url::Url;

use ak_client::models::ProxyOutpostConfig;

/// Resolved OIDC endpoints for an application, with host overrides applied
/// for embedded outposts or when `AUTHENTIK_HOST_BROWSER` is set.
#[derive(Debug, Clone)]
pub(crate) struct OIDCEndpoint {
    pub(crate) authorization_url: String,
    pub(crate) token_url: String,
    pub(crate) token_introspection: String,
    pub(crate) end_session: String,
    pub(crate) jwks_uri: String,
    pub(crate) issuer: String,
}

/// Replace the scheme and host of `raw_url`, preserving the path and query.
/// Returns the original string on parse failure.
fn update_url(raw_url: &str, scheme: &str, host: &str) -> String {
    let Ok(mut u) = Url::parse(raw_url) else {
        return raw_url.to_owned();
    };
    let _ = u.set_scheme(scheme);
    let _ = u.set_host(Some(host));
    u.to_string()
}

/// Build the [`OIDCEndpoint`] for a provider, applying host overrides for
/// embedded outposts and the `AUTHENTIK_HOST_BROWSER` environment variable.
///
/// - **Embedded outpost**: browser-facing URLs (authorize, end-session, issuer,
///   JWKS) are rewritten to `authentik_host`. Backchannel URLs (token,
///   introspection) keep the API-provided host.
/// - **Standalone with `AUTHENTIK_HOST_BROWSER`**: browser-facing URLs use that
///   host; issuer also uses it. Backchannel URLs are unchanged.
/// - **Standalone without override**: all URLs are used as-is from the API.
// TODO: rework that logic for embedded/non-embedded
pub(crate) fn get_oidc_endpoint(
    provider: &ProxyOutpostConfig,
    authentik_host: &str,
    embedded: bool,
    host_browser: &str,
) -> OIDCEndpoint {
    let oidc = &provider.oidc_configuration;
    let mut ep = OIDCEndpoint {
        authorization_url: oidc.authorization_endpoint.clone(),
        token_url: oidc.token_endpoint.clone(),
        token_introspection: oidc.introspection_endpoint.clone(),
        end_session: oidc.end_session_endpoint.clone(),
        jwks_uri: oidc.jwks_uri.clone(),
        issuer: oidc.issuer.clone(),
    };

    let Ok(ak_url) = Url::parse(authentik_host) else {
        return ep;
    };

    if !embedded && host_browser.is_empty() {
        return ep;
    }

    let browser_url = if embedded {
        if authentik_host.is_empty() {
            warn!("outpost has localhost/blank API connection but no authentik_host is configured");
            return ep;
        }
        ak_url
    } else {
        // host_browser is non-empty (checked above)
        let Ok(u) = Url::parse(host_browser) else {
            return ep;
        };
        u
    };

    let browser_scheme = browser_url.scheme();
    let browser_host = browser_url.host_str().unwrap_or_default();

    // Browser-facing URLs
    ep.authorization_url = update_url(&oidc.authorization_endpoint, browser_scheme, browser_host);
    ep.end_session = update_url(&oidc.end_session_endpoint, browser_scheme, browser_host);

    // For embedded: browser_url == ak_url, so issuer/jwks use the same host.
    // For standalone with AUTHENTIK_HOST_BROWSER: issuer uses the browser host.
    ep.issuer = update_url(&oidc.issuer, browser_scheme, browser_host);
    if embedded {
        ep.jwks_uri = update_url(&oidc.jwks_uri, browser_scheme, browser_host);
    }

    ep
}

#[cfg(test)]
mod tests {
    use ak_client::models::OpenIdConnectConfiguration;

    use super::*;

    fn test_provider() -> ProxyOutpostConfig {
        ProxyOutpostConfig {
            oidc_configuration: OpenIdConnectConfiguration::new(
                "https://test.goauthentik.io/application/o/test-app/".to_owned(),
                "https://test.goauthentik.io/application/o/authorize/".to_owned(),
                "https://test.goauthentik.io/application/o/token/".to_owned(),
                "https://test.goauthentik.io/application/o/userinfo/".to_owned(),
                "https://test.goauthentik.io/application/o/test-app/end-session/".to_owned(),
                "https://test.goauthentik.io/application/o/introspect/".to_owned(),
                "https://test.goauthentik.io/application/o/test-app/jwks/".to_owned(),
                vec![],
                vec![],
                vec![],
                vec![],
            ),
            ..Default::default()
        }
    }

    #[test]
    fn default_no_overrides() {
        let pc = test_provider();
        let ep = get_oidc_endpoint(&pc, "https://authentik-host.test.goauthentik.io", false, "");
        assert_eq!(
            ep.authorization_url,
            "https://test.goauthentik.io/application/o/authorize/"
        );
        assert_eq!(
            ep.token_url,
            "https://test.goauthentik.io/application/o/token/"
        );
        assert_eq!(
            ep.issuer,
            "https://test.goauthentik.io/application/o/test-app/"
        );
        assert_eq!(
            ep.jwks_uri,
            "https://test.goauthentik.io/application/o/test-app/jwks/"
        );
        assert_eq!(
            ep.end_session,
            "https://test.goauthentik.io/application/o/test-app/end-session/"
        );
        assert_eq!(
            ep.token_introspection,
            "https://test.goauthentik.io/application/o/introspect/"
        );
    }

    #[test]
    fn authentik_host_browser_override() {
        let pc = test_provider();
        let ep = get_oidc_endpoint(
            &pc,
            "https://authentik-host.test.goauthentik.io",
            false,
            "https://browser.test.goauthentik.io",
        );

        assert_eq!(
            ep.authorization_url,
            "https://browser.test.goauthentik.io/application/o/authorize/"
        );
        assert_eq!(
            ep.end_session,
            "https://browser.test.goauthentik.io/application/o/test-app/end-session/"
        );
        assert_eq!(
            ep.token_url,
            "https://test.goauthentik.io/application/o/token/"
        );
        assert_eq!(
            ep.issuer,
            "https://browser.test.goauthentik.io/application/o/test-app/"
        );
        assert_eq!(
            ep.jwks_uri,
            "https://test.goauthentik.io/application/o/test-app/jwks/"
        );
        assert_eq!(
            ep.token_introspection,
            "https://test.goauthentik.io/application/o/introspect/"
        );
    }

    #[test]
    fn embedded_outpost() {
        let pc = test_provider();
        let ep = get_oidc_endpoint(&pc, "https://authentik-host.test.goauthentik.io", true, "");
        assert_eq!(
            ep.authorization_url,
            "https://authentik-host.test.goauthentik.io/application/o/authorize/"
        );
        assert_eq!(
            ep.issuer,
            "https://authentik-host.test.goauthentik.io/application/o/test-app/"
        );
        assert_eq!(
            ep.token_url,
            "https://test.goauthentik.io/application/o/token/"
        );
        assert_eq!(
            ep.jwks_uri,
            "https://authentik-host.test.goauthentik.io/application/o/test-app/jwks/"
        );
        assert_eq!(
            ep.end_session,
            "https://authentik-host.test.goauthentik.io/application/o/test-app/end-session/"
        );
        assert_eq!(
            ep.token_introspection,
            "https://test.goauthentik.io/application/o/introspect/"
        );
    }
}
