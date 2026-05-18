use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Proxy-specific claims nested under `ak_proxy` in the ID token.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct ProxyClaims {
    #[serde(default)]
    pub(crate) user_attributes: HashMap<String, Value>,
    #[serde(default)]
    pub(crate) backend_override: String,
    #[serde(default)]
    pub(crate) host_header: String,
    #[serde(default)]
    pub(crate) is_superuser: bool,
}

/// Claims extracted from an OIDC ID token or loaded from session storage.
///
/// `raw_token` is not part of the JWT payload — it is set programmatically after
/// token exchange or introspection, and persisted alongside the claims in the
/// session store.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct Claims {
    #[serde(default)]
    pub(crate) sub: String,
    #[serde(default)]
    pub(crate) exp: i64,
    #[serde(default)]
    pub(crate) email: String,
    #[serde(default)]
    pub(crate) email_verified: bool,
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) preferred_username: String,
    #[serde(default)]
    pub(crate) groups: Vec<String>,
    #[serde(default)]
    pub(crate) entitlements: Vec<String>,
    #[serde(default)]
    pub(crate) sid: String,
    #[serde(default)]
    pub(crate) ak_proxy: Option<ProxyClaims>,
    #[serde(default)]
    pub(crate) raw_token: String,
}
