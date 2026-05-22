# Proxy Outpost Rewrite: Go to Rust

## Status Overview

The Rust proxy outpost has the **infrastructure layer** working: outpost lifecycle, provider
fetching, TLS cert resolution, WebSocket events, HTTP/HTTPS servers, request routing by hostname,
and basic metrics. All the **application-level logic** (authentication, OAuth flows, session
management, header injection, reverse proxying, forward-auth protocols) is stubbed with `todo!()`.

---

## What's Done (Rust)

- `ProxyOutpost` struct with `Outpost` trait: init, start, refresh, TLS cert resolution
- Provider fetching from authentik API (`outposts_proxy_list`)
- `Application` struct: external host parsing, cert loading, router setup per mode
- Host-based and cookie-domain-based app lookup (including forward_domain longest-match)
- Top-level request routing: ping handler, app dispatch, single-app fallback
- Request duration metrics (`authentik_outpost_proxy_request_duration_seconds`)
- Query-parameter signature routing (`X-authentik-auth-callback`, `X-authentik-logout`)
- WebSocket event handling (TriggerUpdate refresh, heartbeat, reconnect with backoff)
- Signal handling (SIGUSR1 for manual refresh)

## What's Missing (mapped to Go sources)

### Core Types
- [x] `Claims` and `ProxyClaims` structs (`types/claims.go`) → `src/outpost/proxy/application/types.rs`
- [x] `OAuthState` struct for state JWT (`application/oauth_state.go`) → `src/outpost/proxy/application/oauth_state.rs`
- [x] `OIDCEndpoint` struct with token introspection, end-session, JWKS URIs (`application/endpoint.go`) → `src/outpost/proxy/application/endpoint.rs`
- [x] `ErrorPageData` and error template rendering (`application/error.go`, `templates/`) → `application/error.rs` + `application/templates/error.html`

### Application Setup (Go: `application/application.go`)
- [ ] OIDC configuration (key set, token verifier, oauth2 config)
- [x] Session name derivation (SHA256 of client ID, first 8 hex chars) → `application/mod.rs`
- [x] Redirect URI construction → `application/mod.rs`
- [x] `skip_path_regex` compilation into `unauthenticated_regex` → `application/mod.rs`
- [x] `is_allowlisted(url)` check → `application/mod.rs`
- [x] OIDC endpoint resolution wired into Application::new → `application/mod.rs`
- [x] Outpost name stored on Application → `application/mod.rs`
- [ ] HTTP clients for upstream and public host (with host interception for embedded)
- [x] Error template loading → `application/error.rs` (compile-time `include_str!`)

### Session Management (Go: `application/session.go`, `postgresstore/`, `filesystemstore/`)
- [x] Session store abstraction (cookie-based sessions) → `application/session.rs`
- [x] Session cookie options (HttpOnly, Secure, SameSite, Domain, MaxAge, Path) → `application/session.rs` CookieOptions
- [x] Cookie parsing and Set-Cookie building → `application/session.rs` helpers
- [x] `Logout()` - filter and delete sessions by predicate → `SessionStore::delete_matching`
- [x] Filesystem session store (standalone outposts) → `application/session_filesystem.rs`
- [ ] PostgreSQL session store (embedded outposts)
- [x] Session cleanup (expired session removal) → `proxy/mod.rs` periodic task via `session_cleanup()`, runs `cleanup_expired()` every 5 min

### Authentication (Go: `application/auth.go`)
- [x] `get_claims_from_session()` → `application/auth.rs`
- [x] `check_auth()` - the main authentication decision tree → `application/auth.rs`
  1. Session cookie claims
  2. TTL cache lookup (Authorization header)
  3. Bearer token introspection
  4. Basic auth (username/password -> token endpoint)
- [x] `AuthHeaderCache` — in-memory TTL cache (Authorization header → Claims) → `application/auth.rs`
- [x] `get_claims_from_cache()` → `application/auth.rs`
- [x] `save_and_cache_claims()` - persist claims to session + cache → `application/auth.rs`
- [x] `generate_session_id()` → `application/auth.rs`

### Bearer Token Auth (Go: `application/auth_bearer.go`)
- [x] `extract_bearer_token()` → `application/auth_bearer.rs`
- [x] `attempt_bearer_auth()` → `application/auth_bearer.rs`
- [x] `TokenIntrospectionResponse` struct → `application/auth_bearer.rs`

### Basic Auth (Go: `application/auth_basic.go`)
- [x] `extract_basic_auth()` → `application/auth_basic.rs`
- [x] `attempt_basic_auth()` → `application/auth_basic.rs`
- [x] Special case: `goauthentik.io/token` username → delegates to `attempt_bearer_auth`
- [x] `verify_id_token()` — HS256 JWT verification with issuer/audience validation → `application/auth_basic.rs`
- [x] RS256/JWKS verification → `application/jwks.rs` `RemoteJwksKeySet` with lazy fetch + cache, wired into `verify_id_token`

### OAuth Flow - Start (Go: `application/oauth.go`)
- [x] `/outpost.goauthentik.io/start` route → `application/mod.rs` router + `handlers/mod.rs`
- [x] `handle_auth_start()` - create state JWT, redirect to authorization endpoint → `application/oauth.rs`
- [x] `redirect_to_start()` - save redirect URL to session, redirect to /start → `application/oauth.rs`
- [x] `check_redirect_param()` - validate `rd` query param against external host / cookie domain → `application/oauth.rs`

### OAuth Flow - State (Go: `application/oauth_state.go`)
- [x] `create_state()` - generate state JWT (HS256 signed with cookie_secret) → `application/oauth_state.rs`
- [x] `state_from_request()` - parse and validate state JWT from callback → `application/oauth_state.rs`
- [x] Session ID matching validation → `application/oauth_state.rs`
- [x] Issuer validation → `application/oauth_state.rs`

### OAuth Flow - Callback (Go: `application/oauth_callback.go`)
- [x] `handle_auth_callback()` - exchange code for token, verify ID token, save claims to session → `application/oauth.rs` + `handlers/mod.rs`
- [x] `redeem_callback()` - code exchange + ID token verification + claims extraction → `application/oauth.rs`

### Sign Out (Go: `application/application.go` `handleSignOut`)
- [x] `handle_sign_out()` - get claims, logout matching sessions, redirect to end-session endpoint → `application/oauth.rs` + `handlers/mod.rs`

### Header Injection (Go: `application/mode_common.go`)
- [x] `add_headers()` / `get_headers()` - inject X-authentik-* headers → `application/headers.rs`
  - `X-authentik-username`, `X-authentik-uid`, `X-authentik-name`, `X-authentik-email`
  - `X-authentik-groups` (pipe-separated), `X-authentik-entitlements` (pipe-separated)
  - `X-authentik-jwt` (raw token)
  - `X-authentik-meta-jwks`, `X-authentik-meta-outpost`, `X-authentik-meta-provider`,
    `X-authentik-meta-app`, `X-authentik-meta-version`
- [x] `set_authorization_header()` - inject Basic auth from user attributes → `application/headers.rs`
- [x] Additional headers from `userAttributes.additionalHeaders` → `application/headers.rs`
- [x] `remove_duplicate_underscore_header()` - clean up underscore/hyphen duplicates → `application/headers.rs`

### Forward Auth URL Parsing (Go: `application/mode_common.go`)
- [x] `get_traefik_forward_url()` - parse from `X-Forwarded-Proto/Host/Uri` → `handlers/forward.rs`
- [x] `get_nginx_forward_url()` - parse from `X-Original-URL` → `handlers/forward.rs`
- [x] `get_envoy_forward_url()` - strip prefix + Host header → `handlers/forward.rs`

### Forward Auth Handlers (Go: `application/mode_forward.go`)
- [x] `handle_traefik()` - parse forwarded URL, check auth, add headers or redirect → `handlers/forward.rs`
- [x] `handle_caddy()` - same as traefik (uses same URL parsing) → `handlers/forward.rs`
- [x] `handle_nginx()` - parse X-Original-URL, check auth, return 200+headers or 401 → `handlers/forward.rs`
- [x] `handle_envoy()` - strip prefix, construct URL, check auth, add headers or redirect → `handlers/forward.rs`
- [x] All: check callback/logout signatures in forwarded URL → `handlers/forward.rs`
- [x] All: allowlist check before requiring auth → `handlers/forward.rs`

### Reverse Proxy Handler (Go: `application/mode_proxy.go`)
- [x] `handle()` (proxy mode) - check auth, add headers, reverse proxy to internal_host → `handlers/proxy.rs`
- [x] Request modification: set X-Forwarded-Host, rewrite URL to upstream → `handlers/proxy.rs`
- [x] Per-user backend override (`claims.Proxy.BackendOverride`) → `handlers/proxy.rs`
- [x] Per-user host header override (`claims.Proxy.HostHeader`) → `handlers/proxy.rs`
- [x] Response modification: set `X-Powered-By` → `handlers/proxy.rs`
- [x] Upstream timing metrics (`authentik_outpost_proxy_upstream_response_duration_seconds`) → `handlers/proxy.rs`
- [x] Error handler with error page rendering (detailed for superusers) → `application/error.rs`

### Misconfiguration Reporting (Go: `application/mode_common.go`)
- [x] `report_misconfiguration()` - POST configuration error event to authentik API → `application/misconfiguration.rs`

### Session End via WebSocket (Go: `ws.go`)
- [x] Handle `SessionEnd` events: find and delete matching sessions across all apps → `proxy/mod.rs` end_session

### Auth Header Cache
- [x] TTL cache for Authorization header -> Claims (60s TTL) → `application/auth.rs` AuthHeaderCache
- [x] Cache check in auth flow → `application/auth.rs` check_auth
- [x] Cache population on successful bearer/basic auth → `application/auth.rs` save_and_cache_claims

---

## Implementation Steps (small, ordered)

Each step should be a single, focused PR-sized change.

### Phase 1: Core Types and Data Structures

**Step 1: Claims types**
Add `Claims` and `ProxyClaims` structs to `src/outpost/proxy/application/` (or a `types` submodule).
These are the JWT payload types deserialized from the ID token. Use `serde::Deserialize`.
Go reference: `internal/outpost/proxyv2/types/claims.go`

**Step 2: OIDC endpoint configuration**
Add `OIDCEndpoint` struct holding the full set of OIDC endpoints (authorization, token,
introspection, end-session, JWKS, issuer). Port the `GetOIDCEndpoint()` function that resolves
endpoints with host override support for embedded outposts.
Go reference: `internal/outpost/proxyv2/application/endpoint.go`

**Step 3: OAuth state JWT**
Add `OAuthState` struct. Implement `create_state()` (sign with HS256 using cookie_secret) and
`state_from_request()` (parse, validate issuer, match session ID). Use the `jsonwebtoken` crate.
Go reference: `internal/outpost/proxyv2/application/oauth_state.go`

### Phase 2: Application Initialization

**Step 4: Expand Application struct**
Add fields to `Application`: OIDC endpoint, oauth2 config (client_id, client_secret, redirect_uri,
scopes, endpoints), session name, outpost name, `UnauthenticatedRegex` (compiled skip_path_regex),
error templates. Port session name derivation (SHA256 of client_id, first 8 hex chars).
Go reference: `internal/outpost/proxyv2/application/application.go` NewApplication

**Step 5: Skip-path allowlist**
Implement `is_allowlisted()` on `Application`. Compile `skip_path_regex` (newline-separated) into
a `Vec<Regex>` during `Application::new()`. For proxy/forward_single test against path only; for
forward_domain test against the full URL string.
Go reference: `internal/outpost/proxyv2/application/mode_common.go` IsAllowlisted

### Phase 3: Session Management

**Step 6: Session store abstraction**
Choose a Rust session crate (e.g., `tower-sessions` with cookie backend, or a custom
implementation). Implement a session store trait that can get/save/delete sessions keyed by a cookie.
Set cookie options: HttpOnly, Secure (based on external_host scheme), SameSite=Lax, Domain from
cookie_domain, Path="/".
Go reference: `internal/outpost/proxyv2/application/session.go`

**Step 7: Filesystem session store**
Implement a filesystem-backed session store for standalone outpost deployments. Store session data
encrypted in `/tmp/session_*` files.
Go reference: `internal/outpost/proxyv2/filesystemstore/`

**Step 8: PostgreSQL session store** (can be deferred)
Implement a PostgreSQL-backed session store for embedded outpost deployments using the
`authentik_providers_proxy_proxysession` table.
Go reference: `internal/outpost/proxyv2/postgresstore/`

### Phase 4: Authentication

**Step 9: Claims from session**
Implement `get_claims_from_session()` - load the session by cookie, extract and deserialize the
`Claims` from the session values. Handle stale/invalid sessions by deleting the cookie.
Go reference: `internal/outpost/proxyv2/application/auth.go` getClaimsFromSession

**Step 10: Bearer token introspection**
Implement `check_auth_header_bearer()` (extract token from `Authorization: Bearer <token>`) and
`attempt_bearer_auth()` (POST to token introspection endpoint, parse `TokenIntrospectionResponse`,
check `active` field).
Go reference: `internal/outpost/proxyv2/application/auth_bearer.go`

**Step 11: Basic auth**
Implement `attempt_basic_auth()` - POST client_credentials grant to token endpoint, verify the
returned ID token, extract claims. Handle the special case where username is
`goauthentik.io/token` (treat password as bearer token).
Go reference: `internal/outpost/proxyv2/application/auth_basic.go`

**Step 12: Auth header TTL cache**
Add a TTL cache (e.g., `moka` or `mini-moka` crate) mapping `Authorization` header value to
`Claims` with 60s TTL. Wire into the auth flow: check cache before introspection, populate cache
after successful auth.
Go reference: `internal/outpost/proxyv2/application/auth.go` authHeaderCache, getClaimsFromCache, saveAndCacheClaims

**Step 13: Unified check_auth**
Implement the main `check_auth()` function that tries auth methods in order:
1. Session cookie -> 2. Cache -> 3. Bearer introspection -> 4. Basic auth.
Return `Claims` on success, error on failure.
Go reference: `internal/outpost/proxyv2/application/auth.go` checkAuth

### Phase 5: Header Injection

**Step 14: X-authentik-* header injection**
Implement `get_headers()` returning a `HeaderMap` with all `X-authentik-*` user and meta headers.
Implement `add_headers()` to apply them to a request/response. Include the `Authorization: Basic`
injection when `basic_auth_enabled` is set and user attributes contain the configured password
attribute.
Go reference: `internal/outpost/proxyv2/application/mode_common.go` getHeaders, addHeaders, setAuthorizationHeader

**Step 15: Additional headers and cleanup**
Support `additionalHeaders` from `claims.Proxy.UserAttributes`. Implement
`remove_duplicate_underscore_header()` to clean up headers where both underscore and hyphen
variants exist.
Go reference: `internal/outpost/proxyv2/application/mode_common.go`

### Phase 6: OAuth Flow

**Step 16: /start endpoint and auth start**
Add the `/outpost.goauthentik.io/start` route. Implement `handle_auth_start()`: validate redirect
param, create state JWT, redirect to oauth2 authorization URL with state.
Implement `redirect_to_start()`: save redirect URL in session, redirect to /start.
Go reference: `internal/outpost/proxyv2/application/oauth.go`

**Step 17: OAuth callback**
Implement `handle_auth_callback()`: validate state JWT from query, exchange authorization code for
tokens, verify ID token, extract claims, save to session, redirect to original URL.
Go reference: `internal/outpost/proxyv2/application/oauth_callback.go`

**Step 18: Sign out**
Implement `handle_sign_out()`: get claims from session, delete matching sessions (by sub), redirect
to end-session endpoint with `id_token_hint`.
Go reference: `internal/outpost/proxyv2/application/application.go` handleSignOut

### Phase 7: Forward Auth Handlers

**Step 19: Forward auth handlers** ✅
Implemented all forward auth handlers in `handlers/forward.rs`:
- URL parsers: `get_traefik_forward_url()`, `get_nginx_forward_url()`, `get_envoy_forward_url()`
- Shared `handle_traefik_caddy()` for traefik/caddy
- `handle_caddy()`, `handle_traefik()`, `handle_nginx()`, `handle_envoy()`
- Callback/logout signature detection in forwarded URLs
- Allowlist checks, header injection, User-Agent forwarding
- nginx: 401 instead of redirect, /outpost.goauthentik.io passthrough, session redirect save
- 22 tests (URL parsing, query flags, integration tests for auth/allowlist/redirect/errors)

### Phase 8: Reverse Proxy

**Step 24: Basic reverse proxy** ✅
Implemented in `handlers/proxy.rs`:
- Auth check → redirect to `/start` if unauthenticated, allowlist bypass
- `build_upstream_url()` rewrites URL to `internal_host` + original path/query
- `upstream_client: reqwest::Client` on Application with `internal_host_ssl_validation` support
- Hop-by-hop header filtering, `X-Forwarded-Host`, `X-Powered-By` on response
- Streaming request/response bodies via `reqwest::Body::wrap_stream` / `Body::from_stream`
- 502 Bad Gateway on upstream failure or invalid `internal_host`
- 12 tests (URL building, hop-by-hop filtering, integration tests with mock upstream)

**Step 25: Per-user backend and host overrides** ✅
Added to `handlers/proxy.rs`:
- `backend_override`: parses as URL, overrides scheme/host/port of upstream URL
- `host_header`: overrides the Host header sent to the upstream
- Invalid backend_override URLs log a warning and fall back to default internal_host
- 3 tests (backend override, host header override, invalid override fallback)

**Step 26: Upstream timing metrics** ✅
Added `authentik_outpost_proxy_upstream_response_duration_seconds` histogram to `handlers/proxy.rs`.
Records upstream response time with labels: outpost_name, method, scheme, host, upstream_host.
Uses `Instant::now()` + `histogram!` macro from the `metrics` crate.

### Phase 9: Error Handling and Polish

**Step 27: Error page template** ✅
Implemented in `application/error.rs` + `application/templates/error.html`:
- HTML template embedded at compile time via `include_str!`
- `render_error_html()` with HTML escaping for XSS prevention
- `Application::error_page()` — superusers see detailed error, regular users see "Failed to connect to backend."
- Wired into proxy handler: upstream failures now return styled 502 error page
- 7 tests (template rendering, XSS escaping, superuser/regular/no-claims/no-proxy-claims)

**Step 28: Misconfiguration reporting** ✅
Implemented in `application/misconfiguration.rs`:
- `Application::report_misconfiguration()` — logs error and POSTs `configuration_error` event via `events_events_create` API
- `cleanse_headers()` — flattens `HeaderMap` to `HashMap<String, String>` for event context
- Added `api_config: Configuration` field to `Application` for API calls
- Wired into forward auth handlers: traefik/caddy, nginx, envoy all report misconfigurations on URL parsing failure
- 2 tests (cleanse_headers basic, empty)

**Step 29: Session end via WebSocket** ✅
Implemented `ProxyOutpost::end_session()` in `proxy/mod.rs`:
- On `SessionEnd` event, iterates all apps and calls `delete_matching` with `c.sid == session_id` filter
- Added `EventSessionEnd::session_id()` accessor in `event.rs`
- 1 test (delete_matching by sid in session_filesystem.rs)

**Step 30: Intercept header auth** ✅
Updated `Unauthorized` responses in `handlers/proxy.rs` and `handlers/mod.rs` to render the
error page HTML (title "Unauthenticated", message about receive header authentication) instead
of returning a bare 401 status. Added `render_error_response()` to `error.rs` for flexible
status/title/message rendering. 1 test (proxy intercept header auth returns 401 with HTML).
