use std::str::FromStr;
use std::{fmt, sync::Arc};

use ak_axum::error::Result;
use axum::{
    extract::{Query, Request, State},
    http::{StatusCode, header::SET_COOKIE},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Deserializer};
use tower::util::ServiceExt as _;
use tracing::{debug, instrument};

use crate::outpost::proxy::application::Application;

pub(super) mod forward;
pub(super) mod proxy;

// TODO: move this to ak-common
fn empty_string_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: fmt::Display,
{
    let opt = Option::<String>::deserialize(de)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => FromStr::from_str(s)
            .map_err(serde::de::Error::custom)
            .map(Some),
    }
}

#[derive(Deserialize)]
struct Parameters {
    #[serde(rename = "rd", default, deserialize_with = "empty_string_as_none")]
    redirect: Option<String>,
    #[serde(
        rename = "X-authentik-auth-callback",
        default,
        deserialize_with = "empty_string_as_none"
    )]
    callback_signature: Option<bool>,
    #[serde(
        rename = "X-authentik-logout",
        default,
        deserialize_with = "empty_string_as_none"
    )]
    logout_signature: Option<bool>,
}

#[instrument(skip_all)]
pub(crate) async fn handle(app: Arc<Application>, request: Request) -> Result<Response> {
    if let Ok(query) = Query::<Parameters>::try_from_uri(request.uri()) {
        if query.callback_signature == Some(true) {
            debug!("handling OAuth Callback from querystring signature");
            return handle_auth_callback(State(app), request).await;
        }
        if query.logout_signature == Some(true) {
            debug!("handling OAuth Logout from querystring signature");
            return handle_sign_out(State(app), request).await;
        }
    }

    Ok(app.router.clone().with_state(app).oneshot(request).await?)
}

/// `/outpost.goauthentik.io/start` — begin the OAuth2 authorization flow.
///
/// Reads `?rd=<url>` to determine where to redirect after authentication.
/// Creates a state JWT and redirects to the authorization endpoint.
///
/// Go reference: `handleAuthStart` in `application/oauth.go`.
#[instrument(skip_all)]
pub(super) async fn handle_auth_start(
    State(app): State<Arc<Application>>,
    request: Request,
) -> Result<Response> {
    let query = Query::<Parameters>::try_from_uri(request.uri()).ok();
    let rd = query
        .as_ref()
        .and_then(|q| q.redirect.as_deref())
        .unwrap_or_default();

    let redirect = app
        .check_redirect_param(rd)
        .unwrap_or_else(|| app.provider.external_host.clone());

    let headers = request.headers();
    match app.handle_auth_start(headers, &redirect).await {
        Ok(result) => {
            let mut response = axum::response::Redirect::to(&result.redirect_url).into_response();
            let resp_headers = response.headers_mut();
            for cookie in &result.cookies {
                if let Ok(val) = cookie.parse() {
                    resp_headers.append(SET_COOKIE, val);
                }
            }
            Ok(response)
        }
        Err(status) => Ok(status.into_response()),
    }
}

/// `/outpost.goauthentik.io/callback` — OAuth2 callback handler.
///
/// Validates the state JWT, exchanges the authorization code for tokens,
/// saves claims to the session, and redirects the user to their original URL.
///
/// Go reference: `handleAuthCallback` in `application/oauth_callback.go`.
#[instrument(skip_all)]
pub(super) async fn handle_auth_callback(
    State(app): State<Arc<Application>>,
    request: Request,
) -> Result<Response> {
    let callback_url = {
        let uri = request.uri();
        // Build a full URL from the request URI (it may be relative).
        let base = url::Url::parse(&app.provider.external_host)
            .unwrap_or_else(|_| url::Url::parse("https://localhost").expect("static URL"));
        base.join(&uri.to_string()).unwrap_or(base)
    };

    let headers = request.headers();
    let result = app.handle_auth_callback(headers, &callback_url).await;

    let mut response = axum::response::Redirect::to(&result.redirect_url).into_response();
    let resp_headers = response.headers_mut();
    for cookie in &result.cookies {
        if let Ok(val) = cookie.parse() {
            resp_headers.append(SET_COOKIE, val);
        }
    }
    Ok(response)
}

#[instrument(skip_all)]
pub(super) async fn handle_sign_out(
    State(_app): State<Arc<Application>>,
    _request: Request,
) -> Result<Response> {
    todo!()
}
