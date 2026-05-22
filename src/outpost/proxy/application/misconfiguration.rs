use std::collections::HashMap;

use axum::http::HeaderMap;
use tracing::{error, warn};

use super::Application;

impl Application {
    /// Report a configuration error to the authentik events API.
    ///
    /// Logs the error locally and POSTs a `configuration_error` event to
    /// `events/events/` so it appears in the admin UI.
    ///
    /// Go reference: `ReportMisconfiguration` in `application/mode_common.go`.
    pub(super) async fn report_misconfiguration(
        &self,
        msg: &str,
        request_headers: &HeaderMap,
        request_url: &str,
    ) {
        let headers = cleanse_headers(request_headers);
        let mut context: HashMap<String, serde_json::Value> = HashMap::new();
        context.insert("message".to_owned(), serde_json::json!(msg));
        context.insert("provider".to_owned(), serde_json::json!(self.provider.name));
        context.insert("outpost".to_owned(), serde_json::json!(self.outpost_name));
        context.insert("url".to_owned(), serde_json::json!(request_url));
        context.insert("headers".to_owned(), serde_json::json!(headers));

        error!(
            message = msg,
            provider = self.provider.name,
            outpost = self.outpost_name,
            "reporting configuration error"
        );

        let event_request = ak_client::models::EventRequest {
            action: ak_client::models::EventActions::ConfigurationError,
            app: "authentik.providers.proxy".to_owned(),
            context: Some(context),
            ..Default::default()
        };

        if let Err(err) =
            ak_client::apis::events_api::events_events_create(&self.api_config, event_request)
                .await
        {
            warn!(?err, "failed to report configuration error");
        }
    }
}

/// Flatten a `HeaderMap` into a simple `key → first_value` map for event context.
///
/// Go reference: `cleanseHeaders` in `application/utils.go`.
fn cleanse_headers(headers: &HeaderMap) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (name, value) in headers {
        map.entry(name.to_string())
            .or_insert_with(|| value.to_str().unwrap_or_default().to_owned());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanse_headers_flattens_to_first_value() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-host", "example.com".parse().unwrap());
        headers.append("x-forwarded-host", "other.com".parse().unwrap());

        let cleansed = cleanse_headers(&headers);
        assert_eq!(cleansed.get("x-forwarded-proto").unwrap(), "https");
        // Should contain the first value only.
        assert_eq!(cleansed.get("x-forwarded-host").unwrap(), "example.com");
    }

    #[test]
    fn cleanse_headers_empty() {
        let headers = HeaderMap::new();
        let cleansed = cleanse_headers(&headers);
        assert!(cleansed.is_empty());
    }
}
