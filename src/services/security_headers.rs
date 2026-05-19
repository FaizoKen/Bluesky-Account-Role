//! Default-deny security headers applied to every response.

use axum::extract::Request;
use axum::http::{header, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

pub const PUBLIC_PAGE_CSP: &str = "frame-ancestors 'none'";

pub fn admin_iframe_csp(dashboard_origin: Option<&str>) -> String {
    let ancestor = dashboard_origin.unwrap_or("*");
    format!("frame-ancestors {ancestor}")
}

pub async fn baseline(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();

    h.entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(PUBLIC_PAGE_CSP));
    h.entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    h.entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("strict-origin-when-cross-origin"));
    h.entry(header::STRICT_TRANSPORT_SECURITY)
        .or_insert(HeaderValue::from_static(
            "max-age=31536000; includeSubDomains",
        ));

    resp
}
