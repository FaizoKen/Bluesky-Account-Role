//! Origin-based CSRF defense for cookie-authenticated state-changing routes.

use axum::http::HeaderMap;

use crate::error::AppError;

pub fn verify_origin(headers: &HeaderMap, allowed_origins: &[String]) -> Result<(), AppError> {
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            AppError::Forbidden("State-changing requests must include an Origin header.".into())
        })?;

    let origin_norm = origin.trim_end_matches('/');
    for allowed in allowed_origins {
        if origin_norm == allowed.trim_end_matches('/') {
            return Ok(());
        }
    }
    Err(AppError::Forbidden(format!(
        "Origin '{origin}' is not allowed for state-changing requests."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_origin(origin: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("origin", HeaderValue::from_str(origin).unwrap());
        h
    }

    fn allowed() -> Vec<String> {
        vec![
            "https://app.rolelogic.com".into(),
            "https://plugin.example.com".into(),
        ]
    }

    #[test]
    fn accepts_exact_match() {
        let h = headers_with_origin("https://app.rolelogic.com");
        assert!(verify_origin(&h, &allowed()).is_ok());
    }

    #[test]
    fn accepts_trailing_slash() {
        let h = headers_with_origin("https://app.rolelogic.com/");
        assert!(verify_origin(&h, &allowed()).is_ok());
    }

    #[test]
    fn rejects_missing_origin_header() {
        let h = HeaderMap::new();
        match verify_origin(&h, &allowed()) {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[test]
    fn rejects_attacker_origin() {
        let h = headers_with_origin("https://evil.example");
        assert!(verify_origin(&h, &allowed()).is_err());
    }

    #[test]
    fn rejects_subdomain_of_allowed() {
        let h = headers_with_origin("https://attacker.rolelogic.com");
        assert!(verify_origin(&h, &allowed()).is_err());
    }

    #[test]
    fn rejects_scheme_downgrade() {
        let h = headers_with_origin("http://app.rolelogic.com");
        assert!(verify_origin(&h, &allowed()).is_err());
    }
}
