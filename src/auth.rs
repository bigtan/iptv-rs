use crate::config::{Config, should_protect};
use actix_web::{
    HttpRequest, HttpResponse,
    cookie::{Cookie, SameSite},
    http::header,
};

const AUTH_COOKIE_NAME: &str = "iptv_token";

fn extract_explicit_token(req: &HttpRequest) -> Option<String> {
    if let Some(auth) = req.headers().get(header::AUTHORIZATION)
        && let Ok(auth) = auth.to_str()
        && let Some(token) = auth.strip_prefix("Bearer ")
    {
        return Some(token.to_string());
    }
    if let Some(token) = req
        .headers()
        .get("X-Api-Token")
        .and_then(|value| value.to_str().ok())
    {
        return Some(token.to_string());
    }
    req.query_string().split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == "token").then(|| value.to_string())
    })
}

fn extract_token(req: &HttpRequest) -> Option<String> {
    extract_explicit_token(req).or_else(|| {
        req.cookie(AUTH_COOKIE_NAME)
            .map(|cookie| cookie.value().to_string())
    })
}

fn maybe_auth_cookie(
    req: &HttpRequest,
    config: &Config,
    endpoint: &str,
) -> Option<Cookie<'static>> {
    if !should_protect(config, endpoint) || config.auth.token.is_empty() {
        return None;
    }
    let explicit = extract_explicit_token(req)?;
    if explicit != config.auth.token
        || req
            .cookie(AUTH_COOKIE_NAME)
            .is_some_and(|cookie| cookie.value() == explicit)
    {
        return None;
    }
    Some(
        Cookie::build(AUTH_COOKIE_NAME, explicit)
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .finish(),
    )
}

pub(crate) fn with_auth_cookie(
    req: &HttpRequest,
    config: &Config,
    endpoint: &str,
    mut response: HttpResponse,
) -> HttpResponse {
    if let Some(cookie) = maybe_auth_cookie(req, config, endpoint)
        && let Ok(value) = header::HeaderValue::from_str(&cookie.to_string())
    {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

pub(crate) fn check_auth(req: &HttpRequest, config: &Config, endpoint: &str) -> bool {
    if !should_protect(config, endpoint) || config.auth.token.is_empty() {
        return true;
    }
    extract_token(req).is_some_and(|token| token == config.auth.token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    fn protected_config() -> Config {
        let mut config = Config::default();
        config.auth.token = "secret".to_string();
        config.auth.protect = vec!["playlist".to_string()];
        config
    }

    #[test]
    fn accepts_supported_token_sources() {
        let config = protected_config();
        let bearer = TestRequest::default()
            .insert_header((header::AUTHORIZATION, "Bearer secret"))
            .to_http_request();
        let api_header = TestRequest::default()
            .insert_header(("X-Api-Token", "secret"))
            .to_http_request();
        let query = TestRequest::with_uri("/playlist?token=secret").to_http_request();

        assert!(check_auth(&bearer, &config, "playlist"));
        assert!(check_auth(&api_header, &config, "playlist"));
        assert!(check_auth(&query, &config, "playlist"));
    }

    #[test]
    fn rejects_invalid_token_on_protected_endpoint() {
        let config = protected_config();
        let request = TestRequest::with_uri("/playlist?token=wrong").to_http_request();

        assert!(!check_auth(&request, &config, "playlist"));
        assert!(check_auth(&request, &config, "status"));
    }
}
