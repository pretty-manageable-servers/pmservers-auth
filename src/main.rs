use anyhow::{anyhow, Result as AnyhowResult};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Clone)]
struct App {
    pool: PgPool,
    http: reqwest::Client,
    url: String,
    anon: String,
    service: String,
    public: String,
    attempts: Arc<Mutex<HashMap<String, RateWindow>>>,
    wrong_codes: Arc<Mutex<HashMap<String, WrongCodeWindow>>>,
}
struct RateWindow {
    started: Instant,
    count: u32,
}
struct WrongCodeWindow {
    started: Instant,
    count: u32,
    blocked_until: Option<Instant>,
}
#[derive(Deserialize)]
struct Start {
    client_info: Option<String>,
}
#[derive(Serialize)]
struct Started {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}
#[derive(Deserialize)]
struct DeviceCode {
    device_code: String,
}
#[derive(Deserialize)]
struct UserCode {
    user_code: String,
}
fn hash(device_code: &str) -> String {
    hex::encode(Sha256::digest(device_code.as_bytes()))
}

fn is_expired(expires_at: i64, now: i64) -> bool {
    expires_at <= now
}

fn can_claim_session(status: &str, expired: bool) -> bool {
    status == "approved" && !expired
}

fn can_deny(status: &str) -> bool {
    status == "pending"
}

fn should_slow_down(seconds_since_last_poll: Option<i64>) -> bool {
    seconds_since_last_poll.is_some_and(|seconds| seconds < 5)
}

fn record_bad_ip(
    wrong_codes: &mut HashMap<String, WrongCodeWindow>,
    ip: String,
    now: Instant,
) -> bool {
    wrong_codes.retain(|_, window| {
        window
            .blocked_until
            .is_some_and(|blocked_until| blocked_until > now)
            || now.duration_since(window.started) < Duration::from_secs(600)
    });
    let window = wrong_codes.entry(ip).or_insert(WrongCodeWindow {
        started: now,
        count: 0,
        blocked_until: None,
    });
    if window
        .blocked_until
        .is_some_and(|blocked_until| blocked_until > now)
    {
        return true;
    }
    window.count += 1;
    if window.count >= 5 {
        window.blocked_until = Some(now + Duration::from_secs(600));
        true
    } else {
        false
    }
}

fn email_for_user(email: Option<String>) -> Result<String, ()> {
    email.filter(|email| !email.trim().is_empty()).ok_or(())
}
fn new_code() -> String {
    const ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
    const ACCEPT_BELOW: u8 = 240;
    let mut characters = Vec::with_capacity(8);
    while characters.len() < 8 {
        let mut bytes = [0; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        characters.extend(
            bytes
                .into_iter()
                .filter(|byte| *byte < ACCEPT_BELOW)
                .take(8 - characters.len())
                .map(|byte| ALPHABET[(byte % ALPHABET.len() as u8) as usize]),
        );
    }
    let code = String::from_utf8(characters).expect("alphabet contains ASCII only");
    format!("{}-{}", &code[..4], &code[4..])
}

async fn bad_user_code(
    app: &App,
    headers: &HeaderMap,
    _user_code: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    let ip = client_ip(headers);
    let blocked = record_bad_ip(&mut *app.wrong_codes.lock().await, ip, Instant::now());
    if blocked {
        (StatusCode::LOCKED, err("wrong_code_limit"))
    } else {
        (StatusCode::BAD_REQUEST, err("invalid_user_code"))
    }
}
async fn start(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<Start>,
) -> Result<Json<Started>, (StatusCode, Json<serde_json::Value>)> {
    rate_limit(&app, &headers).await?;
    let mut raw = [0; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let device_code = URL_SAFE_NO_PAD.encode(raw);
    let user_code = new_code();
    sqlx::query(
        "INSERT INTO device_logins
            (device_code_hash, user_code, status, created_at, expires_at, client_info)
         VALUES ($1, $2, 'pending', now(), now() + interval '10 minutes', $3)",
    )
    .bind(hash(&device_code))
    .bind(&user_code)
    .bind(body.client_info.unwrap_or_default())
    .execute(&app.pool)
    .await
    .map_err(internal)?;
    let uri = format!("{}/", app.public.trim_end_matches('/'));
    Ok(Json(Started {
        device_code,
        user_code: user_code.clone(),
        verification_uri: uri.clone(),
        verification_uri_complete: format!("{}{}", uri, user_code),
        expires_in: 600,
        interval: 5,
    }))
}
async fn approve(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<UserCode>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    rate_limit(&app, &headers).await?;
    let token = match bearer(&headers) {
        Ok(token) => token,
        Err(_) => return Err(bad_user_code(&app, &headers, &body.user_code).await),
    };
    let user_response = app
        .http
        .get(format!("{}/auth/v1/user", app.url.trim_end_matches('/')))
        .header("apikey", &app.anon)
        .bearer_auth(token)
        .send()
        .await
        .map_err(internal)?;
    if !user_response.status().is_success() {
        return Err(bad_user_code(&app, &headers, &body.user_code).await);
    }
    let user: serde_json::Value = user_response.json().await.map_err(internal)?;
    let user_id = user["id"]
        .as_str()
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, err("invalid_token")))?;
    let result = sqlx::query(
        "UPDATE device_logins
         SET user_id = $1, status = 'approved'
         WHERE user_code = $2 AND status = 'pending'
           AND expires_at > now()",
    )
    .bind(user_id)
    .bind(normalize(&body.user_code))
    .execute(&app.pool)
    .await
    .map_err(internal)?;
    if result.rows_affected() != 1 {
        return Err(bad_user_code(&app, &headers, &body.user_code).await);
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn deny(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<UserCode>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    rate_limit(&app, &headers).await?;
    let token = match bearer(&headers) {
        Ok(token) => token,
        Err(_) => return Err(bad_user_code(&app, &headers, &body.user_code).await),
    };
    let user_response = app
        .http
        .get(format!("{}/auth/v1/user", app.url.trim_end_matches('/')))
        .header("apikey", &app.anon)
        .bearer_auth(token)
        .send()
        .await
        .map_err(internal)?;
    if !user_response.status().is_success() {
        return Err(bad_user_code(&app, &headers, &body.user_code).await);
    }
    let status: Option<String> = sqlx::query_scalar(
        "SELECT status
         FROM device_logins
         WHERE user_code = $1 AND expires_at > now()",
    )
    .bind(normalize(&body.user_code))
    .fetch_optional(&app.pool)
    .await
    .map_err(internal)?;
    if !status.as_deref().is_some_and(can_deny) {
        return Err(bad_user_code(&app, &headers, &body.user_code).await);
    }
    let result = sqlx::query(
        "UPDATE device_logins SET status = 'denied'
         WHERE user_code = $1 AND status = 'pending'
           AND expires_at > now()",
    )
    .bind(normalize(&body.user_code))
    .execute(&app.pool)
    .await
    .map_err(internal)?;
    if result.rows_affected() == 0 {
        return Err(bad_user_code(&app, &headers, &body.user_code).await);
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn info(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<UserCode>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    rate_limit(&app, &headers).await?;
    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT user_code, client_info FROM device_logins
         WHERE user_code = $1 AND status = 'pending'
           AND expires_at > now()",
    )
    .bind(normalize(&body.user_code))
    .fetch_optional(&app.pool)
    .await
    .map_err(internal)?;
    match row {
        Some((user_code, client_info)) => Ok(Json(
            serde_json::json!({"user_code":user_code,"client_info":client_info}),
        )),
        None => Err(bad_user_code(&app, &headers, &body.user_code).await),
    }
}
async fn rate_limit(
    app: &App,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let ip = client_ip(headers);
    let mut attempts = app.attempts.lock().await;
    let now = Instant::now();
    attempts.retain(|_, window| now.duration_since(window.started) < Duration::from_secs(120));
    let window = attempts.entry(ip).or_insert(RateWindow {
        started: now,
        count: 0,
    });
    if now.duration_since(window.started) >= Duration::from_secs(60) {
        window.started = now;
        window.count = 0;
    }
    window.count += 1;
    if window.count > 20 {
        return Err((StatusCode::TOO_MANY_REQUESTS, err("slow_down")));
    }
    Ok(())
}
fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .to_owned()
}
async fn poll(
    State(app): State<Arc<App>>,
    Json(body): Json<DeviceCode>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let device_code_hash = hash(&body.device_code);
    let poll_state = sqlx::query_as::<_, (String, Option<i64>, i64, i64)>(
        "SELECT status,
                EXTRACT(EPOCH FROM last_poll_at)::bigint,
                EXTRACT(EPOCH FROM expires_at)::bigint,
                EXTRACT(EPOCH FROM now())::bigint
         FROM device_logins WHERE device_code_hash = $1",
    )
    .bind(&device_code_hash)
    .fetch_optional(&app.pool)
    .await
    .map_err(internal)?
    .ok_or_else(|| (StatusCode::GONE, err("expired_token")))?;

    if is_expired(poll_state.2, poll_state.3) {
        return Err((StatusCode::GONE, err("expired_token")));
    }
    if should_slow_down(poll_state.1.map(|last_poll| poll_state.3 - last_poll)) {
        return Err((StatusCode::TOO_MANY_REQUESTS, err("slow_down")));
    }
    if can_claim_session(&poll_state.0, is_expired(poll_state.2, poll_state.3)) {
        let user: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT device_logins.user_id::text, auth.users.email
             FROM device_logins
             LEFT JOIN auth.users ON auth.users.id = device_logins.user_id
             WHERE device_logins.device_code_hash = $1
               AND device_logins.status = 'approved'
               AND device_logins.expires_at > now()",
        )
        .bind(&device_code_hash)
        .fetch_optional(&app.pool)
        .await
        .map_err(internal)?;
        let (expected_user_id, email) =
            user.ok_or_else(|| (StatusCode::CONFLICT, err("access_denied")))?;
        let email = email_for_user(email)
            .map_err(|()| (StatusCode::UNPROCESSABLE_ENTITY, email_required_error()))?;

        let user_id: Option<String> = sqlx::query_scalar::<_, String>(
            "UPDATE device_logins
             SET status = 'used'
             WHERE device_code_hash = $1
               AND status = 'approved'
               AND expires_at > now()
             RETURNING user_id::text",
        )
        .bind(&device_code_hash)
        .fetch_optional(&app.pool)
        .await
        .map_err(internal)?;
        let user_id = user_id.ok_or_else(|| (StatusCode::CONFLICT, err("access_denied")))?;
        if user_id != expected_user_id {
            return Err((StatusCode::CONFLICT, err("access_denied")));
        }
        let session = create_supabase_session(&app.http, &app.url, &app.anon, &app.service, &email)
            .await
            .map_err(internal)?;
        return Ok(Json(serde_json::json!({
            "access_token": session["access_token"],
            "refresh_token": session["refresh_token"],
            "expires_at": session["expires_at"],
            "supabase_url": app.url,
            "email": email,
            "user_id": user_id
        })));
    }
    match poll_state.0.as_str() {
        "pending" => {
            sqlx::query(
                "UPDATE device_logins SET last_poll_at = now()
                 WHERE device_code_hash = $1 AND status = 'pending' AND expires_at > now()",
            )
            .bind(&device_code_hash)
            .execute(&app.pool)
            .await
            .map_err(internal)?;
            Err((StatusCode::ACCEPTED, err("authorization_pending")))
        }
        "denied" => Err((StatusCode::FORBIDDEN, err("access_denied"))),
        "used" => Err((StatusCode::CONFLICT, err("access_denied"))),
        "approved" => Err((StatusCode::CONFLICT, err("access_denied"))),
        _ => Err((StatusCode::INTERNAL_SERVER_ERROR, err("server_error"))),
    }
}

fn email_required_error() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "error": "email_required",
        "error_description": "This GitHub account has no email address available to PMServers. Set a public email in GitHub, then run `pms login` again."
    }))
}

async fn create_supabase_session(
    http: &reqwest::Client,
    supabase_url: &str,
    anon_key: &str,
    service_key: &str,
    email: &str,
) -> AnyhowResult<serde_json::Value> {
    let link: serde_json::Value = http
        .post(format!(
            "{}/auth/v1/admin/generate_link",
            supabase_url.trim_end_matches('/')
        ))
        .header("apikey", service_key)
        .bearer_auth(service_key)
        .json(&serde_json::json!({"type":"magiclink","email":email}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let token_hash = link["properties"]["hashed_token"]
        .as_str()
        .or(link["hashed_token"].as_str())
        .ok_or_else(|| anyhow!("Supabase did not return a magic link token hash"))?;
    let session = http
        .post(format!(
            "{}/auth/v1/verify",
            supabase_url.trim_end_matches('/')
        ))
        .header("apikey", anon_key)
        .json(&serde_json::json!({"type":"magiclink","token_hash":token_hash}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(session)
}
fn normalize(user_code: &str) -> String {
    let code = user_code.to_ascii_uppercase().replace(['-', ' '], "");
    if code.len() == 8 && code.is_ascii() {
        format!("{}-{}", &code[..4], &code[4..])
    } else {
        code
    }
}
fn bearer(headers: &HeaderMap) -> Result<&str, (StatusCode, Json<serde_json::Value>)> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|x| x.to_str().ok())
        .and_then(|x| x.strip_prefix("Bearer "))
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, err("invalid_token")))
}
fn err(error: &str) -> Json<serde_json::Value> {
    Json(serde_json::json!({"error":error}))
}
fn internal<E: std::fmt::Display>(error: E) -> (StatusCode, Json<serde_json::Value>) {
    tracing::error!("request failed: {error}");
    (StatusCode::INTERNAL_SERVER_ERROR, err("server_error"))
}
async fn page(State(app): State<Arc<App>>) -> impl IntoResponse {
    let html = include_str!("../static/index.html")
        .replace("__SUPABASE_URL__", &app.url)
        .replace("__SUPABASE_ANON_KEY__", &app.anon);
    let mut response = Html(html).into_response();
    let csp=format!("default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; connect-src 'self' {}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'", app.url);
    response
        .headers_mut()
        .insert(header::CONTENT_SECURITY_POLICY, csp.parse().unwrap());
    response
        .headers_mut()
        .insert("x-frame-options", "DENY".parse().unwrap());
    response
}
async fn livez() -> StatusCode {
    StatusCode::OK
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn user_codes_use_the_safe_alphabet_and_grouping() {
        let code = new_code();
        assert_eq!(code.len(), 9);
        assert_eq!(&code[4..5], "-");
        assert!(code
            .chars()
            .filter(|c| *c != '-')
            .all(|character| b"BCDFGHJKLMNPQRSTVWXZ".contains(&(character as u8))));
    }

    #[test]
    fn code_input_is_normalized_for_lookup() {
        assert_eq!(normalize("bcdfghjk"), "BCDF-GHJK");
        assert_eq!(normalize("bcdf-ghjk"), "BCDF-GHJK");
        assert_eq!(normalize("bad"), "BAD");
    }

    #[test]
    fn expired_codes_are_rejected() {
        assert!(is_expired(99, 100));
        assert!(is_expired(100, 100));
        assert!(!is_expired(101, 100));
    }

    #[test]
    fn one_time_claim_requires_a_live_approved_code() {
        assert!(can_claim_session("approved", false));
        assert!(!can_claim_session("approved", true));
        assert!(!can_claim_session("used", false));
        assert!(!can_claim_session("pending", false));
    }

    #[test]
    fn poll_interval_requires_five_seconds() {
        assert!(should_slow_down(Some(4)));
        assert!(!should_slow_down(Some(5)));
        assert!(!should_slow_down(None));
    }

    #[test]
    fn fifth_wrong_code_blocks_the_ip_for_ten_minutes() {
        let now = Instant::now();
        let mut wrong_codes = HashMap::new();
        for attempt in 1..5 {
            assert!(!record_bad_ip(&mut wrong_codes, "192.0.2.1".into(), now));
            assert_eq!(attempt, wrong_codes["192.0.2.1"].count);
        }
        assert!(record_bad_ip(&mut wrong_codes, "192.0.2.1".into(), now));
        assert!(record_bad_ip(
            &mut wrong_codes,
            "192.0.2.1".into(),
            now + Duration::from_secs(599)
        ));
        assert!(!record_bad_ip(
            &mut wrong_codes,
            "192.0.2.1".into(),
            now + Duration::from_secs(601)
        ));
    }

    #[test]
    fn deny_only_applies_to_pending_codes() {
        assert!(can_deny("pending"));
        assert!(!can_deny("approved"));
        assert!(!can_deny("denied"));
        assert!(!can_deny("used"));
    }

    #[test]
    fn github_user_without_email_gets_actionable_error() {
        assert!(email_for_user(None).is_err());
        assert!(email_for_user(Some("  ".into())).is_err());
        assert_eq!(
            email_for_user(Some("user@example.com".into())).unwrap(),
            "user@example.com"
        );
        assert!(email_required_error()["error_description"]
            .as_str()
            .unwrap()
            .contains("public email"));
    }

    #[test]
    fn device_code_hash_is_stable_and_not_the_code() {
        let digest = hash("secret-device-code");
        assert_ne!(digest, "secret-device-code");
        assert_eq!(digest, hash("secret-device-code"));
    }

    #[tokio::test]
    async fn session_uses_admin_link_then_verifies_the_link_hash() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/admin/generate_link"))
            .and(header("apikey", "service-key"))
            .and(body_partial_json(
                json!({"type":"magiclink","email":"user@example.com"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "properties": {"hashed_token":"one-time-hash"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/verify"))
            .and(header("apikey", "anon-key"))
            .and(body_partial_json(
                json!({"type":"magiclink","token_hash":"one-time-hash"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token":"access","refresh_token":"refresh","expires_at":1234
            })))
            .expect(1)
            .mount(&server)
            .await;

        let session = create_supabase_session(
            &reqwest::Client::new(),
            &server.uri(),
            "anon-key",
            "service-key",
            "user@example.com",
        )
        .await
        .unwrap();
        assert_eq!(session["access_token"], "access");
        assert_eq!(session["refresh_token"], "refresh");
    }

    #[tokio::test]
    #[ignore = "requires local Supabase with 0010_device_logins.sql applied"]
    async fn local_supabase_sql_allows_one_claim_and_checks_expiry_deny_and_poll_interval() {
        let database_url = std::env::var("LOCAL_SUPABASE_DATABASE_URL")
            .expect("set LOCAL_SUPABASE_DATABASE_URL to the local Supabase database URL");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .expect("connect to local Supabase");
        let auth_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/admin/generate_link"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "properties": {"hashed_token":"integration-hash"}
            })))
            .expect(1)
            .mount(&auth_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/auth/v1/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token":"integration-access","refresh_token":"integration-refresh"
            })))
            .expect(1)
            .mount(&auth_server)
            .await;
        let prefix = format!("it-{}", hash(&new_code()));
        let approved_code = format!("{}-A", &prefix[..12]);
        let expired_code = format!("{}-E", &prefix[..12]);
        let denied_code = format!("{}-D", &prefix[..12]);
        let slow_code = format!("{}-S", &prefix[..12]);

        for (suffix, status, expiry) in [
            ("A", "approved", "now() + interval '1 minute'"),
            ("E", "approved", "now() - interval '1 minute'"),
            ("D", "pending", "now() + interval '1 minute'"),
            ("S", "pending", "now() + interval '1 minute'"),
        ] {
            let user_code = match suffix {
                "A" => &approved_code,
                "E" => &expired_code,
                "D" => &denied_code,
                _ => &slow_code,
            };
            let insert = format!(
                "INSERT INTO device_logins (device_code_hash, user_code, status, expires_at)
                 VALUES ($1, $2, $3, {})",
                expiry
            );
            sqlx::query(&insert)
                .bind(hash(user_code))
                .bind(user_code)
                .bind(status)
                .execute(&pool)
                .await
                .unwrap();
        }

        let claim = || async {
            sqlx::query_scalar::<_, String>(
                "UPDATE device_logins
                 SET status = 'used'
                 WHERE device_code_hash = $1
                   AND status = 'approved'
                   AND expires_at > now()
                 RETURNING user_code",
            )
            .bind(hash(&approved_code))
            .fetch_optional(&pool)
            .await
            .unwrap()
        };
        let (first_claim, second_claim) = tokio::join!(claim(), claim());
        assert_eq!(
            usize::from(first_claim.is_some()) + usize::from(second_claim.is_some()),
            1
        );
        let mut session_count = 0;
        for claim_result in [first_claim, second_claim] {
            if claim_result.is_some() {
                create_supabase_session(
                    &reqwest::Client::new(),
                    &auth_server.uri(),
                    "anon-key",
                    "service-key",
                    "integration@example.com",
                )
                .await
                .unwrap();
                session_count += 1;
            }
        }
        assert_eq!(session_count, 1);

        let expired_claim = sqlx::query_scalar::<_, String>(
            "UPDATE device_logins
             SET status = 'used'
             WHERE device_code_hash = $1
               AND status = 'approved'
               AND expires_at > now()
             RETURNING user_code",
        )
        .bind(hash(&expired_code))
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert!(expired_claim.is_none());

        sqlx::query(
            "UPDATE device_logins
             SET status = 'denied'
             WHERE user_code = $1 AND status = 'pending' AND expires_at > now()",
        )
        .bind(&denied_code)
        .execute(&pool)
        .await
        .unwrap();
        let denied_status: String = sqlx::query_scalar(
            "SELECT status
             FROM device_logins
             WHERE user_code = $1",
        )
        .bind(&denied_code)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(denied_status, "denied");

        sqlx::query(
            "UPDATE device_logins SET last_poll_at = now() - interval '2 seconds'
             WHERE user_code = $1",
        )
        .bind(&slow_code)
        .execute(&pool)
        .await
        .unwrap();
        let seconds_since_poll: i64 = sqlx::query_scalar(
            "SELECT EXTRACT(EPOCH FROM now() - last_poll_at)::bigint
             FROM device_logins WHERE user_code = $1",
        )
        .bind(&slow_code)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(should_slow_down(Some(seconds_since_poll)));

        sqlx::query(
            "DELETE FROM device_logins
             WHERE user_code = ANY($1)",
        )
        .bind([&approved_code, &expired_code, &denied_code, &slow_code])
        .execute(&pool)
        .await
        .unwrap();
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let database = std::env::var("DATABASE_URL").expect("DATABASE_URL required");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database)
        .await
        .expect("database connection failed");
    let _ = sqlx::query(
        "DELETE FROM device_logins
         WHERE expires_at <= now()",
    )
    .execute(&pool)
    .await;
    let cleanup = pool.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            let _ = sqlx::query(
                "DELETE FROM device_logins
                 WHERE expires_at <= now()",
            )
            .execute(&cleanup)
            .await;
        }
    });
    let app = Arc::new(App {
        pool,
        http: reqwest::Client::new(),
        url: std::env::var("SUPABASE_URL").expect("SUPABASE_URL required"),
        anon: std::env::var("SUPABASE_ANON_KEY").expect("SUPABASE_ANON_KEY required"),
        service: std::env::var("SUPABASE_SERVICE_ROLE_KEY")
            .expect("SUPABASE_SERVICE_ROLE_KEY required"),
        public: std::env::var("PUBLIC_URL").unwrap_or_else(|_| "https://auth.pmservers.org".into()),
        attempts: Arc::new(Mutex::new(HashMap::new())),
        wrong_codes: Arc::new(Mutex::new(HashMap::new())),
    });
    let router = Router::new()
        .route("/", get(page))
        .route("/{user_code}", get(page))
        .route("/device", post(start))
        .route("/device/info", post(info))
        .route("/device/approve", post(approve))
        .route("/device/deny", post(deny))
        .route("/device/token", post(poll))
        .route("/livez", get(livez))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, router).await.unwrap();
}
