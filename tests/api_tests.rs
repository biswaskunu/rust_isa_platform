use axum::{routing::{get, post}, Router};
use tower::ServiceExt;
use axum::http::{Request, StatusCode};
use mime::APPLICATION_JSON;
use serde_json::json;

#[path = "../src/models.rs"]
pub mod models;
#[path = "../src/handlers/mod.rs"]
pub mod handlers;
#[path = "../src/middleware.rs"]
pub mod middleware;

// Helper to build the full app router for tests
async fn build_test_app() -> Router {
    dotenvy::dotenv().ok();
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:securepassword123@localhost:5432/iam_db".to_string());

    unsafe {
                std::env::set_var("JWT_SECRET", "test-secret-for-integration-tests");
    }
    let pool = sqlx::PgPool::connect_lazy(&db_url).unwrap();

    Router::new()
        .route("/auth/register", post(handlers::auth::register))
        .route("/auth/login",    post(handlers::auth::login))
        .route("/auth/refresh",  post(handlers::auth::refresh_token))
        .route("/users/me",      get(handlers::auth::get_profile))
        .with_state(pool)
}

fn json_body(val: serde_json::Value) -> axum::body::Body {
    axum::body::Body::from(val.to_string())
}



#[tokio::test]
async fn test_register_returns_201() {
    let app = build_test_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register")
                .header("content-type", APPLICATION_JSON.as_ref())
                .body(json_body(json!({
                    "email": format!("user-{}@example.com", uuid::Uuid::new_v4()),
                    "password": "securepassword"
                })))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

// Validation failures 

#[tokio::test]
async fn test_register_invalid_email_returns_422() {
    let app = build_test_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register")
                .header("content-type", APPLICATION_JSON.as_ref())
                .body(json_body(json!({
                    "email": "notanemail",
                    "password": "securepassword"
                })))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_register_short_password_returns_422() {
    let app = build_test_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register")
                .header("content-type", APPLICATION_JSON.as_ref())
                .body(json_body(json!({
                    "email": "valid@example.com",
                    "password": "short"
                })))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// Auth failures 

#[tokio::test]
async fn test_login_wrong_password_returns_401() {
    let app = build_test_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header("content-type", APPLICATION_JSON.as_ref())
                .body(json_body(json!({
                    "email": "test@example.com",
                    "password": "wrongpassword"
                })))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_login_nonexistent_user_returns_401() {
    let app = build_test_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header("content-type", APPLICATION_JSON.as_ref())
                .body(json_body(json!({
                    "email": "nobody@nowhere.com",
                    "password": "somepassword"
                })))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// Protected route failures 

#[tokio::test]
async fn test_protected_route_without_token_returns_401() {
    let app = build_test_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/users/me")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_protected_route_with_invalid_token_returns_401() {
    let app = build_test_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/users/me")
                .header("Authorization", "Bearer this.is.not.a.valid.token")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_refresh_with_invalid_token_returns_401() {
    let app = build_test_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/refresh")
                .header("content-type", APPLICATION_JSON.as_ref())
                .body(json_body(json!({
                    "refresh_token": "not.a.real.token"
                })))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}