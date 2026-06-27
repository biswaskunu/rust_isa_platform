use axum::{routing::post, Router};
use tower::ServiceExt; 
use axum::http::{Request, StatusCode};
use mime::APPLICATION_JSON;

// Tell the integration test crate how to compile your local modules directly
#[path = "../src/models.rs"]
pub mod models;
#[path = "../src/handlers/mod.rs"]
pub mod handlers;
#[path = "../src/middleware.rs"]
pub mod middleware;

#[tokio::test]
async fn test_registration_endpoint_format() {
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://localhost/test".to_string());
    let pool = sqlx::PgPool::connect_lazy(&db_url).unwrap();

    // Now we can access them cleanly using the locally compiled module path
    let app = Router::new()
        .route("/auth/register", post(handlers::auth::register))
        .with_state(pool);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register")
                .header("content-type", APPLICATION_JSON.as_ref())
                .body(axum::body::Body::from(r#"{"email":"test_integration@mail.com","password":"password123"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.status() == StatusCode::CREATED || response.status() == StatusCode::BAD_REQUEST);
}