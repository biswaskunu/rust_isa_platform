use axum::{routing::{get, post}, Router, routing::patch};
use sqlx::postgres::PgPoolOptions;
use std::env;
use dotenvy::dotenv;

mod models;
mod handlers;
mod middleware;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    // Build server application state router
    let app = Router::new()
        // Public endpoints
        .route("/auth/register", post(handlers::auth::register))
        .route("/auth/login", post(handlers::auth::login))
        // Sample protected route using our extractor
        .route("/users/me", get(|user: middleware::AuthenticatedUser| async move {
            format!("Hello User! Your authenticated ID is: {}", user.user_id)
        }))
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("🚀 IAM Gateway running on http://127.0.0.1:3000");
    axum::serve(listener, app).await?;

    Ok(())
}