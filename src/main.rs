use axum::{routing::{get, post}, Router};
use sqlx::postgres::PgPoolOptions;
use std::env;
use dotenvy::dotenv;

pub mod models;
pub mod handlers;
pub mod middleware;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    let app = Router::new()
        // Auth Routes
        .route("/auth/register", post(handlers::auth::register))
        .route("/auth/login", post(handlers::auth::login))
        .route("/sessions", get(handlers::auth::get_sessions))
        
        // Organization and RBAC Engine Routes
        .route("/organizations", post(handlers::org::create_organization))
        .route("/organizations/:org_id/users", post(handlers::org::create_user_in_org))
        
        // authentication routes
        .route("/users/me", get(|user: middleware::AuthenticatedUser| async move {
            format!("Hello User! Your authenticated ID is: {}", user.user_id)
        }))
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("🚀 IAM Gateway running on http://127.0.0.1:3000");
    axum::serve(listener, app).await?;

    Ok(())
}