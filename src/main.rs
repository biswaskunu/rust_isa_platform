use axum::{routing::{get, post, patch, delete}, Router};
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
        // Auth / User Routes
        .route("/auth/register", post(handlers::auth::register))
        .route("/auth/login", post(handlers::auth::login))
        .route("/auth/logout", post(handlers::auth::logout))
        .route("/sessions", get(handlers::auth::get_sessions))
        .route("/users/me", get(handlers::auth::get_profile).patch(handlers::auth::update_profile)) // Chained patch here!
        
        // Organization Routes
        .route("/organizations", post(handlers::org::create_organization).get(handlers::org::list_organizations)) // Chained get here!
        .route("/organizations/:org_id", get(handlers::org::get_organization).patch(handlers::org::update_organization)) // New profile routes
        .route("/organizations/:org_id/users", post(handlers::org::create_user_in_org))
        
        // Roles CRUD Routes
        .route("/roles", post(handlers::rbac::create_role).get(handlers::rbac::list_roles))
        .route("/roles/:id", patch(handlers::rbac::update_role).delete(handlers::rbac::delete_role))
        
        // Permissions CRUD Routes
        .route("/permissions", post(handlers::rbac::create_permission).get(handlers::rbac::list_permissions))
        
        // API Keys Management Routes
        .route("/api-keys", post(handlers::api_key::create_api_key).get(handlers::api_key::list_api_keys))
        .route("/api-keys/:id", delete(handlers::api_key::delete_api_key))
        
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("🚀 IAM Gateway running on http://127.0.0.1:3000");
    axum::serve(listener, app).await?;

    Ok(())
}