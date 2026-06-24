use sqlx::postgres::PgPoolOptions;
use std::env;
use dotenvy::dotenv;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables from .env file
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL environment variable must be set");

    // Create a database connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    // Run pending migrations programmatically on startup
    sqlx::migrate!("./migrations").run(&pool).await?;

    println!("🚀 Database successfully connected and migrations applied!");

    Ok(())
}