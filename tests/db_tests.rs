use sqlx::PgPool;
use uuid::Uuid;

// A helper function to quickly set up a test database pool
async fn get_test_pool() -> PgPool {
    dotenvy::dotenv().ok();
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgPool::connect(&db_url).await.unwrap()
}

#[tokio::test]
async fn test_create_user_and_organization() {
    let pool = get_test_pool().await;

    // 1. Test insertion of a mock user
    let user_email = format!("test-{}@example.com", Uuid::new_v4());
    let user_id: Uuid = sqlx::query_scalar!(
        r#"
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        RETURNING id
        "#,
        user_email,
        "hashed_password_placeholder"
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    // 2. Test insertion of a mock organization
    let org_id: Uuid = sqlx::query_scalar!(
        r#"
        INSERT INTO organizations (name)
        VALUES ($1)
        RETURNING id
        "#,
        "Test Corp"
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    // 3. Test building a membership link
    let membership_id: Uuid = sqlx::query_scalar!(
        r#"
        INSERT INTO memberships (user_id, organization_id)
        VALUES ($1, $2)
        RETURNING id
        "#,
        user_id,
        org_id
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert!(membership_id.to_string().len() > 0);
}
