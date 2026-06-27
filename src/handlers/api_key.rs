use axum::{extract::{Path, State}, http::StatusCode, Json};
use sqlx::PgPool;
use uuid::Uuid;
use rand::{RngCore, thread_rng};
use sha2::{Sha256, Digest};

use crate::middleware::AuthenticatedUser;
use crate::models::{CreateApiKeyRequest, CreateApiKeyResponse, ApiKeyResponse};

// POST /api-keys
pub async fn create_api_key(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Json(payload): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, (StatusCode, String)> {
    // 1. Generate a secure, unguessable random string
    let mut random_bytes = [0u8; 32];
    thread_rng().fill_bytes(&mut random_bytes);
    let token = hex::encode(random_bytes);
    let plaintext_key = format!("iam_live_{}", token);

    // 2. Hash it using SHA-256 before saving to the database
    let mut hasher = Sha256::new();
    hasher.update(plaintext_key.as_bytes());
    let hashed_key = hex::encode(hasher.finalize());

    // 3. Save to database
    let row = sqlx::query!(
        "INSERT INTO api_keys (user_id, name, key_hash) VALUES ($1, $2, $3) RETURNING id, name",
        user.user_id,
        payload.name,
        hashed_key
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save API key: {}", e)))?;


    sqlx::query!(
        "INSERT INTO audit_logs (actor_id, action, resource) VALUES ($1, $2, $3)",
        user.user_id,
        "API_KEY_CREATED",
        payload.name
    )
    .execute(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Audit log failed".to_string()))?;

    Ok(Json(CreateApiKeyResponse {
        id: row.id,
        name: row.name,
        plaintext_key, // Return the token plaintext exactly once
    }))
}

// GET /api-keys
pub async fn list_api_keys(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<ApiKeyResponse>>, (StatusCode, String)> {
    let keys = sqlx::query_as!(
        ApiKeyResponse,
        "SELECT id, name, created_at FROM api_keys WHERE user_id = $1",
        user.user_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch API keys".to_string()))?;

    Ok(Json(keys))
}

// DELETE /api-keys/{id}
pub async fn delete_api_key(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Path(key_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let rows_affected = sqlx::query!(
        "DELETE FROM api_keys WHERE id = $1 AND user_id = $2",
        key_id,
        user.user_id
    )
    .execute(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?
    .rows_affected();

    if rows_affected == 0 {
        return Err((StatusCode::NOT_FOUND, "API Key not found or unauthorized".to_string()));
    }

    sqlx::query!(
        "INSERT INTO audit_logs (actor_id, action, resource) VALUES ($1, $2, $3)",
        user.user_id,
        "API_KEY_DELETED",
        key_id.to_string()
    )
    .execute(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Audit log failed".to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}