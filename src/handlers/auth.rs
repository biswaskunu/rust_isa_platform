use axum::{extract::State, http::StatusCode, Json};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, Header, EncodingKey};
use sqlx::PgPool;
use chrono::{Utc, Duration};
use serde::Serialize;
use uuid::Uuid;

use crate::models::{RegisterRequest, LoginRequest, AuthResponse, Claims};
use crate::middleware::AuthenticatedUser;

#[derive(Serialize)]
pub struct SessionResponse {
    pub id: Uuid,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

pub async fn register(
    State(pool): State<PgPool>,
    Json(payload): Json<RegisterRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let hashed_password = hash(&payload.password, DEFAULT_COST)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password".to_string()))?;

    // Create a transaction block to insert user and write audit trail safely
    let mut tx = pool.begin().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Transaction error".to_string()))?;

    let user_id: Uuid = sqlx::query_scalar!(
        "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id",
        payload.email,
        hashed_password
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("User registration failed: {}", e)))?;

    // Audit Log recording
    sqlx::query(
        "INSERT INTO audit_logs (actor_id, action, resource) VALUES ($1, $2, $3)"
    )
    .bind(user_id)
    .bind("USER_REGISTERED")
    .bind(payload.email)
    .execute(&mut *tx)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to log audit".to_string()))?;

    tx.commit().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Commit error".to_string()))?;

    Ok(StatusCode::CREATED)
}

pub async fn login(
    State(pool): State<PgPool>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    let user = sqlx::query!("SELECT id, password_hash FROM users WHERE email = $1", payload.email)
        .fetch_optional(&pool)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()))?;

    let is_valid = verify(&payload.password, &user.password_hash)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to verify password".to_string()))?;

    if !is_valid {
        return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()));
    }

    let expiration_duration = Duration::minutes(15);
    let expiration = Utc::now()
        .checked_add_signed(expiration_duration)
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user.id,
        exp: expiration,
    };

    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret("secret_key".as_ref()))
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Token generation failed".to_string()))?;

    // Create session database record and log audit tracking
    let mut tx = pool.begin().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Tx error".to_string()))?;

    let session_expiry = Utc::now() + Duration::days(7);
    
    sqlx::query!(
        "INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        user.id,
        &token[..30], // store a tiny fingerprint hash identifier of the token
        session_expiry
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    sqlx::query!(
        "INSERT INTO audit_logs (actor_id, action, resource) VALUES ($1, $2, $3)",
        user.id,
        "USER_LOGGED_IN",
        user.id.to_string()
    )
    .execute(&mut *tx)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Audit log fail".to_string()))?;

    tx.commit().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Commit error".to_string()))?;

    Ok(Json(AuthResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
    }))
}

// Get active sessions for the user
pub async fn get_sessions(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<SessionResponse>>, (StatusCode, String)> {
    let sessions = sqlx::query_as!(
        SessionResponse,
        "SELECT id, created_at, expires_at FROM sessions WHERE user_id = $1 AND expires_at > NOW()",
        user.user_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load sessions".to_string()))?;

    Ok(Json(sessions))
}