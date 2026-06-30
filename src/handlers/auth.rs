use axum::extract::Path;
use axum::{extract::State, http::StatusCode, Json};
use bcrypt::{hash, DEFAULT_COST};
use jsonwebtoken::{decode, encode, Header, EncodingKey, DecodingKey, Validation};
use sqlx::PgPool;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use sha2::{Sha256, Digest};
use hex;

use crate::models::{RegisterRequest, LoginRequest, Claims,UserProfile, UpdateProfileRequest};
use crate::middleware::AuthenticatedUser;


//checking valid inputs
fn validate_email(email: &str) -> bool {
    // Basic check: has exactly one @, with content on both sides
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len()  == 1 {
        return false;
    }

    !parts[0].is_empty() && parts[1].contains('.')
}

fn validate_password(password: &str) -> bool {
    password.len() >= 8
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub id: Uuid,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

// registers user in users table and makes audit logs
pub async fn register(
    State(pool): State<PgPool>,
    Json(payload): Json<RegisterRequest>,
) -> Result<StatusCode, (StatusCode, String)> {

    if !validate_email(&payload.email) {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "Invalid email format".to_string()));
    }
    if !validate_password(&payload.password) {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "Password must be at least 8 characters".to_string()));
    }

    // get password
    let hashed_password = hash(&payload.password, DEFAULT_COST)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to hash password".to_string()))?;

    // Create a transaction block to insert user and write audit trail safely
    // so if anything fails, it rolls back completely
    
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
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {

    if !validate_email(&payload.email) {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "Invalid email format".to_string()));
    }
    if payload.password.is_empty() {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "Password is required".to_string()));
    }

    let user = sqlx::query!(
        "SELECT id, email, password_hash FROM users WHERE email = $1",
        payload.email
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?
    .ok_or((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()))?;

    let valid = bcrypt::verify(&payload.password, &user.password_hash)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Auth error".to_string()))?;
    
    if !valid {
        return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()));
    }

    let access_token  = generate_token(user.id, "access", 15)?;
    let refresh_token = generate_token(user.id, "refresh", 60 * 24 * 7)?; // 7 days

    let access_hash  = hash_token(&access_token);
    let refresh_hash = hash_token(&refresh_token);

    let session_expiry_time  = Utc::now() + chrono::Duration::minutes(15);
    let refresh_expiry_time  = Utc::now() + chrono::Duration::days(7);

    sqlx::query!(
        "INSERT INTO sessions (user_id, token_hash, expires_at, refresh_token_hash, refresh_token_expires_at)
         VALUES ($1, $2, $3, $4, $5)",
        user.id,
        access_hash,
        session_expiry_time,
        refresh_hash,
        refresh_expiry_time
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Session error: {}", e)))?;

    sqlx::query!(
        "INSERT INTO audit_logs (actor_id, action, resource) VALUES ($1, $2, $3)",
        user.id,
        "USER_LOGGED_IN",
        user.email
    )
    .execute(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Audit log failed".to_string()))?;

    Ok(Json(serde_json::json!({
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "token_type":    "Bearer",
        "expires_in":    900
    })))
}

fn generate_token(
    user_id: Uuid,
    token_type: &str,
    duration_minutes: i64
) -> Result<String, (StatusCode, String)> {

    let jwt_secret = std::env::var("JWT_SECRET")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Server misconfiguration".to_string()))?;

    let expiry = Utc::now()
        .checked_add_signed(chrono::Duration::minutes(duration_minutes))
        .unwrap();

    let claims = Claims {
        sub: user_id,
        exp: expiry.timestamp() as usize,
        token_type: token_type.to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Token generation failed".to_string()))
}

fn hash_token(
    token: &str
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}


// POST /auth/logout
pub async fn logout(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
) -> Result<StatusCode, (StatusCode, String)> {
    // In a real scenario extract the specific session ID from the request.
    // For simplicity, we will revoke all active sessions for this user.
    sqlx::query!(
        "DELETE FROM sessions WHERE user_id = $1",
        user.user_id
    )
    .execute(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to logout".to_string()))?;

    Ok(StatusCode::OK)
}



// SESSIONS MANAGEMENT
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

// DELETE /sessions/{id}
pub async fn revoke_session(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    
    let rows_affected = sqlx::query!(
        "DELETE FROM sessions WHERE id = $1 AND user_id = $2",
        session_id,
        user.user_id
    )
    .execute(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?
    .rows_affected();

    if rows_affected == 0 {
        return Err((StatusCode::NOT_FOUND, "Session not found".to_string()));
    }

    Ok(StatusCode::NO_CONTENT)
}


#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

pub async fn refresh_token(
    State(pool): State<PgPool>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {

    if payload.refresh_token.is_empty() {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "Refresh token is required".to_string()));
    }

    let jwt_secret = std::env::var("JWT_SECRET")
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Server misconfiguration".to_string()))?;

    // Decode and validate it's actually a refresh token
    let token_data = decode::<Claims>(
        &payload.refresh_token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired refresh token".to_string()))?;

    if token_data.claims.token_type != "refresh" {
        return Err((StatusCode::UNAUTHORIZED, "Wrong token type".to_string()));
    }

    let user_id = token_data.claims.sub;

    let refresh_hash = hash_token(&payload.refresh_token);

    // Look up the session by refresh token hash
    let session = sqlx::query!(
        "SELECT id FROM sessions
         WHERE refresh_token_hash = $1
           AND refresh_token_expires_at > NOW()",
        refresh_hash
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?
    .ok_or((StatusCode::UNAUTHORIZED, "Refresh token not found or expired".to_string()))?;

    // Issue new access + refresh tokens (rotation)
    let new_access  = generate_token(user_id, "access", 15)?;
    let new_refresh = generate_token(user_id, "refresh", 60 * 24 * 7)?;

    let new_access_hash  = hash_token(&new_access);
    let new_refresh_hash = hash_token(&new_refresh);

    let new_session_expiry = Utc::now() + chrono::Duration::minutes(15);
    let new_refresh_expiry = Utc::now() + chrono::Duration::days(7);

    // Update the existing session row with new tokens
    sqlx::query!(
        "UPDATE sessions
         SET token_hash = $1, expires_at = $2,
             refresh_token_hash = $3, refresh_token_expires_at = $4
         WHERE id = $5",
        new_access_hash,
        new_session_expiry,
        new_refresh_hash,
        new_refresh_expiry,
        session.id
    )
    .execute(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Session update failed".to_string()))?;

    Ok(Json(serde_json::json!({
        "access_token":  new_access,
        "refresh_token": new_refresh,
        "token_type":    "Bearer",
        "expires_in":    900
    })))
}


// GET /users/me
pub async fn get_profile(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
) -> Result<Json<UserProfile>, (StatusCode, String)> {

    let profile = sqlx::query_as!(
        UserProfile,
        "SELECT id, email, created_at FROM users WHERE id = $1",
        user.user_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

    Ok(Json(profile))
}

// PATCH /users/me
pub async fn update_profile(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Json(payload): Json<UpdateProfileRequest>,
) -> Result<Json<UserProfile>, (StatusCode, String)> {
    let current_profile = sqlx::query!("SELECT email FROM users WHERE id = $1", user.user_id)
        .fetch_optional(&pool)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?
        .ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

    // Fallback to existing email if no new email is supplied in payload
    let target_email = payload.email.unwrap_or(current_profile.email);

    let updated_user = sqlx::query_as!(
        UserProfile,
        "UPDATE users SET email = $1 WHERE id = $2 RETURNING id, email, created_at",
        target_email,
        user.user_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Profile update failed: {}", e)))?;

    Ok(Json(updated_user))
}






// TESTS

// NOTE: tests in this module mutate the JWT_SECRET env var 
// run single-threaded: `cargo test -- --test-threads=1` for reliable results
#[cfg(test)]
mod tests {
    use super::*;
    use bcrypt::{hash, verify, DEFAULT_COST};

    #[test]
    fn test_valid_email_formats() {
        assert!(validate_email("user@example.com"));
        assert!(validate_email("user.name@domain.co.uk"));
        assert!(validate_email("user+tag@example.org"));
    }

    #[test]
    fn test_invalid_email_formats() {
        assert!(!validate_email("notanemail"));
        assert!(!validate_email("missing@dotcom"));
        assert!(!validate_email("@nodomain.com"));
        assert!(!validate_email(""));
        assert!(!validate_email("two@@at.com"));
    }

    #[test]
    fn test_password_validation() {
        assert!(validate_password("password123"));
        assert!(validate_password("exactly8"));
        assert!(!validate_password("short"));
        assert!(!validate_password(""));
        assert!(!validate_password("1234567")); // 7 chars, one under limit
    }

    #[test]
    fn test_password_hashing_and_verification() {
        let password = "mysecretpassword";
        let hashed = hash(password, DEFAULT_COST).unwrap();

        // Hash should not equal plaintext
        assert_ne!(password, hashed);

        // Correct password should verify
        assert!(verify(password, &hashed).unwrap());

        // Wrong password should not verify
        assert!(!verify("wrongpassword", &hashed).unwrap());
    }

    #[test]
    fn test_hash_token_is_deterministic() {
        let token = "some.jwt.token";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_token_different_inputs() {
        let hash1 = hash_token("token.one");
        let hash2 = hash_token("token.two");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_token_is_64_chars() {
        // SHA-256 hex output is always 64 characters
        let result = hash_token("any.input.token");
        assert_eq!(result.len(), 64);
    }

    #[tokio::test]
    async fn test_generate_token_contains_correct_type() {
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-for-unit-tests");
        }
        let user_id = uuid::Uuid::new_v4();

        let access_token = generate_token(user_id, "access", 15).unwrap();
        let refresh_token = generate_token(user_id, "refresh", 60).unwrap();

        // Decode and verify token_type claim
        let jwt_secret = std::env::var("JWT_SECRET").unwrap();

        let access_data = jsonwebtoken::decode::<Claims>(
            &access_token,
            &jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes()),
            &jsonwebtoken::Validation::default(),
        ).unwrap();

        let refresh_data = jsonwebtoken::decode::<Claims>(
            &refresh_token,
            &jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes()),
            &jsonwebtoken::Validation::default(),
        ).unwrap();

        assert_eq!(access_data.claims.token_type, "access");
        assert_eq!(refresh_data.claims.token_type, "refresh");
        assert_eq!(access_data.claims.sub, user_id);
    }

    #[tokio::test]
    async fn test_generate_token_expiry() {
        unsafe {
            std::env::set_var("JWT_SECRET", "test-secret-for-unit-tests");
        }
        let user_id = uuid::Uuid::new_v4();

        let token = generate_token(user_id, "access", 15).unwrap();

        let jwt_secret = std::env::var("JWT_SECRET").unwrap();
        let data = jsonwebtoken::decode::<Claims>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(jwt_secret.as_bytes()),
            &jsonwebtoken::Validation::default(),
        ).unwrap();

        // Expiry should be in the future
        let now = chrono::Utc::now().timestamp() as usize;
        assert!(data.claims.exp > now);
    }
}