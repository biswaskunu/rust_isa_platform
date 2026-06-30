use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::Utc;

// used inside our JWT token
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,      // User ID
    pub exp: usize,     // Expiration timestamp
    pub token_type: String, // "access" or "refresh"
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub token_type: String,
}


// allow admin to assign roles

#[derive(serde::Deserialize)]
pub struct CreateOrgRequest {
    pub name: String,
}

#[derive(serde::Serialize)]
pub struct OrgResponse {
    pub id: uuid::Uuid,
    pub name: String,
}

#[derive(serde::Deserialize)]
pub struct AssignRoleRequest {
    pub user_id: uuid::Uuid,
    pub role_name: String,
}


#[derive(serde::Serialize)]
pub struct UserProfile {
    pub id: uuid::Uuid,
    pub email: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}



#[derive(serde::Deserialize)]
pub struct CreateRoleRequest {
    pub organization_id: uuid::Uuid,
    pub name: String,
}

#[derive(serde::Deserialize)]
pub struct UpdateRoleRequest {
    pub name: String,
}

#[derive(serde::Serialize)]
pub struct RoleResponse {
    pub id: uuid::Uuid,
    pub organization_id: uuid::Uuid,
    pub name: String,
}

#[derive(serde::Deserialize)]
pub struct CreatePermissionRequest {
    pub name: String,
}

#[derive(serde::Serialize)]
pub struct PermissionResponse {
    pub id: uuid::Uuid,
    pub name: String,
}


// api keys payloads
#[derive(serde::Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
}

#[derive(serde::Serialize)]
pub struct CreateApiKeyResponse {
    pub id: uuid::Uuid,
    pub name: String,
    pub plaintext_key: String, 
}

#[derive(serde::Serialize)]
pub struct ApiKeyResponse {
    pub id: uuid::Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}


#[derive(serde::Deserialize)]
pub struct UpdateOrgRequest {
    pub name: String,
}

#[derive(serde::Deserialize)]
pub struct UpdateProfileRequest {
    pub email: Option<String>,
    
}

#[derive(serde::Deserialize)]
pub struct AssignMemberRoleRequest {
    pub role_id: uuid::Uuid,
}

#[derive(serde::Deserialize)]
pub struct RoleFilterParams {
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(serde::Deserialize)]
pub struct AssignPermissionRequest {
    pub permission_id: uuid::Uuid,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub id: Uuid,
    pub created_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}
