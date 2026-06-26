use serde::{Deserialize, Serialize};
use uuid::Uuid;

// goes inside our JWT token
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,      // User ID
    pub exp: usize,     // Expiration timestamp
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