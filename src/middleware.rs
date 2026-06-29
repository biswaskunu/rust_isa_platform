use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use uuid::Uuid;
use crate::models::Claims;

pub struct AuthenticatedUser {
    pub user_id: Uuid,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization Header".to_string()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err((StatusCode::UNAUTHORIZED, "Invalid token format".to_string()));
        }
        let token = &auth_header[7..];


        let jwt_secret = std::env::var("JWT_SECRET")
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Server misconfiguration".to_string()))?;

        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired token".to_string()))?;
    
        // Ensure the token type is "access" and not "refresh"
        if token_data.claims.token_type != "access" {
            return Err((StatusCode::UNAUTHORIZED, "Wrong token type".to_string()));
        }

        Ok(AuthenticatedUser {
            user_id: token_data.claims.sub,
        })
    }
}