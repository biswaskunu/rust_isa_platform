use axum::{extract::{Path, State}, http::StatusCode, Json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::middleware::AuthenticatedUser;
use crate::models::{
    CreateRoleRequest, UpdateRoleRequest, RoleResponse, 
    CreatePermissionRequest, PermissionResponse
};

// ==========================================
// ROLES CRUD MANAGEMENT
// ==========================================

// POST /roles
pub async fn create_role(
    State(pool): State<PgPool>,
    _user: AuthenticatedUser, // Validates authentication
    Json(payload): Json<CreateRoleRequest>,
) -> Result<Json<RoleResponse>, (StatusCode, String)> {
    let role = sqlx::query_as!(
        RoleResponse,
        "INSERT INTO roles (organization_id, name) VALUES ($1, $2) RETURNING id, organization_id, name",
        payload.organization_id,
        payload.name
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to create role: {}", e)))?;

    Ok(Json(role))
}

// GET /roles
pub async fn list_roles(
    State(pool): State<PgPool>,
    _user: AuthenticatedUser,
) -> Result<Json<Vec<RoleResponse>>, (StatusCode, String)> {
    let roles = sqlx::query_as!(
        RoleResponse,
        "SELECT id, organization_id, name FROM roles"
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to list roles".to_string()))?;

    Ok(Json(roles))
}

// PATCH /roles/{id}
pub async fn update_role(
    State(pool): State<PgPool>,
    _user: AuthenticatedUser,
    Path(role_id): Path<Uuid>,
    Json(payload): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>, (StatusCode, String)> {
    let role = sqlx::query_as!(
        RoleResponse,
        "UPDATE roles SET name = $1 WHERE id = $2 RETURNING id, organization_id, name",
        payload.name,
        role_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "Role not found".to_string()))?;

    Ok(Json(role))
}

// DELETE /roles/{id}
pub async fn delete_role(
    State(pool): State<PgPool>,
    _user: AuthenticatedUser,
    Path(role_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let rows_affected = sqlx::query!("DELETE FROM roles WHERE id = $1", role_id)
        .execute(&pool)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?
        .rows_affected();

    if rows_affected == 0 {
        return Err((StatusCode::NOT_FOUND, "Role not found".to_string()));
    }

    Ok(StatusCode::NO_CONTENT)
}

// ==========================================
// PERMISSIONS CRUD MANAGEMENT
// ==========================================

// POST /permissions
pub async fn create_permission(
    State(pool): State<PgPool>,
    _user: AuthenticatedUser,
    Json(payload): Json<CreatePermissionRequest>,
) -> Result<Json<PermissionResponse>, (StatusCode, String)> {
    let permission = sqlx::query_as!(
        PermissionResponse,
        "INSERT INTO permissions (name) VALUES ($1) RETURNING id, name",
        payload.name
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to create permission: {}", e)))?;

    Ok(Json(permission))
}

// GET /permissions
pub async fn list_permissions(
    State(pool): State<PgPool>,
    _user: AuthenticatedUser,
) -> Result<Json<Vec<PermissionResponse>>, (StatusCode, String)> {
    let permissions = sqlx::query_as!(
        PermissionResponse,
        "SELECT id, name FROM permissions"
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to list permissions".to_string()))?;

    Ok(Json(permissions))
}