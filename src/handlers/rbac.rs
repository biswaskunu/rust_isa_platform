use axum::{extract::{Path, State, Query}, http::StatusCode, Json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::middleware::AuthenticatedUser;
use crate::models::{
    CreateRoleRequest, UpdateRoleRequest, RoleResponse, 
    CreatePermissionRequest, PermissionResponse, RoleFilterParams,
    AssignPermissionRequest
};





// ROLES CRUD MANAGEMENT


// check permission
async fn check_permission(
    pool: &PgPool,
    user_id: Uuid,
    required_permission: &str,
) -> Result<(), (StatusCode, String)> {

    let has_access = sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM memberships m
            JOIN member_roles mr ON m.id = mr.membership_id
            JOIN roles r ON mr.role_id = r.id
            JOIN role_permissions rp ON r.id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.id
            WHERE m.user_id = $1 AND p.name = $2
        )
        "#,
        user_id,
        required_permission
    )
    .fetch_one(pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Auth Engine processing error".to_string()))?;

    if Some(true) == has_access {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "Access Denied: You do not have the required permissions for this organization".to_string()))
    }
}



// POST /roles
pub async fn create_role(
    State(pool): State<PgPool>,
    user: AuthenticatedUser, // Validates authentication
    Json(payload): Json<CreateRoleRequest>,
) -> Result<Json<RoleResponse>, (StatusCode, String)> {


    if check_permission(&pool, user.user_id, "role:create")
        .await.is_err() {
            return Err((StatusCode::FORBIDDEN, "Access Denied: You do not have the required permissions for this organization".to_string()));
    }

    let role = sqlx::query_as!(
        RoleResponse,
        "INSERT INTO roles (organization_id, name) VALUES ($1, $2) RETURNING id, organization_id, name",
        payload.organization_id,
        payload.name
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to create role: {}", e)))?;


    sqlx::query!(
        "INSERT INTO audit_logs (actor_id, action, resource) VALUES ($1, $2, $3)",
        user.user_id,
        "ROLE_CREATED",
        role.name
    )
    .execute(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Audit log failed".to_string()))?;


    Ok(Json(role))
}

// GET /roles?search=Admin&limit=10&offset=0
pub async fn list_roles(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Query(params): Query<RoleFilterParams>,
) -> Result<Json<Vec<RoleResponse>>, (StatusCode, String)> {


    if check_permission(&pool, user.user_id, "role:list")
        .await.is_err() {
            return Err((StatusCode::FORBIDDEN, "Access Denied: You do not have the required permissions for this organization".to_string()));
    }

    let search_pattern = format!("%{}%", params.search.unwrap_or_default());
    let limit = params.limit.unwrap_or(20);
    let offset = params.offset.unwrap_or(0);

    let roles = sqlx::query_as!(
        RoleResponse,
        r#"
        SELECT id, organization_id, name FROM roles 
        WHERE name ILIKE $1
        LIMIT $2 OFFSET $3
        "#,
        search_pattern,
        limit,
        offset
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to list roles".to_string()))?;

    Ok(Json(roles))
}

// PATCH /roles/{id}
pub async fn update_role(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Path(role_id): Path<Uuid>,
    Json(payload): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>, (StatusCode, String)> {


    if check_permission(&pool, user.user_id, "role:update")
        .await.is_err() {
            return Err((StatusCode::FORBIDDEN, "Access Denied: You do not have the required permissions for this organization".to_string()));
    }
    
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
    user: AuthenticatedUser,
    Path(role_id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {

    if check_permission(&pool, user.user_id, "role:delete")
        .await.is_err() {
            return Err((StatusCode::FORBIDDEN, "Access Denied: You do not have the required permissions for this organization".to_string()));
    }

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



// PERMISSIONS CRUD MANAGEMENT

// POST /permissions
pub async fn create_permission(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Json(payload): Json<CreatePermissionRequest>,
) -> Result<Json<PermissionResponse>, (StatusCode, String)> {

    if check_permission(&pool, user.user_id, "permission:create")
        .await.is_err() {
            return Err((StatusCode::FORBIDDEN, "Access Denied: You do not have the required permissions for this organization".to_string()));
    }

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
    user: AuthenticatedUser,
) -> Result<Json<Vec<PermissionResponse>>, (StatusCode, String)> {

    if check_permission(&pool, user.user_id, "permission:list")
        .await.is_err() {
            return Err((StatusCode::FORBIDDEN, "Access Denied: You do not have the required permissions for this organization".to_string()));
    }

    let permissions = sqlx::query_as!(
        PermissionResponse,
        "SELECT id, name FROM permissions"
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to list permissions".to_string()))?;

    Ok(Json(permissions))
}


// POST /roles/:id/permissions
pub async fn assign_permission_to_role(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Path(role_id): Path<Uuid>,
    Json(payload): Json<AssignPermissionRequest>,
) -> Result<StatusCode, (StatusCode, String)> {

    if check_permission(&pool, user.user_id, "role:update")
        .await.is_err() {
            return Err((StatusCode::FORBIDDEN, "Access Denied: You do not have the required permissions for this organization".to_string()));
    }

    sqlx::query!(
        "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        role_id,
        payload.permission_id
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to assign permission: {}", e)))?;

    sqlx::query!(
        "INSERT INTO audit_logs (actor_id, action, resource) VALUES ($1, $2, $3)",
        user.user_id,
        "PERMISSION_ASSIGNED",
        format!("role:{} permission:{}", role_id, payload.permission_id)
    )
    .execute(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Audit log failed".to_string()))?;

    Ok(StatusCode::CREATED)
}