use axum::{extract::{Path, State}, http::StatusCode, Json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::middleware::AuthenticatedUser;
use crate::models::{CreateOrgRequest, OrgResponse, AssignRoleRequest};

// 1. Create a new organization and bootstrap its administrative roles
pub async fn create_organization(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Json(payload): Json<CreateOrgRequest>,
) -> Result<Json<OrgResponse>, (StatusCode, String)> {
    // Start a transaction so if anything fails, it rolls back completely
    let mut tx = pool.begin().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Transaction error".to_string()))?;

    // Insert Organization
    let org = sqlx::query!(
        "INSERT INTO organizations (name) VALUES ($1) RETURNING id, name",
        payload.name
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Create a membership entry linking this user to the org
    let membership = sqlx::query!(
        "INSERT INTO memberships (user_id, organization_id) VALUES ($1, $2) RETURNING id",
        user.user_id,
        org.id
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Create an "Owner" role specific to this organization
    let role = sqlx::query!(
        "INSERT INTO roles (organization_id, name) VALUES ($1, $2) RETURNING id",
        org.id,
        "Owner"
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Fetch the standard 'user:create' static permission ID we seeded in migrations
    let perm = sqlx::query!("SELECT id FROM permissions WHERE name = 'user:create'")
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Permission missing".to_string()))?;

    // Attach the 'user:create' permission directly to our new Owner role
    sqlx::query!(
        "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
        role.id,
        perm.id
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Assign this role to our user's membership
    sqlx::query!(
        "INSERT INTO member_roles (membership_id, role_id) VALUES ($1, $2)",
        membership.id,
        role.id
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    tx.commit().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Commit error".to_string()))?;

    Ok(Json(OrgResponse { id: org.id, name: org.name }))
}

// 2. Secured Resource Example: Adding a user inside an organization
pub async fn create_user_in_org(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Path(org_id): Path<Uuid>,
) -> Result<String, (StatusCode, String)> {
    // Call our specialized validation logic
    check_permission(&pool, user.user_id, org_id, "user:create").await?;

    Ok(format!("Successfully authorized! User {} was allowed to perform 'user:create' inside Organization {}", user.user_id, org_id))
}

// auth chechk
async fn check_permission(
    pool: &PgPool,
    user_id: Uuid,
    org_id: Uuid,
    required_permission: &str,
) -> Result<(), (StatusCode, String)> {
    let has_access = sqlx::query_scalar!(
        r#"
        SELECT EXISTS (
            SELECT 1 
            FROM memberships m
            JOIN member_roles mr ON m.id = mr.membership_id
            JOIN roles r ON mr.role_id = r.id
            JOIN role_permissions rp ON r.id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.id
            WHERE m.user_id = $1 
              AND m.organization_id = $2 
              AND r.organization_id = $2
              AND p.name = $3
        )
        "#,
        user_id,
        org_id,
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