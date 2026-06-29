use axum::{extract::{Path, State}, http::StatusCode, Json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::middleware::AuthenticatedUser;
use crate::models::{CreateOrgRequest, OrgResponse, UpdateOrgRequest, AssignRoleRequest};



// 1. Create a new organization and bootstrap its administrative roles
pub async fn create_organization(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Json(payload): Json<CreateOrgRequest>,
) -> Result<Json<OrgResponse>, (StatusCode, String)> {

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

    
    // Assign this role to our user's membership
    sqlx::query!(
        "INSERT INTO member_roles (membership_id, role_id) VALUES ($1, $2)",
        membership.id,
        role.id
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;


    let org_update_perm = sqlx::query!(
        "SELECT id FROM permissions WHERE name = 'org:update'")
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Permission missing".to_string()))?;

    // Attach the 'user:create' permission directly to our new Owner role
    sqlx::query!(
        "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
        role.id,
        org_update_perm.id
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;


    let role_assign_perm = sqlx::query!(
        "SELECT id FROM permissions WHERE name = 'role:assign'")
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Permission missing".to_string()))?;

    sqlx::query!(
        "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
        role.id,
        role_assign_perm.id
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;


    // audit logs
    sqlx::query!(
        "INSERT INTO audit_logs (actor_id, action, resource) VALUES ($1, $2, $3)",
        user.user_id,
        "ORGANIZATION_CREATED",
        org.name
    )
    .execute(&mut *tx)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Audit log failed".to_string()))?;


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
    // Call validation logic
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



// POST /organizations/:org_id/memberships
pub async fn add_org_member(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Path(org_id): Path<Uuid>,
    Json(payload): Json<AssignRoleRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 1. RBAC Validation: Check if the calling actor has permission to manage members
    check_permission(&pool, user.user_id, org_id, "user:create").await?;

    // 2. Add the target user to memberships table
    sqlx::query!(
        "INSERT INTO memberships (user_id, organization_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        payload.user_id,
        org_id
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to add member: {}", e)))?;


    //audit logs
    sqlx::query!(
        "INSERT INTO audit_logs (actor_id, action, resource) VALUES ($1, $2, $3)",
        user.user_id,
        "MEMBER_ADDED",
        payload.user_id.to_string()
    )
    .execute(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Audit log failed".to_string()))?;

    Ok(StatusCode::CREATED)
}


// GET /organizations (Lists all organizations the user belongs to)
pub async fn list_organizations(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<OrgResponse>>, (StatusCode, String)> {

    let orgs = sqlx::query_as!(
        OrgResponse,
        r#"
        SELECT o.id, o.name 
        FROM organizations o
        JOIN memberships m ON o.id = m.organization_id
        WHERE m.user_id = $1
        "#,
        user.user_id
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch organizations".to_string()))?;

    Ok(Json(orgs))
}

// GET /organizations/{id}
pub async fn get_organization(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Path(org_id): Path<Uuid>,
) -> Result<Json<OrgResponse>, (StatusCode, String)> {

    // Validate membership first
    let is_member = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM memberships WHERE user_id = $1 AND organization_id = $2)",
        user.user_id,
        org_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?;

    if Some(true) != is_member {
        return Err((StatusCode::FORBIDDEN, "Access Denied: You are not a member of this organization".to_string()));
    }

    let org = sqlx::query_as!(
        OrgResponse,
        "SELECT id, name FROM organizations WHERE id = $1",
        org_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "Organization not found".to_string()))?;

    Ok(Json(org))
}

// PATCH /organizations/{id}
pub async fn update_organization(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Path(org_id): Path<Uuid>,
    Json(payload): Json<UpdateOrgRequest>,
) -> Result<Json<OrgResponse>, (StatusCode, String)> {
    // RBAC Check: Ensure the user has permission to update organizations
    check_permission(&pool, user.user_id, org_id, "org:update").await?;

    let org = sqlx::query_as!(
        OrgResponse,
        "UPDATE organizations SET name = $1 WHERE id = $2 RETURNING id, name",
        payload.name,
        org_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "Organization not found".to_string()))?;

    Ok(Json(org))
}



#[derive(serde::Deserialize)]
pub struct AssignMemberRoleRequest {
    pub role_id: uuid::Uuid,
}
// POST /memberships/:id/roles
pub async fn assign_role_to_membership(
    State(pool): State<PgPool>,
    user: AuthenticatedUser,
    Path(membership_id): Path<Uuid>,
    Json(payload): Json<AssignMemberRoleRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    
    // Verify the membership exists and get the org_id so we can RBAC check
    let membership = sqlx::query!(
        "SELECT organization_id FROM memberships WHERE id = $1",
        membership_id
    )
    .fetch_optional(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string()))?
    .ok_or((StatusCode::NOT_FOUND, "Membership not found".to_string()))?;

    // Only someone with role:assign permission in that org can do this
    check_permission(&pool, user.user_id, membership.organization_id, "role:assign").await?;

    sqlx::query!(
        "INSERT INTO member_roles (membership_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        membership_id,
        payload.role_id
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to assign role: {}", e)))?;

    sqlx::query!(
        "INSERT INTO audit_logs (actor_id, action, resource) VALUES ($1, $2, $3)",
        user.user_id,
        "ROLE_ASSIGNED",
        format!("membership:{} role:{}", membership_id, payload.role_id)
    )
    .execute(&pool)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Audit log failed".to_string()))?;

    Ok(StatusCode::CREATED)
}