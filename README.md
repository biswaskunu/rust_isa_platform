# Production-Grade Identity & Access Management (IAM) Backend

## System Design Architecture
This platform implements a robust Role-Based Access Control (RBAC) engine using Axum, Rust, and PostgreSQL.

### Core Architecture Entity Layout Diagram
[User] ──► [Membership] ──► [Member Roles] ──► [Roles] ──► [Role Permissions] ──► [Permissions]

## API Route Inventory
- `POST /auth/register` - Creates a user account with hashed credentials.
- `POST /auth/login` - Validates credentials, opens a persistent tracking session, and returns a JWT access token.
- `GET /sessions` - Lists active login sessions for the caller.
- `POST /organizations` - Bootstraps an organization workspace and establishes default ownership rights.
- `POST /organizations/:org_id/users` - Enforces permission engine lookups to evaluate access privileges.

## How to Spin Up the Platform Fast
Ensure Docker is running on your machine and execute:
```bash
docker-compose up --build