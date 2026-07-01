# IAM Platform

A production-grade Identity & Access Management backend built with Rust, Axum and PostgreSQL.

## Stack

- **Rust** + **Axum** — async HTTP framework
- **SQLx** + **PostgreSQL** — type-safe database access
- **JWT** — access + refresh token authentication
- **bcrypt** — password hashing
- **Docker Compose** — local development environment

## Architecture

```
Users → Memberships → Member Roles → Roles → Role Permissions → Permissions
```

Users belong to Organizations via Memberships. Memberships have Roles. Roles have Permissions. The authorization engine evaluates this chain to answer: can this user perform this action in this organization?

## Quick Start

Make sure Docker is running, then:

```bash
docker-compose up --build
```

The API will be available at `http://localhost:3000`.

To run locally without Docker:

```bash
# Copy and configure environment
cp .env.example .env

# Start just the database
docker-compose up -d db

# Run migrations and start the server
cargo run
```

## Environment Variables

| Variable | Description | Example |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://postgres:password@localhost:5432/iam_db` |
| `JWT_SECRET` | Secret key for signing JWTs | `your-secret-key` |

## API Reference

### Auth
| Method | Endpoint | Description | Auth |
|---|---|---|---|
| POST | `/auth/register` | Register a new user | No |
| POST | `/auth/login` | Login, returns access + refresh tokens | No |
| POST | `/auth/refresh` | Exchange refresh token for new token pair | No |
| POST | `/auth/logout` | Revoke all sessions | Yes |

### Users
| Method | Endpoint | Description | Auth |
|---|---|---|---|
| GET | `/users/me` | Get current user profile | Yes |
| PATCH | `/users/me` | Update current user profile | Yes |

### Sessions
| Method | Endpoint | Description | Auth |
|---|---|---|---|
| GET | `/sessions` | List active sessions | Yes |
| DELETE | `/sessions/:id` | Revoke a specific session | Yes |

### Organizations
| Method | Endpoint | Description | Auth |
|---|---|---|---|
| POST | `/organizations` | Create organization (bootstraps Owner role) | Yes |
| GET | `/organizations` | List organizations you belong to | Yes |
| GET | `/organizations/:id` | Get organization details | Yes |
| PATCH | `/organizations/:id` | Update organization (requires org:update) | Yes |
| POST | `/organizations/:org_id/memberships` | Add a member to an organization | Yes |

### Roles & Permissions
| Method | Endpoint | Description | Auth |
|---|---|---|---|
| POST | `/roles` | Create a role | Yes |
| GET | `/roles` | List roles (supports search, limit, offset) | Yes |
| PATCH | `/roles/:id` | Update a role | Yes |
| DELETE | `/roles/:id` | Delete a role | Yes |
| POST | `/roles/:id/permissions` | Assign a permission to a role | Yes |
| POST | `/memberships/:id/roles` | Assign a role to a membership | Yes |
| POST | `/permissions` | Create a permission | Yes |
| GET | `/permissions` | List all permissions | Yes |

### API Keys
| Method | Endpoint | Description | Auth |
|---|---|---|---|
| POST | `/api-keys` | Create API key (plaintext returned once) | Yes |
| GET | `/api-keys` | List your API keys | Yes |
| DELETE | `/api-keys/:id` | Delete an API key | Yes |

## Authorization Model

Permission checks follow this chain:

```sql
user → membership → member_roles → roles → role_permissions → permissions
```

When an organization is created, an Owner role is automatically bootstrapped with `org:update` and `role:assign` permissions and assigned to the creator.

## Security

- Passwords hashed with bcrypt
- JWTs signed with HS256, access tokens expire in 15 minutes
- Refresh tokens expire in 7 days with rotation on each use
- API keys and session tokens stored as SHA-256 hashes only
- JWT secret loaded from environment variable, never hardcoded

## Running Tests

```bash
cargo test
```