# rust_isa_platform

[Incoming Request] 
       │
       ▼
1. Extract User ID (From JWT via Middleware)
       │
       ▼
2. Get Target Organization ID (From Path/Query Parameter)
       │
       ▼
3. Run Database Query:
   Check if User → Member → Role → Has required Permission string?
       │
 ┌─────┴─────┐
 │           │
 ▼           ▼
[YES]       [NO]
Allow       Return 403 Forbidden