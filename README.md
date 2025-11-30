<div align="center">

![IAMClient4D Logo](images/IAMClient4D_logo.png)

IAMClient4D is a Delphi client library for integrating applications with Keycloak, providing full OAuth2/OpenID Connect support (including PKCE), token and user management, and a lightweight asynchronous task framework (Async.Core) for thread-safe operations across VCL and FMX.

### OAuth2/OpenID Connect Client for Delphi

**Production-ready OAuth2/OIDC integration for Delphi** with native Keycloak support, complete JWT validation, user management, and middleware for DMVCFramework.

[Features](#-key-features) • [Quick Start](#-quick-start) • [Documentation](#-table-of-contents) • [Examples](#-usage-examples) • [License](#-license)

</div>

---

## 📋 Table of Contents

- [⚡ Quick Reference](#-quick-reference)
- [Overview](#-overview)
- [Key Features](#-key-features)
- [Requirements](#-requirements)
  - [Integrated Libraries](#integrated-libraries)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
  - [Desktop Application (VCL/FMX)](#desktop-application-vclfmx)
  - [REST API Server (DMVCFramework)](#rest-api-server-dmvcframework)
  - [User Management](#user-management)
- [Architecture](#-architecture)
  - [Core Module](#1-core-module)
  - [Common Utilities](#2-common-utilities)
  - [Callback Management](#3-callback-management)
  - [Security (JWT, JWKS, SSL)](#4-security-jwt-jwks-ssl)
  - [Token Storage](#5-token-storage)
  - [User Management](#6-user-management-keycloak-admin-api)
  - [DMVCFramework Integration](#7-dmvcframework-integration)
  - [Async.Core](#8-asynccore)
- [Security](#-security)
- [License](#-license)
- [Contributing](#-contributing)
- [Roadmap](#-roadmap)

---

## ⚡ Quick Reference

Quick table to get started immediately with the most common features.

### OAuth2 Client - Desktop/Mobile

```pascal
// Configuration and Login
TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('https://keycloak.example.com', 'iamclient4d', 'demo_public')
  .WithScopes(['openid', 'profile', 'email'])
  .WithStrictSSL
  .BuildAsync
  .OnSuccess(procedure(const AClient: IIAM4DClient)
    begin
      AClient.StartAuthorizationFlowAsync.OnSuccess(...).Run;
    end)
  .Run;
```

### REST API - DMVCFramework

```pascal
// JWT Middleware (WebModule)
LMiddleware := TIAM4DJWTMiddleware.Create(
  'https://keycloak.example.com/realms/iamclient4d',  // Issuer
  'demo_public'                                     // Audience
);

// Controller - Authorization
Context.RequireAuthentication;
Context.RequireRealmRole('admin');

// Controller - Claim Access
var LUsername := Context.JWT.PreferredUsername;
var LEmail := Context.JWT.Email;
var LAge := Context.GetCustomClaimAsInteger('user_age', 18);
```

### User Management

```pascal
// Create User
LUser := TIAM4DUser.Create('john.doe', 'john.doe@example.com', 'John', 'Doe');
LUserManager.CreateUserAsync(LUser).Run;

// Assign Role (simplified)
LUserManager.AssignRoleByNameAsync(AUserID, 'admin').Run;

// Batch Import (1000 users)
LUserManager.CreateUsersAsync(LUsersArray).Run;

// Verification Email
LUserManager.SendVerifyEmailAsync(AUserID).Run;
```

### Most Used Methods

| Scenario | Method/Class | Example |
|----------|--------------|---------|
| **Desktop Login** | `TIAM4DClientConfigBuilder.ForAuthorizationCode()` | See [example](#2-desktop-application---authorization-code-flow) |
| **Server JWT Validation** | `TIAM4DJWTMiddleware` | See [example](#3-rest-api---jwt-validation-dmvcframework) |
| **Role Check Controller** | `Context.RequireRealmRole()` | `Context.RequireRealmRole('admin')` |
| **Create User** | `CreateUserAsync()` | See [example](#4-user-management---keycloak-admin-api) |
| **Assign Role** | `AssignRoleByNameAsync()` | `AssignRoleByNameAsync(userID, 'admin')` |
| **Batch Import** | `CreateUsersAsync()` | See [example](#batch-operations) |
| **Custom Claim** | `GetCustomClaimAsInteger()` | `Context.GetCustomClaimAsInteger('age', 0)` |
| **Error Handling** | `TIAM4DErrorCode` | See [section](#️-error-handling) |

### Quick Documentation Links

- 📘 [Complete Architecture](#-architecture)
- 🔐 [Security](#-security)
- ⚠️ [Error Handling](#️-error-handling)
- 👥 [Advanced User Management](#6-user-management-keycloak-admin-api)
- 🛡️ [Controller Helpers](#controller-helpers)

---

## 🎯 Overview

**IAMClient4D** is a complete, strongly-typed, and secure Delphi library for integrating OAuth2/OpenID Connect identity providers, with specific focus on **Keycloak**.

The library consistently covers both:

- **Client applications** (VCL/FMX) requiring interactive flows (Authorization Code + PKCE, callback handling, external browser)
- **Server applications** (e.g., REST with **DMVCFramework**) that need to validate incoming JWTs, extract claims, map roles, and protect endpoints

### Project Goals

1. **Standardize** IAM/OIDC integration in Delphi, eliminating boilerplate and duplicate code across projects
2. **Guarantee security and correctness** of OAuth2/OIDC flows:
   - PKCE implementation compliant with RFC 7636
   - State/nonce management
   - Rigorous JWT validation (signature + claims)
   - Secure in-memory token handling
3. **Expose clean and testable Delphi APIs** with strong typing and clear module separation

### Architectural Philosophy

- **Separation of concerns**: Each module has a single well-defined responsibility
- **Interfaces before implementations**: Storage, SSL validation, HTTP calls are replaceable abstractions
- **Security by design**: Code designed to prevent replay attacks, token leaks, with rigorous claim validation
- **Real-world oriented**: Native integration with DMVCFramework, user/role management via Admin API, support for real UI scenarios

---

## ✨ Key Features

### OAuth2/OIDC Client
- ✅ **Authorization Code Flow** with PKCE (RFC 7636)
- ✅ **Client Credentials Flow** for M2M scenarios
- ✅ **Automatic OIDC Discovery** (`/.well-known/openid-configuration`)
- ✅ **Token Management**: Automatic refresh, expiry tracking, secure storage
- ✅ **State/Nonce Validation**: CSRF and replay attack prevention
- ✅ **Callback Modes**: Local HTTP server (desktop) or external (web app)

### Security
- 🔒 **Complete JWT Validation**:
  - Cryptographic signature verification (RS256/RS384/RS512)
  - **12 claim validation** (iss, sub, aud, exp, nbf, iat, jti, typ, azp, kid, alg + signature)
  - Compliant with RFC 7519, RFC 7515, RFC 7523
  - `alg=none` blocking and algorithm allow-list
  - JWKS auto-discovery with cache and key rotation
- 🔒 **Configurable SSL Modes**: Strict, self-signed, custom validators
- 🔒 **Certificate Pinning**: SHA-256 public key pinning support
- 🔒 **Clock Skew Management**: Configurable tolerance for time differences
- 🔒 **AES-256-GCM Token Storage**: In-memory encryption with CSPRNG keys

### Keycloak Admin API
- 👥 **User Management**: Create, update, delete, search users
- 🎭 **Roles & Groups**: Realm roles, client roles, group membership
- 🔑 **Password Management**: Reset, temporary passwords, required actions
- 🌐 **Federated Identities**: External identity provider linking
- 📊 **Session Management**: Active session tracking and termination

### DMVCFramework Integration
- 🛡️ **JWT Middleware**: Automatic token validation and claim extraction
- 📦 **Typed Claims**: Strongly-typed DTOs for Keycloak claims
- 🎯 **Role Helpers**: `HasRealmRole()`, `HasClientRole()` for authorization
- ⚡ **Zero Boilerplate**: Claims automatically available in controller context

### Async Infrastructure
- ⚡ **Async.Core**: Reusable async/await pattern for Delphi
- 🔄 **Fluent API**: Promise-based error handling
- 🎛️ **Thread Control**: Queue vs Synchronize dispatch modes
- 🖥️ **UI-Friendly**: Non-blocking operations for reactive interfaces

---

## 📦 Requirements

### Minimum Requirements
- **Delphi**: Tested with 12.3 or later
- **Platforms**: Windows (VCL/FMX), Linux, iOS, Android (FMX)
- **Framework**: RTL, Indy (for local callback server)

### Optional Dependencies
- **DMVCFramework** Tested with version 3.4+ (for REST API integration)
- **Keycloak** 22+ (tested up to 24.x)

### Supported OAuth2/OIDC Providers
- ✅ Keycloak (primary focus)
- ✅ Any RFC-compliant OAuth2/OIDC provider (limited testing)

---

## 🐳 Development Environment Setup with Docker

IAMClient4D includes a complete Docker configuration to quickly spin up a Keycloak environment ready for development and testing.

### Stack Architecture

The Docker stack includes:
- **PostgreSQL 18 Alpine**: Persistent database for Keycloak
- **Keycloak 26.4**: IAM server with pre-configured realm
- **Nginx Alpine**: Reverse proxy with HTTPS support

```
┌──────────────────────────────────────┐
│  Nginx Gateway (HTTPS)               │
│  Port: 443 (or 24443 in dev)         │
└────────────┬─────────────────────────┘
             │ Reverse Proxy
             ▼
┌──────────────────────────────────────┐
│  Keycloak                            │
│  Internal HTTP: 8080                 │
│  Path: /auth/                        │
└────────────┬─────────────────────────┘
             │ JDBC
             ▼
┌──────────────────────────────────────┐
│  PostgreSQL                          │
│  Database: keycloak                  │
│  Schema: keycloak                    │
└──────────────────────────────────────┘
```

### Prerequisites

- **Docker Desktop** (Windows/macOS) or **Docker Engine** (Linux)
- **Docker Compose** V2+
- **Available port**: 443 (or custom via `GATEWAY_PORT`)

### First Setup - Step by Step

#### Windows

```cmd
cd Docker

# 1. First setup (generate secrets, volumes, etc.)
first-setup.cmd

# 2. (Optional) Generate self-signed SSL certificate
first-setup.cmd -self-signed

# 3. Start services
start.cmd

# 4. (Optional) Start with real-time logs
start.cmd -logs
```

#### Linux/macOS

```bash
cd Docker

# 1. First setup (generate secrets, volumes, etc.)
./first-setup.sh

# 2. (Optional) Generate self-signed SSL certificate
./first-setup.sh -self-signed

# 3. Start services
./start.sh

# 4. (Optional) Start with real-time logs
./start.sh -logs
```

### What Does First Setup Do?

The `first-setup` script automatically performs:

1. **Secret Generation** (`setup-secrets.sh/cmd`):
   - Creates `secrets/` folder if it doesn't exist
   - Generates secure random passwords (32 characters) for:
     - `pg_admin_password.txt`: PostgreSQL admin password
     - `pg_keycloak_password.txt`: Keycloak database user password

2. **.env File Creation**:
   - Copies `.env.template` → `.env`
   - Automatically inserts Keycloak password from secrets
   - **IMPORTANT**: Copy .env.base as .env.template and modify it manually before starting (see .env Configuration)

3. **Docker Volume Creation**:
   - `iamclient4d-auth-db-data`: Persistent volume for PostgreSQL database
   - `iamclient4d-auth-db-log-archive`: Volume for PostgreSQL log archiving

4. **SSL Certificate Generation** (if `-self-signed` option):
   - Generates self-signed certificate valid for configured domain
   - Saves to `config/nginx/ssl/certs/`
   - Valid for development environment testing

### .env Configuration

After first-setup, **modify the `.env.template` file** to configure your environment:

```bash
# ==================================
# MANDATORY CONFIGURATION
# ==================================

# Domain or IP of your machine
# Development: use local IP (192.168.1.100) or hostname
# Production: use FQDN (auth.example.com)
DOMAIN_NAME=192.168.1.100

# Exposed HTTPS port (default: 443)
# Development: use high port (e.g., 24443) to avoid conflicts
# Production: use 443
GATEWAY_PORT=24443

# ==================================
# KEYCLOAK TEMPORARY ADMIN
# ==================================

# Bootstrap admin credentials (MUST CHANGE!)
# These are ONLY for first access
# After setup, create permanent admin and disable this
IAM_ADMIN_USER=tempadmin
IAM_ADMIN_PASS=ChangeMeNow123!

# ==================================
# ADVANCED CONFIGURATION (optional)
# ==================================

# Docker resource prefix (default: iamclient4d-auth)
APP_NAME_PREFIX=iamclient4d-auth

# OCSP Stapling for production certificates
# Leave commented (#) for self-signed certificates
SSL_TRUSTED_CERT=#
ENABLE_SSL_STAPLING=#
ENABLE_SSL_STAPLING_VERIFY=#
```

### Pre-Configured Realm

The stack automatically imports an `iamclient4d` realm with:

**Token Configuration**:
- Access Token Lifespan: 5 minutes
- Refresh Token Lifespan: 30 days
- SSO Session Idle: 30 minutes
- SSO Session Max: 10 hours

**Security**:
- Signature Algorithm: RS256
- SSL Required: `external` (for reverse proxy)
- Brute Force Protection: disabled (enable in production!)

**Account Settings**:
- Registration: disabled
- Password Reset: disabled (managed via Admin API)
- Edit Username: disabled
- Email Verification: disabled

### Service Management

#### Start/Stop

```bash
# Start all services (detached)
./start.sh              # Linux/macOS
start.cmd               # Windows

# Start with real-time logs
./start.sh -logs        # Linux/macOS
start.cmd -logs         # Windows

# Stop all services
./stop.sh               # Linux/macOS
stop.cmd                # Windows
```

#### Status Check

```bash
# Verify all containers are running
docker ps

# You should see 3 containers:
# - iamclient4d-auth-db (PostgreSQL)
# - iamclient4d-auth-iam (Keycloak)
# - iamclient4d-auth-gateway (Nginx)

# Check logs
docker logs iamclient4d-auth-iam
docker logs iamclient4d-auth-gateway
docker logs iamclient4d-auth-db
```

### Admin Console Access

Once services are started:

1. **Admin Console URL**:
   ```
   https://<DOMAIN_NAME>:<GATEWAY_PORT>/auth/admin/
   ```

   Development example:
   ```
   https://192.168.1.100:24443/auth/admin/
   ```

2. **Temporary Login**:
   - Username: `tempadmin` (or configured in `.env`)
   - Password: `ChangeMeNow123!` (or configured)

3. **Select Realm**:
   - Click dropdown top left
   - Select `iamclient4d` (instead of `master`)

> ⚠️ **IMPORTANT**: The `tempadmin` user is a **temporary bootstrap admin**. After first login, follow the [Initial Keycloak Configuration](#initial-keycloak-configuration) section to create a permanent admin and disable the temporary account.

### Complete Environment Removal

```bash
# 1. Stop and remove containers
./stop.sh

# 2. Remove volumes (WARNING: deletes all data!)
./delete-volumes.sh     # Linux/macOS
delete-volumes.cmd      # Windows

# 3. Clean generated files
rm -rf secrets/
rm .env
```

### Troubleshooting

#### Problem: Port 443 already in use

```bash
# Solution: Modify GATEWAY_PORT in .env
GATEWAY_PORT=24443
```

#### Problem: Untrusted SSL certificate

```bash
# Browser shows self-signed certificate error
# Solution: Accept security exception or:

# 1. Import certificate into system
# Windows: Double-click config/nginx/ssl/certs/server.crt
# Linux: sudo cp config/nginx/ssl/certs/server.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates

# 2. Use Let's Encrypt certificate for production
```

#### Problem: Keycloak won't start

```bash
# Check logs
docker logs iamclient4d-auth-iam

# Common issues:
# - Database not ready: wait for PostgreSQL health check
# - Port 8080 busy: check for conflicting containers
# - Realm import failed: verify config/keycloak/realm/realm.json
```

#### Problem: .env variables not loaded

```bash
# Ensure .env file is in Docker/ folder
cd Docker
ls -la .env

# Restart with explicit reload
docker-compose down
docker-compose up -d
```

---

## 🔧 Initial Keycloak Configuration

After starting the Docker stack, configure Keycloak for use with IAMClient4D.

### Prerequisites

- Docker stack started successfully
- Access to Keycloak admin console
- Realm `iamclient4d` selected

### 1. Create Permanent Administrator

The `tempadmin` user created by bootstrap is temporary and must be replaced.

#### Step 1.1: Create Admin User

From master realm:

1. **Go to**: `Users` → `Add user`
2. **Fill in**:
   - **Username**: `admin` (or preferred name)
   - **Email**: `admin@example.com`
   - **First Name**: `Admin`
   - **Last Name**: `User`
   - **Email Verified**: ✅ ON
   - **Enabled**: ✅ ON
3. **Save**

#### Step 1.2: Set Password

1. **Go to tab**: `Credentials`
2. **Click**: `Set Password`
3. **Fill in**:
   - **Password**: <secure password>
   - **Password Confirmation**: <repeat password>
   - **Temporary**: ❌ OFF (permanent password)
4. **Save**

#### Step 1.3: Assign Realm Management Roles

1. **Go to tab**: `Role Mappings`
2. **Click**: `Assign role`
3. **Filter by**: `Filter by clients` → select `realm-management`
4. **Select the following roles**:
   ```
   ✅ create-realm
   ✅ default-roles-master
   ✅ admin
   ```
5. **Click**: `Assign`

#### Step 1.4: Test New Admin

1. **Logout** from console (click `tempadmin` → `Sign Out`)
2. **Login** with new admin:
   - Username: `admin`
   - Password: <password set>
3. **Verify** you can access `Users`, `Clients`, `Realm Settings`

#### Step 1.5: Disable Temporary Admin

⚠️ **IMPORTANT**: Do this ONLY after testing the new admin!

1. **Switch to Realm**: `master` (dropdown at top)
2. **Go to**: `Users` → search `tempadmin`
3. **Disable**:
   - **Enabled**: ❌ OFF
4. **Save**

### 2. Create OAuth2 Client for IAMClient4D

Create a client for your Delphi applications.

#### Step 2.1: Create Client

1. **Realm**: `iamclient4d`
2. **Go to**: `Clients` → `Create client`
3. **General Settings**:
   - **Client type**: `OpenID Connect`
   - **Client ID**: `demo_public` (or preferred name)
5. **Click**: `Next`

#### Step 2.2: Capability Config

- **Client authentication**: ❌ OFF (public client for desktop/mobile)
- **Authorization**: ❌ OFF
- **Authentication flow**:
  - ✅ Standard flow (Authorization Code)
  - ❌ Direct access grants
  - ❌ Implicit flow (deprecated)
  - ❌ Service accounts roles
- **Click**: `Next`

#### Step 2.3: Login Settings

- **Root URL**: `http://localhost:8888` (for local callback)
- **Valid redirect URIs**:
  ```
  http://localhost:8077/* (for uniGUI example)
  http://localhost/*
  ```
- **Valid post logout redirect URIs**: `+` (inherit from redirect URIs)
- **Web origins**: `+` (inherit from redirect URIs)
- **Click**: `Save`

#### Step 2.4: Advanced Configuration (Optional)

### 3. Create Test User

Create a test user to try the login flow.

#### Step 3.1: Create User

1. **Go to**: `Users` → `Add user`
2. **Fill in**:
   - **Username**: `testuser`
   - **Email**: `test@example.com`
   - **First Name**: `Test`
   - **Last Name**: `User`
   - **Email Verified**: ✅ ON
   - **Enabled**: ✅ ON
3. **Save**

#### Step 3.2: Set Password

1. **Tab**: `Credentials` → `Set Password`
2. **Password**: `Test123!`
3. **Temporary**: ❌ OFF
4. **Save**

> ⚠️ **IMPORTANT**: To enable the `testuser` for realm management, assign the realm-admin role. For user management only, enable the client roles: manage-users, query-users, and view-users.

#### Step 3.3: Assign Business Roles (Optional)

If your app requires specific roles:

1. **Go to**: `Realm roles` → `Create role`
2. **Name**: `user` (or `admin`, `moderator`, etc.)
3. **Save**
4. **Go back to**: `Users` → `testuser` → `Role Mappings`
5. **Assign role**: `user`

### 4. Test Configuration

Test the configuration with IAMClient4D:

```pascal
TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode(
    'https://192.168.1.100:24443/auth/realms/iamclient4d', // Issuer
    'iamclient4d',                                         // Realm
    'demo_public'                                          // Client ID
  )
  .WithAllowSelfSignedSSL  // For self-signed dev certificate
  .BuildAsync
  .OnSuccess(
    procedure(const AClient: IIAM4DClient)
    begin
      AClient.StartAuthorizationFlowAsync
        .OnSuccess(procedure(const AToken: string)
          begin
            ShowMessage('Login successful!');
          end)
        .Run;
    end)
  .Run;
```

**Test Credentials**:
- Username: `testuser`
- Password: `Test123!`

### Final Checklist

✅ Permanent admin created and tested
✅ Bootstrap admin `tempadmin` disabled
✅ OAuth2 client `demo_public` configured
✅ Test user created and working
✅ User Management configured (optional)
✅ Login test from Delphi application successful

---

## 🚀 Quick Start

### 1. Installation

#### Manual Installation
```pascal
// Add the following units to your library path:
// - Source\*.pas
// - Source\DMVCMiddleware\*.pas (if using DMVC)
```

### 2. Desktop Application - Authorization Code Flow

```pascal
uses
  IAMClient4D.Core,
  IAMClient4D.Config.Builder,
  Async.Core;

var
  LClient: IIAM4DClient;
begin
  // Use the builder to configure and create the client
  TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(
      'https://keycloak.example.com',  // BaseURL
      'iamclient4d',                        // Realm
      'demo_public'                     // ClientID
    )
    .WithStrictSSL
    .BuildAsync
    .OnSuccess(
      procedure(const AClient: IIAM4DClient)
      begin
        LClient := AClient;
        // Client configured, start auth flow
        LClient.StartAuthorizationFlowAsync
          .OnSuccess(
            procedure(const AAccessToken: string)
            begin
              ShowMessage('Login successful!');
              // Access token available, can call APIs
            end)
          .OnError(
            procedure(const AException: Exception)
            begin
              ShowMessage('Login failed: ' + AException.Message);
            end)
          .Run;
      end)
    .Run;
end;
```

### 3. REST API - JWT Validation (DMVCFramework)

```pascal
uses
  MVCFramework,
  MVCFramework.Middleware.JWT,
  IAMClient4D.DMVC.Middleware,
  IAMClient4D.DMVC.Helpers;

// In your WebModule:
procedure TMyWebModule.ConfigureMiddlewares;
var
  LMiddleware: TIAM4DJWTMiddleware;
begin
  LMiddleware := TIAM4DJWTMiddleware.Create(
    'https://keycloak.example.com/realms/iamclient4d',  // Issuer
    'demo_public'                                       // Expected audience
  );

  AddMiddleware(LMiddleware);
end;

// In your controller:
procedure TMyController.GetProtectedResource;
begin
  // Validate role
  if not Context.Keycloak.RealmAccess.HasRole('admin') then
    raise EMVCException.Create(HTTP_STATUS.Forbidden, 'Access denied');

  // Access user info
  Render(200, Context.JWT.PreferredUsername);
end;
```

### 4. User Management - Keycloak Admin API

```pascal
uses
  IAMClient4D.UserManagement.Core,
  IAMClient4D.UserManagement.Keycloak;

var
  LUserManager: TIAM4DKeycloakUserManager;
  LAuthProvider: IKeycloakAuthProvider;
  LUser: TIAM4DUser;
  LResult: TIAM4DUsersCreateResult;
begin
  // Create auth provider (use existing IAM client - see previous example)
  LAuthProvider := TClientBasedAuthProvider.Create(LClient);

  // Create user manager
  LUserManager := TIAM4DKeycloakUserManager.Create(
    LAuthProvider,
    'https://keycloak.example.com',
    'iamclient4d'
  );
  try
    // Create new user
    LUser := TIAM4DUser.Create(
      'john.doe',                 // Username
      'john.doe@example.com',     // Email
      'John',                     // FirstName
      'Doe'                       // LastName
    );
    LUser.Enabled := True;
    LUser.TemporaryPassword := 'InitialPass123!';
    LUser.RequirePasswordChange := True;

    // Create user asynchronously
    LUserManager.CreateUserAsync(LUser)
      .OnSuccess(
        procedure(const AResult: TIAM4DUsersCreateResult)
        begin
          if AResult.Success then
            ShowMessage('User created: ' + AResult.User.ID)
          else
            ShowMessage('Error: ' + AResult.Message);
        end)
      .Run;
  finally
    LUserManager.Free;
  end;
end;
```

---

## 💡 Usage Examples

### Desktop Application (VCL/FMX)

#### Complete Login Flow with User Info

```pascal
procedure TMainForm.LoginButtonClick(Sender: TObject);
var
  LClient: IIAM4DClient;
begin
  // Use fluent builder to configure client
  TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(
      edtKeycloakURL.Text,
      edtRealm.Text,
      edtClientID.Text
    )
    .WithStrictSSL
    .BuildAsync
    .OnSuccess(
      procedure(const AClient: IIAM4DClient)
      begin
        LClient := AClient;
        // Start authentication flow
        LClient.StartAuthorizationFlowAsync
          .OnSuccess(
            procedure(const AAccessToken: string)
            begin
              // Get user info
              LClient.GetUserInfoAsync
                .OnSuccess(
                  procedure(const AUserInfo: TIAM4DUserInfo)
                  begin
                    // Callback already executed in main thread by Async.Core
                    lblUsername.Caption := AUserInfo.PreferredUsername;
                    lblEmail.Caption := AUserInfo.Email;
                    pnlLoggedIn.Visible := True;
                  end)
                .Run;
            end)
          .OnError(
            procedure(const AException: Exception)
            begin
              ShowMessage('Login failed: ' + AException.Message);
            end)
          .Run;
      end)
    .OnError(
      procedure(const AException: Exception)
      begin
        ShowMessage('Configuration failed: ' + AException.Message);
      end)
    .Run;
end;

procedure TMainForm.LogoutButtonClick(Sender: TObject);
begin
  LClient.LogoutAsync
    .OnSuccess(
      procedure
      begin
        pnlLoggedIn.Visible := False;
        ShowMessage('Logout successful');
      end)
    .Run;
end;
```

### REST API Server (DMVCFramework)

#### Protected Controller with Role-Based Authorization

```pascal
unit MyController;

interface

uses
  MVCFramework,
  MVCFramework.Commons,
  IAMClient4D.DMVC.Helpers;

type
  [MVCPath('/api')]
  TMyController = class(TMVCController)
  public
    [MVCPath('/public')]
    [MVCHTTPMethod([httpGET])]
    procedure PublicEndpoint;

    [MVCPath('/protected')]
    [MVCHTTPMethod([httpGET])]
    procedure ProtectedEndpoint;

    [MVCPath('/admin')]
    [MVCHTTPMethod([httpGET])]
    procedure AdminEndpoint;
  end;

implementation

procedure TMyController.PublicEndpoint;
begin
  Render(200, 'Public data - no authentication required');
end;

procedure TMyController.ProtectedEndpoint;
begin
  // JWT validated by middleware, claims available in Context

  // Get user info from claims
  var LUsername := Context.JWT.PreferredUsername;
  var LEmail := Context.JWT.Email;

  Render(200, Format('Hello %s (%s)', [LUsername, LEmail]));
end;

procedure TMyController.AdminEndpoint;
begin
  // Check realm role
  if not Context.Keycloak.RealmAccess.HasRole('admin') then
    raise EMVCException.Create(HTTP_STATUS.Forbidden, 'Admin role required');

  // Check client role
  var LClientAccess := Context.Keycloak.GetClientAccess('my-app');
  if not LClientAccess.HasRole('super-admin') then
    raise EMVCException.Create(HTTP_STATUS.Forbidden, 'Super admin role required');

  Render(200, 'Admin data');
end;
```

### User Management

#### Search and Update Users

```pascal
procedure TAdminForm.SearchUsers(const ASearchTerm: string);
var
  LParams: TIAM4DUserSearchParams;
begin
  LParams := TIAM4DUserSearchParams.Create;
  LParams.Search := ASearchTerm;
  LParams.MaxResults := 50;

  FUserManager.SearchUsersAsync(LParams)
    .OnSuccess(
      procedure(const AUsers: TArray<TIAM4DUser>)
      var
        LUser: TIAM4DUser;
      begin
        lvUsers.Items.Clear;
        for LUser in AUsers do
        begin
          var LItem := lvUsers.Items.Add;
          LItem.Caption := LUser.Username;
          LItem.SubItems.Add(LUser.Email);
          LItem.SubItems.Add(IfThen(LUser.Enabled, 'Yes', 'No'));
        end;
      end)
    .OnError(
      procedure(const AException: Exception)
      begin
        ShowMessage('Search failed: ' + AException.Message);
      end)
    .Run;
end;

procedure TAdminForm.AssignRoleToUser(const AUserID, ARoleName: string);
var
  LRole: TIAM4DRole;
begin
  // First, get all realm roles
  FUserManager.GetRealmRolesAsync
    .OnSuccess(
      procedure(const ARoles: TArray<TIAM4DRole>)
      begin
        // Find role by name using helper
        if ARoles.TryGetByName(ARoleName, LRole) then
        begin
          // Assign role to user
          FUserManager.AssignRealmRolesToUserAsync(AUserID, [LRole])
            .OnSuccess(
              procedure(const AResult: TIAM4DOperationResult)
              begin
                if AResult.Success then
                  ShowMessage('Role assigned successfully')
                else
                  ShowMessage('Error: ' + AResult.Message);
              end)
            .Run;
        end
        else
          ShowMessage('Role not found: ' + ARoleName);
      end)
    .Run;
end;
```

#### Password Reset with Required Actions

```pascal
procedure TAdminForm.ResetUserPassword(const AUserID: string);
var
  LCredential: TIAM4DCredential;
begin
  // Set temporary password
  LCredential := TIAM4DCredential.Create('TempPass123!', True); // True = temporary

  FUserManager.ResetPasswordAsync(AUserID, LCredential)
    .OnSuccess(
      procedure(const AResult: TIAM4DOperationResult)
      begin
        if AResult.Success then
        begin
          // Add required action to force password change on next login
          FUserManager.AddRequiredActionsAsync(
            AUserID,
            [TIAM4DRequiredAction.raUpdatePassword]
          )
          .OnSuccess(
            procedure(const AResult2: TIAM4DOperationResult)
            begin
              ShowMessage('Password reset. User must change it on next login.');
            end)
          .Run;
        end;
      end)
    .Run;
end;
```

---

## 🏗️ Architecture

### 1. Core Module

**Namespace**: `IAMClient4D.Core`

The Core module defines the high-level API. It contains the interfaces and fundamental types that applications will use directly.

#### `IIAM4DClient` Interface

The heart of the library. Abstracts the complexity of the OAuth2/OIDC protocol behind a concise set of asynchronous methods.

**Main Methods**:
- `ConfigureAsync`: Initializes client and downloads OIDC discovery document
- `StartAuthorizationFlowAsync`: Starts interactive flow (opens browser, handles PKCE, waits for callback)
- `GetAccessTokenAsync`: Returns valid token (auto-refresh if expired)
- `GetUserInfoAsync`: Retrieves user profile data from UserInfo endpoint
- `LogoutAsync`: Performs logout (local and remote)
- `InitializeAuthorizationFlow`: Prepares auth flow for web apps (call before generating auth URL)
- `CompleteAuthorizationFlowAsync`: Completes auth flow with received code and state (for web apps)

#### `TIAM4DClientConfig`

Immutable configuration record. Factory methods for common use cases:

- `CreateForAuthorizationCode(...)`: For desktop/mobile apps (VCL/FMX)
- `CreateForClientCredentials(...)`: For backend services (M2M)

**Properties**:
- `BaseURL`, `Realm`, `ClientID`, `ClientSecret`
- `Scopes`: Array of OAuth2 scopes
- `GrantType`: Authorization Code or Client Credentials
- `SSLValidationMode`: Strict, self-signed, or custom
- `ConnectionTimeout`, `ResponseTimeout`: In milliseconds
- `TokenExpiryBufferSeconds`: Buffer before expiration (default: 120s)
- `ExternalCallbackURL`: For web apps using external callback

#### `TIAM4DUserInfo`

Strongly-typed representation of user information.

**Standard OIDC Claims**:
- `Sub`, `PreferredUsername`, `Name`, `GivenName`, `FamilyName`
- `Email`, `EmailVerified`, `PhoneNumber`, `PhoneNumberVerified`
- `Picture`, `UpdatedAt`

**Methods**:
- `GetCustomClaims`: Access custom claims as dictionary

#### `TIAM4DTokens`

Strongly-typed token container:

**Properties**:
- `AccessToken`, `RefreshToken`, `IDToken`
- `ExpiresIn`, `RefreshExpiresIn`: Seconds until expiration
- `AccessTokenExpiry`, `RefreshTokenExpiry`: Absolute expiration time

**Methods**:
- `FromJSONObject`, `ToJSONObject`: Serialization support

#### `TIAM4DHTTPClientFactory`

Centralizes HTTP client creation with consistent configuration:

**Methods**:
- `CreateHTTPClient(...)`: Creates configured THTTPClient
- `GetWithRetry(...)`: Idempotent GET with exponential backoff
- `PostFormUrlEncodedWithRetry(...)`: POST with retry logic

**Features**:
- Automatic SSL validation configuration
- Timeout management
- Retry with backoff (respects 4xx errors)

#### `TIAM4DClientConfigBuilder`

**Fluent builder** for client configuration with declarative and readable API.

**Usage Pattern**:
```pascal
TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('https://keycloak.example.com', 'iamclient4d', 'demo_public')
  .WithStrictSSL
  .WithTimeouts(30000, 60000)
  .WithTokenExpiryBuffer(120)
  .BuildAsync
  .OnSuccess(procedure(const AClient: IIAM4DClient) begin ... end)
  .Run;
```

**Available Methods**:
- `ForAuthorizationCode(...)`: Configure Authorization Code flow
- `ForClientCredentials(...)`: Configure Client Credentials flow
- `WithScopes(...)`: Set OAuth2 scopes
- `WithStrictSSL`: Enable strict SSL validation
- `WithAllowSelfSignedSSL`: Allow self-signed certificates (dev)
- `WithPinnedPublicKeys(...)`: SHA-256 certificate pinning
- `WithTimeouts(...)`: Connection/response timeouts
- `WithTokenExpiryBuffer(...)`: Token expiration buffer (seconds)
- `WithIAMClient4DAESStorage`: AES-256 storage (with/without custom key)
- `WithCustomStorage(...)`: Custom storage
- `WithExternalCallback(...)`: External callback URL (web apps)
- `Build`: Build client (synchronous)
- `BuildAsync`: Build client (asynchronous, recommended)

**Benefits**:
- Fluent and self-documenting API
- Type-safe configuration
- Configuration validation before build
- Automatic OIDC discovery in BuildAsync
- Secure memory management (zeroed keys)

---

### 2. Common Utilities

**Namespace**: `IAMClient4D.Common.*`

Cross-cutting utilities used by Core and other modules.

#### OAuth2 & PKCE Utilities

- **`PKCEGenerator`**: Generates `code_verifier` and `code_challenge` (SHA-256) for RFC 7636
- **`OAuth2URLParser`**: Robust callback URL parsing, extraction of `code`, `state`, OAuth2 error handling

#### JSON, Error Handling, Secure Memory

- **`JSONUtils`**: Type-safe wrapper for JSON reading/writing
- **`TokenValidator`**: Basic token validation logic (existence, expiration)
- **`SecureMemory`**: Secure buffer management for sensitive data
- **`IAMClient4D.Exceptions`**: Specific exception hierarchy
  - `EIAM4DConfigurationException`
  - `EIAM4DTokenValidationException`
  - `EIAM4DCallbackException`
  - `EIAM4DAuthenticationException`

#### Cryptographic Utilities

- SHA-256 hashing
- HMAC support
- Secure random byte generation
- Base64URL encoding (critical for PKCE and JWT)

#### OIDC Discovery

**`TIAM4DWellKnownEndpoints`**:

Automatic download from `/.well-known/openid-configuration`:

**Properties**:
- `AuthorizationEndpoint`
- `TokenEndpoint`
- `UserInfoEndpoint`
- `JWKSUri`
- `EndSessionEndpoint`
- `Issuer`

---

### 3. Callback Management

**Namespace**: `IAMClient4D.Callback.*`, `IAMClient4D.Server.Callback.*`

Manages the OAuth2 redirect phase: receiving the redirect from Keycloak and extracting the `code` or error.

#### Callback Modes

Two primary modes:

1. **Local Callback** (`cbmLocalServer`)
   - Starts local HTTP server (Indy-based)
   - Listens on `http://127.0.0.1:<port>/callback`
   - Ideal for desktop apps

2. **External Callback** (`cbmExternal`)
   - For web apps (e.g., uniGUI)
   - Delegates to existing server/infrastructure

#### Key Classes

- **`IIAM4DCallbackHandler`**: Interface for callback handling
  - `Start`, `Stop`: Lifecycle management
  - Delivers callback result

- **`TIAM4DLocalCallbackHandler`**: Concrete implementation
  - Starts HTTP micro-server (`IAMClient4D.Server.Callback.IndyHttpServer`)
  - Receives Keycloak redirect
  - Validates `state` parameter
  - Extracts `code` or error

- **`TIAM4DExternalCallbackHandler`**: For external callback scenarios

#### Security Features

- **State validation**: CSRF prevention via constant-time comparison
- **PKCE coordination**: Links authorization request with callback
- **Nonce validation**: Replay attack prevention (used with ID token)

---

### 4. Security (JWT, JWKS, SSL)

**Namespace**: `IAMClient4D.Security.*`

Manages cryptographic JWT validation and public key management via JWKS.

#### JWT Validation

**`TIAM4DJWTValidator`**:

Complete JWT validation pipeline with rigorous checks compliant with RFC 7519 (JWT) and RFC 7523 (OAuth2 JWT Bearer) specifications:

##### 1. **Parsing and Decoding**
- ✅ **Structure parsing**: Verifies `header.payload.signature` format (3 parts)
- ✅ **Base64URL decoding**: Header, payload, and signature with error handling
- ✅ **JSON parsing**: Header and payload converted to JSON objects

##### 2. **JWT Header Validation**
- ✅ **`alg` (Algorithm)**:
  - Verifies mandatory presence
  - Blocks `alg=none` (security best practice)
  - Configurable algorithm allow-list (default: RS256, RS384, RS512)
- ✅ **`kid` (Key ID)**: Extracted for public key retrieval from JWKS
- ✅ **`typ` (Type)**:
  - Optional in standard mode
  - Requires `typ=JWT` if `FStrictTyp=true` (hardening)

##### 3. **Cryptographic Signature Verification**
- ✅ **Public key retrieval**:
  - From JWKS Provider (auto-discovery) using `iss` + `kid`
  - Or from JWKS URL/file with configurable cache
- ✅ **RSA key construction**: From JWK parameters `n` (modulus) and `e` (exponent)
- ✅ **Signature verification**: RS256/RS384/RS512 using LockBox3 RSA
- ✅ **Fallback**: Specific exception if signature invalid

##### 4. **Mandatory Claims Validation**

**Standard Claims (RFC 7519)**:

- ✅ **`iss` (Issuer)**:
  - Verifies mandatory presence
  - URL normalization (trailing `/` removal)
  - Exact match with configured issuer (case-insensitive)

- ✅ **`sub` (Subject)**:
  - Extracted and available in claims
  - Uniquely identifies user/entity

- ✅ **`aud` (Audience)**:
  - Verifies mandatory presence
  - Supports both single string and array
  - Verifies expected audience is present in array
  - Format validation (string or array)

- ✅ **`exp` (Expiration Time)**:
  - Verifies mandatory presence
  - Unix timestamp → TDateTime UTC conversion
  - Verifies token not expired: `now_utc - clock_skew < exp`
  - Exception with formatted timestamps if expired

- ✅ **`nbf` (Not Before)**:
  - Optional, validated if present
  - Unix timestamp → TDateTime UTC conversion
  - Verifies token not used before: `nbf <= now_utc + clock_skew`
  - Exception with formatted timestamps if too early

- ✅ **`iat` (Issued At)**:
  - Extracted and available in claims
  - Token issuance timestamp

- ✅ **`jti` (JWT ID)**:
  - Extracted and available in claims
  - Unique token identifier (for revocation/tracking)

**Additional OAuth2/OIDC Claims**:

- ✅ **`azp` (Authorized Party)**:
  - OIDC-compliant conditional validation:
    - **Required** if `aud` contains multiple values (default per OIDC spec)
    - **Required** if `FExpectedAzp` explicitly configured
  - Exact match with configured value
  - Useful for multi-tenant scenarios

- ✅ **`typ` (Token Type)**:
  - Extracted and available (e.g., `Bearer`, `Refresh`)
  - Optional `typ=JWT` verification if strict mode

##### 5. **Security Configurations**

**Clock Skew Tolerance**:
- Default: 60 seconds
- Configurable via `SetClockSkewSeconds()`
- Applied to `exp` and `nbf` to compensate clock differences

**Algorithm Allow-List**:
- Configurable via `SetAllowedAlgorithms()`
- Default: `['RS256','RS384','RS512']`
- Blocks symmetric algorithms (HS256) for server-side JWT

**Strict Type Checking**:
- Optional: Requires `typ=JWT` in header
- Activatable via `SetStrictTyp(true)`

**Additional Features**:
- 🔄 Configurable JWKS cache (reduces latency)
- 🔄 Auto-refresh JWKS on key rotation
- ⚠️ Typed exceptions for each validation error
- 📊 Formatted timestamps in error messages for debugging
- 🧵 Thread-safe for concurrent validations

##### Complete Validation Checklist

```
✅ Signature Verification   (RSA with public key from JWKS)
✅ Algorithm Check          (alg: RS256/RS384/RS512)
✅ iss (Issuer)             (Exact match with configuration)
✅ sub (Subject)            (Extracted for user identification)
✅ aud (Audience)           (Verifies single string or array)
✅ exp (Expiration Time)    (Token not expired with clock skew)
✅ nbf (Not Before)         (Token not used before time with clock skew)
✅ iat (Issued At)          (Issuance timestamp available)
✅ jti (JWT ID)             (Unique ID for tracking/revocation)
✅ typ (Type)               (Optional, validated if strict mode)
✅ azp (Authorized Party)   (Validated if configured or multi-audience OIDC)
✅ kid (Key ID)             (Used to select JWKS key)
```

> 🔒 **Security Note**: IAMClient4D implements **all checks** recommended by RFC 7519 (JWT), RFC 7515 (JWS), and RFC 7523 (OAuth2 JWT Bearer), plus security best practices like `alg=none` blocking, algorithm allow-list, and `azp` validation for OIDC multi-audience.

#### JWKS Provider

**`TIAM4DJWKSProvider`**:

Manages JWT verification public keys:

- Downloads JWKS from `jwks_uri`
- **Internal cache** for keys (reduces repeated calls)
- Selects correct key via `kid` from JWT header
- Cache invalidation and forced refresh

**Thread Safety**: Internal synchronization for cache access

#### RSA Verifier

**`IAMClient4D.Security.JWT.Verifiers.RSA`**:

RS256 signature verification logic:

- Constructs RSA keys from JWKS parameters `n` and `e`
- Uses Delphi cryptographic primitives
- Integration with generic validator

#### SSL Certificate Validation

**`TIAM4DSSLValidationMode`**:

- `svmStrict`: Production mode, full certificate validation
- `svmSelfSigned`: Development mode, accepts self-signed certificates

**`IIAM4DSSLCertificateValidator`**:

Custom validator interface for advanced scenarios:

- Certificate pinning
- Custom trust store
- Enterprise CA validation

**Integration**: `TIAM4DHTTPClientSSLHelper` connects validators to `THTTPClient.OnValidateServerCertificate`

---

### 5. Token Storage

**Namespace**: `IAMClient4D.Storage.*`

Manages secure token persistence.

#### `IIAM4DTokenStorage` Interface

Minimal contract for any storage implementation:

```pascal
type
  IIAM4DTokenStorage = interface
    function LoadTokens(out ATokens: TIAM4DTokens): Boolean;
    procedure SaveTokens(const ATokens: TIAM4DTokens);
    procedure ClearTokens;
  end;
```

**Benefits**:
- Pluggable storage implementations
- Easy mocking for tests
- Support for different storage backends

#### AES-256 Encrypted In-Memory Storage

**`TIAM4DAESMemoryTokenStorageRawKey32`**:

Concrete implementation:

- **Memory only**: Never persisted to disk
- **AES-256 encryption**: 32-byte (256-bit) key
- **JSON serialization**: Internal format
- **Secure memory**: Minimizes plaintext exposure window

**Use Cases**:
- Desktop/mobile apps that remain running
- No long-term disk persistence needed
- Maximum security for in-memory tokens

**Extensibility**: Create custom implementations (file, database, secure enclave) by implementing `IIAM4DTokenStorage`

---

### 6. User Management (Keycloak Admin API)

**Namespace**: `IAMClient4D.UserManagement.*`

Strongly-typed Delphi abstraction over Keycloak Admin API.

#### Domain Model

**`TIAM4DUser`**:

Complete user representation:

**Properties**:
- `ID` (UUID), `Username`, `Email`
- `FirstName`, `LastName`
- `Enabled`, `EmailVerified`
- `Attributes`: Multi-value custom attributes
- `CreatedTimestamp`: Unix timestamp (ms)
- `RequiredActions`: Array of required actions
- `TemporaryPassword`: For creation only
- `RequirePasswordChange`: Forces password change

**Methods**:
- `Attributes[name]`: Dictionary-style attribute access
- `HasRequiredAction(...)`: Check specific action
- `Create(...)`: Factory method

**`TIAM4DRole`**:

Role representation:

**Properties**:
- `ID`, `Name`, `Description`
- `IsRealmRole`, `IsClientRole`
- `ClientID`: For client roles
- `Composite`: If role is composite

**`TIAM4DRealmClient`**:

Keycloak client representation:

**Properties**:
- `ID` (UUID), `ClientID` (string identifier)
- `Name`, `Description`, `Enabled`
- `Roles`: Client role array

**`TIAM4DGroup`**:

Group representation with hierarchy support:

**Properties**:
- `ID`, `Name`, `Path`
- `SubGroups`: Nested groups
- `RealmRoles`, `ClientRoles`

**Other Records**:
- `TIAM4DFederatedIdentity`: Linked external identities
- `TIAM4DUserSession`: Active session information
- `TIAM4DCredential`: Password credential
- `TIAM4DUserSearchParams`: Search parameters

#### Result Records

Type-safe operation results:

- `TIAM4DOperationResult`: Base result (Success, HttpStatusCode, Message)
- `TIAM4DUserGetResult`: Single user result
- `TIAM4DUsersCreateResult`: User creation result
- `TIAM4DGroupTryResult`: Group operation result
- `TIAM4DRoleTryResult`: Role operation result

#### Array Helpers

**`IAMClient4D.UserManagement.Helpers`**:

Powerful array manipulation:

**User Helpers**:
- `FilterByEnabled(Boolean)`
- `FilterByEmailVerified(Boolean)`
- `TryGetByUsername(...)`
- `TryGetByEmail(...)`

**Role Helpers**:
- `FilterByRealmRole`
- `FilterByClientRole(ClientID)`
- `TryGetByName(...)`

**Client Helpers**:
- `TryGetClientByID(...)`
- `TryGetClientByClientID(...)`
- `FilterByEnabled(Boolean)`

#### Keycloak Admin Client

**`TIAM4DKeycloakUserManager`**:

Main Admin API client.

**Authentication**:
- `IKeycloakAuthProvider` interface
- `TClientBasedAuthProvider`: Uses IAM4D client (auto-refresh)
- `TTokenBasedAuthProvider`: Static token (manual management)

**User Operations** (sync + async):
- `SearchUsers(Async)`: By username, email, attributes
- `GetUser(Async)`: By ID
- `CreateUser(Async)`: With attributes, temporary password
- `UpdateUser(Async)`: Full or partial update
- `DeleteUser(Async)`: By ID

**Role Management**:
- `GetRealmRoles(Async)`: All realm roles
- `GetUserRealmRoles(Async)`: User's realm roles
- `AssignRealmRolesToUser(Async)`: Assign roles
- `RemoveRealmRolesFromUser(Async)`: Remove roles
- `GetClientRoles(Async)`: Roles for specific client
- `AssignClientRolesToUser(Async)`: Assign client roles
- `RemoveClientRolesFromUser(Async)`: Remove client roles

**Group Management**:
- `GetGroups(Async)`: All groups
- `GetUserGroups(Async)`: User's groups
- `AddUserToGroup(Async)`: Add membership
- `RemoveUserFromGroup(Async)`: Remove membership

**Password & Actions**:
- `ResetPassword(Async)`: Set new password (temporary or permanent)
- `AddRequiredActions(Async)`: Force password change, email verification, etc.
- `RemoveRequiredActions(Async)`: Clear required actions

**Federated Identities**:
- `GetFederatedIdentities(Async)`: Linked identities
- `LinkFederatedIdentity(Async)`: Link external identity
- `UnlinkFederatedIdentity(Async)`: Remove link

**Sessions**:
- `GetUserSessions(Async)`: Active sessions
- `LogoutUser(Async)`: Terminate all sessions

#### Batch Operations

To efficiently handle large volumes of users, the API provides batch operations that execute multiple operations in parallel.

**Batch Creation**:
```pascal
function CreateUsersAsync(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DUsersCreateResult>>;
```

**Example - Massive User Import**:
```pascal
procedure TAdminForm.ImportUsers(const ACSVFile: string);
var
  LUsers: TArray<TIAM4DUser>;
  LResults: TArray<TIAM4DUsersCreateResult>;
begin
  // Read CSV and prepare user array (simplified example)
  SetLength(LUsers, 1000);
  for var I := 0 to 999 do
  begin
    LUsers[I] := TIAM4DUser.Create(
      Format('user%d', [I]),
      Format('user%d@example.com', [I]),
      'User',
      IntToStr(I)
    );
    LUsers[I].Enabled := True;
    LUsers[I].TemporaryPassword := 'Welcome123!';
    LUsers[I].RequirePasswordChange := True;
  end;

  FUserManager.CreateUsersAsync(LUsers)
    .OnSuccess(
      procedure(const AResults: TArray<TIAM4DUsersCreateResult>)
      begin
        var LSuccessCount := 0;
        var LFailedCount := 0;

        for var LResult in AResults do
        begin
          if LResult.Success then
            Inc(LSuccessCount)
          else
          begin
            Inc(LFailedCount);
            LogError('User creation error: %s', [LResult.Message]);
          end;
        end;

        ShowMessage(Format('Import completed: %d successes, %d errors',
          [LSuccessCount, LFailedCount]));
      end)
    .OnError(
      procedure(const AException: Exception)
      begin
        ShowMessage('Batch error: ' + AException.Message);
      end)
    .Run;
end;
```

**Batch Update**:
```pascal
function UpdateUsersAsync(const AUsers: TArray<TIAM4DUser>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
```

**Batch Deletion**:
```pascal
function DeleteUsersAsync(const AUserIDs: TArray<string>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
```

**Batch Password Reset**:
```pascal
function SetPasswordsAsync(const APasswordResets: TArray<TIAM4DPasswordReset>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
```

**Batch Role Assignment**:
```pascal
function AssignRolesToUsersAsync(const ARoleAssignments: TArray<TIAM4DRoleAssignment>): IAsyncPromise<TArray<TIAM4DOperationResult>>;
```

**Batch Operations Benefits**:
- ✅ **Performance**: 10-50x faster than individual calls
- ✅ **Network efficiency**: Reduces number of HTTP round-trips
- ✅ **Granular error handling**: Each operation has its own result
- ✅ **Partial atomicity**: Continues even if some operations fail

#### Simplified Helpers

Simplified APIs for common operations that don't require complex objects:

**Users by Username**:
```pascal
function GetUserByUsernameAsync(const AUsername: string): IAsyncPromise<TIAM4DUser>;
function TryGetUserByUsernameAsync(const AUsername: string): IAsyncPromise<TIAM4DUserTryResult>;
```

**Role Assignment by Name**:
```pascal
function AssignRoleByNameAsync(const AUserID, ARoleName: string): IAsyncVoidPromise;
function RemoveRoleByNameAsync(const AUserID, ARoleName: string): IAsyncVoidPromise;
function AssignClientRoleByNameAsync(const AUserID, AClientName, ARoleName: string): IAsyncVoidPromise;
function RemoveClientRoleByNameAsync(const AUserID, AClientName, ARoleName: string): IAsyncVoidPromise;
```

**Example - Simplified API**:
```pascal
// Instead of searching for role and then assigning...
// "Long" way:
FUserManager.GetRealmRolesAsync
  .OnSuccess(
    procedure(const ARoles: TArray<TIAM4DRole>)
    var LRole: TIAM4DRole;
    begin
      if ARoles.TryGetByName('admin', LRole) then
        FUserManager.AssignRolesToUserAsync(AUserID, [LRole]).Run;
    end)
  .Run;

// Simplified way:
FUserManager.AssignRoleByNameAsync(AUserID, 'admin')
  .OnSuccess(
    procedure
    begin
      ShowMessage('Admin role assigned');
    end)
  .Run;
```

**Groups by Path**:
```pascal
function AddUserToGroupByPathAsync(const AUserID, AGroupPath: string): IAsyncVoidPromise;
function RemoveUserFromGroupByPathAsync(const AUserID, AGroupPath: string): IAsyncVoidPromise;
```

**User Count**:
```pascal
function GetUsersCountAsync: IAsyncPromise<Integer>;
```

#### Email Workflows

Keycloak supports automatic email sending for common workflows:

**Verification Email**:
```pascal
function SendVerifyEmailAsync(const AUserID: string): IAsyncVoidPromise;
```

**Example - User Onboarding with Email**:
```pascal
procedure TAdminForm.CreateUserWithEmailVerification;
var
  LUser: TIAM4DUser;
  LUserID: string;
begin
  // Create user
  LUser := TIAM4DUser.Create(
    'john.doe',
    'john.doe@example.com',
    'John',
    'Doe'
  );
  LUser.Enabled := True;
  LUser.EmailVerified := False; // Email not yet verified

  FUserManager.CreateUserAsync(LUser)
    .OnSuccess(
      procedure(const AUserID: string)
      begin
        // User created, send verification email
        FUserManager.SendVerifyEmailAsync(AUserID)
          .OnSuccess(
            procedure
            begin
              ShowMessage('User created. Verification email sent.');
            end)
          .Run;
      end)
    .Run;
end;
```

**Password Reset Email**:
```pascal
function SendPasswordResetEmailAsync(const AUserID: string): IAsyncVoidPromise;
```

**Example - Self-Service Password Reset**:
```pascal
procedure TAdminForm.InitiatePasswordReset(const AUsername: string);
begin
  // Find user by username
  FUserManager.GetUserByUsernameAsync(AUsername)
    .OnSuccess(
      procedure(const AUser: TIAM4DUser)
      begin
        // Send password reset email
        FUserManager.SendPasswordResetEmailAsync(AUser.ID)
          .OnSuccess(
            procedure
            begin
              ShowMessage(
                Format('Password reset email sent to %s', [AUser.Email])
              );
            end)
          .Run;
      end)
    .OnError(
      procedure(const AException: Exception)
      begin
        ShowMessage('User not found: ' + AUsername);
      end)
    .Run;
end;
```

#### Method Summary Table

| Category    | Synchronous Methods            | Asynchronous Methods                              | Batch                                                |
|-------------|--------------------------------|---------------------------------------------------|------------------------------------------------------|
| **Users**   | GetUser, SearchUsers           | GetUserAsync, SearchUsersAsync                    | CreateUsersAsync, UpdateUsersAsync, DeleteUsersAsync |
| **Roles**   | GetRealmRoles, GetUserRoles    | GetRealmRolesAsync, AssignRoleByNameAsync         | AssignRolesToUsersAsync                              |
| **Password**| SetPassword                    | SetPasswordAsync, SendPasswordResetEmailAsync     | SetPasswordsAsync                                    |
| **Groups**  | GetGroups, GetUserGroups       | AddUserToGroupByPathAsync                         | -                                                    |
| **Email**   | -                              | SendVerifyEmailAsync, SendPasswordResetEmailAsync | -                                                    |
| **Sessions**| GetUserSessions, LogoutUser    | LogoutUserAsync                                   | -                                                    |

---

### 7. DMVCFramework Integration

**Namespace**: `IAMClient4D.DMVC.*`

Native integration with DMVCFramework for JWT-protected REST APIs.

#### JWT Middleware

**`TIAM4DJWTMiddleware`**:

Automatic JWT validation middleware:

**Process**:
1. Extracts bearer token from `Authorization: Bearer <jwt>` header
2. Validates using `TIAM4DJWTValidator` and `TIAM4DJWKSProvider`:
   - Verifies signature
   - Validates claims (`iss`, `aud`, `exp`, `nbf`, etc.)
3. On success:
   - Constructs typed claim DTOs
   - Inserts into DMVC `Context`
   - Automatically parses Keycloak-specific claims
4. On error:
   - Blocks request
   - Returns HTTP 401/403

**Configuration**:
```pascal
var
  LMiddleware := TIAM4DJWTMiddleware.Create(
    'https://keycloak.example.com/realms/iamclient4d',  // Issuer
    'demo_public'                                       // Expected audience
  );

  // Optional: Custom SSL validation
  LMiddleware.SSLValidationMode := svmSelfSigned;

  // Optional: Clock skew tolerance (seconds)
  LMiddleware.ClockSkewSeconds := 60;

  AddMiddleware(LMiddleware);
```

#### Typed Claim DTOs

**`IAMClient4D.DMVC.DTO`**:

**`TIAM4DJWTClaims`**: Standard JWT + OIDC claims (accessible via `Context.JWT`)
- Standard JWT claims: `Sub`, `Iss`, `Aud`, `Exp`, `Nbf`, `Iat`, `Jti`
- OIDC claims: `PreferredUsername`, `Email`, `EmailVerified`, `Name`, `GivenName`, `FamilyName`
- OAuth2: `Azp`, `SessionState`, `Scope`, `Roles`

**`TIAM4DKeycloakClaims`**: Keycloak-specific claims (accessible via `Context.Keycloak`)
- `RealmAccess`: Structure with realm roles
- `ResourceAccess`: Array of client roles for each client
- `Groups`: User group array
- `AllowedOrigins`: Allowed origins

**`TIAM4DKeycloakRealmAccess`**:
- `Roles`: Realm role name array

**`TIAM4DKeycloakClientAccess`**:
- `Roles`: Client role name array for specific client

**Access in Controllers**:
```pascal
// Available via Context extensions
var LJWTClaims := Context.JWT;
var LUsername := LJWTClaims.PreferredUsername;
var LEmail := LJWTClaims.Email;

// Keycloak-specific claims
var LKeycloakClaims := Context.Keycloak;
var LHasAdminRole := LKeycloakClaims.RealmAccess.HasRole('admin');
```

#### Controller Helpers

**`IAMClient4D.DMVC.Helpers`**:

Extension methods for `TMVCContext` that simplify JWT claim access and authorization.

##### Base Claim Access

```pascal
// Direct claim access
Context.JWT                              // TIAM4DJWTClaims - standard JWT + OIDC claims
Context.Keycloak                         // TIAM4DKeycloakClaims - Keycloak-specific claims (RealmAccess, ResourceAccess, Groups)
Context.IsAuthenticated                  // Boolean - verify authentication
```

##### Custom Claims with Typed Conversion

```pascal
// Access custom claims with automatic conversions
function GetCustomClaim(const AClaimName: string): string;
function GetCustomClaim(const AClaimName, ADefault: string): string;
function TryGetCustomClaim(const AClaimName: string; out AValue: string): Boolean;

// Typed conversions with fallback
function GetCustomClaimAsInteger(const AClaimName: string; ADefault: Integer = 0): Integer;
function GetCustomClaimAsBoolean(const AClaimName: string; ADefault: Boolean = False): Boolean;
function GetCustomClaimAsDateTime(const AClaimName: string): TDateTime;
```

**Example**:
```pascal
var
  LUserAge: Integer;
  LIsPremium: Boolean;
  LRegistrationDate: TDateTime;
begin
  // Access custom claims with automatic conversion
  LUserAge := Context.GetCustomClaimAsInteger('user_age', 18);
  LIsPremium := Context.GetCustomClaimAsBoolean('premium_subscriber', False);
  LRegistrationDate := Context.GetCustomClaimAsDateTime('registered_at');

  if LIsPremium then
    // Logic for premium users...
end;
```

##### Require* Methods - Declarative Authorization

These methods automatically raise appropriate HTTP exceptions:

```pascal
procedure RequireAuthentication;                         // Throws 401 if not authenticated
procedure RequireAnyRole(const ARoles: TArray<string>);  // Throws 403 if missing role
procedure RequireAllRoles(const ARoles: TArray<string>); // Throws 403 if missing roles
procedure RequireScope(const AScope: string);            // Throws 403 if missing scope
procedure RequireRealmRole(const ARole: string);         // Throws 403 if missing realm role
procedure RequireAnyRealmRole(const ARoles: TArray<string>); // Throws 403 if missing realm roles
procedure RequireGroup(const AGroup: string);            // Throws 403 if not in group
```

**Example - Declarative Authorization**:
```pascal
procedure TMyController.AdminOnlyEndpoint;
begin
  // Check authentication + role in one line
  Context.RequireAuthentication;
  Context.RequireRealmRole('admin');

  // If we get here, user is authenticated and is admin
  Render(200, 'Admin data');
end;

procedure TMyController.ModeratorEndpoint;
begin
  // Accept users with at least one of specified roles
  Context.RequireAnyRealmRole(['moderator', 'admin', 'super-admin']);

  // Business logic...
end;

procedure TMyController.RestrictedToGroup;
begin
  // Only users belonging to specific group
  Context.RequireGroup('/organizations/acme-corp');

  // Business logic...
end;

procedure TMyController.ScopedEndpoint;
begin
  // Verify token has required scope
  Context.RequireScope('read:users');

  // Business logic...
end;
```

##### Keycloak Helpers - Role and Group Access

```pascal
// Structured access to Keycloak claims (roles and groups)
Context.Keycloak.RealmAccess.HasRole('admin')
Context.Keycloak.GetClientAccess('my-app').HasRole('super-user')
Context.Keycloak.Groups                    // TArray<string> - user groups

// User info access (from standard JWT claims)
Context.JWT.PreferredUsername
Context.JWT.Email
Context.JWT.EmailVerified
```

**Complete Example**:
```pascal
procedure TMyController.ComplexAuthorization;
begin
  // Verify authentication
  Context.RequireAuthentication;

  // Get JWT and Keycloak claims
  var LJWT := Context.JWT;
  var LKeycloak := Context.Keycloak;

  // Check realm roles
  if not LKeycloak.RealmAccess.HasRole('user-manager') then
    raise EMVCException.Create(HTTP_STATUS.Forbidden, 'User-manager role required');

  // Check client-specific roles
  var LClientAccess := LKeycloak.GetClientAccess('admin-console');
  if not LClientAccess.HasRole('edit-users') then
    raise EMVCException.Create(HTTP_STATUS.Forbidden, 'Edit-users permission required');

  // Verify group membership
  if not LKeycloak.Groups.Contains('/admins') then
    raise EMVCException.Create(HTTP_STATUS.Forbidden, 'Must belong to admins group');

  // Log operation (user info from JWT)
  LogInfo('Operation performed by: %s (%s)', [LJWT.PreferredUsername, LJWT.Email]);

  // Business logic...
end;
```

##### Declarative Approach Benefits

**Before** (manual checks):
```pascal
procedure TMyController.OldWay;
begin
  if not Context.IsAuthenticated then
    raise EMVCException.Create(HTTP_STATUS.Unauthorized, 'Authentication required');

  if not Context.Keycloak.RealmAccess.HasRole('admin') then
    raise EMVCException.Create(HTTP_STATUS.Forbidden, 'Admin role required');

  // Business logic...
end;
```

**After** (Require* methods):
```pascal
procedure TMyController.NewWay;
begin
  Context.RequireAuthentication;
  Context.RequireRealmRole('admin');

  // Business logic...
end;
```

✅ **More concise, more readable, fewer errors!**

---

### 8. Async.Core

**File**: `Async.Core.pas`

Generic async infrastructure used by IAMClient4D, but **reusable** in any Delphi project.

#### Purpose

Lightweight async infrastructure for:
- Executing async operations (`TTask`)
- Type-safe callbacks for **success**, **error**, **finally**
- **Automatic callback execution on main thread**
- Complete decoupling from `TTask`, `TThread.Queue`, `TThread.Synchronize` details

> 💡 **Tip**: All IAMClient4D callbacks (`OnSuccess`, `OnError`, `OnFinally`) are automatically executed on the main thread. You can directly access UI controls without worrying about synchronization!

#### Main Constructs

**`TAsyncCore`**: Static entry point

```pascal
class function New<TResult>(const AFunc: TFunc<TResult>): IAsyncPromise<TResult>;
class function NewVoid(const AProc: TProc): IAsyncVoidPromise;
```

**`IAsyncPromise<TResult>` / `IAsyncVoidPromise`**: Fluent interface

```pascal
function OnSuccess(const ACallback: TProc<TResult>): IAsyncPromise<TResult>;
function OnError(const ACallback: TProc<Exception>): IAsyncPromise<TResult>;
function OnFinally(const ACallback: TProc): IAsyncPromise<TResult>;
function WithCallbackDispatchMode(AMode: TAsyncCallbackDispatchMode): IAsyncPromise<TResult>;
procedure Run;
```

**`TAsyncCallbackDispatchMode`**:

- **`dmSynchronize`** (default):
  - Uses `TThread.Synchronize`
  - Worker thread waits for callback completion
  - Guarantees synchronous execution with UI
  - Blocking callback for worker thread

- **`dmQueue`**:
  - Uses `TThread.Queue`
  - Callback queued on main thread
  - Non-blocking for worker thread
  - Recommended for more reactive UI

#### Internal Logic

Async.Core encapsulates:
- `TTask` creation and management
- Exception propagation from worker to `OnError`
- Guaranteed `OnFinally` execution
- State monitoring (`TAsyncOperationState`: Pending, Running, Completed, Faulted, Cancelled)

#### Usage Pattern

```pascal
TAsyncCore
  .New<string>(
    function: string
    begin
      // Long operation (HTTP call, DB query, etc.)
      Sleep(2000);
      Result := 'Operation completed';
    end)
  .OnSuccess(
    procedure(const AResult: string)
    begin
      ShowMessage('Success: ' + AResult);
    end)
  .OnError(
    procedure(const AException: Exception)
    begin
      // Errors also handled on main thread
      ShowMessage('Error: ' + AException.Message);
    end)
  .OnFinally(
    procedure
    begin
      // Cleanup (always executed)
      Cursor := crDefault;
    end)
  .WithCallbackDispatchMode(dmQueue)
  .Run;
```

#### Benefits in IAMClient4D

1. **Non-blocking UI**: HTTP operations, JWT validation, user management in background
2. **Fluent API**: Clean and readable code without nested callbacks
3. **Robust error handling**: Exceptions intercepted and forwarded to `OnError`
4. **Reusable**: Can be extracted for use in any Delphi project
5. **Thread control**: Choose synchronization mode based on requirements

#### Advanced Features

**Cancellation**:
```pascal
var LOperation: IAsyncOperation<string>;

LOperation := TAsyncCore
  .New<string>(
    function: string
    begin
      // Check cancellation periodically
      if LOperation.IsCancellationRequested then
        raise EAsyncCancelException.Create;
      // ... work ...
    end)
  .Run;

// Cancel from UI
LOperation.Cancel;
```

**Wait for Completion**:
```pascal
var LState := LOperation.WaitForCompletion(5000); // 5 second timeout

case LState of
  TAsyncOperationState.Completed: ShowMessage('Done!');
  TAsyncOperationState.Faulted: ShowMessage('Failed!');
  TAsyncOperationState.Cancelled: ShowMessage('Cancelled!');
end;
```

---

## ⚠️ Error Handling

IAMClient4D provides a structured exception hierarchy and specific error codes to facilitate error handling and debugging.

### Exception Hierarchy

**Base Exception**:
```pascal
EIAM4DException = class(Exception)
  ErrorCode: TIAM4DErrorCode;
  HttpStatusCode: Integer;
  AdditionalInfo: TDictionary<string, string>;
end;
```

**Specific Exceptions**:
- `EIAM4DConfigurationException`: Configuration errors
- `EIAM4DAuthenticationException`: Authentication/authorization errors
- `EIAM4DTokenValidationException`: JWT validation errors
- `EIAM4DCallbackException`: OAuth2 callback errors
- `EIAM4DNetworkException`: Network/connection errors
- `EIAM4DUserManagementException`: User management errors
- `EIAM4DStorageException`: Token storage errors

### Structured Error Codes

```pascal
TIAM4DErrorCode = (
  // Authentication/Authorization (1000-1999)
  ecAccessTokenExpired = 1001,
  ecRefreshTokenExpired = 1002,
  ecTokenInvalid = 1003,
  ecInvalidCredentials = 1010,
  ecInvalidAuthorizationCode = 1020,
  ecPKCEValidationFailed = 1021,
  ecStateMismatch = 1022,
  ecAuthorizationCancelled = 1030,
  ecAuthorizationTimeout = 1031,
  ecInsufficientPermissions = 1040,

  // Network/Communication (2000-2999)
  ecNetworkTimeout = 2001,
  ecNetworkUnreachable = 2002,
  ecConnectionRefused = 2003,
  ecSSLCertificateError = 2010,
  ecHTTPClientError = 2100,
  ecHTTPServerError = 2200,

  // User Management (3000-3999)
  ecUserNotFound = 3001,
  ecUserAlreadyExists = 3002,
  ecInvalidUserData = 3003,

  // Configuration (4000-4999)
  // Storage (5000-5999)
  // Security/Validation (6000-6999)
);
```

### Error Handling Patterns

#### 1. Expired Token Handling with Retry

```pascal
procedure TMyForm.CallProtectedAPI;
begin
  LClient.GetAccessTokenAsync
    .OnSuccess(
      procedure(const AToken: string)
      begin
        // Call protected API...
      end)
    .OnError(
      procedure(const AException: Exception)
      begin
        if AException is EIAM4DAuthenticationException then
        begin
          var LAuthEx := EIAM4DAuthenticationException(AException);

          case LAuthEx.ErrorCode of
            ecAccessTokenExpired:
              begin
                // Token expired, refresh is automatic
                // Retry the call (already on main thread)
                CallProtectedAPI; // Retry
              end;

            ecRefreshTokenExpired:
              begin
                // Refresh token expired, re-login needed
                ShowMessage('Session expired. Please login again.');
                NavigateToLogin;
              end;

            ecInsufficientPermissions:
              ShowMessage('Insufficient permissions for this operation');
          end;
        end;
      end)
    .Run;
end;
```

#### 2. User Management Error Handling

```pascal
procedure TAdminForm.CreateUserWithErrorHandling;
var
  LUser: TIAM4DUser;
begin
  LUser := TIAM4DUser.Create('john.doe', 'john.doe@example.com', 'John', 'Doe');

  FUserManager.CreateUserAsync(LUser)
    .OnSuccess(
      procedure(const AUserID: string)
      begin
        ShowMessage('User created: ' + AUserID);
      end)
    .OnError(
      procedure(const AException: Exception)
      begin
        if AException is EIAM4DUserManagementException then
        begin
          var LUMEx := EIAM4DUserManagementException(AException);

          case LUMEx.ErrorCode of
            ecUserAlreadyExists:
              ShowMessage('A user with this username/email already exists');

            ecInvalidUserData:
              begin
                // Show validation details
                var LDetails := '';
                for var LPair in LUMEx.AdditionalInfo do
                  LDetails := LDetails + LPair.Key + ': ' + LPair.Value + #13#10;
                ShowMessage('Invalid user data:'#13#10 + LDetails);
              end;

            ecInsufficientPermissions:
              ShowMessage('You do not have permissions to create users');

            ecHTTPServerError:
              ShowMessage('Keycloak temporarily unavailable. Try again later.');
          else
            ShowMessage('Error: ' + AException.Message);
          end;
        end
        else
          ShowMessage('Error: ' + AException.Message);
      end)
    .Run;
end;
```

#### 3. Network Error Handling with Retry

```pascal
procedure TMyForm.ConfigureWithRetry(ARetryCount: Integer = 3);
begin
  TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(FKeycloakURL, FRealm, FClientID)
    .WithScopes(['openid', 'profile'])
    .BuildAsync
    .OnSuccess(
      procedure(const AClient: IIAM4DClient)
      begin
        FClient := AClient;
        ShowMessage('Configuration completed');
      end)
    .OnError(
      procedure(const AException: Exception)
      begin
        if AException is EIAM4DNetworkException then
        begin
          var LNetEx := EIAM4DNetworkException(AException);

          case LNetEx.ErrorCode of
            ecNetworkTimeout, ecNetworkUnreachable, ecConnectionRefused:
              begin
                if ARetryCount > 0 then
                begin
                  // Retry with exponential backoff
                  var LDelay := (4 - ARetryCount) * 2000; // 2s, 4s, 6s
                  ShowMessage(Format('Network error. Retrying in %d seconds...', [LDelay div 1000]));

                  // Use Async.Core for delayed retry
                  TAsyncCore.NewVoid(
                    procedure
                    begin
                      Sleep(LDelay);
                    end)
                    .OnSuccess(
                      procedure
                      begin
                        ConfigureWithRetry(ARetryCount - 1);
                      end)
                    .Run;
                end
                else
                  ShowMessage('Unable to connect to Keycloak after 3 attempts');
              end;

            ecSSLCertificateError:
              begin
                ShowMessage('SSL certificate error. Check configuration.');
                // In dev, you might offer to use WithAllowSelfSignedSSL
              end;
          end;
        end;
      end)
    .Run;
end;
```

#### 4. Structured Error Logging

```pascal
procedure TMyApp.LogException(const AException: Exception; const AContext: string);
begin
  if AException is EIAM4DException then
  begin
    var LEx := EIAM4DException(AException);

    FLogger.Error(
      'IAM4D Error in %s: [%d] %s (HTTP: %d)',
      [AContext, Ord(LEx.ErrorCode), LEx.Message, LEx.HttpStatusCode]
    );

    // Log additional details if present
    if Assigned(LEx.AdditionalInfo) and (LEx.AdditionalInfo.Count > 0) then
    begin
      for var LPair in LEx.AdditionalInfo do
        FLogger.Debug('  %s: %s', [LPair.Key, LPair.Value]);
    end;
  end
  else
    FLogger.Error('Generic error in %s: %s', [AContext, AException.Message]);
end;
```

### Error Handling Best Practices

1. ✅ **Use ErrorCode for conditional logic**, not Message
2. ✅ **Handle expired tokens automatically** with retry
3. ✅ **Implement retry with exponential backoff** for network errors
4. ✅ **Always log HttpStatusCode and AdditionalInfo** for debugging
5. ✅ **Distinguish recoverable from non-recoverable errors**
6. ✅ **Show user-friendly messages** to end users
7. ✅ **Use OnFinally for cleanup** even in case of errors

---

## 🔒 Security

### OAuth2/OIDC Security

- ✅ **PKCE (RFC 7636)**: SHA-256 code challenge prevents authorization code interception
- ✅ **State Parameter**: CSRF protection via constant-time comparison
- ✅ **Nonce Validation**: Replay attack prevention in ID tokens
- ✅ **Token Expiration**: Automatic tracking with configurable buffer (default: 120s)
- ✅ **Secure Storage**: AES-256 encrypted in-memory token storage

### JWT Security

- ✅ **Signature Verification**: RS256 with JWKS public key rotation
- ✅ **Claim Validation**: Issuer, audience, expiration, not-before, issued-at
- ✅ **Clock Skew Tolerance**: Configurable (default: 60s)
- ✅ **Algorithm Whitelist**: Only RS256 accepted (prevents algorithm confusion)

### SSL/TLS Security

- ✅ **Certificate Validation**: Strict mode for production
- ✅ **Certificate Pinning**: SHA-256 public key pinning support
- ✅ **Configurable Modes**: Strict, self-signed (dev)
- ✅ **Custom Validators**: Interface for enterprise CAs or custom logic

### Integrated Libraries

IAMClient4D includes and directly uses the following excellent open-source libraries:

- **[LockBox3](https://github.com/TurboPack/LockBox3)**: Complete and robust Delphi cryptographic library for AES-256, RSA, and security operations
  - Used for: Token storage encryption, JWT RS256 signature validation, cryptographic operations
  - Standards-compliant cryptographic implementations
  - Integrated directly into project for maximum compatibility
  - **⚠️ IMPORTANT**: The project includes a modified version of LockBox3 with a necessary patch for large integer operations
    - Modification in `uTPLb_HugeCardinal.pas`: Disabling range checking (`{$R-}`) for big integer operations
    - Reason: Range checking is disabled because LockBox3 internal buffer operations generate range check errors with certain large values, even though the operations are mathematically correct
    - Security: This modification is safe as boundary checking is performed at a higher level in the algorithm
    - **Use only the LockBox3 version included in this project** to ensure proper operation

- **[DelphiCSPRNG](https://github.com/jimmckeeth/DelphiCSPRNG)**: Cryptographically Secure Pseudo-Random Number Generator
  - Used for: Secure generation of `state`, `nonce`, PKCE `code_verifier`, encryption keys
  - Based on system APIs for maximum entropy
  - Essential for OAuth2/OIDC flow security

**Note**: These libraries are already included in the project, no additional installation required. They ensure all cryptographic operations are performed according to industry best practices.

### Best Practices

1. **Always use HTTPS** in production
2. **Enable strict SSL validation** in production
3. **Use certificate pinning** for critical deployments
4. **Rotate client secrets** regularly
5. **Minimize token scopes** to required permissions
6. **Monitor token expiration** and proactive refresh
7. **Clear tokens on logout** (local and remote)
8. **Never log sensitive data** (tokens, passwords, secrets)

---

## 📄 License

**IAMClient4D** is distributed under **Apache License 2.0**.

```
Copyright (c) 2018-2025 Claudio Piffer

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

This allows **commercial use** while maintaining clear boundaries between open-source and proprietary code.

---

## 🤝 Contributing

Contributions are welcome! Follow these guidelines:

### Issue Reporting

Open an issue with:
- Delphi version
- Keycloak version (if applicable)
- Platform (VCL/FMX, Windows/macOS/etc.)
- Minimal reproducible example
- Relevant logs (remove sensitive data!)

### Pull Requests

- Align with existing code style
- Add XML documentation to public APIs
- Include unit tests where applicable
- No unnecessary dependencies
- Update README if adding features

### Code Style

- Use XML documentation comments (`///`)
- Follow Delphi naming conventions
- Keep methods focused (single responsibility)
- Prefer immutable records to mutable classes where appropriate
- Use interfaces for dependency injection

---

## 🗺️ Roadmap

### Planned Features

#### Security Improvements
- ✨ Integration with TMS Cryptography Pack library

#### Examples & Documentation
- ✨ Complete FMX/FGX mobile app with login and refresh

### Community Requests

Have a feature request? Open an issue with the `enhancement` label!

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/claudio-piffer/IAMClient4D/issues)
- **Discussions**: [GitHub Discussions](https://github.com/claudio-piffer/IAMClient4D/discussions)
- **Email**: [Contact author](mailto:claudio.piffer@gmail.com)

---

## 🙏 Acknowledgments

IAMClient4D is made possible thanks to these excellent open-source libraries and projects:

### Integrated Cryptographic Libraries
- **[LockBox3](https://github.com/TurboPack/LockBox3)** (TurboPack): Complete and robust Delphi cryptographic library for AES-256, RSA, and security operations. Fundamental for JWT validation and secure token storage. **Note**: The project includes a modified version with patches for big integer operations - use the included version.
- **[DelphiCSPRNG](https://github.com/jimmckeeth/DelphiCSPRNG)** (Jim McKeeth): Cryptographically secure random number generator, essential for OAuth2/OIDC flow security (PKCE, state, nonce).

### Frameworks and Platforms
- **[Keycloak](https://www.keycloak.org/)**: Excellent open-source IAM solution by Red Hat
- **[DMVCFramework](https://github.com/danieleteti/delphimvcframework)**: Powerful REST framework for Delphi by Daniele Teti

### Community
- **Delphi Community**: For continuous support, feedback, and contributions

---

<div align="center">

**Built with ❤️ for the Delphi community**

⭐ **Star this repo** if IAMClient4D helps your project!

[Report Bug](https://github.com/claudio-piffer/IAMClient4D/issues) • [Request Feature](https://github.com/claudio-piffer/IAMClient4D/issues) • [Contribute](CONTRIBUTING.md)

> **Note**: This documentation was created with the assistance of AI (Claude Code). While we strive for accuracy, some information may be incorrect or incomplete. If you find errors or have improvements, please open a pull request or issue!

</div>
