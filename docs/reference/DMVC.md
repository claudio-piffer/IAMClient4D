# DMVCFramework integration

JWT protection of DelphiMVCFramework REST APIs: a filter bundle that validates the bearer token of each request, fills `Context.LoggedUser` and the typed claims, answers 401/503, and documents the bearer scheme in Swagger/OpenAPI. Units in `src/DMVCMiddleware`, namespace `IAMClient4D.DMVC.*`. The validation itself (signature, `iss`, `aud`, `exp`, JWKS) is the one of `TIAM4DJWTValidator`: see [Security.md](Security.md). Getting tokens from a client application: see [Core.md](Core.md).

**Requirements**: DMVCFramework 3.5.0-silicon-rc10 or later (filter bundles, `TMVCUser`; not included: the samples and tests expect it in `src/Lib/delphimvcframework`). Works on the DMVC 3.5 hosts (Indy Direct, WebBroker, HTTP.sys). Coming from 2.x: [MIGRATION_3.0.md, section 9](../MIGRATION_3.0.md#9-dmvcframework).

**Example**: [`samples/DMVC/ScientificCalculator`](../../samples/DMVC/ScientificCalculator/README.md), the same API as a controller server and as a Minimal API server, with client roles, Swagger UI and a web client, against the Keycloak of [Docker/README.md](../../Docker/README.md) (issuer `http://localhost:18180/auth/realms/iamclient4d`, audience `api-server`).

## Contents

- [Units](#units)
- [Registering the filters](#registering-the-filters)
- [Filter functions](#filter-functions)
- [TIAM4DJWTMiddlewareConfig](#tiam4djwtmiddlewareconfig)
- [Authenticator](#authenticator)
- [What a request goes through](#what-a-request-goes-through)
- [Public endpoints](#public-endpoints)
- [Roles and scopes](#roles-and-scopes)
- [Controller helpers](#controller-helpers)
- [Claim DTOs](#claim-dtos)
- [Claims transformation](#claims-transformation)
- [Swagger / OpenAPI](#swagger--openapi)
- [Context keys and utilities](#context-keys-and-utilities)
- [Logging](#logging)
- [Deprecated middleware](#deprecated-middleware)
- [Web applications](#web-applications)
- [Tests](#tests)

## Units

| Unit | Content |
|------|---------|
| `IAMClient4D.DMVC.Filters` | `IAM4DJWTBundle`, `IAM4DJWTEndpointFilter`, `IAM4DSwaggerSecurityHTTPFilter` |
| `IAMClient4D.DMVC.Authenticator` | `TIAM4DJWTMiddlewareConfig`, `IIAM4DJWTAuthenticator`, `TIAM4DJWTAuthenticator` |
| `IAMClient4D.DMVC.Attributes` | `[IAM4DPublic]` |
| `IAMClient4D.DMVC.Helpers` | `TIAM4DJWTHelper`, class helper for `TWebContext`: `JWT`, `Keycloak`, `Require*`, custom claims |
| `IAMClient4D.DMVC.DTO` | `TIAM4DJWTClaims`, `TIAM4DKeycloakClaims`, `TIAM4DKeycloakRealmAccess`, `TIAM4DKeycloakClientAccess` |
| `IAMClient4D.DMVC.ClaimsTransformation` | `IIAM4DClaimsTransformer`, `TIAM4DRolesClaimsTransformer` |
| `IAMClient4D.DMVC.Common` | Context keys, `BearerChallenge`, `SanitizeLogText`, `CaseInsensitiveComparer` |
| `IAMClient4D.DMVC.Middleware` | `TIAM4DJWTMiddleware`, deprecated |
| `IAMClient4D.DMVC.Internal` | Shared by the filters and the middleware; not public API |

## Registering the filters

### Engine-wide

`FEngine.Use(IAM4DJWTBundle(...))` protects every controller action and every Minimal API route. The order of the engine filters matters: the first registered is the outermost.

<!-- snippet ver=3.0 kind=body ctx=dmvc_engine uses=MVCFramework.Filters.OpenAPI,MVCFramework.OpenAPI3 -->
```delphi
var LInfo := Default(TMVCOpenAPIInfo);
LInfo.Title := 'Calculator API';
LInfo.Version := '1.0';

// 1. CORS first: it answers the preflight before any token is asked. A browser reads the
//    challenge (401/403) and Retry-After (503) only through the exposed headers
FEngine.Use(CORSHTTPFilter('http://localhost:8092', False, 'WWW-Authenticate,Retry-After'));

// 2. Token check
FEngine.Use(IAM4DJWTBundle(
  'http://localhost:18180/auth/realms/iamclient4d', // Issuer: OIDC discovery and JWKS
  'api-server'));                                   // Audience: the client ID of this API

// 3. The document after the bundle: the bearer scheme is added on the way out
FEngine.Use(OpenAPIHTTPFilter(FEngine, LInfo, '/openapi.json'));
```

- Requests answered before routing (CORS preflight, Swagger/OpenAPI documents of `SwaggerHTTPFilter`/`OpenAPIHTTPFilter`, static files) never reach the token check: it is an endpoint filter, run after routing.
- OPTIONS requests that reach an action are authenticated like the other verbs: the CORS filter must answer the preflight.
- A controller action or controller marked `[IAM4DPublic]` is public. A Minimal API route under the engine-wide bundle always requires a token (unless `AllowAnonymous`).

### On Minimal API route groups

To keep some Minimal API routes public, put the filter on the protected groups only. One authenticator shared by the groups means one validator and one JWKS cache. The HTTP part of a bundle put on a group is added to the engine after the filters of the engine configuration, so it does not see the Swagger/OpenAPI document: register `IAM4DSwaggerSecurityHTTPFilter()` on the engine yourself.

<!-- snippet ver=3.0 kind=body ctx=dmvc_engine uses=MVCFramework.MinimalAPI,IAMClient4D.DMVC.Helpers -->
```delphi
var LAuthenticator: IIAM4DJWTAuthenticator := TIAM4DJWTAuthenticator.Create(
  TIAM4DJWTMiddlewareConfig.Create('http://localhost:18180/auth/realms/iamclient4d', 'api-server', ''));

FEngine.Use(IAM4DSwaggerSecurityHTTPFilter()); // bearer scheme in the document

// Protected group: token (401), then role (403, DMVC filter on LoggedUser.Roles)
FEngine.Prefix('/api/math')
  .Use(IAM4DJWTEndpointFilter(LAuthenticator))
  .Use(RequireRoleEndpointFilter('calculator-user'))
  .MapGet<TWebContext>('/whoami',
    function(AContext: TWebContext): IMVCResponse
    begin
      Result := Ok(AContext.JWT.PreferredUsername);
    end);

// Public group: no filter
FEngine.Prefix('/api/public')
  .MapGet('/ping',
    function: IMVCResponse
    begin
      Result := Ok('pong');
    end);
```

`TMVCRouteGroup` is a record and `Use` returns a new group: chain the calls, or keep the returned group. A bundle is registered once: the same bundle on the engine and on a group, or twice, raises `EMVCConfigException` (DMVC). Several bundles or endpoint filters built on the same authenticator validate the token once per request.

## Filter functions

Unit `IAMClient4D.DMVC.Filters`.

| Function | Returns | Notes |
|----------|---------|-------|
| `IAM4DJWTBundle(AConfig)` | `IMVCFilterBundle` | Creates a `TIAM4DJWTAuthenticator` from the configuration |
| `IAM4DJWTBundle(AIssuer, AAudience, ASSLValidationMode = svmStrict, AExpectedAzp = '')` | `IMVCFilterBundle` | Configuration from `TIAM4DJWTMiddlewareConfig.Create(AIssuer, AAudience, '')` plus the two settings |
| `IAM4DJWTBundle(AAuthenticator)` | `IMVCFilterBundle` | On an existing authenticator (shared, or a custom implementation). `nil` raises `EIAM4DInvalidConfigurationException` |
| `IAM4DJWTEndpointFilter(...)` | `TMVCEndpointFilter` | Same three overloads. The check part of the bundle, without the Swagger part |
| `IAM4DSwaggerSecurityHTTPFilter` | `TMVCHTTPFilter` | Adds the bearer scheme to Swagger 2.0 / OpenAPI 3 documents. Part of the bundle |

The bundle holds one HTTP filter (`IAM4DSwaggerSecurityHTTPFilter`) and one endpoint filter (`IAM4DJWTEndpointFilter`). The endpoint filter:

1. calls `AuthenticateRequest` on every request, also for public actions, so a public action sees the user when a valid token is sent;
2. lets a controller action marked `[IAM4DPublic]` pass;
3. otherwise calls `AuthorizeRequest`: on refusal the 401/503 response is already written and the filter returns `nil` (the action does not run).

The 401/503 body is `application/json` also for an action whose `[MVCProduces]` is another type.

## TIAM4DJWTMiddlewareConfig

Unit `IAMClient4D.DMVC.Authenticator` (alias in `IAMClient4D.DMVC.Middleware`). A record with an `Initialize` operator: every variable of the type starts with the defaults below, also a local variable filled field by field without `Create`.

`class function Create(const AIssuer, AAudience, AJWKS_URL: string): TIAM4DJWTMiddlewareConfig` sets the three fields on top of the defaults.

| Field | Default | Meaning |
|-------|---------|---------|
| `Issuer` | `''`, required | Expected `iss`. Discovery and keys are fetched for this issuer only |
| `Audience` | `''` | Expected `aud` (the client ID of the API). Also the `realm` of the challenges, and the client whose roles go to `LoggedUser.Roles` |
| `AudienceValidationEnabled` | `True` | `False` accepts the tokens of any client of the realm (warning in the log at startup) |
| `JWKS_URL` | `''` | Empty: OIDC discovery from `Issuer`. Set: JWKS endpoint of `Issuer`, no discovery |
| `JWKSCacheDurationMinutes` | 60 | JWKS cache TTL; 0 or less keeps the provider default |
| `ClockSkewSeconds` | 60 | Clock tolerance of the time checks of the validator |
| `TokenHeaderName` | `'Authorization'` | Header carrying the token; empty raises |
| `TokenPrefix` | `'Bearer '` | Scheme prefix, compared case-insensitively (RFC 7235). A header with another scheme (e.g. `Basic`) counts as no token |
| `SubjectClaimName` | `'sub'` | Claim stored in `LoggedUser.CustomData['sub']` (falls back to `sub` when absent or not a string); last fallback of `LoggedUser.UserName`. A top-level key, not a JSON path |
| `RolesClaimName` | `'roles'` | Top-level claim (array of strings or one string) added to `LoggedUser.Roles`; `''` = none |
| `AllowAnonymous` | `False` | A request without a token passes unauthenticated. A token that fails validation is still refused |
| `SSLValidationMode` | `svmStrict` | TLS validation of discovery and JWKS. `svmAllowSelfSigned`: tests only (warning in the log) |
| `PinnedPublicKeys` | `nil` | SHA-256 pins of the identity provider certificate public key (format of `IIAM4DClient.AddPinnedPublicKeys`), for discovery and JWKS. Not with `SSLValidator`. Linux: `ENotSupportedException` |
| `SSLValidator` | `nil` | Certificate validator of discovery and JWKS; its mode is set to `SSLValidationMode`. Called only in `svmAllowSelfSigned`, with pins, or on Android |
| `ExpectedAzp` | `''` | Required `azp` (not checked when empty). Its client roles also go to `LoggedUser.Roles` |
| `RequireAzpWhenMultipleAud` | `True` | `azp` required when `aud` has several values |
| `HTTPConnectTimeoutMs` | 10000 | Discovery and JWKS run in the request thread |
| `HTTPReceiveTimeoutMs` | 15000 | |
| `ExpectedTokenType` | `'Bearer'` | Payload `typ` (Keycloak writes `Bearer` in access tokens, `ID` in id_tokens). A token without `typ` passes; `''` = not checked |
| `AllowedHeaderTypes` | `['JWT', 'at+jwt']` | Header `typ` accepted. `at+jwt` is RFC 9068 (Keycloak client option "Use 'at+jwt' as access token header type"). `['at+jwt']` accepts only those, `['JWT']` is the 2.x behaviour |
| `RejectedTokenWarningIntervalSec` | 10 | At most one warning per interval for rejected tokens, the others at debug level; 0 = a warning for each |
| `ClaimsTransformer` | `nil` | See [Claims transformation](#claims-transformation) |

With a custom validator (`TIAM4DJWTAuthenticator.Create(AValidator, AConfig)`), `JWKS_URL`, `JWKSCacheDurationMinutes`, the HTTP and TLS settings, `PinnedPublicKeys`, `SSLValidator`, `ExpectedTokenType` and `AllowedHeaderTypes` are not used (a warning is logged for `JWKS_URL`, pins and `SSLValidator`): configure the validator.

<!-- snippet ver=3.0 kind=body ctx=dmvc_engine -->
```delphi
var LConfig := TIAM4DJWTMiddlewareConfig.Create(
  'http://localhost:18180/auth/realms/iamclient4d', 'api-server', '');
LConfig.ClockSkewSeconds := 30;
LConfig.AllowedHeaderTypes := ['at+jwt']; // RFC 9068 access tokens only
LConfig.ExpectedAzp := 'calculator-web';  // only tokens issued to this client
FEngine.Use(IAM4DJWTBundle(LConfig));
```

### Startup errors

`EIAM4DInvalidConfigurationException` (unit `IAMClient4D.Exceptions`) is raised when the authenticator is created (the bundle or filter function call):

- `Issuer` empty (or only `/`);
- `TokenHeaderName` empty;
- `Audience` empty while `AudienceValidationEnabled` is `True` (built-in validator only);
- `PinnedPublicKeys` together with `SSLValidator`, or a pin in the wrong format;
- `AllowedHeaderTypes` refused by the validator.

## Authenticator

Unit `IAMClient4D.DMVC.Authenticator`. The authentication core shared by the bundle, the endpoint filter and the deprecated middleware. Create one explicitly to share it between filters.

| Member | Description |
|--------|-------------|
| `TIAM4DJWTAuthenticator.Create(AConfig)` | Built-in `TIAM4DJWTValidator` with a dedicated `TIAM4DJWKSProvider` |
| `TIAM4DJWTAuthenticator.Create(AValidator, AConfig)` | Custom `IIAM4DJWTValidator`. `ClockSkewSeconds` is set on it; the audience and `azp` settings of `AConfig` too, when it supports `IIAM4DJWTValidatorConfigurable` (an `azp` already set on it is kept when `ExpectedAzp` is empty). `Audience` may be empty. `nil` raises |
| `AuthenticateRequest(AContext)` | Validates the bearer token, if any, and publishes the result (see below). Never blocks the request. Runs once per request and authenticator |
| `AuthorizeRequest(AContext): Boolean` | Applies the policy to an authenticated request: `True` to proceed, or writes 401/503 and returns `False` |
| `SetExpectedAzp(AValue)` | `''` clears the `azp` check |
| `SetRequireAzpWhenMultipleAud(AValue)` | |
| `SetAudienceValidationEnabled(AValue)` | `True` with an empty `Audience` raises (built-in validator) |
| `SetClaimsTransformer(AValue)` | `nil` = none |
| `Config` | Copy of the current configuration |

The authenticator is called concurrently by the server threads. The setters are not thread-safe: call them before the server starts handling requests.

## What a request goes through

### AuthenticateRequest

1. Sets `Context.Data['JWT_Auth_Status']` to `not_authenticated` and `Context.Data['JWT_Realm']` to `Audience`; clears the claims of a previous authenticator.
2. Reads `TokenHeaderName`; without `TokenPrefix` there is no token: stop.
3. Status `invalid_token`, then validation. On success it fills the context and calls the claims transformer; status `authenticated`.
4. On failure the status stays `invalid_token` (rejected token, validator returning no claims, unexpected error), or becomes `unavailable` when the identity provider (discovery, JWKS) cannot be reached (`EIAM4DJWKSUnavailableException`) or the claims transformer raises. The claims and `LoggedUser` filled in the meantime are cleared.

On success:

| Target | Content |
|--------|---------|
| `LoggedUser.UserName` | `preferred_username`, else `email`, else the subject |
| `LoggedUser.Realm` | `azp`, else `Audience` |
| `LoggedUser.LoggedSince` | `iat` (UTC), else the current UTC time |
| `LoggedUser.Roles` | `RolesClaimName` claim, `realm_access.roles`, `resource_access` roles of `Audience` and `ExpectedAzp` only. De-duplicated, case-sensitive |
| `LoggedUser.CustomData` | `sub` (the subject of `SubjectClaimName`), `email` and `email_verified` (`True`/`False`), `given_name`, `family_name`, `name`, `iss`, `sid`, `acr`; `exp`, `iat`, `auth_time` in ISO 8601 UTC (`2026-01-01T00:00:00.000Z`); `scopes` and `groups` comma-separated. Only the claims present |
| `Context.Data` | `JWT_Claims_JSON` (claims), `JWT_Token` (raw token): read them through `Context.JWT` and `Context.Keycloak` |

`LoggedUser` is cleared before it is filled, so a user loaded from a session does not mix with the token.

### AuthorizeRequest

| Status | `AllowAnonymous` | Answer |
|--------|------------------|--------|
| `authenticated` | any | Proceeds |
| `not_authenticated` | `True` | Proceeds, anonymous |
| `not_authenticated` | `False` | 401, `WWW-Authenticate: Bearer realm="<Audience>"`, message `Missing or invalid Authorization header` |
| `invalid_token` | any | 401, `WWW-Authenticate: Bearer realm="<Audience>", error="invalid_token", error_description="Invalid or expired JWT token"` |
| `unavailable` | any | 503 `temporarily_unavailable`, `Retry-After` when the JWKS provider gives one; the client may retry with the same token |

Body: `{"error": "unauthorized" | "temporarily_unavailable", "message": "...", "status": 401 | 503}`. `realm` is omitted when `Audience` is empty. Challenges follow RFC 6750: `error` only when a token was sent. 403 never comes from the filter: it comes from the [role and scope checks](#roles-and-scopes).

## Public endpoints

`IAM4DPublicAttribute` (unit `IAMClient4D.DMVC.Attributes`) on a controller class makes all its actions public; on a method, that action only.

<!-- snippet ver=3.0 kind=decl ctx=dmvc_ctx uses=IAMClient4D.DMVC.Attributes -->
```delphi
type
  [MVCPath('/api')]
  TInfoController = class(TMVCController)
  public
    [MVCPath('/info')]
    [MVCHTTPMethod([httpGET])]
    [IAM4DPublic]
    function Info: IMVCResponse;
  end;

function TInfoController.Info: IMVCResponse;
begin
  // A valid token is still read; an invalid one is ignored here
  if Context.IsAuthenticated then
    Result := OKResponse('Hello ' + Context.JWT.PreferredUsername)
  else
    Result := OKResponse('Hello');
end;
```

- A public action runs whatever the token: none, invalid or valid. `Context.IsAuthenticated` is `True` only for a valid one. A claims transformer failure leaves the user anonymous with empty `CustomData`.
- The attribute is read with RTTI by qualified class name (cached per action): the controller must be declared in the interface section of its unit. Otherwise its actions stay protected and a warning is logged.
- Minimal API routes have no attribute: keep public routes in groups without the filter.
- A controller that serves its own Swagger/OpenAPI document must be marked `[IAM4DPublic]`: document paths have no exemption.

## Roles and scopes

The library has no role or scope attribute. DMVC's `[MVCRequiresAuthentication]` and `[MVCRequiresRole]` are read by DMVC's role-based authentication handler, not by the IAMClient4D filter: under `IAM4DJWTBundle` they do nothing. Check roles with:

| Check | Where | Reads | Answer |
|-------|-------|-------|--------|
| `Context.RequireAnyRole`, `RequireAllRoles` | Action, `OnBeforeAction`, endpoint filter | `LoggedUser.Roles` | 403 `insufficient_scope` |
| `Context.RequireScope` | same | `scope` claim (`scp` when absent) | 403 `insufficient_scope` with `scope="..."` |
| `Context.RequireRealmRole`, `RequireAnyRealmRole` | same | `realm_access.roles` of the token | 403 `insufficient_scope` |
| `Context.RequireGroup` | same | `groups` claim of the token | 403 `insufficient_scope` |
| `RequireRoleEndpointFilter` (DMVC, `MVCFramework.Filters`) | Minimal API group, after the IAMClient4D filter | `LoggedUser.Roles` (any of) | 401 if `LoggedUser.IsValid` is false, 403 `Insufficient privileges`, no challenge |

All comparisons are case-sensitive, as Keycloak names roles. `LoggedUser.Roles` is one list of names: a realm role and a client role with the same name are one entry. To tell them apart use `Context.Keycloak.RealmAccess.HasRole` or `Context.Keycloak.GetClientAccess('<client>').HasRole`. `RequireRealmRole` and `RequireGroup` read the signed token, so a claims transformer does not change them.

One policy for a whole controller:

<!-- snippet ver=3.0 kind=decl ctx=dmvc_ctx -->
```delphi
type
  [MVCPath('/api/advanced')]
  TAdvancedController = class(TMVCController)
  protected
    procedure OnBeforeAction(AContext: TWebContext; const AActionName: string;
      var AHandled: Boolean); override;
  end;

procedure TAdvancedController.OnBeforeAction(AContext: TWebContext; const AActionName: string;
  var AHandled: Boolean);
begin
  inherited;
  AContext.RequireAnyRole(['calculator-advanced']); // 401, 503 or 403 as EMVCException
end;
```

The same check as a route group filter, with the IAMClient4D 403 (challenge and generic message) instead of DMVC's:

<!-- snippet ver=3.0 kind=decl ctx=dmvc_ctx -->
```delphi
function RequireIAM4DRole(const ARole: string): TMVCEndpointFilter;
begin
  Result :=
    function(const AContext: TWebContext; const ANext: TMVCEndpointFilterNext): IMVCResponse
    begin
      AContext.RequireAnyRole([ARole]);
      Result := ANext();
    end;
end;
```

## Controller helpers

`TIAM4DJWTHelper`, class helper for `TWebContext` (unit `IAMClient4D.DMVC.Helpers`). Each request has its own `TWebContext`: no locking needed.

| Method | Description |
|--------|-------------|
| `JWT: TIAM4DJWTClaims` | Standard claims; `RawToken` holds the bearer token. Parses at every call: keep it in a local variable |
| `Keycloak: TIAM4DKeycloakClaims` | `realm_access`, `resource_access`, `groups`, `allowed-origins`. Parses at every call |
| `IsAuthenticated: Boolean` | A valid token was validated for this request |
| `IsPublicEndpoint: Boolean` | `not IsAuthenticated` |
| `GetCustomClaim(AName[, ADefault])` | String claim, `''` or `ADefault` when missing |
| `TryGetCustomClaim(AName, out AValue)` | |
| `GetCustomClaimAsInteger(AName, ADefault = 0)`, `GetCustomClaimAsBoolean(AName, ADefault = False)` | |
| `GetCustomClaimAsDateTime(AName)` | Unix time to UTC `TDateTime`; 0 when missing |
| `RequireAuthentication` | 401 with challenge (`invalid_token` when a token was sent), or 503 with `Retry-After` when the identity provider was unavailable |
| `RequireAnyRole(ARoles)`, `RequireAllRoles(ARoles)` | On `LoggedUser.Roles` |
| `RequireScope(AScope)` | Challenge with `scope="AScope"` |
| `RequireRealmRole(ARole)`, `RequireAnyRealmRole(ARoles)` | On `realm_access.roles` |
| `RequireGroup(AGroup)` | Exact group string, as the `groups` mapper writes it (e.g. `/admins` with full path) |

- A claim name is a top-level key of the payload, not a JSON path: `'https://app.example.com/tenant'` (Auth0, Okta) is read as it is.
- The `Require*` methods raise `EMVCException` (DMVC renders the body). Every `Require*` starts with `RequireAuthentication`.
- A 403 carries `WWW-Authenticate: Bearer realm="...", error="insufficient_scope", error_description="Insufficient permissions"` and the message `Insufficient permissions`. What was required is logged as a warning, never sent to the client.

<!-- snippet ver=3.0 kind=body ctx=dmvc_ctx -->
```delphi
Context.RequireScope('openid');
var LClaims := Context.JWT; // parsed once
var LTenant := Context.GetCustomClaim('https://app.example.com/tenant', 'default');
if not Context.Keycloak.GetClientAccess('api-server').HasRole('calculator-advanced') then
  raise EMVCException.Create(HTTP_STATUS.Forbidden, 'Insufficient permissions');
Writeln(LClaims.PreferredUsername, ' ', LTenant, ' ', LClaims.WasMfaUsed);
```

## Claim DTOs

Unit `IAMClient4D.DMVC.DTO`. Records, nothing to free. Times are UTC `TDateTime` (0 when the claim is missing); string fields are filled only from JSON strings.

**`TIAM4DJWTClaims`**

| Field | Claim |
|-------|-------|
| `Subject`, `Issuer`, `JwtId`, `AuthorizedParty`, `Acr`, `TokenType`, `SessionId` | `sub`, `iss`, `jti`, `azp`, `acr`, `typ`, `sid` |
| `Audience: TArray<string>` | `aud`, string or array |
| `ExpirationTime`, `IssuedAtTime`, `NotBeforeTime`, `AuthTime` | `exp`, `iat`, `nbf`, `auth_time` |
| `Email`, `EmailVerified`, `PreferredUsername`, `GivenName`, `FamilyName`, `Name` | OIDC standard claims |
| `Roles: TArray<string>` | `roles` claim only (not `RolesClaimName`, not Keycloak roles) |
| `Scopes: TArray<string>` | `scope` (space-separated string or array), else `scp` (Entra ID) |
| `Amr: TArray<string>` | `amr` (RFC 8176) |
| `RawToken` | The bearer token (set by `Context.JWT`) |

| Method | Description |
|--------|-------------|
| `IsExpired`, `IsNotYetValid` | Against the current UTC time, no skew; `False` without `exp`/`nbf` |
| `HasRole`, `HasAnyRole`, `HasAllRoles` | On `Roles` |
| `HasScope` | On `Scopes` |
| `HasAuthMethod(AMethod)`, `WasMfaUsed`, `WasPasskeyUsed` | On `Amr`; passkey = `user`, `hwk` or `swk` |
| `ToJSON: TJSONObject` | Caller frees it. Times in ISO 8601 UTC |
| `Empty`, `ParseFromPayload(APayload)` | Class functions |

**`TIAM4DKeycloakClaims`**: `RealmAccess: TIAM4DKeycloakRealmAccess` (`Roles`, `HasRole`, `HasAnyRole`), `ResourceAccess: TArray<TIAM4DKeycloakClientAccess>` (`ClientID`, `Roles`, `HasRole`, `HasAnyRole`; clients without roles are skipped), `Groups`, `AllowedOrigins`.

| Method | Description |
|--------|-------------|
| `GetClientAccess(AClientID)` | Roles of one client; empty record when absent |
| `HasGroup(AGroup)` | Exact match |
| `GetAllRoles` | Realm roles plus the roles of every client (unlike `LoggedUser.Roles`) |
| `GetAllRoles(AClientID)` | Realm roles plus the roles of one client |
| `ToJSON`, `Empty`, `ParseFromPayload` | As above |

All `Has*` comparisons are case-sensitive.

## Claims transformation

Unit `IAMClient4D.DMVC.ClaimsTransformation`. Authentication by the identity provider, authorization by the application: a transformer enriches `LoggedUser` after a valid token, e.g. with roles kept in the application database.

**`IIAM4DClaimsTransformer.Transform(AContext, AClaims, AUser)`**

- Called once per request, only for a valid token, after `LoggedUser` has been filled. `AClaims` is read-only and freed after the call.
- The token is not changed: `Context.JWT`, `Context.Keycloak` and `RequireRealmRole`/`RequireGroup` keep what the identity provider signed; `RequireAnyRole`/`RequireAllRoles` and DMVC's `RequireRoleEndpointFilter` read `LoggedUser.Roles`.
- Called concurrently: the implementation must be thread-safe.
- An exception rejects the request with 503 `temporarily_unavailable` (logged as error), also with `AllowAnonymous`.

**`TIAM4DRolesClaimsTransformer`** sets `LoggedUser.Roles` from a loader.

`Create(ALoader, AMode = rmReplace, ACacheTTLSeconds = 60, AMaxCacheEntries = 10000)`

| Parameter | Description |
|-----------|-------------|
| `ALoader: TIAM4DRolesLoader` | `function(const ASubject: string; const AClaims: TJSONObject): TArray<string>`. `ASubject` is `LoggedUser.CustomData['sub']`. Empty array for an unknown user. Required |
| `AMode` | `rmReplace`: loaded roles only. `rmMerge`: token roles plus loaded roles |
| `ACacheTTLSeconds` | Cache per issuer and subject; 0 = the loader runs on every request |
| `AMaxCacheEntries` | When full: expired entries purged, then an eighth of the oldest |

Invalid arguments raise `EIAM4DInvalidConfigurationException`. Without a subject the loader is not called (in `rmReplace` the user gets no roles). Loaded roles are trimmed, blanks dropped, duplicates skipped. The loader runs outside the cache lock, so concurrent misses may call it more than once for the same subject. A subject is unique only within its issuer: with several identity providers, read `iss` from `AClaims`.

| Member | Description |
|--------|-------------|
| `Invalidate(ASubject)` | Drops the subject for every issuer |
| `Invalidate(AIssuer, ASubject)` | One issuer |
| `Clear` | Everything |
| `CacheCount` | Cached entries, expired ones included until purged |
| `Mode` | |

A load already running when `Invalidate` or `Clear` is called applies its roles to its request but does not cache them.

<!-- snippet ver=3.0 kind=body ctx=dmvc_engine uses=IAMClient4D.DMVC.ClaimsTransformation -->
```delphi
var LConfig := TIAM4DJWTMiddlewareConfig.Create(
  'http://localhost:18180/auth/realms/iamclient4d', 'api-server', '');
LConfig.ClaimsTransformer := TIAM4DRolesClaimsTransformer.Create(
  function(const ASubject: string; const AClaims: TJSONObject): TArray<string>
  begin
    // e.g. SELECT role FROM user_roles WHERE subject = :subject
    Result := ['reports-reader'];
  end,
  TIAM4DRolesMode.rmMerge, 120);
FEngine.Use(IAM4DJWTBundle(LConfig));
```

## Swagger / OpenAPI

`IAM4DSwaggerSecurityHTTPFilter` (part of the bundle) runs after the inner filters and, for a GET whose file name (last path segment) contains `swagger`, `openapi` or `api-docs` and ends with `.json`, adds to the JSON document:

- OpenAPI 3: `components.securitySchemes.bearer` (`type: http`, `scheme: bearer`, `bearerFormat: JWT`);
- Swagger 2.0: `securityDefinitions.bearer` (API key in the `Authorization` header, value `Bearer <token>`);
- in both, a global `security` requirement on `bearer`. Existing entries are kept.

The document must be produced by a filter registered after it (`OpenAPIHTTPFilter`, `SwaggerHTTPFilter`), as text or as a `TMemoryStream`. Compressed responses are left untouched, and so are documents that are neither Swagger 2.0 nor OpenAPI 3 (with a warning in the log). Do not register `CompressionHTTPFilter` between the IAMClient4D filter and the document filter: register it first (outermost) or after the document filter.

## Context keys and utilities

Unit `IAMClient4D.DMVC.Common`.

| Constant | Value | Content of `Context.Data` |
|----------|-------|---------------------------|
| `CONTEXT_KEY_AUTH_STATUS` | `JWT_Auth_Status` | `AUTH_STATUS_AUTHENTICATED` (`authenticated`), `AUTH_STATUS_NOT_AUTHENTICATED` (`not_authenticated`, no token), `AUTH_STATUS_INVALID_TOKEN` (`invalid_token`), `AUTH_STATUS_UNAVAILABLE` (`unavailable`) |
| `CONTEXT_KEY_JWT_CLAIMS` | `JWT_Claims_JSON` | Validated claims as JSON |
| `CONTEXT_KEY_JWT_TOKEN` | `JWT_Token` | Raw token |
| `CONTEXT_KEY_REALM` | `JWT_Realm` | Realm of the challenges (`Audience`) |
| `CONTEXT_KEY_RETRY_AFTER` | `JWT_Retry_After` | Seconds for `Retry-After` of a 503 |
| `CONTEXT_KEY_STD_JSON`, `CONTEXT_KEY_KC_JSON`, `CACHE_KEY`, `KC_CACHE_KEY` | | Deprecated, no longer populated |

| Routine | Description |
|---------|-------------|
| `BearerChallenge(ARealm, AError, ADescription, AScope = '')` | `WWW-Authenticate` value of the Bearer scheme; empty parameters omitted, values reduced to the characters RFC 6750 allows |
| `SanitizeLogText(AText, AMaxLength = 512)` | Control characters escaped (`\r`, `\n`, `\t`, `\xHH`, `\uHHHH`), capped with the original length appended |
| `CaseInsensitiveComparer` | Shared `IEqualityComparer<string>`. Not used by the library since 3.0; kept for application code |

## Logging

Through the DMVC logger (LoggerPro).

| Event | Level |
|-------|-------|
| Authenticator created (issuer, audience, JWKS URL, number of pins) | info |
| Audience check off, `svmAllowSelfSigned` | warning at startup |
| `AllowAnonymous` on | info at startup |
| Rejected token | warning at most once per `RejectedTokenWarningIntervalSec` (with the count of the others), debug otherwise; reason sanitized (`iss`, `alg`, `kid` come from the client) |
| Identity provider unavailable, claims transformer failure, unexpected validation error | error |
| 403 of the `Require*` helpers (user, method, path, what was required) | warning |
| `[IAM4DPublic]` not readable (controller in the implementation section) | warning, once per action |

## Deprecated middleware

`TIAM4DJWTMiddleware` (unit `IAMClient4D.DMVC.Middleware`) is a DMVC classic middleware, deprecated as every classic middleware in DMVC 3.5 (warning W1000). It runs the same authenticator: `OnBeforeRouting` authenticates, `OnBeforeControllerAction` applies `[IAM4DPublic]` and `AuthorizeRequest`, `OnAfterRouting` injects the Swagger scheme. It protects controller actions only: Minimal API routes never reach it.

Constructors: `Create(AConfig)`, `Create(AIssuer, AAudience, AJWKS_URL, AExpectedAzp = '')`, `Create(AIssuer, AAudience, ASSLValidationMode = svmStrict, AExpectedAzp = '')`, `Create(AValidator, AConfig)`. Setters `SetExpectedAzp`, `SetRequireAzpWhenMultipleAud`, `SetAudienceValidationEnabled`, `SetClaimsTransformer` (before the server starts). `Authenticator` exposes the authenticator, to pass it to `IAM4DJWTEndpointFilter`. Replace `FEngine.AddMiddleware(TIAM4DJWTMiddleware.Create(...))` with `FEngine.Use(IAM4DJWTBundle(...))`: see [MIGRATION_3.0.md, 9.1](../MIGRATION_3.0.md#91-from-the-middleware-to-the-filter-bundle).

## Web applications

The DMVC units protect APIs. A server-side web application that logs users in (authorization code with PKCE) uses `IIAM4DClient` of the core library, one per user session: see [Core.md](Core.md). The `WebClient` of the ScientificCalculator sample does this (confidential client `calculator-web`) and calls the API with the user's access token.

## Tests

[`tests/DMVC/RuntimeTest`](../../tests/DMVC/RuntimeTest/README.md) starts a real DMVC server with a fake validator (no identity provider) and checks the bundle, the endpoint filter, the middleware, `[IAM4DPublic]`, the helpers, the challenges, logging, 503, claims transformation and the Swagger injection over HTTP, on Indy Direct and WebBroker, Win32, Win64 and Linux64:

```bat
tests\DMVC\RuntimeTest\run_tests.bat
tests\DMVC\RuntimeTest\run_tests.bat Linux64
```
