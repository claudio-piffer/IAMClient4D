# IAMClient4D DMVC Runtime Test

Console program that starts a real DMVCFramework server on the loopback interface and checks the IAMClient4D integration over HTTP. A fake JWT validator (`RuntimeTestValidatorU`) accepts only its own test tokens (`good`, `good-noiat`, plus `good-otheriss`, `good-badresource`, `good-rolesdown` and `good-noclaims` for the edge cases), so no identity provider is needed. Each run uses one of two modes: `middleware` (controllers protected by the deprecated `TIAM4DJWTMiddleware`, Minimal API groups by `IAM4DJWTEndpointFilter` and `IAM4DJWTBundle`) or `bundle` (`AEngine.Use(IAM4DJWTBundle(...))` for controllers and every Minimal API route). A small fake identity provider (Indy, port + 100) serves a JWKS for the `JWKS_URL` check (RS256 token of `tests/JWT/JWTTestVectorsU.pas`) and answers 500 otherwise, for the identity provider down check.

It builds against the DMVCFramework in `src/Lib/delphimvcframework` (not included: clone it there).

## What it checks

| Area | Checks |
|------|--------|
| Configuration | `TIAM4DJWTMiddleware` / `TIAM4DJWTAuthenticator` without `Issuer` (empty or `/`) raise `EIAM4DInvalidConfigurationException`; `IAM4DJWTBundle` / `IAM4DJWTEndpointFilter` without authenticator raise it too; the same bundle on the engine and on a group raises `EMVCConfigException`; a custom validator does not need it; an empty `TokenHeaderName` raises it too; a `TIAM4DJWTMiddlewareConfig` declared without `Create` has the secure defaults (`AllowAnonymous` off, audience check on); `SetExpectedAzp('')` clears the validator `azp`, an `azp` preset on a custom validator is kept; `CaseInsensitiveComparer` is one instance for 32 threads; built-in validator with an empty or blank `Audience` raises (constructor, `TIAM4DJWTMiddleware`, `SetAudienceValidationEnabled(True)`), accepted with `AudienceValidationEnabled` False and with a custom validator; `SSLValidator` given to the JWKS provider with the mode of `SSLValidationMode`, `PinnedPublicKeys` with `SSLValidator` refused, a pin not of 64 hex characters refused (Linux: `PinnedPublicKeys` raises `ENotSupportedException`) |
| Controllers (`TIAM4DJWTMiddleware`, `IAM4DJWTBundle`) | RFC 6750 challenges: no token or `Basic` credentials 401 `Bearer realm="..."` without error, 401 answered as `application/json` `{"error","message","status"}` without a `data` wrapper, also on an action with `[MVCProduces('text/plain')]` (whose 200 stays `text/plain`), invalid token 401 `error="invalid_token"`, `Require*` 403 `error="insufficient_scope"` (`scope` for `RequireScope`) with the generic message `Insufficient permissions` in body and challenge, the required roles logged as a warning, `RequireAuthentication` 401 with the same challenges; a validator returning True without claims: 401 `invalid_token` and a warning; `resource_access` with values that are not objects: skipped, 200; `bearer`/`BEARER` scheme accepted; claims, `LoggedUser` and Keycloak groups with a valid token; `LoggedUser.CustomData` (`sub`, `auth_time` in ISO 8601 UTC), `LoggedSince` in UTC with and without `iat`; no unused claims JSON in `Context.Data`; `[IAM4DPublic]` without, with an invalid and with a valid token; `RequireAnyRole`/`RequireAllRoles` with realm and audience client roles 200, with a role of another client 403; Swagger-like paths (`/items/openapi.json`) and OPTIONS on an action for every verb no longer bypass authentication; `LoggedUser.Roles` gets the client roles of the audience only; namespaced claim names (`https://app.example.com/tenant`) for `SubjectClaimName` and `GetCustomClaim*` |
| Logging | Rejected tokens logged as warnings (captured through a LoggerPro callback appender): CR/LF and control characters of the reason escaped, reason capped |
| Minimal API, `middleware` mode (`IAM4DJWTEndpointFilter`, `IAM4DJWTBundle` on groups) | 401 without or with an invalid token; 200 with a valid token while the middleware also runs on the same request, validated once; `RequireRealmRole` 403; public group without filter; `AllowAnonymous` (anonymous, authenticated, invalid token rejected); bundle on a group: `RolesClaimName` and `SubjectClaimName`, 401 without token; bundle on a sibling group: `JWKS_URL` (keys without discovery, real validator); real validator: header `typ` `at+jwt` and `application/at+jwt` (RFC 9068) accepted, `dpop+jwt` refused |
| Minimal API, `bundle` mode (engine-wide `IAM4DJWTBundle`) | group without filter: 401 (`application/json`) without or with an invalid token, 200 with a valid token, `RequireRealmRole` 403 with the generic message; bundle and group filter on the same authenticator validate once; every Minimal API route is checked; `[IAM4DPublic]` controller action still public |
| Claims transformation | `TIAM4DRolesClaimsTransformer` without loader or with a negative TTL raise `EIAM4DInvalidConfigurationException`; controllers in `rmMerge` (middleware `SetClaimsTransformer`, bundle `Config.ClaimsTransformer`) (application role satisfies `RequireAnyRole`, token roles kept, no cache with TTL 0, loader not called without a valid token); `middleware` mode, filter with `Config.ClaimsTransformer` in `rmReplace` (blank and duplicate roles dropped, token roles gone from `LoggedUser.Roles`, `Context.Keycloak` and `RequireRealmRole` still read the token); cache once per subject, the same `sub` of another issuer a different user (own roles, own entry), `Invalidate(Issuer, Subject)` and `Invalidate(Subject)` (every issuer), TTL expiry; loader raising: 503 `temporarily_unavailable` (`application/json`) logged as error, also with `AllowAnonymous` and a valid token; controllers with the loader raising: 503, and a `[IAM4DPublic]` action sees an anonymous user with empty `CustomData`; a load overtaken by `Invalidate` applies its roles to the request but caches nothing, the next load is cached |
| Identity provider unavailable (`middleware` mode) | Real validator, discovery answering 500: 503 with `Retry-After`, also within the refresh interval; failure logged as error |
| Swagger / OpenAPI | Bearer scheme and global security requirement injected in Swagger 2.0 and OpenAPI 3 documents generated by `SwaggerHTTPFilter` (by the middleware, or by the bundle registered before `SwaggerHTTPFilter`) |

## Run

From a command prompt (RAD Studio 13, Win64 by default):

```bat
tests\DMVC\RuntimeTest\run_tests.bat
tests\DMVC\RuntimeTest\run_tests.bat Win32
tests\DMVC\RuntimeTest\run_tests.bat Linux64
```

The script builds `IAM4DDMVCRuntimeTest.dproj` with MSBuild and runs the checks on Indy Direct and WebBroker, in `middleware` and in `bundle` mode (four runs). Set `RSVARS` to the `rsvars.bat` of another RAD Studio version if needed.

`Linux64` needs a Linux SDK added in the IDE (Tools > Options > Deployment > SDK Manager); the tests run through WSL (default distribution, `libcurl` required by `THTTPClient`). Without WSL the script only builds. The Linux executable can also be copied to any x86-64 Linux machine and run there.

The executable can also be run directly:

```
IAM4DDMVCRuntimeTest [indy|webbroker|httpsys] [port] [middleware|bundle]
```

- The mode defaults to `middleware`
- `httpsys` is Windows only and listens on `http://localhost:<port>/`; if the registration fails with "access denied", run from an elevated prompt or add a URL reservation: `netsh http add urlacl url=http://localhost:18767/ user=%USERNAME%`
- The fake identity provider listens on `127.0.0.1:<port + 100>`
- Exit code: number of failed checks (`0` = all passed, `99` = startup error); memory leaks are reported on stderr (Windows)
- Build output goes to `tests/bin` and `tests/dcu`; DMVC logs are written to `logs` next to the executable
