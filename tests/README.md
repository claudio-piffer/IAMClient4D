# IAMClient4D Tests

Console programs, one folder per area. Each folder has a `run_tests.bat` that builds the program with `msbuild` and runs it:

```bat
tests\<folder>\run_tests.bat            :: Win64 (default)
tests\<folder>\run_tests.bat Win32
tests\<folder>\run_tests.bat Linux64    :: built for Linux, run through WSL (only built without WSL)
```

Exit code 0 when every check passes. On Windows the scripts run the programs through [`run_checked.bat`](run_checked.bat): a memory leak reported at exit (`ReportMemoryLeaksOnShutdown`, on stderr) fails the suite too, although the program set exit code 0.

Nothing is skipped silently: a check that cannot run (no Internet, an optional Keycloak extension missing) is printed as `SKIP` and counted in the summary. A missing test server fails the suite, unless `IAM4D_ALLOW_SKIP=1` (IdentityProvider without Keycloak, TLS without OpenSSL).

| Folder | What it checks | Needs |
|---|---|---|
| [`Async`](Async/README.md) | `Async.Core`: exceptions, completion sources, callbacks and dispatch modes | nothing |
| [`Crypto`](Crypto/README.md) | LockBox3, TMS and TaurusTLS providers: JWS and AES-GCM vectors, token storage | OpenSSL folders for TaurusTLS (`OPENSSL_DIRS`, default `C:\OpenSSL3-<platform>` and `C:\OpenSSL4-<platform>` when they exist) |
| [`JWT`](JWT/README.md) | `TIAM4DJWTValidator` and `TIAM4DJWKSProvider` against a fake identity provider | nothing |
| [`KeycloakClient`](KeycloakClient/README.md) | Login flows of `TIAM4DKeycloakClient` against a fake identity provider, no browser | nothing |
| [`HTTPTimeout`](HTTPTimeout/README.md) | HTTP timeouts against a slow local server | nothing |
| [`TLS`](TLS/README.md) | Certificate validation and public key pinning over real TLS handshakes (local Indy + TaurusTLS servers) | OpenSSL for the servers (`OPENSSL_DIR`, default `C:\OpenSSL4-<platform>\bin`) |
| [`IdentityProvider`](IdentityProvider/README.md) | Identity brokering and Admin API requests, offline; online part with a reachable Keycloak | Keycloak (`tests\IdentityProvider\docker\up.cmd`); `IAM4D_ALLOW_SKIP=1` runs the offline part alone |
| [`DMVC/RuntimeTest`](DMVC/RuntimeTest/README.md) | DMVCFramework integration over HTTP (bundle, middleware, Minimal API, Swagger) | nothing |

Environment variables:

- `RSVARS` (every script): the `rsvars.bat` of the RAD Studio to use (default: RAD Studio 37.0 in `C:\Program Files (x86)\Embarcadero\Studio\37.0`).
- `TAURUSTLS_SOURCE` (Crypto, TLS): the TaurusTLS `Source` folder when it is not under `src\Lib` (e.g. in a git worktree).
- `IAM4D_ALLOW_SKIP=1` (IdentityProvider, TLS): a missing Keycloak or OpenSSL is a skip instead of a failure.

Outputs go to `tests\bin` and `tests\dcu`.
