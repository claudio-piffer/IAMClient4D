# HTTP Timeout Test

Console program that checks the HTTP timeouts of IAMClient4D against a slow HTTP server: an Indy `TIdTCPServer` on `127.0.0.1` (free port chosen by the system) whose first path segment chooses the timing: `ok`, `hdr<ms>` (headers after `ms`), `drip<ms>` (the last 30 bytes of the body one every `ms`), `stall<ms>` (body `ms` after the headers), `noread<ms>` (request body not read, answer after `ms`) and `dyn` (the mode set by the test, used by the `token_endpoint` of the discovery document). The server answers discovery, token, JWKS and Admin API requests (users and identity providers) and records each request (method, path, `Content-Type`, body). No Keycloak is needed.

Timeouts of 1 s against delays of 6 s; a request cut at the timeout must end within 2.5 s.

## What it checks

| Area | Checks |
|------|--------|
| Configuration | `TIAM4DHTTPClientFactory.CreateHTTPClient` (HTTP and client configuration, defaults), `TTokenBasedAuthProvider` and `TClientBasedAuthProvider`: `ConnectionTimeout`, `ResponseTimeout` and `SendTimeout` (= `ResponseTimeout`) of the client; builder `WithTimeouts` for Client Credentials and Authorization Code; Client Credentials `WithTimeouts`, `WithScopes` and `WithStrictSSL` keep the token expiry buffer |
| `GetWithRetry` | Headers after 6 s, body trickling (a byte every 200 ms), body 6 s after the headers: `EIAM4DNetworkTimeoutException` (`TimeoutMs`, `Endpoint`, `ecNetworkTimeout`) in time, one request (a timeout is not retried); the same client serves the next request; a slow response within a 5 s timeout is complete; `ResponseTimeout` -1 sets no deadline |
| `PostFormUrlEncodedWithRetry` | 1 MB body the server does not read (sending blocks): timeout in time, one request; a form keeps body and `Content-Type` of `THTTPClient.Post` |
| Keycloak client | `ConfigureAsync` and `Build` with a slow discovery; `AuthenticateClient` with a trickling token response, then a new token on the same client; token request with form `Content-Type`; `GetAccessToken` renewing an expired Client Credentials token raises the timeout (not a generic `EIAM4DException`); after `ConfigureAsync` with a shorter timeout the requests use it |
| JWKS provider | Slow discovery and trickling JWKS: `EIAM4DJWKSUnavailableException` caused by the timeout, in time, one request |
| Admin API | `CreateUser` with slow headers: timeout in time; on a normal server `POST` with JSON `Content-Type`, the user in the body and the ID from `Location` |
| User manager | `GetUserByUsername` (`GET`) with the body trickling, also through `TIAM4DKeycloakUserManagerAsync` (`WaitForCompletion` raises the same exception), `DeleteUser` (`DELETE`) and `SendVerifyEmail` (`PUT`) with slow headers: `EIAM4DNetworkTimeoutException` in time, one request; on a normal server method, path, query and empty body as before |
| Identity provider manager | `GetIdentityProviders` (`GET`) with the body trickling, `DeleteIdentityProvider` (`DELETE`) and `CreateIdentityProvider` (JSON `POST`) with slow headers: timeout in time, one request; on a normal server method, path, JSON `Content-Type` and body as before |
| Build | Discovery answering after 31 s with a 45 s timeout: `Build` succeeds (it gave up after 30 s and released the client still being configured) |

A watchdog reports a test that does not end within 90 seconds as hung and exits with code `98`. The whole run takes about one minute (the last test waits 31 s).

## Run

From a command prompt (RAD Studio 13, Win64 by default):

```bat
tests\HTTPTimeout\run_tests.bat
tests\HTTPTimeout\run_tests.bat Win32
tests\HTTPTimeout\run_tests.bat Linux64
```

`Linux64` runs through WSL (`libcurl` required by `THTTPClient`); without WSL the script only builds. Exit code: number of failed checks (`0` = all passed, `98` = a test hung, `99` = the slow server cannot start). Memory leaks are reported on stderr (Windows); with the environment variable `IAM4D_TEST_LEAK=1` the program leaks one `TObject` on purpose, to see that the report reaches stderr. Build output goes to `tests/bin` and `tests/dcu`.
