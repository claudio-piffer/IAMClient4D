# Scientific Calculator (DMVCFramework samples)

Two REST servers with the same API, a scientific calculator secured by IAMClient4D and Keycloak, and a web client of both:

| Project | Style | Default port |
|---------|-------|--------------|
| `ControllersServer/CalculatorControllersServer.dproj` | DMVC controllers | 8090 |
| `MinimalAPIServer/CalculatorMinimalAPIServer.dproj` | DMVC Minimal API (route groups, endpoint filters) | 8091 |
| `WebClient/CalculatorWebClient.dproj` | DMVC web application: TemplatePro views, htmx, Bootstrap | 8092 |

All three are console applications for RAD Studio 13, Win32 and Win64, built into `samples/bin/DMVC/<Platform>/<Config>`. The servers only validate access tokens: no login happens in them, a client gets the token from Keycloak and sends it as `Authorization: Bearer <token>`. The [web client](#web-client) is such a client: it signs the user in and calls the servers.

## Architecture

The math, the use cases and the infrastructure are shared; only the presentation layer differs between the two servers.

```
Core/
  Domain/          math rules, the expression parser, domain errors; depends on nothing
  Application/     use cases (ICalculatorService), DTOs, ports (ICalculationHistory, IClock), TCaller
  Infrastructure/  in-memory history (50 calculations per user, lost on restart), system clock
Shared/            composition root and presentation helpers used by both servers
ControllersServer/Presentation/   controllers
MinimalAPIServer/Presentation/    route groups
```

Dependencies point inwards: Domain <- Application <- Infrastructure / Presentation. The use cases know the caller only as a `TCaller` (subject and user name), never the token or DMVC; the history is keyed by the token subject, so each user sees only their own calculations.

`Shared` holds:

- `Calculator.Presentation.Composition`: the only unit that knows every layer. It registers `ICalculatorService` in the DMVC service container (singleton, history and clock injected) and sets up what both engines share: error mapping, CORS, the IAMClient4D JWT filters, OpenAPI document and Swagger UI.
- `Calculator.Presentation.Settings`: configuration (below) and the public `GET /api/info` description.
- `Calculator.Presentation.Security`: the role names and the bridge from the validated token (`AContext.JWT`, `AContext.LoggedUser`) to `TCaller` and to the `/api/me` profile.
- `Calculator.Presentation.Errors`: domain errors become `422` problem+json.
- `Calculator.Presentation.Requests`: the statistics body, parsed by hand (see [DMVC notes](#dmvc-350-rc10-notes)).
- `Calculator.Presentation.SwaggerUI`: Swagger UI page from a pinned CDN, checked with Subresource Integrity.

### Security in the two servers

Both use the DMVC filters of IAMClient4D (`IAMClient4D.DMVC.Filters`), one authenticator for the issuer, the audience, the signature through the realm JWKS and the expiry. The bearer scheme is added to the OpenAPI document by a filter registered before `OpenAPIHTTPFilter`.

- **Controllers**: `AEngine.Use(IAM4DJWTBundle(Authenticator))` asks for a valid token on every action except those of `[IAM4DPublic]` classes (`TPublicController`). `OnBeforeAction` of each controller calls `AContext.RequireAnyRole([...])`.
- **Minimal API**: a bundle on the engine would check every route, the public ones too, so the token is checked on the groups: the public group has no filter; every protected group has the endpoint filters `IAM4DJWTEndpointFilter(Authenticator)` (401 without a valid token; one authenticator for every group, so the JWKS cache is shared) and a role filter that calls `RequireAnyRole` (403). `IAM4DSwaggerSecurityHTTPFilter()` adds the bearer scheme to the document.

Missing or invalid token: `401` with `WWW-Authenticate: Bearer realm="api-server"` (plus `error="invalid_token"` when a token was sent). Valid token without the role: `403` problem+json with `WWW-Authenticate: Bearer ..., error="insufficient_scope"`.

## Web client

`WebClient/` is a server-rendered web application that signs the user in with Keycloak and calls either server, chosen from the navigation bar. It is a **BFF** (backend for frontend): the tokens stay in the Delphi process, the browser gets only an opaque session cookie.

```
Browser --htmx--> CalculatorWebClient (8092) --Bearer--> Controllers (8090) or Minimal API (8091)
   |                     |
   +---- sign-in ---> Keycloak <--- code exchange, refresh, logout (IAMClient4D)
```

- **Sign-in**: authorization code with PKCE (S256) for the confidential client `calculator-web`, through `TIAM4DClientConfigBuilder.ForAuthorizationCode(...).WithExternalCallback(...)`. `/login` sends the browser to Keycloak with a short-lived `calcweb_login` cookie (the `state`, path `/auth/callback`); `/auth/callback` checks it, exchanges the code with the client secret and creates a new session (new id, no session fixation).
- **Session**: an in-memory store keyed by the `calcweb_session` cookie (HttpOnly, SameSite=Lax, Secure over https), 30 minutes idle. `GetAccessToken` of IAMClient4D refreshes the access token when it expires; when the refresh token is gone too, the page sends the user to sign in again. Sign-out ends the Keycloak session with a back-channel logout, then sends the browser to the Keycloak end session endpoint (`GenerateLogoutURL`, RP-Initiated Logout with `id_token_hint`, generated before `Logout` clears the tokens), which clears the Keycloak cookies and comes back to `CALC_WEB_PUBLIC_URL/` (the post-logout redirect URI of the client).
- **Pages**: Home (`/api/info` of both servers, the public constants), Calculator, Keypad (a calculator with keys: `=` sends the display to `POST /api/expressions/evaluate`; the statistics and equation keys take a list such as `2; 4; 7` and are disabled without `calculator-advanced`), Advanced (statistics and quadratic equations with Chart.js plots), History, Profile (`/api/me` next to the claims of the token). Each form is an htmx request that returns an HTML fragment with the call (method, path, status, time) and the result or the problem+json of the API. With `student` the advanced forms show the `403` of the API.
- **Security**: `CSRFHTTPFilter` (the token, an HMAC of the session id, is sent by htmx in `X-CSRF-Token`), a Content-Security-Policy without `unsafe-inline` or `unsafe-eval` (all page behaviour is in `www/js/app.js`), `X-Frame-Options: DENY`, `Cache-Control: no-store` on the pages, only local paths accepted as the page after the sign-in.
- **Languages**: English and Italian. The texts are in `i18n/en.json` and `i18n/it.json` (one object per page or area, e.g. `home.welcome`); `LanguageHTTPFilter` (`Calculator.Web.Texts`) picks the language of each request (the IT/EN selector in the navigation bar, kept in the `calcweb_lang` cookie for a year, else `Accept-Language`, else English) and puts the catalog into the view data as `t`, also for the error page. Templates write `{{:t.home.welcome|replace,"{name}",display_name}}`; keys ending in `_html` hold markup and are written raw (`{{:t.x_html$}}`), with placeholders filled only by values of this server, never by user data. `app.js` reads its texts from the `app-texts` meta of the layout and formats dates in the page language. The two files must have the same keys: the web client does not start otherwise. Numbers keep the decimal point in both languages; the API messages (problem+json, constant descriptions) stay as the servers send them.
- **Libraries** (jsDelivr, pinned, with Subresource Integrity): Bootstrap 5.3.9, Bootstrap Icons 1.13.2, htmx 2.0.11, Chart.js 4.6.1. System fonts, no Google Fonts.

```
WebClient/
  Infrastructure/  settings, session store (an IAMClient4D client per session), API client (view models)
  Presentation/    controllers, engine (filters, view engine), number parsing and formatting, texts
  templates/       TemplatePro views; the build copies them with www/ and i18n/ into CalculatorWeb/ next to the exe
  www/             app.css, app.js, theme.js, favicon (served on /static)
  i18n/            en.json, it.json: the texts of the pages
```

Run both servers, then the web client with `CALC_WEB_CLIENT_SECRET` set (see [Configuration](#configuration)), and open `http://localhost:8092`.

## Endpoints and roles

Roles are client roles of the `api-server` client (the audience).

| Method and path | Role | |
|-----------------|------|-|
| `GET /api/info` | none | where to get a token, roles checked |
| `GET /api/constants` | none | mathematical constants |
| `GET /api/elementary/power?base=&exponent=` | `calculator-user` | |
| `GET /api/elementary/root?value=&degree=2` | `calculator-user` | odd roots of negative numbers too |
| `GET /api/elementary/log?value=&base=10` | `calculator-user` | |
| `GET /api/elementary/factorial/{n}` | `calculator-user` | 0 <= n <= 170 |
| `GET /api/trigonometry/{fn}?value=&unit=deg` | `calculator-user` | `sin cos tan asin acos atan`, `unit` `deg` or `rad` |
| `POST /api/expressions/evaluate` | `calculator-user` | body `{"expression": "2 * sin(30) + sqrt(16)", "unit": "deg"}`: numbers with the decimal point (`1.5E3`), `+ - * / ^`, parentheses, postfix `!`, implicit multiplication (`2pi`), constants `pi e tau phi`, functions `sin cos tan asin acos atan sqrt cbrt ln log abs exp`; at most 256 characters, parsed by the domain (no eval) |
| `GET /api/number-theory/prime/{n}` | `calculator-user` | primality and factors, 2 <= n <= 10^12 |
| `GET /api/number-theory/combinatorics?n=&k=` | `calculator-user` | C(n,k) and P(n,k), n <= 1000 |
| `POST /api/statistics/describe` | `calculator-advanced` | body `{"values": [1, 2.5, 4], "sample": false}` |
| `POST /api/equations/quadratic` | `calculator-advanced` | body `{"a": 1, "b": -3, "c": 2}`, real or complex roots |
| `GET /api/me` | any valid token | claims and roles the API sees |
| `GET /api/history` | any valid token | your last calculations, most recent first |
| `DELETE /api/history` | any valid token | clears your history |

Successful responses are wrapped in `{"data": ...}`:

```json
{"data":{"operation":"power","expression":"2^10","value":1024.0}}
```

Errors: `400` missing or malformed parameter or body, `401`/`403` as above, `422` problem+json for a domain error (`factorial: n must be between 0 and 170`, `a = 0` in a quadratic equation, empty statistics, unknown trigonometric function). Timestamps (`performedAt`, `expiresAt`) are ISO 8601 strings in UTC, e.g. `2026-11-14T10:37:50.000Z`.

The OpenAPI 3 document is on `/openapi.json`, Swagger UI on `/swagger` (`/` redirects there).

## Keycloak

The sample environment of [`Docker/`](../../../Docker/README.md) has everything the samples need, in the realm `iamclient4d`:

```bat
Docker\start.cmd      & rem Linux/macOS: Docker/start.sh; Keycloak on http://localhost:18180/auth
```

- client roles `calculator-user` and `calculator-advanced` of `api-server`, the audience the servers require;
- users `student` / `Student#2026` (`calculator-user`) and `scientist` / `Scientist#2026` (both roles);
- the confidential client `iam4d-sample-service` (client credentials, secret `iam4d-test-only-secret`), whose service account has `calculator-user`;
- the confidential client `calculator-web` of the web client: standard flow only, PKCE S256, redirect URI `http://localhost:8092/auth/callback`, post-logout redirect URI `http://localhost:8092/`, secret `calculator-web-test-only-secret`;
- the tokens of these clients and of `iam4d-sample-app` carry the audience `api-server` (an audience mapper on each client).

The client secrets are sample values, public with the repository: never reuse them outside this local Keycloak. For a web client on another host or port, change the redirect URI and the post-logout redirect URI of `calculator-web` to match `CALC_WEB_PUBLIC_URL`.

The three programs default to this Keycloak; the web client needs only its secret, in a `.env` next to the executables (see [Configuration](#configuration)):

```ini
CALC_WEB_CLIENT_SECRET=calculator-web-test-only-secret
```

## Configuration

Environment variables, or a `.env` file next to the executable (DMVC dotEnv). The file wins over the environment.

| Variable | Default | |
|----------|---------|-|
| `IAM4D_ISSUER` | `http://localhost:18180/auth/realms/iamclient4d` (the Keycloak of `Docker/`) | realm URL, the `iss` of the tokens: with the profile `tls` of `Docker/`, `https://<DOMAIN_NAME>:<GATEWAY_PORT>/auth/realms/iamclient4d` |
| `IAM4D_AUDIENCE` | `api-server` | required `aud`, and the client whose roles are checked |
| `IAM4D_ALLOW_SELF_SIGNED` | `true` | accept the self-signed certificate of the gateway of `Docker/` (profile `tls`) when reading the JWKS; `false` in production |
| `CALC_CORS_ORIGINS` | `*` | allowed CORS origins, comma separated |
| `CALC_CONTROLLERS_PORT` | `8090` | port of the controller server |
| `CALC_MINIMAL_PORT` | `8091` | port of the Minimal API server |

The web client reads `IAM4D_ISSUER`, `IAM4D_AUDIENCE` and `IAM4D_ALLOW_SELF_SIGNED` too (Keycloak, and the client whose roles it shows), and:

| Variable | Default | |
|----------|---------|-|
| `CALC_WEB_CLIENT_SECRET` | none, required | secret of `calculator-web` |
| `CALC_WEB_CLIENT_ID` | `calculator-web` | confidential client of the web client |
| `CALC_WEB_PORT` | `8092` | port of the web client |
| `CALC_WEB_PUBLIC_URL` | `http://localhost:<CALC_WEB_PORT>` | URL the browser uses; `<url>/auth/callback` is the redirect URI. With `https` the cookies are `Secure` and HSTS is sent |
| `CALC_CONTROLLERS_URL` | `http://localhost:8090` | the controller server |
| `CALC_MINIMAL_URL` | `http://localhost:8091` | the Minimal API server |
| `CALC_WEB_SESSION_IDLE_MINUTES` | `30` | idle time before a session ends |
| `CALC_WEB_ROOT` | `CalculatorWeb` next to the exe | folder with `templates`, `www` and `i18n` |

Example `.env` in `samples/bin/DMVC/Win64/Debug` (one file for the three programs), with the profile `tls` of `Docker/`:

```ini
IAM4D_ISSUER=https://192.168.1.100:24443/auth/realms/iamclient4d
IAM4D_ALLOW_SELF_SIGNED=true
CALC_CORS_ORIGINS=http://localhost:5173
CALC_WEB_CLIENT_SECRET=calculator-web-test-only-secret
```

The issuer must be the URL the clients use to reach Keycloak: Keycloak writes it in `iss`, and a token obtained through another host name or port is rejected.

## Getting a token and using Swagger UI

**Service account** of `iam4d-sample-service` (role `calculator-user` only):

```bash
curl -X POST "http://localhost:18180/auth/realms/iamclient4d/protocol/openid-connect/token" \
  -d grant_type=client_credentials -d client_id=iam4d-sample-service -d client_secret=iam4d-test-only-secret
```

The `access_token` of the answer calls the elementary, trigonometry, expression and number theory endpoints; statistics and equations answer `403`.

**Users** `student` and `scientist`: the simplest way is the [web client](#web-client), whose Profile page shows the claims of the token. Otherwise sign in from an IAMClient4D client, e.g. `samples/VCL/KeycloakClient`, whose defaults are this Keycloak (base URL `http://localhost:18180/auth`, realm `iamclient4d`, public client `iam4d-sample-app`, authorization code with PKCE): after the login it shows the access token.

**Swagger UI**: open `http://localhost:8090/swagger` (or 8091), *Authorize*, paste the access token without the `Bearer ` prefix (the scheme is HTTP bearer, Swagger UI adds it), then *Try it out*. Tokens last 5 minutes in the realm: paste a new one when calls start answering `401`.

## DMVC 3.5.0-rc10 notes

The samples work around a few issues of the vendored DMVCFramework 3.5.0-silicon-rc10:

- **`TArray<Double>` from JSON integers**: the body binder builds an integer array for `[1, 2, 3]` (invalid typecast) and rejects `[1, 2.5]` ("types in the array must be homogeneous"). `POST /api/statistics/describe` parses its body by hand (`Calculator.Presentation.Requests`); malformed input is a `400`.
- **Minimal API record binding leaks**: a query record bound by `MapGet<TRecord, ...>` leaks one string per managed field on every request. The query records have no string field; `unit` of the trigonometry endpoint is read from the request in the handler.
- **Missing required query parameter in a controller**: `[MVCFromQueryString]` without a default raises an `EMVCException` without status (`500`). `Calculator.Presentation.Errors` recognizes it by its message and answers `400` problem+json naming the parameter. The Minimal API server answers `400` too, but its detail does not name the parameter ("Invalid Float value for param [<value>]").
- **Error format of the controllers**: DMVC writes its own JSON for the errors of a controller; `Calculator.Presentation.Errors` writes the `400` and `403` as problem+json, like the Minimal API.
- **Timestamps of `Ok(obj)`**: the streaming serializer writes a `TDateTime` as local time with the local offset and ignores `gLocalTimeStampAsUTC`, so a UTC value comes out one or more hours off. The DTOs carry the timestamps as ISO 8601 strings in UTC (`DateToISO8601(..., True)`), which also avoids the ambiguous local hour when daylight saving time ends.
- The Minimal API body binder uses its own serializer instance: type serializers registered on the engine do not apply to Minimal API bodies.
- **Cookies without `Expires`**: a `TCookie` left with `Expires = 0` goes out as `Expires=Thu, 28-Dec-1899 ...` on Indy Direct too, and the browser drops it at once. The web client always sets a date: the sign-in time-out for `calcweb_login`, a far one for `calcweb_session` (the store decides when a session ends).

The web client sets `attributesToSettle` of htmx to `["class","width","height"]`: by default htmx copies the `style` attribute with `setAttribute` when it settles an element, and the Content-Security-Policy blocks it.
