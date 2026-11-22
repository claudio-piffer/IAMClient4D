# Client core reference

The OAuth2/OpenID Connect client of IAMClient4D 3.0: `IIAM4DClient` and its Keycloak implementation, the configuration and its builder, the login flows and their callback handling, `TIAM4DAuthorizedHTTPClient`, the HTTP layer, the common utilities an application calls, and the exceptions with their error codes. JWT, JWKS and TLS are in [Security.md](Security.md), token storage in [Storage.md](Storage.md), the Keycloak Admin API in [AdminAPI.md](AdminAPI.md), identity providers in [IdentityBrokering.md](IdentityBrokering.md), promises and dispatch modes in [AsyncCore.md](AsyncCore.md). Changes from 2.x: [MIGRATION_3.0.md](../MIGRATION_3.0.md).

The examples use the sample Keycloak of [Docker/README.md](../../Docker/README.md): base URL `http://localhost:18180/auth`, realm `iamclient4d`.

## Contents

1. [Units](#1-units)
2. [Creating a client](#2-creating-a-client)
3. [TIAM4DClientConfig](#3-tiam4dclientconfig)
4. [Login flows](#4-login-flows)
5. [Authorization request options](#5-authorization-request-options)
6. [IIAM4DClient](#6-iiam4dclient)
7. [Tokens, claims and user info](#7-tokens-claims-and-user-info)
8. [Ending a session](#8-ending-a-session)
9. [Callback handling](#9-callback-handling)
10. [TIAM4DAuthorizedHTTPClient](#10-tiam4dauthorizedhttpclient)
11. [HTTP layer and discovery](#11-http-layer-and-discovery)
12. [Common utilities](#12-common-utilities)
13. [Exceptions and error codes](#13-exceptions-and-error-codes)

## 1. Units

| Unit | Content |
|------|---------|
| `IAMClient4D.Core` | `IIAM4DClient`, `TIAM4DClientConfig`, `TIAM4DAuthRequestOptions`, `TIAM4DTokens`, `TIAM4DIDTokenClaims`, `TIAM4DUserInfo`, `TIAM4DWellKnownEndpoints`, `TIAM4DHTTPClientFactory`, `TIAM4DHTTPClientConfig`, the enumerations and the `IAM4D_PROMPT_*`, `IAM4D_MAX_AGE_*`, `IAM4D_KC_ACTION_*` constants |
| `IAMClient4D.Config.Builder` | `TIAM4DClientConfigBuilder` (`IIAM4DClientConfigBuilder`) |
| `IAMClient4D.Keycloak` | `TIAM4DKeycloakClient`, the implementation of `IIAM4DClient` |
| `IAMClient4D.AuthorizedHTTP` | `TIAM4DAuthorizedHTTPClient` |
| `IAMClient4D.Callback.Handler`, `.Local`, `.External`, `.AppRedirect` | callback handlers; `TIAM4DAppRedirect` (entry point of the mobile redirect) |
| `IAMClient4D.Server.Callback.Core`, `.IndyHttpServer` | the local HTTP callback server (Indy) |
| `IAMClient4D.Common.OAuth2URLParser` | `TIAM4DOAuth2URLParser`, `TIAM4DOAuth2CallbackResult` |
| `IAMClient4D.Common.PlatformUtils` | `TIAM4DPlatformUtils` (`OpenURL`, `OpenURLHandler`) |
| `IAMClient4D.Common.Constants` | protocol and Keycloak constants, `IAM4D_VERSION*`, `IAM4D_ACR_*`, `IAM4D_AMR_*` |
| `IAMClient4D.Discovery.Cache` | `TIAM4DDiscoveryCache` |
| `IAMClient4D.Exceptions` | `EIAM4DException`, its descendants, `TIAM4DErrorCode` |
| `src/FMX/IAMClient4D.FMX.AppRedirect` | `TIAM4DAppRedirectListener` (FMX, Android and iOS) |

## 2. Creating a client

### TIAM4DClientConfigBuilder

Unit `IAMClient4D.Config.Builder`. `TIAM4DClientConfigBuilder.New` returns an `IIAM4DClientConfigBuilder`. Call one of `ForAuthorizationCode`, `ForClientCredentials`, `ForPassword` first, chain the `With*` methods, end with `Build` or `BuildAsync`.

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('http://localhost:18180/auth', 'iamclient4d', 'iam4d-sample-app')
  .WithScopes(['openid', 'profile', 'email'])
  .BuildAsync
  .OnSuccess(
    procedure(const AClient: IIAM4DClient)
    begin
      LClient := AClient;
      ShowMessage('Discovery done: ' + LClient.Issuer);
    end)
  .OnError(
    procedure(const AException: Exception)
    begin
      ShowMessage('Configuration failed: ' + AException.Message);
    end)
  .Run;
```

Grant type:

| Method | Grant | Notes |
|--------|-------|-------|
| `ForAuthorizationCode(BaseURL, Realm, ClientID, ClientSecret = '')` | Authorization Code with PKCE | Empty secret: public client (recommended for desktop and mobile apps) |
| `ForClientCredentials(BaseURL, Realm, ClientID, ClientSecret)` | Client Credentials | Empty secret: `EArgumentException` |
| `ForPassword(BaseURL, Realm, ClientID, ClientSecret = '')` | Resource Owner Password Credentials | The Keycloak client needs "Direct access grants" |

`BaseURL` is the Keycloak URL without `/realms/...` (the client requests `BaseURL/realms/Realm/.well-known/openid-configuration`). Empty `BaseURL`, `Realm` or `ClientID`: `EArgumentException`. Calling a `For*` method again starts a new configuration (callback mode back to the local server); storage and pinned keys are kept.

Options. Methods marked *AC* raise `EInvalidOpException` on a Client Credentials or password client. Every method except the storage ones and `WithPinnedPublicKeys` raises `EArgumentException` before a `For*` call.

| Method | Default | Effect |
|--------|---------|--------|
| `WithScopes(Scopes)` | none | Scopes of the token requests. Authorization Code and password grant add `openid`; Client Credentials sends `scope` only when set |
| `WithExternalCallback(URL)` *AC* | | Callback mode `cbmExternal` (web apps): `URL` is the redirect URI. Empty: `EArgumentException`; not `http(s)`: `EIAM4DCallbackHandlerException` at `Build` |
| `WithAppRedirect(URI)` *AC* | | Callback mode `cbmAppRedirect` (mobile apps): redirect on a private-use scheme, e.g. `com.example.app:/oauth2callback`. Invalid URI (section [9.3](#93-app-redirect-mobile)): `EArgumentException` |
| `WithStrictSSL` | yes | Certificates validated by the platform |
| `WithAllowSelfSignedSSL` | | Self-signed certificates accepted (tests): see [Security.md](Security.md) |
| `WithPinnedPublicKeys(Hashes)` | none | Public key pinning on every request of the client, JWKS included, in both SSL modes. `Build` raises `ENotSupportedException` on Linux. Hash format: [Security.md](Security.md) |
| `WithTimeouts(ConnectionMs, ResponseMs)` | 30000, 60000 | Section [11.2](#112-timeouts). A value of 0 or less: `EArgumentOutOfRangeException` |
| `WithTokenExpiryBuffer(Seconds)` | 120 | A token counts as expired this many seconds before its expiry (access and refresh token). Negative: `EArgumentOutOfRangeException`. Applied by the AES storage the builder creates, not by a custom storage |
| `WithAcrValues(Values)` *AC* | none | `acr_values` of every login |
| `WithIdentityProvider(Alias)` *AC* | none | `kc_idp_hint` of every login: Keycloak redirects straight to that identity provider ([IdentityBrokering.md](IdentityBrokering.md)) |
| `WithPrompt(Prompt)` *AC* | none | `prompt` of every login, e.g. `IAM4D_PROMPT_LOGIN`. Not validated here (`TIAM4DAuthRequestOptions.WithPrompt` is) |
| `WithMaxAge(Seconds)` *AC* | not sent | `max_age` of every login; 0 forces a new authentication. The `auth_time` of the id_token is checked against it. Negative: `EArgumentOutOfRangeException` |
| `WithKeycloakAction(Action)` *AC* | none | `kc_action` of every login, e.g. `IAM4D_KC_ACTION_UPDATE_PASSWORD`; outcome in `KeycloakActionStatus` |
| `WithCallbackPort(Port)` *AC* | 0 | Port of the local callback server; 0: free port chosen by the system. Outside 0..65535: `EArgumentOutOfRangeException` |
| `WithAppActivation(Value)` *AC* | `aaNone` | What the app does when the browser reaches the local callback server: `aaFlash` flashes the taskbar button, `aaForeground` brings the window to the foreground. Windows only |
| `WithLoopbackRedirectHost(Value)` *AC* | `lrhLocalhost` | Host of the local redirect URI: `http://localhost:port/...` or, with `lrhLoopbackIP`, `http://127.0.0.1:port/...` (RFC 8252 8.3). Keycloak must have the same host in the redirect URIs |
| `WithAllowInsecureHTTP(Value = True)` | False | Accepts `http://` to a host other than the loopback for `BaseURL` and the external redirect URL. Test environments only |
| `WithIAMClient4DAESStorage` | yes | AES-256 in-memory token storage, random 32-byte key |
| `WithIAMClient4DAESStorage(Key32, AAD = nil)` | | Same storage with the given key (not 32 bytes: `EArgumentException`); empty AAD uses `IAMClient4D/v1`. See [Storage.md](Storage.md) |
| `WithCustomStorage(Storage)` | | An `IIAM4DTokenStorage` of your own (nil: `EArgumentNilException`) |

Build:

| Method | Effect |
|--------|--------|
| `Build: IIAM4DClient` | Creates the client and runs the discovery on the calling thread: on the main thread the UI waits for it |
| `BuildAsync: IAsyncPromise<IIAM4DClient>` | The same in a task: `OnSuccess` receives the configured client |
| `Config: TIAM4DClientConfig` | The configuration built so far |

Both validate first: no `For*` call (`EArgumentException`), external or app redirect mode without its URL (`EInvalidOpException`). Then the client configuration may raise: plain HTTP to a host other than the loopback without `WithAllowInsecureHTTP` (`EIAM4DInvalidConfigurationException`), network errors of the discovery (`EIAM4DNetworkTimeoutException`, `EIAM4DNetworkUnreachableException`, `EIAM4DSSLCertificateException`), a discovery answer other than 200/201 or that is not JSON (`EIAM4DDiscoveryFailedException`, `ecDiscoveryFailed`, message `OIDC discovery failed for <URL>: ...`), an `http://` endpoint in the discovery document of an `https://` realm (`EIAM4DInvalidConfigurationException`). `Build` and `BuildAsync` wait for the discovery as long as it takes; the request itself ends within the timeouts.

The builder is not thread-safe: one instance per thread. Its destructor wipes the storage key and AAD.

### Without the builder

`TIAM4DKeycloakClient` (unit `IAMClient4D.Keycloak`):

| Member | Effect |
|--------|--------|
| `Create(CallbackMode = cbmLocalServer, Storage = nil)` | Nil storage: AES storage with a random key and a 120 s buffer |
| `ConfigureAsync(Config)` | Interface method: configuration and discovery in a task |
| `Configure(Config)` | The same on the calling thread |
| `SSLValidator` | The certificate validator of the client (events, diagnostics): [Security.md](Security.md) |

<!-- snippet ver=3.0 kind=body ctx=client uses=IAMClient4D.Keycloak -->
```delphi
LClient := TIAM4DKeycloakClient.Create(cbmLocalServer, nil);
LClient.ConfigureAsync(
  TIAM4DClientConfig.CreateForAuthorizationCode('http://localhost:18180/auth', 'iamclient4d',
    'iam4d-sample-app', ['openid', 'profile']))
  .Run
  .WaitForCompletion(INFINITE, True);
```

A configuration (`ConfigureAsync`, `Configure`) first refuses plain HTTP as above (the current configuration stays), then replaces the configuration, clears the stored tokens, stops the callback server, cancels a pending login, runs the discovery and creates the id_token validator.

## 3. TIAM4DClientConfig

Unit `IAMClient4D.Core`. An immutable record. The builder fills it; you can also create it with the factory methods and pass it to `ConfigureAsync`.

| Factory | Grant |
|---------|-------|
| `Create(BaseURL, Realm, ClientID, GrantType = gtAuthorizationCode, Scopes = nil, ClientSecret = '', SSLValidationMode = svmStrict, ConnectionTimeout = 30000, ResponseTimeout = 60000, ExternalCallbackURL = '', TokenExpiryBufferSeconds = 120, AcrValues = nil, IdpHint = '')` | any |
| `CreateForAuthorizationCode(BaseURL, Realm, ClientID, Scopes, SSLValidationMode, ConnectionTimeout, ResponseTimeout, ExternalCallbackURL, TokenExpiryBufferSeconds, AcrValues, IdpHint)` | `gtAuthorizationCode`, no secret |
| `CreateForClientCredentials(BaseURL, Realm, ClientID, ClientSecret, Scopes, SSLValidationMode, ConnectionTimeout, ResponseTimeout, TokenExpiryBufferSeconds)` | `gtClientCredentials` |
| `CreateForPassword(BaseURL, Realm, ClientID, ClientSecret = '', Scopes, SSLValidationMode, ConnectionTimeout, ResponseTimeout, TokenExpiryBufferSeconds)` | `gtPassword` |

The parameters after the first ones have the defaults of `Create`. `Create` raises `EArgumentException` for an empty `BaseURL`, `Realm` or `ClientID`, an empty secret with Client Credentials, a negative buffer. It does not check the timeouts (the builder does).

Copies with one value changed: `WithAuthRequestOptions(Prompt, MaxAge)` (`MaxAge` below `IAM4D_MAX_AGE_NONE`: `EArgumentException`), `WithKeycloakAction(Action)`, `WithCallbackPort(Port)` (outside 0..65535: `EArgumentOutOfRangeException`), `WithAppActivation(Value)`, `WithLoopbackRedirectHost(Value)`, `WithAllowInsecureHTTP(Value)`.

| Property | Default | Meaning |
|----------|---------|---------|
| `BaseURL`, `Realm`, `ClientID`, `ClientSecret` | | Keycloak URL, realm, client |
| `GrantType` | | `gtAuthorizationCode`, `gtClientCredentials`, `gtPassword` (`gtUnknown` is refused by the builder) |
| `Scopes` | nil | Requested scopes |
| `SSLValidationMode` | `svmStrict` | `svmStrict` or `svmAllowSelfSigned` |
| `ConnectionTimeout`, `ResponseTimeout` | 30000, 60000 | Milliseconds, section [11.2](#112-timeouts) |
| `ExternalCallbackURL` | '' | Redirect URI of `cbmExternal` and `cbmAppRedirect` |
| `TokenExpiryBufferSeconds` | 120 (`IAM4D_TOKEN_EXPIRATION_BUFFER_SECONDS`) | Used by the storage the builder creates |
| `AcrValues` | nil | `acr_values` |
| `IdpHint` | '' | `kc_idp_hint` |
| `Prompt` | '' | `prompt`; empty: not sent |
| `MaxAge` | `IAM4D_MAX_AGE_NONE` (-1) | `max_age`; -1: not sent |
| `KeycloakAction` | '' | `kc_action` |
| `CallbackPort` | 0 | Port of the local callback server |
| `AppActivation` | `aaNone` | Section [9.2](#92-local-callback-server-desktop) |
| `LoopbackRedirectHost` | `lrhLocalhost` | Section [9.2](#92-local-callback-server-desktop) |
| `AllowInsecureHTTP` | False | Plain HTTP outside the loopback accepted |

`IsInsecureHTTPURL(URL)` (class function) is True for an `http://` URL whose host is not the loopback (`localhost`, `127.0.0.0/8`, `[::1]`). Without `AllowInsecureHTTP` the client refuses such a `BaseURL` or `ExternalCallbackURL` at configuration, and `GenerateLogoutURL` such a post-logout redirect URI.

`TIAM4DHTTPClientConfig` (timeouts and SSL mode of an HTTP client): `Default` (30000, 60000, `svmStrict`), `Create(ConnectionTimeout, ResponseTimeout, SSLValidationMode)`, `FromClientConfig(Config)`.

## 4. Login flows

| Flow | Builder | Start | Complete |
|------|---------|-------|----------|
| Authorization Code, desktop | `ForAuthorizationCode` | `StartAuthorizationFlowAsync` | automatic (local callback server) |
| Authorization Code, mobile | `ForAuthorizationCode` + `WithAppRedirect` | `StartAuthorizationFlowAsync` | automatic, after `TIAM4DAppRedirect.HandleURL` |
| Authorization Code, web app | `ForAuthorizationCode` + `WithExternalCallback` | `InitializeAuthorizationFlow` + `GenerateAuthURL` | `CompleteAuthorizationFlow(Async)` |
| Client Credentials | `ForClientCredentials` | `AuthenticateClient(Async)` | |
| Password grant | `ForPassword` | `AuthenticatePassword(Async)` | |

Every Authorization Code login uses PKCE (`S256`), a `state` and a `nonce` of 128 random bits from the CSPRNG of the library, and adds the `openid` scope. The id_token of every token response is validated before the tokens are stored: section [7.5](#75-id_token-validation).

### 4.1 Desktop: local callback server

`StartAuthorizationFlowAsync` starts the local callback server, opens the authorization URL with `TIAM4DPlatformUtils.OpenURL` and returns a promise that ends when the browser comes back: `OnSuccess` receives the access token.

<!-- snippet ver=3.0 kind=decl ctx=client,ui -->
```delphi
var
  FLogin: IAsyncOperation<string>;

procedure SignIn;
begin
  FLogin := LClient.StartAuthorizationFlowAsync
    .OnSuccess(
      procedure(const AAccessToken: string)
      begin
        ShowMessage('Logged in as ' + LClient.GetIDTokenClaims.PreferredUsername);
      end)
    .OnError(
      procedure(const AException: Exception)
      begin
        // Not called when the login is cancelled
        ShowMessage('Login failed: ' + AException.Message);
      end)
    .OnFinally(
      procedure
      begin
        FLogin := nil;
      end)
    .Run;
end;

procedure CancelSignIn;
begin
  // The user closed the browser: the flow would wait for ever
  if Assigned(FLogin) then
    FLogin.Cancel;
end;
```

- The flow is started by the call itself, before `Run`: an error at that point is raised by `StartAuthorizationFlowAsync` (`EIAM4DException`: not an Authorization Code client, external callback mode, the browser could not be opened; `EIAM4DCallbackHandlerException`: the callback server could not start, e.g. port in use).
- The promise waits until the browser reaches the callback server. `Cancel` on the operation returned by `Run`, or `CancelAuthorizationFlow`, ends it as cancelled: `OnFinally` runs, `OnError` does not.
- A cancel during the code exchange discards the tokens; once they are stored the login completes normally.
- A new `StartAuthorizationFlowAsync` cancels a pending one. A new configuration and the destruction of the client cancel it too; the destructor waits for a code exchange still running.
- `OnError` receives `EIAM4DOAuth2CallbackException` for an error response of Keycloak with the `state` of the flow (`error=access_denied`, `login_required` with `prompt=none`), with `error` and `error_description` in `Context`; `EIAM4DCallbackHandlerException` for a wrong `iss`; `EIAM4DSecurityValidationException` for a refused id_token; `EIAM4DException` for an error of the token endpoint.
- Do not destroy the objects the callbacks use (e.g. the form) while the operation is pending: cancel it and let `OnFinally` run first.

Overloads: `StartAuthorizationFlowAsync(IdpHint = '')`, `StartAuthorizationFlowAsync(IdpHint, LoginHint)`, `StartAuthorizationFlowAsync(Options)` (section [5](#5-authorization-request-options)). Callback server: section [9.2](#92-local-callback-server-desktop).

### 4.2 Mobile: app redirect

With `WithAppRedirect(URI)` the authorization server redirects the browser to a private-use scheme (RFC 8252 7.1) that the operating system hands to the app; no server is started. `StartAuthorizationFlowAsync`, `Cancel` and `CancelAuthorizationFlow` work as on the desktop. The app passes every URL it receives on its scheme to `TIAM4DAppRedirect.HandleURL`; `TIAM4DAppRedirectListener` (`src/FMX/IAMClient4D.FMX.AppRedirect.pas`) does it for FMX on Android and iOS and opens the login page in a Custom Tab (Android) or in Safari or an `ASWebAuthenticationSession` (iOS). Details: section [9.3](#93-app-redirect-mobile).

### 4.3 Web app: external callback

With `WithExternalCallback(URL)` the web server receives the redirect. Keep one client per user session: a client holds one pending login.

<!-- snippet ver=3.0 kind=decl ctx=client uses=IAMClient4D.Common.OAuth2URLParser -->
```delphi
procedure CreateWebClient;
begin
  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode('http://localhost:18180/auth', 'iamclient4d', 'iam4d-sample-unigui')
    .WithExternalCallback('http://localhost:8077/?oauthcallback=keycloak')
    .Build;
end;

// Login request: redirect the browser to the returned URL
function BeginLogin: string;
begin
  LClient.InitializeAuthorizationFlow;
  Result := LClient.GenerateAuthURL;
end;

// Callback request: ACallbackURL is the full URL that reached the web server
procedure HandleCallback(const ACallbackURL: string);
var
  LResult: TIAM4DOAuth2CallbackResult;
begin
  LResult := TIAM4DOAuth2URLParser.ParseOAuth2Callback(ACallbackURL);
  if LResult.IsError then
    raise TIAM4DOAuth2URLParser.CreateErrorException(LResult);
  LClient.CompleteAuthorizationFlow(LResult.Code, LResult.State, LResult.Iss);
end;
```

| Method | Effect |
|--------|--------|
| `InitializeAuthorizationFlow` | New `state`, `nonce` and PKCE verifier; replaces a pending login of this client. External mode only (`EIAM4DException` otherwise) |
| `InitializeAuthorizationFlow(Options)` | The same with the options of this login: `GenerateAuthURL` without arguments uses them |
| `GenerateAuthURL(LoginHint = '', IdpHint = '')` | Authorization URL with the options of `InitializeAuthorizationFlow` and these hints. Before `InitializeAuthorizationFlow`: `EIAM4DException` |
| `GenerateAuthURL(Options)` | Authorization URL with these options; its `max_age` replaces the one the flow was initialized with |
| `CompleteAuthorizationFlow(Code, State, Iss = '')` | Checks `state` and `iss`, exchanges the code with the PKCE verifier, validates the id_token, stores the tokens; returns the access token |
| `CompleteAuthorizationFlowAsync(Code, State, Iss = '')` | The same in a task |

- The pending login is taken atomically with its `state`: the same callback twice exchanges the code once; the second call finds no login waiting (`EIAM4DException`).
- `state` empty, not 32 hexadecimal characters, or not the one of the pending login: `EIAM4DStateMismatchException`; the pending login stays.
- `Iss` (RFC 9207): pass the `iss` of the callback. A different one is refused (`EIAM4DCallbackHandlerException`, mix-up attack). An empty one is not checked in this mode.
- Error responses (`error`, `error_description`) and `kc_action_status` reach the web server: read them with `TIAM4DOAuth2URLParser` (section [9.5](#95-tiam4doauth2urlparser)). `KeycloakActionStatus` stays empty in this mode.
- Bind the login to the browser that started it (e.g. an HttpOnly cookie with the `state`, compared at the callback) and let pending logins expire: see `samples/uniGUI/KeycloakWebApp` and the web client of `samples/DMVC/ScientificCalculator`.

### 4.4 Client Credentials

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
LClient := TIAM4DClientConfigBuilder.New
  .ForClientCredentials('http://localhost:18180/auth', 'iamclient4d', 'iam4d-sample-service',
    'iam4d-test-only-secret')
  .Build;
LClient.AuthenticateClient;
ShowMessage(LClient.GetAccessToken);
```

`AuthenticateClient` requests a token (scope only when configured) and stores it. `GetAccessToken` requests a new one when it expires (no refresh token); on failure the tokens are cleared and the error raised. `IsAuthenticated` is True while the access token is valid. `GetUserInfo` raises `EIAM4DException`. An id_token, issued only when `openid` is requested, is validated.

### 4.5 Password grant

Resource Owner Password Credentials (RFC 6749 4.3), deprecated by RFC 9700: the application handles the password, and the login cannot go through brokered identity providers, MFA or required actions. For trusted first-party clients and legacy login forms only. The Keycloak client needs "Direct access grants" enabled (no client of the sample realm has it: `my-trusted-app` below is a placeholder).

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
LClient := TIAM4DClientConfigBuilder.New
  .ForPassword('http://localhost:18180/auth', 'iamclient4d', 'my-trusted-app')
  .Build;
try
  LClient.AuthenticatePassword('demo', 'demo');
except
  on E: EIAM4DInvalidCredentialsException do
    ShowMessage('Wrong username or password');
  on E: EIAM4DAccountNotFullySetUpException do
    ShowMessage('A required action is pending, e.g. a temporary password');
  on E: EIAM4DAccountDisabledException do
    ShowMessage('Account disabled');
end;
```

| Exception | When |
|-----------|------|
| `EIAM4DInvalidCredentialsException` | Wrong username or password, empty username. Also a user locked by the brute force detection: Keycloak 26 answers "Invalid user credentials" even for the right password |
| `EIAM4DAccountNotFullySetUpException` | Right credentials, a required action pending (e.g. `UPDATE_PASSWORD`) |
| `EIAM4DAccountDisabledException` | Account disabled (Keycloak tells it only for the right password) |
| `EIAM4DException` | Not a password client; another error of the token endpoint (e.g. direct access grants disabled) |

`openid` is always requested. The session works as with Authorization Code: `GetAccessToken` refreshes, `GetUserInfo` works, `Logout` ends the Keycloak session. A new login on a client that has a session ends that Keycloak session first (errors ignored). The request form, with the password, is wiped after the request.

## 5. Authorization request options

Values sent with every Authorization Code login come from the configuration (builder `WithPrompt`, `WithMaxAge`, `WithAcrValues`, `WithIdentityProvider`, `WithKeycloakAction`). `TIAM4DAuthRequestOptions` (unit `IAMClient4D.Core`) changes them for one login, e.g. a stronger or fresher authentication before a sensitive operation, without another client.

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
// Fresh authentication at the level "gold" (ACR to LoA mapping of the realm) before a payment
LClient.StartAuthorizationFlowAsync(
  TIAM4DAuthRequestOptions.Create
    .WithAcrValues(['gold'])
    .WithMaxAge(0)
    .WithLoginHint('demo'))
  .OnSuccess(
    procedure(const AAccessToken: string)
    begin
      // The application decides whether the level reached is enough
      if LClient.GetIDTokenClaims.Acr <> 'gold' then
        ShowMessage('Stronger authentication required');
    end)
  .Run;
```

`TIAM4DAuthRequestOptions.Create` (or a local without `Create`: the record has an `Initialize` operator) keeps the whole configuration. Each `With*` returns a copy; invalid values raise `EArgumentException`.

| Method | Parameter | Effect |
|--------|-----------|--------|
| `WithLoginHint(Value)` | `login_hint` | Username or e-mail prefilled on the login page; empty: not sent |
| `WithIdpHint(Value)` | `kc_idp_hint` | Replaces `Config.IdpHint`; empty keeps it; `IAM4D_IDP_HINT_NONE` sends none (Keycloak login page) |
| `WithAcrValues(Values)` | `acr_values` | Replaces the configured values (in order of preference). Empty value, space or control character: `EArgumentException` |
| `WithPrompt(Value)` | `prompt` | Space-separated `none`, `login`, `consent`, `select_account`; `none` only alone; empty keeps the configured one. Other values: `EArgumentException` |
| `WithMaxAge(Seconds)` | `max_age` | 0: authenticate again; `IAM4D_MAX_AGE_NONE` sends none; `IAM4D_MAX_AGE_CONFIGURED` (default) keeps the configured one. Below -2: `EArgumentException` |
| `WithUILocales(Locales)` | `ui_locales` | BCP 47 tags in order of preference. Same checks as `WithAcrValues` |
| `WithParameter(Name, Value)` | any | Another parameter, e.g. one read by a Keycloak authenticator. Name of letters, digits, `_`, `-`, `.`; the same name again (same case) replaces the value. A reserved name: `EArgumentException` |
| `IsReservedParameter(Name)` | | True for the names set by the client or by a dedicated option, compared case-insensitively: `response_type`, `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method`, `login_hint`, `kc_idp_hint`, `acr_values`, `prompt`, `max_age`, `ui_locales`, `kc_action`, `response_mode`, `request`, `request_uri`, `client_secret` |

`kc_action` has no per-login option: it comes from the configuration only.

Where the options apply: `StartAuthorizationFlowAsync(Options)`, `InitializeAuthorizationFlow(Options)`, `GenerateAuthURL(Options)`. `StartAuthorizationFlowAsync(IdpHint, LoginHint)` and `GenerateAuthURL(LoginHint, IdpHint)` are shortcuts for the two hints.

`max_age` is checked, not only requested: with `max_age` sent, an id_token without `auth_time`, or with `auth_time` more than `max_age` seconds before the start of the flow, is refused with `EIAM4DSecurityValidationException` (`ErrorCode = ecTokenInvalid`, `Context` keys `max_age` and `auth_time`) and its tokens are discarded. Tolerance: `IAM4D_AUTH_TIME_CLOCK_SKEW_SECONDS` (300 s). `acr` is not checked: read `GetIDTokenClaims.Acr`.

Constants (unit `IAMClient4D.Core`):

| Constant | Value | Use |
|----------|-------|-----|
| `IAM4D_PROMPT_NONE` | `none` | No page; without an active session the login fails with `error=login_required` |
| `IAM4D_PROMPT_LOGIN` | `login` | Credentials asked even with an active SSO session |
| `IAM4D_PROMPT_CONSENT` | `consent` | Consent asked again |
| `IAM4D_PROMPT_SELECT_ACCOUNT` | `select_account` | Account selection |
| `IAM4D_MAX_AGE_NONE` | -1 | No `max_age` |
| `IAM4D_MAX_AGE_CONFIGURED` | -2 | Options: the configured `max_age` |
| `IAM4D_IDP_HINT_NONE` | `/none` | No `kc_idp_hint` for this login, even with `Config.IdpHint` |
| `IAM4D_KC_ACTION_UPDATE_PASSWORD` | `UPDATE_PASSWORD` | `kc_action`: Keycloak asks for a new password after the login |
| `IAM4D_KC_ACTION_STATUS_SUCCESS`, `_CANCELLED`, `_ERROR` | `success`, `cancelled`, `error` | Values of `KeycloakActionStatus` |
| `IAM4D_AUTH_TIME_CLOCK_SKEW_SECONDS` | 300 | Clock tolerance of the id_token checks |
| `IAM4D_TOKEN_EXPIRATION_BUFFER_SECONDS` | 120 | Default token expiry buffer |

`IAM4D_ACR_PASSKEY`, `IAM4D_ACR_2FA`, `IAM4D_ACR_1FA` (`urn:keycloak:acr:...`) and the `IAM4D_AMR_*` values of RFC 8176 are in `IAMClient4D.Common.Constants`.

`kc_action` and `KeycloakActionStatus`: Keycloak returns a code even when the user cancels the action, so the login succeeds and only `KeycloakActionStatus` tells the outcome. It is set for flows completed through the local callback server or the app redirect, empty without `kc_action` and while a flow runs. It is the redirect parameter, not signed: treat it as the user's report and check a decision that matters on the server (Admin API).

## 6. IIAM4DClient

Unit `IAMClient4D.Core`; implementation `TIAM4DKeycloakClient`. The async methods return a promise started by `Run`; the callbacks run on the main thread by default ([AsyncCore.md](AsyncCore.md)). They keep a reference to the client until their task ends. `Cancel` stops only the login flows (`StartAuthorizationFlowAsync`); the other tasks do not check it and run to their end, bounded by `ResponseTimeout`. Exceptions reach `OnError`; `WaitForResult` re-raises a copy with `ErrorCode` and `Context`.

| Async | Sync | Grant | Effect |
|-------|------|-------|--------|
| `ConfigureAsync(Config)` | (`TIAM4DKeycloakClient.Configure`) | any | Section [2](#without-the-builder) |
| `StartAuthorizationFlowAsync(...)` | | AC | Section [4.1](#41-desktop-local-callback-server) |
| | `InitializeAuthorizationFlow(...)`, `GenerateAuthURL(...)` | AC | Section [4.3](#43-web-app-external-callback) |
| `CompleteAuthorizationFlowAsync(Code, State, Iss)` | `CompleteAuthorizationFlow` | AC | Section [4.3](#43-web-app-external-callback) |
| `AuthenticateClientAsync` | `AuthenticateClient` | CC | Section [4.4](#44-client-credentials) |
| `AuthenticatePasswordAsync(User, Password)` | `AuthenticatePassword` | password | Section [4.5](#45-password-grant) |
| `GetAccessTokenAsync` | `GetAccessToken` | any | Valid access token, renewed when needed: section [7.1](#71-access-token) |
| | `InvalidateAccessToken(Token)` | any | Section [7.1](#71-access-token) |
| `GetUserInfoAsync` | `GetUserInfo` | AC, password | Section [7.4](#74-user-info) |
| `LogoutAsync` | `Logout` | any | Section [8](#8-ending-a-session) |
| `RevokeTokensAsync` | `RevokeTokens` | any | Section [8](#8-ending-a-session) |
| | `GenerateLogoutURL(PostLogoutRedirectURI, State)` | AC | Section [8](#8-ending-a-session) |
| | `CancelAuthorizationFlow` | AC | Stops the callback server; the pending login ends as cancelled |

AC: Authorization Code; CC: Client Credentials.

| Member | Meaning |
|--------|---------|
| `IsAuthenticated` | AC and password: tokens stored and refresh token valid (with the expiry buffer); CC: access token valid |
| `Issuer`, `JWKSUri` | From the discovery document |
| `RedirectURI` | Redirect URI of the callback handler; '' for other grants. With port 0, known once the callback server started |
| `KeycloakActionStatus` | Section [5](#5-authorization-request-options) |
| `GetIDTokenClaims` | Section [7.3](#73-id-token-claims) |
| `GetGrantedScopes`, `HasGrantedScope(Scope)` | Section [7.2](#72-granted-scopes) |
| `CreateHTTPClient` | A new `THTTPClient` (the caller frees it) with the SSL mode, pinned keys and timeouts of the client; redirects not followed |
| `AddPinnedPublicKeys(Hashes)`, `ClearPinnedPublicKeys` | Pinning: [Security.md](Security.md). `ENotSupportedException` on Linux |

Thread safety (`TIAM4DKeycloakClient`): calls from several threads run in parallel, each request on an HTTP client of a pool (4 idle clients kept). One refresh runs at a time; concurrent `GetAccessToken` calls wait for it and get its token. `Logout` and `RevokeTokens` wait for a refresh in progress, and no refresh stores tokens after them; a refresh that overlaps a login or a new configuration drops its tokens. One login at a time per client.

## 7. Tokens, claims and user info

### 7.1 Access token

`GetAccessToken` returns the stored access token while it is valid (expiry minus the buffer). Otherwise:

| Grant | Renewal | Failure |
|-------|---------|---------|
| AC, password | Refresh token grant | `EIAM4DRefreshTokenExpiredException`: refresh token expired, or Keycloak refused it (`invalid_grant`: session ended, token revoked; `Context['error_description']` holds the reason), also when not logged in. Tokens cleared: a new login is needed |
| | | Network error, timeout, 5xx: `EIAM4DNetworkTimeoutException`, `EIAM4DNetworkUnreachableException`, `EIAM4DException`. Tokens kept: a later call can refresh them |
| | | Refreshed id_token not valid: `EIAM4DSecurityValidationException`, tokens cleared |
| CC | New Client Credentials request | The error raised, tokens cleared |

A refresh response without refresh token, id_token or scope keeps the previous one. With the signing keys unavailable the new tokens are stored with the previous id_token. When a login replaced the session during the refresh, the new session's access token is returned, or `EIAM4DException` asks to call again.

`InvalidateAccessToken(Token)` marks `Token` expired if it is still the stored one: the next `GetAccessToken` renews it. For an API that answered 401 to a token not yet expired (revoked, keys rotated, clocks apart). Another token (renewed meanwhile, a new login) is left alone, so concurrent 401s renew once. The session and the refresh token are kept. `TIAM4DAuthorizedHTTPClient` calls it before its retry.

### 7.2 Granted scopes

`GetGrantedScopes` returns the `scope` of the token response (RFC 6749 5.1), or the requested scopes when the server sent none; empty when not authenticated. `HasGrantedScope(Scope)` compares case-sensitively (RFC 6749 3.3). The server may grant fewer scopes than requested: check them before calling an API that needs one.

### 7.3 ID token claims

`GetIDTokenClaims: TIAM4DIDTokenClaims` reads the id_token stored after the login or the last refresh. It was validated then and is not checked again. Empty (`IsEmpty`) without an id_token (not authenticated, Client Credentials without `openid`).

| Field | Claim |
|-------|-------|
| `Subject`, `Issuer`, `AuthorizedParty`, `SessionID` | `sub`, `iss`, `azp`, `sid` |
| `Audience`, `Amr` | `aud`, `amr` (string arrays) |
| `Acr` | `acr` |
| `AuthTime`, `IssuedAt`, `ExpiresAt` | `auth_time`, `iat`, `exp` (Unix seconds, 0 when absent) |
| `PreferredUsername`, `Email`, `Name` | `preferred_username`, `email`, `name` |

Methods: `HasClaim(Name)`, `GetClaim(Name)` (string value, JSON text for another type, '' when absent), `JSON` (the payload). `TIAM4DIDTokenClaims.FromIDToken(Token)` decodes any id_token without verifying it; a value that is not a JWS compact serialization with a JSON object payload raises `EIAM4DException`.

### 7.4 User info

`GetUserInfo` calls the UserInfo endpoint with the access token (renewed if needed). Client Credentials: `EIAM4DException`. An answer other than 200/201: `EIAM4DException` (`User info failed: <status> - <body>`). A `sub` different from the one of the id_token: `EIAM4DSecurityValidationException` (`ecTokenInvalid`).

`TIAM4DUserInfo`: `Sub`, `PreferredUsername`, `Name`, `GivenName`, `FamilyName`, `Email`, `EmailVerified`, `PhoneNumber`, `PhoneNumberVerified`, `Picture`, `UpdatedAt`, `RawJSON`. `GetCustomClaims` returns a new `TDictionary<string, string>` with the other claims (the caller frees it; a claim that is an object or an array has an empty value: read `RawJSON`). `GetCustomClaim(Name)` reads one claim.

### 7.5 id_token validation

Every id_token of the token endpoint is validated before the tokens are stored: signature with the keys of the `jwks_uri` of the discovery document, `iss` equal to the issuer of the discovery, `aud` containing the client ID, `azp` (required with several audiences, equal to the client ID when present), `exp`, `iat` (not in the future, not older than 300 s plus the response timeout in seconds, at least 60), `typ` `ID`, within a clock skew of 300 s. The code exchange also checks `nonce` and, with `max_age`, `auth_time`; a refresh checks that `sub` and `aud` are those of the login, and `nonce` when present. A failure raises `EIAM4DSecurityValidationException` with the code of the failed check (`ecJWTSignatureInvalid`, `ecJWKSKeyNotFound`, `ecJWTIssuerMismatch`, `ecJWTAudienceMismatch`, `ecJWTExpired`, `ecJWTNotYetValid`, `ecNonceValidationFailed`; `ecTokenInvalid` for the other checks); signing keys that cannot be fetched raise `EIAM4DJWKSUnavailableException` (`ecDiscoveryFailed`). Validator and JWKS: [Security.md](Security.md).

### 7.6 TIAM4DTokens

The token record of the storage: `AccessToken`, `RefreshToken`, `IDToken`, `ExpiresIn`, `RefreshExpiresIn` (seconds, from the token response), `AccessTokenExpiry`, `RefreshTokenExpiry` (UTC; a `refresh_expires_in` of 0, as Keycloak sends for offline tokens, gives 10 days), `Scope`. `FromJSONObject`, `ToJSONObject`: serialization. Not thread-safe. Storage: [Storage.md](Storage.md).

## 8. Ending a session

| | `Logout` | `RevokeTokens` | `GenerateLogoutURL` |
|--|----------|----------------|---------------------|
| Ends | The whole Keycloak user session | What this client holds (RFC 7009): with Keycloak the session of this client, and the user session when no other client uses it | The session of the browser cookie |
| Request | Back-channel POST of the refresh token to the end session endpoint; without refresh token (AC), GET of the end session URL with `id_token_hint` | POST of the refresh token, then of the access token, to the revocation endpoint | None: the browser is redirected there |
| Tokens | Cleared, configured scopes restored, also when the request fails | Cleared once revocation is attempted, also when it fails | Kept |
| For | Desktop, mobile, password grant | Any client; also ends an offline session (`offline_access`) | Web apps |

`Logout`: a session already closed or a refresh token Keycloak refuses is not an error; with a refresh token already expired nothing is sent. Client Credentials: tokens cleared, no request. Keycloak unreachable or an error answer: `EIAM4DException` (or a network exception), tokens cleared anyway. It also stops the callback server.

`RevokeTokens`: no `revocation_endpoint` in the discovery document: `EIAM4DException`, nothing sent, tokens kept (`Logout` can still end the session). A token the server does not know is not an error (RFC 7009 2.2), nor `unsupported_token_type`. The access token is revoked also when the refresh token revocation fails; the first error is raised. A revoked access token is refused by userinfo and introspection; an API that validates the JWT locally accepts it until it expires.

`GenerateLogoutURL(PostLogoutRedirectURI = '', State = '')` (OpenID Connect RP-Initiated Logout): URL of the end session endpoint with `client_id` and, while tokens are stored, `id_token_hint` (generate it before `Logout` or `RevokeTokens`; without it Keycloak asks the user to confirm). Keycloak then redirects to `PostLogoutRedirectURI`, registered in the client as a valid post logout redirect URI, with `State`. No end session endpoint: `EIAM4DException`. A redirect URI that is not HTTP(S), or plain HTTP outside the loopback without `AllowInsecureHTTP`: `EIAM4DInvalidConfigurationException`.

## 9. Callback handling

### 9.1 Modes

`TIAM4DCallbackMode` (unit `IAMClient4D.Core`), chosen by the builder:

| Mode | Builder | Redirect URI | Handler |
|------|---------|--------------|---------|
| `cbmLocalServer` | default | `http://localhost:<port>/oauth2callback` (`lrhLocalhost`) or `http://127.0.0.1:<port>/oauth2callback` (`lrhLoopbackIP`) | `TIAM4DLocalCallbackHandler` |
| `cbmAppRedirect` | `WithAppRedirect(URI)` | the given private-use URI | `TIAM4DAppRedirectCallbackHandler` |
| `cbmExternal` | `WithExternalCallback(URL)` | the given URL | `TIAM4DExternalCallbackHandler` |

The client creates and drives the handler; applications do not call it. The callback path is `IAM4D_OAUTH2_CALLBACK_DEFAULT_PATH` (`/oauth2callback`). Register the redirect URI in the Keycloak client: the sample client `iam4d-sample-app` accepts `http://localhost/oauth2callback` and `http://127.0.0.1/oauth2callback` on any port (RFC 8252).

`TIAM4DLocalCallbackHandler` and `TIAM4DAppRedirectCallbackHandler` descend from `TIAM4DRedirectCallbackHandlerBase`, which receives the redirect URL: a callback without the `state` of the flow (code or error) or one that cannot be parsed is ignored and the login keeps waiting; with the `state` of the flow the `iss` is checked first (RFC 9207: absent when the discovery announces `authorization_response_iss_parameter_supported`, or different from the issuer: `EIAM4DCallbackHandlerException`), then an error response ends the login with `EIAM4DOAuth2CallbackException`, a code goes to the token exchange. `SetOnCodeReceived` takes a `TProc<string, string, string>`: code, state, `kc_action_status` ([MIGRATION_3.0.md](../MIGRATION_3.0.md) for handlers of your own).

### 9.2 Local callback server (desktop)

Unit `IAMClient4D.Callback.Handler.Local`, Indy server of `IAMClient4D.Server.Callback.IndyHttpServer`.

- Listens on `127.0.0.1`, on `CallbackPort` or a free port (0), from the start of the flow to its end (completed, failed, cancelled), and stops on `Logout`, `RevokeTokens`, a new configuration, the destruction of the client.
- A `Host` header other than `localhost`, `127.0.0.1` or `[::1]` gets 400 (DNS rebinding).
- A callback with a wrong or missing `state` gets an error page (400) and the login keeps waiting: any web page can call the loopback URL. A second callback for the same `state` (reload) is ignored: the code is exchanged once.
- Values of the request shown in the pages are HTML-escaped.
- `AppActivation` (`TIAM4DAppActivation`), Windows only, after a callback of the flow: `aaNone` (the user goes back to the app), `aaFlash` (taskbar button flashes, no focus taken), `aaForeground` (the window comes to the foreground; if Windows refuses, the button flashes). The window is the first visible, unowned, non-tool top-level window of the process.
- `LoopbackRedirectHost` (`TIAM4DLoopbackRedirectHost`): host of the redirect URI only; the server listens on `127.0.0.1` in both cases. `lrhLoopbackIP` avoids name resolution and browsers that try `::1` first (RFC 8252 8.3).

### 9.3 App redirect (mobile)

Unit `IAMClient4D.Callback.Handler.AppRedirect` (no FMX dependency).

`TIAM4DAppRedirectCallbackHandler.IsValidRedirectURI(URI, out Error)`: the URI must have a lowercase scheme that is a reverse domain name (at least one dot, no empty label, starting with a letter, characters `a-z 0-9 + - .`), then `:/` or `://` and a path, no query, no fragment; `http` and `https` are refused. Keycloak accepts `com.example.app:/oauth2callback` as it is.

`TIAM4DAppRedirect` (thread-safe):

| Method | Effect |
|--------|--------|
| `HandleURL(URL): Boolean` | True if `URL` is the redirect of a waiting login (its redirect URI, scheme case-insensitive, and the `state` of the flow): processed in the background, once. False otherwise (other URI, forged `state`, malformed, no login waiting): nothing happens, the login keeps waiting. Two clients with the same URI are told apart by the `state` |
| `IsWaiting: Boolean` | True while a login waits for the redirect |

<!-- snippet ver=3.0 kind=decl uses=IAMClient4D.Callback.Handler.AppRedirect -->
```delphi
// Called by the code that receives the URLs of the app scheme (intent, OpenURL event)
procedure OnAppURL(const AURL: string);
begin
  if not TIAM4DAppRedirect.HandleURL(AURL) then
    Writeln('Not the redirect of a pending login: ignored');
end;
```

The pending login is not persisted: if the operating system kills the app while the browser is open, the redirect finds no login waiting. Another app may claim the same scheme: without the PKCE verifier it cannot exchange the code (RFC 8252 8.1).

`TIAM4DAppRedirectListener` (unit `IAMClient4D.FMX.AppRedirect`, folder `src/FMX`, main thread):

| Method | Effect |
|--------|--------|
| `Install(OnURL = nil, UseCustomTabs = True, IOSLoginBrowser = ilbSafari)` | Passes the URLs the system hands to the app to `HandleURL` (`OnURL` receives each URL and whether it was taken). Android: intent filter on the scheme, page in a Custom Tab (`browser-1.8.0.dex.jar`, falls back to the browser). iOS: `TApplicationEvent.OpenURL`; page in Safari or, with `ilbAuthenticationSession`, in an `ASWebAuthenticationSession`. Replaces `TIAM4DPlatformUtils.OpenURLHandler`. Other platforms: nothing |
| `Uninstall` | Stops listening, restores the previous open URL handler |
| `OpenInCustomTab(URL): Boolean` | Android: opens a URL in a Custom Tab; False on other platforms |

Android: main activity `android:launchMode="singleTask"` and an intent filter `VIEW`/`DEFAULT`/`BROWSABLE` with the scheme. iOS: `CFBundleURLTypes` with the scheme. Complete app: `samples/FMX/IdentityBrokering`.

### 9.4 External callback (web apps)

Unit `IAMClient4D.Callback.Handler.External`. No server is started: the redirect URL must be an `http(s)` URL of the web server (`EIAM4DCallbackHandlerException` otherwise). The handler keeps the context of one pending login; the client takes it with the `state` of the callback. Flow and checks: section [4.3](#43-web-app-external-callback).

### 9.5 TIAM4DOAuth2URLParser

Unit `IAMClient4D.Common.OAuth2URLParser`, class methods, thread-safe.

| Method | Effect |
|--------|--------|
| `ParseOAuth2Callback(URL): TIAM4DOAuth2CallbackResult` | `Code`, `State`, `Error`, `ErrorDescription`, `KeycloakActionStatus` (`kc_action_status`), `Iss` of a callback URL, also of a private-use scheme without authority (`com.example.app:/path?...`). Unparsable: `EIAM4DOAuth2CallbackException` |
| `ExtractCodeAndState(URL, out Code, out State)` | Error response, or missing code or state: `EIAM4DOAuth2CallbackException` |
| `CreateErrorException(Result)` | `EIAM4DOAuth2CallbackException` for an error response, `Context` keys `error` and `error_description` (when present) |
| `ParseQueryString(Query): TStringList` | Decoded name-value pairs; the caller frees the list |
| `HasOAuth2Error(Params)`, `GetOAuth2ErrorMessage(Params)` | On the list of `ParseQueryString` |

`TIAM4DOAuth2CallbackResult.IsSuccess`: a code and no error; `IsError`: an error.

## 10. TIAM4DAuthorizedHTTPClient

Unit `IAMClient4D.AuthorizedHTTP`. An HTTP client that sends the access token of an `IIAM4DClient` as bearer.

<!-- snippet ver=3.0 kind=body ctx=client,ui uses=IAMClient4D.AuthorizedHTTP -->
```delphi
var LAPI := TIAM4DAuthorizedHTTPClient.Create(LClient);
try
  var LResponse := LAPI.Get('http://localhost:8090/api/elementary/power?base=2&exponent=10');
  ShowMessage(Format('%d %s', [LResponse.StatusCode, LResponse.ContentAsString]));
finally
  LAPI.Free;
end;
```

| Member | Effect |
|--------|--------|
| `Create(Client, HTTPClient = nil, OwnsHTTPClient = True)` | Nil `HTTPClient`: a new `THTTPClient` (RTL timeouts); a given one is freed with this object when `OwnsHTTPClient`. Nil `Client`: `EArgumentNilException` |
| `Execute(Method, URL, Body = nil, Headers = nil)` | Request with `Authorization: Bearer <token>` |
| `Get`, `Delete(URL, Headers)` | |
| `Post`, `Put`, `Patch(URL, Body: TStream, Headers)` | |
| `Post`, `Put`, `Patch(URL, Content, ContentType, Headers)` | `Content` sent as UTF-8 with that `Content-Type` |
| `RetryOnUnauthorized` | Default True: a 401 is retried once after `InvalidateAccessToken` and a renewed token; a second 401 is returned |
| `AllowInsecureHTTP` | Default False: the bearer is not sent over `http://` outside the loopback (`EIAM4DInvalidConfigurationException`) |
| `HTTPClient` | The `THTTPClient` used: configure TLS, proxy and timeouts there |
| `Client` | The `IIAM4DClient` |

- Each request takes the token from `GetAccessToken`: its errors propagate (`EIAM4DRefreshTokenExpiredException` means a new login).
- A URL that is not HTTP(S), or `Headers` with `Authorization`: `EArgumentException`.
- Redirects are never followed (`HandleRedirects` set to False before each request): a 3xx is returned, the token stays on that host.
- The `THTTPClient` is not the one of `IIAM4DClient`: the pinned keys of Keycloak do not apply to the API.
- A body stream is sent again from its starting position on the retry: it must be seekable.
- Not thread-safe: one instance per thread; instances can share the `IIAM4DClient`.

## 11. HTTP layer and discovery

### 11.1 TIAM4DHTTPClientFactory

Unit `IAMClient4D.Core`. Every request of the client goes through it.

| Method | Effect |
|--------|--------|
| `CreateHTTPClient` (overloads: none, `TIAM4DHTTPClientConfig`, `TIAM4DClientConfig`, `TIAM4DClientConfig` + `TIAM4DHTTPClientSSLHelper`) | A `THTTPClient` with the timeouts, `SendTimeout = ResponseTimeout`, redirects not followed, certificate validation of the SSL mode. The caller frees it |
| `Execute(Client, Method, URL, Source = nil, Headers = nil)` | One request bounded as a whole by `Client.ResponseTimeout` |
| `GetWithRetry(Client, URL, Headers, MaxRetries = 3)` | GET with exponential backoff and jitter (100 ms, 200 ms, ...) |
| `PostFormUrlEncodedWithRetry(Client, URL, Form, Headers, MaxRetries = 3)` | Form POST with the same retries |

`Execute` raises `EIAM4DNetworkTimeoutException` past the deadline, `EIAM4DSSLCertificateException` for a refused certificate, `EIAM4DNetworkUnreachableException` for any other network error (connection refused, name not resolved, connection reset): never a raw `ENetException`. The retrying methods retry network errors, 429 and the transient 5xx (500, 502, 503, 504 and unknown 5xx; not 501, 505-508, 510, 511), never other 4xx, timeouts or certificate errors; after the last attempt the 429/5xx response is returned and a network error raised. Thread-safe.

Requests of your own with the client settings and the same deadline:

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
var LHTTP := LClient.CreateHTTPClient;
try
  var LResponse := TIAM4DHTTPClientFactory.Execute(LHTTP, 'GET',
    'http://localhost:18180/auth/realms/iamclient4d/.well-known/openid-configuration');
  ShowMessage(LResponse.StatusCode.ToString);
finally
  LHTTP.Free;
end;
```

### 11.2 Timeouts

`ConnectionTimeout` and `ResponseTimeout` (milliseconds, default 30000 and 60000) apply to every request of the client: discovery, token, user info, logout, revocation, JWKS.

- `ConnectionTimeout` bounds name resolution and connection.
- `ResponseTimeout` bounds the whole request: connection, sending, waiting for the response and reading it. It is also the send timeout. Past it: `EIAM4DNetworkTimeoutException` (`ErrorCode = ecNetworkTimeout`, `Endpoint` without query, `TimeoutMs`); the JWKS provider reports it as `EIAM4DJWKSUnavailableException`.
- `ResponseTimeout` 0 or less sets no deadline.
- On Windows `THTTPClient` (WinHTTP) applies the timeouts to each network operation, so a response that trickles in would never time out: `Execute` cancels the request at the deadline with a timer of the system timer queue. On Linux libcurl applies `ResponseTimeout` to the whole transfer.

### 11.3 Discovery

The client reads `BaseURL/realms/Realm/.well-known/openid-configuration` into `TIAM4DWellKnownEndpoints`: `AuthorizationEndpoint`, `TokenEndpoint`, `UserInfoEndpoint`, `EndSessionEndpoint`, `RevocationEndpoint` (empty when not announced), `JWKSUri`, `Issuer`, `AuthorizationResponseIssParameterSupported` (RFC 9207). For an `https://` realm an `http://` endpoint is refused (`EIAM4DInvalidConfigurationException`).

`TIAM4DDiscoveryCache` (unit `IAMClient4D.Discovery.Cache`, thread-safe) keeps the endpoints of successful discoveries for the whole process, by realm URL and SSL validation mode: a host that creates a client per login does not fetch the document every time.

| Member | Effect |
|--------|--------|
| `Enabled` | Default True; False clears the entries and every client fetches the document |
| `TimeToLiveSeconds` | Lifetime of an entry, default 3600 (`DEFAULT_TIME_TO_LIVE_SECONDS`), greater than 0 |
| `Clear` | Forgets every entry (e.g. after moving a realm) |
| `Count` | Entries stored, expired ones included |

Failed discoveries are not stored. A client with pinned keys always fetches its own document. A strict client never reuses a document fetched by a client that accepts self-signed certificates.

## 12. Common utilities

### 12.1 TIAM4DPlatformUtils

Unit `IAMClient4D.Common.PlatformUtils`.

| Member | Effect |
|--------|--------|
| `OpenURL(URL): Boolean` | Opens an `http` or `https` URL with the system handler (Windows `ShellExecute`, macOS `open`, Linux `xdg-open`, iOS `openURL:options:completionHandler:`, Android `ACTION_VIEW`), or with `OpenURLHandler` when assigned. Other schemes, an empty or invalid URL, a failure: False, no exception |
| `OpenURLHandler` | `TIAM4DOpenURLHandler = reference to function(const AURL: string): Boolean` used by `OpenURL` in place of the system handler; nil (default) restores it |
| `TryGetURIScheme(URL, out Scheme): Boolean` | Lowercase scheme if present and valid (letter, then letters, digits, `+ - .`) |
| `ActivateApplication(Mode)` | Section [9.2](#92-local-callback-server-desktop) (`AppActivation`); never raises |

`OpenURLHandler` is process-wide: assign it before the first login. The scheme check of `OpenURL` runs first, so only `http` and `https` reach it. It runs on the thread calling `OpenURL`; an exception raised by it makes `OpenURL` return False. Reading and assigning it is thread-safe. Uses: tests without a browser, an embedded browser, showing the URL on a headless machine. `StartAuthorizationFlowAsync` raises `EIAM4DException` when `OpenURL` returns False.

<!-- snippet ver=3.0 kind=body uses=IAMClient4D.Common.PlatformUtils -->
```delphi
// Headless machine: show the URL instead of opening a browser
TIAM4DPlatformUtils.OpenURLHandler :=
  function(const AURL: string): Boolean
  begin
    Writeln('Open this URL in a browser: ', AURL);
    Result := True;
  end;
```

### 12.2 Constants

`IAMClient4D.Common.Constants` holds the protocol names the library sends and reads (`IAM4D_OAUTH2_PARAM_*`, `IAM4D_OIDC_METADATA_*`, ...). Those an application uses:

| Constant | Value |
|----------|-------|
| `IAM4D_VERSION`, `IAM4D_VERSION_MAJOR`, `_MINOR`, `_PATCH` | `3.0.0`, 3, 0, 0 |
| `IAM4D_ACR_PASSKEY`, `IAM4D_ACR_2FA`, `IAM4D_ACR_1FA` | `urn:keycloak:acr:passkey`, `urn:keycloak:acr:2fa`, `urn:keycloak:acr:1fa` |
| `IAM4D_AMR_PASSWORD`, `_OTP`, `_HARDWARE_KEY`, `_MFA`, ... | RFC 8176 values (`pwd`, `otp`, `hwk`, `mfa`, ...) for `TIAM4DIDTokenClaims.Amr` |
| `IAM4D_OAUTH2_SCOPE_OPENID` | `openid` |
| `IAM4D_OAUTH2_CALLBACK_DEFAULT_PATH` | `/oauth2callback` |
| `IAM4D_OAUTH2_ERROR`, `IAM4D_OAUTH2_ERROR_DESCRIPTION` | `error`, `error_description` (also `Context` keys) |
| `IAM4D_KEYCLOAK_PARAM_IDP_HINT`, `IAM4D_KEYCLOAK_PARAM_KC_ACTION`, `IAM4D_KEYCLOAK_PARAM_KC_ACTION_STATUS` | `kc_idp_hint`, `kc_action`, `kc_action_status` |

The login constants (`IAM4D_PROMPT_*`, `IAM4D_MAX_AGE_*`, `IAM4D_IDP_HINT_NONE`, `IAM4D_KC_ACTION_*`) are in `IAMClient4D.Core`: section [5](#5-authorization-request-options).

### 12.3 Other common units

Used by the library; public, rarely needed by an application.

| Unit | Content |
|------|---------|
| `IAMClient4D.Common.CryptoUtils` | `TIAM4DCryptoUtils.GenerateSecureRandomBytes(Count)` (CSPRNG, e.g. a storage key), `HMAC_SHA256` |
| `IAMClient4D.Common.SecureMemory` | `SecureEquals`, `SecureStringEquals` (constant time), `SecureZero`, `SecureZeroString`, `SecureZeroStrings` |
| `IAMClient4D.Common.PKCEGenerator` | `TIAM4DPKCEGenerator` (RFC 7636 verifier and `S256` challenge) |
| `IAMClient4D.Common.JSONUtils` | `TIAM4DJSONUtils` (`SafeParse*` raise `EIAM4DJSONParseException`, `TryParse*`) |
| `IAMClient4D.Common.CryptoHashUtils` | `TIAM4DPublicKeyHashUtils` (public key hashes for pinning: [Security.md](Security.md)) |
| `IAMClient4D.Common.TokenSerializer` | `TIAM4DTokenSerializer` (`TIAM4DTokens` to JSON and bytes: [Storage.md](Storage.md)) |
| `IAMClient4D.Common.Security` | `TIAM4DSSLValidationMode`, certificate validator: [Security.md](Security.md) |

## 13. Exceptions and error codes

Unit `IAMClient4D.Exceptions` unless stated otherwise.

### 13.1 EIAM4DException

The base of the library exceptions (`EIAM4DCryptoNotSupportedException` of `IAMClient4D.Security.Crypto.Interfaces` descends from `Exception`).

| Member | Meaning |
|--------|---------|
| `ErrorCode: TIAM4DErrorCode` | Machine-readable code: use it, not `Message`, in conditions |
| `Context: TDictionary<string, string>` | Non-sensitive details (e.g. `status_code`, `endpoint`, `error_description`), created on demand; never tokens or passwords |
| `WithContext(Key, Value)` | Adds an entry, returns the exception |
| `Clone` | Independent copy: same class, message, code, context and fields. Registered with Async.Core, so `OnError` and `WaitForResult` get every field |
| `Create(Message, ErrorCode = ecUnknown)`, `CreateFmt(...)` | Constructors |

### 13.2 Classes

| Class | Parent | ErrorCode | Raised by, data |
|-------|--------|-----------|-----------------|
| `EIAM4DException` | `Exception` | `ecUnknown` | Generic errors of the client: wrong grant or callback mode, a call out of order, an error answer of the token, userinfo, logout or revocation endpoint (`<operation> failed: <status> - <body>`; a 3xx names the `Location` not followed), a missing endpoint |
| `EIAM4DSecurityValidationException` | `EIAM4DException` | JWT validator: `ecJWTExpired`, `ecJWTNotYetValid`, `ecJWTAudienceMismatch` or `ecUnknown`; client: the code of the validator for the id_token (`ecTokenInvalid` when there is none), `ecNonceValidationFailed`, `ecTokenInvalid` | id_token, `nonce`, `auth_time`, UserInfo `sub`; JWT validation ([Security.md](Security.md)) |
| `EIAM4DStateMismatchException` | `EIAM4DSecurityValidationException` | `ecStateMismatch` | `CompleteAuthorizationFlow`: `state` missing, malformed or wrong |
| `EIAM4DJWTSignatureInvalidException` | `EIAM4DSecurityValidationException` | `ecJWTSignatureInvalid` | JWT validator; `Context` `key_id`, `algorithm` |
| `EIAM4DJWTIssuerMismatchException` | `EIAM4DSecurityValidationException` | `ecJWTIssuerMismatch` | JWT validator; `Context` `expected_issuer`, `actual_issuer` |
| `EIAM4DJWKSKeyNotFoundException` | `EIAM4DSecurityValidationException` | `ecJWKSKeyNotFound` | JWKS provider: no key for the `kid` |
| `EIAM4DJWKSUnavailableException` (unit `IAMClient4D.Security.JWT.JWKS`) | `EIAM4DSecurityValidationException` | `ecDiscoveryFailed` | Keys of the issuer not obtainable; `RetryAfterSeconds` |
| `EIAM4DRefreshTokenExpiredException` | `EIAM4DException` | `ecRefreshTokenExpired` | `GetAccessToken`: section [7.1](#71-access-token); `Context['error_description']` |
| `EIAM4DInvalidCredentialsException` | `EIAM4DException` | `ecInvalidCredentials` | `AuthenticatePassword` |
| `EIAM4DAccountNotFullySetUpException` | `EIAM4DException` | `ecAccountNotFullySetUp` | `AuthenticatePassword` |
| `EIAM4DAccountDisabledException` | `EIAM4DException` | `ecAccountDisabled` | `AuthenticatePassword` |
| `EIAM4DNetworkTimeoutException` | `EIAM4DException` | `ecNetworkTimeout` | Any request: `Endpoint`, `TimeoutMs`; `Context` `endpoint`, `timeout_ms` |
| `EIAM4DNetworkUnreachableException` | `EIAM4DException` | `ecNetworkUnreachable` | Any request: connection refused, name not resolved, reset; `Context` `host` |
| `EIAM4DSSLCertificateException` | `EIAM4DException` | `ecSSLCertificateError` | Certificate refused: `CertificateIssue` |
| `EIAM4DInvalidConfigurationException` | `EIAM4DException` | `ecInvalidConfiguration` | Plain HTTP refused (configuration, discovery endpoints, post-logout URI, `TIAM4DAuthorizedHTTPClient`); invalid settings elsewhere in the library |
| `EIAM4DCallbackHandlerException` | `EIAM4DException` | `ecUnknown` | Callback handlers: server not started, invalid redirect URI, wrong `iss` |
| `EIAM4DOAuth2CallbackException` | `EIAM4DException` | `ecUnknown` | Error response of the authorization server (`Context` `error`, `error_description`); unparsable callback URL |
| `EIAM4DServerCallbackException` | `EIAM4DException` | `ecUnknown` | Local callback server |
| `EIAM4DHTTPClientErrorException` | `EIAM4DException` | `ecHTTPClientError` | Admin API 4xx: `StatusCode`, `ResponseBody` ([AdminAPI.md](AdminAPI.md)) |
| `EIAM4DInsufficientPermissionsException` | `EIAM4DHTTPClientErrorException` | `ecInsufficientPermissions` | Admin API 403 |
| `EIAM4DHTTPNotFoundException` | `EIAM4DHTTPClientErrorException` | `ecHTTPClientError` | Admin API 404 |
| `EIAM4DUserNotFoundException` | `EIAM4DHTTPNotFoundException` | `ecUserNotFound` | Admin API: `UserIdentifier` |
| `EIAM4DRoleNotFoundException` | `EIAM4DHTTPNotFoundException` | `ecRoleNotFound` | Admin API |
| `EIAM4DGroupNotFoundException` | `EIAM4DHTTPNotFoundException` | `ecGroupNotFound` | Admin API |
| `EIAM4DHTTPConflictException` | `EIAM4DHTTPClientErrorException` | `ecHTTPClientError` | Admin API 409 |
| `EIAM4DUserAlreadyExistsException` | `EIAM4DHTTPConflictException` | `ecUserAlreadyExists` | `CreateUser`: `ConflictingField`, `Value` |
| `EIAM4DHTTPServerErrorException` | `EIAM4DException` | `ecHTTPServerError` | Admin API 5xx: `StatusCode`, `ResponseBody`, `RetryAfterSeconds` |
| `EIAM4DInvalidUserDataException` | `EIAM4DException` | `ecInvalidUserData` | Admin API: user data validation |
| `EIAM4DStorageException` | `EIAM4DException` | `ecUnknown` | AES token storage: invalid arguments ([Storage.md](Storage.md)) |
| `EIAM4DStorageCryptoException` (unit `IAMClient4D.Storage.Crypto.Interfaces`) | `EIAM4DException` | `ecUnknown` | Storage crypto provider: `ProviderName` |
| `EIAM4DStorageEncryptionException` | `EIAM4DStorageCryptoException` | `ecStorageEncryptionFailed` | Token encryption |
| `EIAM4DStorageDecryptionException` | `EIAM4DStorageCryptoException` | `ecStorageDecryptionFailed` | Decryption or authentication of the stored tokens |
| `EIAM4DOpenSSLException` (unit `IAMClient4D.Crypto.TaurusTLS.Common`) | `EIAM4DException` | `ecCryptoProviderUnavailable` | OpenSSL missing or older than 3.0 (TaurusTLS provider) |
| `EIAM4DJSONParseException` | `EIAM4DException` | `ecUnknown` | Invalid JSON in a response |
| `EIAM4DCryptoUtilsException` | `EIAM4DException` | `ecUnknown` | Random generator, PKCE |
| `EAES256RawException` | `EIAM4DException` | `ecUnknown` | AES-256-CBC + HMAC (LockBox3) |
| `EIAM4DDiscoveryFailedException` | `EIAM4DException` | `ecDiscoveryFailed` | `Build`, `ConfigureAsync`: the discovery document cannot be read (HTTP error or redirect, invalid JSON); the message names the URL |

Deprecated, never raised (warning W1000): `EIAM4DAccessTokenExpiredException` (`ecAccessTokenExpired`), `EIAM4DInvalidAuthCodeException` (`ecInvalidAuthorizationCode`; a refused code exchange raises `EIAM4DException`), `EIAM4DPKCEValidationException` (`ecPKCEValidationFailed`), `EIAM4DAuthorizationTimeoutException` (`ecAuthorizationTimeout`), `EIAM4DEndpointsNotConfiguredException` (`ecEndpointsNotConfigured`), `EIAM4DUnknownRequiredActionException` (`ecInvalidUserData`), `EIAM4DTokenInvalidException` (`ecTokenInvalid`), `EIAM4DAuthorizationCancelledException` (`ecAuthorizationCancelled`; a cancelled login ends as cancelled, without exception).

Order the `except` branches from the most specific class: an `EIAM4DHTTPClientErrorException` branch also catches 403, 404 and 409, an `EIAM4DSecurityValidationException` branch also catches `EIAM4DStateMismatchException` and `EIAM4DJWKSUnavailableException`. The RTL exceptions raised for invalid arguments (`EArgumentException`, `EArgumentOutOfRangeException`, `EArgumentNilException`, `EInvalidOpException`, `ENotSupportedException`) are not `EIAM4DException`. Async.Core exceptions (`EAsyncTimeoutException`, ...): [AsyncCore.md](AsyncCore.md).

### 13.3 Error codes

`TIAM4DErrorCode`, by range. "Not assigned": no class of the library raises an exception with this code.

| Range | Code | Value | Class |
|-------|------|-------|-------|
| | `ecUnknown` | 0 | generic |
| Authentication 1000-1999 | `ecAccessTokenExpired` | 1001 | deprecated class |
| | `ecRefreshTokenExpired` | 1002 | `EIAM4DRefreshTokenExpiredException` |
| | `ecTokenInvalid` | 1003 | `EIAM4DSecurityValidationException` (client) |
| | `ecInvalidCredentials` | 1010 | `EIAM4DInvalidCredentialsException` |
| | `ecAccountNotFullySetUp` | 1011 | `EIAM4DAccountNotFullySetUpException` |
| | `ecAccountDisabled` | 1012 | `EIAM4DAccountDisabledException` |
| | `ecInvalidAuthorizationCode` | 1020 | deprecated class |
| | `ecPKCEValidationFailed` | 1021 | deprecated class |
| | `ecStateMismatch` | 1022 | `EIAM4DStateMismatchException` |
| | `ecAuthorizationCancelled` | 1030 | deprecated class |
| | `ecAuthorizationTimeout` | 1031 | deprecated class |
| | `ecInsufficientPermissions` | 1040 | `EIAM4DInsufficientPermissionsException` |
| Network 2000-2999 | `ecNetworkTimeout` | 2001 | `EIAM4DNetworkTimeoutException` |
| | `ecNetworkUnreachable` | 2002 | `EIAM4DNetworkUnreachableException` (refused connections too) |
| | `ecConnectionRefused` | 2003 | not assigned |
| | `ecSSLCertificateError` | 2010 | `EIAM4DSSLCertificateException` |
| | `ecHTTPClientError` | 2100 | `EIAM4DHTTPClientErrorException`, `EIAM4DHTTPNotFoundException`, `EIAM4DHTTPConflictException` |
| | `ecHTTPServerError` | 2200 | `EIAM4DHTTPServerErrorException` |
| User management 3000-3999 | `ecUserNotFound` | 3001 | `EIAM4DUserNotFoundException` |
| | `ecUserAlreadyExists` | 3002 | `EIAM4DUserAlreadyExistsException` |
| | `ecInvalidUserData` | 3010 | `EIAM4DInvalidUserDataException` |
| | `ecRoleNotFound` | 3020 | `EIAM4DRoleNotFoundException` |
| | `ecGroupNotFound` | 3030 | `EIAM4DGroupNotFoundException` |
| Configuration 4000-4999 | `ecInvalidConfiguration` | 4001 | `EIAM4DInvalidConfigurationException` |
| | `ecEndpointsNotConfigured` | 4002 | deprecated class |
| | `ecDiscoveryFailed` | 4003 | `EIAM4DDiscoveryFailedException`, `EIAM4DJWKSUnavailableException` |
| | `ecCryptoProviderUnavailable` | 4004 | `EIAM4DOpenSSLException` |
| Storage 5000-5999 | `ecStorageNotInitialized` | 5001 | not assigned |
| | `ecStorageEncryptionFailed` | 5002 | `EIAM4DStorageEncryptionException` |
| | `ecStorageDecryptionFailed` | 5003 | `EIAM4DStorageDecryptionException` |
| Security 6000-6999 | `ecJWTSignatureInvalid` | 6001 | `EIAM4DJWTSignatureInvalidException` |
| | `ecJWTIssuerMismatch` | 6002 | `EIAM4DJWTIssuerMismatchException` |
| | `ecJWTAudienceMismatch` | 6003 | `EIAM4DSecurityValidationException` (JWT validator, id_token) |
| | `ecJWTExpired` | 6004 | `EIAM4DSecurityValidationException` (JWT validator, id_token) |
| | `ecJWTNotYetValid` | 6005 | `EIAM4DSecurityValidationException` (JWT validator, id_token) |
| | `ecJWKSKeyNotFound` | 6010 | `EIAM4DJWKSKeyNotFoundException` |
| | `ecNonceValidationFailed` | 6020 | `EIAM4DSecurityValidationException` (`nonce` of the id_token) |

### 13.4 Handling

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
try
  ShowMessage(LClient.GetUserInfo.PreferredUsername);
except
  on E: EIAM4DRefreshTokenExpiredException do
    ShowMessage('Session over, log in again'); // tokens cleared
  on E: EIAM4DException do
    case E.ErrorCode of
      ecNetworkTimeout, ecNetworkUnreachable:
        ShowMessage('Keycloak unreachable, retry later'); // tokens kept
      ecSSLCertificateError:
        ShowMessage('Certificate refused: ' + E.Message);
    else
      ShowMessage(Format('[%d] %s', [Ord(E.ErrorCode), E.Message]));
    end;
end;
```

- Retry network errors a bounded number of times, with a growing delay; let `GetAccessToken` renew expired tokens: only `EIAM4DRefreshTokenExpiredException` asks for a new login.
- Log `ErrorCode`, `Message` and `Context` (and `StatusCode`, `ResponseBody` of the HTTP errors); never the tokens.
- In async code use `OnFinally` for cleanup: a cancelled login runs it but not `OnError`.
