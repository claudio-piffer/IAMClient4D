{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Core.pas
  Project    : IAMClient4D
  Author     : Claudio Piffer
  Copyright  : Copyright (c) 2018-2025 Claudio Piffer
  License    : Apache License, Version 2.0, January 2004
  Source URL : https://github.com/claudio-piffer/IAMClient4D

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  ---------------------------------------------------------------------------
}

unit IAMClient4D.Core;

interface

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.Generics.Collections,
  System.Net.HttpClient,
  System.Net.URLClient,
  Async.Core,
  IAMClient4D.Common.Security,
  IAMClient4D.Common.JSONUtils,
  IAMClient4D.Exceptions;

const
  /// <summary>
  /// Default buffer time in seconds for token expiration checks
  /// </summary>
  IAM4D_TOKEN_EXPIRATION_BUFFER_SECONDS = 120;

  /// <summary>
  /// AIdpHint of StartAuthorizationFlowAsync and GenerateAuthURL: no kc_idp_hint for this login,
  /// even when Config.IdpHint is set (Keycloak shows its login page).
  /// </summary>
  /// <remarks>
  /// Never a valid alias: Keycloak uses the alias as a URL path segment (broker endpoints) and
  /// TIAM4DKeycloakIdentityProviderManager rejects '/' in aliases.
  /// </remarks>
  IAM4D_IDP_HINT_NONE = '/none';

  /// <summary>
  /// TIAM4DClientConfig.MaxAge: no max_age in the authorization request.
  /// </summary>
  IAM4D_MAX_AGE_NONE = -1;

  /// <summary>
  /// TIAM4DAuthRequestOptions.MaxAge: the max_age of the configuration (TIAM4DClientConfig.MaxAge).
  /// </summary>
  IAM4D_MAX_AGE_CONFIGURED = -2;

  /// <summary>
  /// prompt=none: no page is shown; without an active session the login fails with
  /// error=login_required (EIAM4DOAuth2CallbackException).
  /// </summary>
  IAM4D_PROMPT_NONE = 'none';

  /// <summary>
  /// prompt=consent: the authorization server asks the user to consent again.
  /// </summary>
  IAM4D_PROMPT_CONSENT = 'consent';

  /// <summary>
  /// prompt=select_account: the authorization server lets the user pick the account.
  /// </summary>
  IAM4D_PROMPT_SELECT_ACCOUNT = 'select_account';

  /// <summary>
  /// Tolerance in seconds of the time checks of the id_token (exp, iat and, with max_age,
  /// auth_time): difference allowed between the clock of the authorization server and the one
  /// of the client.
  /// </summary>
  IAM4D_AUTH_TIME_CLOCK_SKEW_SECONDS = 300;

  /// <summary>
  /// prompt=login: the authorization server asks for the credentials even with an active SSO session.
  /// </summary>
  IAM4D_PROMPT_LOGIN = 'login';

  /// <summary>
  /// kc_action=UPDATE_PASSWORD: after the login Keycloak asks the user for a new password
  /// (application initiated action).
  /// </summary>
  IAM4D_KC_ACTION_UPDATE_PASSWORD = 'UPDATE_PASSWORD';

  /// <summary>
  /// IIAM4DClient.KeycloakActionStatus: the user completed the requested kc_action.
  /// </summary>
  IAM4D_KC_ACTION_STATUS_SUCCESS = 'success';

  /// <summary>
  /// IIAM4DClient.KeycloakActionStatus: the user cancelled the requested kc_action (still logged in).
  /// </summary>
  IAM4D_KC_ACTION_STATUS_CANCELLED = 'cancelled';

  /// <summary>
  /// IIAM4DClient.KeycloakActionStatus: Keycloak could not run the requested kc_action.
  /// </summary>
  IAM4D_KC_ACTION_STATUS_ERROR = 'error';

type
  /// <summary>
  /// OAuth2 callback handling mode
  /// </summary>
  /// <remarks>
  /// cbmLocalServer: Desktop apps - starts local HTTP server for callback.
  /// cbmExternal: Web apps (uniGUI, ISAPI) - callback handled by external server.
  /// cbmAppRedirect: Mobile apps - redirect on a private-use URI scheme (RFC 8252 7.1) received by the app.
  /// </remarks>
  TIAM4DCallbackMode = (
    cbmLocalServer,

    cbmExternal,

    cbmAppRedirect);

  /// <summary>
  /// What the app does to the user when the browser redirects to the local callback server.
  /// </summary>
  /// <remarks>
  /// aaNone: nothing, the user goes back to the app by himself (default).
  /// aaFlash: the taskbar button of the app flashes, the focus is not taken.
  /// aaForeground: the app window comes to the foreground.
  /// Windows only: other platforms ignore it.
  /// </remarks>
  TIAM4DAppActivation = (
    aaNone,

    aaFlash,

    aaForeground);

  /// <summary>
  /// Host of the redirect URI of the local callback server (the server listens on 127.0.0.1).
  /// </summary>
  /// <remarks>
  /// lrhLocalhost: http://localhost:port/path (default, as in 2.x).
  /// lrhLoopbackIP: http://127.0.0.1:port/path, as RFC 8252 8.3 recommends: no name resolution, and
  /// no browser trying ::1 first. The redirect URI registered in Keycloak must use the same host.
  /// </remarks>
  TIAM4DLoopbackRedirectHost = (
    lrhLocalhost,

    lrhLoopbackIP);

  /// <summary>
  /// OpenID Connect well-known endpoints from discovery document.
  /// </summary>
  /// <remarks>
  /// Retrieved from /.well-known/openid-configuration endpoint.
  /// Contains OAuth2/OIDC server endpoints for authentication flow.
  /// </remarks>
  TIAM4DWellKnownEndpoints = record
  public
    AuthorizationEndpoint: string;
    TokenEndpoint: string;
    UserInfoEndpoint: string;
    EndSessionEndpoint: string;
    /// <summary>revocation_endpoint (RFC 7009); empty when the server does not announce one</summary>
    RevocationEndpoint: string;
    JWKSUri: string;
    Issuer: string;
    /// <summary>
    /// authorization_response_iss_parameter_supported (RFC 9207): the redirect to the client
    /// carries iss, and a redirect without it is refused
    /// </summary>
    AuthorizationResponseIssParameterSupported: Boolean;

    /// <summary>
    /// Parses well-known endpoints from OIDC discovery JSON
    /// </summary>
    class function FromJSONObject(const AJSONObject: TJSONObject): TIAM4DWellKnownEndpoints; static;
  end;

  /// <summary>
  /// OAuth2 grant type
  /// </summary>
  /// <remarks>
  /// gtPassword: Resource Owner Password Credentials (RFC 6749 section 4.3). The client sends the
  /// user's password to the token endpoint (Keycloak: "Direct access grants" enabled on the client).
  /// Only for trusted first-party clients; it cannot log in through a brokered identity provider
  /// nor complete MFA or required actions: use Authorization Code for those.
  /// </remarks>
  TIAM4DGrantType = (gtUnknown, gtAuthorizationCode, gtClientCredentials, gtPassword);

  /// <summary>
  /// OAuth2/OIDC tokens container.
  /// </summary>
  /// <remarks>
  /// Contains access, refresh, and ID tokens with expiry information.
  /// ExpiresIn: Seconds until access token expires (from token response).
  /// AccessTokenExpiry: Calculated absolute expiry time.
  /// Thread-safety: Not thread-safe. Use external synchronization if needed.
  /// </remarks>
  TIAM4DTokens = record
  private
    FAccessToken: string;
    FRefreshToken: string;
    FIDToken: string;
    FExpiresIn: Integer;
    FRefreshExpiresIn: Integer;
    FAccessTokenExpiry: TDateTime;
    FRefreshTokenExpiry: TDateTime;
    FScope: string;
  public
    property AccessToken: string read FAccessToken write FAccessToken;
    property RefreshToken: string read FRefreshToken write FRefreshToken;
    property IDToken: string read FIDToken write FIDToken;
    property ExpiresIn: Integer read FExpiresIn write FExpiresIn;
    property RefreshExpiresIn: Integer read FRefreshExpiresIn write FRefreshExpiresIn; // NOTE: naming kept as in original
    property AccessTokenExpiry: TDateTime read FAccessTokenExpiry write FAccessTokenExpiry;
    property RefreshTokenExpiry: TDateTime read FRefreshTokenExpiry write FRefreshTokenExpiry;
    /// <summary>scope of the token response, space-separated (empty: the server sent none)</summary>
    property Scope: string read FScope write FScope;

    /// <summary>
    /// Deserializes tokens from JSON object
    /// </summary>
    class function FromJSONObject(const AJSONObject: TJSONObject): TIAM4DTokens; static;

    /// <summary>
    /// Serializes tokens to JSON object
    /// </summary>
    class function ToJSONObject(const ATokens: TIAM4DTokens): TJSONObject; static;
  end;

  /// <summary>
  /// Configuration for IAM client.
  /// </summary>
  /// <remarks>
  /// Immutable configuration record for OAuth2/OIDC client.
  /// Use factory methods: CreateForAuthorizationCode() or CreateForClientCredentials().
  /// BaseURL: Keycloak server URL (e.g., https://keycloak.example.com).
  /// Realm: Keycloak realm name.
  /// Timeouts: In milliseconds (default: 30s connection, 60s response).
  /// ExternalCallbackURL: Redirect URI of the cbmExternal (web apps) and cbmAppRedirect (mobile apps) modes.
  /// TokenExpiryBufferSeconds: Buffer time before actual expiration (default: 120 seconds).
  /// </remarks>
  TIAM4DClientConfig = record
  private
    FBaseURL: string;
    FRealm: string;
    FClientID: string;
    FClientSecret: string;
    FScopes: TArray<string>;
    FGrantType: TIAM4DGrantType;
    FSSLValidationMode: TIAM4DSSLValidationMode;
    FConnectionTimeout: Integer; // milliseconds
    FResponseTimeout: Integer; // milliseconds
    FExternalCallbackURL: string;
    FTokenExpiryBufferSeconds: Integer;
    FAcrValues: TArray<string>;
    FIdpHint: string;
    FPrompt: string;
    FMaxAge: Integer;
    FKeycloakAction: string;
    FCallbackPort: Integer;
    FAppActivation: TIAM4DAppActivation;
    FLoopbackRedirectHost: TIAM4DLoopbackRedirectHost;
    FAllowInsecureHTTP: Boolean;
  public
    /// <summary>
    /// Creates client configuration with specified grant type
    /// </summary>
    class function Create(
      const ABaseURL, ARealm, AClientID: string;
      const AGrantType: TIAM4DGrantType = TIAM4DGrantType.gtAuthorizationCode;
      const AScopes: TArray<string> = nil;
      const AClientSecret: string = '';
      const ASSLValidationMode: TIAM4DSSLValidationMode = TIAM4DSSLValidationMode.svmStrict;
      const AConnectionTimeout: Integer = 30000;
      const AResponseTimeout: Integer = 60000;
      const AExternalCallbackURL: string = '';
      const ATokenExpiryBufferSeconds: Integer = IAM4D_TOKEN_EXPIRATION_BUFFER_SECONDS;
      const AAcrValues: TArray<string> = nil;
      const AIdpHint: string = ''
      ): TIAM4DClientConfig; static;

    /// <summary>
    /// Creates configuration for Authorization Code flow
    /// </summary>
    class function CreateForAuthorizationCode(
      const ABaseURL, ARealm, AClientID: string;
      const AScopes: TArray<string> = nil;
      const ASSLValidationMode: TIAM4DSSLValidationMode = TIAM4DSSLValidationMode.svmStrict;
      const AConnectionTimeout: Integer = 30000;
      const AResponseTimeout: Integer = 60000;
      const AExternalCallbackURL: string = '';
      const ATokenExpiryBufferSeconds: Integer = IAM4D_TOKEN_EXPIRATION_BUFFER_SECONDS;
      const AAcrValues: TArray<string> = nil;
      const AIdpHint: string = ''
      ): TIAM4DClientConfig; static;

    /// <summary>
    /// Creates configuration for Client Credentials flow
    /// </summary>
    class function CreateForClientCredentials(
      const ABaseURL, ARealm, AClientID, AClientSecret: string;
      const AScopes: TArray<string> = nil;
      const ASSLValidationMode: TIAM4DSSLValidationMode = TIAM4DSSLValidationMode.svmStrict;
      const AConnectionTimeout: Integer = 30000;
      const AResponseTimeout: Integer = 60000;
      const ATokenExpiryBufferSeconds: Integer = IAM4D_TOKEN_EXPIRATION_BUFFER_SECONDS
      ): TIAM4DClientConfig; static;

    /// <summary>
    /// Creates configuration for the Resource Owner Password Credentials flow
    /// </summary>
    /// <remarks>
    /// AClientSecret: empty for a public client. The openid scope is always requested, so the
    /// token response has the id_token used by Logout.
    /// </remarks>
    class function CreateForPassword(
      const ABaseURL, ARealm, AClientID: string;
      const AClientSecret: string = '';
      const AScopes: TArray<string> = nil;
      const ASSLValidationMode: TIAM4DSSLValidationMode = TIAM4DSSLValidationMode.svmStrict;
      const AConnectionTimeout: Integer = 30000;
      const AResponseTimeout: Integer = 60000;
      const ATokenExpiryBufferSeconds: Integer = IAM4D_TOKEN_EXPIRATION_BUFFER_SECONDS
      ): TIAM4DClientConfig; static;

    /// <summary>
    /// Copy of this configuration with prompt and max_age of the authorization request
    /// </summary>
    /// <remarks>
    /// APrompt: e.g. IAM4D_PROMPT_LOGIN (empty: not sent). AMaxAge: seconds since the last active
    /// authentication of the user, 0 forces a new one (IAM4D_MAX_AGE_NONE: not sent).
    /// Authorization Code only.
    /// </remarks>
    function WithAuthRequestOptions(const APrompt: string; const AMaxAge: Integer): TIAM4DClientConfig;

    /// <summary>
    /// Copy of this configuration with the kc_action of the authorization request
    /// </summary>
    /// <remarks>
    /// AAction: Keycloak required action to run after the login, e.g. IAM4D_KC_ACTION_UPDATE_PASSWORD
    /// (empty: not sent). The outcome is IIAM4DClient.KeycloakActionStatus. Authorization Code only.
    /// </remarks>
    function WithKeycloakAction(const AAction: string): TIAM4DClientConfig;

    /// <summary>
    /// Copy of this configuration with the port of the local callback server (0: free port)
    /// </summary>
    /// <remarks>
    /// A fixed port is needed when the authorization server accepts only exact redirect URIs.
    /// Authorization Code with local callback server only.
    /// </remarks>
    function WithCallbackPort(const APort: Integer): TIAM4DClientConfig;

    /// <summary>
    /// Copy of this configuration with what the app does when the local callback server receives
    /// the redirect of the browser
    /// </summary>
    /// <remarks>
    /// Authorization Code with local callback server only.
    /// </remarks>
    function WithAppActivation(const AValue: TIAM4DAppActivation): TIAM4DClientConfig;
    /// <summary>
    /// Copy of this configuration with the host of the redirect URI of the local callback server
    /// </summary>
    function WithLoopbackRedirectHost(const AValue: TIAM4DLoopbackRedirectHost): TIAM4DClientConfig;
    /// <summary>
    /// Copy of this configuration that accepts plain HTTP to a host other than the loopback
    /// (BaseURL, ExternalCallbackURL): code, tokens, passwords and secrets travel in clear text.
    /// Test environments only (e.g. Keycloak on the LAN for a phone).
    /// </summary>
    function WithAllowInsecureHTTP(const AValue: Boolean): TIAM4DClientConfig;
    /// <summary>
    /// True for an http:// URL whose host is not the loopback (localhost, 127.0.0.0/8, [::1]).
    /// </summary>
    class function IsInsecureHTTPURL(const AURL: string): Boolean; static;

    property BaseURL: string read FBaseURL;
    property Realm: string read FRealm;
    property ClientID: string read FClientID;
    property Scopes: TArray<string> read FScopes;
    property GrantType: TIAM4DGrantType read FGrantType;
    property ClientSecret: string read FClientSecret;
    property SSLValidationMode: TIAM4DSSLValidationMode read FSSLValidationMode;
    property ConnectionTimeout: Integer read FConnectionTimeout;
    property ResponseTimeout: Integer read FResponseTimeout;
    property ExternalCallbackURL: string read FExternalCallbackURL;
    property TokenExpiryBufferSeconds: Integer read FTokenExpiryBufferSeconds;
    /// <summary>
    /// ACR values to request specific authentication levels from Keycloak.
    /// Examples: 'urn:keycloak:acr:passkey', 'urn:keycloak:acr:2fa'
    /// </summary>
    property AcrValues: TArray<string> read FAcrValues;
    /// <summary>
    /// Alias of the Keycloak identity provider to log in with (kc_idp_hint).
    /// Keycloak skips its login page and redirects to that provider. Empty: login page.
    /// </summary>
    property IdpHint: string read FIdpHint;
    /// <summary>
    /// prompt of the authorization request (e.g. IAM4D_PROMPT_LOGIN); empty: not sent.
    /// </summary>
    property Prompt: string read FPrompt;
    /// <summary>
    /// max_age of the authorization request in seconds; IAM4D_MAX_AGE_NONE: not sent.
    /// </summary>
    property MaxAge: Integer read FMaxAge;
    /// <summary>
    /// kc_action of the authorization request (e.g. IAM4D_KC_ACTION_UPDATE_PASSWORD); empty: not sent.
    /// </summary>
    property KeycloakAction: string read FKeycloakAction;
    /// <summary>
    /// Port of the local callback server; 0: free port chosen by the system.
    /// </summary>
    property CallbackPort: Integer read FCallbackPort;
    /// <summary>
    /// What the app does when the local callback server receives the redirect; default aaNone.
    /// </summary>
    property AppActivation: TIAM4DAppActivation read FAppActivation;
    /// <summary>
    /// Host of the redirect URI of the local callback server; default lrhLocalhost.
    /// </summary>
    property LoopbackRedirectHost: TIAM4DLoopbackRedirectHost read FLoopbackRedirectHost;
    /// <summary>
    /// Plain HTTP accepted to a host other than the loopback; default False (see WithAllowInsecureHTTP).
    /// </summary>
    property AllowInsecureHTTP: Boolean read FAllowInsecureHTTP;
  end;

  /// <summary>
  /// Configuration for HTTP client instances.
  /// </summary>
  /// <remarks>
  /// Lightweight config for creating THTTPClient instances.
  /// Timeouts in milliseconds (default: 30s connection, 60s response).
  /// ResponseTimeout bounds each whole request of the library (connection, sending, response) and is
  /// also the send timeout; ConnectionTimeout bounds name resolution and connection. See
  /// TIAM4DHTTPClientFactory.Execute.
  /// </remarks>
  TIAM4DHTTPClientConfig = record
  private
    FConnectionTimeout: Integer;
    FResponseTimeout: Integer;
    FSSLValidationMode: TIAM4DSSLValidationMode;
  public
    /// <summary>
    /// Creates default HTTP client configuration
    /// </summary>
    class function Default: TIAM4DHTTPClientConfig; static;

    /// <summary>
    /// Creates HTTP client config from IAM client config
    /// </summary>
    class function FromClientConfig(const AClientConfig: TIAM4DClientConfig): TIAM4DHTTPClientConfig; static;

    /// <summary>
    /// Creates HTTP client configuration with custom timeouts
    /// </summary>
    class function Create(
      const AConnectionTimeout: Integer = 30000;
      const AResponseTimeout: Integer = 60000;
      const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict
      ): TIAM4DHTTPClientConfig; static;

    property ConnectionTimeout: Integer read FConnectionTimeout write FConnectionTimeout;
    property ResponseTimeout: Integer read FResponseTimeout write FResponseTimeout;
    property SSLValidationMode: TIAM4DSSLValidationMode read FSSLValidationMode write FSSLValidationMode;
  end;

  /// <summary>
  /// Helper class for SSL certificate validation in THTTPClient.
  /// </summary>
  /// <remarks>
  /// Bridges IIAM4DSSLCertificateValidator with THTTPClient.OnValidateServerCertificate event.
  /// Internal use by TIAM4DHTTPClientFactory.
  /// IMPORTANT: This object must be freed manually by the owner of THTTPClient.
  /// </remarks>
  TIAM4DHTTPClientSSLHelper = class
  private
    FSSLValidator: IIAM4DSSLCertificateValidator;
  public
    constructor Create(const ASSLValidator: IIAM4DSSLCertificateValidator);
    /// <summary>
    /// Event handler for THTTPClient.OnValidateServerCertificate: Accepted comes in with the
    /// verdict of the platform and goes out with the one of the validator
    /// </summary>
    procedure ValidateServerCertificate(const Sender: TObject; const ARequest: TURLRequest; const Certificate: TCertificate; var Accepted: Boolean);
    /// <summary>
    /// Event handler that keeps the verdict of the platform (strict clients on Android, see IsCallbackNeeded)
    /// </summary>
    procedure KeepPlatformVerdict(const Sender: TObject; const ARequest: TURLRequest; const Certificate: TCertificate; var Accepted: Boolean);
    /// <summary>
    /// True when THTTPClient must call the validator: self-signed mode, or pinned keys to check.
    /// Strict mode without pins keeps the platform validation alone, except on Android: always True
    /// </summary>
    /// <remarks>
    /// The Android THTTPClient records a refused chain or date in SecureFailureReasons and goes on:
    /// without a callback it accepts any CA and an expired certificate (only the host name is checked).
    /// With a callback Accepted comes in False for such a certificate and the request is refused.
    /// </remarks>
    class function IsCallbackNeeded(AMode: TIAM4DSSLValidationMode;
      const AValidator: IIAM4DSSLCertificateValidator): Boolean; static;
    property SSLValidator: IIAM4DSSLCertificateValidator read FSSLValidator;
  end;

  /// <summary>
  /// Factory for creating configured THTTPClient instances.
  /// </summary>
  /// <remarks>
  /// Centralizes HTTP client creation with SSL validation configuration.
  /// Singleton SSL validator shared across all created clients.
  /// Thread-safety: Safe to call from multiple threads.
  /// Lifecycle: Class constructor/destructor manage SSL validator instance.
  /// </remarks>
  TIAM4DHTTPClientFactory = class
  private
    class var FSSLValidator: IIAM4DSSLCertificateValidator;
    class var FSSLHelper: TIAM4DHTTPClientSSLHelper;
    class procedure ConfigureSSLValidation(const AHTTPClient: THTTPClient; const AConfig: TIAM4DHTTPClientConfig); static;
    class procedure ConfigureSSLValidationWithHelper(const AHTTPClient: THTTPClient; const AConfig: TIAM4DHTTPClientConfig; const ASSLHelper: TIAM4DHTTPClientSSLHelper); static;
    class function NewHTTPClient(const AConfig: TIAM4DHTTPClientConfig): THTTPClient; static;
  public
    /// <summary>
    /// Sends one request: AClient.ResponseTimeout (when > 0) bounds the whole request, from the
    /// connection to the last byte of the response.
    /// </summary>
    /// <remarks>
    /// THTTPClient alone does not: WinHTTP (Windows) applies the timeouts to each network operation,
    /// in steps of a few seconds, so a response that trickles in never times out. On Windows the
    /// request is cancelled at the deadline; on Linux libcurl already applies ResponseTimeout to the
    /// whole transfer. Without a deadline (ResponseTimeout <= 0) it is the same as THTTPClient.Execute.
    /// </remarks>
    /// <exception cref="EIAM4DNetworkTimeoutException">The request did not end within ResponseTimeout.</exception>
    /// <exception cref="EIAM4DNetworkUnreachableException">Any other network error (connection refused,
    /// name not resolved, connection reset): host and THTTPClient's message. Never a raw ENetException.</exception>
    /// <exception cref="EIAM4DSSLCertificateException">The server certificate was refused.</exception>
    class function Execute(
      const AClient: THTTPClient;
      const AMethod, AURL: string;
      const ASource: TStream = nil;
      const AHeaders: TNetHeaders = nil
      ): IHTTPResponse; static;

    /// <summary>
    /// Creates HTTP client with specified configuration
    /// </summary>
    class function CreateHTTPClient(const AConfig: TIAM4DHTTPClientConfig): THTTPClient; overload; static;

    /// <summary>
    /// Creates HTTP client from IAM client configuration
    /// </summary>
    class function CreateHTTPClient(const AClientConfig: TIAM4DClientConfig): THTTPClient; overload; static;

    /// <summary>
    /// Creates HTTP client with custom SSL helper (caller manages helper lifetime)
    /// </summary>
    class function CreateHTTPClient(const AClientConfig: TIAM4DClientConfig; const ASSLHelper: TIAM4DHTTPClientSSLHelper): THTTPClient; overload; static;

    /// <summary>
    /// Creates HTTP client with default configuration
    /// </summary>
    class function CreateHTTPClient: THTTPClient; overload; static;

    /// <summary>
    /// Performs idempotent GET request with retry/backoff (no retry on 4xx errors). Optional headers.
    /// </summary>
    /// <remarks>
    /// Each attempt goes through Execute. A timeout is not retried: it raises EIAM4DNetworkTimeoutException.
    /// A network error is retried, then raises EIAM4DNetworkUnreachableException. 429 and transient 5xx
    /// are retried; after the last attempt their response is returned (no exception).
    /// </remarks>
    class function GetWithRetry(
      const AClient: THTTPClient;
      const AUrl: string;
      const AHeaders: TNetHeaders;
      const AMaxRetries: Integer = 3
      ): IHTTPResponse; static;

    /// <summary>
    /// Performs POST request with application/x-www-form-urlencoded and retry/backoff (no retry on 4xx errors).
    /// </summary>
    /// <remarks>
    /// Each attempt goes through Execute. A timeout is not retried: it raises EIAM4DNetworkTimeoutException.
    /// A network error is retried, then raises EIAM4DNetworkUnreachableException. 429 and transient 5xx
    /// are retried; after the last attempt their response is returned (no exception).
    /// </remarks>
    class function PostFormUrlEncodedWithRetry(
      const AClient: THTTPClient;
      const AUrl: string;
      const AForm: TStrings;
      const AHeaders: TNetHeaders;
      const AMaxRetries: Integer = 3
      ): IHTTPResponse; static;

    class constructor Create;
    class destructor Destroy;
  end;

  /// <summary>
  /// User information from OIDC UserInfo endpoint.
  /// </summary>
  /// <remarks>
  /// Contains standard OIDC claims and custom claims from identity provider.
  /// RawJSON: Full JSON response for accessing custom claims.
  /// Memory: GetCustomClaims() returns dictionary - caller must free it.
  /// Standard claims: sub, preferred_username, name, given_name, family_name, email, etc.
  /// </remarks>
  TIAM4DUserInfo = record
  private
    FSub: string;
    FPreferredUsername: string;
    FName: string;
    FGivenName: string;
    FFamilyName: string;
    FEmail: string;
    FEmailVerified: Boolean;
    FPhoneNumber: string;
    FPhoneNumberVerified: Boolean;
    FPicture: string;
    FUpdatedAt: Int64;
    FRawJSON: string;
  public
    property Sub: string read FSub;
    property PreferredUsername: string read FPreferredUsername;
    property Name: string read FName;
    property GivenName: string read FGivenName;
    property FamilyName: string read FFamilyName;
    property Email: string read FEmail;
    property EmailVerified: Boolean read FEmailVerified;
    property PhoneNumber: string read FPhoneNumber;
    property PhoneNumberVerified: Boolean read FPhoneNumberVerified;
    property Picture: string read FPicture;
    property UpdatedAt: Int64 read FUpdatedAt;
    property RawJSON: string read FRawJSON;

    /// <summary>
    /// Gets all non-standard claims as dictionary
    /// </summary>
    function GetCustomClaims: TDictionary<string, string>;

    /// <summary>
    /// Gets specific custom claim value by name
    /// </summary>
    function GetCustomClaim(const AName: string): string;

    /// <summary>
    /// Parses user info from JSON response
    /// </summary>
    class function FromJSONObject(const AJSONObject: TJSONObject): TIAM4DUserInfo; static;
  end;

  /// <summary>
  /// Claims of the id_token of the session (IIAM4DClient.GetIDTokenClaims).
  /// </summary>
  /// <remarks>
  /// Read from the id_token stored after the login or the last refresh: it was validated then
  /// (signature, issuer, audience, nonce, times), it is not checked again here.
  /// Times are Unix seconds, 0 when the claim is absent. Empty record (IsEmpty) without an id_token.
  /// </remarks>
  TIAM4DIDTokenClaims = record
  private
    FJSON: string;
  public
    Subject: string;
    Issuer: string;
    Audience: TArray<string>;
    AuthorizedParty: string;
    /// <summary>acr: authentication context class reached (e.g. the level of acr_values)</summary>
    Acr: string;
    /// <summary>amr: authentication methods (RFC 8176, e.g. pwd, otp, hwk)</summary>
    Amr: TArray<string>;
    /// <summary>sid: Keycloak session</summary>
    SessionID: string;
    AuthTime: Int64;
    IssuedAt: Int64;
    ExpiresAt: Int64;
    PreferredUsername: string;
    Email: string;
    Name: string;

    /// <summary>Claims of the payload of AIDToken, not verified; empty for an empty token</summary>
    /// <exception cref="EIAM4DException">Not a JWS compact serialization with a JSON object payload</exception>
    class function FromIDToken(const AIDToken: string): TIAM4DIDTokenClaims; static;
    function IsEmpty: Boolean;
    function HasClaim(const AName: string): Boolean;
    /// <summary>String value of the claim, JSON text for another type, '' when absent</summary>
    function GetClaim(const AName: string): string;
    /// <summary>The payload as JSON text</summary>
    property JSON: string read FJSON;
  end;

  /// <summary>
  /// Options of one login (authorization request), on top of the configuration.
  /// </summary>
  /// <remarks>
  /// Empty fields keep the configuration: an empty Prompt or AcrValues sends the configured ones,
  /// MaxAge IAM4D_MAX_AGE_CONFIGURED (the default) the configured max_age. Use it to ask for a
  /// stronger or fresher authentication before a sensitive operation (WithAcrValues, WithMaxAge(0),
  /// WithPrompt(IAM4D_PROMPT_LOGIN)) without configuring another client.
  /// The With* methods validate their values (EArgumentException) and return a copy.
  /// A local declared without With* already has the defaults (class operator Initialize).
  /// </remarks>
  TIAM4DAuthRequestOptions = record
  private
    FLoginHint: string;
    FIdpHint: string;
    FAcrValues: TArray<string>;
    FPrompt: string;
    FMaxAge: Integer;
    FUILocales: TArray<string>;
    FParameterNames: TArray<string>;
    FParameterValues: TArray<string>;
    class procedure CheckTokens(const AValues: TArray<string>; const AWhat: string); static;
  public
    class operator Initialize(out ADest: TIAM4DAuthRequestOptions);

    /// <summary>Options that keep the whole configuration</summary>
    class function Create: TIAM4DAuthRequestOptions; static;

    /// <summary>
    /// True for the names the client sets itself or through a dedicated option (client_id,
    /// redirect_uri, state, nonce, PKCE, prompt, max_age...): not accepted by WithParameter
    /// </summary>
    class function IsReservedParameter(const AName: string): Boolean; static;

    /// <summary>login_hint: username or e-mail prefilled on the login page (empty: not sent)</summary>
    function WithLoginHint(const AValue: string): TIAM4DAuthRequestOptions;
    /// <summary>kc_idp_hint: empty keeps Config.IdpHint, IAM4D_IDP_HINT_NONE sends none</summary>
    function WithIdpHint(const AValue: string): TIAM4DAuthRequestOptions;
    /// <summary>acr_values of this login, in order of preference, instead of the configured ones</summary>
    function WithAcrValues(const AValues: TArray<string>): TIAM4DAuthRequestOptions;
    /// <summary>
    /// prompt: space-separated none, login, consent, select_account (none alone); empty keeps the
    /// configured one
    /// </summary>
    function WithPrompt(const AValue: string): TIAM4DAuthRequestOptions;
    /// <summary>
    /// max_age in seconds (0: authenticate again); IAM4D_MAX_AGE_NONE sends none, IAM4D_MAX_AGE_CONFIGURED
    /// keeps the configured one. auth_time of the id_token is checked against it
    /// </summary>
    function WithMaxAge(const ASeconds: Integer): TIAM4DAuthRequestOptions;
    /// <summary>ui_locales: BCP 47 language tags in order of preference (e.g. it, en)</summary>
    function WithUILocales(const ALocales: TArray<string>): TIAM4DAuthRequestOptions;
    /// <summary>
    /// Another parameter of the authorization request (e.g. a custom one read by a Keycloak
    /// authenticator). Name of letters, digits, '_', '-' and '.', not reserved in any case; names
    /// are case-sensitive: the same name again, with the same case, replaces its value
    /// </summary>
    function WithParameter(const AName, AValue: string): TIAM4DAuthRequestOptions;

    property LoginHint: string read FLoginHint;
    property IdpHint: string read FIdpHint;
    property AcrValues: TArray<string> read FAcrValues;
    property Prompt: string read FPrompt;
    property MaxAge: Integer read FMaxAge;
    property UILocales: TArray<string> read FUILocales;
    property ParameterNames: TArray<string> read FParameterNames;
    property ParameterValues: TArray<string> read FParameterValues;
  end;

  /// <summary>
  /// Main interface for OAuth2/OIDC client operations.
  /// </summary>
  /// <remarks>
  /// Supports Authorization Code (with PKCE), Client Credentials and Password flows.
  /// Async operations: All auth methods return IAsyncPromise for non-blocking execution.
  /// Thread-safety: Implementation-dependent - check specific implementation docs.
  /// Token management: Automatically refreshes access tokens when expired.
  /// Lifecycle: Call ConfigureAsync() first, then authentication methods.
  /// </remarks>
  IIAM4DClient = interface
    ['{195EEEDF-F456-4843-87C1-FC5F80A5442D}']

    /// <summary>
    /// Configures client with endpoints discovery
    /// </summary>
    function ConfigureAsync(const AConfig: TIAM4DClientConfig): IAsyncVoidPromise;

    /// <summary>
    /// Generates authorization URL for browser redirect
    /// </summary>
    /// <remarks>
    /// AIdpHint: alias of the Keycloak identity provider to log in with (kc_idp_hint);
    /// empty uses Config.IdpHint; IAM4D_IDP_HINT_NONE sends no hint (Keycloak login page).
    /// </remarks>
    function GenerateAuthURL(const ALoginHint: string = ''; const AIdpHint: string = ''): string; overload;

    /// <summary>
    /// Authorization URL with the options of this login (external callback: after
    /// InitializeAuthorizationFlow; its max_age replaces the one the flow was initialized with)
    /// </summary>
    function GenerateAuthURL(const AOptions: TIAM4DAuthRequestOptions): string; overload;

    /// <summary>
    /// Starts authorization flow (opens browser and waits for callback)
    /// </summary>
    /// <remarks>
    /// The flow waits until the browser redirects to the local callback server: if the user closes
    /// the browser it never ends by itself. Cancel on the operation returned by Run (or
    /// CancelAuthorizationFlow) ends it as cancelled: OnFinally runs, OnError does not.
    /// Cancel it and let OnFinally run before destroying the objects its callbacks use (e.g. the form).
    /// AIdpHint: alias of the Keycloak identity provider to log in with (kc_idp_hint): Keycloak
    /// redirects straight to it. Empty uses Config.IdpHint; both empty show the Keycloak login page.
    /// IAM4D_IDP_HINT_NONE shows the Keycloak login page even when Config.IdpHint is set.
    /// The browser is opened through TIAM4DPlatformUtils.OpenURL (OpenURLHandler replaces it).
    /// </remarks>
    function StartAuthorizationFlowAsync(const AIdpHint: string = ''): IAsyncPromise<string>; overload;

    /// <summary>
    /// Starts authorization flow with a login_hint (username or e-mail prefilled by Keycloak)
    /// </summary>
    /// <remarks>
    /// Same as StartAuthorizationFlowAsync(AIdpHint); ALoginHint empty sends no login_hint.
    /// </remarks>
    function StartAuthorizationFlowAsync(const AIdpHint, ALoginHint: string): IAsyncPromise<string>; overload;

    /// <summary>
    /// Starts authorization flow with the options of this login (acr_values, max_age, prompt,
    /// ui_locales, other parameters) on top of the configuration
    /// </summary>
    /// <remarks>
    /// E.g. a stronger authentication before a payment:
    /// StartAuthorizationFlowAsync(TIAM4DAuthRequestOptions.Create.WithAcrValues(['gold']).WithMaxAge(0)).
    /// The acr obtained is in GetIDTokenClaims.Acr: the application decides whether it is enough.
    /// </remarks>
    function StartAuthorizationFlowAsync(const AOptions: TIAM4DAuthRequestOptions): IAsyncPromise<string>; overload;

    /// <summary>
    /// Initializes authorization context without starting callback listener
    /// </summary>
    procedure InitializeAuthorizationFlow; overload;

    /// <summary>
    /// Same, with the options of this login: GenerateAuthURL without arguments then uses them
    /// </summary>
    procedure InitializeAuthorizationFlow(const AOptions: TIAM4DAuthRequestOptions); overload;

    /// <summary>
    /// Completes authorization flow with received code and state
    /// </summary>
    /// <remarks>
    /// AIss: the iss parameter of the redirect (RFC 9207), when present: one of another issuer is
    /// refused (mix-up attack). Pass it with more than one realm or identity provider on the same
    /// redirect URI.
    /// </remarks>
    function CompleteAuthorizationFlowAsync(const ACode, AState: string; const AIss: string = ''): IAsyncPromise<string>;

    /// <summary>
    /// Authenticates using Client Credentials flow
    /// </summary>
    function AuthenticateClientAsync: IAsyncPromise<string>;

    /// <summary>
    /// Authenticates using the Resource Owner Password Credentials flow
    /// </summary>
    function AuthenticatePasswordAsync(const AUserName, APassword: string): IAsyncPromise<string>;

    /// <summary>
    /// Gets valid access token (refreshes if expired)
    /// </summary>
    function GetAccessTokenAsync: IAsyncPromise<string>;

    /// <summary>
    /// Retrieves user info from OIDC UserInfo endpoint
    /// </summary>
    function GetUserInfoAsync: IAsyncPromise<TIAM4DUserInfo>;

    /// <summary>
    /// Logs out user and clears tokens
    /// </summary>
    function LogoutAsync: IAsyncVoidPromise;

    /// <summary>
    /// Revokes the tokens of this client (RFC 7009) and clears them
    /// </summary>
    function RevokeTokensAsync: IAsyncVoidPromise;

    // ========================================================================
    // Synchronous Operations
    // ========================================================================

    /// <summary>
    /// Gets valid access token synchronously (refreshes if expired).
    /// </summary>
    /// <returns>Valid access token string.</returns>
    /// <exception cref="EIAM4DRefreshTokenExpiredException">
    /// The refresh token has expired, or Keycloak refused it (invalid_grant: session closed,
    /// token revoked; Context['error_description'] has Keycloak's reason). The tokens are
    /// cleared: IsAuthenticated is False and a new login is needed.
    /// </exception>
    /// <exception cref="EIAM4DException">
    /// The refresh did not reach Keycloak or failed on its side (network error, timeout, 5xx):
    /// the tokens are kept, IsAuthenticated stays True and a later call can refresh them.
    /// </exception>
    /// <remarks>
    /// For Authorization Code and password grant: Automatically refreshes using refresh token.
    /// For Client Credentials flow: Automatically requests new token.
    /// </remarks>
    function GetAccessToken: string;

    /// <summary>
    /// Marks AAccessToken expired when it is still the stored one: the next GetAccessToken renews it.
    /// </summary>
    /// <remarks>
    /// For a resource server that answered 401 to a token not yet expired (revoked, signing keys
    /// rotated, clocks apart). Another token (renewed meanwhile by another thread, a new login) is
    /// left alone, so concurrent 401s renew once. The session and the refresh token are kept.
    /// TIAM4DAuthorizedHTTPClient calls it before its retry.
    /// </remarks>
    procedure InvalidateAccessToken(const AAccessToken: string);

    /// <summary>
    /// Authenticates using Client Credentials flow synchronously.
    /// </summary>
    /// <returns>Access token string.</returns>
    /// <exception cref="EIAM4DException">
    /// Raised when not configured for Client Credentials flow or on errors.
    /// </exception>
    function AuthenticateClient: string;

    /// <summary>
    /// Authenticates using the Resource Owner Password Credentials flow synchronously.
    /// </summary>
    /// <returns>Access token string.</returns>
    /// <exception cref="EIAM4DInvalidCredentialsException">Wrong username or password.</exception>
    /// <exception cref="EIAM4DAccountNotFullySetUpException">
    /// Right credentials, but a required action is pending (e.g. UPDATE_PASSWORD).
    /// </exception>
    /// <exception cref="EIAM4DAccountDisabledException">
    /// Account disabled (Keycloak tells it only for the right password). A user locked by the
    /// brute force detection gets EIAM4DInvalidCredentialsException: Keycloak 26 answers
    /// "Invalid user credentials" even for the right password.
    /// </exception>
    /// <exception cref="EIAM4DException">
    /// Not configured for the password grant, or another error of the token endpoint
    /// (e.g. "Direct access grants" disabled on the client).
    /// </exception>
    /// <remarks>
    /// The tokens are stored as for Authorization Code: GetAccessToken refreshes them and
    /// Logout ends the Keycloak session. A new login on a client with a session ends the
    /// previous Keycloak session first (errors ignored). The password is not kept: the
    /// request form is wiped after use.
    /// </remarks>
    function AuthenticatePassword(const AUserName, APassword: string): string;

    /// <summary>
    /// Completes Authorization Code flow with received code and state synchronously.
    /// </summary>
    /// <param name="ACode">Authorization code from callback.</param>
    /// <param name="AState">State parameter for CSRF validation.</param>
    /// <param name="AIss">iss parameter of the redirect (RFC 9207), '' when absent.</param>
    /// <returns>Access token string.</returns>
    /// <exception cref="EIAM4DStateMismatchException">
    /// Raised when state parameter does not match.
    /// </exception>
    /// <exception cref="EIAM4DCallbackHandlerException">
    /// Raised when AIss is not the issuer of this client.
    /// </exception>
    function CompleteAuthorizationFlow(const ACode, AState: string; const AIss: string = ''): string;

    /// <summary>
    /// Retrieves user info from OIDC UserInfo endpoint synchronously.
    /// </summary>
    /// <returns>User information record with standard OIDC claims.</returns>
    /// <exception cref="EIAM4DException">
    /// Raised when using Client Credentials flow (no user context).
    /// </exception>
    function GetUserInfo: TIAM4DUserInfo;

    /// <summary>
    /// Logs out user and clears tokens synchronously.
    /// </summary>
    /// <remarks>
    /// Authorization Code and password grant: back-channel POST of the refresh token to the end
    /// session endpoint. A session already closed or a refresh token Keycloak refuses is not an
    /// error; with a refresh token already expired no request is sent. The tokens are cleared
    /// and the configured scopes restored in every case, also when the request fails.
    /// </remarks>
    /// <exception cref="EIAM4DException">Keycloak could not be reached or answered an error (tokens cleared anyway)</exception>
    procedure Logout;

    /// <summary>
    /// Revokes the refresh token, then the access token, at the revocation endpoint (RFC 7009) and
    /// clears them.
    /// </summary>
    /// <remarks>
    /// Unlike Logout, which ends the whole user session, it ends only what this client holds: with
    /// Keycloak the session of this client (and the user session when no other client uses it).
    /// With an offline token (scope offline_access) both end its offline session. The revoked
    /// access token is refused by userinfo and introspection; a resource server validating the
    /// JWT locally accepts it until it expires.
    /// A token the server does not know is not an error (RFC 7009 2.2). The access token is revoked
    /// also when the revocation of the refresh token fails; the first error is raised. The tokens
    /// are cleared and the configured scopes restored once revocation is attempted, also when the
    /// requests fail.
    /// </remarks>
    /// <exception cref="EIAM4DException">
    /// No revocation endpoint in the discovery document (nothing sent, tokens kept: Logout can
    /// still end the session); Keycloak not reachable or an error answer (tokens cleared anyway)
    /// </exception>
    procedure RevokeTokens;

    /// <summary>
    /// URL of the end session endpoint for the browser (OpenID Connect RP-Initiated Logout)
    /// </summary>
    /// <remarks>
    /// For web applications: redirect the browser there to end the Keycloak session of its cookie,
    /// then Keycloak redirects to APostLogoutRedirectURI (registered in the client as a valid post
    /// logout redirect URI) with AState. Carries client_id and, while the tokens are stored, the
    /// id_token as id_token_hint: generate it before Logout or RevokeTokens.
    /// APostLogoutRedirectURI: HTTP(S); plain HTTP to a host other than the loopback only with
    /// AllowInsecureHTTP.
    /// </remarks>
    /// <exception cref="EIAM4DException">No end session endpoint in the discovery document</exception>
    function GenerateLogoutURL(const APostLogoutRedirectURI: string = ''; const AState: string = ''): string;

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /// <summary>
    /// Cancels ongoing authorization flow
    /// </summary>
    /// <remarks>
    /// Stops the local callback server; the pending operation ends as cancelled (OnFinally, no OnError).
    /// </remarks>
    procedure CancelAuthorizationFlow;

    /// <summary>
    /// Gets OIDC issuer URL
    /// </summary>
    function GetIssuer: string;

    /// <summary>
    /// Gets JWKS URI for token validation
    /// </summary>
    function GetJWKSUri: string;

    /// <summary>
    /// Checks if user is authenticated with valid tokens
    /// </summary>
    function GetIsAuthenticated: Boolean;

    /// <summary>
    /// Gets OAuth2 redirect URI for current flow
    /// </summary>
    function GetRedirectURI: string;

    /// <summary>
    /// kc_action_status of the last authorization flow completed through the local callback server
    /// </summary>
    /// <remarks>
    /// With Config.KeycloakAction: IAM4D_KC_ACTION_STATUS_SUCCESS, IAM4D_KC_ACTION_STATUS_CANCELLED or
    /// IAM4D_KC_ACTION_STATUS_ERROR. Keycloak returns a code even when the user cancels the action, so
    /// the flow succeeds and only this value tells the outcome. Empty when Keycloak sent none (no
    /// kc_action) and while a flow is running. External callback mode: read kc_action_status from
    /// the callback URL.
    /// Not signed by Keycloak and not in any token: it is the redirect URL parameter. It is stored
    /// only with a code that passed the state check and the PKCE exchange, so no other site can
    /// forge it, but whoever controls the browser (the user) can change it. Treat it as the
    /// user's report: a decision that matters must be checked on the server (Admin API).
    /// </remarks>
    function GetKeycloakActionStatus: string;

    /// <summary>
    /// Claims of the id_token of the session (acr, amr, auth_time, sid...); empty without one
    /// (not authenticated, Client Credentials)
    /// </summary>
    /// <remarks>
    /// E.g. after a login with acr_values: GetIDTokenClaims.Acr tells the level reached, the
    /// application decides whether it is enough for the operation.
    /// </remarks>
    function GetIDTokenClaims: TIAM4DIDTokenClaims;

    /// <summary>
    /// Scopes granted to the stored tokens (scope of the token response, RFC 6749 5.1); the requested
    /// ones when the server sent none; empty when not authenticated
    /// </summary>
    /// <remarks>
    /// The authorization server may grant fewer scopes than requested (user consent, client policy):
    /// check them before calling an API that needs one.
    /// </remarks>
    function GetGrantedScopes: TArray<string>;

    /// <summary>True when AScope is granted (case-sensitive, RFC 6749 3.3)</summary>
    function HasGrantedScope(const AScope: string): Boolean;

    property Issuer: string read GetIssuer;
    property JWKSUri: string read GetJWKSUri;
    property IsAuthenticated: Boolean read GetIsAuthenticated;
    property RedirectURI: string read GetRedirectURI;
    property KeycloakActionStatus: string read GetKeycloakActionStatus;

    /// <summary>
    /// Creates HTTP client with same SSL configuration
    /// </summary>
    function CreateHTTPClient: THTTPClient;

    /// <summary>
    /// Adds public key hashes for certificate pinning
    /// </summary>
    procedure AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);

    /// <summary>
    /// Clears all pinned public keys
    /// </summary>
    procedure ClearPinnedPublicKeys;
  end;

implementation

{TIAM4DTokens}

uses
  {$IFDEF MSWINDOWS}
  Winapi.Windows,
  {$ENDIF}
  System.DateUtils,
  System.NetEncoding,
  System.Math,
  IAMClient4D.Common.Constants,
  IAMClient4D.Common.TokenSerializer;

{ TIAM4DIDTokenClaims }

class function TIAM4DIDTokenClaims.FromIDToken(const AIDToken: string): TIAM4DIDTokenClaims;
var
  LParts: TArray<string>;
  LPayload: TJSONValue;
  LObj: TJSONObject;

  function Str(const AName: string): string;
  begin
    Result := LObj.GetValue<string>(AName, '');
  end;

  function Num(const AName: string): Int64;
  var
    LNumber: TJSONValue;
    LValue: Double;
  begin
    // NumericDate: a JSON number, also with a fraction or an exponent (the validation accepts them)
    Result := 0;
    LNumber := LObj.Values[AName];
    if LNumber is TJSONNumber then
    begin
      LValue := TJSONNumber(LNumber).AsDouble;
      if (LValue >= 0) and (LValue < 1E15) then
        Result := Trunc(LValue);
    end;
  end;

  function StrArray(const AName: string): TArray<string>;
  var
    LValue, LItem: TJSONValue;
  begin
    Result := nil;
    LValue := LObj.Values[AName];
    if LValue is TJSONString then
      Result := [TJSONString(LValue).Value]
    else if LValue is TJSONArray then
      for LItem in TJSONArray(LValue) do
        if LItem is TJSONString then
          Result := Result + [TJSONString(LItem).Value];
  end;

begin
  Result := Default(TIAM4DIDTokenClaims);
  if AIDToken.Trim.IsEmpty then
    Exit;
  LParts := AIDToken.Trim.Split(['.']);
  if Length(LParts) <> 3 then
    raise EIAM4DException.Create('id_token is not a JWS compact serialization');
  try
    LPayload := TJSONObject.ParseJSONValue(TEncoding.UTF8.GetString(
      TNetEncoding.Base64URL.DecodeStringToBytes(LParts[1])));
  except
    on E: Exception do
      raise EIAM4DException.CreateFmt('id_token payload cannot be decoded: %s', [E.Message]);
  end;
  try
    if not (LPayload is TJSONObject) then
      raise EIAM4DException.Create('id_token payload is not a JSON object');
    LObj := TJSONObject(LPayload);
    Result.FJSON := LObj.ToJSON;
    Result.Subject := Str('sub');
    Result.Issuer := Str('iss');
    Result.Audience := StrArray('aud');
    Result.AuthorizedParty := Str('azp');
    Result.Acr := Str('acr');
    Result.Amr := StrArray('amr');
    Result.SessionID := Str('sid');
    Result.AuthTime := Num('auth_time');
    Result.IssuedAt := Num('iat');
    Result.ExpiresAt := Num('exp');
    Result.PreferredUsername := Str('preferred_username');
    Result.Email := Str('email');
    Result.Name := Str('name');
  finally
    LPayload.Free;
  end;
end;

function TIAM4DIDTokenClaims.IsEmpty: Boolean;
begin
  Result := FJSON.IsEmpty;
end;

function TIAM4DIDTokenClaims.HasClaim(const AName: string): Boolean;
var
  LObj: TJSONValue;
begin
  if FJSON.IsEmpty then
    Exit(False);
  LObj := TJSONObject.ParseJSONValue(FJSON);
  try
    Result := (LObj is TJSONObject) and Assigned(TJSONObject(LObj).Values[AName]);
  finally
    LObj.Free;
  end;
end;

function TIAM4DIDTokenClaims.GetClaim(const AName: string): string;
var
  LObj, LValue: TJSONValue;
begin
  Result := '';
  if FJSON.IsEmpty then
    Exit;
  LObj := TJSONObject.ParseJSONValue(FJSON);
  try
    if not (LObj is TJSONObject) then
      Exit;
    LValue := TJSONObject(LObj).Values[AName];
    if LValue is TJSONString then
      Result := TJSONString(LValue).Value
    else if Assigned(LValue) then
      Result := LValue.ToJSON;
  finally
    LObj.Free;
  end;
end;

class function TIAM4DTokens.FromJSONObject(const AJSONObject: TJSONObject): TIAM4DTokens;
begin
  Result := TIAM4DTokenSerializer.FromJSONObject(AJSONObject);
end;

class function TIAM4DTokens.ToJSONObject(const ATokens: TIAM4DTokens): TJSONObject;
begin
  Result := TIAM4DTokenSerializer.ToJSONObject(ATokens);
end;

{TIAM4DWellKnownEndpoints}

class function TIAM4DWellKnownEndpoints.FromJSONObject(const AJSONObject: TJSONObject): TIAM4DWellKnownEndpoints;
begin
  Result.AuthorizationEndpoint := AJSONObject.GetValue<string>(IAM4D_OIDC_METADATA_AUTHORIZATION_ENDPOINT, '');
  Result.TokenEndpoint := AJSONObject.GetValue<string>(IAM4D_OIDC_METADATA_TOKEN_ENDPOINT, '');
  Result.UserInfoEndpoint := AJSONObject.GetValue<string>(IAM4D_OIDC_METADATA_USERINFO_ENDPOINT, '');
  Result.EndSessionEndpoint := AJSONObject.GetValue<string>(IAM4D_OIDC_METADATA_END_SESSION_ENDPOINT, '');
  Result.RevocationEndpoint := AJSONObject.GetValue<string>(IAM4D_OIDC_METADATA_REVOCATION_ENDPOINT, '');
  Result.JWKSUri := AJSONObject.GetValue<string>(IAM4D_OIDC_METADATA_JWKS_URI, '');
  Result.Issuer := AJSONObject.GetValue<string>(IAM4D_OIDC_METADATA_ISSUER, '');
  Result.AuthorizationResponseIssParameterSupported :=
    AJSONObject.GetValue<Boolean>(IAM4D_OIDC_METADATA_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED, False);
end;

{TIAM4DClientConfig}

class function TIAM4DClientConfig.Create(
  const ABaseURL, ARealm, AClientID: string;
  const AGrantType: TIAM4DGrantType;
  const AScopes: TArray<string>;
  const AClientSecret: string;
  const ASSLValidationMode: TIAM4DSSLValidationMode;
  const AConnectionTimeout: Integer;
  const AResponseTimeout: Integer;
  const AExternalCallbackURL: string;
  const ATokenExpiryBufferSeconds: Integer;
  const AAcrValues: TArray<string>;
  const AIdpHint: string): TIAM4DClientConfig;
begin
  if ABaseURL.Trim.IsEmpty then
    raise EArgumentException.Create('BaseURL cannot be empty.');
  if ARealm.Trim.IsEmpty then
    raise EArgumentException.Create('Realm cannot be empty.');
  if AClientID.Trim.IsEmpty then
    raise EArgumentException.Create('ClientID cannot be empty.');

  if (AGrantType = gtClientCredentials) and (AClientSecret.Trim.IsEmpty) then
    raise EArgumentException.Create('ClientSecret is required for Client Credentials grant type.');

  if ATokenExpiryBufferSeconds < 0 then
    raise EArgumentException.Create('TokenExpiryBufferSeconds cannot be negative.');

  Result.FBaseURL := ABaseURL;
  Result.FRealm := ARealm;
  Result.FClientID := AClientID;
  Result.FClientSecret := AClientSecret;
  Result.FScopes := Copy(AScopes);
  Result.FGrantType := AGrantType;
  Result.FSSLValidationMode := ASSLValidationMode;
  Result.FConnectionTimeout := AConnectionTimeout;
  Result.FResponseTimeout := AResponseTimeout;
  Result.FExternalCallbackURL := AExternalCallbackURL;
  Result.FTokenExpiryBufferSeconds := ATokenExpiryBufferSeconds;
  Result.FAcrValues := Copy(AAcrValues);
  Result.FIdpHint := AIdpHint.Trim;
  Result.FPrompt := '';
  Result.FMaxAge := IAM4D_MAX_AGE_NONE;
  Result.FKeycloakAction := '';
  Result.FCallbackPort := 0;
  Result.FAppActivation := aaNone;
  Result.FLoopbackRedirectHost := lrhLocalhost;
  Result.FAllowInsecureHTTP := False;
end;

class function TIAM4DClientConfig.CreateForPassword(
  const ABaseURL, ARealm, AClientID: string;
  const AClientSecret: string;
  const AScopes: TArray<string>;
  const ASSLValidationMode: TIAM4DSSLValidationMode;
  const AConnectionTimeout: Integer;
  const AResponseTimeout: Integer;
  const ATokenExpiryBufferSeconds: Integer): TIAM4DClientConfig;
begin
  Result := Create(
    ABaseURL,
    ARealm,
    AClientID,
    gtPassword,
    AScopes,
    AClientSecret,
    ASSLValidationMode,
    AConnectionTimeout,
    AResponseTimeout,
    EmptyStr, // no callback
    ATokenExpiryBufferSeconds,
    nil); // ACR values need the authorization endpoint
end;

{ TIAM4DAuthRequestOptions }

class operator TIAM4DAuthRequestOptions.Initialize(out ADest: TIAM4DAuthRequestOptions);
begin
  ADest.FLoginHint := '';
  ADest.FIdpHint := '';
  ADest.FAcrValues := nil;
  ADest.FPrompt := '';
  ADest.FMaxAge := IAM4D_MAX_AGE_CONFIGURED;
  ADest.FUILocales := nil;
  ADest.FParameterNames := nil;
  ADest.FParameterValues := nil;
end;

class function TIAM4DAuthRequestOptions.Create: TIAM4DAuthRequestOptions;
begin
  // Every field set here: Result may be the destination of the call (e.g. a field), with the
  // values of the earlier options
  Result.FLoginHint := '';
  Result.FIdpHint := '';
  Result.FAcrValues := nil;
  Result.FPrompt := '';
  Result.FMaxAge := IAM4D_MAX_AGE_CONFIGURED;
  Result.FUILocales := nil;
  Result.FParameterNames := nil;
  Result.FParameterValues := nil;
end;

class procedure TIAM4DAuthRequestOptions.CheckTokens(const AValues: TArray<string>; const AWhat: string);
var
  LValue: string;
  LChar: Char;
begin
  // Space-separated lists in the request: a value with a space would become two
  for LValue in AValues do
  begin
    if LValue.Trim.IsEmpty then
      raise EArgumentException.CreateFmt('%s: empty value', [AWhat]);
    for LChar in LValue do
      if (LChar <= ' ') or (LChar = #$7F) then
        raise EArgumentException.CreateFmt('%s: "%s" has a space or a control character', [AWhat, LValue]);
  end;
end;

class function TIAM4DAuthRequestOptions.IsReservedParameter(const AName: string): Boolean;
const
  RESERVED: array[0..18] of string = ('response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce',
    'code_challenge', 'code_challenge_method', 'login_hint', 'kc_idp_hint', 'acr_values', 'prompt', 'max_age',
    'ui_locales', 'kc_action', 'response_mode', 'request', 'request_uri', 'client_secret');
var
  LName: string;
begin
  // Case-insensitive: a server may read Client_ID as client_id
  for LName in RESERVED do
    if SameText(LName, AName.Trim) then
      Exit(True);
  Result := False;
end;

function TIAM4DAuthRequestOptions.WithLoginHint(const AValue: string): TIAM4DAuthRequestOptions;
begin
  Result := Self;
  Result.FLoginHint := AValue.Trim;
end;

function TIAM4DAuthRequestOptions.WithIdpHint(const AValue: string): TIAM4DAuthRequestOptions;
begin
  Result := Self;
  Result.FIdpHint := AValue.Trim;
end;

function TIAM4DAuthRequestOptions.WithAcrValues(const AValues: TArray<string>): TIAM4DAuthRequestOptions;
begin
  CheckTokens(AValues, 'acr_values');
  Result := Self;
  Result.FAcrValues := Copy(AValues);
end;

function TIAM4DAuthRequestOptions.WithPrompt(const AValue: string): TIAM4DAuthRequestOptions;
var
  LValues: TArray<string>;
  LValue: string;
begin
  // OIDC Core 3.1.2.1: none, login, consent, select_account; none with another value is an error
  LValues := AValue.Trim.Split([' '], TStringSplitOptions.ExcludeEmpty);
  for LValue in LValues do
    if not ((LValue = IAM4D_PROMPT_NONE) or (LValue = IAM4D_PROMPT_LOGIN) or (LValue = IAM4D_PROMPT_CONSENT) or
      (LValue = IAM4D_PROMPT_SELECT_ACCOUNT)) then
      raise EArgumentException.CreateFmt('prompt: "%s" is not none, login, consent or select_account', [LValue]);
  if (Length(LValues) > 1) and (string.Join(' ', LValues) + ' ').Contains(IAM4D_PROMPT_NONE + ' ') then
    raise EArgumentException.Create('prompt: none cannot be combined with other values');
  Result := Self;
  Result.FPrompt := string.Join(' ', LValues);
end;

function TIAM4DAuthRequestOptions.WithMaxAge(const ASeconds: Integer): TIAM4DAuthRequestOptions;
begin
  if ASeconds < IAM4D_MAX_AGE_CONFIGURED then
    raise EArgumentException.Create('max_age cannot be negative (IAM4D_MAX_AGE_NONE: not sent, ' +
      'IAM4D_MAX_AGE_CONFIGURED: the configured one).');
  Result := Self;
  Result.FMaxAge := ASeconds;
end;

function TIAM4DAuthRequestOptions.WithUILocales(const ALocales: TArray<string>): TIAM4DAuthRequestOptions;
begin
  CheckTokens(ALocales, 'ui_locales');
  Result := Self;
  Result.FUILocales := Copy(ALocales);
end;

function TIAM4DAuthRequestOptions.WithParameter(const AName, AValue: string): TIAM4DAuthRequestOptions;
var
  LName: string;
  LChar: Char;
  LIndex: Integer;
begin
  LName := AName.Trim;
  if LName.IsEmpty then
    raise EArgumentException.Create('Parameter name cannot be empty');
  for LChar in LName do
    if not CharInSet(LChar, ['A'..'Z', 'a'..'z', '0'..'9', '_', '-', '.']) then
      raise EArgumentException.CreateFmt('Parameter name "%s": only letters, digits, "_", "-" and "."', [LName]);
  if IsReservedParameter(LName) then
    raise EArgumentException.CreateFmt('Parameter "%s" is set by the client or by a dedicated option', [LName]);
  Result := Self;
  Result.FParameterNames := Copy(FParameterNames);
  Result.FParameterValues := Copy(FParameterValues);
  for LIndex := 0 to High(Result.FParameterNames) do
    if Result.FParameterNames[LIndex] = LName then
    begin
      Result.FParameterValues[LIndex] := AValue;
      Exit;
    end;
  Result.FParameterNames := Result.FParameterNames + [LName];
  Result.FParameterValues := Result.FParameterValues + [AValue];
end;

function TIAM4DClientConfig.WithAuthRequestOptions(const APrompt: string;
  const AMaxAge: Integer): TIAM4DClientConfig;
begin
  if AMaxAge < IAM4D_MAX_AGE_NONE then
    raise EArgumentException.Create('MaxAge cannot be negative (IAM4D_MAX_AGE_NONE: not sent).');

  Result := Self;
  Result.FPrompt := APrompt.Trim;
  Result.FMaxAge := AMaxAge;
end;

function TIAM4DClientConfig.WithKeycloakAction(const AAction: string): TIAM4DClientConfig;
begin
  Result := Self;
  Result.FKeycloakAction := AAction.Trim;
end;

function TIAM4DClientConfig.WithCallbackPort(const APort: Integer): TIAM4DClientConfig;
begin
  if (APort < 0) or (APort > 65535) then
    raise EArgumentOutOfRangeException.Create('CallbackPort must be between 0 and 65535.');

  Result := Self;
  Result.FCallbackPort := APort;
end;

function TIAM4DClientConfig.WithAppActivation(const AValue: TIAM4DAppActivation): TIAM4DClientConfig;
begin
  Result := Self;
  Result.FAppActivation := AValue;
end;

function TIAM4DClientConfig.WithLoopbackRedirectHost(const AValue: TIAM4DLoopbackRedirectHost): TIAM4DClientConfig;
begin
  Result := Self;
  Result.FLoopbackRedirectHost := AValue;
end;

function TIAM4DClientConfig.WithAllowInsecureHTTP(const AValue: Boolean): TIAM4DClientConfig;
begin
  Result := Self;
  Result.FAllowInsecureHTTP := AValue;
end;

class function TIAM4DClientConfig.IsInsecureHTTPURL(const AURL: string): Boolean;

  // 127.0.0.0/8 as an IPv4 literal (a name such as 127.0.0.1.example.com is not the loopback)
  function IsLoopbackIPv4(const AHost: string): Boolean;
  var
    LParts: TArray<string>;
    LOctet: Integer;
  begin
    LParts := AHost.Split(['.']);
    if (Length(LParts) <> 4) or (LParts[0] <> '127') then
      Exit(False);
    for var LPart in LParts do
      if (LPart = '') or (LPart.Length > 3) or not TryStrToInt(LPart, LOctet) or (LOctet < 0) or
        (LOctet > 255) or not CharInSet(LPart[1], ['0'..'9']) then
        Exit(False);
    Result := True;
  end;

var
  LURI: TURI;
  LHost: string;
begin
  if not AURL.Trim.ToLower.StartsWith('http://') then
    Exit(False);
  try
    LURI := TURI.Create(AURL.Trim);
    LHost := LURI.Host.ToLower;
  except
    // Not parsable: not the loopback
    Exit(True);
  end;
  if LHost.StartsWith('[') and LHost.EndsWith(']') then
    LHost := LHost.Substring(1, LHost.Length - 2);
  Result := not ((LHost = 'localhost') or IsLoopbackIPv4(LHost) or (LHost = '::1'));
end;

class function TIAM4DClientConfig.CreateForAuthorizationCode(
  const ABaseURL, ARealm, AClientID: string;
  const AScopes: TArray<string>;
  const ASSLValidationMode: TIAM4DSSLValidationMode;
  const AConnectionTimeout: Integer;
  const AResponseTimeout: Integer;
  const AExternalCallbackURL: string;
  const ATokenExpiryBufferSeconds: Integer;
  const AAcrValues: TArray<string>;
  const AIdpHint: string): TIAM4DClientConfig;
begin
  Result := Create(
    ABaseURL,
    ARealm,
    AClientID,
    gtAuthorizationCode,
    AScopes,
    EmptyStr, // no secret
    ASSLValidationMode,
    AConnectionTimeout,
    AResponseTimeout,
    AExternalCallbackURL,
    ATokenExpiryBufferSeconds,
    AAcrValues,
    AIdpHint);
end;

class function TIAM4DClientConfig.CreateForClientCredentials(
  const ABaseURL, ARealm, AClientID, AClientSecret: string;
  const AScopes: TArray<string>;
  const ASSLValidationMode: TIAM4DSSLValidationMode;
  const AConnectionTimeout: Integer;
  const AResponseTimeout: Integer;
  const ATokenExpiryBufferSeconds: Integer): TIAM4DClientConfig;
begin
  Result := Create(
    ABaseURL,
    ARealm,
    AClientID,
    gtClientCredentials,
    AScopes,
    AClientSecret,
    ASSLValidationMode,
    AConnectionTimeout,
    AResponseTimeout,
    EmptyStr, // no external callback URL
    ATokenExpiryBufferSeconds,
    nil); // ACR values not applicable for Client Credentials
end;

{TIAM4DUserInfo}

class function TIAM4DUserInfo.FromJSONObject(const AJSONObject: TJSONObject): TIAM4DUserInfo;
begin
  Result.FRawJSON := AJSONObject.ToString;

  Result.FSub := AJSONObject.GetValue<string>('sub', '');
  Result.FPreferredUsername := AJSONObject.GetValue<string>('preferred_username', '');
  Result.FName := AJSONObject.GetValue<string>('name', '');
  Result.FGivenName := AJSONObject.GetValue<string>('given_name', '');
  Result.FFamilyName := AJSONObject.GetValue<string>('family_name', '');
  Result.FEmail := AJSONObject.GetValue<string>('email', '');
  Result.FEmailVerified := AJSONObject.GetValue<Boolean>('email_verified', False);
  Result.FPhoneNumber := AJSONObject.GetValue<string>('phone_number', '');
  Result.FPhoneNumberVerified := AJSONObject.GetValue<Boolean>('phone_number_verified', False);
  Result.FPicture := AJSONObject.GetValue<string>('picture', '');
  Result.FUpdatedAt := AJSONObject.GetValue<Int64>('updated_at', 0);
end;

function TIAM4DUserInfo.GetCustomClaims: TDictionary<string, string>;
const
  STANDARD_CLAIMS: array[0..10] of string = (
    'sub', 'preferred_username', 'name', 'given_name', 'family_name',
    'email', 'email_verified', 'phone_number', 'phone_number_verified',
    'picture', 'updated_at');
var
  LJSONObj: TJSONObject;
  LPair: TJSONPair;
  LIsStandard: Boolean;
  LStandardClaim: string;
begin
  Result := TDictionary<string, string>.Create;
  try
    if not TIAM4DJSONUtils.TryParseJSONObject(FRawJSON, LJSONObj) then
      Exit;

    try
      for LPair in LJSONObj do
      begin
        LIsStandard := False;
        for LStandardClaim in STANDARD_CLAIMS do
        begin
          // Claim names are case-sensitive (RFC 7519 4)
          if LPair.JsonString.Value = LStandardClaim then
          begin
            LIsStandard := True;
            Break;
          end;
        end;

        if not LIsStandard then
        begin
          Result.Add(LPair.JsonString.Value, LPair.JsonValue.Value);
        end;
      end;
    finally
      LJSONObj.Free;
    end;
  except
    Result.Free;
    raise;
  end;
end;

function TIAM4DUserInfo.GetCustomClaim(const AName: string): string;
var
  LJSONObj: TJSONObject;
begin
  Result := EmptyStr;

  if not TIAM4DJSONUtils.TryParseJSONObject(FRawJSON, LJSONObj) then
    Exit;

  try
    Result := LJSONObj.GetValue<string>(AName, '');
  finally
    LJSONObj.Free;
  end;
end;

{ TIAM4DHTTPClientConfig }

class function TIAM4DHTTPClientConfig.Default: TIAM4DHTTPClientConfig;
begin
  Result := Create(30000, 60000, svmStrict);
end;

class function TIAM4DHTTPClientConfig.FromClientConfig(
  const AClientConfig: TIAM4DClientConfig): TIAM4DHTTPClientConfig;
begin
  Result.FConnectionTimeout := AClientConfig.ConnectionTimeout;
  Result.FResponseTimeout := AClientConfig.ResponseTimeout;
  Result.FSSLValidationMode := AClientConfig.SSLValidationMode;
end;

class function TIAM4DHTTPClientConfig.Create(
  const AConnectionTimeout: Integer;
  const AResponseTimeout: Integer;
  const ASSLValidationMode: TIAM4DSSLValidationMode): TIAM4DHTTPClientConfig;
begin
  Result.FConnectionTimeout := AConnectionTimeout;
  Result.FResponseTimeout := AResponseTimeout;
  Result.FSSLValidationMode := ASSLValidationMode;
end;

{ TIAM4DHTTPClientSSLHelper }

constructor TIAM4DHTTPClientSSLHelper.Create(const ASSLValidator: IIAM4DSSLCertificateValidator);
begin
  inherited Create;
  FSSLValidator := ASSLValidator;
end;

procedure TIAM4DHTTPClientSSLHelper.ValidateServerCertificate(
  const Sender: TObject;
  const ARequest: TURLRequest;
  const Certificate: TCertificate;
  var Accepted: Boolean);
begin
  Accepted := FSSLValidator.ValidateCertificate(Certificate, Accepted);
end;

procedure TIAM4DHTTPClientSSLHelper.KeepPlatformVerdict(
  const Sender: TObject;
  const ARequest: TURLRequest;
  const Certificate: TCertificate;
  var Accepted: Boolean);
begin
  // Accepted already holds the platform verdict: assigning the handler is what makes it count
end;

class function TIAM4DHTTPClientSSLHelper.IsCallbackNeeded(AMode: TIAM4DSSLValidationMode;
  const AValidator: IIAM4DSSLCertificateValidator): Boolean;
begin
{$IFDEF ANDROID}
  // Without a callback the Android THTTPClient ignores a refused chain or date (see the remarks)
  Result := True;
{$ELSE}
  Result := (AMode = svmAllowSelfSigned) or AValidator.HasPinnedPublicKeys;
{$ENDIF}
end;

{ TIAM4DHTTPClientFactory }

class constructor TIAM4DHTTPClientFactory.Create;
begin
  // Used only by the clients in svmAllowSelfSigned (strict clients have no callback): its mode is
  // set once, a client being configured cannot change it under another one validating
  FSSLValidator := TIAM4DSSLCertificateValidator.Create;
  FSSLValidator.SetValidationMode(svmAllowSelfSigned);
  FSSLHelper := TIAM4DHTTPClientSSLHelper.Create(FSSLValidator);
end;

class destructor TIAM4DHTTPClientFactory.Destroy;
begin
  FreeAndNil(FSSLHelper);
  FSSLValidator := nil;
end;

class procedure TIAM4DHTTPClientFactory.ConfigureSSLValidation(
  const AHTTPClient: THTTPClient;
  const AConfig: TIAM4DHTTPClientConfig);
begin
  case AConfig.SSLValidationMode of
    svmStrict:
{$IFDEF ANDROID}
      // The validator of FSSLHelper is in self-signed mode: only the platform verdict here
      AHTTPClient.OnValidateServerCertificate := FSSLHelper.KeepPlatformVerdict;
{$ELSE}
      AHTTPClient.OnValidateServerCertificate := nil;
{$ENDIF}
    svmAllowSelfSigned:
      AHTTPClient.OnValidateServerCertificate := FSSLHelper.ValidateServerCertificate;
  end;
end;

class procedure TIAM4DHTTPClientFactory.ConfigureSSLValidationWithHelper(
  const AHTTPClient: THTTPClient;
  const AConfig: TIAM4DHTTPClientConfig;
  const ASSLHelper: TIAM4DHTTPClientSSLHelper);
begin
  if TIAM4DHTTPClientSSLHelper.IsCallbackNeeded(AConfig.SSLValidationMode, ASSLHelper.SSLValidator) then
    AHTTPClient.OnValidateServerCertificate := ASSLHelper.ValidateServerCertificate
  else
    AHTTPClient.OnValidateServerCertificate := nil;
end;

class function TIAM4DHTTPClientFactory.NewHTTPClient(const AConfig: TIAM4DHTTPClientConfig): THTTPClient;
begin
  Result := THTTPClient.Create;
  try
    Result.ConnectionTimeout := AConfig.ConnectionTimeout;
    Result.ResponseTimeout := AConfig.ResponseTimeout;
    // The requests already use ResponseTimeout for sending: the client says so too (it kept 60 s)
    Result.SendTimeout := AConfig.ResponseTimeout;
    Result.UserAgent := 'IAMClient4D/' + IAM4D_VERSION;
    // Keycloak's back-channel endpoints never redirect. A followed 3xx could go to http:// or to
    // another host, with the Authorization header, the form body (307/308) and no pin check
    Result.HandleRedirects := False;
  except
    Result.Free;
    raise;
  end;
end;

class function TIAM4DHTTPClientFactory.CreateHTTPClient(
  const AConfig: TIAM4DHTTPClientConfig): THTTPClient;
begin
  Result := NewHTTPClient(AConfig);
  try
    ConfigureSSLValidation(Result, AConfig);
  except
    Result.Free;
    raise;
  end;
end;

class function TIAM4DHTTPClientFactory.CreateHTTPClient(
  const AClientConfig: TIAM4DClientConfig): THTTPClient;
var
  LConfig: TIAM4DHTTPClientConfig;
begin
  LConfig := TIAM4DHTTPClientConfig.FromClientConfig(AClientConfig);
  Result := CreateHTTPClient(LConfig);
end;

class function TIAM4DHTTPClientFactory.CreateHTTPClient(
  const AClientConfig: TIAM4DClientConfig;
  const ASSLHelper: TIAM4DHTTPClientSSLHelper): THTTPClient;
var
  LConfig: TIAM4DHTTPClientConfig;
begin
  LConfig := TIAM4DHTTPClientConfig.FromClientConfig(AClientConfig);

  Result := NewHTTPClient(LConfig);
  try
    ConfigureSSLValidationWithHelper(Result, LConfig, ASSLHelper);
  except
    Result.Free;
    raise;
  end;
end;

class function TIAM4DHTTPClientFactory.CreateHTTPClient: THTTPClient;
var
  LConfig: TIAM4DHTTPClientConfig;
begin
  LConfig := TIAM4DHTTPClientConfig.Default;
  Result := CreateHTTPClient(LConfig);
end;

{$IFDEF MSWINDOWS}
type
  /// <summary>Deadline of one request, shared with its timer-queue timer.</summary>
  TIAM4DRequestDeadline = record
    Request: IHTTPRequest;
    Expired: Boolean;
  end;
  PIAM4DRequestDeadline = ^TIAM4DRequestDeadline;

procedure RequestDeadlineExpired(AContext: Pointer; ATimerOrWaitFired: Boolean); stdcall;
begin
  try
    PIAM4DRequestDeadline(AContext).Expired := True;
    // As IAsyncResult.Cancel does: closes the WinHTTP request handle, the waiting call returns at once
    PIAM4DRequestDeadline(AContext).Request.Cancel;
  except
    // System thread: nothing may escape
  end;
end;
{$ENDIF}

// Android raises ENetHTTPCertificateException for every failed connect (System.Net.HttpClient.Android):
// a certificate error only when it recorded a TLS failure reason (javax.net.ssl.*,
// java.security.cert.*, certificate not accepted); a refused connection or an unknown host is a
// network error. Without TLS there is no certificate at all
function IsCertificateFailure(AClient: THTTPClient; E: ENetException; const AURL: string): Boolean;
begin
  Result := (E is ENetHTTPCertificateException) and not AURL.StartsWith('http:', True);
{$IFDEF ANDROID}
  if Result then
    Result := AClient.SecureFailureReasons <> [];
{$ENDIF}
end;

function HostOfURL(const AURL: string): string;
begin
  try
    Result := TURI.Create(AURL).Host;
  except
    Result := AURL;
  end;
end;

class function TIAM4DHTTPClientFactory.Execute(
  const AClient: THTTPClient;
  const AMethod, AURL: string;
  const ASource: TStream;
  const AHeaders: TNetHeaders): IHTTPResponse;
const
  // Platform timers are a few ms coarse: libcurl may report its timeout just before the full time
  DEADLINE_SLACK_MS = 50;
var
  LRequest: IHTTPRequest;
  LTimeoutMs: Integer;
  LStart: UInt64;
  LExpired: Boolean;
  LCertificateError: Boolean;
{$IFDEF MSWINDOWS}
  LDeadline: TIAM4DRequestDeadline;
  LTimer: THandle;
{$ENDIF}
begin
  LTimeoutMs := AClient.ResponseTimeout;
  LRequest := AClient.GetRequest(AMethod, AURL);
  LRequest.SourceStream := ASource;
  LExpired := False;
  LStart := TThread.GetTickCount64;
{$IFDEF MSWINDOWS}
  LDeadline.Request := LRequest;
  LDeadline.Expired := False;
  LTimer := 0;
  if LTimeoutMs > 0 then
  begin
    // The timer callback runs on a system thread: the memory manager must be thread-safe
    IsMultiThread := True;
    if not CreateTimerQueueTimer(LTimer, 0, RequestDeadlineExpired, @LDeadline, Cardinal(LTimeoutMs), 0,
      WT_EXECUTEONLYONCE) then
      RaiseLastOSError;
  end;
{$ENDIF}
  try
    try
      Result := AClient.Execute(LRequest, nil, AHeaders);
    finally
{$IFDEF MSWINDOWS}
      // Waits for a running callback: from here on the request is not touched by the timer
      if LTimer <> 0 then
        DeleteTimerQueueTimer(0, LTimer, INVALID_HANDLE_VALUE);
      LExpired := LDeadline.Expired;
{$ENDIF}
    end;
  except
    on E: ENetException do
    begin
      LCertificateError := IsCertificateFailure(AClient, E, AURL);
      // A failure after the whole time is the timeout too: WinHTTP's own, or libcurl's on Linux
      if LExpired or ((LTimeoutMs > 0) and not LCertificateError and
        (TThread.GetTickCount64 - LStart + DEADLINE_SLACK_MS >= UInt64(LTimeoutMs))) then
        raise EIAM4DNetworkTimeoutException.Create(AURL, LTimeoutMs)
      else if LCertificateError then
        raise EIAM4DSSLCertificateException.Create(E.Message)
      else
        // Connection refused, name not resolved, connection reset...: a library exception as for the
        // timeout, never THTTPClient's
        raise EIAM4DNetworkUnreachableException.Create(HostOfURL(AURL), E.Message);
    end;
  end;
  // Cancelled while waiting for the headers: THTTPClient returns an empty response
  if LExpired then
    raise EIAM4DNetworkTimeoutException.Create(AURL, LTimeoutMs);
end;

// Helper function: determines if HTTP status code is retryable
// Returns True for transient errors (429, 500, 502, 503, 504), False for permanent errors
function IsRetryableStatusCode(AStatusCode: Integer): Boolean;
begin
  case AStatusCode of
    429, // Too Many Requests - retryable with backoff (rate limiting)
    500, // Internal Server Error - might be temporary
    502, // Bad Gateway - typically temporary
    503, // Service Unavailable - explicitly temporary
    504: // Gateway Timeout - temporary
      Result := True;
    501, // Not Implemented - permanent
    505, // HTTP Version Not Supported - permanent
    506, // Variant Also Negotiates - configuration error
    507, // Insufficient Storage - capacity issue
    508, // Loop Detected - configuration error
    510, // Not Extended - permanent
    511: // Network Authentication Required - permanent
      Result := False;
  else
    // For unknown 5xx codes, default to retry
    Result := (AStatusCode >= 500) and (AStatusCode < 600);
  end;
end;

// 429 Too Many Requests and the transient 5xx; the other 4xx and 5xx are permanent
function IsRetryableResponse(AStatusCode: Integer): Boolean;
begin
  Result := (AStatusCode = 429) or ((AStatusCode >= 500) and IsRetryableStatusCode(AStatusCode));
end;

class function TIAM4DHTTPClientFactory.GetWithRetry(
  const AClient: THTTPClient;
  const AUrl: string;
  const AHeaders: TNetHeaders;
  const AMaxRetries: Integer
  ): IHTTPResponse;
var
  LAttempt: Integer;
  LDelayMs: Integer;
  LHeaders: TNetHeaders;
  LStatusCode: Integer;
begin
  LHeaders := AHeaders;

  LAttempt := 1;
  while True do
    try
      Result := Execute(AClient, sHTTPMethodGet, AUrl, nil, LHeaders);
      LStatusCode := Integer(Result.StatusCode);

      // The last attempt returns the response: the caller sees the status, never an exception
      if not IsRetryableResponse(LStatusCode) or (LAttempt >= AMaxRetries) then
        Exit;
      raise ENetHTTPClientException.CreateFmt('HTTP %d', [LStatusCode]); // Next attempt
    except
      // Execute raises the library exceptions: a connection error is retried, a timeout or a
      // certificate error is not
      on E: EIAM4DNetworkUnreachableException do
      begin
        if LAttempt >= AMaxRetries then
          raise;

        LDelayMs := Round(100 * Power(2, LAttempt - 1));
        LDelayMs := Max(50, Trunc(LDelayMs * (0.8 + Random * 0.4)));
        Sleep(LDelayMs);
        Inc(LAttempt);
      end;
      on E: ENetHTTPClientException do
      begin
        if LAttempt >= AMaxRetries then
          raise;
        LDelayMs := Round(100 * Power(2, LAttempt - 1));
        LDelayMs := Max(50, Trunc(LDelayMs * (0.8 + Random * 0.4)));
        Sleep(LDelayMs);
        Inc(LAttempt);
      end;
    end;
end;

class function TIAM4DHTTPClientFactory.PostFormUrlEncodedWithRetry(
  const AClient: THTTPClient;
  const AUrl: string;
  const AForm: TStrings;
  const AHeaders: TNetHeaders;
  const AMaxRetries: Integer
  ): IHTTPResponse;
var
  LAttempt: Integer;
  LDelayMs: Integer;
  LHeaders: TNetHeaders;
  LStatusCode: Integer;
  LSource: TStream;
  LSourceHeaders: TNetHeaders;
begin
  LHeaders := AHeaders;

  LAttempt := 1;
  while True do
    try
      // Same body and Content-Type as THTTPClient.Post(AUrl, AForm)
      AClient.CreateFormFromStrings(AForm, nil, LHeaders, LSource, LSourceHeaders);
      try
        Result := Execute(AClient, sHTTPMethodPost, AUrl, LSource, LSourceHeaders);
      finally
        LSource.Free;
      end;
      LStatusCode := Integer(Result.StatusCode);

      // The last attempt returns the response: the caller sees the status, never an exception
      if not IsRetryableResponse(LStatusCode) or (LAttempt >= AMaxRetries) then
        Exit;
      raise ENetHTTPClientException.CreateFmt('HTTP %d', [LStatusCode]); // Next attempt
    except
      // Execute raises the library exceptions: a connection error is retried, a timeout or a
      // certificate error is not
      on E: EIAM4DNetworkUnreachableException do
      begin
        if LAttempt >= AMaxRetries then
          raise;

        LDelayMs := Round(100 * Power(2, LAttempt - 1));
        LDelayMs := Max(50, Trunc(LDelayMs * (0.8 + Random * 0.4)));
        Sleep(LDelayMs);
        Inc(LAttempt);
      end;
      on E: ENetHTTPClientException do
      begin
        if LAttempt >= AMaxRetries then
          raise;

        LDelayMs := Round(100 * Power(2, LAttempt - 1));
        LDelayMs := Max(50, Trunc(LDelayMs * (0.8 + Random * 0.4)));
        Sleep(LDelayMs);
        Inc(LAttempt);
      end;
    end;
end;

end.