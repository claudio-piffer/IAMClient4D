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

type
  /// <summary>
  /// OAuth2 callback handling mode
  /// </summary>
  /// <remarks>
  /// cbmLocalServer: Desktop apps - starts local HTTP server for callback.
  /// cbmExternal: Web apps (uniGUI, ISAPI) - callback handled by external server.
  /// </remarks>
  TIAM4DCallbackMode = (
    cbmLocalServer,

    cbmExternal);

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
    JWKSUri: string;
    Issuer: string;

    /// <summary>
    /// Parses well-known endpoints from OIDC discovery JSON
    /// </summary>
    class function FromJSONObject(const AJSONObject: TJSONObject): TIAM4DWellKnownEndpoints; static;
  end;

  /// <summary>
  /// OAuth2 grant type
  /// </summary>
  TIAM4DGrantType = (gtUnknown, gtAuthorizationCode, gtClientCredentials);

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
  public
    property AccessToken: string read FAccessToken write FAccessToken;
    property RefreshToken: string read FRefreshToken write FRefreshToken;
    property IDToken: string read FIDToken write FIDToken;
    property ExpiresIn: Integer read FExpiresIn write FExpiresIn;
    property RefreshExpiresIn: Integer read FRefreshExpiresIn write FRefreshExpiresIn; // NOTE: naming kept as in original
    property AccessTokenExpiry: TDateTime read FAccessTokenExpiry write FAccessTokenExpiry;
    property RefreshTokenExpiry: TDateTime read FRefreshTokenExpiry write FRefreshTokenExpiry;

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
  /// ExternalCallbackURL: Required only for web apps using cbmExternal mode.
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
      const AAcrValues: TArray<string> = nil
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
      const AAcrValues: TArray<string> = nil
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
  end;

  /// <summary>
  /// Configuration for HTTP client instances.
  /// </summary>
  /// <remarks>
  /// Lightweight config for creating THTTPClient instances.
  /// Timeouts in milliseconds (default: 30s connection, 60s response).
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
    /// Event handler for THTTPClient.OnValidateServerCertificate
    /// </summary>
    procedure ValidateServerCertificate(const Sender: TObject; const ARequest: TURLRequest; const Certificate: TCertificate; var Accepted: Boolean);
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
  public
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
    class function GetWithRetry(
      const AClient: THTTPClient;
      const AUrl: string;
      const AHeaders: TNetHeaders;
      const AMaxRetries: Integer = 3
      ): IHTTPResponse; static;

    /// <summary>
    /// Performs POST request with application/x-www-form-urlencoded and retry/backoff (no retry on 4xx errors).
    /// </summary>
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
  /// Main interface for OAuth2/OIDC client operations.
  /// </summary>
  /// <remarks>
  /// Supports Authorization Code (with PKCE) and Client Credentials flows.
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
    function GenerateAuthURL(const ALoginHint: string = ''): string;

    /// <summary>
    /// Starts authorization flow (opens browser and waits for callback)
    /// </summary>
    function StartAuthorizationFlowAsync: IAsyncPromise<string>;

    /// <summary>
    /// Initializes authorization context without starting callback listener
    /// </summary>
    procedure InitializeAuthorizationFlow;

    /// <summary>
    /// Completes authorization flow with received code and state
    /// </summary>
    function CompleteAuthorizationFlowAsync(const ACode, AState: string): IAsyncPromise<string>;

    /// <summary>
    /// Authenticates using Client Credentials flow
    /// </summary>
    function AuthenticateClientAsync: IAsyncPromise<string>;

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

    // ========================================================================
    // Synchronous Operations
    // ========================================================================

    /// <summary>
    /// Gets valid access token synchronously (refreshes if expired).
    /// </summary>
    /// <returns>Valid access token string.</returns>
    /// <exception cref="EIAM4DRefreshTokenExpiredException">
    /// Raised when refresh token has expired (Authorization Code flow).
    /// </exception>
    /// <remarks>
    /// For Authorization Code flow: Automatically refreshes using refresh token.
    /// For Client Credentials flow: Automatically requests new token.
    /// </remarks>
    function GetAccessToken: string;

    /// <summary>
    /// Authenticates using Client Credentials flow synchronously.
    /// </summary>
    /// <returns>Access token string.</returns>
    /// <exception cref="EIAM4DException">
    /// Raised when not configured for Client Credentials flow or on errors.
    /// </exception>
    function AuthenticateClient: string;

    /// <summary>
    /// Completes Authorization Code flow with received code and state synchronously.
    /// </summary>
    /// <param name="ACode">Authorization code from callback.</param>
    /// <param name="AState">State parameter for CSRF validation.</param>
    /// <returns>Access token string.</returns>
    /// <exception cref="EIAM4DStateMismatchException">
    /// Raised when state parameter does not match.
    /// </exception>
    function CompleteAuthorizationFlow(const ACode, AState: string): string;

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
    procedure Logout;

    // ========================================================================
    // Utility Methods
    // ========================================================================

    /// <summary>
    /// Cancels ongoing authorization flow
    /// </summary>
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

    property Issuer: string read GetIssuer;
    property JWKSUri: string read GetJWKSUri;
    property IsAuthenticated: Boolean read GetIsAuthenticated;
    property RedirectURI: string read GetRedirectURI;

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
  System.DateUtils,
  System.Math,
  IAMClient4D.Common.Constants,
  IAMClient4D.Common.TokenSerializer;

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
  Result.JWKSUri := AJSONObject.GetValue<string>(IAM4D_OIDC_METADATA_JWKS_URI, '');
  Result.Issuer := AJSONObject.GetValue<string>(IAM4D_OIDC_METADATA_ISSUER, '');
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
  const AAcrValues: TArray<string>): TIAM4DClientConfig;
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
end;

class function TIAM4DClientConfig.CreateForAuthorizationCode(
  const ABaseURL, ARealm, AClientID: string;
  const AScopes: TArray<string>;
  const ASSLValidationMode: TIAM4DSSLValidationMode;
  const AConnectionTimeout: Integer;
  const AResponseTimeout: Integer;
  const AExternalCallbackURL: string;
  const ATokenExpiryBufferSeconds: Integer;
  const AAcrValues: TArray<string>): TIAM4DClientConfig;
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
    AAcrValues);
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
          if SameText(LPair.JsonString.Value, LStandardClaim) then
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
  Accepted := FSSLValidator.ValidateCertificate(Certificate);
end;

{ TIAM4DHTTPClientFactory }

class constructor TIAM4DHTTPClientFactory.Create;
begin
  FSSLValidator := TIAM4DSSLCertificateValidator.Create;
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
  FSSLValidator.SetValidationMode(AConfig.SSLValidationMode);

  case AConfig.SSLValidationMode of
    svmStrict:
      AHTTPClient.OnValidateServerCertificate := nil;
    svmAllowSelfSigned:
      AHTTPClient.OnValidateServerCertificate := FSSLHelper.ValidateServerCertificate;
  end;
end;

class procedure TIAM4DHTTPClientFactory.ConfigureSSLValidationWithHelper(
  const AHTTPClient: THTTPClient;
  const AConfig: TIAM4DHTTPClientConfig;
  const ASSLHelper: TIAM4DHTTPClientSSLHelper);
begin
  case AConfig.SSLValidationMode of
    svmStrict:
      AHTTPClient.OnValidateServerCertificate := nil;
    svmAllowSelfSigned:
      AHTTPClient.OnValidateServerCertificate := ASSLHelper.ValidateServerCertificate;
  end;
end;

class function TIAM4DHTTPClientFactory.CreateHTTPClient(
  const AConfig: TIAM4DHTTPClientConfig): THTTPClient;
begin
  Result := THTTPClient.Create;
  try
    Result.ConnectionTimeout := AConfig.ConnectionTimeout;
    Result.ResponseTimeout := AConfig.ResponseTimeout;

    Result.UserAgent := 'IAMClient4D/1.0';

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

  Result := THTTPClient.Create;
  try
    Result.ConnectionTimeout := LConfig.ConnectionTimeout;
    Result.ResponseTimeout := LConfig.ResponseTimeout;

    Result.UserAgent := 'IAMClient4D/1.0';

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
      Result := AClient.Get(AUrl, nil, LHeaders);
      LStatusCode := Integer(Result.StatusCode);

      // 4xx: Client errors - don't retry (except 429 Too Many Requests)
      if (LStatusCode >= 400) and (LStatusCode < 500) then
      begin
        if LStatusCode = 429 then
          raise ENetHTTPClientException.CreateFmt('HTTP %d', [LStatusCode]) // Retryable
        else
          Exit; // Other 4xx are permanent
      end;

      // 5xx: Server errors - retry only if transient
      if LStatusCode >= 500 then
      begin
        if not IsRetryableStatusCode(LStatusCode) then
          Exit; // Permanent server error - don't retry
        raise ENetHTTPClientException.CreateFmt('HTTP %d', [LStatusCode]);
      end;

      Exit;
    except
      on E: ENetHTTPRequestException do
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
begin
  LHeaders := AHeaders;

  LAttempt := 1;
  while True do
    try
      Result := AClient.Post(AUrl, AForm, nil, nil, LHeaders);
      LStatusCode := Integer(Result.StatusCode);

      // 4xx: Client errors - don't retry (except 429 Too Many Requests)
      if (LStatusCode >= 400) and (LStatusCode < 500) then
      begin
        if LStatusCode = 429 then
          raise ENetHTTPClientException.CreateFmt('HTTP %d', [LStatusCode]) // Retryable
        else
          Exit; // Other 4xx are permanent
      end;

      // 5xx: Server errors - retry only if transient
      if LStatusCode >= 500 then
      begin
        if not IsRetryableStatusCode(LStatusCode) then
          Exit; // Permanent server error - don't retry
        raise ENetHTTPClientException.CreateFmt('HTTP %d', [LStatusCode]);
      end;

      Exit;
    except
      on E: ENetHTTPRequestException do
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