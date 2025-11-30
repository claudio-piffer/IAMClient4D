{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Exceptions.pas
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

unit IAMClient4D.Exceptions;

interface

uses
  System.SysUtils,
  System.Generics.Collections;

type
  /// <summary>
  /// Error code enumeration for precise error identification.
  /// </summary>
  /// <remarks>
  /// Error codes are grouped by category (ranges):
  /// - 0: Unknown/Unspecified
  /// - 1000-1999: Authentication/Authorization errors
  /// - 2000-2999: Network/Communication errors
  /// - 3000-3999: User Management errors
  /// - 4000-4999: Configuration errors
  /// - 5000-5999: Storage errors
  /// - 6000-6999: Security/Validation errors
  /// </remarks>
  TIAM4DErrorCode = (
    /// <summary>Unknown or unspecified error</summary>
    ecUnknown = 0,

    // ========================================================================
    // Authentication/Authorization Errors (1000-1999)
    // ========================================================================

    /// <summary>Access token has expired (recoverable with refresh)</summary>
    ecAccessTokenExpired = 1001,
    /// <summary>Refresh token has expired (requires re-authentication)</summary>
    ecRefreshTokenExpired = 1002,
    /// <summary>Token is malformed or invalid</summary>
    ecTokenInvalid = 1003,
    /// <summary>Invalid username or password</summary>
    ecInvalidCredentials = 1010,
    /// <summary>Authorization code is invalid or expired</summary>
    ecInvalidAuthorizationCode = 1020,
    /// <summary>PKCE code verifier validation failed</summary>
    ecPKCEValidationFailed = 1021,
    /// <summary>State parameter mismatch (CSRF protection)</summary>
    ecStateMismatch = 1022,
    /// <summary>User cancelled the authorization flow</summary>
    ecAuthorizationCancelled = 1030,
    /// <summary>Authorization flow timed out</summary>
    ecAuthorizationTimeout = 1031,
    /// <summary>Insufficient permissions for requested operation</summary>
    ecInsufficientPermissions = 1040,

    // ========================================================================
    // Network/Communication Errors (2000-2999)
    // ========================================================================

    /// <summary>Network request timed out</summary>
    ecNetworkTimeout = 2001,
    /// <summary>Network host is unreachable</summary>
    ecNetworkUnreachable = 2002,
    /// <summary>Connection refused by server</summary>
    ecConnectionRefused = 2003,
    /// <summary>SSL/TLS certificate validation failed</summary>
    ecSSLCertificateError = 2010,
    /// <summary>HTTP 4xx client error</summary>
    ecHTTPClientError = 2100,
    /// <summary>HTTP 5xx server error (Keycloak unavailable)</summary>
    ecHTTPServerError = 2200,

    // ========================================================================
    // User Management Errors (3000-3999)
    // ========================================================================

    /// <summary>User not found in identity provider</summary>
    ecUserNotFound = 3001,
    /// <summary>User already exists (duplicate username/email)</summary>
    ecUserAlreadyExists = 3002,
    /// <summary>Invalid user data (validation failed)</summary>
    ecInvalidUserData = 3010,
    /// <summary>Role not found</summary>
    ecRoleNotFound = 3020,
    /// <summary>Group not found</summary>
    ecGroupNotFound = 3030,

    // ========================================================================
    // Configuration Errors (4000-4999)
    // ========================================================================

    /// <summary>Client configuration is invalid or incomplete</summary>
    ecInvalidConfiguration = 4001,
    /// <summary>OIDC endpoints not configured (call ConfigureAsync first)</summary>
    ecEndpointsNotConfigured = 4002,
    /// <summary>Well-known endpoint discovery failed</summary>
    ecDiscoveryFailed = 4003,

    // ========================================================================
    // Storage Errors (5000-5999)
    // ========================================================================

    /// <summary>Token storage is not initialized</summary>
    ecStorageNotInitialized = 5001,
    /// <summary>Failed to encrypt token data</summary>
    ecStorageEncryptionFailed = 5002,
    /// <summary>Failed to decrypt token data</summary>
    ecStorageDecryptionFailed = 5003,

    // ========================================================================
    // Security/Validation Errors (6000-6999)
    // ========================================================================

    /// <summary>JWT signature verification failed</summary>
    ecJWTSignatureInvalid = 6001,
    /// <summary>JWT issuer mismatch</summary>
    ecJWTIssuerMismatch = 6002,
    /// <summary>JWT audience mismatch</summary>
    ecJWTAudienceMismatch = 6003,
    /// <summary>JWT expired</summary>
    ecJWTExpired = 6004,
    /// <summary>JWT not yet valid (nbf claim)</summary>
    ecJWTNotYetValid = 6005,
    /// <summary>JWKS key not found for kid</summary>
    ecJWKSKeyNotFound = 6010,
    /// <summary>Nonce validation failed</summary>
    ecNonceValidationFailed = 6020);

  /// <summary>
  /// Base exception class for IAMClient4D with enhanced error context.
  /// </summary>
  /// <remarks>
  /// All exceptions in IAMClient4D inherit from this base class.
  /// Provides error code for programmatic handling and optional context dictionary.
  /// Context dictionary should never contain sensitive data (tokens, passwords, etc.).
  /// Thread-safety: Context dictionary is created on-demand and should not be accessed concurrently.
  /// </remarks>
  EIAM4DException = class(Exception)
  private
    FErrorCode: TIAM4DErrorCode;
    FContext: TDictionary<string, string>;
    function GetContext: TDictionary<string, string>;
  public
    /// <summary>
    /// Creates exception with message and error code.
    /// </summary>
    constructor Create(const AMessage: string; AErrorCode: TIAM4DErrorCode = ecUnknown); reintroduce; overload;

    /// <summary>
    /// Creates exception with formatted message and error code.
    /// </summary>
    constructor CreateFmt(const AMessage: string; const AArgs: array of const;
      AErrorCode: TIAM4DErrorCode = ecUnknown); reintroduce; overload;

    /// <summary>
    /// Destroys exception and frees context dictionary.
    /// </summary>
    destructor Destroy; override;

    /// <summary>
    /// Adds context information to exception (fluent API).
    /// </summary>
    /// <param name="AKey">Context key (e.g., 'endpoint', 'username')</param>
    /// <param name="AValue">Context value (non-sensitive data only)</param>
    /// <returns>Self for method chaining</returns>
    function WithContext(const AKey, AValue: string): EIAM4DException;

    /// <summary>
    /// Machine-readable error code for programmatic handling.
    /// </summary>
    property ErrorCode: TIAM4DErrorCode read FErrorCode;

    /// <summary>
    /// Additional context information (created on-demand).
    /// </summary>
    /// <remarks>
    /// Use WithContext() to add entries. Never store sensitive data here.
    /// </remarks>
    property Context: TDictionary<string, string> read GetContext;
  end;

  // ==========================================================================
  // Security/Validation Exceptions (declared early for use in other exceptions)
  // ==========================================================================

  /// <summary>
  /// Raised when JWT or certificate validation fails.
  /// </summary>
  EIAM4DSecurityValidationException = class(EIAM4DException)
  public
    constructor Create(const AMessage: string; AErrorCode: TIAM4DErrorCode = ecUnknown);
  end;

  // ==========================================================================
  // Authentication/Authorization Exceptions
  // ==========================================================================

  /// <summary>
  /// Raised when access token has expired.
  /// </summary>
  /// <remarks>
  /// Recoverable: Use refresh token to obtain new access token.
  /// Action: Call GetAccessTokenAsync which handles refresh automatically.
  /// </remarks>
  EIAM4DAccessTokenExpiredException = class(EIAM4DException)
  public
    constructor Create;
  end;

  /// <summary>
  /// Raised when refresh token has expired.
  /// </summary>
  /// <remarks>
  /// Non-recoverable: Requires user re-authentication.
  /// Action: Redirect user to login screen.
  /// </remarks>
  EIAM4DRefreshTokenExpiredException = class(EIAM4DException)
  public
    constructor Create;
  end;

  /// <summary>
  /// Raised when token is malformed or invalid.
  /// </summary>
  EIAM4DTokenInvalidException = class(EIAM4DException)
  public
    constructor Create(const AReason: string);
  end;

  /// <summary>
  /// Raised when username/password credentials are invalid.
  /// </summary>
  /// <remarks>
  /// Non-recoverable with same credentials.
  /// Action: Prompt user to re-enter credentials.
  /// </remarks>
  EIAM4DInvalidCredentialsException = class(EIAM4DException)
  public
    constructor Create;
  end;

  /// <summary>
  /// Raised when OAuth2 authorization code is invalid or expired.
  /// </summary>
  EIAM4DInvalidAuthCodeException = class(EIAM4DException)
  public
    constructor Create(const AReason: string);
  end;

  /// <summary>
  /// Raised when PKCE code verifier validation fails.
  /// </summary>
  EIAM4DPKCEValidationException = class(EIAM4DException)
  public
    constructor Create;
  end;

  /// <summary>
  /// Raised when OAuth2 state parameter doesn't match (CSRF attack).
  /// </summary>
  /// <remarks>
  /// This exception is raised for various state validation failures:
  /// - State parameter is missing or empty (possible CSRF attack)
  /// - State parameter has invalid format (tampering detected)
  /// - State parameter doesn't match expected value (CSRF attack)
  /// Security: Only partial state values are logged to prevent information leakage.
  /// </remarks>
  EIAM4DStateMismatchException = class(EIAM4DSecurityValidationException)
  public
    /// <summary>
    /// Creates state mismatch exception with custom message (for empty/invalid format).
    /// </summary>
    constructor Create(const AMessage: string); overload;
    /// <summary>
    /// Creates state mismatch exception with expected and received values (for mismatch).
    /// </summary>
    constructor Create(const AExpected, AReceived: string); overload;
  end;

  /// <summary>
  /// Raised when user cancels authorization flow.
  /// </summary>
  /// <remarks>
  /// This is a normal user action, not a system error.
  /// Action: Return to previous screen or show login prompt.
  /// </remarks>
  EIAM4DAuthorizationCancelledException = class(EIAM4DException)
  public
    constructor Create;
  end;

  /// <summary>
  /// Raised when authorization flow times out waiting for callback.
  /// </summary>
  EIAM4DAuthorizationTimeoutException = class(EIAM4DException)
  public
    constructor Create(ATimeoutSeconds: Integer);
  end;

  /// <summary>
  /// Raised when user has insufficient permissions for requested operation.
  /// </summary>
  EIAM4DInsufficientPermissionsException = class(EIAM4DException)
  private
    FRequiredRole: string;
    FOperation: string;
  public
    constructor Create(const AOperation, ARequiredRole: string);
    property RequiredRole: string read FRequiredRole;
    property Operation: string read FOperation;
  end;

  // ==========================================================================
  // Network/Communication Exceptions
  // ==========================================================================

  /// <summary>
  /// Raised when network request times out.
  /// </summary>
  /// <remarks>
  /// Recoverable: Retry the operation.
  /// Action: Implement exponential backoff retry logic.
  /// </remarks>
  EIAM4DNetworkTimeoutException = class(EIAM4DException)
  private
    FEndpoint: string;
    FTimeoutMs: Integer;
  public
    constructor Create(const AEndpoint: string; ATimeoutMs: Integer);
    property Endpoint: string read FEndpoint;
    property TimeoutMs: Integer read FTimeoutMs;
  end;

  /// <summary>
  /// Raised when network host is unreachable.
  /// </summary>
  EIAM4DNetworkUnreachableException = class(EIAM4DException)
  public
    constructor Create(const AHost: string);
  end;

  /// <summary>
  /// Raised when SSL/TLS certificate validation fails.
  /// </summary>
  EIAM4DSSLCertificateException = class(EIAM4DException)
  private
    FCertificateIssue: string;
  public
    constructor Create(const ACertificateIssue: string);
    property CertificateIssue: string read FCertificateIssue;
  end;

  /// <summary>
  /// Raised for HTTP 4xx client errors.
  /// </summary>
  /// <remarks>
  /// Non-recoverable with retry (except 408 Request Timeout, 429 Too Many Requests).
  /// Contains full response body for detailed error analysis.
  /// </remarks>
  EIAM4DHTTPClientErrorException = class(EIAM4DException)
  private
    FStatusCode: Integer;
    FResponseBody: string;
  public
    constructor Create(AStatusCode: Integer; const AResponseBody: string);
    property StatusCode: Integer read FStatusCode;
    property ResponseBody: string read FResponseBody;
  end;

  /// <summary>
  /// Raised for HTTP 5xx server errors (Keycloak unavailable/error).
  /// </summary>
  /// <remarks>
  /// Recoverable: Retry with exponential backoff.
  /// Check RetryAfterSeconds for server-suggested retry delay.
  /// </remarks>
  EIAM4DHTTPServerErrorException = class(EIAM4DException)
  private
    FStatusCode: Integer;
    FRetryAfterSeconds: Integer;
  public
    constructor Create(AStatusCode: Integer; ARetryAfterSeconds: Integer = 0);
    property StatusCode: Integer read FStatusCode;
    property RetryAfterSeconds: Integer read FRetryAfterSeconds;
  end;

  // ==========================================================================
  // User Management Exceptions
  // ==========================================================================

  /// <summary>
  /// Raised when user is not found in identity provider.
  /// </summary>
  EIAM4DUserNotFoundException = class(EIAM4DException)
  private
    FUserIdentifier: string;
  public
    constructor Create(const AUserIdentifier: string);
    property UserIdentifier: string read FUserIdentifier;
  end;

  /// <summary>
  /// Raised when attempting to create user that already exists.
  /// </summary>
  EIAM4DUserAlreadyExistsException = class(EIAM4DException)
  private
    FConflictingField: string;
    FValue: string;
  public
    constructor Create(const AConflictingField, AValue: string);
    property ConflictingField: string read FConflictingField;
    property Value: string read FValue;
  end;

  /// <summary>
  /// Raised when user data fails validation.
  /// </summary>
  EIAM4DInvalidUserDataException = class(EIAM4DException)
  public
    constructor Create(const AValidationMessage: string);
  end;

  /// <summary>
  /// Raised when role is not found.
  /// </summary>
  EIAM4DRoleNotFoundException = class(EIAM4DException)
  public
    constructor Create(const ARoleName: string);
  end;

  /// <summary>
  /// Raised when group is not found.
  /// </summary>
  EIAM4DGroupNotFoundException = class(EIAM4DException)
  public
    constructor Create(const AGroupPath: string);
  end;

  // ==========================================================================
  // Configuration Exceptions
  // ==========================================================================

  /// <summary>
  /// Raised when client configuration is invalid.
  /// </summary>
  EIAM4DInvalidConfigurationException = class(EIAM4DException)
  public
    constructor Create(const AReason: string);
  end;

  /// <summary>
  /// Raised when OIDC endpoints are not configured.
  /// </summary>
  /// <remarks>
  /// Action: Call ConfigureAsync before using client.
  /// </remarks>
  EIAM4DEndpointsNotConfiguredException = class(EIAM4DException)
  public
    constructor Create;
  end;

  /// <summary>
  /// Raised when OIDC well-known endpoint discovery fails.
  /// </summary>
  EIAM4DDiscoveryFailedException = class(EIAM4DException)
  public
    constructor Create(const ADiscoveryURL: string; const AReason: string);
  end;

  // ==========================================================================
  // Storage Exceptions
  // ==========================================================================

  /// <summary>
  /// Raised when token storage operation fails.
  /// </summary>
  EIAM4DStorageException = class(EIAM4DException)
  public
    constructor Create(const AMessage: string; AErrorCode: TIAM4DErrorCode = ecUnknown);
  end;

  // ==========================================================================
  // Security/Validation Exceptions (continued)
  // ==========================================================================

  /// <summary>
  /// Raised when JWT signature verification fails.
  /// </summary>
  EIAM4DJWTSignatureInvalidException = class(EIAM4DSecurityValidationException)
  public
    constructor Create(const AAlgorithm: string);
  end;

  /// <summary>
  /// Raised when JWT issuer doesn't match expected value.
  /// </summary>
  EIAM4DJWTIssuerMismatchException = class(EIAM4DSecurityValidationException)
  public
    constructor Create(const AExpected, AActual: string);
  end;

  /// <summary>
  /// Raised when an unknown required action is encountered during JSON parsing.
  /// </summary>
  /// <remarks>
  /// This exception indicates that Keycloak returned a required action that is not
  /// defined in the TIAM4DRequiredAction enumeration. This may happen when:
  /// - Keycloak is upgraded and introduces new required actions
  /// - Custom required actions are configured in Keycloak
  /// Action: Update the TIAM4DRequiredAction enum to include the new action.
  /// </remarks>
  EIAM4DUnknownRequiredActionException = class(EIAM4DException)
  private
    FActionName: string;
    FUserID: string;
  public
    constructor Create(const AActionName: string; const AUserID: string = '');
    property ActionName: string read FActionName;
    property UserID: string read FUserID;
  end;

  /// <summary>
  /// Raised when JWKS key is not found for specified kid.
  /// </summary>
  EIAM4DJWKSKeyNotFoundException = class(EIAM4DSecurityValidationException)
  public
    constructor Create(const AKeyID, AIssuer: string);
  end;

  // ==========================================================================
  // JSON Parsing Exception (keep existing for compatibility)
  // ==========================================================================

  /// <summary>
  /// Raised when JSON parsing fails.
  /// </summary>
  EIAM4DJSONParseException = class(EIAM4DException)
  public
    constructor Create(const AMessage: string);
  end;

  // ==========================================================================
  // Callback Handler Exceptions
  // ==========================================================================

  /// <summary>
  /// Raised by OAuth2 callback handlers.
  /// </summary>
  EIAM4DCallbackHandlerException = class(EIAM4DException)
  public
    constructor Create(const AMessage: string);
  end;

  /// <summary>
  /// Raised by server callback operations.
  /// </summary>
  EIAM4DServerCallbackException = class(EIAM4DException)
  public
    constructor Create(const AMessage: string);
  end;

  /// <summary>
  /// Raised when parsing OAuth2 callback URL fails.
  /// </summary>
  EIAM4DOAuth2CallbackException = class(EIAM4DException)
  public
    constructor Create(const AMessage: string);
  end;

  // ==========================================================================
  // Crypto/Utility Exceptions
  // ==========================================================================

  /// <summary>
  /// Raised by cryptographic utility operations.
  /// </summary>
  EIAM4DCryptoUtilsException = class(EIAM4DException)
  public
    constructor Create(const AMessage: string);
  end;

  /// <summary>
  /// Raised by AES256 encryption/decryption operations.
  /// </summary>
  EAES256RawException = class(EIAM4DException)
  public
    constructor Create(const AMessage: string);
  end;

implementation

{ EIAM4DException }

constructor EIAM4DException.Create(const AMessage: string; AErrorCode: TIAM4DErrorCode);
begin
  inherited Create(AMessage);
  FErrorCode := AErrorCode;
  FContext := nil;
end;

constructor EIAM4DException.CreateFmt(const AMessage: string; const AArgs: array of const;
  AErrorCode: TIAM4DErrorCode);
begin
  inherited CreateFmt(AMessage, AArgs);
  FErrorCode := AErrorCode;
  FContext := nil;
end;

destructor EIAM4DException.Destroy;
begin
  FreeAndNil(FContext);
  inherited;
end;

function EIAM4DException.GetContext: TDictionary<string, string>;
begin
  if not Assigned(FContext) then
    FContext := TDictionary<string, string>.Create;
  Result := FContext;
end;

function EIAM4DException.WithContext(const AKey, AValue: string): EIAM4DException;
begin
  Context.AddOrSetValue(AKey, AValue);
  Result := Self;
end;

{ EIAM4DAccessTokenExpiredException }

constructor EIAM4DAccessTokenExpiredException.Create;
begin
  inherited Create('Access token has expired', ecAccessTokenExpired);
end;

{ EIAM4DRefreshTokenExpiredException }

constructor EIAM4DRefreshTokenExpiredException.Create;
begin
  inherited Create('Refresh token has expired - re-authentication required', ecRefreshTokenExpired);
end;

{ EIAM4DTokenInvalidException }

constructor EIAM4DTokenInvalidException.Create(const AReason: string);
begin
  inherited CreateFmt('Token is invalid: %s', [AReason], ecTokenInvalid);
end;

{ EIAM4DInvalidCredentialsException }

constructor EIAM4DInvalidCredentialsException.Create;
begin
  inherited Create('Invalid username or password', ecInvalidCredentials);
end;

{ EIAM4DInvalidAuthCodeException }

constructor EIAM4DInvalidAuthCodeException.Create(const AReason: string);
begin
  inherited CreateFmt('Invalid authorization code: %s', [AReason], ecInvalidAuthorizationCode);
end;

{ EIAM4DPKCEValidationException }

constructor EIAM4DPKCEValidationException.Create;
begin
  inherited Create('PKCE code verifier validation failed', ecPKCEValidationFailed);
end;

{ EIAM4DStateMismatchException }

constructor EIAM4DStateMismatchException.Create(const AMessage: string);
begin
  inherited Create(AMessage, ecStateMismatch);
end;

constructor EIAM4DStateMismatchException.Create(const AExpected, AReceived: string);
var
  LExpectedPrefix, LReceivedPrefix: string;
begin
  // Only log first 8 characters to prevent information leakage
  LExpectedPrefix := Copy(AExpected, 1, 8);
  if Length(AExpected) > 8 then
    LExpectedPrefix := LExpectedPrefix + '...';

  LReceivedPrefix := Copy(AReceived, 1, 8);
  if Length(AReceived) > 8 then
    LReceivedPrefix := LReceivedPrefix + '...';

  inherited CreateFmt('State parameter mismatch - possible CSRF attack (expected: %s, received: %s)',
    [LExpectedPrefix, LReceivedPrefix], ecStateMismatch);
  WithContext('expected_state_prefix', LExpectedPrefix);
  WithContext('received_state_prefix', LReceivedPrefix);
end;

{ EIAM4DAuthorizationCancelledException }

constructor EIAM4DAuthorizationCancelledException.Create;
begin
  inherited Create('User cancelled authorization', ecAuthorizationCancelled);
end;

{ EIAM4DAuthorizationTimeoutException }

constructor EIAM4DAuthorizationTimeoutException.Create(ATimeoutSeconds: Integer);
begin
  inherited CreateFmt('Authorization timed out after %d seconds', [ATimeoutSeconds], ecAuthorizationTimeout);
  WithContext('timeout_seconds', IntToStr(ATimeoutSeconds));
end;

{ EIAM4DInsufficientPermissionsException }

constructor EIAM4DInsufficientPermissionsException.Create(const AOperation, ARequiredRole: string);
begin
  inherited CreateFmt('Insufficient permissions for operation "%s" (required role: %s)',
    [AOperation, ARequiredRole], ecInsufficientPermissions);
  FOperation := AOperation;
  FRequiredRole := ARequiredRole;
  WithContext('operation', AOperation);
  WithContext('required_role', ARequiredRole);
end;

{ EIAM4DNetworkTimeoutException }

constructor EIAM4DNetworkTimeoutException.Create(const AEndpoint: string; ATimeoutMs: Integer);
begin
  inherited CreateFmt('Network timeout after %d ms calling %s', [ATimeoutMs, AEndpoint], ecNetworkTimeout);
  FEndpoint := AEndpoint;
  FTimeoutMs := ATimeoutMs;
  WithContext('endpoint', AEndpoint);
  WithContext('timeout_ms', IntToStr(ATimeoutMs));
end;

{ EIAM4DNetworkUnreachableException }

constructor EIAM4DNetworkUnreachableException.Create(const AHost: string);
begin
  inherited CreateFmt('Network host unreachable: %s', [AHost], ecNetworkUnreachable);
  WithContext('host', AHost);
end;

{ EIAM4DSSLCertificateException }

constructor EIAM4DSSLCertificateException.Create(const ACertificateIssue: string);
begin
  inherited CreateFmt('SSL certificate validation failed: %s', [ACertificateIssue], ecSSLCertificateError);
  FCertificateIssue := ACertificateIssue;
  WithContext('certificate_issue', ACertificateIssue);
end;

{ EIAM4DHTTPClientErrorException }

constructor EIAM4DHTTPClientErrorException.Create(AStatusCode: Integer; const AResponseBody: string);
begin
  inherited CreateFmt('HTTP client error %d', [AStatusCode], ecHTTPClientError);
  FStatusCode := AStatusCode;
  FResponseBody := AResponseBody;
  WithContext('status_code', IntToStr(AStatusCode));
end;

{ EIAM4DHTTPServerErrorException }

constructor EIAM4DHTTPServerErrorException.Create(AStatusCode: Integer; ARetryAfterSeconds: Integer);
begin
  inherited CreateFmt('HTTP server error %d', [AStatusCode], ecHTTPServerError);
  FStatusCode := AStatusCode;
  FRetryAfterSeconds := ARetryAfterSeconds;
  WithContext('status_code', IntToStr(AStatusCode));
  if ARetryAfterSeconds > 0 then
    WithContext('retry_after_seconds', IntToStr(ARetryAfterSeconds));
end;

{ EIAM4DUserNotFoundException }

constructor EIAM4DUserNotFoundException.Create(const AUserIdentifier: string);
begin
  inherited CreateFmt('User not found: %s', [AUserIdentifier], ecUserNotFound);
  FUserIdentifier := AUserIdentifier;
  WithContext('user_identifier', AUserIdentifier);
end;

{ EIAM4DUserAlreadyExistsException }

constructor EIAM4DUserAlreadyExistsException.Create(const AConflictingField, AValue: string);
begin
  inherited CreateFmt('User already exists - %s: %s', [AConflictingField, AValue], ecUserAlreadyExists);
  FConflictingField := AConflictingField;
  FValue := AValue;
  WithContext('conflicting_field', AConflictingField);
  WithContext('value', AValue);
end;

{ EIAM4DInvalidUserDataException }

constructor EIAM4DInvalidUserDataException.Create(const AValidationMessage: string);
begin
  inherited CreateFmt('Invalid user data: %s', [AValidationMessage], ecInvalidUserData);
end;

{ EIAM4DRoleNotFoundException }

constructor EIAM4DRoleNotFoundException.Create(const ARoleName: string);
begin
  inherited CreateFmt('Role not found: %s', [ARoleName], ecRoleNotFound);
  WithContext('role_name', ARoleName);
end;

{ EIAM4DGroupNotFoundException }

constructor EIAM4DGroupNotFoundException.Create(const AGroupPath: string);
begin
  inherited CreateFmt('Group not found: %s', [AGroupPath], ecGroupNotFound);
  WithContext('group_path', AGroupPath);
end;

{ EIAM4DInvalidConfigurationException }

constructor EIAM4DInvalidConfigurationException.Create(const AReason: string);
begin
  inherited CreateFmt('Invalid configuration: %s', [AReason], ecInvalidConfiguration);
end;

{ EIAM4DEndpointsNotConfiguredException }

constructor EIAM4DEndpointsNotConfiguredException.Create;
begin
  inherited Create('OIDC endpoints not configured - call ConfigureAsync first', ecEndpointsNotConfigured);
end;

{ EIAM4DDiscoveryFailedException }

constructor EIAM4DDiscoveryFailedException.Create(const ADiscoveryURL, AReason: string);
begin
  inherited CreateFmt('OIDC discovery failed for %s: %s', [ADiscoveryURL, AReason], ecDiscoveryFailed);
  WithContext('discovery_url', ADiscoveryURL);
end;

{ EIAM4DStorageException }

constructor EIAM4DStorageException.Create(const AMessage: string; AErrorCode: TIAM4DErrorCode);
begin
  inherited Create(AMessage, AErrorCode);
end;

{ EIAM4DSecurityValidationException }

constructor EIAM4DSecurityValidationException.Create(const AMessage: string; AErrorCode: TIAM4DErrorCode);
begin
  inherited Create(AMessage, AErrorCode);
end;

{ EIAM4DJWTSignatureInvalidException }

constructor EIAM4DJWTSignatureInvalidException.Create(const AAlgorithm: string);
begin
  inherited CreateFmt('JWT signature verification failed (algorithm: %s)', [AAlgorithm], ecJWTSignatureInvalid);
  WithContext('algorithm', AAlgorithm);
end;

{ EIAM4DJWTIssuerMismatchException }

constructor EIAM4DJWTIssuerMismatchException.Create(const AExpected, AActual: string);
begin
  inherited CreateFmt('JWT issuer mismatch (expected: %s, actual: %s)',
    [AExpected, AActual], ecJWTIssuerMismatch);
  WithContext('expected_issuer', AExpected);
  WithContext('actual_issuer', AActual);
end;

{ EIAM4DJWKSKeyNotFoundException }

constructor EIAM4DJWKSKeyNotFoundException.Create(const AKeyID, AIssuer: string);
begin
  inherited CreateFmt('JWKS key not found (kid: %s, issuer: %s)', [AKeyID, AIssuer], ecJWKSKeyNotFound);
  WithContext('key_id', AKeyID);
  WithContext('issuer', AIssuer);
end;

{ EIAM4DJSONParseException }

constructor EIAM4DJSONParseException.Create(const AMessage: string);
begin
  inherited Create(AMessage, ecUnknown);
end;

{ EIAM4DCallbackHandlerException }

constructor EIAM4DCallbackHandlerException.Create(const AMessage: string);
begin
  inherited Create(AMessage, ecUnknown);
end;

{ EIAM4DServerCallbackException }

constructor EIAM4DServerCallbackException.Create(const AMessage: string);
begin
  inherited Create(AMessage, ecUnknown);
end;

{ EIAM4DOAuth2CallbackException }

constructor EIAM4DOAuth2CallbackException.Create(const AMessage: string);
begin
  inherited Create(AMessage, ecUnknown);
end;

{ EIAM4DCryptoUtilsException }

constructor EIAM4DCryptoUtilsException.Create(const AMessage: string);
begin
  inherited Create(AMessage, ecUnknown);
end;

{ EAES256RawException }

constructor EAES256RawException.Create(const AMessage: string);
begin
  inherited Create(AMessage, ecUnknown);
end;

{ EIAM4DUnknownRequiredActionException }

constructor EIAM4DUnknownRequiredActionException.Create(const AActionName: string; const AUserID: string);
begin
  if AUserID.IsEmpty then
    inherited CreateFmt('Unknown required action encountered: %s', [AActionName], ecInvalidUserData)
  else
    inherited CreateFmt('Unknown required action "%s" for user %s', [AActionName, AUserID], ecInvalidUserData);

  FActionName := AActionName;
  FUserID := AUserID;
  WithContext('action_name', AActionName);
  if not AUserID.IsEmpty then
    WithContext('user_id', AUserID);
end;

end.