unit RuntimeTestValidatorU;

interface

uses
  System.JSON,
  IAMClient4D.Security.Core;

const
  TEST_ISSUER = 'https://idp.test/realms/iamclient4d';
  TEST_AUDIENCE = 'api-server';
  TEST_VALID_TOKEN = 'good';
  // Valid, without iat: LoggedSince falls back to the current time
  TEST_VALID_TOKEN_NO_IAT = 'good-noiat';
  // Rejected with a reason carrying CR/LF and a control character (log injection)
  TEST_CRLF_TOKEN = 'crlf';
  TEST_CRLF_MARKER = 'IAM4D-CRLF-MARKER';
  // Rejected with a 20000 character reason
  TEST_LONG_TOKEN = 'long';
  TEST_LONG_MARKER = 'IAM4D-LONG-MARKER';
  // Fixed auth_time of the valid payload: 2026-01-01T00:00:00Z
  TEST_AUTH_TIME = 1767225600;
  // Accepted by the validator without claims (a broken custom validator)
  TEST_NO_CLAIMS_TOKEN = 'good-noclaims';
  // Valid, same sub (u-123) from another issuer
  TEST_OTHER_ISSUER = 'https://idp2.test/realms/other';
  TEST_OTHER_ISSUER_TOKEN = 'good-otheriss';
  // Valid, resource_access with a value that is not an object
  TEST_BAD_RESOURCE_TOKEN = 'good-badresource';
  // Valid, subject whose application roles cannot be loaded
  TEST_ROLES_DOWN_TOKEN = 'good-rolesdown';
  TEST_ROLES_DOWN_SUBJECT = 'u-rolesdown';

type
  /// <summary>
  /// Fake JWT validator: accepts only TEST_VALID_TOKEN(_NO_IAT) and returns a fixed Keycloak-like payload.
  /// Lets the runtime test exercise the DMVC integration without an identity provider.
  /// </summary>
  TRuntimeTestValidator = class(TInterfacedObject, IIAM4DJWTValidator)
  private
    FClockSkewSeconds: Integer;
  public
    function ValidateToken(const AToken: string; out AClaims: TJSONObject): Boolean;
    function GetClockSkewSeconds: Integer;
    procedure SetClockSkewSeconds(const AValue: Integer);
    function GetExpectedIssuer: string;
    function GetExpectedAudience: string;
    function GetExpectedAzp: string;
  end;

var
  // ValidateToken calls of every TRuntimeTestValidator (interlocked)
  GValidateCalls: Integer = 0;

implementation

uses
  System.SysUtils,
  System.SyncObjs,
  System.DateUtils,
  IAMClient4D.Exceptions;

// Keycloak-like payload of a valid token
function ValidPayload(AWithIat: Boolean; const AIssuer, ASubject, AExtraResourceAccess: string): TJSONObject;
var
  LNow: Int64;
  LIat: string;
begin
  LNow := DateTimeToUnix(TDateTime.NowUTC);
  if AWithIat then
    LIat := '"iat":' + IntToStr(LNow - 10) + ','
  else
    LIat := '';
  Result := TJSONObject.ParseJSONValue(
    '{"sub":"' + ASubject + '","oid":"object-42","preferred_username":"mario","email":"mario@example.com",' +
    '"iss":"' + AIssuer + '","aud":"' + TEST_AUDIENCE + '","azp":"web-client",' +
    LIat + '"exp":' + IntToStr(LNow + 600) + ',"auth_time":' + IntToStr(TEST_AUTH_TIME) + ',' +
    '"scope":"openid profile read",' +
    '"roles":["legacy-role"],"app_roles":["app-editor"],' +
    '"realm_access":{"roles":["admin","user"]},' +
    '"resource_access":{' + AExtraResourceAccess + '"web-client":{"roles":["reader"]},"' + TEST_AUDIENCE +
    '":{"roles":["api-reader"]},"other-client":{"roles":["other-admin"]}},' +
    '"groups":["/staff"],' +
    // Namespaced custom claims (Auth0, Okta): names with '.' and '/'
    '"https://app.example.com/tenant":"acme","https://app.example.com/level":7}') as TJSONObject;
end;

function TRuntimeTestValidator.ValidateToken(const AToken: string; out AClaims: TJSONObject): Boolean;
begin
  TInterlocked.Increment(GValidateCalls);
  AClaims := nil;

  if AToken = TEST_CRLF_TOKEN then
    raise EIAM4DSecurityValidationException.Create('Invalid issuer. Expected "' + TEST_ISSUER + '", got "evil' +
      #13#10'2026-01-01 00:00:00 [ERROR] ' + TEST_CRLF_MARKER + ' forged entry'#0#27'[31m".');
  if AToken = TEST_LONG_TOKEN then
    raise EIAM4DSecurityValidationException.Create(TEST_LONG_MARKER + StringOfChar('x', 20000));

  Result := True;
  if AToken = TEST_VALID_TOKEN then
    AClaims := ValidPayload(True, TEST_ISSUER, 'u-123', '')
  else if AToken = TEST_VALID_TOKEN_NO_IAT then
    AClaims := ValidPayload(False, TEST_ISSUER, 'u-123', '')
  else if AToken = TEST_OTHER_ISSUER_TOKEN then
    AClaims := ValidPayload(True, TEST_OTHER_ISSUER, 'u-123', '')
  else if AToken = TEST_BAD_RESOURCE_TOKEN then
    AClaims := ValidPayload(True, TEST_ISSUER, 'u-123', '"broken":"not an object","nullclient":null,')
  else if AToken = TEST_ROLES_DOWN_TOKEN then
    AClaims := ValidPayload(True, TEST_ISSUER, TEST_ROLES_DOWN_SUBJECT, '')
  else if AToken = TEST_NO_CLAIMS_TOKEN then
    // True without claims: what a broken custom validator may answer
  else
    Result := False;
end;

function TRuntimeTestValidator.GetClockSkewSeconds: Integer;
begin
  Result := FClockSkewSeconds;
end;

procedure TRuntimeTestValidator.SetClockSkewSeconds(const AValue: Integer);
begin
  FClockSkewSeconds := AValue;
end;

function TRuntimeTestValidator.GetExpectedIssuer: string;
begin
  Result := TEST_ISSUER;
end;

function TRuntimeTestValidator.GetExpectedAudience: string;
begin
  Result := TEST_AUDIENCE;
end;

function TRuntimeTestValidator.GetExpectedAzp: string;
begin
  Result := '';
end;

end.
