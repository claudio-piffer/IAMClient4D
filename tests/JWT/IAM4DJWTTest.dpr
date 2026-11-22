program IAM4DJWTTest;

{ Runtime test of TIAM4DJWTValidator and TIAM4DJWKSProvider.

  A fake identity provider (Indy HTTP server on 127.0.0.1:18781) serves OIDC discovery and
  JWKS for any /realms/<name> and counts the requests per path. Tokens and keys come from
  JWTTestVectorsU (gen_tokens.py); tokens that fail before the signature check are built here.

  Usage : IAM4DJWTTest
          Builds for Win32, Win64 and Linux64.
  Exit  : number of failed checks (0 = all passed, 99 = startup error). }

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Classes,
  System.JSON,
  System.SyncObjs,
  System.DateUtils,
  System.NetEncoding,
  System.Generics.Collections,
  IdContext,
  IdCustomHTTPServer,
  IdHTTPServer,
  IAMClient4D.Core,
  IAMClient4D.Exceptions,
  IAMClient4D.Common.Security,
  IAMClient4D.Security.Core,
  IAMClient4D.Security.JWT,
  IAMClient4D.Security.JWT.JWKS,
  JWTTestVectorsU in 'JWTTestVectorsU.pas';

const
  TEST_PORT = 18781;
  IDP_BASE = 'http://127.0.0.1:18781';
  ATTACKER_ISSUER = IDP_BASE + '/realms/attacker';
  DISCOVERY_SUFFIX = '/.well-known/openid-configuration';
  JWKS_SUFFIX = '/protocol/openid-connect/certs';
  TEST_DISCOVERY = '/realms/test' + DISCOVERY_SUFFIX;
  TEST_JWKS = '/realms/test' + JWKS_SUFFIX;
  // JWKS served without discovery (JWKS URL configured explicitly)
  CUSTOM_JWKS = '/custom/certs';
  SLOW_ISSUER = IDP_BASE + '/realms/slow';

type
  TDiscoveryIssuerMode = (dimRealm, dimCustom, dimMissing);

  /// <summary>Fake OIDC provider: discovery and JWKS for /realms/*, request counters.</summary>
  TFakeIdP = class
  private
    FServer: TIdHTTPServer;
    FLock: TCriticalSection;
    FCounts: TDictionary<string, Integer>;
    FKeys: string;
    FJWKSDelayMs: Integer;
    FJWKSDelayPrefix: string;
    FJWKSStatus: Integer;
    FIssuerMode: TDiscoveryIssuerMode;
    FIssuer: string;
    procedure CommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo;
      AResponseInfo: TIdHTTPResponseInfo);
  public
    constructor Create;
    destructor Destroy; override;
    /// <summary>Clears the counters and serves AKeys (JSON array items), no delay, status 200, realm issuer.</summary>
    procedure Reset(const AKeys: string);
    procedure SetKeys(const AKeys: string);
    /// <summary>Delays the JWKS responses whose path starts with APathPrefix (empty: all).</summary>
    procedure SetJWKSDelay(AMs: Integer; const APathPrefix: string = '');
    procedure SetJWKSStatus(AStatus: Integer);
    /// <summary>issuer of the discovery documents: the realm URL, AIssuer (dimCustom) or none.</summary>
    procedure SetDiscoveryIssuer(AMode: TDiscoveryIssuerMode; const AIssuer: string = '');
    function Count(const APath: string): Integer;
    function Total: Integer;
  end;

  /// <summary>
  /// Verifier for the parallel tests, which check the JWKS provider and not the crypto provider:
  /// accepts RS256 when the key returned for the kid is key 1.
  /// </summary>
  TKeyIdentityVerifier = class(TInterfacedObject, IIAM4DJWTSignatureVerifier)
  public
    function Verify(const ASigningInput: string; const ASignatureBytes: TBytes;
      const APublicKeyJWK: TJSONObject; const AAlg: string): Boolean;
    function GetSupportedAlgorithms: TArray<string>;
  end;

var
  GPassed: Integer = 0;
  GFailed: Integer = 0;
  GIdP: TFakeIdP;

{ TFakeIdP }

constructor TFakeIdP.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FCounts := TDictionary<string, Integer>.Create;
  FJWKSStatus := 200;
  FServer := TIdHTTPServer.Create(nil);
  FServer.Bindings.Clear;
  with FServer.Bindings.Add do
  begin
    IP := '127.0.0.1';
    Port := TEST_PORT;
  end;
  FServer.OnCommandGet := CommandGet;
  FServer.Active := True;
end;

destructor TFakeIdP.Destroy;
begin
  if Assigned(FServer) then
    FServer.Active := False;
  FServer.Free;
  FCounts.Free;
  FLock.Free;
  inherited;
end;

procedure TFakeIdP.CommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo;
  AResponseInfo: TIdHTTPResponseInfo);
var
  LPath, LRealmBase, LKeys, LDelayPrefix, LIssuer: string;
  LCount, LDelay, LStatus: Integer;
  LIssuerMode: TDiscoveryIssuerMode;
begin
  LPath := ARequestInfo.Document;
  FLock.Enter;
  try
    if not FCounts.TryGetValue(LPath, LCount) then
      LCount := 0;
    FCounts.AddOrSetValue(LPath, LCount + 1);
    LKeys := FKeys;
    LDelay := FJWKSDelayMs;
    LDelayPrefix := FJWKSDelayPrefix;
    LStatus := FJWKSStatus;
    LIssuerMode := FIssuerMode;
    LIssuer := FIssuer;
  finally
    FLock.Leave;
  end;

  AResponseInfo.ContentType := 'application/json';
  AResponseInfo.CharSet := 'utf-8';
  if LPath.StartsWith('/realms/') and LPath.EndsWith(DISCOVERY_SUFFIX) then
  begin
    LRealmBase := IDP_BASE + LPath.Substring(0, LPath.Length - DISCOVERY_SUFFIX.Length);
    AResponseInfo.ResponseNo := 200;
    case LIssuerMode of
      dimRealm:
        AResponseInfo.ContentText := Format('{"issuer":"%s","jwks_uri":"%s"}', [LRealmBase, LRealmBase + JWKS_SUFFIX]);
      dimCustom:
        AResponseInfo.ContentText := Format('{"issuer":"%s","jwks_uri":"%s"}', [LIssuer, LRealmBase + JWKS_SUFFIX]);
      dimMissing:
        AResponseInfo.ContentText := Format('{"jwks_uri":"%s"}', [LRealmBase + JWKS_SUFFIX]);
    end;
  end
  else if (LPath.StartsWith('/realms/') and LPath.EndsWith(JWKS_SUFFIX)) or (LPath = CUSTOM_JWKS) then
  begin
    if (LDelay > 0) and ((LDelayPrefix = '') or LPath.StartsWith(LDelayPrefix)) then
      Sleep(LDelay);
    AResponseInfo.ResponseNo := LStatus;
    if LStatus = 200 then
      AResponseInfo.ContentText := '{"keys":[' + LKeys + ']}'
    else
      AResponseInfo.ContentText := '{"error":"unavailable"}';
  end
  else
  begin
    AResponseInfo.ResponseNo := 404;
    AResponseInfo.ContentText := '{"error":"not found"}';
  end;
end;

procedure TFakeIdP.Reset(const AKeys: string);
begin
  FLock.Enter;
  try
    FCounts.Clear;
    FKeys := AKeys;
    FJWKSDelayMs := 0;
    FJWKSDelayPrefix := '';
    FJWKSStatus := 200;
    FIssuerMode := dimRealm;
    FIssuer := '';
  finally
    FLock.Leave;
  end;
end;

procedure TFakeIdP.SetDiscoveryIssuer(AMode: TDiscoveryIssuerMode; const AIssuer: string);
begin
  FLock.Enter;
  try
    FIssuerMode := AMode;
    FIssuer := AIssuer;
  finally
    FLock.Leave;
  end;
end;

procedure TFakeIdP.SetKeys(const AKeys: string);
begin
  FLock.Enter;
  try
    FKeys := AKeys;
  finally
    FLock.Leave;
  end;
end;

procedure TFakeIdP.SetJWKSDelay(AMs: Integer; const APathPrefix: string);
begin
  FLock.Enter;
  try
    FJWKSDelayMs := AMs;
    FJWKSDelayPrefix := APathPrefix;
  finally
    FLock.Leave;
  end;
end;

procedure TFakeIdP.SetJWKSStatus(AStatus: Integer);
begin
  FLock.Enter;
  try
    FJWKSStatus := AStatus;
  finally
    FLock.Leave;
  end;
end;

function TFakeIdP.Count(const APath: string): Integer;
begin
  FLock.Enter;
  try
    if not FCounts.TryGetValue(APath, Result) then
      Result := 0;
  finally
    FLock.Leave;
  end;
end;

function TFakeIdP.Total: Integer;
var
  LValue: Integer;
begin
  Result := 0;
  FLock.Enter;
  try
    for LValue in FCounts.Values do
      Inc(Result, LValue);
  finally
    FLock.Leave;
  end;
end;

{ TKeyIdentityVerifier }

function TKeyIdentityVerifier.Verify(const ASigningInput: string; const ASignatureBytes: TBytes;
  const APublicKeyJWK: TJSONObject; const AAlg: string): Boolean;
begin
  Result := (AAlg = 'RS256') and (APublicKeyJWK.GetValue<string>('kid', '') = KID_1);
end;

function TKeyIdentityVerifier.GetSupportedAlgorithms: TArray<string>;
begin
  Result := ['RS256'];
end;

{ Helpers }

procedure Check(ACondition: Boolean; const AName: string);
begin
  if ACondition then
  begin
    TInterlocked.Increment(GPassed);
    Writeln('  PASS ', AName);
  end
  else
  begin
    TInterlocked.Increment(GFailed);
    Writeln('  FAIL ', AName);
  end;
end;

function HTTPConfig: TIAM4DHTTPClientConfig;
begin
  Result := TIAM4DHTTPClientConfig.Create(2000, 5000, svmStrict);
end;

function NewValidator(const AIssuer: string; const AProvider: IIAM4DJWKSProvider;
  const AVerifier: IIAM4DJWTSignatureVerifier = nil): IIAM4DJWTValidator;
var
  LValidator: TIAM4DJWTValidator;
begin
  if Assigned(AVerifier) then
    LValidator := TIAM4DJWTValidator.Create(AIssuer, TEST_AUDIENCE, AVerifier, AProvider, HTTPConfig)
  else
    LValidator := TIAM4DJWTValidator.Create(AIssuer, TEST_AUDIENCE, AProvider, HTTPConfig);
  Result := LValidator;
  // Every call goes through the key lookup
  LValidator.SetTokenCacheEnabled(False);
end;

// True when the token is accepted; AError gets the exception otherwise
function Validate(const AValidator: IIAM4DJWTValidator; const AToken: string; out AError: string): Boolean;
var
  LClaims: TJSONObject;
begin
  AError := '';
  LClaims := nil;
  try
    try
      Result := AValidator.ValidateToken(AToken, LClaims) and Assigned(LClaims);
    except
      on E: Exception do
      begin
        Result := False;
        AError := E.ClassName + ': ' + E.Message;
      end;
    end;
  finally
    LClaims.Free;
  end;
end;

// ErrorCode of the rejection; ecUnknown when the token is accepted or the exception is not an EIAM4DException
function RejectionCode(const AValidator: IIAM4DJWTValidator; const AToken: string): TIAM4DErrorCode;
var
  LClaims: TJSONObject;
begin
  Result := ecUnknown;
  LClaims := nil;
  try
    try
      AValidator.ValidateToken(AToken, LClaims);
    except
      on E: EIAM4DException do
        Result := E.ErrorCode;
    end;
  finally
    LClaims.Free;
  end;
end;

function Accepted(const AValidator: IIAM4DJWTValidator; const AToken: string): Boolean;
var
  LError: string;
begin
  Result := Validate(AValidator, AToken, LError);
  if not Result then
    Writeln('    rejected: ', LError);
end;

function Rejected(const AValidator: IIAM4DJWTValidator; const AToken: string; const AExpected: string = ''): Boolean;
var
  LError: string;
begin
  Result := not Validate(AValidator, AToken, LError);
  if Result and (AExpected <> '') and not LError.Contains(AExpected) then
  begin
    Writeln('    unexpected error: ', LError);
    Result := False;
  end;
end;

function B64(const S: string): string;
begin
  Result := TNetEncoding.Base64URL.EncodeBytesToString(TEncoding.UTF8.GetBytes(S));
end;

// Token with a fake signature: rejected before (or at) the signature check
function MakeToken(const AAlg, AKid, AIssuer: string): string;
begin
  Result := B64(Format('{"alg":"%s","typ":"JWT","kid":"%s"}', [AAlg, AKid])) + '.' +
    B64(Format('{"iss":"%s","aud":"%s","sub":"forged","exp":4070908800}', [AIssuer, TEST_AUDIENCE])) + '.' +
    B64('not a signature');
end;

// Same, without kid: the first signing key of the JWKS is used
function MakeTokenWithoutKid(const AIssuer: string): string;
begin
  Result := B64('{"alg":"RS256","typ":"JWT"}') + '.' +
    B64(Format('{"iss":"%s","aud":"%s","sub":"forged","exp":4070908800}', [AIssuer, TEST_AUDIENCE])) + '.' +
    B64('not a signature');
end;

function RandomKidToken: string;
begin
  Result := MakeToken('RS256', TGUID.NewGuid.ToString, TEST_ISSUER);
end;

procedure Expect(const AName: string; AActual, AExpected: Integer);
begin
  Check(AActual = AExpected, Format('%s = %d (got %d)', [AName, AExpected, AActual]));
end;

procedure ExpectAtMost(const AName: string; AActual, AMax: Integer);
begin
  Check(AActual <= AMax, Format('%s <= %d (got %d)', [AName, AMax, AActual]));
end;

// Requests to APath reach ACount within ATimeoutMs (a background refresh ends a little later)
function WaitForCount(const APath: string; ACount: Integer; ATimeoutMs: Integer = 5000): Integer;
var
  LDeadline: UInt64;
begin
  LDeadline := TThread.GetTickCount64 + UInt64(ATimeoutMs);
  repeat
    Result := GIdP.Count(APath);
    if Result >= ACount then
      Exit;
    Sleep(20);
  until TThread.GetTickCount64 >= LDeadline;
end;

{ Tests }

procedure TestValidToken;
var
  LProvider: IIAM4DJWKSProvider;
  LValidator: IIAM4DJWTValidator;
  LClaims: TJSONObject;
  LAllAccepted: Boolean;
  I: Integer;
begin
  GIdP.Reset(JWK_1);
  LProvider := TIAM4DJWKSProvider.Create(HTTPConfig);
  LValidator := NewValidator(TEST_ISSUER, LProvider);

  LClaims := nil;
  try
    Check(LValidator.ValidateToken(TOKEN_RS256, LClaims) and Assigned(LClaims), 'RS256 token accepted');
    Check(Assigned(LClaims) and (LClaims.GetValue<string>('sub', '') = 'user-1'), 'claims returned');
  finally
    LClaims.Free;
  end;
  Expect('discovery requests', GIdP.Count(TEST_DISCOVERY), 1);
  Expect('JWKS requests', GIdP.Count(TEST_JWKS), 1);

  LAllAccepted := True;
  for I := 1 to 10 do
    LAllAccepted := Accepted(LValidator, TOKEN_RS256) and LAllAccepted;
  Check(LAllAccepted, 'accepted again from the key cache');
  Expect('requests after 10 more validations', GIdP.Total, 2);

  Check(Rejected(LValidator, TOKEN_RS256.Substring(0, TOKEN_RS256.Length - 4) + 'AAAA',
    'EIAM4DJWTSignatureInvalidException: JWT signature verification failed'),
    'tampered signature rejected (EIAM4DJWTSignatureInvalidException)');
end;

// Explicit typing (typ claim), header crit, canonical base64url
// Same bytes, other string: the next character of the alphabet sets an unused bit of the last
// character (the signature of an RSA-2048 token has 342 characters, 4 unused bits)
function NonCanonicalLastChar(const AToken: string): string;
const
  ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
var
  LLast: Char;
begin
  LLast := AToken[High(AToken)];
  Result := AToken.Substring(0, AToken.Length - 1) + ALPHABET[ALPHABET.IndexOf(LLast) + 2];
end;

procedure TestTokenFormat;
var
  LValidatorObj: TIAM4DJWTValidator;
  LValidator: IIAM4DJWTValidator;
  LToken, LError: string;
  LRaised: Boolean;
begin
  GIdP.Reset(JWK_1);
  LValidatorObj := TIAM4DJWTValidator.Create(TEST_ISSUER, TEST_AUDIENCE, TIAM4DJWKSProvider.Create(HTTPConfig), HTTPConfig);
  LValidator := LValidatorObj;
  LValidatorObj.SetTokenCacheEnabled(False);
  LValidatorObj.SetExpectedTokenType('Bearer');
  Check(Accepted(LValidator, TOKEN_RS256), 'expected type Bearer: token without typ claim accepted');

  LToken := B64(Format('{"alg":"RS256","typ":"JWT","kid":"%s"}', [KID_1])) + '.' +
    B64(Format('{"iss":"%s","aud":"%s","sub":"x","typ":"ID","exp":4070908800}', [TEST_ISSUER, TEST_AUDIENCE])) + '.' +
    B64('not a signature');
  Check(Rejected(LValidator, LToken, 'is not the expected token type "Bearer"'),
    'ID token (typ ID) refused where an access token is expected');

  LToken := B64(Format('{"alg":"RS256","typ":"JWT","kid":"%s","crit":["b64"],"b64":false}', [KID_1])) + '.' +
    B64(Format('{"iss":"%s","aud":"%s","sub":"x","exp":4070908800}', [TEST_ISSUER, TEST_AUDIENCE])) + '.' +
    B64('not a signature');
  Check(Rejected(LValidator, LToken, 'crit lists extensions'), 'header crit refused (RFC 7515 4.1.11)');

  // Strings that decode to the same bytes as the signed token
  Check(Rejected(LValidator, TOKEN_RS256 + '==', 'base64url without padding'), 'padding refused');
  Check(Rejected(LValidator, TOKEN_RS256.Insert(TOKEN_RS256.Length - 10, '!'), 'base64url without padding'),
    'character outside the base64url alphabet refused');
  Check(Rejected(LValidator, NonCanonicalLastChar(TOKEN_RS256), 'base64url without padding'),
    'unused bits of the last character set refused (same signature bytes)');
  Check(Accepted(LValidator, TOKEN_RS256), 'the canonical token is still accepted');

  // Malformed compact serialization
  Check(Rejected(LValidator, '', 'must have 3 parts'), 'empty token refused');
  LToken := TOKEN_RS256.Substring(0, TOKEN_RS256.LastIndexOf('.'));
  Check(Rejected(LValidator, LToken, 'must have 3 parts'), 'token with 2 parts refused');
  Check(Rejected(LValidator, TOKEN_RS256 + '.' + B64('x'), 'must have 3 parts'), 'token with 4 parts refused');
  LToken := B64('not json') + TOKEN_RS256.Substring(TOKEN_RS256.IndexOf('.'));
  Check(Rejected(LValidator, LToken), 'header that is not JSON refused');
  LToken := B64(Format('{"alg":"RS256","typ":"at+jwt","kid":"%s"}', [KID_1])) +
    TOKEN_RS256.Substring(TOKEN_RS256.IndexOf('.'));
  Check(Rejected(LValidator, LToken, 'typ is missing or not "JWT"'), 'header typ other than JWT refused');
  LToken := B64(Format('{"alg":"RS256","kid":"%s"}', [KID_1])) + TOKEN_RS256.Substring(TOKEN_RS256.IndexOf('.'));
  Check(Rejected(LValidator, LToken, 'typ is missing or not "JWT"'), 'header without typ refused');

  // RFC 9068: header typ at+jwt when allowed (the typ check comes before the signature)
  LValidatorObj.SetAllowedHeaderTypes(['JWT', 'at+jwt']);
  Check(Accepted(LValidator, TOKEN_RS256), 'JWT and at+jwt allowed: typ JWT still accepted');
  LToken := B64(Format('{"alg":"RS256","typ":"at+jwt","kid":"%s"}', [KID_1])) +
    TOKEN_RS256.Substring(TOKEN_RS256.IndexOf('.'));
  Check((not Validate(LValidator, LToken, LError)) and not LError.Contains('typ'),
    'at+jwt allowed: passes the typ check, refused only for its signature (' + LError + ')');
  LToken := B64(Format('{"alg":"RS256","typ":"application/AT+JWT","kid":"%s"}', [KID_1])) +
    TOKEN_RS256.Substring(TOKEN_RS256.IndexOf('.'));
  Check((not Validate(LValidator, LToken, LError)) and not LError.Contains('typ'),
    'application/AT+JWT: same type, any case (RFC 7515 4.1.9) (' + LError + ')');
  LToken := B64(Format('{"alg":"RS256","typ":"dpop+jwt","kid":"%s"}', [KID_1])) +
    TOKEN_RS256.Substring(TOKEN_RS256.IndexOf('.'));
  Check(Rejected(LValidator, LToken, 'is missing or not one of jwt, at+jwt'), 'other header typ still refused');
  LValidatorObj.SetAllowedHeaderTypes(['at+jwt']);
  Check(Rejected(LValidator, TOKEN_RS256, 'is missing or not one of at+jwt'), 'only at+jwt allowed: typ JWT refused');
  LRaised := False;
  try
    LValidatorObj.SetAllowedHeaderTypes([]);
  except
    on EArgumentException do
      LRaised := True;
  end;
  Check(LRaised, 'empty list of header types refused');
end;

procedure TestAlgCase;
var
  LProvider: IIAM4DJWKSProvider;
  LValidator: IIAM4DJWTValidator;
begin
  GIdP.Reset(JWK_1);
  LProvider := TIAM4DJWKSProvider.Create(HTTPConfig);
  LValidator := NewValidator(TEST_ISSUER, LProvider);

  Check(Accepted(LValidator, TOKEN_RS256), 'alg RS256 accepted');
  Check(Rejected(LValidator, TOKEN_LOWERCASE_ALG, 'not allowed'), 'alg rs256 (validly signed) rejected by the allow-list');
  (LValidator as TIAM4DJWTValidator).SetAllowedAlgs(['RS256']);
  Check(Rejected(LValidator, TOKEN_LOWERCASE_ALG, 'not allowed'), 'alg rs256 rejected with allow-list [RS256]');
  Check(Accepted(LValidator, TOKEN_RS256), 'alg RS256 accepted with allow-list [RS256]');
  Check(Rejected(LValidator, MakeToken('none', KID_1, TEST_ISSUER), 'alg=none'), 'alg none rejected');
  Check(Rejected(LValidator, MakeToken('NONE', KID_1, TEST_ISSUER), 'alg=none'), 'alg NONE rejected');
  Check(Rejected(LValidator, MakeToken('None', KID_1, TEST_ISSUER), 'alg=none'), 'alg None rejected');
end;

procedure TestIssuerNotConfigured;
var
  LValidator: IIAM4DJWTValidator;
begin
  GIdP.Reset(JWK_1);
  LValidator := NewValidator('', TIAM4DJWKSProvider.Create(HTTPConfig));
  Check(Rejected(LValidator, MakeToken('RS256', KID_1, ATTACKER_ISSUER)), 'empty issuer: token of any issuer rejected');
  Check(Rejected(LValidator, TOKEN_RS256), 'empty issuer: validly signed token rejected');
  Expect('empty issuer: requests to the identity provider', GIdP.Total, 0);

  GIdP.Reset(JWK_1);
  LValidator := NewValidator('/', TIAM4DJWKSProvider.Create(HTTPConfig));
  Check(Rejected(LValidator, MakeToken('RS256', KID_1, ATTACKER_ISSUER)), 'issuer "/": token rejected');
  Expect('issuer "/": requests to the identity provider', GIdP.Total, 0);

  GIdP.Reset(JWK_1);
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig));
  Check(Rejected(LValidator, MakeToken('RS256', KID_1, ATTACKER_ISSUER), 'EIAM4DJWTIssuerMismatchException: Invalid issuer'),
    'other issuer rejected (EIAM4DJWTIssuerMismatchException)');
  Expect('other issuer: requests to the identity provider', GIdP.Total, 0);
end;

procedure TestUnknownKidStorm;
var
  LProviderObj: TIAM4DJWKSProvider;
  LProvider: IIAM4DJWKSProvider;
  LValidator: IIAM4DJWTValidator;
  LAllRejected: Boolean;
  I: Integer;
begin
  GIdP.Reset(JWK_1);
  LProviderObj := TIAM4DJWKSProvider.Create(HTTPConfig);
  LProvider := LProviderObj;
  LValidator := NewValidator(TEST_ISSUER, LProvider);

  LAllRejected := True;
  for I := 1 to 200 do
    LAllRejected := Rejected(LValidator, RandomKidToken) and LAllRejected;
  Check(LAllRejected, '200 tokens with random kids rejected');
  ExpectAtMost('discovery requests', GIdP.Count(TEST_DISCOVERY), 1);
  ExpectAtMost('JWKS requests', GIdP.Count(TEST_JWKS), 1);
  ExpectAtMost('negative cache entries', LProviderObj.NegativeKidCacheCount, 1);

  Check(Accepted(LValidator, TOKEN_RS256), 'known kid accepted after the storm');
  ExpectAtMost('requests after the storm', GIdP.Total, 2);
end;

procedure TestParallelStorm;
const
  THREADS = 16;
  ROUNDS = 20;
var
  LProvider: IIAM4DJWKSProvider;
  LValidator: IIAM4DJWTValidator;
  LThreads: TArray<TThread>;
  LWrong, LAccepted: Integer;
  I: Integer;
begin
  GIdP.Reset(JWK_1);
  GIdP.SetJWKSDelay(300);
  LProvider := TIAM4DJWKSProvider.Create(HTTPConfig);
  LValidator := NewValidator(TEST_ISSUER, LProvider, TKeyIdentityVerifier.Create);
  LWrong := 0;
  LAccepted := 0;

  // Cold start: every thread arrives while the first JWKS request is in flight
  SetLength(LThreads, THREADS);
  for I := 0 to THREADS - 1 do
  begin
    LThreads[I] := TThread.CreateAnonymousThread(
      procedure
      var
        J: Integer;
        LError: string;
      begin
        for J := 0 to ROUNDS - 1 do
          if J mod 4 = 0 then
          begin
            if Validate(LValidator, TOKEN_RS256, LError) then
              TInterlocked.Increment(LAccepted)
            else
              TInterlocked.Increment(LWrong);
          end
          else if Validate(LValidator, RandomKidToken, LError) then
            TInterlocked.Increment(LWrong);
      end);
    LThreads[I].FreeOnTerminate := False;
  end;
  for I := 0 to THREADS - 1 do
    LThreads[I].Start;
  for I := 0 to THREADS - 1 do
  begin
    LThreads[I].WaitFor;
    LThreads[I].Free;
  end;

  Expect('valid tokens accepted', LAccepted, THREADS * (ROUNDS div 4));
  Expect('wrong outcomes', LWrong, 0);
  Expect('discovery requests', GIdP.Count(TEST_DISCOVERY), 1);
  Expect('JWKS requests', GIdP.Count(TEST_JWKS), 1);
end;

procedure TestRefreshInterval;
var
  LProviderObj: TIAM4DJWKSProvider;
  LProvider: IIAM4DJWKSProvider;
  LValidator: IIAM4DJWTValidator;
begin
  GIdP.Reset(JWK_1);
  LProviderObj := TIAM4DJWKSProvider.Create(HTTPConfig);
  LProvider := LProviderObj;
  LProviderObj.SetMinRefreshIntervalSeconds(1);
  LValidator := NewValidator(TEST_ISSUER, LProvider);

  Check(Accepted(LValidator, TOKEN_RS256), 'key 1 accepted');
  // Key rotation: the provider now publishes key 2 too
  GIdP.SetKeys(JWK_1 + ',' + JWK_2);
  Check(Rejected(LValidator, TOKEN_KEY_2), 'key 2 rejected within the refresh interval');
  Expect('JWKS requests within the interval', GIdP.Count(TEST_JWKS), 1);

  Sleep(1200);
  Check(Accepted(LValidator, TOKEN_KEY_2), 'key 2 accepted after the interval');
  Expect('JWKS requests after the interval', GIdP.Count(TEST_JWKS), 2);
  Expect('discovery requests (cached)', GIdP.Count(TEST_DISCOVERY), 1);
  Check(Rejected(LValidator, RandomKidToken), 'random kid rejected');
  Expect('JWKS requests after a random kid', GIdP.Count(TEST_JWKS), 2);
end;

procedure TestNegativeCacheBound;
var
  LProviderObj: TIAM4DJWKSProvider;
  LProvider: IIAM4DJWKSProvider;
  LValidator: IIAM4DJWTValidator;
  LAllRejected: Boolean;
  I: Integer;
begin
  GIdP.Reset(JWK_1);
  LProviderObj := TIAM4DJWKSProvider.Create(HTTPConfig);
  LProvider := LProviderObj;
  // No rate limit: every unknown kid reaches the identity provider and the negative cache
  LProviderObj.SetMinRefreshIntervalSeconds(0);
  LProviderObj.SetMaxNegativeKidEntries(10);
  LValidator := NewValidator(TEST_ISSUER, LProvider);

  LAllRejected := True;
  for I := 1 to 50 do
    LAllRejected := Rejected(LValidator, RandomKidToken) and LAllRejected;
  Check(LAllRejected, '50 tokens with random kids rejected');
  ExpectAtMost('negative cache entries', LProviderObj.NegativeKidCacheCount, 10);
  Expect('JWKS requests (one per unknown kid)', GIdP.Count(TEST_JWKS), 50);
  Expect('discovery requests (cached)', GIdP.Count(TEST_DISCOVERY), 1);
end;

procedure TestStaleKeys;
const
  THREADS = 8;
var
  LProviderObj: TIAM4DJWKSProvider;
  LProvider: IIAM4DJWKSProvider;
  LValidator, LParallelValidator: IIAM4DJWTValidator;
  LThreads: TArray<TThread>;
  LRejectedCount, LJWKS: Integer;
  I: Integer;
begin
  GIdP.Reset(JWK_1);
  LProviderObj := TIAM4DJWKSProvider.Create(HTTPConfig);
  LProvider := LProviderObj;
  LProvider.SetCacheTTL(1);
  // Interval well above the time of one refresh on a loaded machine: no retry between two checks
  LProviderObj.SetMinRefreshIntervalSeconds(3);
  LValidator := NewValidator(TEST_ISSUER, LProvider);

  Check(Accepted(LValidator, TOKEN_RS256), 'key cached');
  GIdP.SetJWKSStatus(404);
  Sleep(3200);
  Check(Accepted(LValidator, TOKEN_RS256), 'expired key served while the JWKS endpoint fails');
  // The refresh of the expired key runs in the background
  Expect('JWKS requests (one failed refresh)', WaitForCount(TEST_JWKS, 2), 2);
  // Its failure recorded before the next check
  Sleep(200);
  Check(Accepted(LValidator, TOKEN_RS256), 'expired key served again');
  Expect('JWKS requests (no retry within the interval)', GIdP.Count(TEST_JWKS), 2);

  // Endpoint back, slow: one refresh, the other threads use the expired key meanwhile
  GIdP.SetJWKSStatus(200);
  GIdP.SetJWKSDelay(300);
  Sleep(3200);
  LParallelValidator := NewValidator(TEST_ISSUER, LProvider, TKeyIdentityVerifier.Create);
  LJWKS := GIdP.Count(TEST_JWKS);
  LRejectedCount := 0;
  SetLength(LThreads, THREADS);
  for I := 0 to THREADS - 1 do
  begin
    LThreads[I] := TThread.CreateAnonymousThread(
      procedure
      var
        J: Integer;
        LError: string;
      begin
        for J := 1 to 10 do
          if not Validate(LParallelValidator, TOKEN_RS256, LError) then
            TInterlocked.Increment(LRejectedCount);
      end);
    LThreads[I].FreeOnTerminate := False;
  end;
  for I := 0 to THREADS - 1 do
    LThreads[I].Start;
  for I := 0 to THREADS - 1 do
  begin
    LThreads[I].WaitFor;
    LThreads[I].Free;
  end;
  Expect('rejections during the refresh', LRejectedCount, 0);
  Expect('JWKS requests for the expired key', WaitForCount(TEST_JWKS, LJWKS + 1) - LJWKS, 1);
  // Background refresh of 300 ms: nothing more once it is over
  Sleep(500);
  Expect('JWKS requests after the refresh', GIdP.Count(TEST_JWKS) - LJWKS, 1);
end;

procedure TestStaleWhileRevalidate;
var
  LProviderObj: TIAM4DJWKSProvider;
  LProvider: IIAM4DJWKSProvider;
  LValidator: IIAM4DJWTValidator;
  LStart: UInt64;
  LElapsed, LJWKS: Integer;
begin
  GIdP.Reset(JWK_1);
  LProviderObj := TIAM4DJWKSProvider.Create(HTTPConfig);
  LProvider := LProviderObj;
  LProvider.SetCacheTTL(1);
  LProviderObj.SetMinRefreshIntervalSeconds(1);
  LValidator := NewValidator(TEST_ISSUER, LProvider);
  Check(Accepted(LValidator, TOKEN_RS256), 'key cached');

  // Key expired, identity provider slow: the request does not wait for the refresh
  GIdP.SetJWKSDelay(2000);
  Sleep(2200);
  LJWKS := GIdP.Count(TEST_JWKS);
  LStart := TThread.GetTickCount64;
  Check(Accepted(LValidator, TOKEN_RS256), 'expired key served at once');
  LElapsed := TThread.GetTickCount64 - LStart;
  Check(LElapsed < 1000, Format('validation did not wait for the slow JWKS endpoint (%d ms)', [LElapsed]));
  Expect('one background refresh', WaitForCount(TEST_JWKS, LJWKS + 1) - LJWKS, 1);
  Check(Accepted(LValidator, TOKEN_RS256), 'served during the refresh');
  Expect('no second refresh while one runs', GIdP.Count(TEST_JWKS) - LJWKS, 1);
  // The refresh ends: fresh key, no request
  Sleep(2500);
  GIdP.SetJWKSDelay(0);
  LJWKS := GIdP.Count(TEST_JWKS);
  Check(Accepted(LValidator, TOKEN_RS256), 'key fresh after the refresh');
  Expect('fresh key: no request', GIdP.Count(TEST_JWKS) - LJWKS, 0);

  // Key withdrawn: the background refresh stores the new set, the old kid stops validating
  GIdP.SetKeys(JWK_2);
  Sleep(2200);
  LJWKS := GIdP.Count(TEST_JWKS);
  Check(Accepted(LValidator, TOKEN_RS256), 'withdrawn key served once, while its JWKS is refreshed');
  WaitForCount(TEST_JWKS, LJWKS + 1);
  Sleep(300);
  Check(Rejected(LValidator, TOKEN_RS256), 'withdrawn key refused after the refresh');
  Check(Accepted(LValidator, TOKEN_KEY_2), 'the new key validates');

  LValidator := nil;
  LProvider := nil;
end;

procedure TestKeyUse;
var
  LEncKey1, LJWK1Enc, LJWK1Encrypt, LJWK1Verify: string;
  LValidator: IIAM4DJWTValidator;
begin
  // RFC 7517 4.2/4.3: keys for encryption must not verify signatures
  LEncKey1 := JWK_1.Replace('"kid":"test-key-1","use":"sig"', '"kid":"enc-1","use":"enc"');
  LJWK1Enc := JWK_1.Replace('"use":"sig"', '"use":"enc"');
  LJWK1Encrypt := JWK_1.Replace('"use":"sig"', '"key_ops":["encrypt"]');
  LJWK1Verify := JWK_1.Replace('"use":"sig"', '"key_ops":["verify"]');

  GIdP.Reset(LEncKey1 + ',' + JWK_1);
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig), TKeyIdentityVerifier.Create);
  Check(Accepted(LValidator, MakeTokenWithoutKid(TEST_ISSUER)), 'token without kid: the "use":"enc" key listed first is skipped');

  GIdP.Reset(LJWK1Enc);
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig));
  Check(Rejected(LValidator, TOKEN_RS256), 'key with matching kid and "use":"enc" not used');

  GIdP.Reset(LJWK1Encrypt);
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig));
  Check(Rejected(LValidator, TOKEN_RS256), 'key with "key_ops":["encrypt"] not used');

  GIdP.Reset(LJWK1Verify);
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig));
  Check(Accepted(LValidator, TOKEN_RS256), 'key with "key_ops":["verify"] used');
end;

procedure TestKeyAlg;

  procedure CheckKey(const AJWK, AName: string; AAccepted: Boolean);
  var
    LValidator: IIAM4DJWTValidator;
  begin
    GIdP.Reset(AJWK);
    LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig));
    if AAccepted then
      Check(Accepted(LValidator, TOKEN_RS256), AName)
    else
      Check(Rejected(LValidator, TOKEN_RS256, 'does not match'), AName);
  end;

begin
  // RFC 7517 4.4, RFC 8725 3.1: same RSA key, token RS256 (PS256 is allowed by policy too)
  CheckKey(JWK_1, 'key "alg":"RS256" verifies an RS256 token', True);
  CheckKey(JWK_1.Replace('"alg":"RS256",', ''), 'key without alg verifies an RS256 token', True);
  CheckKey(JWK_1.Replace('"alg":"RS256"', '"alg":"PS256"'), 'key "alg":"PS256" does not verify an RS256 token', False);
  CheckKey(JWK_1.Replace('"alg":"RS256"', '"alg":"rs256"'), 'key "alg":"rs256" does not verify an RS256 token (case-sensitive)', False);
  CheckKey(JWK_1.Replace('"alg":"RS256"', '"alg":256'), 'key with a non-string alg not used', False);
end;

procedure TestDiscoveryIssuer;
var
  LValidator: IIAM4DJWTValidator;
begin
  // OpenID Connect Discovery 1.0 4.3: the issuer of the document must be the requested one
  GIdP.Reset(JWK_1);
  GIdP.SetDiscoveryIssuer(dimCustom, IDP_BASE + '/realms/other');
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig));
  Check(Rejected(LValidator, TOKEN_RS256, 'issuer'), 'discovery document of another issuer rejected');
  Expect('JWKS requests after a wrong discovery issuer', GIdP.Count(TEST_JWKS), 0);

  GIdP.Reset(JWK_1);
  GIdP.SetDiscoveryIssuer(dimMissing);
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig));
  Check(Rejected(LValidator, TOKEN_RS256, 'issuer'), 'discovery document without issuer rejected');
  Expect('JWKS requests without discovery issuer', GIdP.Count(TEST_JWKS), 0);

  GIdP.Reset(JWK_1);
  GIdP.SetDiscoveryIssuer(dimCustom, TEST_ISSUER + '/');
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig));
  Check(Accepted(LValidator, TOKEN_RS256), 'discovery issuer with a trailing "/" accepted (same normalization as iss)');
end;

// RetryAfterSeconds of the EIAM4DJWKSUnavailableException raised, -1 for any other outcome
function UnavailableRetryAfter(const AValidator: IIAM4DJWTValidator; const AToken: string): Integer;
var
  LClaims: TJSONObject;
begin
  Result := -1;
  LClaims := nil;
  try
    try
      AValidator.ValidateToken(AToken, LClaims);
    except
      on E: Exception do
        if E is EIAM4DJWKSUnavailableException then
          Result := EIAM4DJWKSUnavailableException(E).RetryAfterSeconds;
    end;
  finally
    LClaims.Free;
  end;
end;

procedure TestUnavailable;
var
  LProviderObj: TIAM4DJWKSProvider;
  LProvider: IIAM4DJWKSProvider;
  LValidator: IIAM4DJWTValidator;
  LRetryAfter: Integer;
begin
  // Identity provider failing: EIAM4DJWKSUnavailableException, not a token error
  GIdP.Reset(JWK_1);
  GIdP.SetJWKSStatus(500);
  LProviderObj := TIAM4DJWKSProvider.Create(HTTPConfig);
  LProvider := LProviderObj;
  LProviderObj.SetMinRefreshIntervalSeconds(20);
  LValidator := NewValidator(TEST_ISSUER, LProvider);
  LRetryAfter := UnavailableRetryAfter(LValidator, TOKEN_RS256);
  Check(LRetryAfter = 20, Format('JWKS endpoint failing: unavailable, retry after the interval (%d)', [LRetryAfter]));
  LRetryAfter := UnavailableRetryAfter(LValidator, TOKEN_RS256);
  Check((LRetryAfter >= 1) and (LRetryAfter <= 20),
    Format('within the interval: unavailable, retry after the remaining seconds (%d)', [LRetryAfter]));

  GIdP.Reset(JWK_1);
  GIdP.SetDiscoveryIssuer(dimCustom, IDP_BASE + '/realms/other');
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig));
  Check(UnavailableRetryAfter(LValidator, TOKEN_RS256) >= 0, 'wrong discovery issuer: unavailable');

  GIdP.Reset(JWK_1);
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig));
  Check(Rejected(LValidator, RandomKidToken, 'not found') and (UnavailableRetryAfter(LValidator, RandomKidToken) = -1),
    'unknown kid with the identity provider up: token error, not unavailable');
  Check(Rejected(LValidator, MakeToken('RS256', 'missing-kid', TEST_ISSUER), 'EIAM4DJWKSKeyNotFoundException: Public key with kid') and
    Rejected(LValidator, MakeToken('RS256', 'missing-kid', TEST_ISSUER), 'EIAM4DJWKSKeyNotFoundException: Public key with kid "missing-kid"'),
    'unknown kid: EIAM4DJWKSKeyNotFoundException, also within the refresh interval or from the negative cache');
end;

procedure TestStaticJWKSUri;
var
  LProviderObj: TIAM4DJWKSProvider;
  LProvider: IIAM4DJWKSProvider;
  LValidator: IIAM4DJWTValidator;
begin
  GIdP.Reset(JWK_1);
  LProviderObj := TIAM4DJWKSProvider.Create(HTTPConfig);
  LProvider := LProviderObj;
  LProviderObj.SetJWKSUri(TEST_ISSUER + '/', IDP_BASE + CUSTOM_JWKS);
  LValidator := NewValidator(TEST_ISSUER, LProvider);
  Check(Accepted(LValidator, TOKEN_RS256), 'SetJWKSUri: token accepted');
  Expect('SetJWKSUri: discovery requests', GIdP.Count(TEST_DISCOVERY), 0);
  Expect('SetJWKSUri: requests to the configured JWKS', GIdP.Count(CUSTOM_JWKS), 1);

  LProvider.ClearCache;
  Check(Accepted(LValidator, TOKEN_RS256), 'SetJWKSUri kept by ClearCache');
  Expect('discovery requests after ClearCache', GIdP.Count(TEST_DISCOVERY), 0);

  LProviderObj.SetJWKSUri(TEST_ISSUER, '');
  LProvider.ClearCache;
  Check(Accepted(LValidator, TOKEN_RS256), 'empty JWKS URI: discovery again');
  Expect('discovery requests after reset', GIdP.Count(TEST_DISCOVERY), 1);
end;

procedure TestSlowIssuerIsolation;
var
  LProvider: IIAM4DJWKSProvider;
  LFast, LSlow: IIAM4DJWTValidator;
  LThread: TThread;
  LStart: TDateTime;
  LElapsedMs: Int64;
begin
  // One provider for two issuers: a slow JWKS endpoint must not delay the other issuer
  GIdP.Reset(JWK_1);
  GIdP.SetJWKSDelay(1500, '/realms/slow/');
  LProvider := TIAM4DJWKSProvider.Create(HTTPConfig);
  LFast := NewValidator(TEST_ISSUER, LProvider);
  LSlow := NewValidator(SLOW_ISSUER, LProvider);

  LThread := TThread.CreateAnonymousThread(
    procedure
    var
      LError: string;
    begin
      Validate(LSlow, MakeToken('RS256', KID_1, SLOW_ISSUER), LError);
    end);
  LThread.FreeOnTerminate := False;
  LThread.Start;
  try
    // Wait until the slow JWKS request is in flight
    LStart := Now;
    while (GIdP.Count('/realms/slow' + JWKS_SUFFIX) = 0) and (MilliSecondsBetween(Now, LStart) < 3000) do
      Sleep(10);
    LStart := Now;
    Check(Accepted(LFast, TOKEN_RS256), 'other issuer accepted while a JWKS request is slow');
    LElapsedMs := MilliSecondsBetween(Now, LStart);
    Check(LElapsedMs < 1000, Format('other issuer not blocked (%d ms, slow JWKS 1500 ms)', [LElapsedMs]));
  finally
    LThread.WaitFor;
    LThread.Free;
  end;
end;

procedure TestTokenCache;
const
  THREADS = 8;
  ROUNDS = 200;
var
  LValidatorObj: TIAM4DJWTValidator;
  LValidator: IIAM4DJWTValidator;
  LClaims: TJSONObject;
  LThreads: TArray<TThread>;
  LRejectedCount: Integer;
  I: Integer;
  LAllAccepted: Boolean;
begin
  GIdP.Reset(JWK_1 + ',' + JWK_2);
  LValidatorObj := TIAM4DJWTValidator.Create(TEST_ISSUER, TEST_AUDIENCE, TIAM4DJWKSProvider.Create(HTTPConfig), HTTPConfig);
  LValidator := LValidatorObj;

  Check(Accepted(LValidator, TOKEN_RS256), 'token validated and cached');
  // Cache hit: the caller owns the returned claims
  LClaims := nil;
  try
    Check(LValidator.ValidateToken(TOKEN_RS256, LClaims) and Assigned(LClaims), 'cache hit returns claims');
    if Assigned(LClaims) then
      LClaims.AddPair('injected', 'x');
  finally
    LClaims.Free;
  end;
  LClaims := nil;
  try
    Check(LValidator.ValidateToken(TOKEN_RS256, LClaims) and Assigned(LClaims) and
      (LClaims.GetValue('injected') = nil) and (LClaims.GetValue<string>('sub', '') = 'user-1'),
      'cache hit claims independent of a previous caller''s copy');
  finally
    LClaims.Free;
  end;
  Expect('JWKS requests with the token cache', GIdP.Count(TEST_JWKS), 1);

  LRejectedCount := 0;
  SetLength(LThreads, THREADS);
  for I := 0 to THREADS - 1 do
  begin
    LThreads[I] := TThread.CreateAnonymousThread(
      procedure
      var
        J: Integer;
        LError: string;
      begin
        for J := 1 to ROUNDS do
          if not Validate(LValidator, TOKEN_RS256, LError) then
            TInterlocked.Increment(LRejectedCount);
      end);
    LThreads[I].FreeOnTerminate := False;
  end;
  for I := 0 to THREADS - 1 do
    LThreads[I].Start;
  for I := 0 to THREADS - 1 do
  begin
    LThreads[I].WaitFor;
    LThreads[I].Free;
  end;
  Expect('rejections among concurrent cache hits', LRejectedCount, 0);

  // One entry: every token evicts the other
  LValidatorObj.SetMaxTokenCacheEntries(1);
  LAllAccepted := True;
  for I := 1 to 5 do
    LAllAccepted := Accepted(LValidator, TOKEN_RS256) and Accepted(LValidator, TOKEN_KEY_2) and LAllAccepted;
  Check(LAllAccepted, 'tokens accepted with one cache entry (LRU eviction)');
end;

// Token for TKeyIdentityVerifier with claims relative to now (UTC); AExtra is appended to the payload
function MakeTimedToken(AExpOffset: Int64; const AExtra: string = ''): string;
var
  LNow: Int64;
begin
  LNow := DateTimeToUnix(TDateTime.NowUTC);
  Result := B64(Format('{"alg":"RS256","typ":"JWT","kid":"%s"}', [KID_1])) + '.' +
    B64(Format('{"iss":"%s","aud":"%s","sub":"timed","exp":%d%s}',
      [TEST_ISSUER, TEST_AUDIENCE, LNow + AExpOffset, AExtra])) + '.' +
    B64('not a signature');
end;

// "nbf"/"iat" at now + AOffset seconds
function TimeClaim(const AName: string; AOffset: Int64): string;
begin
  Result := Format(',"%s":%d', [AName, DateTimeToUnix(TDateTime.NowUTC) + AOffset]);
end;

procedure TestDuplicateKid;
var
  LECKey: string;
  LValidator: IIAM4DJWTValidator;
begin
  // RFC 7517 4.5: keys of different types may share a kid. The EC key comes first: the RS256
  // token must get the RSA key, after the refresh and from the cache
  LECKey := Format('{"kty":"EC","crv":"P-256","kid":"%s","use":"sig","alg":"ES256",' +
    '"x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}', [KID_1]);
  GIdP.Reset(LECKey + ',' + JWK_1);
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig), TKeyIdentityVerifier.Create);
  Check(Accepted(LValidator, MakeTimedToken(600)), 'kid shared by an EC and an RSA key: RS256 token gets the RSA key');
  Check(Accepted(LValidator, MakeTimedToken(600)), 'same token from the key cache');
  Expect('JWKS requests for the shared kid', GIdP.Count(TEST_JWKS), 1);

  // Only the EC key under the kid: no RSA key for the RS256 token
  GIdP.Reset(LECKey);
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig), TKeyIdentityVerifier.Create);
  Check(Rejected(LValidator, MakeTimedToken(600), 'not found'), 'only an EC key with the kid: RS256 token rejected');
end;

procedure TestTimeClaims;
var
  LValidator: IIAM4DJWTValidator;
begin
  GIdP.Reset(JWK_1);
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig), TKeyIdentityVerifier.Create);
  LValidator.SetClockSkewSeconds(60);

  Check(Accepted(LValidator, MakeTimedToken(-30)), 'exp 30 s ago accepted (skew 60 s)');
  Check(Rejected(LValidator, B64(Format('{"alg":"RS256","typ":"JWT","kid":"%s"}', [KID_1])) + '.' +
    B64(Format('{"iss":"%s","aud":"%s","sub":"timed"}', [TEST_ISSUER, TEST_AUDIENCE])) + '.' + B64('not a signature'),
    'expiration time claim (exp)'), 'token without exp rejected');
  Check(Rejected(LValidator, B64(Format('{"alg":"RS256","typ":"JWT","kid":"%s"}', [KID_1])) + '.' +
    B64(Format('{"iss":"%s","aud":"%s","sub":"timed","exp":"never"}', [TEST_ISSUER, TEST_AUDIENCE])) + '.' +
    B64('not a signature')), 'token with a non-numeric exp rejected');
  Check(Rejected(LValidator, MakeTimedToken(-120), 'expired'), 'exp 120 s ago rejected');
  Check(Rejected(LValidator, B64(Format('{"alg":"RS256","typ":"JWT","kid":"%s"}', [KID_1])) + '.' +
    B64(Format('{"iss":"%s","aud":"%s","sub":"timed","exp":"4070908800"}', [TEST_ISSUER, TEST_AUDIENCE])) + '.' +
    B64('not a signature'), 'not a number'), 'exp as a numeric string rejected (RFC 7519 2 NumericDate)');
  Check(Accepted(LValidator, MakeTimedToken(600, '.5')), 'exp with a fraction accepted');

  Check(Accepted(LValidator, MakeTimedToken(600, TimeClaim('nbf', -30))), 'nbf 30 s ago accepted');
  Check(Accepted(LValidator, MakeTimedToken(600, TimeClaim('nbf', 30))), 'nbf 30 s ahead accepted (skew 60 s)');
  Check(Rejected(LValidator, MakeTimedToken(600, TimeClaim('nbf', 120)), 'not-before'), 'nbf 120 s ahead rejected');
  Check(Rejected(LValidator, MakeTimedToken(600, TimeClaim('nbf', 120) + '.5'), 'not-before'),
    'nbf 120.5 s ahead rejected (a fraction is not ignored)');
  Check(Rejected(LValidator, MakeTimedToken(600, ',"nbf":true'), 'not a number'), 'nbf not a number rejected');

  (LValidator as TIAM4DJWTValidator).SetIatMaxAge(3600);
  Check(Rejected(LValidator, MakeTimedToken(600), 'issued-at'), 'iat required with max age');
  Check(Accepted(LValidator, MakeTimedToken(600, TimeClaim('iat', -30))), 'iat 30 s ago accepted');
  Check(Accepted(LValidator, MakeTimedToken(600, TimeClaim('iat', -30) + '.25')), 'iat with a fraction accepted');
  Check(Accepted(LValidator, MakeTimedToken(600, TimeClaim('iat', 30))), 'iat 30 s ahead accepted (skew 60 s)');
  Check(Rejected(LValidator, MakeTimedToken(600, TimeClaim('iat', 120)), 'future'), 'iat 120 s ahead rejected');
  Check(Rejected(LValidator, MakeTimedToken(600, TimeClaim('iat', -7200)), 'too old'), 'iat older than max age rejected');
end;

// Token for TKeyIdentityVerifier: iss and exp valid, AAudClaim (JSON value, '' = no aud) and AExtra
function MakeAudToken(const AAudClaim: string; const AExtra: string = ''): string;
var
  LAud: string;
begin
  if AAudClaim = '' then
    LAud := ''
  else
    LAud := ',"aud":' + AAudClaim;
  Result := B64(Format('{"alg":"RS256","typ":"JWT","kid":"%s"}', [KID_1])) + '.' +
    B64(Format('{"iss":"%s"%s,"sub":"aud","exp":4070908800%s}', [TEST_ISSUER, LAud, AExtra])) + '.' +
    B64('not a signature');
end;

procedure TestErrorCodes;
var
  LValidator: IIAM4DJWTValidator;
begin
  GIdP.Reset(JWK_1);
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig), TKeyIdentityVerifier.Create);
  Check(RejectionCode(LValidator, MakeTimedToken(-120)) = ecJWTExpired, 'expired token: ecJWTExpired');
  Check(RejectionCode(LValidator, MakeTimedToken(600, TimeClaim('nbf', 120))) = ecJWTNotYetValid,
    'nbf ahead: ecJWTNotYetValid');
  Check(RejectionCode(LValidator, MakeAudToken('"other-api"')) = ecJWTAudienceMismatch,
    'another audience: ecJWTAudienceMismatch');
  Check(RejectionCode(LValidator, MakeAudToken('["other-api"]')) = ecJWTAudienceMismatch,
    'audience array without the expected one: ecJWTAudienceMismatch');
  Check(RejectionCode(LValidator, MakeAudToken('')) = ecJWTAudienceMismatch, 'no aud: ecJWTAudienceMismatch');
  Check(RejectionCode(LValidator, MakeToken('RS256', KID_1, ATTACKER_ISSUER)) = ecJWTIssuerMismatch,
    'another issuer: ecJWTIssuerMismatch');
end;

procedure TestAudience;
const
  OTHER = '"other-api"';
var
  LValidator: IIAM4DJWTValidator;
  LConfigurable: TIAM4DJWTValidator;
  LExpected: string;
begin
  GIdP.Reset(JWK_1);
  LValidator := NewValidator(TEST_ISSUER, TIAM4DJWKSProvider.Create(HTTPConfig), TKeyIdentityVerifier.Create);
  LConfigurable := LValidator as TIAM4DJWTValidator;
  LExpected := '"' + TEST_AUDIENCE + '"';

  Check(Accepted(LValidator, MakeAudToken(LExpected)), 'aud the expected audience accepted');
  Check(Rejected(LValidator, MakeAudToken(OTHER), 'Invalid audience'), 'aud another audience rejected');
  Check(Rejected(LValidator, MakeAudToken('"' + UpperCase(TEST_AUDIENCE) + '"'), 'Invalid audience'),
    'aud compared case-sensitively (RFC 7519 4.1.3)');
  Check(Rejected(LValidator, MakeAudToken(''), 'Missing audience'), 'no aud rejected');
  Check(Rejected(LValidator, MakeAudToken('""'), 'empty'), 'empty aud rejected');
  Check(Rejected(LValidator, MakeAudToken('42'), 'Invalid audience claim format'), 'numeric aud rejected');
  Check(Rejected(LValidator, MakeAudToken('[' + OTHER + ',"account"]'), 'not found in audience array'),
    'aud array without the expected audience rejected');
  Check(Rejected(LValidator, MakeAudToken('[' + LExpected + ',' + OTHER + ']'), 'Authorized party (azp) is required'),
    'aud array without azp rejected (RequireAzpWhenMultipleAud)');
  Check(Accepted(LValidator, MakeAudToken('[' + LExpected + ',' + OTHER + ']', ',"azp":"web-client"')),
    'aud array with azp accepted');
  Check(Accepted(LValidator, MakeAudToken('[' + LExpected + ']')), 'aud array of one value accepted');

  LConfigurable.SetRequireAzpWhenMultipleAud(False);
  Check(Accepted(LValidator, MakeAudToken('[' + LExpected + ',' + OTHER + ']')),
    'aud array without azp accepted, RequireAzpWhenMultipleAud False');
  LConfigurable.SetRequireAzpWhenMultipleAud(True);

  LConfigurable.SetExpectedAzp('web-client');
  Check(Accepted(LValidator, MakeAudToken(LExpected, ',"azp":"web-client"')), 'expected azp accepted');
  Check(Rejected(LValidator, MakeAudToken(LExpected, ',"azp":"other-client"'), 'Invalid authorized party'),
    'other azp rejected');
  Check(Rejected(LValidator, MakeAudToken(LExpected), 'Missing authorized party'), 'no azp rejected with an expected azp');
  LConfigurable.SetExpectedAzp('');

  LConfigurable.SetAudienceValidationEnabled(False);
  Check(Accepted(LValidator, MakeAudToken(OTHER)), 'another audience accepted, audience validation off');
  Check(Accepted(LValidator, MakeAudToken('')), 'no aud accepted, audience validation off');

  // No expected audience with the check on: a configuration error, never a match with aud ""
  LValidator := TIAM4DJWTValidator.Create(TEST_ISSUER, '', TKeyIdentityVerifier.Create,
    TIAM4DJWKSProvider.Create(HTTPConfig), HTTPConfig);
  Check(Rejected(LValidator, MakeAudToken(LExpected), 'no expected audience is configured'),
    'empty expected audience: rejected as a configuration error');
  Check(Rejected(LValidator, MakeAudToken('["", ' + OTHER + ']', ',"azp":"x"'), 'no expected audience is configured'),
    'empty expected audience: an aud "" element does not match');
end;

// Validator with the token cache on (the default) and the fake verifier
function NewCachingValidator: TIAM4DJWTValidator;
begin
  Result := TIAM4DJWTValidator.Create(TEST_ISSUER, TEST_AUDIENCE, TKeyIdentityVerifier.Create,
    TIAM4DJWKSProvider.Create(HTTPConfig), HTTPConfig);
end;

procedure TestTokenCachePolicy;
var
  LValidatorObj: TIAM4DJWTValidator;
  LValidator: IIAM4DJWTValidator;
  LToken: string;
begin
  GIdP.Reset(JWK_1);
  LValidatorObj := NewCachingValidator;
  LValidator := LValidatorObj;

  // Cached, then a stricter policy: the cached token is validated again
  LToken := MakeTimedToken(600);
  Check(Accepted(LValidator, LToken) and Accepted(LValidator, LToken), 'token validated and cached');
  LValidatorObj.SetExpectedAzp('another-client');
  Check(Rejected(LValidator, LToken, 'authorized party'), 'cached token rejected after SetExpectedAzp');
  LValidatorObj.SetExpectedAzp('');
  Check(Accepted(LValidator, LToken), 'accepted again with the old policy');
  LValidatorObj.SetAllowedAlgs(['PS256']);
  Check(Rejected(LValidator, LToken, 'not allowed'), 'cached token rejected after SetAllowedAlgs');
  LValidatorObj.SetAllowedAlgs(['RS256']);

  // iat max age: the cache hit window ends when the token gets too old
  LValidatorObj.SetIatMaxAge(3600);
  LToken := MakeTimedToken(600, TimeClaim('iat', -3598));
  Check(Accepted(LValidator, LToken) and Accepted(LValidator, LToken), 'token near the max age accepted and cached');
  Sleep(3500);
  Check(Rejected(LValidator, LToken, 'too old'), 'cached token rejected once older than the max age');
end;

procedure TestJtiReplay;
const
  THREADS = 8;
  ROUNDS = 20;
var
  LValidatorObj: TIAM4DJWTValidator;
  LValidator: IIAM4DJWTValidator;
  LToken: string;
  LThreads: TArray<TThread>;
  LStart: TEvent;
  LAccepted, LReady, LRound, I, LMultiple: Integer;
begin
  GIdP.Reset(JWK_1);
  LValidatorObj := NewCachingValidator;
  LValidator := LValidatorObj;
  LValidatorObj.SetJtiValidation(True, 60);

  Check(Rejected(LValidator, MakeTimedToken(600), 'jti'), 'token without jti rejected');
  LToken := MakeTimedToken(600, ',"jti":"jti-once"');
  Check(Accepted(LValidator, LToken), 'token with jti accepted');
  Check(Rejected(LValidator, LToken, 'replay'), 'same token rejected (token cache on)');

  // The same token from parallel requests: one is accepted
  LMultiple := 0;
  LStart := TEvent.Create(nil, True, False, '');
  try
    for LRound := 1 to ROUNDS do
    begin
      LStart.ResetEvent;
      LToken := MakeTimedToken(600, Format(',"jti":"jti-parallel-%d"', [LRound]));
      LAccepted := 0;
      LReady := 0;
      SetLength(LThreads, THREADS);
      for I := 0 to THREADS - 1 do
      begin
        LThreads[I] := TThread.CreateAnonymousThread(
          procedure
          var
            LError: string;
          begin
            TInterlocked.Increment(LReady);
            LStart.WaitFor(5000);
            if Validate(LValidator, LToken, LError) then
              TInterlocked.Increment(LAccepted);
          end);
        LThreads[I].FreeOnTerminate := False;
        LThreads[I].Start;
      end;
      while TInterlocked.CompareExchange(LReady, 0, 0) < THREADS do
        Sleep(1);
      LStart.SetEvent;
      for I := 0 to THREADS - 1 do
      begin
        LThreads[I].WaitFor;
        LThreads[I].Free;
      end;
      if LAccepted <> 1 then
      begin
        Inc(LMultiple);
        Writeln(Format('    round %d: %d accepted', [LRound, LAccepted]));
      end;
    end;
  finally
    LStart.Free;
  end;
  Expect('rounds where a parallel replay was not exactly one acceptance', LMultiple, 0);
end;

procedure RunTest(const AName: string; const ATest: TProc);
begin
  Writeln(AName);
  try
    ATest();
  except
    on E: Exception do
    begin
      Inc(GFailed);
      Writeln('  FAIL unexpected ', E.ClassName, ': ', E.Message);
    end;
  end;
end;

begin
  ReportMemoryLeaksOnShutdown := True;
  try
    GIdP := TFakeIdP.Create;
  except
    on E: Exception do
    begin
      Writeln('Cannot start the fake identity provider on port ', TEST_PORT, ': ', E.Message);
      ExitCode := 99;
      Exit;
    end;
  end;
  try
    RunTest('Valid RS256 token', TestValidToken);
    RunTest('alg is case-sensitive', TestAlgCase);
    RunTest('No key lookup for an issuer that is not configured', TestIssuerNotConfigured);
    RunTest('Unknown kid storm', TestUnknownKidStorm);
    RunTest('Unknown kid storm from parallel threads (cold start)', TestParallelStorm);
    RunTest('One refresh per interval (key rotation)', TestRefreshInterval);
    RunTest('Negative cache bounded', TestNegativeCacheBound);
    RunTest('Expired keys served while the identity provider fails', TestStaleKeys);
    RunTest('Expired key served while its JWKS is refreshed in the background', TestStaleWhileRevalidate);
    RunTest('Only signing keys verify ("use", "key_ops")', TestKeyUse);
    RunTest('Key alg equal to the token alg', TestKeyAlg);
    RunTest('Keys of different types under one kid', TestDuplicateKid);
    RunTest('Discovery document of the requested issuer only', TestDiscoveryIssuer);
    RunTest('Identity provider failures are not token errors', TestUnavailable);
    RunTest('JWKS URI configured without discovery', TestStaticJWKSUri);
    RunTest('A slow issuer does not block another one', TestSlowIssuerIsolation);
    RunTest('Validated token cache', TestTokenCache);
    RunTest('exp, nbf and iat with clock skew', TestTimeClaims);
    RunTest('aud and azp', TestAudience);
    RunTest('Error codes of exp, nbf, aud and iss', TestErrorCodes);
    RunTest('Token cache follows the policy and the iat max age', TestTokenCachePolicy);
    RunTest('jti replay, also from parallel requests', TestJtiReplay);
    RunTest('Explicit typing, crit, canonical base64url', TestTokenFormat);
  finally
    GIdP.Free;
  end;

  Writeln;
  Writeln(Format('Passed: %d  Failed: %d', [GPassed, GFailed]));
  ExitCode := GFailed;
end.
