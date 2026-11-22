program IAM4DDMVCRuntimeTest;

{ Runtime test of the IAMClient4D DMVCFramework integration.

  Starts a real DMVC server on the loopback interface with a fake JWT validator (no identity
  provider needed) and checks over HTTP the controllers (OPTIONS included, client roles),
  [IAM4DPublic], Require* helpers, RFC 6750 challenges, the Issuer required by the
  configuration, the IAM4DJWTEndpointFilter / IAM4DJWTBundle Minimal API filters, AllowAnonymous,
  logging of rejected tokens and the Swagger 2.0 / OpenAPI 3 security injection. A small fake
  identity provider (Indy, port + 100) serves a JWKS for the JWKS_URL check, the key of the
  tokens signed by the test (real validator: rejected iss, aud, exp, alg, signature, kid, typ,
  azp) and answers 500 otherwise (identity provider down -> 503).

  Modes : middleware - controllers protected by the deprecated TIAM4DJWTMiddleware, Minimal API
                       groups by IAM4DJWTEndpointFilter and IAM4DJWTBundle (public group open)
          bundle     - AEngine.Use(IAM4DJWTBundle(...)) for controllers and every Minimal API route

  Usage : IAM4DDMVCRuntimeTest [indy|webbroker|httpsys] [port] [middleware|bundle]
          httpsys is Windows only and may need a "netsh http add urlacl" reservation.
          Builds for Win32, Win64 and Linux64.
  Exit  : number of failed checks (0 = all passed, 99 = startup error). }

{$APPTYPE CONSOLE}

{$WARN SYMBOL_DEPRECATED OFF} // TIAM4DJWTMiddleware is deprecated: still checked here

uses
  System.SysUtils,
  System.StrUtils,
  System.Classes,
  System.SyncObjs,
  System.NetEncoding,
  System.JSON,
  System.Generics.Collections,
  System.Generics.Defaults,
  System.Hash,
  System.DateUtils,
  System.Net.HttpClient,
  System.Net.URLClient,
  Web.WebReq,
  IdContext,
  IdCustomHTTPServer,
  IdHTTPServer,
  LoggerPro,
  MVCFramework,
  MVCFramework.Commons,
  MVCFramework.Logger,
  MVCFramework.Server.Intf,
  MVCFramework.Server.Factory,
  MVCFramework.MinimalAPI,
  MVCFramework.Swagger.Commons,
  MVCFramework.Filters.Swagger,
  Swag.Common.Types,
  IAMClient4D.Common.Security,
  IAMClient4D.Security.Core,
  IAMClient4D.Security.JWT,
  IAMClient4D.DMVC.Common,
  IAMClient4D.DMVC.Middleware,
  IAMClient4D.DMVC.Filters,
  IAMClient4D.DMVC.Helpers,
  IAMClient4D.DMVC.ClaimsTransformation,
  IAMClient4D.Exceptions,
  JWTTestVectorsU in '..\..\JWT\JWTTestVectorsU.pas',
  RuntimeTestValidatorU in 'RuntimeTestValidatorU.pas',
  RuntimeTestControllerU in 'RuntimeTestControllerU.pas',
  TestRSASignerU in '..\..\KeycloakClient\TestRSASignerU.pas';

type
  /// <summary>Expected WWW-Authenticate header.</summary>
  TChallenge = (
    chIgnore,             // not checked
    chNone,               // no header
    chCredentialsMissing, // Bearer realm="...", no error (RFC 6750 3.1)
    chInvalidToken,       // error="invalid_token" with error_description
    chInsufficientScope); // error="insufficient_scope"

  /// <summary>Log items written by DMVC and IAMClient4D (kept alive by the logger callback).</summary>
  ILogCapture = interface
    ['{5C0B7A3E-2F4D-4E61-9B8A-7D3C1E0F6A42}']
    procedure Add(ALevel: TLogType; const AMessage: string);
    /// <summary>Find looks only at the items added from now on</summary>
    procedure Mark;
    function Find(const AMarker: string; out ALevel: TLogType; out AMessage: string): Boolean;
  end;

  TLogCapture = class(TInterfacedObject, ILogCapture)
  private
    FLock: TCriticalSection;
    FItems: TList<TPair<TLogType, string>>;
    FMark: Integer;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Add(ALevel: TLogType; const AMessage: string);
    procedure Mark;
    function Find(const AMarker: string; out ALevel: TLogType; out AMessage: string): Boolean;
  end;

  /// <summary>Fake identity provider: JWKS at /custom/certs, 500 for anything else.</summary>
  TFakeIdP = class
  private
    FServer: TIdHTTPServer;
    procedure CommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo;
      AResponseInfo: TIdHTTPResponseInfo);
  public
    constructor Create(APort: Integer);
    destructor Destroy; override;
  end;

var
  GHost: string = '127.0.0.1';
  GPort: Integer = 18765;
  GPassed: Integer = 0;
  GFailed: Integer = 0;
  GLogCapture: ILogCapture;
  GBundleMode: Boolean = False;  // third parameter "bundle"
  GLastContentType: string;      // Content-Type of the last DoRequest
  GLastBody: string;             // body of the last DoRequest
  GLastWWWAuthenticate: string;  // WWW-Authenticate of the last DoRequest

  // Claims transformers, shared by every engine (WebBroker may create more than one web module)
  GReplaceLoads: Integer = 0;
  GMergeLoads: Integer = 0;
  GShortLoads: Integer = 0;
  GReplaceTransformer: IIAM4DClaimsTransformer;
  GReplaceTransformerObj: TIAM4DRolesClaimsTransformer; // for Invalidate, kept alive by GReplaceTransformer
  GMergeTransformer: IIAM4DClaimsTransformer;
  GShortTransformer: IIAM4DClaimsTransformer;
  GFailTransformer: IIAM4DClaimsTransformer;

const
  ROLES_DOWN_MARKER = 'IAM4D-ROLES-DOWN';
  // Tokens signed by the test (TestRSASignerU), checked by the real validator
  SIGNED_KID = 'signed-key';
  SIGNED_AZP = 'signed-client';

var
  GSigner: TTestRSASigner;
  GSignLock: TCriticalSection;

function IdPBase: string;
begin
  Result := Format('http://127.0.0.1:%d', [GPort + 100]);
end;

function IdPDownIssuer: string;
begin
  Result := IdPBase + '/realms/iam4d-down';
end;

function B64(const S: string): string;
begin
  Result := TNetEncoding.Base64URL.EncodeBytesToString(TEncoding.UTF8.GetBytes(S));
end;

function B64NoPad(const ABytes: TBytes): string;
begin
  Result := TNetEncoding.Base64URL.EncodeBytesToString(ABytes).Replace('=', '').Replace(#13, '').Replace(#10, '');
end;

function SignedIssuer: string;
begin
  Result := IdPBase + '/realms/signed';
end;

function SignedJWKS: string;
begin
  Result := Format('{"keys":[{"kty":"RSA","kid":"%s","use":"sig","alg":"RS256","n":"%s","e":"%s"}]}',
    [SIGNED_KID, B64NoPad(GSigner.Modulus), B64NoPad(GSigner.Exponent)]);
end;

type
  /// <summary>What is wrong with a token signed by the test</summary>
  TSignedFault = (sfNone, sfOtherIssuer, sfOtherAudience, sfExpired, sfNotYetValid, sfAlgNone, sfBadSignature,
    sfUnknownKid, sfTypID, sfOtherAzp, sfMultiAudWithAzp, sfMultiAudNoAzp, sfHS256,
    // Header typ: RFC 9068 access token, its media type form, another type
    sfAtJwt, sfAppAtJwt, sfDPoPJwt);

/// <summary>Keycloak-like access token, RS256 with the key of the fake JWKS, except AFault</summary>
function SignedToken(AFault: TSignedFault): string;
var
  LNow, LIat, LExp, LNbf: Int64;
  LIss, LAud, LAzp, LTyp, LHeader, LInput, LNbfClaim: string;
  LSignature: TBytes;
begin
  LNow := DateTimeToUnix(TDateTime.NowUTC);
  LIat := LNow - 10;
  LExp := LNow + 300;
  LNbf := 0;
  LIss := SignedIssuer;
  LAud := '"' + RuntimeTestValidatorU.TEST_AUDIENCE + '"';
  LAzp := ',"azp":"' + SIGNED_AZP + '"';
  LTyp := 'Bearer';
  LHeader := Format('{"alg":"RS256","typ":"JWT","kid":"%s"}', [SIGNED_KID]);
  case AFault of
    sfOtherIssuer: LIss := IdPBase + '/realms/other';
    sfOtherAudience: LAud := '"other-api"';
    sfExpired:
      begin
        // Beyond the default clock skew
        LIat := LNow - 3600;
        LExp := LNow - 1800;
      end;
    sfNotYetValid: LNbf := LNow + 3600;
    sfAlgNone: LHeader := '{"alg":"none","typ":"JWT"}';
    sfUnknownKid: LHeader := '{"alg":"RS256","typ":"JWT","kid":"unknown-kid"}';
    sfTypID: LTyp := 'ID';
    sfOtherAzp: LAzp := ',"azp":"other-client"';
    sfMultiAudWithAzp: LAud := '["' + RuntimeTestValidatorU.TEST_AUDIENCE + '","account"]';
    sfMultiAudNoAzp:
      begin
        LAud := '["' + RuntimeTestValidatorU.TEST_AUDIENCE + '","account"]';
        LAzp := '';
      end;
    sfHS256: LHeader := Format('{"alg":"HS256","typ":"JWT","kid":"%s"}', [SIGNED_KID]);
    sfAtJwt: LHeader := Format('{"alg":"RS256","typ":"at+jwt","kid":"%s"}', [SIGNED_KID]);
    sfAppAtJwt: LHeader := Format('{"alg":"RS256","typ":"application/at+jwt","kid":"%s"}', [SIGNED_KID]);
    sfDPoPJwt: LHeader := Format('{"alg":"RS256","typ":"dpop+jwt","kid":"%s"}', [SIGNED_KID]);
  end;
  LNbfClaim := '';
  if LNbf <> 0 then
    LNbfClaim := Format(',"nbf":%d', [LNbf]);
  LInput := B64NoPad(TEncoding.UTF8.GetBytes(LHeader)) + '.' + B64NoPad(TEncoding.UTF8.GetBytes(Format(
    '{"iss":"%s","aud":%s%s,"sub":"signed-user","typ":"%s","iat":%d,"exp":%d%s,' +
    '"realm_access":{"roles":["admin"]},"scope":"openid read"}',
    [LIss, LAud, LAzp, LTyp, LIat, LExp, LNbfClaim])));
  case AFault of
    sfAlgNone:
      Exit(LInput + '.');
    sfHS256:
      // Algorithm confusion: HMAC keyed with the public modulus, which anyone can read in the JWKS
      Exit(LInput + '.' + B64NoPad(THashSHA2.GetHMACAsBytes(TEncoding.UTF8.GetBytes(LInput), GSigner.Modulus)));
  end;
  GSignLock.Enter;
  try
    LSignature := GSigner.SignSHA256(THashSHA2.GetHashBytes(LInput));
  finally
    GSignLock.Leave;
  end;
  if AFault = sfBadSignature then
    LSignature[Length(LSignature) div 2] := LSignature[Length(LSignature) div 2] xor $01;
  Result := LInput + '.' + B64NoPad(LSignature);
end;

// Well-formed RS256 token with a fake signature: reaches the key lookup
function UnsignedToken(const AIssuer: string): string;
begin
  Result := B64('{"alg":"RS256","typ":"JWT","kid":"down-key"}') + '.' +
    B64(Format('{"iss":"%s","aud":"%s","sub":"u-1","exp":4070908800}', [AIssuer, RuntimeTestValidatorU.TEST_AUDIENCE])) + '.' +
    B64('not a signature');
end;

{ TLogCapture }

constructor TLogCapture.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FItems := TList<TPair<TLogType, string>>.Create;
end;

destructor TLogCapture.Destroy;
begin
  FItems.Free;
  FLock.Free;
  inherited;
end;

procedure TLogCapture.Add(ALevel: TLogType; const AMessage: string);
begin
  FLock.Enter;
  try
    FItems.Add(TPair<TLogType, string>.Create(ALevel, AMessage));
  finally
    FLock.Leave;
  end;
end;

procedure TLogCapture.Mark;
begin
  FLock.Enter;
  try
    FMark := FItems.Count;
  finally
    FLock.Leave;
  end;
end;

function TLogCapture.Find(const AMarker: string; out ALevel: TLogType; out AMessage: string): Boolean;
var
  I: Integer;
begin
  FLock.Enter;
  try
    for I := FMark to FItems.Count - 1 do
      if FItems[I].Value.Contains(AMarker) then
      begin
        ALevel := FItems[I].Key;
        AMessage := FItems[I].Value;
        Exit(True);
      end;
  finally
    FLock.Leave;
  end;
  Result := False;
end;

{ TFakeIdP }

constructor TFakeIdP.Create(APort: Integer);
begin
  inherited Create;
  FServer := TIdHTTPServer.Create(nil);
  FServer.Bindings.Clear;
  with FServer.Bindings.Add do
  begin
    IP := '127.0.0.1';
    Port := APort;
  end;
  FServer.OnCommandGet := CommandGet;
  FServer.Active := True;
end;

destructor TFakeIdP.Destroy;
begin
  if Assigned(FServer) then
    FServer.Active := False;
  FServer.Free;
  inherited;
end;

procedure TFakeIdP.CommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo;
  AResponseInfo: TIdHTTPResponseInfo);
begin
  AResponseInfo.ContentType := 'application/json';
  AResponseInfo.CharSet := 'utf-8';
  if ARequestInfo.Document = '/custom/certs' then
  begin
    AResponseInfo.ResponseNo := 200;
    AResponseInfo.ContentText := '{"keys":[' + JWK_1 + ']}';
  end
  else if ARequestInfo.Document = '/signed/certs' then
  begin
    AResponseInfo.ResponseNo := 200;
    AResponseInfo.ContentText := SignedJWKS;
  end
  else
  begin
    AResponseInfo.ResponseNo := 500;
    AResponseInfo.ContentText := '{"error":"down"}';
  end;
end;

{ Logger }

procedure InstallLogCapture;
var
  LCapture: ILogCapture;
begin
  LCapture := TLogCapture.Create;
  GLogCapture := LCapture;
  // File logs as before, plus every item in memory
  SetDefaultLogger(CreateLogBuilderWithDefaultConfiguration
    .WriteToCallback
      .WithCallback(
        procedure(const aLogItem: TLogItem; const aFormattedMessage: string)
        begin
          LCapture.Add(aLogItem.LogType, aLogItem.LogMessage);
        end)
      .Done
    .Build);
end;

// LoggerPro writes asynchronously
function WaitForLog(const AMarker: string; out ALevel: TLogType; out AMessage: string): Boolean;
var
  LWaited: Integer;
begin
  LWaited := 0;
  repeat
    Result := GLogCapture.Find(AMarker, ALevel, AMessage);
    if Result or (LWaited >= 5000) then
      Exit;
    Sleep(20);
    Inc(LWaited, 20);
  until False;
end;

{ Claims transformers }

procedure CreateClaimsTransformers;
begin
  // Application roles of u-123 only, cached; blanks and duplicates dropped, another case is
  // another role (Keycloak role names are case-sensitive).
  // The u-123 of TEST_OTHER_ISSUER is another user, with another role
  GReplaceTransformerObj := TIAM4DRolesClaimsTransformer.Create(
    function(const ASubject: string; const AClaims: TJSONObject): TArray<string>
    var
      LIssuer: string;
    begin
      TInterlocked.Increment(GReplaceLoads);
      if not AClaims.TryGetValue<string>('iss', LIssuer) then
        LIssuer := '';
      if (ASubject = 'u-123') and (LIssuer = TEST_OTHER_ISSUER) then
        Result := ['other-iss-role']
      else if ASubject = 'u-123' then
        Result := ['db-editor', ' db-viewer ', '', 'db-editor', 'DB-EDITOR']
      else
        Result := [];
    end, rmReplace, 300);
  GReplaceTransformer := GReplaceTransformerObj;

  // Token roles + application roles, no cache; the roles of TEST_ROLES_DOWN_SUBJECT cannot be loaded
  GMergeTransformer := TIAM4DRolesClaimsTransformer.Create(
    function(const ASubject: string; const AClaims: TJSONObject): TArray<string>
    begin
      if ASubject = TEST_ROLES_DOWN_SUBJECT then
        raise Exception.Create('roles database unreachable for the controllers');
      TInterlocked.Increment(GMergeLoads);
      Result := ['db-auditor', 'ADMIN'];
    end, rmMerge, 0);

  // One second cache
  GShortTransformer := TIAM4DRolesClaimsTransformer.Create(
    function(const ASubject: string; const AClaims: TJSONObject): TArray<string>
    begin
      TInterlocked.Increment(GShortLoads);
      Result := ['db-short'];
    end, rmReplace, 1);

  // Roles database down
  GFailTransformer := TIAM4DRolesClaimsTransformer.Create(
    function(const ASubject: string; const AClaims: TJSONObject): TArray<string>
    begin
      raise Exception.Create('roles database unreachable ' + ROLES_DOWN_MARKER);
    end, rmReplace, 300);
end;

procedure ReleaseClaimsTransformers;
begin
  GReplaceTransformerObj := nil;
  GReplaceTransformer := nil;
  GMergeTransformer := nil;
  GShortTransformer := nil;
  GFailTransformer := nil;
end;

function RolesReport(Ctx: TWebContext): string;
begin
  Result := 'editor=' + BoolToStr(Ctx.LoggedUser.Roles.Contains('db-editor'), True) +
    ' viewer=' + BoolToStr(Ctx.LoggedUser.Roles.Contains('db-viewer'), True) +
    ' auditor=' + BoolToStr(Ctx.LoggedUser.Roles.Contains('db-auditor'), True) +
    ' admin=' + BoolToStr(Ctx.LoggedUser.Roles.Contains('admin'), True) +
    ' short=' + BoolToStr(Ctx.LoggedUser.Roles.Contains('db-short'), True) +
    ' otherIss=' + BoolToStr(Ctx.LoggedUser.Roles.Contains('other-iss-role'), True) +
    ' count=' + IntToStr(Ctx.LoggedUser.Roles.Count) +
    ' tokenRealmAdmin=' + BoolToStr(Ctx.Keycloak.RealmAccess.HasRole('admin'), True) + ' ';
end;

procedure MapRolesGroup(AEngine: TMVCEngine; const APrefix: string; const ABaseConfig: TIAM4DJWTMiddlewareConfig;
  const ATransformer: IIAM4DClaimsTransformer);
var
  LConfig: TIAM4DJWTMiddlewareConfig;
  LGroup: TMVCRouteGroup<TObject>;
begin
  LConfig := ABaseConfig;
  LConfig.ClaimsTransformer := ATransformer;
  LGroup := AEngine.Prefix(APrefix).Use(IAM4DJWTEndpointFilter(TIAM4DJWTAuthenticator.Create(TRuntimeTestValidator.Create, LConfig)));
  LGroup.MapGet<TWebContext>('/hello',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Result := Status(200, 'roles ' + RolesReport(Ctx));
      end);
  LGroup.MapGet<TWebContext>('/editor',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Ctx.RequireAnyRole(['db-editor']);
        Result := Status(200, 'editor ok');
      end);
  LGroup.MapGet<TWebContext>('/anyadmin',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Ctx.RequireAnyRole(['admin']);
        Result := Status(200, 'anyadmin ok');
      end);
  LGroup.MapGet<TWebContext>('/realmadmin',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Ctx.RequireRealmRole('admin');
        Result := Status(200, 'realmadmin ok');
      end);
end;

{ Engine }

procedure UseSwagger(AEngine: TMVCEngine);
var
  LInfo: TMVCSwaggerInfo;
begin
  LInfo.Title := 'IAMClient4D DMVC runtime test';
  LInfo.Version := 'v1';
  AEngine.Use(SwaggerHTTPFilter(AEngine, LInfo, '/swagger2.json',
    JWT_DEFAULT_DESCRIPTION, [], '', '', '', [psHTTP], ssvSwagger2));
  AEngine.Use(SwaggerHTTPFilter(AEngine, LInfo, '/openapi3.json',
    JWT_DEFAULT_DESCRIPTION, [], '', '', '', [psHTTP], ssvOpenAPI3));
end;

function TestConfig: TIAM4DJWTMiddlewareConfig;
begin
  Result := TIAM4DJWTMiddlewareConfig.Create(RuntimeTestValidatorU.TEST_ISSUER, RuntimeTestValidatorU.TEST_AUDIENCE, '');
  // The checks read the warning of every rejected token
  Result.RejectedTokenWarningIntervalSec := 0;
end;

procedure ConfigureEngineMiddleware(AEngine: TMVCEngine);
var
  LConfig, LAnonConfig, LClaimsConfig, LDownConfig, LJWKSConfig, LNamespacedConfig: TIAM4DJWTMiddlewareConfig;
  LSignedConfig, LNoAudConfig: TIAM4DJWTMiddlewareConfig;
  LSigned: TMVCRouteGroup<TObject>;
  LIAM: TIAM4DJWTMiddleware;
  LAnonAuthenticator: IIAM4DJWTAuthenticator;
  LSecure: TMVCRouteGroup<TObject>;
begin
  UseSwagger(AEngine);

  // Classic middleware: registered before the first MapXxx
  LConfig := TestConfig;
  LIAM := TIAM4DJWTMiddleware.Create(TRuntimeTestValidator.Create, LConfig);
  // Adds db-auditor (and ADMIN, already a realm role) to the token roles
  LIAM.SetClaimsTransformer(GMergeTransformer);
  AEngine.AddMiddleware(LIAM);

  AEngine.AddController(TRuntimeTestController);
  AEngine.AddController(HiddenPublicControllerClass);

  // Minimal API: protected group sharing the middleware authenticator
  LSecure := AEngine.Prefix('/min/secure').Use(IAM4DJWTEndpointFilter(LIAM.Authenticator));
  LSecure.MapGet<TWebContext>('/hello',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Result := Status(200, 'secure user=' + Ctx.JWT.PreferredUsername +
          ' logged=' + Ctx.LoggedUser.UserName);
      end);
  LSecure.MapGet<TWebContext>('/superadmin',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Ctx.RequireRealmRole('superadmin');
        Result := Status(200, 'superadmin ok');
      end);

  // Minimal API: group without filter (public)
  AEngine.Prefix('/min/open')
    .MapGet('/hello',
      function: IMVCResponse
      begin
        Result := Status(200, 'open ok');
      end);

  // Minimal API: AllowAnonymous group with its own authenticator
  LAnonConfig := LConfig;
  LAnonConfig.AllowAnonymous := True;
  LAnonAuthenticator := TIAM4DJWTAuthenticator.Create(TRuntimeTestValidator.Create, LAnonConfig);
  AEngine.Prefix('/min/anon')
    .Use(IAM4DJWTEndpointFilter(LAnonAuthenticator))
    .MapGet<TWebContext>('/hello',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Result := Status(200, 'anon authenticated=' + BoolToStr(Ctx.IsAuthenticated, True));
      end);

  // Minimal API: roles and subject from configured claims; the bundle on a group
  // (its HTTP part goes on the engine, after SwaggerHTTPFilter)
  LClaimsConfig := LConfig;
  LClaimsConfig.RolesClaimName := 'app_roles';
  LClaimsConfig.SubjectClaimName := 'oid';
  AEngine.Prefix('/min/claims')
    .Use(IAM4DJWTBundle(TIAM4DJWTAuthenticator.Create(TRuntimeTestValidator.Create, LClaimsConfig)))
    .MapGet<TWebContext>('/hello',
      function(Ctx: TWebContext): IMVCResponse
      var
        LSub: string;
      begin
        if not Ctx.LoggedUser.CustomData.TryGetValue('sub', LSub) then
          LSub := '';
        Result := Status(200, 'claims appEditor=' + BoolToStr(Ctx.LoggedUser.Roles.Contains('app-editor'), True) +
          ' legacy=' + BoolToStr(Ctx.LoggedUser.Roles.Contains('legacy-role'), True) +
          ' sub=' + LSub);
      end);

  // Namespaced claim names: keys, not JSON paths
  LNamespacedConfig := LConfig;
  LNamespacedConfig.SubjectClaimName := 'https://app.example.com/tenant';
  AEngine.Prefix('/min/nsclaims')
    .Use(IAM4DJWTBundle(TIAM4DJWTAuthenticator.Create(TRuntimeTestValidator.Create, LNamespacedConfig)))
    .MapGet<TWebContext>('/hello',
      function(Ctx: TWebContext): IMVCResponse
      var
        LSub, LTenant: string;
      begin
        if not Ctx.LoggedUser.CustomData.TryGetValue('sub', LSub) then
          LSub := '';
        if not Ctx.TryGetCustomClaim('https://app.example.com/tenant', LTenant) then
          LTenant := 'missing';
        Result := Status(200, 'ns sub=' + LSub + ' tenant=' + LTenant +
          ' default=' + Ctx.GetCustomClaim('https://app.example.com/tenant', 'none') +
          ' level=' + IntToStr(Ctx.GetCustomClaimAsInteger('https://app.example.com/level', -1)) +
          ' absent=' + Ctx.GetCustomClaim('https://app.example.com/absent', 'none') + ' ');
      end);

  // Minimal API: real validator, identity provider answering 500
  LDownConfig := TIAM4DJWTMiddlewareConfig.Create(IdPDownIssuer, RuntimeTestValidatorU.TEST_AUDIENCE, '');
  AEngine.Prefix('/min/idpdown')
    .Use(IAM4DJWTEndpointFilter(LDownConfig))
    .MapGet('/hello',
      function: IMVCResponse
      begin
        Result := Status(200, 'idpdown ok');
      end);

  // Minimal API: real validator, keys from JWKS_URL (the issuer host does not answer);
  // a second bundle on a sibling group
  LJWKSConfig := TIAM4DJWTMiddlewareConfig.Create(JWTTestVectorsU.TEST_ISSUER, JWTTestVectorsU.TEST_AUDIENCE,
    IdPBase + '/custom/certs');
  AEngine.Prefix('/min/jwksurl')
    .Use(IAM4DJWTBundle(LJWKSConfig))
    .MapGet<TWebContext>('/hello',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Result := Status(200, 'jwksurl sub=' + Ctx.JWT.Subject);
      end);

  // Minimal API: real validator on tokens signed by the test. ExpectedAzp, typ Bearer (default)
  // and the audience must reach the validator: each rejection below depends on one of them
  LSignedConfig := TIAM4DJWTMiddlewareConfig.Create(SignedIssuer, RuntimeTestValidatorU.TEST_AUDIENCE,
    IdPBase + '/signed/certs');
  LSignedConfig.ExpectedAzp := SIGNED_AZP;
  LSignedConfig.RejectedTokenWarningIntervalSec := 0;
  LSigned := AEngine.Prefix('/min/signed').Use(IAM4DJWTEndpointFilter(LSignedConfig));
  LSigned.MapGet<TWebContext>('/hello',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Ctx.RequireRealmRole('admin');
        Ctx.RequireScope('read');
        Result := Status(200, 'signed sub=' + Ctx.JWT.Subject);
      end);
  LSigned.MapGet<TWebContext>('/upperrealm',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Ctx.RequireRealmRole('ADMIN');
        Result := Status(200, 'upper realm role accepted');
      end);
  LSigned.MapGet<TWebContext>('/upperrole',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Ctx.RequireAnyRole(['ADMIN']);
        Result := Status(200, 'upper role accepted');
      end);
  LSigned.MapGet<TWebContext>('/upperscope',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Ctx.RequireScope('READ');
        Result := Status(200, 'upper scope accepted');
      end);
  // Same, audience validation off: a token for another API passes (the switch is forwarded)
  LNoAudConfig := LSignedConfig;
  LNoAudConfig.ExpectedAzp := '';
  LNoAudConfig.AudienceValidationEnabled := False;
  AEngine.Prefix('/min/signednoaud')
    .Use(IAM4DJWTEndpointFilter(LNoAudConfig))
    .MapGet<TWebContext>('/hello',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Result := Status(200, 'signednoaud sub=' + Ctx.JWT.Subject);
      end);

  // Minimal API: claims transformers through TIAM4DJWTMiddlewareConfig.ClaimsTransformer
  MapRolesGroup(AEngine, '/min/rolesdb', LConfig, GReplaceTransformer);
  MapRolesGroup(AEngine, '/min/rolesshort', LConfig, GShortTransformer);
  MapRolesGroup(AEngine, '/min/rolesdown', LConfig, GFailTransformer);
  MapRolesGroup(AEngine, '/min/rolesdownanon', LAnonConfig, GFailTransformer);
end;

procedure ConfigureEngineBundle(AEngine: TMVCEngine);
var
  LConfig: TIAM4DJWTMiddlewareConfig;
  LAuthenticator: IIAM4DJWTAuthenticator;
  LSecure: TMVCRouteGroup<TObject>;
begin
  LConfig := TestConfig;
  // Adds db-auditor (and ADMIN, already a realm role) to the token roles
  LConfig.ClaimsTransformer := GMergeTransformer;
  LAuthenticator := TIAM4DJWTAuthenticator.Create(TRuntimeTestValidator.Create, LConfig);

  // Before SwaggerHTTPFilter: its HTTP part completes the documents on the way out
  AEngine.Use(IAM4DJWTBundle(LAuthenticator));
  UseSwagger(AEngine);

  AEngine.AddController(TRuntimeTestController);
  AEngine.AddController(HiddenPublicControllerClass);

  // Minimal API: no filter on the group, the engine-wide bundle checks it
  LSecure := AEngine.Prefix('/min/secure');
  LSecure.MapGet<TWebContext>('/hello',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Result := Status(200, 'secure user=' + Ctx.JWT.PreferredUsername +
          ' logged=' + Ctx.LoggedUser.UserName);
      end);
  LSecure.MapGet<TWebContext>('/superadmin',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Ctx.RequireRealmRole('superadmin');
        Result := Status(200, 'superadmin ok');
      end);

  // Minimal API: the engine-wide bundle plus a group filter on the same authenticator
  AEngine.Prefix('/min/shared')
    .Use(IAM4DJWTEndpointFilter(LAuthenticator))
    .MapGet<TWebContext>('/hello',
      function(Ctx: TWebContext): IMVCResponse
      begin
        Result := Status(200, 'shared user=' + Ctx.JWT.PreferredUsername);
      end);

  // Minimal API: group without filter, still under the engine-wide bundle
  AEngine.Prefix('/min/open')
    .MapGet('/hello',
      function: IMVCResponse
      begin
        Result := Status(200, 'open ok');
      end);
end;

procedure ConfigureEngine(AEngine: TMVCEngine);
begin
  if GBundleMode then
    ConfigureEngineBundle(AEngine)
  else
    ConfigureEngineMiddleware(AEngine);
end;

{ Checks }

procedure Report(const AName, AReason: string; const ABody: string = '');
begin
  if AReason.IsEmpty then
  begin
    Inc(GPassed);
    Writeln('  PASS  ', AName);
  end
  else
  begin
    Inc(GFailed);
    Writeln('  FAIL  ', AName);
    Writeln('        ', AReason.Trim);
    if not ABody.IsEmpty then
      Writeln('        body: ', Copy(ABody, 1, 300));
  end;
end;

procedure CheckTrue(ACondition: Boolean; const AName, ADetail: string);
begin
  if ACondition then
    Report(AName, '')
  else
    Report(AName, ADetail);
end;

function DoRequest(const AMethod, APath, AAuthorization: string;
  out ABody, AWWWAuthenticate, ARetryAfter: string): Integer;
var
  LClient: THTTPClient;
  LResponse: IHTTPResponse;
  LHeaders: TNetHeaders;
begin
  // CheckLog looks at what this request logs, not at an item of an earlier one
  if Assigned(GLogCapture) then
    GLogCapture.Mark;
  LClient := THTTPClient.Create;
  try
    if AAuthorization <> '' then
      LHeaders := [TNetHeader.Create('Authorization', AAuthorization)]
    else
      LHeaders := [];
    if AMethod = 'OPTIONS' then
      LResponse := LClient.Options(Format('http://%s:%d%s', [GHost, GPort, APath]), nil, LHeaders)
    else
      LResponse := LClient.Get(Format('http://%s:%d%s', [GHost, GPort, APath]), nil, LHeaders);
    ABody := LResponse.ContentAsString(TEncoding.UTF8);
    AWWWAuthenticate := LResponse.HeaderValue['WWW-Authenticate'];
    ARetryAfter := LResponse.HeaderValue['Retry-After'];
    GLastContentType := LResponse.HeaderValue['Content-Type'];
    GLastBody := ABody;
    GLastWWWAuthenticate := AWWWAuthenticate;
    Result := LResponse.StatusCode;
  finally
    LClient.Free;
  end;
end;

function ChallengeProblem(AChallenge: TChallenge; const AHeader, AMustContain: string): string;
var
  LOk: Boolean;
begin
  case AChallenge of
    chNone:
      LOk := AHeader.IsEmpty;
    chCredentialsMissing:
      LOk := AHeader.StartsWith('Bearer') and
        AHeader.Contains('realm="' + RuntimeTestValidatorU.TEST_AUDIENCE + '"') and not AHeader.Contains('error');
    chInvalidToken:
      LOk := AHeader.StartsWith('Bearer ') and AHeader.Contains('error="invalid_token"') and
        AHeader.Contains('error_description="');
    chInsufficientScope:
      LOk := AHeader.StartsWith('Bearer ') and AHeader.Contains('error="insufficient_scope"');
  else
    LOk := True;
  end;
  if LOk and (AMustContain <> '') then
    LOk := AHeader.Contains(AMustContain);
  if LOk then
    Result := ''
  else
    Result := Format(' WWW-Authenticate "%s";', [AHeader]);
end;

procedure CheckRequest(const AName, AMethod, APath, AAuthorization: string; AExpectedStatus: Integer;
  const AMustContain: array of string; AChallenge: TChallenge = chIgnore;
  const AChallengeMustContain: string = ''; AExpectRetryAfter: Boolean = False);
var
  LStatus, LRetryAfter: Integer;
  LBody, LWWWAuthenticate, LRetryAfterHeader, LFragment, LReason: string;
begin
  LReason := '';
  LBody := '';
  try
    LStatus := DoRequest(AMethod, APath, AAuthorization, LBody, LWWWAuthenticate, LRetryAfterHeader);
    if LStatus <> AExpectedStatus then
      LReason := Format('status %d, expected %d;', [LStatus, AExpectedStatus]);
    for LFragment in AMustContain do
      if not LBody.Contains(LFragment) then
        LReason := LReason + Format(' body without "%s";', [LFragment]);
    LReason := LReason + ChallengeProblem(AChallenge, LWWWAuthenticate, AChallengeMustContain);
    if AExpectRetryAfter and not (TryStrToInt(LRetryAfterHeader, LRetryAfter) and (LRetryAfter > 0)) then
      LReason := LReason + Format(' Retry-After "%s";', [LRetryAfterHeader]);
  except
    on E: Exception do
      LReason := E.ClassName + ': ' + E.Message;
  end;
  Report(AName, LReason, LBody);
end;

procedure Check(const AName, APath, AToken: string; AExpectedStatus: Integer;
  const AMustContain: array of string; AChallenge: TChallenge = chIgnore;
  const AMethod: string = 'GET');
var
  LAuthorization: string;
begin
  if AToken <> '' then
    LAuthorization := 'Bearer ' + AToken
  else
    LAuthorization := '';
  CheckRequest(AName, AMethod, APath, LAuthorization, AExpectedStatus, AMustContain, AChallenge);
end;

// The access policy (required roles, groups) is not in the last 403: neither body nor challenge
procedure CheckForbiddenGeneric(const AName: string; const ASecrets: array of string);
var
  LReason, LSecret: string;
begin
  LReason := '';
  if not GLastBody.Contains('Insufficient permissions') then
    LReason := 'body without "Insufficient permissions";';
  if not GLastWWWAuthenticate.Contains('error_description="Insufficient permissions"') then
    LReason := LReason + Format(' WWW-Authenticate "%s";', [GLastWWWAuthenticate]);
  for LSecret in ASecrets do
  begin
    if GLastBody.Contains(LSecret) then
      LReason := LReason + Format(' body names "%s";', [LSecret]);
    if GLastWWWAuthenticate.Contains(LSecret) then
      LReason := LReason + Format(' WWW-Authenticate names "%s";', [LSecret]);
  end;
  Report(AName, LReason, GLastBody);
end;

// The last answer is an IAMClient4D 401/503: application/json {"error","message","status"},
// not wrapped in "data" (as an IMVCResponse body would be)
procedure CheckAuthAnswer(const AName: string; AStatus: Integer; const AError: string);
var
  LReason, LFragment: string;
begin
  LReason := '';
  if not GLastContentType.StartsWith('application/json') then
    LReason := Format('Content-Type "%s";', [GLastContentType]);
  for LFragment in [Format('{"error":"%s"', [AError]), '"message":"', Format('"status":%d}', [AStatus])] do
    if not GLastBody.Contains(LFragment) then
      LReason := LReason + Format(' body without %s;', [LFragment]);
  if GLastBody.Contains('"data"') then
    LReason := LReason + ' body wrapped in "data";';
  Report(AName, LReason, GLastBody);
end;

procedure CheckLog(const AName, AMarker: string; AExpectedLevel: TLogType; AMaxLength: Integer = 0);
var
  LLevel: TLogType;
  LMessage, LReason: string;
  LChar: Char;
begin
  LReason := '';
  if not WaitForLog(AMarker, LLevel, LMessage) then
    LReason := Format('no log item with "%s"', [AMarker])
  else
  begin
    if LLevel <> AExpectedLevel then
      LReason := Format('level %d, expected %d;', [Ord(LLevel), Ord(AExpectedLevel)]);
    for LChar in LMessage do
      if (LChar < ' ') or (LChar = #127) then
      begin
        LReason := LReason + Format(' control character #%d in the message;', [Ord(LChar)]);
        Break;
      end;
    if (AMaxLength > 0) and (LMessage.Length > AMaxLength) then
      LReason := LReason + Format(' %d characters, at most %d expected;', [LMessage.Length, AMaxLength]);
  end;
  Report(AName, LReason, Copy(LMessage, 1, 300));
end;

procedure CheckConfig(const AName: string; const AConfigure: TProc; AMustRaise: Boolean);
var
  LReason: string;
begin
  LReason := '';
  try
    AConfigure();
    if AMustRaise then
      LReason := 'no exception';
  except
    on E: EIAM4DInvalidConfigurationException do
      if not AMustRaise then
        LReason := E.ClassName + ': ' + E.Message;
    on E: Exception do
      LReason := E.ClassName + ': ' + E.Message;
  end;
  Report(AName, LReason);
end;

function MakeComparerThread(AStart: TEvent; const AInstances: TArray<Pointer>; AIndex: Integer): TThread;
begin
  Result := TThread.CreateAnonymousThread(
    procedure
    var
      LComparer: IEqualityComparer<string>;
    begin
      AStart.WaitFor(INFINITE);
      LComparer := CaseInsensitiveComparer;
      AInstances[AIndex] := Pointer(LComparer);
    end);
  Result.FreeOnTerminate := False;
end;

procedure CheckComparerSingleton;
const
  THREADS = 32;
var
  LStart: TEvent;
  LThreads: TArray<TThread>;
  LInstances: TArray<Pointer>;
  LSame: Boolean;
  I: Integer;
begin
  LStart := TEvent.Create(nil, True, False, '');
  try
    SetLength(LInstances, THREADS);
    SetLength(LThreads, THREADS);
    for I := 0 to THREADS - 1 do
    begin
      LThreads[I] := MakeComparerThread(LStart, LInstances, I);
      LThreads[I].Start;
    end;
    LStart.SetEvent;
    for I := 0 to THREADS - 1 do
    begin
      LThreads[I].WaitFor;
      LThreads[I].Free;
    end;
  finally
    LStart.Free;
  end;
  LSame := LInstances[0] <> nil;
  for I := 1 to THREADS - 1 do
    LSame := LSame and (LInstances[I] = LInstances[0]);
  CheckTrue(LSame and (Pointer(CaseInsensitiveComparer) = LInstances[0]),
    'CaseInsensitiveComparer: one instance for 32 threads calling it together', 'different instances');
end;

procedure CheckExpectedAzp;
var
  LValidator: TIAM4DJWTValidator;
  LValidatorIntf: IIAM4DJWTValidator;
  LAuthenticator: IIAM4DJWTAuthenticator;
begin
  LValidator := TIAM4DJWTValidator.Create(RuntimeTestValidatorU.TEST_ISSUER, RuntimeTestValidatorU.TEST_AUDIENCE, svmStrict);
  LValidatorIntf := LValidator;
  LValidator.SetExpectedAzp('preset-client');
  LAuthenticator := TIAM4DJWTAuthenticator.Create(LValidatorIntf,
    TIAM4DJWTMiddlewareConfig.Create(RuntimeTestValidatorU.TEST_ISSUER, RuntimeTestValidatorU.TEST_AUDIENCE, ''));
  CheckTrue(LValidatorIntf.GetExpectedAzp = 'preset-client', 'custom validator keeps its azp when the config has none',
    'azp "' + LValidatorIntf.GetExpectedAzp + '"');
  LAuthenticator.SetExpectedAzp('web-client');
  CheckTrue(LValidatorIntf.GetExpectedAzp = 'web-client', 'SetExpectedAzp sets the validator azp',
    'azp "' + LValidatorIntf.GetExpectedAzp + '"');
  LAuthenticator.SetExpectedAzp('');
  CheckTrue(LValidatorIntf.GetExpectedAzp = '', 'SetExpectedAzp('''') clears the validator azp',
    'azp "' + LValidatorIntf.GetExpectedAzp + '"');
end;

procedure CheckConfigDefaults;
var
  LConfig: TIAM4DJWTMiddlewareConfig;
begin
  // A local filled field by field: Initialize gives the defaults of Create, not stack garbage
  LConfig.Issuer := RuntimeTestValidatorU.TEST_ISSUER;
  CheckTrue(not LConfig.AllowAnonymous and LConfig.AudienceValidationEnabled and LConfig.RequireAzpWhenMultipleAud and
    (LConfig.ClockSkewSeconds = 60) and (LConfig.TokenHeaderName = 'Authorization') and
    (LConfig.TokenPrefix = 'Bearer ') and (LConfig.SSLValidationMode = svmStrict) and
    (LConfig.ExpectedTokenType = 'Bearer') and (LConfig.HTTPConnectTimeoutMs = 10000) and
    (LConfig.HTTPReceiveTimeoutMs = 15000) and (LConfig.RejectedTokenWarningIntervalSec = 10),
    'config declared without Create has the secure defaults', 'AllowAnonymous=' + BoolToStr(LConfig.AllowAnonymous, True));
end;

type
  /// <summary>Validator recording the calls of the JWKS provider</summary>
  TRecordingSSLValidator = class(TInterfacedObject, IIAM4DSSLCertificateValidator)
  private
    FInner: IIAM4DSSLCertificateValidator;
    FModeSet: Boolean;
    FMode: TIAM4DSSLValidationMode;
  public
    constructor Create;
    procedure SetValidationMode(AMode: TIAM4DSSLValidationMode);
    function GetValidationMode: TIAM4DSSLValidationMode;
    procedure AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);
    procedure ClearPinnedPublicKeys;
    function HasPinnedPublicKeys: Boolean;
    function ValidateCertificate(const Certificate: TCertificate; ASystemAccepted: Boolean): Boolean;
    property ModeSet: Boolean read FModeSet;
    property Mode: TIAM4DSSLValidationMode read FMode;
  end;

constructor TRecordingSSLValidator.Create;
begin
  inherited Create;
  FInner := TIAM4DSSLCertificateValidator.Create;
end;

procedure TRecordingSSLValidator.SetValidationMode(AMode: TIAM4DSSLValidationMode);
begin
  FModeSet := True;
  FMode := AMode;
  FInner.SetValidationMode(AMode);
end;

function TRecordingSSLValidator.GetValidationMode: TIAM4DSSLValidationMode;
begin
  Result := FInner.GetValidationMode;
end;

procedure TRecordingSSLValidator.AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);
begin
  FInner.AddPinnedPublicKeys(APublicKeyHashes);
end;

procedure TRecordingSSLValidator.ClearPinnedPublicKeys;
begin
  FInner.ClearPinnedPublicKeys;
end;

function TRecordingSSLValidator.HasPinnedPublicKeys: Boolean;
begin
  Result := FInner.HasPinnedPublicKeys;
end;

function TRecordingSSLValidator.ValidateCertificate(const Certificate: TCertificate; ASystemAccepted: Boolean): Boolean;
begin
  Result := FInner.ValidateCertificate(Certificate, ASystemAccepted);
end;

procedure CheckCertificateSettings;
const
  PIN = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
var
  LRecorder: TRecordingSSLValidator;
  LRecorderIntf: IIAM4DSSLCertificateValidator;
{$IFDEF LINUX}
  LConfig: TIAM4DJWTMiddlewareConfig;
  LAuthenticator: IIAM4DJWTAuthenticator;
  LRaised: Boolean;
{$ENDIF}
begin
  // Given validator: the JWKS provider uses it and sets its mode
  LRecorder := TRecordingSSLValidator.Create;
  LRecorderIntf := LRecorder;
  CheckConfig('SSLValidator accepted',
    procedure
    var
      LConfig: TIAM4DJWTMiddlewareConfig;
      LAuthenticator: IIAM4DJWTAuthenticator;
    begin
      LConfig := TIAM4DJWTMiddlewareConfig.Create(RuntimeTestValidatorU.TEST_ISSUER,
        RuntimeTestValidatorU.TEST_AUDIENCE, '');
      LConfig.SSLValidationMode := svmAllowSelfSigned;
      LConfig.SSLValidator := LRecorderIntf;
      LAuthenticator := TIAM4DJWTAuthenticator.Create(LConfig);
    end, False);
  CheckTrue(LRecorder.ModeSet and (LRecorder.Mode = svmAllowSelfSigned),
    'SSLValidator given to the JWKS provider, mode set from SSLValidationMode', 'mode set ' + BoolToStr(LRecorder.ModeSet, True));
  LRecorderIntf := nil;

  CheckConfig('PinnedPublicKeys and SSLValidator together -> EIAM4DInvalidConfigurationException',
    procedure
    var
      LConfig: TIAM4DJWTMiddlewareConfig;
      LAuthenticator: IIAM4DJWTAuthenticator;
    begin
      LConfig := TIAM4DJWTMiddlewareConfig.Create(RuntimeTestValidatorU.TEST_ISSUER,
        RuntimeTestValidatorU.TEST_AUDIENCE, '');
      LConfig.PinnedPublicKeys := [PIN];
      LConfig.SSLValidator := TIAM4DSSLCertificateValidator.Create;
      LAuthenticator := TIAM4DJWTAuthenticator.Create(LConfig);
    end, True);
{$IFDEF LINUX}
  // libcurl does not call back for a certificate the system accepted: the pin would not be checked
  LRaised := False;
  LConfig := TIAM4DJWTMiddlewareConfig.Create(RuntimeTestValidatorU.TEST_ISSUER,
    RuntimeTestValidatorU.TEST_AUDIENCE, '');
  LConfig.PinnedPublicKeys := [PIN];
  try
    LAuthenticator := TIAM4DJWTAuthenticator.Create(LConfig);
  except
    on ENotSupportedException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'Linux: PinnedPublicKeys -> ENotSupportedException', '');
{$ELSE}
  CheckConfig('PinnedPublicKeys accepted',
    procedure
    var
      LConfig: TIAM4DJWTMiddlewareConfig;
      LAuthenticator: IIAM4DJWTAuthenticator;
    begin
      LConfig := TIAM4DJWTMiddlewareConfig.Create(RuntimeTestValidatorU.TEST_ISSUER,
        RuntimeTestValidatorU.TEST_AUDIENCE, '');
      LConfig.PinnedPublicKeys := [PIN.ToUpper];
      LAuthenticator := TIAM4DJWTAuthenticator.Create(LConfig);
    end, False);
  CheckConfig('PinnedPublicKeys not 64 hex characters -> EIAM4DInvalidConfigurationException',
    procedure
    var
      LConfig: TIAM4DJWTMiddlewareConfig;
      LAuthenticator: IIAM4DJWTAuthenticator;
    begin
      LConfig := TIAM4DJWTMiddlewareConfig.Create(RuntimeTestValidatorU.TEST_ISSUER,
        RuntimeTestValidatorU.TEST_AUDIENCE, '');
      LConfig.PinnedPublicKeys := ['sha256/abc'];
      LAuthenticator := TIAM4DJWTAuthenticator.Create(LConfig);
    end, True);
{$ENDIF}
end;

procedure CheckAudienceRequired;
begin
  // Built-in validator: an empty audience is a configuration error, not a validation turned off
  CheckConfig('built-in validator, empty Audience -> EIAM4DInvalidConfigurationException',
    procedure
    var
      LAuthenticator: IIAM4DJWTAuthenticator;
    begin
      LAuthenticator := TIAM4DJWTAuthenticator.Create(
        TIAM4DJWTMiddlewareConfig.Create(RuntimeTestValidatorU.TEST_ISSUER, '', ''));
    end, True);
  CheckConfig('built-in validator, blank Audience -> EIAM4DInvalidConfigurationException',
    procedure
    var
      LAuthenticator: IIAM4DJWTAuthenticator;
    begin
      LAuthenticator := TIAM4DJWTAuthenticator.Create(
        TIAM4DJWTMiddlewareConfig.Create(RuntimeTestValidatorU.TEST_ISSUER, '  ', ''));
    end, True);
  CheckConfig('built-in validator, empty Audience, AudienceValidationEnabled False -> accepted',
    procedure
    var
      LConfig: TIAM4DJWTMiddlewareConfig;
      LAuthenticator: IIAM4DJWTAuthenticator;
    begin
      LConfig := TIAM4DJWTMiddlewareConfig.Create(RuntimeTestValidatorU.TEST_ISSUER, '', '');
      LConfig.AudienceValidationEnabled := False;
      LAuthenticator := TIAM4DJWTAuthenticator.Create(LConfig);
    end, False);
  CheckConfig('built-in validator: SetAudienceValidationEnabled(True) with empty Audience -> EIAM4DInvalidConfigurationException',
    procedure
    var
      LConfig: TIAM4DJWTMiddlewareConfig;
      LAuthenticator: IIAM4DJWTAuthenticator;
    begin
      LConfig := TIAM4DJWTMiddlewareConfig.Create(RuntimeTestValidatorU.TEST_ISSUER, '', '');
      LConfig.AudienceValidationEnabled := False;
      LAuthenticator := TIAM4DJWTAuthenticator.Create(LConfig);
      LAuthenticator.SetAudienceValidationEnabled(True);
    end, True);
  CheckConfig('TIAM4DJWTMiddleware, empty Audience -> EIAM4DInvalidConfigurationException',
    procedure
    var
      LMiddleware: IMVCMiddleware;
    begin
      LMiddleware := TIAM4DJWTMiddleware.Create(RuntimeTestValidatorU.TEST_ISSUER, '', '');
    end, True);
  // A custom validator decides the audience itself: accepted, with a log line at startup
  CheckConfig('custom validator, empty Audience -> accepted',
    procedure
    var
      LAuthenticator: IIAM4DJWTAuthenticator;
    begin
      LAuthenticator := TIAM4DJWTAuthenticator.Create(TRuntimeTestValidator.Create,
        TIAM4DJWTMiddlewareConfig.Create(RuntimeTestValidatorU.TEST_ISSUER, '', ''));
    end, False);
end;

procedure CheckRolesLoadOvertakenByInvalidate;
var
  LObj: TIAM4DRolesClaimsTransformer;
  LTransformer: IIAM4DClaimsTransformer;
  LUser: TMVCUser;
  LClaims: TJSONObject;
  LLoads: Integer;
  LInvalidateDuringLoad: Boolean;
begin
  // The roles changed while the loader was reading them: what it read may be the revoked roles,
  // and must not stay in the cache for the TTL
  LLoads := 0;
  LInvalidateDuringLoad := True;
  LObj := nil;
  LObj := TIAM4DRolesClaimsTransformer.Create(
    function(const ASubject: string; const AClaims: TJSONObject): TArray<string>
    begin
      Inc(LLoads);
      if LInvalidateDuringLoad then
        LObj.Invalidate(ASubject);
      Result := ['db-editor'];
    end, rmReplace, 300);
  LTransformer := LObj;
  LClaims := TJSONObject.Create;
  LUser := TMVCUser.Create;
  try
    LUser.CustomData := TMVCCustomData.Create;
    LUser.CustomData.Add('sub', 'u-gen');
    LUser.CustomData.Add('iss', RuntimeTestValidatorU.TEST_ISSUER);
    LTransformer.Transform(nil, LClaims, LUser);
    CheckTrue((LUser.Roles.Count = 1) and (LUser.Roles[0] = 'db-editor'), 'load overtaken by Invalidate: roles of the request applied',
      Format('%d roles', [LUser.Roles.Count]));
    CheckTrue(LObj.CacheCount = 0, 'load overtaken by Invalidate: nothing cached',
      Format('%d entries', [LObj.CacheCount]));
    LInvalidateDuringLoad := False;
    LTransformer.Transform(nil, LClaims, LUser);
    LTransformer.Transform(nil, LClaims, LUser);
    CheckTrue((LLoads = 2) and (LObj.CacheCount = 1), 'next load cached as usual',
      Format('%d loads, %d entries', [LLoads, LObj.CacheCount]));
  finally
    LUser.Free;
    LClaims.Free;
  end;
  LTransformer := nil;
end;

procedure CheckBundleRegisteredOnce;
var
  LEngine: TMVCEngine;
  LBundle: IMVCFilterBundle;
  LReason: string;
begin
  LReason := 'no exception';
  LBundle := IAM4DJWTBundle(TIAM4DJWTAuthenticator.Create(TRuntimeTestValidator.Create, TestConfig));
  LEngine := TMVCEngine.Create(nil);
  try
    try
      LEngine.Use(LBundle);
      LEngine.Prefix('/twice').Use(LBundle);
    except
      on EMVCConfigException do
        LReason := '';
      on E: Exception do
        LReason := E.ClassName + ': ' + E.Message;
    end;
  finally
    LEngine.Free;
  end;
  Report('the same bundle on the engine and on a group -> EMVCConfigException', LReason);
end;

procedure RunChecks;
var
  LCalls: Integer;
begin
  Writeln('Configuration');
  // First: nothing has called it yet
  CheckComparerSingleton;
  CheckConfig('empty Issuer -> EIAM4DInvalidConfigurationException',
    procedure
    var
      LMiddleware: IMVCMiddleware;
    begin
      LMiddleware := TIAM4DJWTMiddleware.Create('', RuntimeTestValidatorU.TEST_AUDIENCE, '');
    end, True);
  CheckConfig('Issuer "/" -> EIAM4DInvalidConfigurationException',
    procedure
    var
      LAuthenticator: IIAM4DJWTAuthenticator;
    begin
      LAuthenticator := TIAM4DJWTAuthenticator.Create(
        TIAM4DJWTMiddlewareConfig.Create('/', RuntimeTestValidatorU.TEST_AUDIENCE, ''));
    end, True);
  CheckConfig('custom validator without Issuer -> accepted',
    procedure
    var
      LAuthenticator: IIAM4DJWTAuthenticator;
    begin
      LAuthenticator := TIAM4DJWTAuthenticator.Create(TRuntimeTestValidator.Create,
        TIAM4DJWTMiddlewareConfig.Create('', RuntimeTestValidatorU.TEST_AUDIENCE, ''));
    end, False);
  CheckExpectedAzp;
  CheckConfigDefaults;
  CheckCertificateSettings;
  CheckAudienceRequired;
  CheckConfig('empty TokenHeaderName -> EIAM4DInvalidConfigurationException',
    procedure
    var
      LConfig: TIAM4DJWTMiddlewareConfig;
      LAuthenticator: IIAM4DJWTAuthenticator;
    begin
      LConfig := TIAM4DJWTMiddlewareConfig.Create(RuntimeTestValidatorU.TEST_ISSUER, RuntimeTestValidatorU.TEST_AUDIENCE, '');
      LConfig.TokenHeaderName := '';
      LAuthenticator := TIAM4DJWTAuthenticator.Create(TRuntimeTestValidator.Create, LConfig);
    end, True);
  CheckConfig('IAM4DJWTBundle without authenticator -> EIAM4DInvalidConfigurationException',
    procedure
    var
      LAuthenticator: IIAM4DJWTAuthenticator;
      LBundle: IMVCFilterBundle;
    begin
      LAuthenticator := nil;
      LBundle := IAM4DJWTBundle(LAuthenticator);
    end, True);
  CheckConfig('IAM4DJWTEndpointFilter without authenticator -> EIAM4DInvalidConfigurationException',
    procedure
    var
      LAuthenticator: IIAM4DJWTAuthenticator;
      LFilter: TMVCEndpointFilter;
    begin
      LAuthenticator := nil;
      LFilter := IAM4DJWTEndpointFilter(LAuthenticator);
    end, True);
  CheckBundleRegisteredOnce;

  if GBundleMode then
    Writeln('Controllers (IAM4DJWTBundle)')
  else
    Writeln('Controllers (TIAM4DJWTMiddleware)');
  Check('no token -> 401, challenge without error (RFC 6750 3.1)', '/api/ctrl/protected', '', 401, ['unauthorized'],
    chCredentialsMissing);
  CheckAuthAnswer('401 answer is application/json {error,message,status}', 401, 'unauthorized');
  Check('invalid token -> 401 invalid_token', '/api/ctrl/protected', 'bad', 401, ['unauthorized'], chInvalidToken);
  CheckAuthAnswer('invalid token: answer is application/json', 401, 'unauthorized');
  Check('[MVCProduces(text/plain)] action, no token -> 401 with challenge', '/api/ctrl/plain', '', 401, ['unauthorized'],
    chCredentialsMissing);
  CheckAuthAnswer('[MVCProduces(text/plain)] action: 401 answer is application/json, not text/plain', 401,
    'unauthorized');
  Check('[MVCProduces(text/plain)] action, valid token -> 200', '/api/ctrl/plain', TEST_VALID_TOKEN, 200, ['plain ok']);
  CheckTrue(GLastContentType.StartsWith('text/plain'), '[MVCProduces(text/plain)] action: 200 answer is text/plain',
    Format('Content-Type "%s"', [GLastContentType]));
  CheckRequest('Basic credentials -> 401, challenge without error', 'GET', '/api/ctrl/protected',
    'Basic dXNlcjpwYXNz', 401, ['unauthorized'], chCredentialsMissing);
  CheckRequest('lowercase "bearer" scheme -> 200', 'GET', '/api/ctrl/protected', 'bearer ' + TEST_VALID_TOKEN, 200,
    ['user=mario']);
  CheckRequest('uppercase "BEARER" scheme -> 200', 'GET', '/api/ctrl/protected', 'BEARER ' + TEST_VALID_TOKEN, 200,
    ['user=mario']);
  Check('valid token -> 200, claims and LoggedUser populated', '/api/ctrl/protected', TEST_VALID_TOKEN, 200,
    ['user=mario', 'logged=mario', 'admin=True', 'group=True'], chNone);
  Check('LoggedUser.Roles: client roles of the audience only', '/api/ctrl/protected', TEST_VALID_TOKEN, 200,
    ['apiRole=True', 'otherClientRole=False']);
  Check('CustomData sub: the sub claim by default', '/api/ctrl/protected', TEST_VALID_TOKEN, 200, [' sub=u-123 ']);
  Check('CustomData auth_time: ISO 8601 UTC', '/api/ctrl/protected', TEST_VALID_TOKEN, 200,
    ['authTime=2026-01-01T00:00:00.000Z']);
  Check('LoggedSince from iat (UTC)', '/api/ctrl/protected', TEST_VALID_TOKEN, 200, ['loggedSinceUtc=True']);
  Check('LoggedSince without iat: current UTC time', '/api/ctrl/protected', TEST_VALID_TOKEN_NO_IAT, 200,
    ['loggedSinceUtc=True']);
  Check('Context.Data: only the keys the library reads (no claims JSON or cache nobody reads)', '/api/ctrl/protected',
    TEST_VALID_TOKEN, 200, [' dataKeys=JWT_Auth_Status,JWT_Claims_JSON,JWT_Realm,JWT_Token,__IAM4D_AUTHENTICATED_BY__ ']);
  Check('[IAM4DPublic] action, no token -> 200', '/api/ctrl/public', '', 200, ['public ok authenticated=False']);
  // Its attribute cannot be read: protected, never public by mistake, and the reason is logged
  Check('[IAM4DPublic] controller declared in the implementation section, no token -> 401', '/api/hidden/public',
    '', 401, ['unauthorized'], chCredentialsMissing);
  CheckLog('[IAM4DPublic] not readable: warning', 'not declared in the interface section', TLogType.Warning);
  Check('controller declared in the implementation section, valid token -> 200', '/api/hidden/public',
    TEST_VALID_TOKEN, 200, ['hidden public ok']);
  Check('[IAM4DPublic] action, invalid token -> 200 anonymous', '/api/ctrl/public', 'bad', 200,
    ['public ok authenticated=False']);
  Check('[IAM4DPublic] action, valid token -> claims available', '/api/ctrl/public', TEST_VALID_TOKEN, 200,
    ['public ok authenticated=True', ' user=mario ', ' sub=u-123 ']);
  // A valid token whose application roles cannot be loaded does not authenticate the request
  Check('claims transformer raising -> protected action 503', '/api/ctrl/protected', TEST_ROLES_DOWN_TOKEN, 503,
    ['temporarily_unavailable'], chNone);
  CheckAuthAnswer('claims transformer raising: 503 answer is application/json', 503, 'temporarily_unavailable');
  Check('claims transformer raising, [IAM4DPublic] action -> anonymous, LoggedUser and CustomData empty',
    '/api/ctrl/public', TEST_ROLES_DOWN_TOKEN, 200,
    ['authenticated=False', ' user= ', ' customData=0 ', ' sub= ']);
  Check('RequireAuthentication, no token -> 401 with challenge', '/api/ctrl/publicrequire', '', 401, [],
    chCredentialsMissing);
  Check('RequireAuthentication, invalid token -> 401 invalid_token', '/api/ctrl/publicrequire', 'bad', 401, [],
    chInvalidToken);
  Check('RequireRealmRole satisfied -> 200', '/api/ctrl/admin', TEST_VALID_TOKEN, 200, ['admin ok']);
  Check('RequireRealmRole not satisfied -> 403 insufficient_scope', '/api/ctrl/superadmin', TEST_VALID_TOKEN, 403, [],
    chInsufficientScope);
  CheckForbiddenGeneric('403: the required realm role is not sent to the client', ['superadmin"', 'realm role']);
  CheckLog('403: the required realm role is logged as a warning', 'realm role "superadmin"', TLogType.Warning);
  CheckRequest('RequireScope not satisfied -> 403 insufficient_scope with scope', 'GET', '/api/ctrl/scope',
    'Bearer ' + TEST_VALID_TOKEN, 403, [], chInsufficientScope, 'scope="write"');
  CheckForbiddenGeneric('403 RequireScope: generic message, the scope only in the scope attribute', ['required scope']);
  Check('Swagger-like path does not bypass authentication -> 401', '/api/ctrl/items/openapi.json', '', 401,
    ['unauthorized'], chCredentialsMissing);
  Check('Swagger-like path with valid token -> 200', '/api/ctrl/items/openapi.json', TEST_VALID_TOKEN, 200, ['item openapi.json']);
  Check('OPTIONS on an action for every verb, no token -> 401', '/api/ctrl/anyverb', '', 401, ['unauthorized'],
    chCredentialsMissing, 'OPTIONS');
  Check('OPTIONS on an action for every verb, valid token -> 200', '/api/ctrl/anyverb', TEST_VALID_TOKEN, 200, ['anyverb ok'],
    chIgnore, 'OPTIONS');
  Check('RequireAnyRole with a realm role -> 200', '/api/ctrl/anyrole', TEST_VALID_TOKEN, 200, ['anyrole ok']);
  Check('RequireAllRoles with realm and audience client roles -> 200', '/api/ctrl/allroles', TEST_VALID_TOKEN, 200, ['allroles ok']);
  Check('RequireAnyRole with a role of another client -> 403 insufficient_scope', '/api/ctrl/otherclientrole',
    TEST_VALID_TOKEN, 403, [], chInsufficientScope);
  CheckForbiddenGeneric('403 RequireAnyRole: the required roles are not sent to the client', ['other-admin']);
  CheckLog('403 RequireAnyRole: the required roles are logged', 'these roles: [other-admin]', TLogType.Warning);

  Check('validator accepting a token without claims -> 401 invalid_token', '/api/ctrl/protected', TEST_NO_CLAIMS_TOKEN,
    401, ['unauthorized'], chInvalidToken);
  Check('validator accepting a token without claims, [IAM4DPublic] action -> anonymous', '/api/ctrl/public',
    TEST_NO_CLAIMS_TOKEN, 200, ['authenticated=False', ' user= ']);
  CheckLog('validator without claims: warning', 'returned no claims', TLogType.Warning);
  // resource_access with values that are not objects: skipped, the other clients still read
  Check('resource_access with a non-object value -> 200, audience client roles kept', '/api/ctrl/protected',
    TEST_BAD_RESOURCE_TOKEN, 200, ['user=mario', 'apiRole=True', 'otherClientRole=False', 'group=True']);

  Writeln('Logging of rejected tokens');
  Check('reason with CR/LF -> 401', '/api/ctrl/protected', TEST_CRLF_TOKEN, 401, ['unauthorized'], chInvalidToken);
  CheckLog('rejected token: warning, control characters escaped', TEST_CRLF_MARKER, TLogType.Warning);
  Check('reason of 20000 characters -> 401', '/api/ctrl/protected', TEST_LONG_TOKEN, 401, ['unauthorized'], chInvalidToken);
  CheckLog('rejected token: warning, reason capped', TEST_LONG_MARKER, TLogType.Warning, 1024);

  if GBundleMode then
  begin
    Writeln('Minimal API (engine-wide IAM4DJWTBundle)');
    Check('group without filter, no token -> 401', '/min/secure/hello', '', 401, ['unauthorized'], chCredentialsMissing);
    CheckAuthAnswer('Minimal API 401 answer is application/json', 401, 'unauthorized');
    Check('group without filter, invalid token -> 401 invalid_token', '/min/secure/hello', 'bad', 401, ['unauthorized'],
      chInvalidToken);
    Check('group without filter, valid token -> 200', '/min/secure/hello', TEST_VALID_TOKEN, 200,
      ['user=mario', 'logged=mario']);
    Check('RequireRealmRole not satisfied -> 403 insufficient_scope', '/min/secure/superadmin', TEST_VALID_TOKEN, 403, [],
      chInsufficientScope);
    CheckForbiddenGeneric('Minimal API 403: the required realm role is not sent to the client', ['realm role']);
    LCalls := GValidateCalls;
    Check('bundle and group filter on the same authenticator -> 200', '/min/shared/hello', TEST_VALID_TOKEN, 200,
      ['shared user=mario']);
    CheckTrue(GValidateCalls - LCalls = 1, 'bundle and group filter sharing the authenticator validate once',
      Format('%d validations', [GValidateCalls - LCalls]));
    Check('engine-wide bundle checks every Minimal API route: group without filter, no token -> 401',
      '/min/open/hello', '', 401, ['unauthorized'], chCredentialsMissing);
    Check('[IAM4DPublic] controller action still public under the bundle', '/api/ctrl/public', '', 200,
      ['public ok authenticated=False']);
  end
  else
  begin
    Writeln('Minimal API (IAM4DJWTEndpointFilter and IAM4DJWTBundle on groups)');
    Check('no token -> 401, challenge without error', '/min/secure/hello', '', 401, ['unauthorized'], chCredentialsMissing);
    CheckAuthAnswer('group filter: 401 answer is application/json', 401, 'unauthorized');
    Check('invalid token -> 401 invalid_token', '/min/secure/hello', 'bad', 401, ['unauthorized'], chInvalidToken);
    LCalls := GValidateCalls;
    Check('valid token -> 200 (middleware and filter on the same request)', '/min/secure/hello', TEST_VALID_TOKEN, 200,
      ['user=mario', 'logged=mario']);
    CheckTrue(GValidateCalls - LCalls = 1, 'middleware and filter sharing the authenticator validate once',
      Format('%d validations', [GValidateCalls - LCalls]));
    Check('RequireRealmRole not satisfied -> 403 insufficient_scope', '/min/secure/superadmin', TEST_VALID_TOKEN, 403, [],
      chInsufficientScope);
    CheckForbiddenGeneric('Minimal API 403: the required realm role is not sent to the client', ['realm role']);
    Check('group without filter, no token -> 200', '/min/open/hello', '', 200, ['open ok']);
    Check('AllowAnonymous, no token -> 200 anonymous', '/min/anon/hello', '', 200, ['authenticated=False']);
    Check('AllowAnonymous, valid token -> 200 authenticated', '/min/anon/hello', TEST_VALID_TOKEN, 200, ['authenticated=True']);
    Check('AllowAnonymous, invalid token -> 401', '/min/anon/hello', 'bad', 401, ['Invalid or expired JWT token'],
      chInvalidToken);
    Check('bundle on a group, RolesClaimName: LoggedUser.Roles from the configured claim', '/min/claims/hello', TEST_VALID_TOKEN, 200,
      ['appEditor=True', 'legacy=False']);
    Check('SubjectClaimName: CustomData sub from the configured claim', '/min/claims/hello', TEST_VALID_TOKEN, 200,
      ['sub=object-42']);
    Check('namespaced claim names (https://app.example.com/...): SubjectClaimName and GetCustomClaim*',
      '/min/nsclaims/hello', TEST_VALID_TOKEN, 200,
      ['ns sub=acme ', 'tenant=acme ', 'default=acme ', 'level=7 ', 'absent=none ']);
    Check('bundle on a sibling group, JWKS_URL: keys fetched without discovery -> 200', '/min/jwksurl/hello', TOKEN_RS256, 200, ['jwksurl sub=user-1']);

    // Real validator, tokens signed by the test: the configuration reaches the validator
    Check('real validator: signed token -> 200', '/min/signed/hello', SignedToken(sfNone), 200, ['signed sub=signed-user']);
    Check('real validator: several audiences, azp the client -> 200', '/min/signed/hello',
      SignedToken(sfMultiAudWithAzp), 200, ['signed sub=signed-user']);
    Check('real validator: header typ at+jwt (RFC 9068) -> 200', '/min/signed/hello', SignedToken(sfAtJwt), 200,
      ['signed sub=signed-user']);
    Check('real validator: header typ application/at+jwt -> 200', '/min/signed/hello', SignedToken(sfAppAtJwt), 200,
      ['signed sub=signed-user']);
    Check('real validator: header typ dpop+jwt -> 401', '/min/signed/hello', SignedToken(sfDPoPJwt), 401, [],
      chInvalidToken);
    Check('real validator: other issuer -> 401', '/min/signed/hello', SignedToken(sfOtherIssuer), 401, [], chInvalidToken);
    Check('real validator: other audience -> 401', '/min/signed/hello', SignedToken(sfOtherAudience), 401, [], chInvalidToken);
    Check('real validator: expired -> 401', '/min/signed/hello', SignedToken(sfExpired), 401, [], chInvalidToken);
    Check('real validator: nbf in the future -> 401', '/min/signed/hello', SignedToken(sfNotYetValid), 401, [], chInvalidToken);
    Check('real validator: alg none -> 401', '/min/signed/hello', SignedToken(sfAlgNone), 401, [], chInvalidToken);
    Check('real validator: HS256 keyed with the public modulus -> 401', '/min/signed/hello', SignedToken(sfHS256), 401, [],
      chInvalidToken);
    Check('real validator: altered signature -> 401', '/min/signed/hello', SignedToken(sfBadSignature), 401, [],
      chInvalidToken);
    Check('real validator: unknown kid -> 401', '/min/signed/hello', SignedToken(sfUnknownKid), 401, [], chInvalidToken);
    Check('real validator: typ ID (ExpectedTokenType Bearer) -> 401', '/min/signed/hello', SignedToken(sfTypID), 401, [],
      chInvalidToken);
    Check('real validator: azp of another client (ExpectedAzp) -> 401', '/min/signed/hello', SignedToken(sfOtherAzp), 401,
      [], chInvalidToken);
    Check('real validator: several audiences without azp (RequireAzpWhenMultipleAud) -> 401', '/min/signed/hello',
      SignedToken(sfMultiAudNoAzp), 401, [], chInvalidToken);
    Check('real validator, AudienceValidationEnabled False: other audience -> 200', '/min/signednoaud/hello',
      SignedToken(sfOtherAudience), 200, ['signednoaud sub=signed-user']);
    Check('real validator, AudienceValidationEnabled False: other issuer still -> 401', '/min/signednoaud/hello',
      SignedToken(sfOtherIssuer), 401, [], chInvalidToken);
    // Case-sensitive, as Keycloak: the token has realm role "admin" and scope "read"
    Check('RequireRealmRole(''ADMIN'') with realm role admin -> 403', '/min/signed/upperrealm', SignedToken(sfNone), 403, [],
      chInsufficientScope);
    Check('RequireAnyRole([''ADMIN'']) with role admin -> 403', '/min/signed/upperrole', SignedToken(sfNone), 403, [],
      chInsufficientScope);
    Check('RequireScope(''READ'') with scope read -> 403', '/min/signed/upperscope', SignedToken(sfNone), 403, [],
      chInsufficientScope);

    Check('bundle on a group, no token -> 401', '/min/claims/hello', '', 401, ['unauthorized'], chCredentialsMissing);
  end;

  Writeln('Claims transformation (roles from the application)');
  CheckConfig('TIAM4DRolesClaimsTransformer without loader -> EIAM4DInvalidConfigurationException',
    procedure
    var
      LTransformer: IIAM4DClaimsTransformer;
    begin
      LTransformer := TIAM4DRolesClaimsTransformer.Create(nil);
    end, True);
  CheckConfig('TIAM4DRolesClaimsTransformer with negative TTL -> EIAM4DInvalidConfigurationException',
    procedure
    var
      LTransformer: IIAM4DClaimsTransformer;
    begin
      LTransformer := TIAM4DRolesClaimsTransformer.Create(
        function(const ASubject: string; const AClaims: TJSONObject): TArray<string>
        begin
          Result := [];
        end, rmReplace, -1);
    end, True);
  CheckRolesLoadOvertakenByInvalidate;
  // Controllers (middleware: SetClaimsTransformer; bundle: Config.ClaimsTransformer), rmMerge, no cache
  LCalls := GMergeLoads;
  Check('controllers rmMerge: role of the application -> RequireAnyRole 200', '/api/ctrl/dbrole', TEST_VALID_TOKEN, 200,
    ['dbrole ok']);
  Check('controllers rmMerge: token roles kept', '/api/ctrl/protected', TEST_VALID_TOKEN, 200,
    ['admin=True', 'apiRole=True', 'otherClientRole=False']);
  CheckTrue(GMergeLoads - LCalls = 2, 'no cache (TTL 0): loader called on every request',
    Format('%d loads for 2 requests', [GMergeLoads - LCalls]));
  LCalls := GMergeLoads;
  Check('controllers rmMerge: invalid token -> 401', '/api/ctrl/dbrole', 'bad', 401, ['unauthorized'], chInvalidToken);
  Check('controllers rmMerge: no token -> 401', '/api/ctrl/dbrole', '', 401, ['unauthorized'], chCredentialsMissing);
  CheckTrue(GMergeLoads = LCalls, 'loader not called without a valid token',
    Format('%d loads', [GMergeLoads - LCalls]));
  if not GBundleMode then
  begin
    // Minimal API filter (Config.ClaimsTransformer, rmReplace, cache)
    GReplaceTransformerObj.Clear;
    LCalls := GReplaceLoads;
    Check('filter rmReplace: application roles, blanks and duplicates dropped, other case kept, token roles gone',
      '/min/rolesdb/hello', TEST_VALID_TOKEN, 200, ['editor=True', 'viewer=True', 'admin=False', 'auditor=False', 'count=3 ']);
    Check('filter rmReplace: the token is unchanged (Context.Keycloak)', '/min/rolesdb/hello', TEST_VALID_TOKEN, 200,
      ['tokenRealmAdmin=True']);
    Check('filter rmReplace: RequireAnyRole with an application role -> 200', '/min/rolesdb/editor', TEST_VALID_TOKEN, 200,
      ['editor ok']);
    Check('filter rmReplace: RequireAnyRole with a dropped token role -> 403', '/min/rolesdb/anyadmin', TEST_VALID_TOKEN,
      403, [], chInsufficientScope);
    Check('filter rmReplace: RequireRealmRole still reads the token -> 200', '/min/rolesdb/realmadmin', TEST_VALID_TOKEN,
      200, ['realmadmin ok']);
    CheckTrue(GReplaceLoads - LCalls = 1, 'cache: loader called once for 5 requests of the same subject',
      Format('%d loads', [GReplaceLoads - LCalls]));
    CheckTrue(GReplaceTransformerObj.CacheCount = 1, 'cache: one entry per subject',
      Format('%d entries', [GReplaceTransformerObj.CacheCount]));
    // Same sub from another issuer: another user, never the cached roles of the first one
    LCalls := GReplaceLoads;
    Check('cache: same sub from another issuer -> its own roles, not the cached ones', '/min/rolesdb/hello',
      TEST_OTHER_ISSUER_TOKEN, 200, ['otherIss=True', 'editor=False', 'count=1 ']);
    Check('cache: the first issuer still gets its roles', '/min/rolesdb/hello', TEST_VALID_TOKEN, 200,
      ['editor=True', 'otherIss=False']);
    CheckTrue(GReplaceLoads - LCalls = 1, 'cache: loaded once for the new issuer, first issuer still cached',
      Format('%d loads', [GReplaceLoads - LCalls]));
    CheckTrue(GReplaceTransformerObj.CacheCount = 2, 'cache: one entry per issuer and subject',
      Format('%d entries', [GReplaceTransformerObj.CacheCount]));
    GReplaceTransformerObj.Invalidate(TEST_OTHER_ISSUER, 'u-123');
    CheckTrue(GReplaceTransformerObj.CacheCount = 1, 'Invalidate(issuer, subject): only that user dropped',
      Format('%d entries', [GReplaceTransformerObj.CacheCount]));
    Check('cache: the other issuer reloaded once more', '/min/rolesdb/hello', TEST_OTHER_ISSUER_TOKEN, 200,
      ['otherIss=True']);
    CheckTrue(GReplaceTransformerObj.CacheCount = 2, 'cache: two entries again',
      Format('%d entries', [GReplaceTransformerObj.CacheCount]));
    GReplaceTransformerObj.Invalidate('u-123');
    CheckTrue(GReplaceTransformerObj.CacheCount = 0, 'Invalidate(subject): the subject dropped for every issuer',
      Format('%d entries', [GReplaceTransformerObj.CacheCount]));
    LCalls := GReplaceLoads;
    Check('after Invalidate(subject) -> 200', '/min/rolesdb/hello', TEST_VALID_TOKEN, 200, ['editor=True']);
    CheckTrue(GReplaceLoads - LCalls = 1, 'Invalidate(subject): roles loaded again',
      Format('%d loads', [GReplaceLoads - LCalls]));
    LCalls := GShortLoads;
    Check('TTL 1 second: first request', '/min/rolesshort/hello', TEST_VALID_TOKEN, 200, ['short=True']);
    Check('TTL 1 second: cached', '/min/rolesshort/hello', TEST_VALID_TOKEN, 200, ['short=True']);
    // Well past the TTL: a slow machine does not turn the expiry into a cache hit
    Sleep(1600);
    Check('TTL 1 second: expired', '/min/rolesshort/hello', TEST_VALID_TOKEN, 200, ['short=True']);
    CheckTrue(GShortLoads - LCalls = 2, 'TTL: roles loaded again after expiry',
      Format('%d loads for 3 requests', [GShortLoads - LCalls]));
    // Roles source down
    CheckRequest('loader raising -> 503 temporarily_unavailable, no challenge', 'GET', '/min/rolesdown/hello',
      'Bearer ' + TEST_VALID_TOKEN, 503, ['temporarily_unavailable'], chNone);
    CheckAuthAnswer('loader raising: 503 answer is application/json', 503, 'temporarily_unavailable');
    CheckLog('loader failure logged as error', ROLES_DOWN_MARKER, TLogType.Error);
    Check('loader raising, invalid token -> 401 (transformer not called)', '/min/rolesdown/hello', 'bad', 401,
      ['unauthorized'], chInvalidToken);
    Check('AllowAnonymous, loader raising, no token -> 200 anonymous', '/min/rolesdownanon/hello', '', 200, ['count=0 ']);
    Check('AllowAnonymous, loader raising, valid token -> 503 (not anonymous)', '/min/rolesdownanon/hello',
      TEST_VALID_TOKEN, 503, ['temporarily_unavailable']);

    Writeln('Identity provider unavailable');
    CheckRequest('JWKS discovery failing -> 503 with Retry-After', 'GET', '/min/idpdown/hello',
      'Bearer ' + UnsignedToken(IdPDownIssuer), 503, ['temporarily_unavailable'], chNone, '', True);
    CheckAuthAnswer('identity provider down: 503 answer is application/json', 503, 'temporarily_unavailable');
    // Before the second request: its message (failure kept within the refresh interval) names the issuer anyway
    CheckLog('identity provider failure logged as error, issuer named', 'iam4d-down"', TLogType.Error);
    CheckRequest('within the refresh interval -> 503 with Retry-After', 'GET', '/min/idpdown/hello',
      'Bearer ' + UnsignedToken(IdPDownIssuer), 503, ['temporarily_unavailable'], chNone, '', True);
  end;

  Writeln('Swagger / OpenAPI security injection');
  Check('Swagger 2.0: securityDefinitions.bearer + global requirement', '/swagger2.json', '', 200,
    ['"securityDefinitions"', '"bearer":{"type":"apiKey"', '"security":[{"bearer":[]}]']);
  Check('OpenAPI 3: components.securitySchemes.bearer + global requirement', '/openapi3.json', '', 200,
    ['"securitySchemes"', '"scheme":"bearer"', '"security":[{"bearer":[]}]']);
end;

var
  LHostType: string;
  LServer: IMVCServer;
  LEngine: TMVCEngine;
  LIdP: TFakeIdP;
begin
  ReportMemoryLeaksOnShutdown := True;
  IsMultiThread := True;
  UseConsoleLogger := False; // keep the console for check results; logs still go to files
  LEngine := nil;
  try
    LHostType := LowerCase(ParamStr(1));
    if LHostType = '' then
      LHostType := 'indy';
    if ParamStr(2) <> '' then
      GPort := StrToInt(ParamStr(2));
    if SameText(ParamStr(3), 'bundle') then
      GBundleMode := True
    else if (ParamStr(3) <> '') and not SameText(ParamStr(3), 'middleware') then
      raise EArgumentException.CreateFmt('Unknown mode "%s": use middleware or bundle', [ParamStr(3)]);

    InstallLogCapture;
    CreateClaimsTransformers;

    if LHostType = 'webbroker' then
      LServer := TMVCServerFactory.CreateWebBroker(nil, ConfigureEngine)
{$IFDEF MSWINDOWS}
    else if LHostType = 'httpsys' then
    begin
      GHost := 'localhost';
      LEngine := TMVCEngine.Create(nil);
      ConfigureEngine(LEngine);
      LServer := TMVCServerFactory.CreateHttpSys(LEngine);
    end
{$ENDIF}
    else if LHostType = 'indy' then
    begin
      LEngine := TMVCEngine.Create(nil);
      ConfigureEngine(LEngine);
      LServer := TMVCServerFactory.CreateIndyDirect(LEngine);
    end
    else
      raise EArgumentException.CreateFmt('Unknown host "%s": use indy, webbroker or httpsys (Windows only)', [LHostType]);

    GSignLock := TCriticalSection.Create;
    GSigner := TTestRSASigner.Create(2048);
    LIdP := TFakeIdP.Create(GPort + 100);
    try
      LServer.Listen(GPort, GHost);
      try
        Writeln(Format('IAMClient4D DMVC runtime test - host %s, mode %s, DMVC %s, http://%s:%d',
          [LHostType, IfThen(GBundleMode, 'bundle', 'middleware'), DMVCFRAMEWORK_VERSION, GHost, GPort]));
        RunChecks;
      finally
        LServer.Stop;
      end;
    finally
      LIdP.Free;
    end;
    LServer := nil;
    FreeAndNil(GSigner);
    FreeAndNil(GSignLock);
    // Indy Direct and HTTP.sys servers do not own the engine
    LEngine.Free;

    // WebBroker web modules (engine, middleware, filters) are otherwise freed in the
    // finalization of Web.WebReq, after the DMVC units they depend on
    if LHostType = 'webbroker' then
      FreeWebModules;

    Writeln(Format('%d passed, %d failed', [GPassed, GFailed]));
    ExitCode := GFailed;
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
      ExitCode := 99;
    end;
  end;
  ReleaseClaimsTransformers;
  GLogCapture := nil;
end.
