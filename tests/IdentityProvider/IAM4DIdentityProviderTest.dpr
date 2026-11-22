program IAM4DIdentityProviderTest;

// Identity brokering test. Offline: config map, JSON mapping, broker builders, kc_idp_hint config,
// Admin API requests against a local HTTP server (path encoding, error mapping, async wrappers).
// With a reachable Keycloak: identity provider and mapper management through the Admin REST API,
// user manager on names that need encoding, the login redirect driven by kc_idp_hint, and the
// password grant (revocation, offline token, at+jwt access tokens) and prompt=none login.
// Usage: IAM4DIdentityProviderTest [KeycloakURL [AdminUser [AdminPassword]]]
//   defaults: http://localhost:18080 (docker\up.cmd) admin admin. Creates and deletes the realm iam4d-idp-test.

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Classes,
  System.DateUtils,
  System.SyncObjs,
  System.Generics.Collections,
  System.JSON,
  System.Net.URLClient,
  System.NetConsts,
  System.Net.HttpClient,
  System.NetEncoding,
  System.RegularExpressions,
  IdContext,
  IdSocketHandle,
  IdCustomHTTPServer,
  IdHTTPServer,
  Async.Core,
  IAMClient4D.Core,
  IAMClient4D.Common.Security,
  IAMClient4D.Common.Constants,
  IAMClient4D.Common.PlatformUtils,
  IAMClient4D.Security.Core,
  IAMClient4D.Security.JWT,
  IAMClient4D.Exceptions,
  IAMClient4D.Config.Builder,
  IAMClient4D.UserManagement.Core,
  IAMClient4D.UserManagement.Helpers,
  IAMClient4D.UserManagement.Keycloak,
  IAMClient4D.UserManagement.Keycloak.Async,
  IAMClient4D.UserManagement.Validation,
  IAMClient4D.IdentityProvider.Core,
  IAMClient4D.IdentityProvider.Keycloak,
  IAMClient4D.IdentityProvider.Keycloak.Async,
  IAMClient4D.IdentityProvider.Builders;

const
  CRealm = 'iam4d-idp-test';
  CAdminClientID = 'iam4d-admin';
  CAdminClientSecret = 'iam4d-admin-secret';
  CAppClientID = 'iam4d-app';
  CCallbackURL = 'http://127.0.0.1:18765/callback';
  CTenant = '6f1c3a52-0b7e-4d2a-9c8f-2e5d7b4a1c90';
  // Realm role and user whose names need encoding: space in a path segment, '+' in a query value
  CRoleWithSpace = 'Sales Manager';
  CUsername = 'mario.rossi';
  CUserEmail = 'mario.rossi+iam4d@example.com';
  CUserFirstName = 'Mario Luigi';
  // Public client with "Direct access grants" (Resource Owner Password Credentials)
  CPasswordClientID = 'iam4d-password';
  // Same, with RFC 9068 access tokens (header typ at+jwt)
  CAtJwtClientID = 'iam4d-password-atjwt';
  // Local callback server of the prompt=none login (a redirect URI of CAppClientID)
  CCallbackPort = 18765;
  CUserPassword = 'Pa&ss=w+rd %1';
  // Self-signed certificate (base64 DER) standing for the signing certificate of an identity provider
  CTestCertificate =
    'MIIBsjCCAVegAwIBAgIUMFVDEaZDdWSwiqUVPesEs2GDJCAwCgYIKoZIzj0EAwIwLTErMCkGA1UEAwwiSUFNQ2xpZW50NEQgdGVzdCBp' +
    'ZGVudGl0eSBwcm92aWRlcjAgFw0yNjA5MjgxMzMzMDZaGA8yMTI2MDkwNDEzMzMwNlowLTErMCkGA1UEAwwiSUFNQ2xpZW50NEQgdGVz' +
    'dCBpZGVudGl0eSBwcm92aWRlcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBLEqf0ceYcy/KIKJbagNWluCDx/82SyOwrX8VM0aPrr' +
    'PSbjAi5RB0hlqg2URLbHGrzIdhVpzeOuFC/WhFBe7C6jUzBRMB0GA1UdDgQWBBRj20PYXiLmPC00Xjghp8bto/KCQjAfBgNVHSMEGDAW' +
    'gBRj20PYXiLmPC00Xjghp8bto/KCQjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQDSpwPcfEWMmfiz+4UoMKOgEd+E' +
    'AMYVTqaxfpH+tIZ2GAIhAJukNiWSQUgjnTN+IMwoSvTVFybJ1pGrauHaddObPIEO';

var
  GPassed: Integer = 0;
  GFailed: Integer = 0;
  GSkipped: Integer = 0;

procedure Check(const AName: string; ACondition: Boolean);
begin
  if ACondition then
    Inc(GPassed)
  else
  begin
    Inc(GFailed);
    Writeln('  FAIL ', AName);
  end;
end;

// A check not run: counted and printed, so a partial run never reads as a full pass
procedure Skip(const AName, AReason: string);
begin
  Inc(GSkipped);
  Writeln('  SKIP ', AName, ': ', AReason);
end;

// True when this machine gets an HTTP response from AURL (any status): the Internet is there
function InternetReachable(const AURL: string): Boolean;
var
  LClient: THTTPClient;
begin
  LClient := THTTPClient.Create;
  try
    LClient.ConnectionTimeout := 5000;
    LClient.ResponseTimeout := 10000;
    LClient.HandleRedirects := False;
    try
      Result := LClient.Head(AURL).StatusCode > 0;
    except
      on Exception do
        Result := False;
    end;
  finally
    LClient.Free;
  end;
end;

function Raises(const AProc: TProc; AClass: ExceptClass): Boolean;
begin
  try
    AProc();
    Result := False;
  except
    on E: Exception do
      Result := E is AClass;
  end;
end;

function IsRedirect(const AResponse: IHTTPResponse): Boolean;
begin
  Result := (AResponse.StatusCode = 301) or (AResponse.StatusCode = 302) or (AResponse.StatusCode = 303) or
    (AResponse.StatusCode = 307);
end;

// Printed with a failed navigation check
function Describe(const AResponse: IHTTPResponse): string;
begin
  Result := Format('[%d %s]', [AResponse.StatusCode, AResponse.HeaderValue['Location'].Substring(0, 160)]);
  if not IsRedirect(AResponse) then
    Result := Result + ' ' + AResponse.ContentAsString(TEncoding.UTF8).Substring(0, 300);
end;

function ParseObject(const AText: string): TJSONObject;
begin
  Result := TJSONObject.ParseJSONValue(AText) as TJSONObject;
  if Result = nil then
    raise Exception.Create('Invalid JSON: ' + AText);
end;

// Exception raised by AProc (the caller frees it), nil if none
function Capture(const AProc: TProc): Exception;
begin
  Result := nil;
  try
    AProc();
  except
    Result := Exception(AcquireExceptionObject);
  end;
end;

// Result of AFunc; False, with the exception printed, if it raises
function Safely(const AFunc: TFunc<Boolean>): Boolean;
begin
  try
    Result := AFunc();
  except
    on E: Exception do
    begin
      Writeln('    ', E.ClassName, ': ', E.Message.Substring(0, 300));
      Result := False;
    end;
  end;
end;

// ============================================================================
// Offline
// ============================================================================

procedure TestConfigMap;
var
  LMap, LCopy, LOther: TIAM4DConfigMap;
begin
  Writeln('Config map');
  LMap := Default(TIAM4DConfigMap);
  Check('empty map', LMap.Count = 0);
  Check('missing key reads empty', LMap.Values['a'] = '');

  LMap.Values['a'] := '1';
  LMap.Values['a'] := '2';
  Check('set replaces', (LMap.Values['a'] = '2') and (LMap.Count = 1));
  Check('keys are case-sensitive', not LMap.Contains('A'));

  LCopy := LMap;
  LCopy.Values['a'] := 'x';
  LCopy.Values['b'] := 'y';
  Check('copy write does not change the source', (LMap.Values['a'] = '2') and not LMap.Contains('b'));
  LCopy.Remove('a');
  Check('copy remove does not change the source', LMap.Contains('a') and not LCopy.Contains('a'));

  LMap.SetBool('t', True);
  Check('SetBool writes true', LMap.Values['t'] = 'true');
  Check('GetBool reads true', LMap.GetBool('t'));
  LMap.Values['t'] := 'TRUE';
  Check('GetBool ignores case', LMap.GetBool('t'));
  Check('GetBool default', LMap.GetBool('missing', True) and not LMap.GetBool('missing'));

  LOther := Default(TIAM4DConfigMap);
  LOther.Values['a'] := 'z';
  LOther.Values['c'] := 'w';
  LMap.Merge(LOther);
  Check('merge replaces and adds', (LMap.Values['a'] = 'z') and (LMap.Values['c'] = 'w') and (LMap.Count = 3));

  Check('empty key rejected', Raises(
    procedure
    var
      LLocal: TIAM4DConfigMap;
    begin
      LLocal := Default(TIAM4DConfigMap);
      LLocal.Values[''] := 'x';
    end, EArgumentException));

  LMap.Clear;
  Check('clear', LMap.Count = 0);
end;

procedure TestIdentityProviderRecord;
var
  LIdP, LCopy: TIAM4DIdentityProvider;
  LMapper: TIAM4DIdentityProviderMapper;
begin
  Writeln('Identity provider record');
  LIdP := TIAM4DIdentityProvider.Create(' entra ', IAM4D_IDP_PROVIDER_OIDC);
  Check('Create trims alias', LIdP.Alias = 'entra');
  Check('Create enables', LIdP.Enabled);
  Check('Create defaults', not LIdP.HideOnLogin and not LIdP.TrustEmail and (LIdP.Config.Count = 0));
  Check('SyncMode default', LIdP.SyncMode = ismDefault);

  LIdP.SyncMode := ismForce;
  Check('SyncMode writes config', LIdP.Config.Values['syncMode'] = 'FORCE');
  Check('SyncMode reads config', LIdP.SyncMode = ismForce);
  LIdP.SyncMode := ismDefault;
  Check('SyncMode default removes the key', not LIdP.Config.Contains('syncMode'));

  LIdP.Config.Values['k'] := 'v';
  Check('config writable through the property', LIdP.Config.Values['k'] = 'v');
  LCopy := LIdP;
  LCopy.Config.Values['k'] := 'w';
  Check('record copies have independent config', LIdP.Config.Values['k'] = 'v');

  Check('sync mode strings', (TIAM4DIdentityProviderSyncMode.FromString('import') = ismImport) and
    (TIAM4DIdentityProviderSyncMode.FromString('') = ismDefault) and (ismInherit.ToString = 'INHERIT'));

  LMapper := TIAM4DIdentityProviderMapper.Create('entra', 'email', 'oidc-user-attribute-idp-mapper');
  Check('mapper Create', (LMapper.IdentityProviderAlias = 'entra') and (LMapper.ID = '') and (LMapper.Config.Count = 0));
end;

procedure TestJSON;
var
  LIdP, LRead: TIAM4DIdentityProvider;
  LJSON, LConfig: TJSONObject;
  LMapper, LMapperRead: TIAM4DIdentityProviderMapper;
  LMap: TIAM4DConfigMap;
begin
  Writeln('JSON mapping');
  LIdP := TIAM4DIdentityProvider.Create('entra', IAM4D_IDP_PROVIDER_OIDC);
  LIdP.HideOnLogin := True;
  LIdP.TrustEmail := True;
  LIdP.FirstBrokerLoginFlowAlias := 'first broker login';
  LIdP.Config.Values['clientId'] := 'abc';

  LJSON := TIAM4DIdentityProviderJSON.IdentityProviderToJSON(LIdP);
  try
    Check('JSON alias/providerId', (LJSON.GetValue<string>('alias') = 'entra') and
      (LJSON.GetValue<string>('providerId') = 'oidc'));
    Check('JSON hideOnLogin', LJSON.GetValue<Boolean>('hideOnLogin'));
    Check('JSON flow alias', LJSON.GetValue<string>('firstBrokerLoginFlowAlias') = 'first broker login');
    Check('JSON empty fields omitted', (LJSON.GetValue('displayName') = nil) and (LJSON.GetValue('internalId') = nil)
      and (LJSON.GetValue('postBrokerLoginFlowAlias') = nil));
    LConfig := LJSON.GetValue('config') as TJSONObject;
    Check('JSON config', LConfig.GetValue<string>('clientId') = 'abc');
    Check('JSON config hideOnLoginPage (Keycloak < 26)', LConfig.GetValue<string>('hideOnLoginPage') = 'true');

    LRead := TIAM4DIdentityProviderJSON.IdentityProviderFromJSON(LJSON);
    Check('round trip', (LRead.Alias = 'entra') and LRead.Enabled and LRead.HideOnLogin and LRead.TrustEmail and
      (LRead.FirstBrokerLoginFlowAlias = 'first broker login') and (LRead.Config.Values['clientId'] = 'abc'));
    Check('round trip drops hideOnLoginPage', (LRead.Config.Count = 1) and not LRead.Config.Contains('hideOnLoginPage'));
  finally
    LJSON.Free;
  end;
  Check('ToJSON leaves the record config unchanged', not LIdP.Config.Contains('hideOnLoginPage'));

  // As returned by Keycloak 26.4
  LJSON := ParseObject('{"alias":"probe","internalId":"64003068-2ef5","providerId":"oidc","enabled":true,' +
    '"updateProfileFirstLoginMode":"on","trustEmail":true,"storeToken":false,"addReadTokenRoleOnCreate":false,' +
    '"authenticateByDefault":false,"linkOnly":false,"hideOnLogin":true,"config":{"syncMode":"IMPORT",' +
    '"clientSecret":"**********","clientId":"x"}}');
  try
    LRead := TIAM4DIdentityProviderJSON.IdentityProviderFromJSON(LJSON);
    Check('Keycloak 26 representation', (LRead.InternalID = '64003068-2ef5') and LRead.TrustEmail and
      LRead.HideOnLogin and not LRead.StoreToken and (LRead.SyncMode = ismImport));
    Check('masked secret', LRead.Config.Values['clientSecret'] = IAM4D_IDP_SECRET_MASK);
  finally
    LJSON.Free;
  end;

  // Keycloak < 26: hideOnLoginPage in config only
  LJSON := ParseObject('{"alias":"old","providerId":"saml","enabled":false,"config":{"hideOnLoginPage":"true","x":"1"}}');
  try
    LRead := TIAM4DIdentityProviderJSON.IdentityProviderFromJSON(LJSON);
    Check('legacy hideOnLoginPage', LRead.HideOnLogin and not LRead.Enabled and (LRead.Config.Count = 1));
  finally
    LJSON.Free;
  end;

  LJSON := ParseObject('{"s":"a","n":5,"b":true,"z":null}');
  try
    LMap := TIAM4DIdentityProviderJSON.ConfigFromJSON(LJSON);
    Check('config non-string values', (LMap.Values['s'] = 'a') and (LMap.Values['n'] = '5') and
      (LMap.Values['b'] = 'true') and not LMap.Contains('z'));
  finally
    LJSON.Free;
  end;

  LMapper := TIAM4DIdentityProviderMapper.Create('entra', 'email', 'oidc-user-attribute-idp-mapper');
  LMapper.Config.Values['claim'] := 'email';
  LJSON := TIAM4DIdentityProviderJSON.MapperToJSON(LMapper);
  try
    Check('mapper JSON', (LJSON.GetValue<string>('identityProviderMapper') = 'oidc-user-attribute-idp-mapper') and
      (LJSON.GetValue('id') = nil));
    LJSON.AddPair('id', 'm1');
    LMapperRead := TIAM4DIdentityProviderJSON.MapperFromJSON(LJSON);
    Check('mapper round trip', (LMapperRead.ID = 'm1') and (LMapperRead.Name = 'email') and
      (LMapperRead.IdentityProviderAlias = 'entra') and (LMapperRead.Config.Values['claim'] = 'email'));
  finally
    LJSON.Free;
  end;
end;

procedure TestEntraBuilder;
var
  LIdP: TIAM4DIdentityProvider;
begin
  Writeln('Entra builder');
  LIdP := TIAM4DEntraIdPBuilder.New
    .WithTenant(CTenant)
    .WithClient('entra-client', 'entra-secret')
    .Build;
  Check('Entra defaults', (LIdP.Alias = 'entra') and (LIdP.ProviderID = 'oidc') and LIdP.Enabled and
    (LIdP.DisplayName = 'Microsoft'));
  Check('Entra endpoints', (LIdP.Config.Values['authorizationUrl'] =
    'https://login.microsoftonline.com/' + CTenant + '/oauth2/v2.0/authorize') and
    (LIdP.Config.Values['tokenUrl'] = 'https://login.microsoftonline.com/' + CTenant + '/oauth2/v2.0/token') and
    (LIdP.Config.Values['jwksUrl'] = 'https://login.microsoftonline.com/' + CTenant + '/discovery/v2.0/keys') and
    (LIdP.Config.Values['logoutUrl'] = 'https://login.microsoftonline.com/' + CTenant + '/oauth2/v2.0/logout'));
  Check('Entra issuer for a tenant ID', LIdP.Config.Values['issuer'] = 'https://login.microsoftonline.com/' + CTenant + '/v2.0');
  Check('Entra client', (LIdP.Config.Values['clientId'] = 'entra-client') and
    (LIdP.Config.Values['clientSecret'] = 'entra-secret') and
    (LIdP.Config.Values['clientAuthMethod'] = 'client_secret_post'));
  Check('Entra security', LIdP.Config.GetBool('validateSignature') and LIdP.Config.GetBool('useJwksUrl') and
    LIdP.Config.GetBool('pkceEnabled') and (LIdP.Config.Values['pkceMethod'] = 'S256'));
  Check('Entra scopes', LIdP.Config.Values['defaultScope'] = 'openid profile email');

  LIdP := TIAM4DEntraIdPBuilder.New('entra-any')
    .WithTenant('organizations')
    .WithClient('c', 's')
    .WithDisplayName('Work account')
    .WithScopes(['openid', 'email'])
    .WithSyncMode(ismForce)
    .WithTrustEmail(False)
    .WithHideOnLogin
    .WithPrompt('select_account')
    .WithFirstBrokerLoginFlow('custom first login')
    .WithConfig('loginHint', 'true')
    .Build;
  Check('Entra multi-tenant: no issuer check', not LIdP.Config.Contains('issuer'));
  Check('Entra multi-tenant endpoints', LIdP.Config.Values['authorizationUrl'] =
    'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize');
  Check('Entra options', (LIdP.Alias = 'entra-any') and (LIdP.DisplayName = 'Work account') and
    (LIdP.Config.Values['defaultScope'] = 'openid email') and (LIdP.SyncMode = ismForce) and not LIdP.TrustEmail and
    LIdP.HideOnLogin and (LIdP.Config.Values['prompt'] = 'select_account') and
    (LIdP.FirstBrokerLoginFlowAlias = 'custom first login') and LIdP.Config.GetBool('loginHint'));

  // Trust email: only for a directory ID, where the issuer is checked
  LIdP := TIAM4DEntraIdPBuilder.New.WithTenant(CTenant).WithClient('c', 's').WithTrustEmail.Build;
  Check('Entra trust email with a directory ID', LIdP.TrustEmail);
  // Multi-tenant or domain tenant: tokens of any tenant, email claim not verified by Microsoft (nOAuth)
  for var LTenant in ['organizations', 'common', 'consumers', 'contoso.onmicrosoft.com'] do
    Check('Entra trust email rejected for tenant ' + LTenant, Raises(
      procedure
      begin
        TIAM4DEntraIdPBuilder.New.WithTenant(LTenant).WithClient('c', 's').WithTrustEmail.Build;
      end, EIAM4DInvalidConfigurationException));

  Check('Entra without tenant', Raises(
    procedure
    begin
      TIAM4DEntraIdPBuilder.New.WithClient('c', 's').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('Entra without client', Raises(
    procedure
    begin
      TIAM4DEntraIdPBuilder.New.WithTenant(CTenant).Build;
    end, EIAM4DInvalidConfigurationException));
  Check('Entra invalid tenant', Raises(
    procedure
    begin
      TIAM4DEntraIdPBuilder.New.WithTenant('a/b').WithClient('c', 's').Build;
    end, EIAM4DInvalidConfigurationException));
end;

// What ImportConfig returns for an OIDC discovery document, plus keys the builder must not take
function OidcDiscovery: TIAM4DConfigMap;
begin
  Result := Default(TIAM4DConfigMap);
  Result.Values['authorizationUrl'] := 'https://idp.example.com/oauth2/authorize';
  Result.Values['tokenUrl'] := 'https://idp.example.com/oauth2/token';
  Result.Values['userInfoUrl'] := 'https://idp.example.com/oauth2/userinfo';
  Result.Values['jwksUrl'] := 'https://idp.example.com/oauth2/keys';
  Result.Values['logoutUrl'] := 'https://idp.example.com/oauth2/logout';
  Result.Values['issuer'] := 'https://idp.example.com';
  Result.Values['tokenIntrospectionUrl'] := 'https://idp.example.com/oauth2/introspect';
  Result.Values['metadataDescriptorUrl'] := 'https://idp.example.com/.well-known/openid-configuration';
  Result.Values['validateSignature'] := 'false';
  Result.Values['pkceEnabled'] := 'false';
  Result.Values['clientAuthMethod'] := 'client_secret_basic';
  Result.Values['clientId'] := 'imported-client';
end;

function ErrorCodeOf(const AProc: TProc): TIAM4DErrorCode;
var
  LError: Exception;
begin
  Result := ecUnknown;
  LError := Capture(AProc);
  try
    if LError is EIAM4DException then
      Result := EIAM4DException(LError).ErrorCode;
  finally
    LError.Free;
  end;
end;

procedure TestOidcBuilder;
var
  LIdP: TIAM4DIdentityProvider;
  LImported: TIAM4DConfigMap;
begin
  Writeln('OIDC builder');
  LIdP := TIAM4DOidcIdPBuilder.New('okta')
    .WithImportedConfig(OidcDiscovery)
    .WithClient(' okta-client ', 'okta-secret')
    .Build;
  Check('OIDC defaults', (LIdP.Alias = 'okta') and (LIdP.ProviderID = IAM4D_IDP_PROVIDER_OIDC) and LIdP.Enabled and
    (LIdP.DisplayName = '') and not LIdP.TrustEmail and not LIdP.HideOnLogin);
  Check('OIDC imported endpoints', (LIdP.Config.Values['authorizationUrl'] = 'https://idp.example.com/oauth2/authorize') and
    (LIdP.Config.Values['tokenUrl'] = 'https://idp.example.com/oauth2/token') and
    (LIdP.Config.Values['userInfoUrl'] = 'https://idp.example.com/oauth2/userinfo') and
    (LIdP.Config.Values['jwksUrl'] = 'https://idp.example.com/oauth2/keys') and
    (LIdP.Config.Values['logoutUrl'] = 'https://idp.example.com/oauth2/logout') and
    (LIdP.Config.Values['issuer'] = 'https://idp.example.com') and
    (LIdP.Config.Values['tokenIntrospectionUrl'] = 'https://idp.example.com/oauth2/introspect'));
  Check('OIDC client', (LIdP.Config.Values['clientId'] = 'okta-client') and
    (LIdP.Config.Values['clientSecret'] = 'okta-secret') and
    (LIdP.Config.Values['clientAuthMethod'] = 'client_secret_post'));
  // The imported validateSignature, pkceEnabled and clientAuthMethod are not taken
  Check('OIDC secure defaults', LIdP.Config.GetBool('validateSignature') and LIdP.Config.GetBool('useJwksUrl') and
    LIdP.Config.GetBool('pkceEnabled') and (LIdP.Config.Values['pkceMethod'] = 'S256'));
  Check('OIDC scopes', LIdP.Config.Values['defaultScope'] = 'openid profile email');
  Check('OIDC no assertion algorithm by default', not LIdP.Config.Contains('clientAssertionSigningAlg'));

  // Endpoints by hand; optional user info and logout left out
  LIdP := TIAM4DOidcIdPBuilder.New('adfs')
    .WithEndpoints(' https://adfs.example.com/adfs/oauth2/authorize ', 'https://adfs.example.com/adfs/oauth2/token')
    .WithJwksURL('https://adfs.example.com/adfs/discovery/keys')
    .WithIssuer(' https://adfs.example.com/adfs ')
    .WithClient('c', 's')
    .Build;
  Check('OIDC manual endpoints', (LIdP.Config.Values['authorizationUrl'] = 'https://adfs.example.com/adfs/oauth2/authorize') and
    (LIdP.Config.Values['tokenUrl'] = 'https://adfs.example.com/adfs/oauth2/token') and
    (LIdP.Config.Values['jwksUrl'] = 'https://adfs.example.com/adfs/discovery/keys') and
    (LIdP.Config.Values['issuer'] = 'https://adfs.example.com/adfs') and
    not LIdP.Config.Contains('userInfoUrl') and not LIdP.Config.Contains('logoutUrl'));
  LIdP := TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery)
    .WithEndpoints('https://a.example.com/auth', 'https://a.example.com/token', 'https://a.example.com/me',
      'https://a.example.com/logout')
    .WithIssuer('https://a.example.com,https://b.example.com')
    .WithClient('c', 's').Build;
  Check('OIDC later call wins over the import', (LIdP.Config.Values['authorizationUrl'] = 'https://a.example.com/auth') and
    (LIdP.Config.Values['userInfoUrl'] = 'https://a.example.com/me') and
    (LIdP.Config.Values['logoutUrl'] = 'https://a.example.com/logout') and
    (LIdP.Config.Values['issuer'] = 'https://a.example.com,https://b.example.com'));
  // The import replaces what was set before, also the keys the discovery document lacks
  LImported := OidcDiscovery;
  LImported.Remove('logoutUrl');
  LImported.Remove('userInfoUrl');
  LIdP := TIAM4DOidcIdPBuilder.New('o')
    .WithEndpoints('https://old.example.com/auth', 'https://old.example.com/token', 'https://old.example.com/me',
      'https://old.example.com/logout')
    .WithJwksURL('https://old.example.com/keys')
    .WithImportedConfig(LImported)
    .WithClient('c', 's').Build;
  Check('OIDC import replaces the endpoints set before', (LIdP.Config.Values['tokenUrl'] = 'https://idp.example.com/oauth2/token') and
    (LIdP.Config.Values['jwksUrl'] = 'https://idp.example.com/oauth2/keys') and
    not LIdP.Config.Contains('logoutUrl') and not LIdP.Config.Contains('userInfoUrl'));

  // Client authentication
  LIdP := TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', 's')
    .WithClientAuthMethod(ocaClientSecretBasic).Build;
  Check('OIDC client_secret_basic', LIdP.Config.Values['clientAuthMethod'] = 'client_secret_basic');
  LIdP := TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', '')
    .WithClientAuthMethod(ocaPrivateKeyJwt).Build;
  Check('OIDC private_key_jwt without secret', (LIdP.Config.Values['clientAuthMethod'] = 'private_key_jwt') and
    (LIdP.Config.Values['clientSecret'] = '') and not LIdP.Config.Contains('clientAssertionSigningAlg'));
  LIdP := TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', '')
    .WithClientAuthMethod(ocaPrivateKeyJwt, ' PS256 ').Build;
  Check('OIDC private_key_jwt algorithm', LIdP.Config.Values['clientAssertionSigningAlg'] = 'PS256');
  LIdP := TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', 's')
    .WithClientAuthMethod(ocaClientSecretJwt, 'HS512').Build;
  Check('OIDC client_secret_jwt', (LIdP.Config.Values['clientAuthMethod'] = 'client_secret_jwt') and
    (LIdP.Config.Values['clientAssertionSigningAlg'] = 'HS512'));
  Check('OIDC client_secret_jwt without secret', Raises(
    procedure
    begin
      TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', '')
        .WithClientAuthMethod(ocaClientSecretJwt).Build;
    end, EIAM4DInvalidConfigurationException));
  Check('OIDC assertion algorithm without a JWT method', Raises(
    procedure
    begin
      TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', 's')
        .WithClientAuthMethod(ocaClientSecretPost, 'RS256').Build;
    end, EIAM4DInvalidConfigurationException));
  LIdP := TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', '')
    .WithClientAuthMethod(ocaPrivateKeyJwt, 'EdDSA').Build;
  Check('OIDC private_key_jwt EdDSA', LIdP.Config.Values['clientAssertionSigningAlg'] = 'EdDSA');
  // Keycloak signs private_key_jwt with a realm key and client_secret_jwt with the secret
  for var LAlgorithm in ['HS256', 'rs256', 'none', 'RSA'] do
    Check('OIDC private_key_jwt with "' + LAlgorithm + '"', Raises(
      procedure
      begin
        TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', '')
          .WithClientAuthMethod(ocaPrivateKeyJwt, LAlgorithm).Build;
      end, EIAM4DInvalidConfigurationException));
  for var LAlgorithm in ['RS256', 'ES256', 'hs256'] do
    Check('OIDC client_secret_jwt with "' + LAlgorithm + '"', Raises(
      procedure
      begin
        TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', 's')
          .WithClientAuthMethod(ocaClientSecretJwt, LAlgorithm).Build;
      end, EIAM4DInvalidConfigurationException));

  LIdP := TIAM4DOidcIdPBuilder.New('auth0')
    .WithImportedConfig(OidcDiscovery)
    .WithClient('c', 's')
    .WithDisplayName('Auth0')
    .WithScopes(['openid', 'email', 'offline_access'])
    .WithPrompt(' login ')
    .WithSyncMode(ismForce)
    .WithTrustEmail
    .WithHideOnLogin
    .WithFirstBrokerLoginFlow('custom first login')
    .WithConfig('loginHint', 'true')
    .Build;
  Check('OIDC options', (LIdP.DisplayName = 'Auth0') and
    (LIdP.Config.Values['defaultScope'] = 'openid email offline_access') and (LIdP.Config.Values['prompt'] = 'login') and
    (LIdP.SyncMode = ismForce) and LIdP.TrustEmail and LIdP.HideOnLogin and
    (LIdP.FirstBrokerLoginFlowAlias = 'custom first login') and LIdP.Config.GetBool('loginHint'));

  // Turning a check off takes the dedicated method: WithConfig does not
  LIdP := TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', 's')
    .WithConfig('validateSignature', 'false').WithConfig('pkceEnabled', 'false').WithConfig('pkceMethod', 'plain')
    .WithConfig('clientAuthMethod', 'client_secret_basic').Build;
  Check('OIDC WithConfig cannot turn the checks off', LIdP.Config.GetBool('validateSignature') and
    LIdP.Config.GetBool('pkceEnabled') and (LIdP.Config.Values['pkceMethod'] = 'S256') and
    (LIdP.Config.Values['clientAuthMethod'] = 'client_secret_post'));
  LIdP := TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', 's').DisableIssuerCheck.Build;
  Check('OIDC DisableIssuerCheck removes the imported issuer', not LIdP.Config.Contains('issuer') and
    LIdP.Config.GetBool('validateSignature'));
  LIdP := TIAM4DOidcIdPBuilder.New('o').WithEndpoints('https://a.example.com/auth', 'https://a.example.com/token')
    .WithIssuer('https://a.example.com').WithClient('c', 's').DisableSignatureValidation.Build;
  Check('OIDC DisableSignatureValidation: no JWKS needed', not LIdP.Config.GetBool('validateSignature', True) and
    not LIdP.Config.Contains('jwksUrl') and (LIdP.Config.Values['issuer'] = 'https://a.example.com'));
  LIdP := TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', 's').DisablePkce.Build;
  Check('OIDC DisablePkce', not LIdP.Config.GetBool('pkceEnabled', True) and not LIdP.Config.Contains('pkceMethod'));

  // nOAuth: trust email only with the issuer check
  Check('OIDC trust email without the issuer check', Raises(
    procedure
    begin
      TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', 's')
        .DisableIssuerCheck.WithTrustEmail.Build;
    end, EIAM4DInvalidConfigurationException));
  // A token whose signature is not validated could claim any email
  Check('OIDC trust email without signature validation', Raises(
    procedure
    begin
      TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', 's')
        .DisableSignatureValidation.WithTrustEmail.Build;
    end, EIAM4DInvalidConfigurationException));
  Check('OIDC without issuer', Raises(
    procedure
    begin
      TIAM4DOidcIdPBuilder.New('o').WithEndpoints('https://a.example.com/auth', 'https://a.example.com/token')
        .WithJwksURL('https://a.example.com/keys').WithClient('c', 's').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('OIDC without JWKS URL', Raises(
    procedure
    begin
      TIAM4DOidcIdPBuilder.New('o').WithEndpoints('https://a.example.com/auth', 'https://a.example.com/token')
        .WithIssuer('https://a.example.com').WithClient('c', 's').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('OIDC without endpoints', Raises(
    procedure
    begin
      TIAM4DOidcIdPBuilder.New('o').WithJwksURL('https://a.example.com/keys').WithIssuer('https://a.example.com')
        .WithClient('c', 's').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('OIDC without client', Raises(
    procedure
    begin
      TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).Build;
    end, EIAM4DInvalidConfigurationException));
  Check('OIDC without secret', Raises(
    procedure
    begin
      TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', '').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('OIDC invalid alias', Raises(
    procedure
    begin
      TIAM4DOidcIdPBuilder.New('o k').WithImportedConfig(OidcDiscovery).WithClient('c', 's').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('OIDC error code', ErrorCodeOf(
    procedure
    begin
      TIAM4DOidcIdPBuilder.New('o').WithImportedConfig(OidcDiscovery).WithClient('c', 's').DisableIssuerCheck
        .WithTrustEmail.Build;
    end) = ecInvalidConfiguration);
end;

// What ImportConfig returns for SAML metadata (Redirect binding only), plus keys the builder must not take
function SamlMetadata: TIAM4DConfigMap;
begin
  Result := Default(TIAM4DConfigMap);
  Result.Values['idpEntityId'] := 'https://idp.example.com/saml';
  Result.Values['singleSignOnServiceUrl'] := 'https://idp.example.com/saml/sso';
  Result.Values['singleLogoutServiceUrl'] := 'https://idp.example.com/saml/slo';
  Result.Values['signingCertificate'] := CTestCertificate;
  Result.Values['metadataDescriptorUrl'] := 'https://idp.example.com/saml/metadata';
  Result.Values['postBindingAuthnRequest'] := 'false';
  Result.Values['postBindingLogout'] := 'false';
  Result.Values['postBindingResponse'] := 'false';
  Result.Values['nameIDPolicyFormat'] := IAM4D_SAML_NAMEID_UNSPECIFIED;
  Result.Values['wantAuthnRequestsSigned'] := 'false';
  Result.Values['validateSignature'] := 'false';
  Result.Values['loginHint'] := 'false';
  Result.Values['enabledFromMetadata'] := 'true';
  Result.Values['artifactResolutionServiceUrl'] := 'https://idp.example.com/saml/resolve';
end;

procedure TestSamlBuilder;
var
  LIdP: TIAM4DIdentityProvider;
  LImported: TIAM4DConfigMap;
  LMapper: TIAM4DIdentityProviderMapper;
begin
  Writeln('SAML builder');
  LIdP := TIAM4DSamlIdPBuilder.New('shibboleth')
    .WithIdentityProviderEndpoints(' https://idp.example.com/saml ', 'https://idp.example.com/saml/sso', CTestCertificate)
    .Build;
  Check('SAML defaults', (LIdP.Alias = 'shibboleth') and (LIdP.ProviderID = IAM4D_IDP_PROVIDER_SAML) and LIdP.Enabled and
    (LIdP.DisplayName = '') and not LIdP.TrustEmail and not LIdP.HideOnLogin);
  Check('SAML manual endpoints', (LIdP.Config.Values['idpEntityId'] = 'https://idp.example.com/saml') and
    (LIdP.Config.Values['singleSignOnServiceUrl'] = 'https://idp.example.com/saml/sso') and
    (LIdP.Config.Values['signingCertificate'] = CTestCertificate) and not LIdP.Config.Contains('singleLogoutServiceUrl'));
  Check('SAML signatures', LIdP.Config.GetBool('wantAuthnRequestsSigned') and LIdP.Config.GetBool('wantAssertionsSigned') and
    LIdP.Config.GetBool('validateSignature') and (LIdP.Config.Values['signatureAlgorithm'] = 'RSA_SHA256'));
  Check('SAML POST bindings', LIdP.Config.GetBool('postBindingAuthnRequest') and LIdP.Config.GetBool('postBindingResponse') and
    LIdP.Config.GetBool('postBindingLogout'));
  Check('SAML principal and NameID', (LIdP.Config.Values['principalType'] = 'SUBJECT') and
    not LIdP.Config.Contains('principalAttribute') and (LIdP.Config.Values['nameIDPolicyFormat'] = IAM4D_SAML_NAMEID_PERSISTENT));
  Check('SAML no metadata URL', not LIdP.Config.Contains('useMetadataDescriptorUrl'));

  LIdP := TIAM4DSamlIdPBuilder.New('adfs').WithImportedConfig(SamlMetadata).Build;
  Check('SAML imported provider data', (LIdP.Config.Values['idpEntityId'] = 'https://idp.example.com/saml') and
    (LIdP.Config.Values['singleSignOnServiceUrl'] = 'https://idp.example.com/saml/sso') and
    (LIdP.Config.Values['singleLogoutServiceUrl'] = 'https://idp.example.com/saml/slo') and
    (LIdP.Config.Values['signingCertificate'] = CTestCertificate) and
    (LIdP.Config.Values['metadataDescriptorUrl'] = 'https://idp.example.com/saml/metadata'));
  // The bindings follow the imported endpoints, the signatures stay the builder's
  Check('SAML imported bindings', not LIdP.Config.GetBool('postBindingAuthnRequest', True) and
    not LIdP.Config.GetBool('postBindingLogout', True) and LIdP.Config.GetBool('postBindingResponse'));
  Check('SAML imported NameID format', LIdP.Config.Values['nameIDPolicyFormat'] = IAM4D_SAML_NAMEID_UNSPECIFIED);
  Check('SAML signatures kept over the import', LIdP.Config.GetBool('wantAuthnRequestsSigned') and
    LIdP.Config.GetBool('validateSignature') and LIdP.Config.GetBool('wantAssertionsSigned'));
  Check('SAML other imported keys not taken', not LIdP.Config.Contains('loginHint') and
    not LIdP.Config.Contains('enabledFromMetadata') and not LIdP.Config.Contains('artifactResolutionServiceUrl') and
    not LIdP.Config.Contains('useMetadataDescriptorUrl'));

  // The later call replaces the provider data of the other, also what it does not set
  LImported := SamlMetadata;
  LImported.Values['encryptionPublicKey'] := CTestCertificate;
  LIdP := TIAM4DSamlIdPBuilder.New('s').WithImportedConfig(LImported)
    .WithIdentityProviderEndpoints('https://other.example.com/saml', 'https://other.example.com/saml/sso', CTestCertificate)
    .Build;
  Check('SAML endpoints after the import: imported data removed', (LIdP.Config.Values['idpEntityId'] =
    'https://other.example.com/saml') and not LIdP.Config.Contains('singleLogoutServiceUrl') and
    not LIdP.Config.Contains('encryptionPublicKey') and not LIdP.Config.Contains('metadataDescriptorUrl') and
    (LIdP.Config.Values['nameIDPolicyFormat'] = IAM4D_SAML_NAMEID_PERSISTENT) and
    LIdP.Config.GetBool('postBindingAuthnRequest') and LIdP.Config.GetBool('postBindingLogout'));
  LImported := SamlMetadata;
  LImported.Remove('singleLogoutServiceUrl');
  LImported.Remove('postBindingLogout');
  LIdP := TIAM4DSamlIdPBuilder.New('s')
    .WithIdentityProviderEndpoints('https://other.example.com/saml', 'https://other.example.com/saml/sso', 'OTHER',
      'https://other.example.com/saml/slo')
    .WithImportedConfig(LImported)
    .Build;
  Check('SAML import after the endpoints: endpoints replaced', (LIdP.Config.Values['idpEntityId'] =
    'https://idp.example.com/saml') and (LIdP.Config.Values['signingCertificate'] = CTestCertificate) and
    not LIdP.Config.Contains('singleLogoutServiceUrl') and LIdP.Config.GetBool('postBindingLogout'));
  LIdP := TIAM4DSamlIdPBuilder.New('s').WithMetadataURL('https://idp.example.com/saml/metadata')
    .WithIdentityProviderEndpoints('https://idp.example.com/saml', 'https://idp.example.com/saml/sso', '').Build;
  Check('SAML endpoints keep the metadata URL Keycloak reads', LIdP.Config.GetBool('useMetadataDescriptorUrl') and
    (LIdP.Config.Values['metadataDescriptorUrl'] = 'https://idp.example.com/saml/metadata'));

  // Explicit NameID format wins over the imported one, in either order
  LIdP := TIAM4DSamlIdPBuilder.New('s').WithNameIDFormat(IAM4D_SAML_NAMEID_EMAIL).WithImportedConfig(SamlMetadata).Build;
  Check('SAML NameID format before the import', LIdP.Config.Values['nameIDPolicyFormat'] = IAM4D_SAML_NAMEID_EMAIL);
  LIdP := TIAM4DSamlIdPBuilder.New('s').WithImportedConfig(SamlMetadata).WithNameIDFormat(IAM4D_SAML_NAMEID_EMAIL).Build;
  Check('SAML NameID format after the import', LIdP.Config.Values['nameIDPolicyFormat'] = IAM4D_SAML_NAMEID_EMAIL);

  // Signing keys from the metadata URL: no certificate needed
  LIdP := TIAM4DSamlIdPBuilder.New('s')
    .WithIdentityProviderEndpoints('https://idp.example.com/saml', 'https://idp.example.com/saml/sso', '',
      'https://idp.example.com/saml/slo')
    .WithMetadataURL(' https://idp.example.com/saml/metadata ')
    .Build;
  Check('SAML metadata URL', LIdP.Config.GetBool('useMetadataDescriptorUrl') and
    (LIdP.Config.Values['metadataDescriptorUrl'] = 'https://idp.example.com/saml/metadata') and
    not LIdP.Config.Contains('signingCertificate') and
    (LIdP.Config.Values['singleLogoutServiceUrl'] = 'https://idp.example.com/saml/slo'));
  Check('SAML without certificate nor metadata URL', Raises(
    procedure
    begin
      TIAM4DSamlIdPBuilder.New('s').WithIdentityProviderEndpoints('https://idp.example.com/saml',
        'https://idp.example.com/saml/sso', '').Build;
    end, EIAM4DInvalidConfigurationException));

  LIdP := TIAM4DSamlIdPBuilder.New('okta-saml')
    .WithImportedConfig(SamlMetadata)
    .WithServiceProviderEntityID(' https://keycloak.example.com/sp ')
    .WithPrincipal(sptAttribute, ' email ')
    .WithNameIDFormat(IAM4D_SAML_NAMEID_TRANSIENT)
    .WithDisplayName('Okta')
    .WithSyncMode(ismImport)
    .WithTrustEmail
    .WithHideOnLogin
    .WithFirstBrokerLoginFlow('custom first login')
    .WithConfig('forceAuthn', 'true')
    .Build;
  Check('SAML options', (LIdP.Config.Values['entityId'] = 'https://keycloak.example.com/sp') and
    (LIdP.Config.Values['principalType'] = 'ATTRIBUTE') and (LIdP.Config.Values['principalAttribute'] = 'email') and
    (LIdP.Config.Values['nameIDPolicyFormat'] = IAM4D_SAML_NAMEID_TRANSIENT) and (LIdP.DisplayName = 'Okta') and
    (LIdP.SyncMode = ismImport) and LIdP.TrustEmail and LIdP.HideOnLogin and
    (LIdP.FirstBrokerLoginFlowAlias = 'custom first login') and LIdP.Config.GetBool('forceAuthn'));
  LIdP := TIAM4DSamlIdPBuilder.New('s').WithImportedConfig(SamlMetadata).WithPrincipal(sptFriendlyAttribute, 'mail').Build;
  Check('SAML friendly attribute principal', (LIdP.Config.Values['principalType'] = 'FRIENDLY_ATTRIBUTE') and
    (LIdP.Config.Values['principalAttribute'] = 'mail'));
  LIdP := TIAM4DSamlIdPBuilder.New('s').WithImportedConfig(SamlMetadata).WithPrincipal(sptAttribute, 'mail')
    .WithPrincipal(sptSubject).Build;
  Check('SAML back to the subject principal', (LIdP.Config.Values['principalType'] = 'SUBJECT') and
    not LIdP.Config.Contains('principalAttribute'));
  Check('SAML attribute principal without attribute', Raises(
    procedure
    begin
      TIAM4DSamlIdPBuilder.New('s').WithImportedConfig(SamlMetadata).WithPrincipal(sptAttribute).Build;
    end, EIAM4DInvalidConfigurationException));
  // Keycloak rejects it: the transient NameID changes at every login
  Check('SAML transient NameID as principal', Raises(
    procedure
    begin
      TIAM4DSamlIdPBuilder.New('s').WithImportedConfig(SamlMetadata).WithNameIDFormat(IAM4D_SAML_NAMEID_TRANSIENT).Build;
    end, EIAM4DInvalidConfigurationException));

  // Turning a check off takes the dedicated method
  LIdP := TIAM4DSamlIdPBuilder.New('s').WithImportedConfig(SamlMetadata).WithConfig('validateSignature', 'false')
    .WithConfig('wantAssertionsSigned', 'false').WithConfig('wantAuthnRequestsSigned', 'false')
    .WithConfig('principalType', 'ATTRIBUTE').Build;
  Check('SAML WithConfig cannot turn the checks off', LIdP.Config.GetBool('validateSignature') and
    LIdP.Config.GetBool('wantAssertionsSigned') and LIdP.Config.GetBool('wantAuthnRequestsSigned') and
    (LIdP.Config.Values['principalType'] = 'SUBJECT'));
  LIdP := TIAM4DSamlIdPBuilder.New('s').WithImportedConfig(SamlMetadata).DisableRequestSigning.Build;
  Check('SAML DisableRequestSigning', not LIdP.Config.GetBool('wantAuthnRequestsSigned', True) and
    LIdP.Config.GetBool('wantAssertionsSigned') and LIdP.Config.GetBool('validateSignature'));
  LIdP := TIAM4DSamlIdPBuilder.New('s').WithImportedConfig(SamlMetadata).AllowUnsignedAssertions.WithTrustEmail.Build;
  Check('SAML AllowUnsignedAssertions', not LIdP.Config.GetBool('wantAssertionsSigned', True) and
    LIdP.Config.GetBool('validateSignature') and LIdP.TrustEmail);
  LIdP := TIAM4DSamlIdPBuilder.New('s').WithIdentityProviderEndpoints('https://idp.example.com/saml',
    'https://idp.example.com/saml/sso', '').DisableSignatureValidation.Build;
  Check('SAML DisableSignatureValidation: no certificate needed', not LIdP.Config.GetBool('validateSignature', True) and
    not LIdP.Config.GetBool('wantAssertionsSigned', True));
  Check('SAML trust email without signature validation', Raises(
    procedure
    begin
      TIAM4DSamlIdPBuilder.New('s').WithImportedConfig(SamlMetadata).DisableSignatureValidation.WithTrustEmail.Build;
    end, EIAM4DInvalidConfigurationException));

  Check('SAML without entity ID', Raises(
    procedure
    begin
      TIAM4DSamlIdPBuilder.New('s').WithIdentityProviderEndpoints('', 'https://idp.example.com/saml/sso',
        CTestCertificate).Build;
    end, EIAM4DInvalidConfigurationException));
  Check('SAML without single sign-on URL', Raises(
    procedure
    begin
      TIAM4DSamlIdPBuilder.New('s').WithIdentityProviderEndpoints('https://idp.example.com/saml', '',
        CTestCertificate).Build;
    end, EIAM4DInvalidConfigurationException));
  Check('SAML without provider data', Raises(
    procedure
    begin
      TIAM4DSamlIdPBuilder.New('s').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('SAML invalid alias', Raises(
    procedure
    begin
      TIAM4DSamlIdPBuilder.New('').WithImportedConfig(SamlMetadata).Build;
    end, EIAM4DInvalidConfigurationException));
  Check('SAML error code', ErrorCodeOf(
    procedure
    begin
      TIAM4DSamlIdPBuilder.New('s').Build;
    end) = ecInvalidConfiguration);

  LMapper := TIAM4DSamlIdPBuilder.AttributeMapper('adfs',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', 'email');
  Check('SAML attribute mapper', (LMapper.IdentityProviderAlias = 'adfs') and
    (LMapper.MapperType = IAM4D_IDP_MAPPER_SAML_ATTRIBUTE) and
    (LMapper.Config.Values['attribute.name'] = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress') and
    (LMapper.Config.Values['user.attribute'] = 'email') and (LMapper.Config.Values['syncMode'] = 'INHERIT'));
end;

procedure TestGoogleBuilder;
var
  LIdP: TIAM4DIdentityProvider;
  LMapper: TIAM4DIdentityProviderMapper;
begin
  Writeln('Google builder');
  LIdP := TIAM4DGoogleIdPBuilder.New
    .WithClient(' google-client ', 'google-secret')
    .Build;
  Check('Google defaults', (LIdP.Alias = 'google') and (LIdP.ProviderID = 'google') and LIdP.Enabled and
    (LIdP.DisplayName = 'Google') and not LIdP.TrustEmail and not LIdP.HideOnLogin);
  Check('Google client', (LIdP.Config.Values['clientId'] = 'google-client') and
    (LIdP.Config.Values['clientSecret'] = 'google-secret'));
  Check('Google scopes and PKCE', (LIdP.Config.Values['defaultScope'] = 'openid profile email') and
    LIdP.Config.GetBool('pkceEnabled') and (LIdP.Config.Values['pkceMethod'] = 'S256'));
  Check('Google endpoints left to Keycloak', not LIdP.Config.Contains('authorizationUrl') and
    not LIdP.Config.Contains('tokenUrl') and not LIdP.Config.Contains('hostedDomain'));

  LIdP := TIAM4DGoogleIdPBuilder.New('google-work')
    .WithClient('c', 's')
    .WithDisplayName('Google Workspace')
    .WithScopes(['openid', 'email'])
    .WithHostedDomains([' Example.com ', 'example.org'])
    .WithPrompt('select_account')
    .WithSyncMode(ismForce)
    .WithTrustEmail
    .WithHideOnLogin
    .WithFirstBrokerLoginFlow('custom first login')
    .WithConfig('offlineAccess', 'true')
    .Build;
  Check('Google options', (LIdP.Alias = 'google-work') and (LIdP.DisplayName = 'Google Workspace') and
    (LIdP.Config.Values['defaultScope'] = 'openid email') and (LIdP.SyncMode = ismForce) and LIdP.TrustEmail and
    LIdP.HideOnLogin and (LIdP.Config.Values['prompt'] = 'select_account') and
    (LIdP.FirstBrokerLoginFlowAlias = 'custom first login') and LIdP.Config.GetBool('offlineAccess'));
  // Keycloak splits on the comma and compares with the hd claim as is
  Check('Google hosted domains: lower case, comma, no spaces',
    LIdP.Config.Values['hostedDomain'] = 'example.com,example.org');

  LIdP := TIAM4DGoogleIdPBuilder.New.WithClient('c', 's').WithScopes([]).Build;
  Check('Google no scopes: Keycloak default', not LIdP.Config.Contains('defaultScope'));

  LMapper := TIAM4DGoogleIdPBuilder.AttributeMapper('google', 'picture', 'avatar');
  Check('Google attribute mapper', (LMapper.IdentityProviderAlias = 'google') and (LMapper.Name = 'picture') and
    (LMapper.MapperType = IAM4D_IDP_MAPPER_GOOGLE_ATTRIBUTE) and (LMapper.Config.Values['jsonField'] = 'picture') and
    (LMapper.Config.Values['userAttribute'] = 'avatar') and (LMapper.Config.Values['syncMode'] = 'INHERIT'));

  Check('Google without client', Raises(
    procedure
    begin
      TIAM4DGoogleIdPBuilder.New.Build;
    end, EIAM4DInvalidConfigurationException));
  Check('Google without secret', Raises(
    procedure
    begin
      TIAM4DGoogleIdPBuilder.New.WithClient('c', '').Build;
    end, EIAM4DInvalidConfigurationException));
  // '*': any Google Workspace account, only as the whole value (Keycloak compares the list otherwise)
  LIdP := TIAM4DGoogleIdPBuilder.New.WithClient('c', 's').WithHostedDomains([' * ']).Build;
  Check('Google any Workspace domain', LIdP.Config.Values['hostedDomain'] = '*');
  Check('Google "*" with other domains', Raises(
    procedure
    begin
      TIAM4DGoogleIdPBuilder.New.WithClient('c', 's').WithHostedDomains(['*', 'example.com']).Build;
    end, EIAM4DInvalidConfigurationException));
  Check('Google error code', ErrorCodeOf(
    procedure
    begin
      TIAM4DGoogleIdPBuilder.New.Build;
    end) = ecInvalidConfiguration);
  for var LDomain in ['', 'example', 'a.com,b.com', 'a b.com', 'example.com/x'] do
    Check('Google invalid hosted domain "' + LDomain + '"', Raises(
      procedure
      begin
        TIAM4DGoogleIdPBuilder.New.WithClient('c', 's').WithHostedDomains([LDomain]).Build;
      end, EIAM4DInvalidConfigurationException));
  Check('Google invalid alias', Raises(
    procedure
    begin
      TIAM4DGoogleIdPBuilder.New('google/x').WithClient('c', 's').Build;
    end, EIAM4DInvalidConfigurationException));
end;

procedure TestFacebookBuilder;
var
  LIdP: TIAM4DIdentityProvider;
  LMapper: TIAM4DIdentityProviderMapper;
begin
  Writeln('Facebook builder');
  LIdP := TIAM4DFacebookIdPBuilder.New
    .WithClient('facebook-app', 'facebook-secret')
    .Build;
  Check('Facebook defaults', (LIdP.Alias = 'facebook') and (LIdP.ProviderID = 'facebook') and LIdP.Enabled and
    (LIdP.DisplayName = 'Facebook') and not LIdP.TrustEmail and not LIdP.HideOnLogin);
  Check('Facebook client and scopes', (LIdP.Config.Values['clientId'] = 'facebook-app') and
    (LIdP.Config.Values['clientSecret'] = 'facebook-secret') and
    (LIdP.Config.Values['defaultScope'] = 'email public_profile') and not LIdP.Config.Contains('fetchedFields'));

  LIdP := TIAM4DFacebookIdPBuilder.New('fb')
    .WithClient('c', 's')
    .WithDisplayName('Meta')
    .WithScopes(['email', 'public_profile', 'user_birthday'])
    .WithFetchedFields(['birthday', ' picture.type(large) ', 'location{name,id}'])
    .WithSyncMode(ismImport)
    .WithHideOnLogin
    .WithFirstBrokerLoginFlow('custom first login')
    .WithConfig('guiOrder', '2')
    .Build;
  Check('Facebook options', (LIdP.Alias = 'fb') and (LIdP.DisplayName = 'Meta') and
    (LIdP.Config.Values['defaultScope'] = 'email public_profile user_birthday') and (LIdP.SyncMode = ismImport) and
    LIdP.HideOnLogin and (LIdP.FirstBrokerLoginFlowAlias = 'custom first login') and
    (LIdP.Config.Values['guiOrder'] = '2'));
  Check('Facebook fetched fields', LIdP.Config.Values['fetchedFields'] = 'birthday,picture.type(large),location{name,id}');

  LMapper := TIAM4DFacebookIdPBuilder.AttributeMapper('fb', 'birthday', 'birthdate');
  Check('Facebook attribute mapper', (LMapper.IdentityProviderAlias = 'fb') and
    (LMapper.MapperType = IAM4D_IDP_MAPPER_FACEBOOK_ATTRIBUTE) and (LMapper.Config.Values['jsonField'] = 'birthday') and
    (LMapper.Config.Values['userAttribute'] = 'birthdate'));

  Check('Facebook without client', Raises(
    procedure
    begin
      TIAM4DFacebookIdPBuilder.New.Build;
    end, EIAM4DInvalidConfigurationException));
  for var LField in ['', 'birthday&access_token=x', 'a b', 'x#y'] do
    Check('Facebook invalid fetched field "' + LField + '"', Raises(
      procedure
      begin
        TIAM4DFacebookIdPBuilder.New.WithClient('c', 's').WithFetchedFields([LField]).Build;
      end, EIAM4DInvalidConfigurationException));
end;

procedure TestOAuth2Builder;
var
  LIdP: TIAM4DIdentityProvider;
  LImported: TIAM4DConfigMap;
begin
  Writeln('OAuth 2.0 builder');
  LIdP := TIAM4DOAuth2IdPBuilder.New('strava')
    .WithEndpoints(' https://www.strava.com/oauth/authorize ', 'https://www.strava.com/oauth/token',
      'https://www.strava.com/api/v3/athlete')
    .WithClient(' strava-client ', 'strava-secret')
    .Build;
  Check('OAuth2 defaults', (LIdP.Alias = 'strava') and (LIdP.ProviderID = IAM4D_IDP_PROVIDER_OAUTH2) and
    LIdP.Enabled and (LIdP.DisplayName = '') and not LIdP.TrustEmail and not LIdP.HideOnLogin);
  Check('OAuth2 endpoints', (LIdP.Config.Values['authorizationUrl'] = 'https://www.strava.com/oauth/authorize') and
    (LIdP.Config.Values['tokenUrl'] = 'https://www.strava.com/oauth/token') and
    (LIdP.Config.Values['userInfoUrl'] = 'https://www.strava.com/api/v3/athlete'));
  Check('OAuth2 client', (LIdP.Config.Values['clientId'] = 'strava-client') and
    (LIdP.Config.Values['clientSecret'] = 'strava-secret') and
    (LIdP.Config.Values['clientAuthMethod'] = 'client_secret_post'));
  Check('OAuth2 PKCE by default', LIdP.Config.GetBool('pkceEnabled') and (LIdP.Config.Values['pkceMethod'] = 'S256'));
  // No id_token: nothing to validate, and Keycloak's default claims
  Check('OAuth2 no OIDC keys', not LIdP.Config.Contains('validateSignature') and not LIdP.Config.Contains('useJwksUrl') and
    not LIdP.Config.Contains('issuer') and not LIdP.Config.Contains('jwksUrl'));
  Check('OAuth2 no scope and default claims', not LIdP.Config.Contains('defaultScope') and
    not LIdP.Config.Contains('userIDClaim') and not LIdP.Config.Contains('userNameClaim') and
    not LIdP.Config.Contains('emailClaim') and not LIdP.Config.Contains('fullNameClaim'));

  LIdP := TIAM4DOAuth2IdPBuilder.New('strava')
    .WithEndpoints('https://a.example.com/auth', 'https://a.example.com/token', 'https://a.example.com/me')
    .WithClient('c', 's')
    .WithUserProfileClaims(' id ', 'data.login', 'emails.primary')
    .WithNameClaims('', 'firstname', 'lastname')
    .WithClientAuthMethod(ocaClientSecretBasic)
    .WithScopes(['read', 'profile:read_all'])
    .WithDisplayName('Strava')
    .WithPrompt('consent')
    .WithSyncMode(ismImport)
    .WithTrustEmail
    .WithHideOnLogin
    .WithFirstBrokerLoginFlow('custom first login')
    .WithConfig('pkceEnabled', 'false')
    .Build;
  Check('OAuth2 claims', (LIdP.Config.Values['userIDClaim'] = 'id') and
    (LIdP.Config.Values['userNameClaim'] = 'data.login') and (LIdP.Config.Values['emailClaim'] = 'emails.primary') and
    not LIdP.Config.Contains('fullNameClaim') and (LIdP.Config.Values['givenNameClaim'] = 'firstname') and
    (LIdP.Config.Values['familyNameClaim'] = 'lastname'));
  Check('OAuth2 options', (LIdP.DisplayName = 'Strava') and
    (LIdP.Config.Values['defaultScope'] = 'read profile:read_all') and
    (LIdP.Config.Values['clientAuthMethod'] = 'client_secret_basic') and (LIdP.Config.Values['prompt'] = 'consent') and
    (LIdP.SyncMode = ismImport) and LIdP.TrustEmail and LIdP.HideOnLogin and
    (LIdP.FirstBrokerLoginFlowAlias = 'custom first login'));
  Check('OAuth2 WithConfig cannot turn PKCE off', LIdP.Config.GetBool('pkceEnabled'));

  LIdP := TIAM4DOAuth2IdPBuilder.New('strava')
    .WithEndpoints('https://a.example.com/auth', 'https://a.example.com/token', 'https://a.example.com/me')
    .WithClient('c', 's')
    .WithUserProfileClaims('id', 'login', 'mail')
    .WithUserProfileClaims('', '', '')
    .DisablePkce
    .Build;
  Check('OAuth2 empty claims back to the default', not LIdP.Config.Contains('userIDClaim') and
    not LIdP.Config.Contains('userNameClaim') and not LIdP.Config.Contains('emailClaim'));
  Check('OAuth2 DisablePkce', not LIdP.Config.GetBool('pkceEnabled', True) and not LIdP.Config.Contains('pkceMethod'));

  // As returned by ImportConfig('oauth2', metadata URL)
  LImported := Default(TIAM4DConfigMap);
  LImported.Values['authorizationUrl'] := 'https://idp.example.com/authorize';
  LImported.Values['tokenUrl'] := 'https://idp.example.com/token';
  LImported.Values['userInfoUrl'] := 'https://idp.example.com/userinfo';
  LImported.Values['tokenIntrospectionUrl'] := 'https://idp.example.com/introspect';
  LImported.Values['issuer'] := 'https://idp.example.com';
  LImported.Values['clientId'] := 'imported-client';
  LImported.Values['pkceEnabled'] := 'false';
  LIdP := TIAM4DOAuth2IdPBuilder.New('imported')
    .WithImportedConfig(LImported)
    .WithClient('c', '')
    .WithClientAuthMethod(ocaPrivateKeyJwt, 'ES256')
    .Build;
  Check('OAuth2 imported endpoints only', (LIdP.Config.Values['authorizationUrl'] = 'https://idp.example.com/authorize') and
    (LIdP.Config.Values['userInfoUrl'] = 'https://idp.example.com/userinfo') and
    (LIdP.Config.Values['tokenIntrospectionUrl'] = 'https://idp.example.com/introspect') and
    not LIdP.Config.Contains('issuer') and (LIdP.Config.Values['clientId'] = 'c') and LIdP.Config.GetBool('pkceEnabled'));
  Check('OAuth2 private_key_jwt without secret', (LIdP.Config.Values['clientAuthMethod'] = 'private_key_jwt') and
    (LIdP.Config.Values['clientAssertionSigningAlg'] = 'ES256'));

  Check('OAuth2 without user info URL', Raises(
    procedure
    begin
      TIAM4DOAuth2IdPBuilder.New('x').WithEndpoints('https://a/auth', 'https://a/token', ' ').WithClient('c', 's').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('OAuth2 without endpoints', Raises(
    procedure
    begin
      TIAM4DOAuth2IdPBuilder.New('x').WithClient('c', 's').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('OAuth2 without secret', Raises(
    procedure
    begin
      TIAM4DOAuth2IdPBuilder.New('x').WithEndpoints('https://a/auth', 'https://a/token', 'https://a/me')
        .WithClient('c', '').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('OAuth2 assertion algorithm without a JWT method', Raises(
    procedure
    begin
      TIAM4DOAuth2IdPBuilder.New('x').WithEndpoints('https://a/auth', 'https://a/token', 'https://a/me')
        .WithClient('c', 's').WithClientAuthMethod(ocaClientSecretPost, 'RS256').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('OAuth2 invalid alias', Raises(
    procedure
    begin
      TIAM4DOAuth2IdPBuilder.New('').WithEndpoints('https://a/auth', 'https://a/token', 'https://a/me')
        .WithClient('c', 's').Build;
    end, EIAM4DInvalidConfigurationException));
end;

procedure TestMicrosoftBuilder;
const
  CTenant = '6f1c3a52-0b7e-4d2a-9c8f-2e5d7b4a1c90';
var
  LIdP: TIAM4DIdentityProvider;
  LMapper: TIAM4DIdentityProviderMapper;
begin
  Writeln('Microsoft builder');
  LIdP := TIAM4DMicrosoftIdPBuilder.New
    .WithClient('ms-client', 'ms-secret')
    .Build;
  Check('Microsoft defaults', (LIdP.Alias = 'microsoft') and (LIdP.ProviderID = 'microsoft') and LIdP.Enabled and
    (LIdP.DisplayName = 'Microsoft') and not LIdP.TrustEmail and not LIdP.HideOnLogin);
  Check('Microsoft personal accounts by default', LIdP.Config.Values['tenantId'] = 'consumers');
  Check('Microsoft scopes and PKCE', (LIdP.Config.Values['defaultScope'] = 'User.Read') and
    LIdP.Config.GetBool('pkceEnabled') and (LIdP.Config.Values['pkceMethod'] = 'S256'));
  Check('Microsoft endpoints left to Keycloak', not LIdP.Config.Contains('authorizationUrl') and
    not LIdP.Config.Contains('tokenUrl') and (LIdP.Config.Values['clientSecret'] = 'ms-secret'));

  LIdP := TIAM4DMicrosoftIdPBuilder.New('ms-work')
    .WithTenant(' ' + CTenant + ' ')
    .WithClient('c', 's')
    .WithDisplayName('Microsoft account')
    .WithPrompt('select_account')
    .WithSyncMode(ismForce)
    .WithTrustEmail
    .WithHideOnLogin
    .Build;
  Check('Microsoft options', (LIdP.Alias = 'ms-work') and (LIdP.Config.Values['tenantId'] = CTenant) and
    (LIdP.DisplayName = 'Microsoft account') and (LIdP.Config.Values['prompt'] = 'select_account') and
    (LIdP.SyncMode = ismForce) and LIdP.HideOnLogin);
  Check('Microsoft trust email with a directory ID', LIdP.TrustEmail);

  LIdP := TIAM4DMicrosoftIdPBuilder.New.WithTenant('common').WithClient('c', 's').Build;
  Check('Microsoft common tenant', LIdP.Config.Values['tenantId'] = 'common');
  LIdP := TIAM4DMicrosoftIdPBuilder.New.WithTenant('common').WithTenant(' ').WithClient('c', 's').Build;
  Check('Microsoft empty tenant: consumers', LIdP.Config.Values['tenantId'] = 'consumers');

  LMapper := TIAM4DMicrosoftIdPBuilder.AttributeMapper('microsoft', 'jobTitle', 'jobTitle');
  Check('Microsoft attribute mapper', (LMapper.MapperType = IAM4D_IDP_MAPPER_MICROSOFT_ATTRIBUTE) and
    (LMapper.Config.Values['jsonField'] = 'jobTitle') and (LMapper.Config.Values['userAttribute'] = 'jobTitle'));

  for var LTenant in ['consumers', 'common', 'organizations', 'contoso.onmicrosoft.com'] do
    Check('Microsoft trust email with tenant "' + LTenant + '"', Raises(
      procedure
      begin
        TIAM4DMicrosoftIdPBuilder.New.WithTenant(LTenant).WithClient('c', 's').WithTrustEmail.Build;
      end, EIAM4DInvalidConfigurationException));
  for var LTenant in ['a/b', 'common?x=1'] do
    Check('Microsoft invalid tenant "' + LTenant + '"', Raises(
      procedure
      begin
        TIAM4DMicrosoftIdPBuilder.New.WithTenant(LTenant).WithClient('c', 's').Build;
      end, EIAM4DInvalidConfigurationException));
  Check('Microsoft without client', Raises(
    procedure
    begin
      TIAM4DMicrosoftIdPBuilder.New.Build;
    end, EIAM4DInvalidConfigurationException));
end;

procedure TestLinkedInBuilder;
var
  LIdP: TIAM4DIdentityProvider;
  LMapper: TIAM4DIdentityProviderMapper;
begin
  Writeln('LinkedIn builder');
  LIdP := TIAM4DLinkedInIdPBuilder.New
    .WithClient('li-client', 'li-secret')
    .Build;
  Check('LinkedIn defaults', (LIdP.Alias = 'linkedin') and (LIdP.ProviderID = 'linkedin-openid-connect') and
    LIdP.Enabled and (LIdP.DisplayName = 'LinkedIn') and not LIdP.TrustEmail and not LIdP.HideOnLogin);
  Check('LinkedIn scopes, no PKCE', (LIdP.Config.Values['defaultScope'] = 'openid profile email') and
    not LIdP.Config.Contains('pkceEnabled') and (LIdP.Config.Values['clientId'] = 'li-client'));

  LIdP := TIAM4DLinkedInIdPBuilder.New('li')
    .WithClient('c', 's')
    .WithDisplayName('LinkedIn members')
    .WithScopes(['openid', 'profile'])
    .WithSyncMode(ismImport)
    .WithTrustEmail
    .WithHideOnLogin
    .WithFirstBrokerLoginFlow('custom first login')
    .Build;
  Check('LinkedIn options', (LIdP.Alias = 'li') and (LIdP.DisplayName = 'LinkedIn members') and
    (LIdP.Config.Values['defaultScope'] = 'openid profile') and (LIdP.SyncMode = ismImport) and LIdP.TrustEmail and
    LIdP.HideOnLogin and (LIdP.FirstBrokerLoginFlowAlias = 'custom first login'));

  LMapper := TIAM4DLinkedInIdPBuilder.AttributeMapper('linkedin', 'picture', 'picture');
  Check('LinkedIn attribute mapper', (LMapper.MapperType = IAM4D_IDP_MAPPER_LINKEDIN_ATTRIBUTE) and
    (LMapper.Config.Values['jsonField'] = 'picture') and (LMapper.Config.Values['userAttribute'] = 'picture'));

  Check('LinkedIn without secret', Raises(
    procedure
    begin
      TIAM4DLinkedInIdPBuilder.New.WithClient('c', '').Build;
    end, EIAM4DInvalidConfigurationException));
end;

procedure TestGitHubBuilder;
var
  LIdP: TIAM4DIdentityProvider;
  LMapper: TIAM4DIdentityProviderMapper;
begin
  Writeln('GitHub builder');
  LIdP := TIAM4DGitHubIdPBuilder.New
    .WithClient('gh-client', 'gh-secret')
    .Build;
  Check('GitHub defaults', (LIdP.Alias = 'github') and (LIdP.ProviderID = 'github') and LIdP.Enabled and
    (LIdP.DisplayName = 'GitHub') and not LIdP.TrustEmail and not LIdP.HideOnLogin);
  Check('GitHub scopes and PKCE', (LIdP.Config.Values['defaultScope'] = 'user:email') and
    LIdP.Config.GetBool('pkceEnabled') and (LIdP.Config.Values['pkceMethod'] = 'S256'));
  Check('GitHub: github.com by default', not LIdP.Config.Contains('baseUrl') and not LIdP.Config.Contains('apiUrl'));

  LIdP := TIAM4DGitHubIdPBuilder.New('ghe')
    .WithClient('c', 's')
    .WithEnterprise(' https://github.example.com/ ', 'https://github.example.com/api/v3/')
    .WithDisplayName('GitHub Enterprise')
    .WithScopes(['read:user', 'user:email'])
    .WithSyncMode(ismImport)
    .WithHideOnLogin
    .WithConfig('githubJsonFormat', 'true')
    .Build;
  Check('GitHub Enterprise URLs', (LIdP.Config.Values['baseUrl'] = 'https://github.example.com') and
    (LIdP.Config.Values['apiUrl'] = 'https://github.example.com/api/v3'));
  Check('GitHub options', (LIdP.Alias = 'ghe') and (LIdP.DisplayName = 'GitHub Enterprise') and
    (LIdP.Config.Values['defaultScope'] = 'read:user user:email') and (LIdP.SyncMode = ismImport) and
    LIdP.HideOnLogin and LIdP.Config.GetBool('githubJsonFormat'));

  LMapper := TIAM4DGitHubIdPBuilder.AttributeMapper('github', 'company', 'company');
  Check('GitHub attribute mapper', (LMapper.MapperType = IAM4D_IDP_MAPPER_GITHUB_ATTRIBUTE) and
    (LMapper.Config.Values['jsonField'] = 'company') and (LMapper.Config.Values['userAttribute'] = 'company'));

  Check('GitHub Enterprise without API URL', Raises(
    procedure
    begin
      TIAM4DGitHubIdPBuilder.New.WithClient('c', 's').WithEnterprise('https://github.example.com', '').Build;
    end, EIAM4DInvalidConfigurationException));
  for var LURL in ['http://github.example.com', 'github.example.com', 'https://', 'https://a b.com'] do
    Check('GitHub Enterprise invalid URL "' + LURL + '"', Raises(
      procedure
      begin
        TIAM4DGitHubIdPBuilder.New.WithClient('c', 's').WithEnterprise(LURL, 'https://github.example.com/api/v3').Build;
      end, EIAM4DInvalidConfigurationException));
  // Not in the interface: through the class it is still refused
  Check('GitHub trust email refused', Raises(
    procedure
    var
      LBuilder: TIAM4DGitHubIdPBuilder;
      LIntf: IIAM4DGitHubIdPBuilder;
    begin
      LBuilder := TIAM4DGitHubIdPBuilder.New.WithClient('c', 's') as TIAM4DGitHubIdPBuilder;
      LIntf := LBuilder;
      LBuilder.WithTrustEmail;
      LIntf.Build;
    end, EIAM4DInvalidConfigurationException));
  Check('GitHub without client', Raises(
    procedure
    begin
      TIAM4DGitHubIdPBuilder.New.Build;
    end, EIAM4DInvalidConfigurationException));
end;

procedure TestGitLabBuilder;
var
  LIdP: TIAM4DIdentityProvider;
begin
  Writeln('GitLab builder');
  LIdP := TIAM4DGitLabIdPBuilder.New
    .WithClient('gl-client', 'gl-secret')
    .Build;
  Check('GitLab defaults', (LIdP.Alias = 'gitlab') and (LIdP.ProviderID = 'gitlab') and LIdP.Enabled and
    (LIdP.DisplayName = 'GitLab') and not LIdP.TrustEmail and not LIdP.HideOnLogin);
  Check('GitLab scopes and PKCE', (LIdP.Config.Values['defaultScope'] = 'openid read_user email') and
    LIdP.Config.GetBool('pkceEnabled') and (LIdP.Config.Values['pkceMethod'] = 'S256'));
  Check('GitLab id_token signature and issuer checked', LIdP.Config.GetBool('validateSignature') and
    LIdP.Config.GetBool('useJwksUrl') and (LIdP.Config.Values['issuer'] = 'https://gitlab.com') and
    (LIdP.Config.Values['jwksUrl'] = 'https://gitlab.com/oauth/discovery/keys'));

  LIdP := TIAM4DGitLabIdPBuilder.New('gl')
    .WithClient('c', 's')
    .WithDisplayName('GitLab.com')
    .WithScopes(['openid', 'read_user', 'email', 'profile'])
    .WithSyncMode(ismImport)
    .WithTrustEmail
    .WithHideOnLogin
    .WithConfig('validateSignature', 'false')
    .Build;
  Check('GitLab options', (LIdP.Alias = 'gl') and (LIdP.DisplayName = 'GitLab.com') and
    (LIdP.Config.Values['defaultScope'] = 'openid read_user email profile') and (LIdP.SyncMode = ismImport) and
    LIdP.TrustEmail and LIdP.HideOnLogin);
  Check('GitLab WithConfig cannot turn the signature check off', LIdP.Config.GetBool('validateSignature'));
  // Keycloak sends the scopes joined by spaces: one element may hold several
  LIdP := TIAM4DGitLabIdPBuilder.New.WithClient('c', 's').WithScopes(['openid read_user', ' email ']).WithTrustEmail.Build;
  Check('GitLab space-separated scopes', LIdP.TrustEmail and
    (LIdP.Config.Values['defaultScope'] = 'openid read_user email'));

  Check('GitLab without openid', Raises(
    procedure
    begin
      TIAM4DGitLabIdPBuilder.New.WithClient('c', 's').WithScopes(['read_user']).Build;
    end, EIAM4DInvalidConfigurationException));
  Check('GitLab trust email without the email scope', Raises(
    procedure
    begin
      TIAM4DGitLabIdPBuilder.New.WithClient('c', 's').WithScopes(['openid', 'read_user']).WithTrustEmail.Build;
    end, EIAM4DInvalidConfigurationException));
  Check('GitLab without secret', Raises(
    procedure
    begin
      TIAM4DGitLabIdPBuilder.New.WithClient('c', '').Build;
    end, EIAM4DInvalidConfigurationException));
end;

procedure TestSpidBuilder;
var
  LIdP: TIAM4DIdentityProvider;
  LImported: TIAM4DConfigMap;
  LMapper: TIAM4DIdentityProviderMapper;
begin
  Writeln('SPID builder');
  // As returned by ImportConfig('spid-saml', <AgID registry entry of Poste>)
  LImported := Default(TIAM4DConfigMap);
  LImported.Values['idpEntityId'] := 'https://posteid.poste.it';
  LImported.Values['singleSignOnServiceUrl'] := 'https://posteid.poste.it/jod-fs/ssoservicepost';
  LImported.Values['singleLogoutServiceUrl'] := 'https://posteid.poste.it/jod-fs/sloservicepost';
  LImported.Values['signingCertificate'] := 'MIIFgzCC';
  LImported.Values['metadataDescriptorUrl'] := 'https://registry.spid.gov.it/entities-idp/https%3A%2F%2Fposteid.poste.it';
  LImported.Values['wantAuthnRequestsSigned'] := 'false';
  LImported.Values['loginHint'] := 'false';

  LIdP := TIAM4DSpidIdPBuilder.New('spid-poste')
    .WithDisplayName('Poste ID')
    .WithImportedConfig(LImported)
    .WithAttributeConsumingService(1, 'Servizi online')
    .WithOrganization('Comune di Esempio', 'Comune di Esempio', 'https://www.comune.esempio.it')
    .WithPublicServiceProvider('c_x000', 'protocollo@comune.esempio.it')
    .Build;
  Check('SPID provider', (LIdP.Alias = 'spid-poste') and (LIdP.ProviderID = IAM4D_IDP_PROVIDER_SPID) and
    LIdP.Enabled and LIdP.TrustEmail and (LIdP.SyncMode = ismForce));
  Check('SPID imported identity provider data', (LIdP.Config.Values['idpEntityId'] = 'https://posteid.poste.it') and
    (LIdP.Config.Values['singleSignOnServiceUrl'] = 'https://posteid.poste.it/jod-fs/ssoservicepost') and
    (LIdP.Config.Values['signingCertificate'] = 'MIIFgzCC') and LIdP.Config.Contains('metadataDescriptorUrl'));
  Check('SPID import keeps the AgID profile', LIdP.Config.GetBool('wantAuthnRequestsSigned') and
    not LIdP.Config.Contains('loginHint'));
  Check('SPID SAML profile', (LIdP.Config.Values['principalType'] = 'ATTRIBUTE') and
    (LIdP.Config.Values['principalAttribute'] = 'fiscalNumber') and
    (LIdP.Config.Values['nameIDPolicyFormat'] = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient') and
    LIdP.Config.GetBool('postBindingAuthnRequest') and LIdP.Config.GetBool('postBindingResponse') and
    LIdP.Config.GetBool('wantAssertionsSigned') and (LIdP.Config.Values['signatureAlgorithm'] = 'RSA_SHA256'));
  Check('SPID default level L2 minimum', (LIdP.Config.Values['authnContextClassRefs'] = '["https://www.spid.gov.it/SpidL2"]') and
    (LIdP.Config.Values['authnContextComparisonType'] = 'minimum'));
  Check('SPID attribute consuming service', (LIdP.Config.Values['attributeConsumingServiceIndex'] = '1') and
    (LIdP.Config.Values['attributeConsumingServiceName'] = 'it|Servizi online'));
  Check('SPID organization', (LIdP.Config.Values['organizationNames'] = 'it|Comune di Esempio') and
    (LIdP.Config.Values['organizationUrls'] = 'it|https://www.comune.esempio.it'));
  Check('SPID public service provider', not LIdP.Config.GetBool('otherContactIsSpPrivate', True) and
    (LIdP.Config.Values['otherContactIpaCode'] = 'c_x000'));

  LIdP := TIAM4DSpidIdPBuilder.New('spid-test')
    .WithIdentityProviderEndpoints('https://idp.example.it', 'https://idp.example.it/sso', 'CERT1,CERT2')
    .WithMetadataURL('https://idp.example.it/metadata')
    .WithServiceProviderEntityID('https://sp.example.it')
    .WithLevel(slL3)
    .WithAttributeConsumingService(2, 'Servizi online')
    .WithPrivateServiceProvider('IT12345678901', '12345678901', 'Esempio S.r.l.', 'info@esempio.it', '+39061234567')
    .WithHideOnLogin
    .WithSyncMode(ismImport)
    .Build;
  Check('SPID endpoints by hand', (LIdP.Config.Values['idpEntityId'] = 'https://idp.example.it') and
    (LIdP.Config.Values['signingCertificate'] = 'CERT1,CERT2') and not LIdP.Config.Contains('singleLogoutServiceUrl'));
  Check('SPID metadata URL', LIdP.Config.GetBool('useMetadataDescriptorUrl') and
    (LIdP.Config.Values['metadataDescriptorUrl'] = 'https://idp.example.it/metadata'));
  Check('SPID options', (LIdP.Config.Values['entityId'] = 'https://sp.example.it') and
    (LIdP.Config.Values['authnContextClassRefs'] = '["https://www.spid.gov.it/SpidL3"]') and
    (LIdP.Config.Values['attributeConsumingServiceIndex'] = '2') and
    (LIdP.Config.Values['attributeConsumingServiceName'] = 'it|Servizi online') and LIdP.HideOnLogin and
    (LIdP.SyncMode = ismImport));
  Check('SPID private service provider', LIdP.Config.GetBool('otherContactIsSpPrivate') and
    (LIdP.Config.Values['otherContactVatNumber'] = 'IT12345678901') and
    (LIdP.Config.Values['otherContactCompany'] = 'Esempio S.r.l.'));

  // Billing contact of a private service provider (fpa:CessionarioCommittente)
  LIdP := TIAM4DSpidIdPBuilder.New('spid-private')
    .WithIdentityProviderEndpoints('https://idp.example.it', 'https://idp.example.it/sso', 'CERT1')
    .WithAttributeConsumingService(1, 'Servizi online')
    .WithPrivateServiceProvider('IT12345678901', '12345678901', 'Esempio S.r.l.', 'info@esempio.it')
    .WithBillingContact('Esempio S.r.l.', 'fatture@esempio.it', '+39061234567', 'Esempio S.r.l.', 'Via Roma', '1',
      '00100', 'Roma', 'RM')
    .Build;
  Check('SPID billing contact', (LIdP.Config.Values['billingContactCompany'] = 'Esempio S.r.l.') and
    (LIdP.Config.Values['billingContactEmail'] = 'fatture@esempio.it') and
    (LIdP.Config.Values['billingContactPhone'] = '+39061234567') and
    (LIdP.Config.Values['billingContactRegistryName'] = 'Esempio S.r.l.') and
    (LIdP.Config.Values['billingContactSiteAddress'] = 'Via Roma') and
    (LIdP.Config.Values['billingContactSiteNumber'] = '1') and
    (LIdP.Config.Values['billingContactSiteZipCode'] = '00100') and
    (LIdP.Config.Values['billingContactSiteCity'] = 'Roma') and
    (LIdP.Config.Values['billingContactSiteProvince'] = 'RM') and
    (LIdP.Config.Values['billingContactSiteCountry'] = 'IT'));
  // The extension writes the billing contact only for private service providers
  Check('SPID billing contact of a public service provider rejected', Raises(
    procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid-x').WithIdentityProviderEndpoints('e', 'u', 'c')
        .WithAttributeConsumingService(1, 'Servizi online').WithPublicServiceProvider('c_x000', 'a@b.it')
        .WithBillingContact('C', 'f@b.it', '', 'C', 'Via Roma', '1', '00100', 'Roma', 'RM').Build;
    end, EIAM4DInvalidConfigurationException));
  // IdPaese and IdCodice come from the VAT number: without the country code the metadata has no fiscal ID
  Check('SPID billing contact with a VAT number without country code rejected', Raises(
    procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid-x').WithIdentityProviderEndpoints('e', 'u', 'c')
        .WithAttributeConsumingService(1, 'Servizi online')
        .WithPrivateServiceProvider('12345678901', '12345678901', 'C', 'a@b.it')
        .WithBillingContact('C', 'f@b.it', '', 'C', 'Via Roma', '1', '00100', 'Roma', 'RM').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('SPID billing contact without registered name rejected', Raises(
    procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid-x').WithBillingContact('C', 'f@b.it', '', ' ', 'Via Roma', '1', '00100', 'Roma', 'RM');
    end, EIAM4DInvalidConfigurationException));

  Check('SPID without identity provider data', Raises(
    procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid-x').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('SPID invalid alias', Raises(
    procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid poste').WithIdentityProviderEndpoints('e', 'u', 'c')
        .WithAttributeConsumingService(1, 'Servizi online').Build;
    end, EIAM4DInvalidConfigurationException));
  // The SP metadata needs the ServiceName of the attribute consuming service
  Check('SPID without service name', Raises(
    procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid-x').WithIdentityProviderEndpoints('e', 'u', 'c').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('SPID empty service name', Raises(
    procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid-x').WithAttributeConsumingService(1, ' ');
    end, EIAM4DInvalidConfigurationException));
  Check('SPID organization with a comma', Raises(
    procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid-x').WithOrganization('Comune, Ufficio', 'x', 'https://x.it');
    end, EIAM4DInvalidConfigurationException));
  Check('SPID public without IPA code', Raises(
    procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid-x').WithPublicServiceProvider('', 'a@b.it');
    end, EIAM4DInvalidConfigurationException));
  // validateSignature without a certificate: Keycloak would reject every response of the identity provider
  Check('SPID without signing certificate', Raises(
    procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid-x').WithIdentityProviderEndpoints('e', 'u', ' ')
        .WithAttributeConsumingService(1, 'Servizi online').Build;
    end, EIAM4DInvalidConfigurationException));
  LIdP := TIAM4DSpidIdPBuilder.New('spid-x')
    .WithIdentityProviderEndpoints('e', 'u', '')
    .WithMetadataURL('https://idp.example.it/metadata')
    .WithAttributeConsumingService(1, 'Servizi online')
    .Build;
  Check('SPID certificate read by Keycloak from the metadata URL', LIdP.Config.GetBool('useMetadataDescriptorUrl') and
    not LIdP.Config.Contains('signingCertificate'));
  // WithConfig cannot turn the signatures off: no certificate is still an error
  Check('SPID WithConfig(validateSignature, false) without certificate', Raises(
    procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid-x')
        .WithIdentityProviderEndpoints('e', 'u', '')
        .WithConfig('validateSignature', 'false')
        .WithAttributeConsumingService(1, 'Servizi online')
        .Build;
    end, EIAM4DInvalidConfigurationException));
  for var LKey in ['validateSignature', 'wantAssertionsSigned', 'wantAuthnRequestsSigned', 'signSpMetadata'] do
  begin
    LIdP := TIAM4DSpidIdPBuilder.New('spid-x')
      .WithIdentityProviderEndpoints('e', 'u', 'c')
      .WithConfig(LKey, 'false')
      .WithAttributeConsumingService(1, 'Servizi online')
      .Build;
    Check(Format('SPID WithConfig(%s, false) cannot turn the signatures off', [LKey]),
      LIdP.Config.GetBool('validateSignature') and LIdP.Config.GetBool('wantAssertionsSigned') and
      LIdP.Config.GetBool('wantAuthnRequestsSigned') and LIdP.Config.GetBool('signSpMetadata'));
  end;
  // Endpoints by hand after the import: nothing of the imported provider remains, the AgID profile stays
  LIdP := TIAM4DSpidIdPBuilder.New('spid-x')
    .WithImportedConfig(LImported)
    .WithIdentityProviderEndpoints('https://idp.example.it', 'https://idp.example.it/sso', 'CERT1')
    .WithAttributeConsumingService(1, 'Servizi online')
    .Build;
  Check('SPID endpoints after the import', (LIdP.Config.Values['idpEntityId'] = 'https://idp.example.it') and
    not LIdP.Config.Contains('singleLogoutServiceUrl') and not LIdP.Config.Contains('metadataDescriptorUrl') and
    (LIdP.Config.Values['nameIDPolicyFormat'] = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'));
  Check('SPID error code', ErrorCodeOf(
    procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid-x').Build;
    end) = ecInvalidConfiguration);

  LMapper := TIAM4DSpidIdPBuilder.AttributeMapper('spid-poste', 'fiscalNumber', 'fiscalNumber');
  Check('SPID attribute mapper', (LMapper.MapperType = IAM4D_IDP_MAPPER_SPID_ATTRIBUTE) and
    (LMapper.Config.Values['attribute.name'] = 'fiscalNumber') and (LMapper.Config.Values['user.attribute'] = 'fiscalNumber'));
  Check('SPID SP metadata URL', TIAM4DSpidIdPBuilder.ServiceProviderMetadataURL('https://kc.example.it/', 'pa') =
    'https://kc.example.it/realms/pa/spid-sp-metadata');
  Check('SPID level URIs', (slL1.ToURI = 'https://www.spid.gov.it/SpidL1') and (slL3.ToURI = 'https://www.spid.gov.it/SpidL3'));
end;

// As returned by ImportConfig(IAM4D_IDP_PROVIDER_CIE, MetadataURL(AEnvironment)); SLO with the redirect
// binding, unlike the builder default, so the order checks can tell the two apart
function CieMetadata(const AEnvironment: TIAM4DCieEnvironment): TIAM4DConfigMap;
const
  CHosts: array[TIAM4DCieEnvironment] of string = (
    'https://idserver.servizicie.interno.gov.it',
    'https://preproduzione.idserver.servizicie.interno.gov.it');
begin
  Result := Default(TIAM4DConfigMap);
  Result.Values['idpEntityId'] := CHosts[AEnvironment] + '/idp/profile/SAML2/POST/SSO';
  Result.Values['singleSignOnServiceUrl'] := CHosts[AEnvironment] + '/idp/profile/SAML2/POST/SSO';
  Result.Values['singleLogoutServiceUrl'] := CHosts[AEnvironment] + '/idp/profile/SAML2/Redirect/SLO';
  Result.Values['signingCertificate'] := CTestCertificate;
  Result.Values['metadataDescriptorUrl'] := TIAM4DCieIdPBuilder.MetadataURL(AEnvironment);
  Result.Values['validateSignature'] := 'false';
end;

procedure TestCieBuilder;
var
  LIdP, LOther: TIAM4DIdentityProvider;
  LSimulator: TIAM4DConfigMap;
  LEntry: TIAM4DConfigEntry;
  LProductionLeft: Boolean;
  LMapper: TIAM4DIdentityProviderMapper;
begin
  Writeln('CIE builder');
  // Endpoints of WithEnvironment, but no certificate to validate the responses with
  Check('CIE without signing certificate', Raises(
    procedure
    begin
      TIAM4DCieIdPBuilder.New.WithAttributeConsumingService(1, 'Servizi online').Build;
    end, EIAM4DInvalidConfigurationException));
  LIdP := TIAM4DCieIdPBuilder.New
    .WithConfig('useMetadataDescriptorUrl', 'true')
    .WithAttributeConsumingService(1, 'Servizi online')
    .Build;
  Check('CIE certificate read by Keycloak from the metadata URL', not LIdP.Config.Contains('signingCertificate'));
  // WithConfig cannot turn the signatures off: no certificate is still an error
  Check('CIE WithConfig(validateSignature, false) without certificate', Raises(
    procedure
    begin
      TIAM4DCieIdPBuilder.New
        .WithConfig('validateSignature', 'false')
        .WithAttributeConsumingService(1, 'Servizi online')
        .Build;
    end, EIAM4DInvalidConfigurationException));
  for var LKey in ['validateSignature', 'wantAssertionsSigned', 'wantAuthnRequestsSigned', 'signSpMetadata'] do
  begin
    LIdP := TIAM4DCieIdPBuilder.New
      .WithImportedConfig(CieMetadata(ceProduction))
      .WithConfig(LKey, 'false')
      .WithAttributeConsumingService(1, 'Servizi online')
      .Build;
    Check(Format('CIE WithConfig(%s, false) cannot turn the signatures off', [LKey]),
      LIdP.Config.GetBool('validateSignature') and LIdP.Config.GetBool('wantAssertionsSigned') and
      LIdP.Config.GetBool('wantAuthnRequestsSigned') and LIdP.Config.GetBool('signSpMetadata'));
  end;

  LIdP := TIAM4DCieIdPBuilder.New
    .WithImportedConfig(CieMetadata(ceProduction))
    .WithAttributeConsumingService(1, 'Servizi online')
    .Build;
  Check('CIE provider', (LIdP.Alias = 'cie') and (LIdP.ProviderID = IAM4D_IDP_PROVIDER_CIE) and
    (LIdP.DisplayName = 'CIE ID') and LIdP.TrustEmail);
  Check('CIE imported certificate, AgID profile kept', (LIdP.Config.Values['signingCertificate'] = CTestCertificate) and
    LIdP.Config.GetBool('validateSignature'));
  // The CIE extension writes the name as is: no '{locale}|' prefix
  Check('CIE attribute consuming service', (LIdP.Config.Values['attributeConsumingServiceIndex'] = '1') and
    (LIdP.Config.Values['attributeConsumingServiceName'] = 'Servizi online'));
  Check('CIE without service name', Raises(
    procedure
    begin
      TIAM4DCieIdPBuilder.New.Build;
    end, EIAM4DInvalidConfigurationException));
  Check('CIE production endpoints', (LIdP.Config.Values['idpEntityId'] =
    'https://idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO') and
    (LIdP.Config.Values['singleSignOnServiceUrl'] = 'https://idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO') and
    (LIdP.Config.Values['singleLogoutServiceUrl'] = 'https://idserver.servizicie.interno.gov.it/idp/profile/SAML2/Redirect/SLO'));
  Check('CIE SAML profile', (LIdP.Config.Values['principalAttribute'] = 'fiscalNumber') and
    LIdP.Config.GetBool('wantAuthnRequestsSigned') and
    (LIdP.Config.Values['authnContextClassRefs'] = '["https://www.spid.gov.it/SpidL2"]'));

  LIdP := TIAM4DCieIdPBuilder.New('cie-test')
    .WithEnvironment(cePreProduction)
    .WithImportedConfig(CieMetadata(cePreProduction))
    .WithPublicServiceProvider('Comune di Esempio', 'c_x000', 'L6', 'protocollo@comune.esempio.it')
    .WithTechnicalContact('Fornitore S.r.l.', 'IT12345678901', '12345678901', 'tech@fornitore.it')
    .WithOrganization('Comune di Esempio', 'Comune di Esempio', 'https://www.comune.esempio.it')
    .WithLevel(slL3)
    .WithAttributeConsumingService(2, 'Servizi online')
    .Build;
  Check('CIE pre-production', LIdP.Config.Values['idpEntityId'] =
    'https://preproduzione.idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO');
  Check('CIE contacts', not LIdP.Config.GetBool('administrativeContactIsSpPrivate', True) and
    (LIdP.Config.Values['administrativeContactIpaCode'] = 'c_x000') and
    (LIdP.Config.Values['administrativeContactIpaCategory'] = 'L6') and
    (LIdP.Config.Values['technicalContactVatNumber'] = 'IT12345678901'));
  Check('CIE metadata URLs', (TIAM4DCieIdPBuilder.MetadataURL(cePreProduction) =
    'https://preproduzione.idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata') and
    (TIAM4DCieIdPBuilder.ServiceProviderMetadataURL('https://kc.example.it', 'pa') =
    'https://kc.example.it/realms/pa/cieid-sp-metadata'));

  // Environment and metadata in either order: same provider
  LOther := TIAM4DCieIdPBuilder.New('cie-test')
    .WithImportedConfig(CieMetadata(cePreProduction))
    .WithEnvironment(cePreProduction)
    .WithAttributeConsumingService(2, 'Servizi online')
    .Build;
  Check('CIE environment after the metadata: imported endpoints kept',
    (LOther.Config.Values['idpEntityId'] = LIdP.Config.Values['idpEntityId']) and
    (LOther.Config.Values['singleLogoutServiceUrl'] = LIdP.Config.Values['singleLogoutServiceUrl']) and
    (LOther.Config.Values['metadataDescriptorUrl'] = LIdP.Config.Values['metadataDescriptorUrl']) and
    (LOther.Config.Values['signingCertificate'] = CTestCertificate));
  // Without WithEnvironment the metadata decides
  LOther := TIAM4DCieIdPBuilder.New
    .WithImportedConfig(CieMetadata(cePreProduction))
    .WithAttributeConsumingService(1, 'Servizi online')
    .Build;
  Check('CIE metadata without environment', (LOther.Config.Values['idpEntityId'] = LIdP.Config.Values['idpEntityId']) and
    (LOther.Config.Values['metadataDescriptorUrl'] = TIAM4DCieIdPBuilder.MetadataURL(cePreProduction)));
  // Production metadata (MetadataURL defaults to production) for the pre-production server, and vice versa
  Check('CIE production metadata for pre-production', Raises(
    procedure
    begin
      TIAM4DCieIdPBuilder.New.WithEnvironment(cePreProduction).WithImportedConfig(CieMetadata(ceProduction))
        .WithAttributeConsumingService(1, 'Servizi online').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('CIE production metadata, then pre-production', Raises(
    procedure
    begin
      TIAM4DCieIdPBuilder.New.WithImportedConfig(CieMetadata(ceProduction)).WithEnvironment(cePreProduction)
        .WithAttributeConsumingService(1, 'Servizi online').Build;
    end, EIAM4DInvalidConfigurationException));
  Check('CIE pre-production metadata for production', Raises(
    procedure
    begin
      TIAM4DCieIdPBuilder.New.WithEnvironment(ceProduction).WithImportedConfig(CieMetadata(cePreProduction))
        .WithAttributeConsumingService(1, 'Servizi online').Build;
    end, EIAM4DInvalidConfigurationException));

  // Local test identity server (tests/IdentityProvider/docker CIE simulator), as ImportConfig returns it:
  // nothing of the production defaults may remain
  LSimulator := Default(TIAM4DConfigMap);
  LSimulator.Values['idpEntityId'] := 'http://localhost:8444/demo';
  LSimulator.Values['singleSignOnServiceUrl'] := 'http://localhost:8444/demo/samlsso';
  LSimulator.Values['singleLogoutServiceUrl'] := 'http://localhost:8444/demo/samlsso';
  LSimulator.Values['signingCertificate'] := CTestCertificate;
  LSimulator.Values['metadataDescriptorUrl'] := 'http://cie-simulator:8444/demo/metadata.xml';
  LIdP := TIAM4DCieIdPBuilder.New
    .WithImportedConfig(LSimulator)
    .WithAttributeConsumingService(1, 'Servizi online')
    .Build;
  LProductionLeft := False;
  for LEntry in LIdP.Config.Entries do
    LProductionLeft := LProductionLeft or LEntry.Value.Contains('servizicie.interno.gov.it');
  Check('CIE local test identity server: imported endpoints only', not LProductionLeft and
    (LIdP.Config.Values['idpEntityId'] = 'http://localhost:8444/demo') and
    (LIdP.Config.Values['singleLogoutServiceUrl'] = 'http://localhost:8444/demo/samlsso'));

  LMapper := TIAM4DCieIdPBuilder.AttributeMapper('cie', 'familyName', 'lastName');
  Check('CIE attribute mapper', (LMapper.IdentityProviderAlias = 'cie') and
    (LMapper.MapperType = IAM4D_IDP_MAPPER_CIE_ATTRIBUTE) and (LMapper.Config.Values['syncMode'] = 'INHERIT') and
    (LMapper.Config.Values['attribute.name'] = 'familyName') and (LMapper.Config.Values['user.attribute'] = 'lastName'));
end;

// EIAM4DInvalidConfigurationException with ecInvalidConfiguration and the prefix once
procedure CheckConfigError(const AName: string; const AProc: TProc);
const
  CPrefix = 'Invalid configuration: ';
var
  LError: Exception;
begin
  LError := Capture(AProc);
  try
    Check(AName, (LError is EIAM4DInvalidConfigurationException) and
      (EIAM4DException(LError).ErrorCode = ecInvalidConfiguration) and LError.Message.StartsWith(CPrefix) and
      not LError.Message.Substring(CPrefix.Length).Contains(CPrefix));
    if Assigned(LError) and not LError.Message.StartsWith(CPrefix) then
      Writeln('    message: ', LError.Message);
  finally
    LError.Free;
  end;
end;

procedure TestConfigurationErrors;
var
  LIdPs: IIAM4DIdentityProviderManager;
begin
  CheckConfigError('config error: alias', procedure
    begin
      TIAM4DOidcIdPBuilder.New('o k').WithImportedConfig(OidcDiscovery).WithClient('c', 's').Build;
    end);
  CheckConfigError('config error: Entra tenant', procedure
    begin
      TIAM4DEntraIdPBuilder.New.WithTenant('a/b').WithClient('c', 's').Build;
    end);
  CheckConfigError('config error: Entra trust email', procedure
    begin
      TIAM4DEntraIdPBuilder.New.WithTenant('common').WithClient('c', 's').WithTrustEmail.Build;
    end);
  CheckConfigError('config error: Google hosted domain', procedure
    begin
      TIAM4DGoogleIdPBuilder.New.WithClient('c', 's').WithHostedDomains(['a b.com']).Build;
    end);
  CheckConfigError('config error: Facebook fetched field', procedure
    begin
      TIAM4DFacebookIdPBuilder.New.WithClient('c', 's').WithFetchedFields(['a b']).Build;
    end);
  CheckConfigError('config error: Microsoft tenant', procedure
    begin
      TIAM4DMicrosoftIdPBuilder.New.WithTenant('a/b').WithClient('c', 's').Build;
    end);
  CheckConfigError('config error: Microsoft trust email', procedure
    begin
      TIAM4DMicrosoftIdPBuilder.New.WithTenant('common').WithClient('c', 's').WithTrustEmail.Build;
    end);
  CheckConfigError('config error: GitHub Enterprise URL', procedure
    begin
      TIAM4DGitHubIdPBuilder.New.WithClient('c', 's').WithEnterprise('http://github.example.com',
        'https://github.example.com/api/v3').Build;
    end);
  CheckConfigError('config error: SPID billing contact field', procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid-x').WithBillingContact('C', 'f@b.it', '', ' ', 'Via Roma', '1', '00100', 'Roma', 'RM');
    end);
  CheckConfigError('config error: SPID billing contact of a public service provider', procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid-x').WithIdentityProviderEndpoints('e', 'u', 'c')
        .WithAttributeConsumingService(1, 'Servizi online').WithPublicServiceProvider('c_x000', 'a@b.it')
        .WithBillingContact('C', 'f@b.it', '', 'C', 'Via Roma', '1', '00100', 'Roma', 'RM').Build;
    end);
  CheckConfigError('config error: SPID VAT number', procedure
    begin
      TIAM4DSpidIdPBuilder.New('spid-x').WithIdentityProviderEndpoints('e', 'u', 'c')
        .WithAttributeConsumingService(1, 'Servizi online')
        .WithPrivateServiceProvider('12345678901', '12345678901', 'C', 'a@b.it')
        .WithBillingContact('C', 'f@b.it', '', 'C', 'Via Roma', '1', '00100', 'Roma', 'RM').Build;
    end);

  // Checks of the manager, before any request
  LIdPs := TIAM4DKeycloakIdentityProviderManager.Create('token', 'http://127.0.0.1:1', 'r');
  CheckConfigError('config error: empty alias', procedure
    begin
      LIdPs.TryGetIdentityProvider(' ');
    end);
  CheckConfigError('config error: alias with an invalid character', procedure
    begin
      LIdPs.TryGetIdentityProvider('a/b');
    end);
  CheckConfigError('config error: negative first result', procedure
    begin
      LIdPs.GetIdentityProviders('', -1, 10);
    end);
end;

procedure TestLoginConfig;
var
  LBuilder: IIAM4DClientConfigBuilder;
  LConfig: TIAM4DClientConfig;
begin
  Writeln('Login configuration (kc_idp_hint)');
  LConfig := TIAM4DClientConfig.CreateForAuthorizationCode('https://kc.example.com', 'r', 'app');
  Check('no hint by default', LConfig.IdpHint = '');
  LConfig := TIAM4DClientConfig.CreateForAuthorizationCode('https://kc.example.com', 'r', 'app', nil,
    svmStrict, 30000, 60000, '', 120, nil, ' cie ');
  Check('record hint trimmed', LConfig.IdpHint = 'cie');

  LBuilder := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode('https://kc.example.com', 'r', 'app')
    .WithIdentityProvider(' entra ');
  Check('WithIdentityProvider', LBuilder.Config.IdpHint = 'entra');
  LBuilder.WithScopes(['openid', 'profile']);
  Check('kept by WithScopes', LBuilder.Config.IdpHint = 'entra');
  LBuilder.WithAllowSelfSignedSSL;
  LBuilder.WithStrictSSL;
  LBuilder.WithTimeouts(1000, 2000);
  LBuilder.WithTokenExpiryBuffer(10);
  LBuilder.WithAcrValues(['urn:keycloak:acr:2fa']);
  LBuilder.WithExternalCallback(CCallbackURL);
  Check('kept by the other With* methods', (LBuilder.Config.IdpHint = 'entra') and
    (LBuilder.Config.ExternalCallbackURL = CCallbackURL) and (Length(LBuilder.Config.AcrValues) = 1));
  LBuilder.WithIdentityProvider('');
  Check('cleared with an empty alias', LBuilder.Config.IdpHint = '');

  Check('client credentials rejected', Raises(
    procedure
    begin
      TIAM4DClientConfigBuilder.New
        .ForClientCredentials('https://kc.example.com', 'r', 'svc', 'secret')
        .WithIdentityProvider('entra');
    end, EInvalidOpException));
end;

// ============================================================================
// Admin API requests against a local server (offline)
// ============================================================================

type
  TFakeResponse = record
    Status: Integer;
    Body: string;
    Location: string;
    class function Create(AStatus: Integer; const ABody: string; const ALocation: string = ''): TFakeResponse; static;
  end;

  // Response to a request line (method and path, as sent)
  TFakeResponder = reference to function(const ARequestLine: string): TFakeResponse;

  // Stands in for the Keycloak Admin API: records the requests, answers with the configured response
  TFakeAdminServer = class
  private
    FServer: TIdHTTPServer;
    FRequestLine: string;
    FRequestBody: string;
    FAuthorization: string;
    FRequests: TStringList;
    FAuthorizations: TStringList;
    FStatus: Integer;
    FBody: string;
    FRetryAfter: string;
    FResponder: TFakeResponder;
    FConnectionCount: Integer;
    procedure HandleConnect(AContext: TIdContext);
    function GetConnectionCount: Integer;
    procedure SetKeepAlive(AValue: Boolean);
    procedure HandleRequest(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo;
      AResponseInfo: TIdHTTPResponseInfo);
    procedure AcceptAuthorization(AContext: TIdContext; const AAuthType, AAuthData: string;
      var VUsername, VPassword: string; var VHandled: Boolean);
    function GetRequestLine: string;
    function GetRequestBody: string;
    function GetAuthorization: string;
    function GetRequestCount: Integer;
    function GetRequests: string;
    function GetAuthorizations: string;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Reply(AStatus: Integer; const ABody: string; const ARetryAfter: string = '');
    /// <summary>Answers each request with AResponder, until the next Reply.</summary>
    procedure Respond(const AResponder: TFakeResponder);
    function URL: string;
    /// <summary>Method and path of the last request, as sent (still percent-encoded).</summary>
    property RequestLine: string read GetRequestLine;
    property RequestBody: string read GetRequestBody;
    property Authorization: string read GetAuthorization;
    /// <summary>Requests since the last Reply/Respond.</summary>
    property RequestCount: Integer read GetRequestCount;
    /// <summary>Request lines since the last Reply/Respond, one per line.</summary>
    property Requests: string read GetRequests;
    /// <summary>Authorization header of each request since the last Reply/Respond, one per line.</summary>
    property Authorizations: string read GetAuthorizations;
    /// <summary>TCP connections accepted since the creation of the server.</summary>
    property ConnectionCount: Integer read GetConnectionCount;
    /// <summary>HTTP keep-alive (off by default: every answer closes the connection).</summary>
    property KeepAlive: Boolean write SetKeepAlive;
  end;

class function TFakeResponse.Create(AStatus: Integer; const ABody, ALocation: string): TFakeResponse;
begin
  Result.Status := AStatus;
  Result.Body := ABody;
  Result.Location := ALocation;
end;

constructor TFakeAdminServer.Create;
var
  LBinding: TIdSocketHandle;
begin
  inherited Create;
  FRequests := TStringList.Create;
  FAuthorizations := TStringList.Create;
  FServer := TIdHTTPServer.Create(nil);
  LBinding := FServer.Bindings.Add;
  LBinding.IP := '127.0.0.1';
  LBinding.Port := 0;
  FServer.OnCommandGet := HandleRequest;
  FServer.OnCommandOther := HandleRequest;
  FServer.OnParseAuthentication := AcceptAuthorization;
  FServer.OnConnect := HandleConnect;
  FServer.Active := True;
end;

procedure TFakeAdminServer.HandleConnect(AContext: TIdContext);
begin
  TMonitor.Enter(Self);
  try
    Inc(FConnectionCount);
  finally
    TMonitor.Exit(Self);
  end;
end;

function TFakeAdminServer.GetConnectionCount: Integer;
begin
  TMonitor.Enter(Self);
  try
    Result := FConnectionCount;
  finally
    TMonitor.Exit(Self);
  end;
end;

procedure TFakeAdminServer.SetKeepAlive(AValue: Boolean);
begin
  FServer.KeepAlive := AValue;
end;

// Indy answers 401 to an authorization scheme it does not know (Bearer) unless handled here
procedure TFakeAdminServer.AcceptAuthorization(AContext: TIdContext; const AAuthType, AAuthData: string;
  var VUsername, VPassword: string; var VHandled: Boolean);
begin
  VHandled := True;
end;

destructor TFakeAdminServer.Destroy;
begin
  FServer.Active := False;
  FServer.Free;
  FRequests.Free;
  FAuthorizations.Free;
  inherited;
end;

procedure TFakeAdminServer.HandleRequest(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo;
  AResponseInfo: TIdHTTPResponseInfo);
var
  LBody: TStringStream;
  LResponse: TFakeResponse;
begin
  TMonitor.Enter(Self);
  try
    FRequestLine := ARequestInfo.RawHTTPCommand;
    FRequests.Add(FRequestLine);
    FAuthorization := ARequestInfo.RawHeaders.Values['Authorization'];
    FAuthorizations.Add(FAuthorization);
    FRequestBody := '';
    if Assigned(ARequestInfo.PostStream) then
    begin
      LBody := TStringStream.Create('', TEncoding.UTF8);
      try
        LBody.CopyFrom(ARequestInfo.PostStream, 0);
        FRequestBody := LBody.DataString;
      finally
        LBody.Free;
      end;
    end;
    if Assigned(FResponder) then
      LResponse := FResponder(FRequestLine)
    else
      LResponse := TFakeResponse.Create(FStatus, FBody);
    AResponseInfo.ResponseNo := LResponse.Status;
    AResponseInfo.ContentType := 'application/json';
    AResponseInfo.CharSet := 'utf-8';
    AResponseInfo.ContentText := LResponse.Body;
    if LResponse.Location <> '' then
      AResponseInfo.Location := LResponse.Location;
    if FRetryAfter <> '' then
      AResponseInfo.CustomHeaders.Values['Retry-After'] := FRetryAfter;
  finally
    TMonitor.Exit(Self);
  end;
end;

function TFakeAdminServer.GetRequestLine: string;
begin
  TMonitor.Enter(Self);
  try
    Result := FRequestLine;
  finally
    TMonitor.Exit(Self);
  end;
end;

function TFakeAdminServer.GetRequestBody: string;
begin
  TMonitor.Enter(Self);
  try
    Result := FRequestBody;
  finally
    TMonitor.Exit(Self);
  end;
end;

function TFakeAdminServer.GetAuthorization: string;
begin
  TMonitor.Enter(Self);
  try
    Result := FAuthorization;
  finally
    TMonitor.Exit(Self);
  end;
end;

function TFakeAdminServer.GetRequestCount: Integer;
begin
  TMonitor.Enter(Self);
  try
    Result := FRequests.Count;
  finally
    TMonitor.Exit(Self);
  end;
end;

function TFakeAdminServer.GetAuthorizations: string;
begin
  TMonitor.Enter(Self);
  try
    Result := FAuthorizations.Text;
  finally
    TMonitor.Exit(Self);
  end;
end;

function TFakeAdminServer.GetRequests: string;
begin
  TMonitor.Enter(Self);
  try
    Result := FRequests.Text;
  finally
    TMonitor.Exit(Self);
  end;
end;

procedure TFakeAdminServer.Reply(AStatus: Integer; const ABody: string; const ARetryAfter: string);
begin
  TMonitor.Enter(Self);
  try
    FStatus := AStatus;
    FBody := ABody;
    FRetryAfter := ARetryAfter;
    FResponder := nil;
    FRequestLine := '';
    FRequestBody := '';
    FAuthorization := '';
    FRequests.Clear;
    FAuthorizations.Clear;
  finally
    TMonitor.Exit(Self);
  end;
end;

procedure TFakeAdminServer.Respond(const AResponder: TFakeResponder);
begin
  Reply(200, '');
  TMonitor.Enter(Self);
  try
    FResponder := AResponder;
  finally
    TMonitor.Exit(Self);
  end;
end;

function TFakeAdminServer.URL: string;
begin
  Result := 'http://127.0.0.1:' + FServer.Bindings[0].Port.ToString;
end;

function StatusCodeOf(const AError: Exception): Integer;
begin
  if AError is EIAM4DHTTPClientErrorException then
    Result := EIAM4DHTTPClientErrorException(AError).StatusCode
  else if AError is EIAM4DHTTPServerErrorException then
    Result := EIAM4DHTTPServerErrorException(AError).StatusCode
  else
    Result := -1;
end;

function ResponseBodyOf(const AError: Exception): string;
begin
  if AError is EIAM4DHTTPClientErrorException then
    Result := EIAM4DHTTPClientErrorException(AError).ResponseBody
  else if AError is EIAM4DHTTPServerErrorException then
    Result := EIAM4DHTTPServerErrorException(AError).ResponseBody
  else
    Result := '';
end;

// AProc fails with exactly AClass, still an EIAM4DException but no longer EIAM4DInvalidConfigurationException,
// carrying the status code and a response body that contains ABodyPart; AMessagePart, if given, is in the message
procedure CheckHTTPError(const AName: string; const AProc: TProc; AClass: ExceptClass; AStatusCode: Integer;
  const ABodyPart: string; const AMessagePart: string = '');
var
  LError: Exception;
  LDetail: string;
begin
  LError := Capture(AProc);
  try
    if LError = nil then
      LDetail := 'no exception'
    else
      LDetail := LError.ClassName + ': ' + LError.Message.Substring(0, 200);
    Check(AName + ' [' + LDetail + ']', (LError <> nil) and (LError.ClassType = AClass) and
      (LError is EIAM4DException) and not (LError is EIAM4DInvalidConfigurationException) and
      (StatusCodeOf(LError) = AStatusCode) and ((ABodyPart = '') or ResponseBodyOf(LError).Contains(ABodyPart)) and
      ((AMessagePart = '') or LError.Message.Contains(AMessagePart)));
  finally
    LError.Free;
  end;
end;

procedure TestAdminRequests;
var
  LServer: TFakeAdminServer;
  LUsers: IIAM4DUserManager;
  LIdPs: IIAM4DIdentityProviderManager;
  LIdPsAsync: IIAM4DIdentityProviderManagerAsync;
  LUsersAsync: IIAM4DUserManagerAsync;
  LProvidersPromise: IAsyncPromise<TArray<TIAM4DIdentityProvider>>;
  LCountPromise: IAsyncPromise<Integer>;
  LCriteria: TIAM4DUserSearchCriteria;
  LError: Exception;
  LInstancesURL: string;
begin
  Writeln('Admin API requests (local server)');
  LServer := TFakeAdminServer.Create;
  try
    LUsers := TIAM4DKeycloakUserManager.Create('token', LServer.URL, 'r');
    LIdPs := TIAM4DKeycloakIdentityProviderManager.Create('token', LServer.URL, 'r');

    // Path segments: a space is %20 ('+' is a literal plus in a path: /roles/Sales+Manager is another role)
    LServer.Reply(200, '{"id":"r1","name":"Sales Manager"}');
    Check('role with a space', Safely(
      function: Boolean
      begin
        Result := LUsers.GetRoleByName(CRoleWithSpace).Name = CRoleWithSpace;
      end));
    Check('path segment: space as %20 [' + LServer.RequestLine + ']',
      LServer.RequestLine.StartsWith('GET /admin/realms/r/roles/Sales%20Manager '));
    LServer.Reply(200, '[]');
    Safely(
      function: Boolean
      begin
        Result := Length(LUsers.GetUsersWithRole('a+b/c?d#e%f ' + #$00E8)) = 0;
      end);
    Check('path segment: reserved characters escaped [' + LServer.RequestLine + ']',
      LServer.RequestLine.StartsWith('GET /admin/realms/r/roles/a%2Bb%2Fc%3Fd%23e%25f%20%C3%A8/users?first=0&max=100 '));

    // Query values stay form-encoded: there '+' is a space and a literal plus is %2B
    LServer.Reply(200, '[]');
    LCriteria := TIAM4DUserSearchCriteria.Create;
    LCriteria.FirstName := CUserFirstName;
    Safely(
      function: Boolean
      begin
        Result := Length(LUsers.SearchUsers(LCriteria)) = 0;
      end);
    Check('query value: space as + [' + LServer.RequestLine + ']', LServer.RequestLine.Contains('firstName=Mario+Luigi&'));
    Check('no enabled filter by default [' + LServer.RequestLine + ']', not LServer.RequestLine.Contains('enabled='));

    // Enabled filter only when asked; invalid paging refused before any request
    LServer.Reply(200, '[]');
    LCriteria := TIAM4DUserSearchCriteria.Create;
    LCriteria.FilterByEnabled := True;
    LCriteria.Enabled := False;
    Safely(
      function: Boolean
      begin
        Result := Length(LUsers.SearchUsers(LCriteria)) = 0;
      end);
    Check('enabled filter sent [' + LServer.RequestLine + ']', LServer.RequestLine.Contains('enabled=false&'));
    LServer.Reply(200, '[]');
    LCriteria := TIAM4DUserSearchCriteria.Create('', 0, 0);
    Check('MaxResults 0 refused, no request', Raises(
      procedure
      begin
        LUsers.SearchUsers(LCriteria);
      end, EIAM4DInvalidConfigurationException) and (LServer.RequestCount = 0));

    // Client roles of two clients: one role mapping per client; a role not read from Keycloak is refused
    LServer.Reply(204, '');
    Check('client roles of two clients: one POST per client', Safely(
      function: Boolean
      var
        LRoles: TArray<TIAM4DRole>;
      begin
        SetLength(LRoles, 3);
        LRoles[0].ID := 'r1';
        LRoles[0].Name := 'a';
        LRoles[0].ContainerID := 'c1';
        LRoles[0].ClientID := 'app1';
        LRoles[1].ID := 'r2';
        LRoles[1].Name := 'b';
        LRoles[1].ContainerID := 'c2';
        LRoles[1].ClientID := 'app2';
        LRoles[2].ID := 'r3';
        LRoles[2].Name := 'c';
        LRoles[2].ContainerID := 'c1';
        LRoles[2].ClientID := 'app1';
        LUsers.AssignClientRolesToUser('u1', LRoles);
        Result := (LServer.RequestCount = 2) and
          LServer.Requests.Contains('POST /admin/realms/r/users/u1/role-mappings/clients/c1 ') and
          LServer.Requests.Contains('POST /admin/realms/r/users/u1/role-mappings/clients/c2 ');
      end));
    LServer.Reply(204, '');
    Check('client role without ID refused, no request', Raises(
      procedure
      var
        LRoles: TArray<TIAM4DRole>;
      begin
        SetLength(LRoles, 2);
        LRoles[0].ID := 'r1';
        LRoles[0].Name := 'a';
        LRoles[0].ContainerID := 'c1';
        LRoles[0].ClientID := 'app1';
        LRoles[1].Name := 'b';
        LRoles[1].ContainerID := 'c1';
        LRoles[1].ClientID := 'app1';
        LUsers.AssignClientRolesToUser('u1', LRoles);
      end, EIAM4DInvalidConfigurationException) and (LServer.RequestCount = 0));

    // A session of another user is not revoked
    LServer.Reply(200, '[{"id":"s-other"}]');
    Check('RevokeUserSession: session of another user refused (404), no DELETE', Raises(
      procedure
      begin
        LUsers.RevokeUserSession('u1', 's1');
      end, EIAM4DHTTPNotFoundException) and not LServer.Requests.Contains('DELETE'));
    LServer.Reply(200, '[{"id":"s1"}]');
    Check('RevokeUserSession: own session revoked', Safely(
      function: Boolean
      begin
        LUsers.RevokeUserSession('u1', 's1');
        Result := LServer.Requests.Contains('DELETE /admin/realms/r/sessions/s1 ');
      end));
    LServer.Reply(200, '[{"id":"u1","username":"mario.rossi","email":"mario.rossi+iam4d@example.com","enabled":true}]');
    Check('GetUserByEmail', Safely(
      function: Boolean
      begin
        Result := LUsers.GetUserByEmail(CUserEmail).ID = 'u1';
      end));
    Check('query value: plus as %2B [' + LServer.RequestLine + ']',
      LServer.RequestLine.StartsWith('GET /admin/realms/r/users?email=mario.rossi%2Biam4d@example.com&exact=true '));
    Check('TryGetUserByEmail', Safely(
      function: Boolean
      begin
        Result := LUsers.TryGetUserByEmail(CUserEmail).Found;
      end));
    LServer.Reply(200, '{"numFailures":3,"disabled":true,"lastIPFailure":"127.0.0.1","lastFailure":0}');
    Check('IsUserLocked', Safely(
      function: Boolean
      begin
        Result := LUsers.IsUserLocked('u1');
      end));
    Check('IsUserLocked request [' + LServer.RequestLine + ']',
      LServer.RequestLine.StartsWith('GET /admin/realms/r/attack-detection/brute-force/users/u1 '));

    // Status code -> exception class
    LInstancesURL := LServer.URL + '/admin/realms/r/identity-provider/instances';
    LServer.Reply(401, '{"error":"HTTP 401 Unauthorized"}');
    CheckHTTPError('401: HTTP client error',
      procedure
      begin
        LIdPs.GetIdentityProviders;
      end, EIAM4DHTTPClientErrorException, 401, '{"error":"HTTP 401 Unauthorized"}', 'GET ' + LInstancesURL);
    LServer.Reply(403, '{"error":"HTTP 403 Forbidden"}');
    CheckHTTPError('403: insufficient permissions',
      procedure
      begin
        LIdPs.GetIdentityProviders;
      end, EIAM4DInsufficientPermissionsException, 403, '{"error":"HTTP 403 Forbidden"}', 'Get identity providers failed');
    CheckHTTPError('403, short message form',
      procedure
      begin
        LUsers.GetUsersCount;
      end, EIAM4DInsufficientPermissionsException, 403, '{"error":"HTTP 403 Forbidden"}', 'Get users count failed: 403');
    LError := Capture(
      procedure
      begin
        LIdPs.GetIdentityProviders;
      end);
    try
      Check('403 error code', (LError is EIAM4DException) and
        (EIAM4DException(LError).ErrorCode = ecInsufficientPermissions));
    finally
      LError.Free;
    end;
    LServer.Reply(404, '{"error":"Could not find role"}');
    CheckHTTPError('404: not found',
      procedure
      begin
        LUsers.GetUsersWithRole('missing');
      end, EIAM4DHTTPNotFoundException, 404, '{"error":"Could not find role"}');
    LServer.Reply(404, '');
    CheckHTTPError('404 identity provider: not found',
      procedure
      begin
        LIdPs.GetIdentityProvider('missing');
      end, EIAM4DHTTPNotFoundException, 404, '', 'Identity provider "missing" not found');
    LServer.Reply(409, '{"errorMessage":"Identity Provider dup already exists"}');
    CheckHTTPError('409: conflict',
      procedure
      begin
        LIdPs.CreateIdentityProvider(TIAM4DIdentityProvider.Create('dup', IAM4D_IDP_PROVIDER_OIDC));
      end, EIAM4DHTTPConflictException, 409, '{"errorMessage":"Identity Provider dup already exists"}',
      'POST ' + LInstancesURL);
    LServer.Reply(400, '{"errorMessage":"Invalid"}');
    CheckHTTPError('other 4xx: HTTP client error',
      procedure
      begin
        LIdPs.DeleteIdentityProvider('x');
      end, EIAM4DHTTPClientErrorException, 400, '{"errorMessage":"Invalid"}', 'DELETE ' + LInstancesURL + '/x');
    LServer.Reply(500, 'Internal error');
    CheckHTTPError('500: HTTP server error',
      procedure
      begin
        LIdPs.GetIdentityProviders;
      end, EIAM4DHTTPServerErrorException, 500, 'Internal error');
    LServer.Reply(503, '', '30');
    LError := Capture(
      procedure
      begin
        LIdPs.GetIdentityProviders;
      end);
    try
      Check('503: Retry-After', (LError is EIAM4DHTTPServerErrorException) and
        (EIAM4DHTTPServerErrorException(LError).StatusCode = 503) and
        (EIAM4DHTTPServerErrorException(LError).RetryAfterSeconds = 30));
    finally
      LError.Free;
    end;

    // The copy re-raised by an async operation keeps class and data
    LServer.Reply(403, 'forbidden');
    LIdPsAsync := TIAM4DKeycloakIdentityProviderManagerAsync.Create(LIdPs);
    CheckHTTPError('async: 403 keeps class, status and body',
      procedure
      begin
        LIdPsAsync.GetIdentityProvidersAsync.Run.WaitForResult;
      end, EIAM4DInsufficientPermissionsException, 403, 'forbidden');

    // Async wrappers released before their operation runs: the operation keeps the sync manager alive
    LServer.Reply(200, '[]');
    LIdPsAsync := TIAM4DKeycloakIdentityProviderManagerAsync.Create(
      TIAM4DKeycloakIdentityProviderManager.Create('token', LServer.URL, 'r') as IIAM4DIdentityProviderManager);
    LProvidersPromise := LIdPsAsync.GetIdentityProvidersAsync;
    LIdPsAsync := nil;
    Check('identity provider async wrapper released', Safely(
      function: Boolean
      begin
        Result := Length(LProvidersPromise.Run.WaitForResult) = 0;
      end));
    LServer.Reply(200, '7');
    LUsersAsync := TIAM4DKeycloakUserManagerAsync.Create(
      TIAM4DKeycloakUserManager.Create('token', LServer.URL, 'r') as IIAM4DUserManager);
    LCountPromise := LUsersAsync.GetUsersCountAsync;
    LUsersAsync := nil;
    Check('user async wrapper released', Safely(
      function: Boolean
      begin
        Result := LCountPromise.Run.WaitForResult = 7;
      end));
  finally
    LServer.Free;
  end;
end;

// Integer query parameter of a request line; ADefault if missing
function QueryValue(const ARequestLine, AName: string; ADefault: Integer): Integer;
var
  LPath, LPair: string;
  LQueryPos: Integer;
begin
  Result := ADefault;
  LPath := ARequestLine.Split([' '])[1];
  LQueryPos := LPath.IndexOf('?');
  if LQueryPos < 0 then
    Exit;
  for LPair in LPath.Substring(LQueryPos + 1).Split(['&']) do
    if LPair.StartsWith(AName + '=') then
      Result := LPair.Substring(Length(AName) + 1).ToInteger;
end;

// Identity providers p000..p<ATotal-1> as Keycloak 24+ pages them (max 100 when not given)
function ProvidersPage(const ARequestLine: string; ATotal: Integer): TFakeResponse;
var
  LFirst, LMax, LIndex: Integer;
  LItems: TArray<string>;
begin
  LFirst := QueryValue(ARequestLine, 'first', 0);
  LMax := QueryValue(ARequestLine, 'max', 100);
  LItems := nil;
  LIndex := LFirst;
  while (LIndex < ATotal) and ((LMax < 0) or (LIndex < LFirst + LMax)) do
  begin
    LItems := LItems + [Format('{"alias":"p%.3d","providerId":"oidc","enabled":true,"config":{}}', [LIndex])];
    Inc(LIndex);
  end;
  Result := TFakeResponse.Create(200, '[' + string.Join(',', LItems) + ']');
end;

function AliasesUnique(const AProviders: TArray<TIAM4DIdentityProvider>): Boolean;
var
  LSeen: TStringList;
  LProvider: TIAM4DIdentityProvider;
begin
  LSeen := TStringList.Create;
  try
    LSeen.Sorted := True;
    LSeen.Duplicates := dupError;
    Result := True;
    for LProvider in AProviders do
      if LSeen.IndexOf(LProvider.Alias) >= 0 then
        Exit(False)
      else
        LSeen.Add(LProvider.Alias);
  finally
    LSeen.Free;
  end;
end;

// Identity provider manager requests: IDs and masked secrets on create/update, paging
procedure TestIdentityProviderRequests;
var
  LServer: TFakeAdminServer;
  LIdPs: IIAM4DIdentityProviderManager;
  LIdP: TIAM4DIdentityProvider;
  LMapper: TIAM4DIdentityProviderMapper;
  LAll: TArray<TIAM4DIdentityProvider>;
  LMapperID: string;
  LNotFoundOnGet: TFakeResponder;
begin
  Writeln('Identity provider requests (local server)');
  LServer := TFakeAdminServer.Create;
  try
    LIdPs := TIAM4DKeycloakIdentityProviderManager.Create('token', LServer.URL, 'r');
    LNotFoundOnGet :=
      function(const ALine: string): TFakeResponse
      begin
        if ALine.StartsWith('GET ') then
          Result := TFakeResponse.Create(404, '')
        else
          Result := TFakeResponse.Create(201, '');
      end;

    // Provider read from Keycloak and created again (another alias or realm): its internal ID is
    // Keycloak's primary key, reusing it fails with 409 in the same server
    LIdP := TIAM4DIdentityProvider.Create('copy', IAM4D_IDP_PROVIDER_OIDC);
    LIdP.InternalID := '6cf5141a-8f81-4213-89de-b99d8c33b861';
    LIdP.Config.Values['clientSecret'] := 'real-secret';
    LServer.Reply(201, '');
    Check('create sent', Safely(
      function: Boolean
      begin
        LIdPs.CreateIdentityProvider(LIdP);
        Result := True;
      end));
    Check('create without internalId [' + LServer.RequestBody + ']',
      LServer.RequestBody.Contains('"alias":"copy"') and not LServer.RequestBody.Contains('internalId'));
    LServer.Respond(LNotFoundOnGet);
    Safely(
      function: Boolean
      begin
        LIdPs.SaveIdentityProvider(LIdP);
        Result := True;
      end);
    Check('save that creates: without internalId [' + LServer.Requests.Trim + ']',
      LServer.RequestLine.StartsWith('POST ') and not LServer.RequestBody.Contains('internalId'));
    LServer.Reply(204, '');
    Safely(
      function: Boolean
      begin
        LIdPs.UpdateIdentityProvider(LIdP);
        Result := True;
      end);
    Check('update keeps internalId', LServer.RequestBody.Contains('"internalId":"6cf5141a-8f81-4213-89de-b99d8c33b861"'));

    // Secret mask read from Keycloak: create would store it as the secret
    LIdP.Config.Values['clientSecret'] := IAM4D_IDP_SECRET_MASK;
    LServer.Reply(201, '');
    Check('create with the masked secret rejected', Raises(
      procedure
      begin
        LIdPs.CreateIdentityProvider(LIdP);
      end, EIAM4DInvalidConfigurationException));
    Check('create with the masked secret: nothing sent', LServer.RequestCount = 0);
    LServer.Respond(LNotFoundOnGet);
    Check('save that creates, masked secret rejected', Raises(
      procedure
      begin
        LIdPs.SaveIdentityProvider(LIdP);
      end, EIAM4DInvalidConfigurationException));
    Check('save that creates, masked secret: not posted [' + LServer.Requests.Trim + ']',
      not LServer.Requests.Contains('POST '));
    // Update: Keycloak keeps the stored clientSecret when it gets the mask
    LServer.Reply(204, '');
    Check('update with the masked client secret', Safely(
      function: Boolean
      begin
        LIdPs.UpdateIdentityProvider(LIdP);
        Result := LServer.RequestBody.Contains('"clientSecret":"' + IAM4D_IDP_SECRET_MASK + '"');
      end));
    // Keycloak restores clientSecret only: the mask in any other key would be stored as is
    LIdP.Config.Values['clientSecret'] := 'real-secret';
    LIdP.Config.Values['jwtSecret'] := IAM4D_IDP_SECRET_MASK;
    LServer.Reply(204, '');
    Check('update with the mask in another key rejected', Raises(
      procedure
      begin
        LIdPs.UpdateIdentityProvider(LIdP);
      end, EIAM4DInvalidConfigurationException));
    Check('update with the mask in another key: nothing sent', LServer.RequestCount = 0);

    // Mapper read from Keycloak and created on another provider: its ID is a primary key too
    LMapper := TIAM4DIdentityProviderMapper.Create('copy', 'email', 'oidc-user-attribute-idp-mapper');
    LMapper.ID := '7afe3e74-f07b-4013-aa03-96545ce36cbf';
    LServer.Respond(
      function(const ALine: string): TFakeResponse
      begin
        Result := TFakeResponse.Create(201, '', LServer.URL + '/admin/realms/r/identity-provider/instances/copy/mappers/new-id');
      end);
    Check('mapper create returns the new ID', Safely(
      function: Boolean
      begin
        LMapperID := LIdPs.CreateMapper(LMapper);
        Result := LMapperID = 'new-id';
      end));
    Check('mapper create without id [' + LServer.RequestBody + ']',
      LServer.RequestBody.Contains('"name":"email"') and not LServer.RequestBody.Contains('"id"'));

    // Keycloak 24+ returns at most 100 providers when first/max are not given
    LServer.Respond(
      function(const ALine: string): TFakeResponse
      begin
        Result := ProvidersPage(ALine, 205);
      end);
    Check('all providers, beyond the first page', Safely(
      function: Boolean
      begin
        LAll := LIdPs.GetIdentityProviders;
        Result := (Length(LAll) = 205) and (LAll[0].Alias = 'p000') and (LAll[204].Alias = 'p204') and
          AliasesUnique(LAll);
      end));
    Check('providers requested page by page [' + LServer.Requests.Trim + ']', LServer.RequestCount = 3);
    // A server that ignores first/max (every page the same): no endless loop, no duplicates
    LServer.Respond(
      function(const ALine: string): TFakeResponse
      begin
        Result := ProvidersPage('GET /x HTTP/1.1', 100);
      end);
    Check('server ignoring paging', Safely(
      function: Boolean
      begin
        LAll := LIdPs.GetIdentityProviders;
        Result := (Length(LAll) = 100) and AliasesUnique(LAll) and (LServer.RequestCount <= 2);
      end));
  finally
    LServer.Free;
  end;
end;

// AProc fails with AClass, a 404 (EIAM4DHTTPNotFoundException) with the given error code
procedure CheckNotFound(const AName: string; const AProc: TProc; AClass: ExceptClass;
  AErrorCode: TIAM4DErrorCode = ecHTTPClientError);
var
  LError: Exception;
  LDetail: string;
begin
  LError := Capture(AProc);
  try
    if LError = nil then
      LDetail := 'no exception'
    else
      LDetail := LError.ClassName + ': ' + LError.Message.Substring(0, 200);
    Check(AName + ' [' + LDetail + ']', (LError <> nil) and (LError.ClassType = AClass) and
      (LError is EIAM4DHTTPNotFoundException) and (StatusCodeOf(LError) = 404) and
      (EIAM4DException(LError).ErrorCode = AErrorCode));
  finally
    LError.Free;
  end;
end;

// User manager: "not found" answers as typed 404 exceptions, IsUserLocked errors
// IDs that would address another resource are refused before any request; a 3xx is not followed
// with the bearer; role names are compared case-sensitively, as Keycloak does
procedure TestAdminPathsAndRedirects;
var
  LServer: TFakeAdminServer;
  LUsers: IIAM4DUserManager;
  LCase: TArray<string>;
  LID: string;
  LError: Exception;
  LRedirect: TFakeResponder;
  LServerURL: string;
begin
  Writeln('Admin API: path segments, redirects, case of role names (local server)');
  LServer := TFakeAdminServer.Create;
  try
    LUsers := TIAM4DKeycloakUserManager.Create('token', LServer.URL, 'r');
    LServerURL := LServer.URL;

    LCase := ['', '.', '..'];
    for LID in LCase do
    begin
      LServer.Reply(204, '');
      CheckConfigError(Format('UnlockUser("%s") refused', [LID]),
        procedure
        begin
          LUsers.UnlockUser(LID);
        end);
      CheckConfigError(Format('DeleteUser("%s") refused', [LID]),
        procedure
        begin
          LUsers.DeleteUser(LID);
        end);
      Check(Format('no request for user ID "%s"', [LID]), LServer.RequestCount = 0);
    end;
    LServer.Reply(204, '');
    LUsers.UnlockUser('..u1');
    Check('UnlockUser("..u1"): one request on the user path', (LServer.RequestCount = 1) and
      LServer.RequestLine.Contains('/attack-detection/brute-force/users/..u1 '));

    LRedirect :=
      function(const ALine: string): TFakeResponse
      begin
        if ALine.Contains('/elsewhere') then
          Result := TFakeResponse.Create(204, '')
        else
          Result := TFakeResponse.Create(307, '', LServerURL + '/elsewhere');
      end;
    LServer.Respond(LRedirect);
    LError := Capture(
      procedure
      begin
        LUsers.DeleteUser('u1');
      end);
    try
      Check('307 on DeleteUser -> EIAM4DInvalidConfigurationException', LError is EIAM4DInvalidConfigurationException);
    finally
      LError.Free;
    end;
    Check('redirect not followed (one request, none to the Location)', (LServer.RequestCount = 1) and
      not LServer.Requests.Contains('/elsewhere'));

    // A database with a case-insensitive collation answers "Admin" to /roles/admin
    LServer.Reply(200, '{"id":"r0","name":"Admin"}');
    CheckNotFound('AssignRoleByName("admin") with the realm role "Admin": not found',
      procedure
      begin
        LUsers.AssignRoleByName('u1', 'admin');
      end, EIAM4DRoleNotFoundException, ecRoleNotFound);
    Check('AssignRoleByName: the role read by name, nothing assigned [' + LServer.Requests.Trim + ']',
      (LServer.RequestCount = 1) and LServer.RequestLine.StartsWith('GET /admin/realms/r/roles/admin '));
  finally
    LUsers := nil;
    LServer.Free;
  end;
end;

type
  TCountingAuthProvider = class(TInterfacedObject, IKeycloakAuthProvider)
  private
    FCount: Integer;
  public
    function GetAccessToken: string;
    function CreateHTTPClient: THTTPClient;
  end;

function TCountingAuthProvider.GetAccessToken: string;
begin
  Result := 'token-' + IntToStr(TInterlocked.Increment(FCount));
end;

function TCountingAuthProvider.CreateHTTPClient: THTTPClient;
begin
  Result := THTTPClient.Create;
end;

// Batches renew the bearer per item; usernames as Keycloak accepts them; UpdateUser sends the profile
procedure TestUserManagerPayloads;
var
  LServer: TFakeAdminServer;
  LUsers: IIAM4DUserManager;
  LUser: TIAM4DUser;
  LBody: TJSONObject;
  LAuth: TStringList;

  function CreateConflict(const AKeycloakMessage: string): string;
  begin
    Result := 'no exception';
    LServer.Reply(409, '{"errorMessage":"' + AKeycloakMessage + '"}');
    try
      LUsers.CreateUser(TIAM4DUser.Create('mario', 'mario@example.com', 'Mario', 'Rossi'));
    except
      on E: EIAM4DUserAlreadyExistsException do
        if (E is EIAM4DHTTPConflictException) and (E.StatusCode = 409) and (E.ErrorCode = ecUserAlreadyExists) and
          E.ResponseBody.Contains(AKeycloakMessage) then
          Result := E.ConflictingField + '=' + E.Value
        else
          Result := 'wrong fields: ' + E.Message;
      on E: Exception do
        Result := E.ClassName + ': ' + E.Message;
    end;
  end;

begin
  Writeln('User manager: batch tokens, usernames, update payload (local server)');
  LServer := TFakeAdminServer.Create;
  try
    LUsers := TIAM4DKeycloakUserManager.Create(TCountingAuthProvider.Create, LServer.URL, 'r');
    LServer.Reply(204, '');
    LUsers.DeleteUsers(['u1', 'u2', 'u3']);
    LAuth := TStringList.Create;
    try
      LAuth.Text := LServer.Authorizations;
      Check('DeleteUsers: the token is read again for each item [' + LAuth.CommaText + ']',
        (LAuth.Count = 3) and (LAuth[0] <> LAuth[1]) and (LAuth[1] <> LAuth[2]) and LAuth[2].StartsWith('Bearer token-'));
    finally
      LAuth.Free;
    end;

    LServer.Reply(200, '[{"id":"u9","username":"mario.rossi+test@example.com","enabled":true}]');
    Check('GetUserByUsername with "@" and "+": looked up, query encoded',
      (LUsers.GetUserByUsername('mario.rossi+test@example.com').ID = 'u9'));
    // '+' would be a space in the query; '@' is allowed as it is
    Check('GetUserByUsername: query encoded [' + LServer.RequestLine + ']',
      LServer.RequestLine.Contains('username=mario.rossi%2Btest@example.com&exact=true'));
    Check('TryGetUserByUsername with "@"', LUsers.TryGetUserByUsername('anna@example.com').Found);
    Check('ValidateUsername accepts an email as username', not Raises(
      procedure
      begin
        TIAM4DUserManagementValidator.ValidateUsername('mario.rossi+test@example.com');
      end, Exception));
    Check('GetUserByUsername("") refused', Raises(
      procedure
      begin
        LUsers.GetUserByUsername('');
      end, EIAM4DInvalidUserDataException));

    // Keycloak's createdTimestamp is in milliseconds
    LUser := TIAM4DUser.Create('luigi', 'luigi@example.com');
    Check('TIAM4DUser.Create: CreatedTimestamp in milliseconds [' + LUser.CreatedTimestamp.ToString + ']',
      Abs(LUser.CreatedTimestamp - DateTimeToUnix(TDateTime.NowUTC) * MSecsPerSec) < 60000);

    // 409 of CreateUser: EIAM4DUserAlreadyExistsException, still an EIAM4DHTTPConflictException
    LAuth := TStringList.Create;
    try
      LAuth.Add(CreateConflict('User exists with same email'));
      LAuth.Add(CreateConflict('User exists with same username'));
      Check('CreateUser 409: EIAM4DUserAlreadyExistsException with the field Keycloak names [' + LAuth.CommaText + ']',
        (LAuth[0] = 'email=mario@example.com') and (LAuth[1] = 'username=mario'));
    finally
      LAuth.Free;
    end;

    // The record is the new profile: empty fields clear, an empty username is not sent
    LServer.Reply(204, '');
    LUser := Default(TIAM4DUser);
    LUser.ID := 'u1';
    LUser.FirstName := 'Mario';
    LUser.Enabled := True;
    LUser.EmailVerified := True;
    LUsers.UpdateUser(LUser);
    LBody := TJSONObject.ParseJSONValue(LServer.RequestBody) as TJSONObject;
    try
      Check('UpdateUser: PUT with email and lastName empty, no username [' + LServer.RequestBody + ']',
        LServer.RequestLine.StartsWith('PUT /admin/realms/r/users/u1 ') and Assigned(LBody) and
        (LBody.GetValue('username') = nil) and (LBody.GetValue<string>('email', 'x') = '') and
        (LBody.GetValue<string>('lastName', 'x') = '') and (LBody.GetValue<string>('firstName', '') = 'Mario') and
        LBody.GetValue<Boolean>('emailVerified', False) and (LBody.GetValue('requiredActions') is TJSONArray));
    finally
      LBody.Free;
    end;
  finally
    LUsers := nil;
    LServer.Free;
  end;
end;

// Groups by path through group-by-path (Keycloak 23+ lists only the top level); GetGroups walks the children
procedure TestGroupRequests;
var
  LServer: TFakeAdminServer;
  LUsers: IIAM4DUserManager;
  LGroups: TArray<TIAM4DGroup>;
  LPaths: string;
  LGroup: TIAM4DGroup;
begin
  Writeln('Groups by path and group tree (local server)');
  LServer := TFakeAdminServer.Create;
  try
    LUsers := TIAM4DKeycloakUserManager.Create('token', LServer.URL, 'r');

    LServer.Reply(200, '{"id":"g2","name":"Italia Nord","path":"/Sales/Italia Nord"}');
    Check('GetGroupByPath: one encoded segment per level',
      (LUsers.GetGroupByPath('/Sales/Italia Nord').ID = 'g2') and
      LServer.RequestLine.StartsWith('GET /admin/realms/r/group-by-path/Sales/Italia%20Nord '));
    Check('GetGroupByPath: path without the leading slash', (LUsers.GetGroupByPath('Sales/Italia Nord').ID = 'g2'));
    // A case-insensitive database collation may return a group with another case
    Check('TryGetGroupByPath: group with a path of another case not found',
      not LUsers.TryGetGroupByPath('/sales/italia nord').Found);
    LServer.Reply(204, '');
    CheckConfigError('GetGroupByPath("/Sales/../admin") refused',
      procedure
      begin
        LUsers.GetGroupByPath('/Sales/../admin');
      end);
    Check('no request for a path with ".."', LServer.RequestCount = 0);

    // Keycloak 23+: top level with subGroupCount, children asked with an explicit max
    LServer.Respond(
      function(const ALine: string): TFakeResponse
      var
        LChildren: TStringBuilder;
        I: Integer;
      begin
        if ALine.StartsWith('GET /admin/realms/r/groups/g1/children?first=0&max=100 ') then
        begin
          LChildren := TStringBuilder.Create('[');
          try
            for I := 1 to 12 do
            begin
              if I > 1 then
                LChildren.Append(',');
              LChildren.AppendFormat('{"id":"c%d","name":"Area %d","path":"/Sales/Area %d","subGroupCount":%d}',
                [I, I, I, Ord(I = 1)]);
            end;
            Result := TFakeResponse.Create(200, LChildren.Append(']').ToString);
          finally
            LChildren.Free;
          end;
        end
        else if ALine.StartsWith('GET /admin/realms/r/groups/c1/children?') then
          Result := TFakeResponse.Create(200, '[{"id":"d1","name":"Milano","path":"/Sales/Area 1/Milano","subGroupCount":0}]')
        else if ALine.StartsWith('GET /admin/realms/r/groups ') then
          // g3: Keycloak < 23, subGroups inline
          Result := TFakeResponse.Create(200, '[{"id":"g1","name":"Sales","path":"/Sales","subGroupCount":12},' +
            '{"id":"g3","name":"Old","path":"/Old","subGroups":[{"id":"g4","name":"Inline","path":"/Old/Inline","subGroups":[]}]}]')
        else
          Result := TFakeResponse.Create(500, '{"error":"unexpected ' + ALine + '"}');
      end);
    LGroups := LUsers.GetGroups;
    LPaths := '';
    for LGroup in LGroups do
      LPaths := LPaths + LGroup.Path + ';';
    Check('GetGroups: top level, children (12), grandchildren and inline subGroups [' + LPaths + ']',
      (Length(LGroups) = 16) and LPaths.Contains('/Sales/Area 12;') and LPaths.Contains('/Sales/Area 1/Milano;') and
      LPaths.Contains('/Old/Inline;'));
  finally
    LUsers := nil;
    LServer.Free;
  end;
end;

procedure TestAdminConnectionReuse;
const
  OPERATIONS = 10;
  PARALLEL = 8;
var
  LServer: TFakeAdminServer;
  LUsers: IIAM4DUserManager;
  LUsersAsync: IIAM4DUserManagerAsync;
  LPromises: TArray<IAsyncOperation<TIAM4DUser>>;
  LIndex, LConnections: Integer;
  LAllBearer, LAllDone: Boolean;
begin
  Writeln('Admin API connection reuse (local server)');
  LServer := TFakeAdminServer.Create;
  try
    LServer.KeepAlive := True;
    LUsers := TIAM4DKeycloakUserManager.Create('token', LServer.URL, 'r');
    LServer.Reply(200, '{"id":"u1","username":"mario"}');
    for LIndex := 1 to OPERATIONS do
      Safely(
        function: Boolean
        begin
          Result := LUsers.GetUser('u1').ID = 'u1';
        end);
    Check(Format('%d operations: %d requests', [OPERATIONS, LServer.RequestCount]), LServer.RequestCount = OPERATIONS);
    LAllBearer := True;
    for var LLine in LServer.Authorizations.Split([sLineBreak], TStringSplitOptions.ExcludeEmpty) do
      LAllBearer := LAllBearer and (LLine = 'Bearer token');
    Check('every request of a reused client carries the bearer', LAllBearer);
{$IFDEF MSWINDOWS}
    // WinHTTP keeps the connection of a client alive between its requests
    Check(Format('%d sequential operations: one connection (%d)', [OPERATIONS, LServer.ConnectionCount]),
      LServer.ConnectionCount = 1);
{$ELSE}
    Check(Format('%d sequential operations: at most %d connections (%d)', [OPERATIONS, OPERATIONS,
      LServer.ConnectionCount]), LServer.ConnectionCount <= OPERATIONS);
{$ENDIF}

    // Parallel operations of the async manager: each on a client of its own, all completed
    LConnections := LServer.ConnectionCount;
    LUsersAsync := TIAM4DKeycloakUserManagerAsync.Create(LUsers);
    LServer.Reply(200, '{"id":"u1","username":"mario"}');
    SetLength(LPromises, PARALLEL);
    for LIndex := 0 to PARALLEL - 1 do
      LPromises[LIndex] := LUsersAsync.GetUserAsync('u1').Run;
    LAllDone := True;
    for LIndex := 0 to PARALLEL - 1 do
      LAllDone := LAllDone and Safely(
        function: Boolean
        begin
          Result := LPromises[LIndex].WaitForResult.ID = 'u1';
        end);
    Check(Format('%d parallel operations completed', [PARALLEL]), LAllDone and (LServer.RequestCount = PARALLEL));
    Check(Format('%d parallel operations: at most %d new connections (%d)', [PARALLEL, PARALLEL,
      LServer.ConnectionCount - LConnections]), LServer.ConnectionCount - LConnections <= PARALLEL);
    LPromises := nil;
    LUsersAsync := nil;
    LUsers := nil;
  finally
    LServer.Free;
  end;
end;

procedure TestUserManagerRequests;
var
  LServer: TFakeAdminServer;
  LUsers: IIAM4DUserManager;
  LRole: TIAM4DRole;
  LClientWithOtherRole: TFakeResponder;
  LRequests: Integer;
begin
  Writeln('User manager requests (local server)');
  LServer := TFakeAdminServer.Create;
  try
    LUsers := TIAM4DKeycloakUserManager.Create('token', LServer.URL, 'r');
    LRole := Default(TIAM4DRole);
    LRole.Name := 'r1';

    LServer.Reply(404, '{"error":"Could not find role"}');
    CheckNotFound('AssignRoleByName: realm role not found',
      procedure
      begin
        LUsers.AssignRoleByName('u1', 'missing');
      end, EIAM4DRoleNotFoundException, ecRoleNotFound);
    CheckNotFound('RemoveRoleByName: realm role not found',
      procedure
      begin
        LUsers.RemoveRoleByName('u1', 'missing');
      end, EIAM4DRoleNotFoundException, ecRoleNotFound);
    LServer.Reply(404, '{"error":"Could not find role"}');
    CheckNotFound('GetRoleByName: 404',
      procedure
      begin
        LUsers.GetRoleByName('missing');
      end, EIAM4DRoleNotFoundException, ecRoleNotFound);

    // Client found, role missing
    LClientWithOtherRole :=
      function(const ALine: string): TFakeResponse
      begin
        if ALine.Contains('/clients?clientId=') then
          Result := TFakeResponse.Create(200, '[{"id":"c1","clientId":"app"}]')
        else if ALine.StartsWith('GET /admin/realms/r/clients/c1/roles/r1 ') then
          Result := TFakeResponse.Create(200, '{"id":"cr1","name":"r1","clientRole":true,"containerId":"c1"}')
        else if ALine.StartsWith('GET /admin/realms/r/clients/c1/roles/Missing ') then
          Result := TFakeResponse.Create(200, '{"id":"cr2","name":"missing","clientRole":true,"containerId":"c1"}')
        else if ALine.StartsWith('GET ') then
          Result := TFakeResponse.Create(404, '{"error":"Could not find role"}')
        else
          Result := TFakeResponse.Create(204, '');
      end;
    LServer.Respond(LClientWithOtherRole);
    CheckNotFound('AssignClientRoleByClientID: client role not found',
      procedure
      begin
        LUsers.AssignClientRoleByClientID('u1', 'app', 'missing');
      end, EIAM4DRoleNotFoundException, ecRoleNotFound);
    CheckNotFound('RemoveClientRoleByClientID: client role not found',
      procedure
      begin
        LUsers.RemoveClientRoleByClientID('u1', 'app', 'missing');
      end, EIAM4DRoleNotFoundException, ecRoleNotFound);
    CheckNotFound('AssignClientRoleByClientID: role of another case not found',
      procedure
      begin
        LUsers.AssignClientRoleByClientID('u1', 'app', 'Missing');
      end, EIAM4DRoleNotFoundException, ecRoleNotFound);
    LServer.Respond(LClientWithOtherRole);
    Check('AssignClientRoleByClientID: client, role by name, mapping', Safely(
      function: Boolean
      begin
        LUsers.AssignClientRoleByClientID('u1', 'app', 'r1');
        Result := LServer.Requests.Contains('GET /admin/realms/r/clients/c1/roles/r1 ') and
          LServer.Requests.Contains('POST /admin/realms/r/users/u1/role-mappings/clients/c1 ') and
          LServer.RequestBody.Contains('"cr1"') and not LServer.Requests.Contains('/clients/c1/roles ');
      end));

    // Client missing
    LServer.Reply(200, '[]');
    CheckNotFound('GetClientRolesByClientID: client not found',
      procedure
      begin
        LUsers.GetClientRolesByClientID('missing');
      end, EIAM4DHTTPNotFoundException);
    CheckNotFound('GetClientByClientID: client not found',
      procedure
      begin
        LUsers.GetClientByClientID('missing');
      end, EIAM4DHTTPNotFoundException);
    CheckNotFound('HasClientRoleByClientID: client not found',
      procedure
      begin
        LUsers.HasClientRoleByClientID('u1', 'missing', 'r1');
      end, EIAM4DHTTPNotFoundException);
    CheckNotFound('GetUserClientRolesByClientID: client not found',
      procedure
      begin
        LUsers.GetUserClientRolesByClientID('u1', 'missing');
      end, EIAM4DHTTPNotFoundException);
    CheckNotFound('RemoveClientRolesFromUserByClientID: client not found',
      procedure
      begin
        LUsers.RemoveClientRolesFromUserByClientID('u1', 'missing', [LRole]);
      end, EIAM4DHTTPNotFoundException);
    CheckNotFound('AssignClientRoleByClientID: client not found',
      procedure
      begin
        LUsers.AssignClientRoleByClientID('u1', 'missing', 'r1');
      end, EIAM4DHTTPNotFoundException);

    // Group missing: 404 from group-by-path
    LServer.Reply(404, '{"error":"Group path does not exist"}');
    CheckNotFound('AddUserToGroupByPath: group not found',
      procedure
      begin
        LUsers.AddUserToGroupByPath('u1', '/missing');
      end, EIAM4DGroupNotFoundException, ecGroupNotFound);
    CheckNotFound('RemoveUserFromGroupByPath: group not found',
      procedure
      begin
        LUsers.RemoveUserFromGroupByPath('u1', '/missing');
      end, EIAM4DGroupNotFoundException, ecGroupNotFound);
    CheckNotFound('GetUsersInGroupByPath: group not found',
      procedure
      begin
        LUsers.GetUsersInGroupByPath('/missing');
      end, EIAM4DGroupNotFoundException, ecGroupNotFound);
    CheckNotFound('GetGroupByPath: group not found',
      procedure
      begin
        LUsers.GetGroupByPath('/missing');
      end, EIAM4DGroupNotFoundException, ecGroupNotFound);
    LServer.Reply(200, '[]');

    // User missing
    CheckNotFound('GetUserByUsername: user not found',
      procedure
      begin
        LUsers.GetUserByUsername('nobody');
      end, EIAM4DUserNotFoundException, ecUserNotFound);
    CheckNotFound('GetUserByEmail: user not found',
      procedure
      begin
        LUsers.GetUserByEmail('nobody@example.com');
      end, EIAM4DUserNotFoundException, ecUserNotFound);

    // IsUserLocked: only "not locked" (or no brute force record) is False
    LServer.Reply(403, '{"error":"HTTP 403 Forbidden"}');
    CheckHTTPError('IsUserLocked: 403 raises',
      procedure
      begin
        LUsers.IsUserLocked('u1');
      end, EIAM4DInsufficientPermissionsException, 403, 'Forbidden');
    LServer.Reply(500, 'Internal error');
    CheckHTTPError('IsUserLocked: 500 raises',
      procedure
      begin
        LUsers.IsUserLocked('u1');
      end, EIAM4DHTTPServerErrorException, 500, 'Internal error');
    LServer.Reply(200, 'not json');
    Check('IsUserLocked: invalid response raises', Raises(
      procedure
      begin
        LUsers.IsUserLocked('u1');
      end, EIAM4DException));
    LServer.Reply(404, '');
    Check('IsUserLocked: 404 is not locked', Safely(
      function: Boolean
      begin
        Result := not LUsers.IsUserLocked('u1');
      end));
    LServer.Reply(200, '{"numFailures":0,"disabled":false}');
    Check('IsUserLocked: not locked', Safely(
      function: Boolean
      begin
        Result := not LUsers.IsUserLocked('u1');
      end));

    // Two users with the same email (realm with duplicate emails allowed): never the first one
    LServer.Reply(200, '[{"id":"u1","username":"a","email":"dup@example.com"},' +
      '{"id":"u2","username":"b","email":"dup@example.com"}]');
    Check('GetUserByEmail: two users -> EIAM4DInvalidUserDataException', Raises(
      procedure
      begin
        LUsers.GetUserByEmail('dup@example.com');
      end, EIAM4DInvalidUserDataException));
    Check('TryGetUserByEmail: two users -> EIAM4DInvalidUserDataException', Raises(
      procedure
      begin
        LUsers.TryGetUserByEmail('dup@example.com');
      end, EIAM4DInvalidUserDataException));

    // Paging checked before the request
    LServer.Reply(200, '[]');
    LRequests := LServer.RequestCount;
    Check('GetUsersWithRole: first -1 -> EIAM4DInvalidConfigurationException', Raises(
      procedure
      begin
        LUsers.GetUsersWithRole('r1', -1, 10);
      end, EIAM4DInvalidConfigurationException));
    Check('GetUsersWithRole: max 0 -> EIAM4DInvalidConfigurationException', Raises(
      procedure
      begin
        LUsers.GetUsersWithRole('r1', 0, 0);
      end, EIAM4DInvalidConfigurationException));
    Check('GetUsersInGroupByPath: max -5 -> EIAM4DInvalidConfigurationException', Raises(
      procedure
      begin
        LUsers.GetUsersInGroupByPath('/g', 0, -5);
      end, EIAM4DInvalidConfigurationException));
    Check('SearchUsers: negative FirstResult -> EIAM4DInvalidConfigurationException', Raises(
      procedure
      var
        LCriteria: TIAM4DUserSearchCriteria;
      begin
        LCriteria := TIAM4DUserSearchCriteria.Create;
        LCriteria.FirstResult := -1;
        LUsers.SearchUsers(LCriteria);
      end, EIAM4DInvalidConfigurationException));
    Check('invalid paging: no request sent', LServer.RequestCount = LRequests);

    // Temporary password checked as SetPassword does, before the request
    Check('CreateUser: temporary password too short -> EIAM4DInvalidUserDataException', Raises(
      procedure
      var
        LUser: TIAM4DUser;
      begin
        LUser := TIAM4DUser.Create('mario', 'mario@example.com', 'Mario', 'Rossi');
        LUser.TemporaryPassword := 'short';
        LUsers.CreateUser(LUser);
      end, EIAM4DInvalidUserDataException));
    Check('CreateUsers: temporary password too short -> error in the result of the item', Safely(
      function: Boolean
      var
        LUser: TIAM4DUser;
        LResults: TArray<TIAM4DUsersCreateResult>;
      begin
        LUser := TIAM4DUser.Create('mario', 'mario@example.com', 'Mario', 'Rossi');
        LUser.TemporaryPassword := 'short';
        LResults := LUsers.CreateUsers([LUser]);
        Result := (Length(LResults) = 1) and LResults[0].ErrorMessage.Contains('Password') and
          (LResults[0].ID = '');
      end));
    Check('temporary password too short: no request sent', LServer.RequestCount = LRequests);
  finally
    LServer.Free;
  end;
end;

// Alias validation before any request, and the static token provider
procedure TestAliasAndTokenProvider;
var
  LServer: TFakeAdminServer;
  LIdPs: IIAM4DIdentityProviderManager;
  LAlias: string;
begin
  Writeln('Alias validation and static token (local server)');
  LServer := TFakeAdminServer.Create;
  try
    LIdPs := TIAM4DKeycloakIdentityProviderManager.Create('static-token', LServer.URL, 'r');
    LServer.Reply(200, '{"alias":"x","providerId":"oidc"}');
    for LAlias in ['', ' ', 'a/b', 'a\b', 'a?b', 'a#b', 'a%b', 'a b', 'a&b'] do
      Check(Format('alias "%s" rejected', [LAlias]), Raises(
        procedure
        begin
          LIdPs.GetIdentityProvider(LAlias);
        end, EIAM4DInvalidConfigurationException));
    Check('mapper alias rejected', Raises(
      procedure
      begin
        LIdPs.CreateMapper(TIAM4DIdentityProviderMapper.Create('a/b', 'm', 't'));
      end, EIAM4DInvalidConfigurationException));
    Check('mapper ID rejected', Raises(
      procedure
      begin
        LIdPs.DeleteMapper('x', '../y');
      end, EIAM4DInvalidConfigurationException));
    Check('invalid aliases: nothing sent', LServer.RequestCount = 0);
    Check('valid alias', Safely(
      function: Boolean
      begin
        Result := LIdPs.GetIdentityProvider('x.y_z-1').Alias = 'x';
      end));

    // Static token: sent as is, as a bearer token
    Check('static token sent [' + LServer.Authorization + ']', LServer.Authorization = 'Bearer static-token');
    Check('empty static token rejected', Raises(
      procedure
      begin
        TTokenBasedAuthProvider.Create('');
      end, EIAM4DInvalidConfigurationException));
    Check('empty static token rejected by the manager', Raises(
      procedure
      begin
        TIAM4DKeycloakIdentityProviderManager.Create('', LServer.URL, 'r');
      end, EIAM4DInvalidConfigurationException));
    // Static token with an HTTP configuration, on the user manager
    LServer.Reply(200, '3');
    Check('static token with HTTP configuration', Safely(
      function: Boolean
      begin
        Result := ((TIAM4DKeycloakUserManager.Create('other-token', LServer.URL, 'r',
          TIAM4DHTTPClientConfig.Create(5000, 10000)) as IIAM4DUserManager).GetUsersCount = 3) and
          (LServer.Authorization = 'Bearer other-token');
      end));
  finally
    LServer.Free;
  end;
end;

// Mapper type as Keycloak 26 returns it (subset)
const
  CMapperTypes =
    '{"oidc-user-attribute-idp-mapper":{"id":"oidc-user-attribute-idp-mapper","name":"Attribute Importer",' +
    '"category":"Attribute Importer","helpText":"Import declared claim","properties":[' +
    '{"name":"claim","label":"Claim","helpText":"Name of claim","type":"String","secret":false,"required":false,' +
    '"readOnly":false},{"name":"syncMode","label":"Sync mode override","type":"List","defaultValue":"INHERIT",' +
    '"options":["INHERIT","IMPORT","FORCE"],"secret":false,"required":true,"readOnly":false}]},' +
    '"hardcoded-attribute-idp-mapper":{"id":"hardcoded-attribute-idp-mapper","name":"Hardcoded Attribute",' +
    '"category":"Attribute Importer","helpText":"","properties":[]}}';

// Identity provider types, single mappers and mapper types, one page of providers, Keycloak < 26, links
procedure TestNewAdminRequests;
var
  LServer: TFakeAdminServer;
  LIdPs: IIAM4DIdentityProviderManager;
  LUsers: IIAM4DUserManager;
  LTypes: TArray<TIAM4DIdentityProviderMapperType>;
  LIdP: TIAM4DIdentityProvider;
  LLink: TIAM4DFederatedIdentity;
begin
  Writeln('New Admin API requests (local server)');
  LServer := TFakeAdminServer.Create;
  try
    LIdPs := TIAM4DKeycloakIdentityProviderManager.Create('token', LServer.URL, 'r');
    LUsers := TIAM4DKeycloakUserManager.Create('token', LServer.URL, 'r');

    // Provider types: Keycloak answers 400 for a type it does not have
    LServer.Reply(200, '{"id":"spid-saml","name":"SPID"}');
    Check('provider installed', Safely(
      function: Boolean
      begin
        Result := LIdPs.IsProviderInstalled(IAM4D_IDP_PROVIDER_SPID);
      end));
    Check('provider type request [' + LServer.RequestLine + ']',
      LServer.RequestLine.StartsWith('GET /admin/realms/r/identity-provider/providers/spid-saml '));
    LServer.Reply(400, '{"error":"HTTP 400 Bad Request"}');
    Check('provider not installed', Safely(
      function: Boolean
      begin
        Result := not LIdPs.IsProviderInstalled('nope');
      end));
    LServer.Reply(403, 'forbidden');
    CheckHTTPError('provider type without permission (403)',
      procedure
      begin
        LIdPs.IsProviderInstalled('oidc');
      end, EIAM4DInsufficientPermissionsException, 403, 'forbidden');

    // One page
    LServer.Respond(
      function(const ALine: string): TFakeResponse
      begin
        Result := ProvidersPage(ALine, 205);
      end);
    Check('page of providers', Safely(
      function: Boolean
      var
        LPage: TArray<TIAM4DIdentityProvider>;
      begin
        LPage := LIdPs.GetIdentityProviders('spid-*', 200, 10);
        Result := (Length(LPage) = 5) and (LPage[0].Alias = 'p200');
      end));
    Check('page request [' + LServer.RequestLine + ']', LServer.RequestLine.StartsWith(
      'GET /admin/realms/r/identity-provider/instances?search=spid-*&first=200&max=10 '));
    Check('page: negative first rejected', Raises(
      procedure
      begin
        LIdPs.GetIdentityProviders('', -1, 10);
      end, EIAM4DInvalidConfigurationException));
    Check('page: max below 1 rejected', Raises(
      procedure
      begin
        LIdPs.GetIdentityProviders('', 0, 0);
      end, EIAM4DInvalidConfigurationException));

    // Single mapper: Keycloak looks the ID up in the whole realm
    LServer.Reply(200, '{"id":"m1","name":"email","identityProviderAlias":"entra",' +
      '"identityProviderMapper":"oidc-user-attribute-idp-mapper","config":{"claim":"email"}}');
    Check('get mapper', Safely(
      function: Boolean
      var
        LMapper: TIAM4DIdentityProviderMapper;
      begin
        LMapper := LIdPs.GetMapper('entra', 'm1');
        Result := (LMapper.ID = 'm1') and (LMapper.Config.Values['claim'] = 'email');
      end));
    Check('get mapper request [' + LServer.RequestLine + ']',
      LServer.RequestLine.StartsWith('GET /admin/realms/r/identity-provider/instances/entra/mappers/m1 '));
    CheckHTTPError('mapper of another provider (404)',
      procedure
      begin
        LIdPs.GetMapper('other', 'm1');
      end, EIAM4DHTTPNotFoundException, 404, '');

    // Mapper types: map of ID to type, returned ordered by ID
    LServer.Reply(200, CMapperTypes);
    Check('mapper types', Safely(
      function: Boolean
      begin
        LTypes := LIdPs.GetMapperTypes('entra');
        Result := (Length(LTypes) = 2) and (LTypes[0].ID = 'hardcoded-attribute-idp-mapper') and
          (LTypes[1].Name = 'Attribute Importer') and (Length(LTypes[1].Properties) = 2) and
          (LTypes[1].Properties[0].Name = 'claim') and (LTypes[1].Properties[0].PropertyType = 'String') and
          (LTypes[1].Properties[1].DefaultValue = 'INHERIT') and LTypes[1].Properties[1].Required and
          (Length(LTypes[1].Properties[1].Options) = 3) and (LTypes[1].Properties[1].Options[2] = 'FORCE');
      end));
    Check('mapper types request [' + LServer.RequestLine + ']',
      LServer.RequestLine.StartsWith('GET /admin/realms/r/identity-provider/instances/entra/mapper-types '));

    // Keycloak < 26 rejects the hideOnLogin field: sent again with config hideOnLoginPage only
    LServer.Respond(
      function(const ALine: string): TFakeResponse
      begin
        if LServer.RequestBody.Contains('"hideOnLogin"') then
          Result := TFakeResponse.Create(400, '{"error":"Unrecognized field \"hideOnLogin\" (class ' +
            'org.keycloak.representations.idm.IdentityProviderRepresentation), not marked as ignorable"}')
        else
          Result := TFakeResponse.Create(201, '');
      end);
    LIdP := TIAM4DIdentityProvider.Create('old', IAM4D_IDP_PROVIDER_SAML);
    LIdP.HideOnLogin := True;
    Check('Keycloak < 26: create without hideOnLogin', Safely(
      function: Boolean
      begin
        LIdPs.CreateIdentityProvider(LIdP);
        Result := (LServer.RequestCount = 2) and not LServer.RequestBody.Contains('"hideOnLogin"') and
          LServer.RequestBody.Contains('"hideOnLoginPage":"true"');
      end));
    Check('Keycloak < 26: update without hideOnLogin', Safely(
      function: Boolean
      begin
        LServer.Respond(
          function(const ALine: string): TFakeResponse
          begin
            if LServer.RequestBody.Contains('"hideOnLogin"') then
              Result := TFakeResponse.Create(400, '{"error":"Unrecognized field \"hideOnLogin\""}')
            else
              Result := TFakeResponse.Create(204, '');
          end);
        LIdPs.UpdateIdentityProvider(LIdP);
        Result := (LServer.RequestCount = 2) and LServer.RequestLine.StartsWith('PUT ');
      end));
    LServer.Reply(400, '{"errorMessage":"Invalid request"}');
    CheckHTTPError('other 400: not sent again',
      procedure
      begin
        LIdPs.CreateIdentityProvider(LIdP);
      end, EIAM4DHTTPClientErrorException, 400, 'Invalid request');
    Check('other 400: one request', LServer.RequestCount = 1);

    // Federated identity links
    LLink := TIAM4DFederatedIdentity.Create('spid poste', 'RSSMRA80A01H501U', 'mario');
    LServer.Reply(204, '');
    Check('link federated identity', Safely(
      function: Boolean
      begin
        LUsers.LinkFederatedIdentity('u1', LLink);
        Result := LServer.RequestLine.StartsWith('POST /admin/realms/r/users/u1/federated-identity/spid%20poste ') and
          LServer.RequestBody.Contains('"userId":"RSSMRA80A01H501U"') and LServer.RequestBody.Contains('"userName":"mario"');
      end));
    Check('link without user name rejected', Raises(
      procedure
      begin
        LUsers.LinkFederatedIdentity('u1', TIAM4DFederatedIdentity.Create('spid', 'x', ''));
      end, EIAM4DInvalidConfigurationException));
    Check('unlink federated identity', Safely(
      function: Boolean
      begin
        LUsers.UnlinkFederatedIdentity('u1', 'spid poste');
        Result := LServer.RequestLine.StartsWith('DELETE /admin/realms/r/users/u1/federated-identity/spid%20poste ');
      end));
    LServer.Reply(409, '{"errorMessage":"User is already linked with provider"}');
    CheckHTTPError('link twice (409)',
      procedure
      begin
        LUsers.LinkFederatedIdentity('u1', LLink);
      end, EIAM4DHTTPConflictException, 409, 'already linked');
    LServer.Reply(404, '{"error":"Link not found"}');
    CheckHTTPError('unlink a missing link (404)',
      procedure
      begin
        LUsers.UnlinkFederatedIdentity('u1', 'spid');
      end, EIAM4DHTTPNotFoundException, 404, 'Link not found');

    // Async wrappers of the new methods
    LServer.Reply(200, CMapperTypes);
    Check('async mapper types', Safely(
      function: Boolean
      begin
        Result := Length((TIAM4DKeycloakIdentityProviderManagerAsync.Create(LIdPs) as IIAM4DIdentityProviderManagerAsync)
          .GetMapperTypesAsync('entra').Run.WaitForResult) = 2;
      end));
    LServer.Reply(204, '');
    Check('async unlink', Safely(
      function: Boolean
      begin
        (TIAM4DKeycloakUserManagerAsync.Create(LUsers) as IIAM4DUserManagerAsync)
          .UnlinkFederatedIdentityAsync('u1', 'spid').Run.WaitForCompletion(INFINITE, True);
        Result := LServer.RequestLine.StartsWith('DELETE ');
      end));
  finally
    LServer.Free;
  end;
end;

// ============================================================================
// Integration (Keycloak Admin REST API and login redirect)
// ============================================================================

var
  GKeycloakURL: string;
  GAdminToken: string;
  GAdminUser, GAdminPassword: string;

function TryGetAdminToken(const AUser, APassword: string): Boolean; forward;

function SendAdminRequest(const AMethod, APath, ABody: string): IHTTPResponse;
var
  LClient: THTTPClient;
  LBody: TStringStream;
begin
  LClient := THTTPClient.Create;
  try
    LClient.CustomHeaders['Authorization'] := 'Bearer ' + GAdminToken;
    LClient.ContentType := 'application/json';
    LBody := TStringStream.Create(ABody, TEncoding.UTF8);
    try
      if AMethod = 'GET' then
        Result := LClient.Get(GKeycloakURL + APath)
      else if AMethod = 'POST' then
        Result := LClient.Post(GKeycloakURL + APath, LBody)
      else if AMethod = 'PUT' then
        Result := LClient.Put(GKeycloakURL + APath, LBody)
      else
        Result := LClient.Delete(GKeycloakURL + APath);
    finally
      LBody.Free;
    end;
  finally
    LClient.Free;
  end;
end;

// Admin request with the master token; a new token if the session was ended meanwhile
// (another client of the shared Keycloak may log the admin out)
function AdminRequest(const AMethod, APath: string; const ABody: string = ''): IHTTPResponse;
begin
  Result := SendAdminRequest(AMethod, APath, ABody);
  if (Result.StatusCode = 401) and TryGetAdminToken(GAdminUser, GAdminPassword) then
    Result := SendAdminRequest(AMethod, APath, ABody);
end;

procedure EnsureStatus(const AResponse: IHTTPResponse; const AContext: string);
begin
  if not (AResponse.StatusCode in [200, 201, 204]) then
    raise Exception.CreateFmt('%s: %d %s', [AContext, AResponse.StatusCode, AResponse.ContentAsString]);
end;

function TryGetAdminToken(const AUser, APassword: string): Boolean;
var
  LClient: THTTPClient;
  LForm: TStringList;
  LResponse: IHTTPResponse;
  LJSON: TJSONObject;
begin
  Result := False;
  LClient := THTTPClient.Create;
  LForm := TStringList.Create;
  try
    LClient.ConnectionTimeout := 5000;
    LClient.ResponseTimeout := 10000;
    LForm.AddPair('client_id', 'admin-cli');
    LForm.AddPair('grant_type', 'password');
    LForm.AddPair('username', AUser);
    LForm.AddPair('password', APassword);
    try
      LResponse := LClient.Post(GKeycloakURL + '/realms/master/protocol/openid-connect/token', LForm);
    except
      Exit;
    end;
    if LResponse.StatusCode <> 200 then
      Exit;
    LJSON := ParseObject(LResponse.ContentAsString);
    try
      GAdminToken := LJSON.GetValue<string>('access_token');
      Result := True;
    finally
      LJSON.Free;
    end;
  finally
    LForm.Free;
    LClient.Free;
  end;
end;

function LocationID(const AResponse: IHTTPResponse): string;
var
  LLocation: string;
begin
  LLocation := AResponse.HeaderValue['Location'];
  Result := LLocation.Substring(LLocation.LastIndexOf('/') + 1);
end;

function FirstObject(const AResponse: IHTTPResponse): TJSONObject;
var
  LArray: TJSONArray;
begin
  LArray := TJSONObject.ParseJSONValue(AResponse.ContentAsString) as TJSONArray;
  try
    Result := LArray.Items[0].Clone as TJSONObject;
  finally
    LArray.Free;
  end;
end;

// Realm with a service account client allowed to manage identity providers and to read users and roles
// (not to write them), a public app client, a realm role with a space and a user with that role
procedure SetupRealm;
var
  LResponse: IHTTPResponse;
  LAdminClientUUID, LServiceUserID, LRealmManagementUUID, LUserID, LScopeID, LGroupID: string;
  LClient: TJSONObject;
  I: Integer;
  LRoles, LScopes: TJSONArray;
  LScope: TJSONValue;
  LRoleName: string;
begin
  AdminRequest('DELETE', '/admin/realms/' + CRealm);
  EnsureStatus(AdminRequest('POST', '/admin/realms', '{"realm":"' + CRealm + '","enabled":true}'), 'Create realm');

  LResponse := AdminRequest('POST', '/admin/realms/' + CRealm + '/clients',
    '{"clientId":"' + CAdminClientID + '","enabled":true,"publicClient":false,"serviceAccountsEnabled":true,' +
    '"standardFlowEnabled":false,"clientAuthenticatorType":"client-secret","secret":"' + CAdminClientSecret + '"}');
  EnsureStatus(LResponse, 'Create admin client');
  LAdminClientUUID := LocationID(LResponse);

  // Keycloak 26.8.2+: Admin REST API tokens need the audience of the kc-admin-api client scope,
  // default only on admin-cli and security-admin-console
  LResponse := AdminRequest('GET', '/admin/realms/' + CRealm + '/client-scopes');
  EnsureStatus(LResponse, 'Get client scopes');
  LScopeID := '';
  LScopes := TJSONObject.ParseJSONValue(LResponse.ContentAsString) as TJSONArray;
  try
    for LScope in LScopes do
      if TJSONObject(LScope).GetValue<string>('name') = 'kc-admin-api' then
        LScopeID := TJSONObject(LScope).GetValue<string>('id');
  finally
    LScopes.Free;
  end;
  if LScopeID <> '' then
    EnsureStatus(AdminRequest('PUT', '/admin/realms/' + CRealm + '/clients/' + LAdminClientUUID +
      '/default-client-scopes/' + LScopeID), 'Add kc-admin-api to the admin client');

  LResponse := AdminRequest('GET', '/admin/realms/' + CRealm + '/clients/' + LAdminClientUUID + '/service-account-user');
  EnsureStatus(LResponse, 'Get service account user');
  LClient := ParseObject(LResponse.ContentAsString);
  try
    LServiceUserID := LClient.GetValue<string>('id');
  finally
    LClient.Free;
  end;

  LResponse := AdminRequest('GET', '/admin/realms/' + CRealm + '/clients?clientId=realm-management');
  EnsureStatus(LResponse, 'Get realm-management');
  LClient := FirstObject(LResponse);
  try
    LRealmManagementUUID := LClient.GetValue<string>('id');
  finally
    LClient.Free;
  end;

  LRoles := TJSONArray.Create;
  try
    for LRoleName in ['manage-identity-providers', 'view-identity-providers', 'view-users', 'view-realm', 'view-clients'] do
    begin
      LResponse := AdminRequest('GET', '/admin/realms/' + CRealm + '/clients/' + LRealmManagementUUID + '/roles/' + LRoleName);
      EnsureStatus(LResponse, 'Get role ' + LRoleName);
      LRoles.AddElement(TJSONObject.ParseJSONValue(LResponse.ContentAsString));
    end;
    EnsureStatus(AdminRequest('POST', '/admin/realms/' + CRealm + '/users/' + LServiceUserID +
      '/role-mappings/clients/' + LRealmManagementUUID, LRoles.ToString), 'Assign realm-management roles');
  finally
    LRoles.Free;
  end;

  EnsureStatus(AdminRequest('POST', '/admin/realms/' + CRealm + '/clients',
    '{"clientId":"' + CAppClientID + '","enabled":true,"publicClient":true,"standardFlowEnabled":true,' +
    '"redirectUris":["' + CCallbackURL + '","http://127.0.0.1:' + CCallbackPort.ToString +
    IAM4D_OAUTH2_CALLBACK_DEFAULT_PATH + '"],"attributes":{"pkce.code.challenge.method":"S256"}}'),
    'Create app client');

  EnsureStatus(AdminRequest('POST', '/admin/realms/' + CRealm + '/roles', '{"name":"' + CRoleWithSpace + '"}'),
    'Create role');
  LResponse := AdminRequest('POST', '/admin/realms/' + CRealm + '/users',
    '{"username":"' + CUsername + '","email":"' + CUserEmail + '","firstName":"' + CUserFirstName + '",' +
    '"lastName":"Rossi","enabled":true}');
  EnsureStatus(LResponse, 'Create user');
  LUserID := LocationID(LResponse);
  LResponse := AdminRequest('GET', '/admin/realms/' + CRealm + '/roles/Sales%20Manager');
  EnsureStatus(LResponse, 'Get role');
  EnsureStatus(AdminRequest('POST', '/admin/realms/' + CRealm + '/users/' + LUserID + '/role-mappings/realm',
    '[' + LResponse.ContentAsString + ']'), 'Assign role');

  // Nested groups: more children than the default page (10) of the children endpoint
  LResponse := AdminRequest('POST', '/admin/realms/' + CRealm + '/groups', '{"name":"Sales"}');
  EnsureStatus(LResponse, 'Create group');
  LGroupID := LocationID(LResponse);
  EnsureStatus(AdminRequest('POST', '/admin/realms/' + CRealm + '/groups/' + LGroupID + '/children',
    '{"name":"Italia Nord"}'), 'Create subgroup');
  for I := 1 to 11 do
    EnsureStatus(AdminRequest('POST', '/admin/realms/' + CRealm + '/groups/' + LGroupID + '/children',
      Format('{"name":"Area %.2d"}', [I])), 'Create subgroup');
end;

// Follows the redirects inside Keycloak and stops at the first response that leaves it, or that
// redirects to AStopAt (an identity provider inside the same Keycloak).
// Keycloak marks its session cookies Secure even over http: THTTPClient would drop them, so they
// are carried by hand.
function Navigate(const AURL: string; const AStopAt: string = ''): IHTTPResponse;
var
  LClient: THTTPClient;
  LURL: string;
  LCookies: TStringList;
  LCookie: TCookie;
  LHops: Integer;
begin
  LClient := THTTPClient.Create;
  LCookies := TStringList.Create;
  try
    LClient.HandleRedirects := False;
    LClient.AllowCookies := False;
    LURL := AURL;
    for LHops := 1 to 10 do
    begin
      LClient.CustomHeaders['Cookie'] := string.Join('; ', LCookies.ToStringArray);
      Result := LClient.Get(LURL);
      for LCookie in Result.Cookies do
        LCookies.Values[LCookie.Name] := LCookie.Value;
      if not IsRedirect(Result) then
        Exit;
      LURL := Result.HeaderValue['Location'];
      if LURL.StartsWith('/') then
        LURL := GKeycloakURL.Substring(0, GKeycloakURL.IndexOf('/', 8)) + LURL;
      if not LURL.StartsWith(GKeycloakURL) or (not AStopAt.IsEmpty and LURL.StartsWith(AStopAt)) then
        Exit;
    end;
  finally
    LCookies.Free;
    LClient.Free;
  end;
end;

function ProviderInstalled(const AProviderID: string): Boolean;
var
  LResponse: IHTTPResponse;
begin
  LResponse := AdminRequest('GET', '/admin/serverinfo');
  Result := (LResponse.StatusCode = 200) and LResponse.ContentAsString.Contains('"id":"' + AProviderID + '"');
end;

function PublicGet(const AURL: string): string;
var
  LClient: THTTPClient;
begin
  LClient := THTTPClient.Create;
  try
    Result := LClient.Get(AURL).ContentAsString(TEncoding.UTF8);
  finally
    LClient.Free;
  end;
end;

function AppAuthURL(const AConfiguredHint, ACallHint: string): string;
var
  LBuilder: IIAM4DClientConfigBuilder;
  LClient: IIAM4DClient;
begin
  LBuilder := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GKeycloakURL, CRealm, CAppClientID)
    .WithExternalCallback(CCallbackURL);
  if not AConfiguredHint.IsEmpty then
    LBuilder.WithIdentityProvider(AConfiguredHint);
  LClient := LBuilder.Build;
  LClient.InitializeAuthorizationFlow;
  Result := LClient.GenerateAuthURL('', ACallHint);
end;

// Keycloak downloads the document itself: from inside a container the published URL does not reach it,
// so the container port (8080) is tried too
function ImportMasterDiscovery(const AManager: IIAM4DIdentityProviderManager): TIAM4DConfigMap;
const
  CDiscovery = '/realms/master/.well-known/openid-configuration';
begin
  try
    Result := AManager.ImportConfig(IAM4D_IDP_PROVIDER_OIDC, GKeycloakURL + CDiscovery);
  except
    on EIAM4DException do
      Result := AManager.ImportConfig(IAM4D_IDP_PROVIDER_OIDC,
        'http://localhost:8080' + TURI.Create(GKeycloakURL).Path.TrimRight(['/']) + CDiscovery);
  end;
end;

// SAML IdP descriptor of the master realm, same fallback as ImportMasterDiscovery; AURL: the one Keycloak read
function ImportMasterSamlDescriptor(const AManager: IIAM4DIdentityProviderManager; out AURL: string): TIAM4DConfigMap;
const
  CDescriptor = '/realms/master/protocol/saml/descriptor';
begin
  try
    AURL := GKeycloakURL + CDescriptor;
    Result := AManager.ImportConfig(IAM4D_IDP_PROVIDER_SAML, AURL);
  except
    on EIAM4DException do
    begin
      AURL := 'http://localhost:8080' + TURI.Create(GKeycloakURL).Path.TrimRight(['/']) + CDescriptor;
      Result := AManager.ImportConfig(IAM4D_IDP_PROVIDER_SAML, AURL);
    end;
  end;
end;

// CIE metadata imported by Keycloak from the identity server (Internet needed); False if not reachable
function TryImportCieMetadata(const AManager: IIAM4DIdentityProviderManager; AEnvironment: TIAM4DCieEnvironment;
  out AConfig: TIAM4DConfigMap): Boolean;
begin
  try
    AConfig := AManager.ImportConfig(IAM4D_IDP_PROVIDER_CIE, TIAM4DCieIdPBuilder.MetadataURL(AEnvironment));
    Result := not AConfig.Values['idpEntityId'].IsEmpty;
  except
    on E: EIAM4DException do
    begin
      Result := False;
      // Skipped only without Internet: with it, a failed import is a failure
      if InternetReachable(TIAM4DCieIdPBuilder.MetadataURL(AEnvironment)) then
        Check('CIE metadata imported by Keycloak (' + E.ClassName + ': ' + E.Message + ')', False)
      else
        Skip('CIE real metadata', 'identity server not reachable from this machine (' + E.ClassName + ')');
    end;
  end;
end;

// Metadata of the CIE simulator of docker\docker-compose.yml, imported by Keycloak through the Docker
// network (CIE_SIMULATOR_METADATA_URL, default http://cie-simulator:8444/demo/metadata.xml); False if
// Keycloak does not reach it
function TryImportCieSimulatorMetadata(const AManager: IIAM4DIdentityProviderManager;
  out AConfig: TIAM4DConfigMap): Boolean;
var
  LURL: string;
begin
  LURL := GetEnvironmentVariable('CIE_SIMULATOR_METADATA_URL');
  if LURL.IsEmpty then
    LURL := 'http://cie-simulator:8444/demo/metadata.xml';
  try
    AConfig := AManager.ImportConfig(IAM4D_IDP_PROVIDER_CIE, LURL);
    Result := not AConfig.Values['idpEntityId'].IsEmpty;
  except
    on E: EIAM4DException do
    begin
      Skip('CIE simulator', 'not reached by Keycloak at ' + LURL + ' (' + E.ClassName + '): tests\IdentityProvider\docker\up.cmd starts it');
      Result := False;
    end;
  end;
end;

// SPID and CIE providers: need the Keycloak extensions installed
// Built-in social providers: Keycloak builds the redirect, no request leaves the server
procedure TestSocialProviders(const AManager: IIAM4DIdentityProviderManager);
var
  LRead: TIAM4DIdentityProvider;
  LLocation: string;
  LResponse: IHTTPResponse;
begin
  Check('Google and Facebook provider types installed',
    AManager.IsProviderInstalled(IAM4D_IDP_PROVIDER_GOOGLE) and AManager.IsProviderInstalled(IAM4D_IDP_PROVIDER_FACEBOOK));

  AManager.CreateIdentityProvider(TIAM4DGoogleIdPBuilder.New('google-test')
    .WithClient('google-client-id', 'google-secret')
    .WithHostedDomains(['example.com', 'example.org'])
    .WithPrompt('select_account')
    .WithTrustEmail
    .Build);
  LRead := AManager.GetIdentityProvider('google-test');
  Check('Google created', (LRead.ProviderID = IAM4D_IDP_PROVIDER_GOOGLE) and LRead.TrustEmail and
    (LRead.Config.Values['hostedDomain'] = 'example.com,example.org') and
    (LRead.Config.Values['clientSecret'] = IAM4D_IDP_SECRET_MASK));
  Check('Google mapper created',
    AManager.CreateMapper(TIAM4DGoogleIdPBuilder.AttributeMapper('google-test', 'picture', 'picture')) <> '');

  LResponse := Navigate(AppAuthURL('', 'google-test'));
  LLocation := LResponse.HeaderValue['Location'];
  Check('kc_idp_hint to Google ' + Describe(LResponse), IsRedirect(LResponse) and
    LLocation.StartsWith('https://accounts.google.com/o/oauth2/v2/auth?') and
    LLocation.Contains('client_id=google-client-id') and LLocation.Contains('scope=openid+profile+email') and
    LLocation.Contains('code_challenge_method=S256') and LLocation.Contains('prompt=select_account') and
    LLocation.Contains('hd=example.com%2Cexample.org') and
    LLocation.Contains(TNetEncoding.URL.Encode('/broker/google-test/endpoint')));

  AManager.CreateIdentityProvider(TIAM4DFacebookIdPBuilder.New('facebook-test')
    .WithClient('facebook-app-id', 'facebook-secret')
    .WithFetchedFields(['birthday'])
    .Build);
  LRead := AManager.GetIdentityProvider('facebook-test');
  Check('Facebook created', (LRead.ProviderID = IAM4D_IDP_PROVIDER_FACEBOOK) and not LRead.TrustEmail and
    (LRead.Config.Values['fetchedFields'] = 'birthday'));
  Check('Facebook mapper created',
    AManager.CreateMapper(TIAM4DFacebookIdPBuilder.AttributeMapper('facebook-test', 'birthday', 'birthday')) <> '');

  LResponse := Navigate(AppAuthURL('', 'facebook-test'));
  LLocation := LResponse.HeaderValue['Location'];
  Check('kc_idp_hint to Facebook ' + Describe(LResponse), IsRedirect(LResponse) and
    LLocation.StartsWith('https://graph.facebook.com/oauth/authorize?') and
    LLocation.Contains('client_id=facebook-app-id') and LLocation.Contains('scope=email+public_profile') and
    LLocation.Contains(TNetEncoding.URL.Encode('/broker/facebook-test/endpoint')));

  AManager.DeleteIdentityProvider('google-test');
  AManager.DeleteIdentityProvider('facebook-test');
end;

// Microsoft, LinkedIn, GitHub and GitLab: Keycloak builds the redirect (LinkedIn: from its discovery
// document, downloaded by Keycloak at the first use)
procedure TestMoreSocialProviders(const AManager: IIAM4DIdentityProviderManager);
var
  LRead: TIAM4DIdentityProvider;
  LLocation: string;
  LResponse: IHTTPResponse;
  LTypes: TArray<TIAM4DIdentityProviderMapperType>;
  LType: TIAM4DIdentityProviderMapperType;
  LHasGitLabImporter: Boolean;
begin
  Check('Microsoft, LinkedIn, GitHub and GitLab provider types installed',
    AManager.IsProviderInstalled(IAM4D_IDP_PROVIDER_MICROSOFT) and AManager.IsProviderInstalled(IAM4D_IDP_PROVIDER_LINKEDIN) and
    AManager.IsProviderInstalled(IAM4D_IDP_PROVIDER_GITHUB) and AManager.IsProviderInstalled(IAM4D_IDP_PROVIDER_GITLAB));

  AManager.CreateIdentityProvider(TIAM4DMicrosoftIdPBuilder.New('microsoft-test')
    .WithClient('ms-client-id', 'ms-secret')
    .WithPrompt('select_account')
    .Build);
  LRead := AManager.GetIdentityProvider('microsoft-test');
  Check('Microsoft created', (LRead.ProviderID = IAM4D_IDP_PROVIDER_MICROSOFT) and not LRead.TrustEmail and
    (LRead.Config.Values['tenantId'] = 'consumers') and (LRead.Config.Values['defaultScope'] = 'User.Read') and
    LRead.Config.GetBool('pkceEnabled') and (LRead.Config.Values['clientSecret'] = IAM4D_IDP_SECRET_MASK));
  Check('Microsoft mapper created',
    AManager.CreateMapper(TIAM4DMicrosoftIdPBuilder.AttributeMapper('microsoft-test', 'jobTitle', 'jobTitle')) <> '');
  LResponse := Navigate(AppAuthURL('', 'microsoft-test'));
  LLocation := LResponse.HeaderValue['Location'];
  Check('kc_idp_hint to Microsoft ' + Describe(LResponse), IsRedirect(LResponse) and
    LLocation.StartsWith('https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?') and
    LLocation.Contains('client_id=ms-client-id') and LLocation.Contains('scope=User.Read') and
    LLocation.Contains('code_challenge_method=S256') and LLocation.Contains('prompt=select_account') and
    LLocation.Contains(TNetEncoding.URL.Encode('/broker/microsoft-test/endpoint')));

  AManager.CreateIdentityProvider(TIAM4DLinkedInIdPBuilder.New('linkedin-test')
    .WithClient('li-client-id', 'li-secret')
    .WithTrustEmail
    .Build);
  LRead := AManager.GetIdentityProvider('linkedin-test');
  Check('LinkedIn created', (LRead.ProviderID = IAM4D_IDP_PROVIDER_LINKEDIN) and LRead.TrustEmail and
    (LRead.Config.Values['defaultScope'] = 'openid profile email'));
  Check('LinkedIn mapper created',
    AManager.CreateMapper(TIAM4DLinkedInIdPBuilder.AttributeMapper('linkedin-test', 'picture', 'picture')) <> '');
  LResponse := Navigate(AppAuthURL('', 'linkedin-test'));
  LLocation := LResponse.HeaderValue['Location'];
  if IsRedirect(LResponse) then
    Check('kc_idp_hint to LinkedIn ' + Describe(LResponse),
      LLocation.StartsWith('https://www.linkedin.com/oauth/v2/authorization?') and
      LLocation.Contains('client_id=li-client-id') and LLocation.Contains('scope=openid+profile+email') and
      not LLocation.Contains('code_challenge') and LLocation.Contains(TNetEncoding.URL.Encode('/broker/linkedin-test/endpoint')))
  // Keycloak reads the LinkedIn discovery document from the Internet: skipped only without it
  else if InternetReachable('https://www.linkedin.com/oauth/.well-known/openid-configuration') then
    Check('kc_idp_hint to LinkedIn: Keycloak error with the Internet reachable ' + Describe(LResponse), False)
  else
    Skip('kc_idp_hint to LinkedIn', 'linkedin.com not reachable from this machine (' + Describe(LResponse) + ')');

  AManager.CreateIdentityProvider(TIAM4DGitHubIdPBuilder.New('github-test')
    .WithClient('gh-client-id', 'gh-secret')
    .Build);
  LRead := AManager.GetIdentityProvider('github-test');
  Check('GitHub created', (LRead.ProviderID = IAM4D_IDP_PROVIDER_GITHUB) and not LRead.TrustEmail and
    (LRead.Config.Values['defaultScope'] = 'user:email') and LRead.Config.GetBool('pkceEnabled'));
  Check('GitHub mapper created',
    AManager.CreateMapper(TIAM4DGitHubIdPBuilder.AttributeMapper('github-test', 'company', 'company')) <> '');
  LResponse := Navigate(AppAuthURL('', 'github-test'));
  LLocation := LResponse.HeaderValue['Location'];
  Check('kc_idp_hint to GitHub ' + Describe(LResponse), IsRedirect(LResponse) and
    LLocation.StartsWith('https://github.com/login/oauth/authorize?') and
    LLocation.Contains('client_id=gh-client-id') and LLocation.Contains('scope=user%3Aemail') and
    LLocation.Contains('code_challenge_method=S256') and
    LLocation.Contains(TNetEncoding.URL.Encode('/broker/github-test/endpoint')));

  // The Enterprise URLs change the token URL: Keycloak 26.8.1+ rejects the mask (the secret must
  // be sent again), earlier versions keep the stored secret
  try
    AManager.SaveIdentityProvider(TIAM4DGitHubIdPBuilder.New('github-test')
      .WithClient('gh-client-id', IAM4D_IDP_SECRET_MASK)
      .WithEnterprise('https://github.example.com', 'https://github.example.com/api/v3')
      .Build);
    Writeln('  Mask accepted with a new token URL (Keycloak before 26.8.1)');
  except
    on E: EIAM4DHTTPClientErrorException do
      Check('mask with a new token URL -> 400 secret to re-enter',
        (E.StatusCode = 400) and E.ResponseBody.Contains('must be re-entered'));
  end;
  AManager.SaveIdentityProvider(TIAM4DGitHubIdPBuilder.New('github-test')
    .WithClient('gh-client-id', 'gh-secret')
    .WithEnterprise('https://github.example.com', 'https://github.example.com/api/v3')
    .Build);
  LRead := AManager.GetIdentityProvider('github-test');
  Check('GitHub Enterprise saved', (LRead.Config.Values['baseUrl'] = 'https://github.example.com') and
    (LRead.Config.Values['apiUrl'] = 'https://github.example.com/api/v3'));
  LResponse := Navigate(AppAuthURL('', 'github-test'));
  LLocation := LResponse.HeaderValue['Location'];
  Check('kc_idp_hint to GitHub Enterprise ' + Describe(LResponse), IsRedirect(LResponse) and
    LLocation.StartsWith('https://github.example.com/login/oauth/authorize?'));

  AManager.CreateIdentityProvider(TIAM4DGitLabIdPBuilder.New('gitlab-test')
    .WithClient('gl-client-id', 'gl-secret')
    .WithTrustEmail
    .Build);
  LRead := AManager.GetIdentityProvider('gitlab-test');
  Check('GitLab created', (LRead.ProviderID = IAM4D_IDP_PROVIDER_GITLAB) and LRead.TrustEmail and
    LRead.Config.GetBool('validateSignature') and LRead.Config.GetBool('useJwksUrl') and
    (LRead.Config.Values['issuer'] = 'https://gitlab.com') and
    (LRead.Config.Values['jwksUrl'] = 'https://gitlab.com/oauth/discovery/keys'));
  // GitLab has no attribute importer: only the username template and the hardcoded mappers
  LTypes := AManager.GetMapperTypes('gitlab-test');
  LHasGitLabImporter := False;
  for LType in LTypes do
    if LType.ID.StartsWith('gitlab') then
      LHasGitLabImporter := True;
  Check('GitLab mapper types without attribute importer', (Length(LTypes) > 0) and not LHasGitLabImporter);
  LResponse := Navigate(AppAuthURL('', 'gitlab-test'));
  LLocation := LResponse.HeaderValue['Location'];
  Check('kc_idp_hint to GitLab ' + Describe(LResponse), IsRedirect(LResponse) and
    LLocation.StartsWith('https://gitlab.com/oauth/authorize?') and
    LLocation.Contains('client_id=gl-client-id') and LLocation.Contains('scope=openid+read_user+email') and
    LLocation.Contains('code_challenge_method=S256') and LLocation.Contains('nonce=') and
    LLocation.Contains(TNetEncoding.URL.Encode('/broker/gitlab-test/endpoint')));

  AManager.DeleteIdentityProvider('microsoft-test');
  AManager.DeleteIdentityProvider('linkedin-test');
  AManager.DeleteIdentityProvider('github-test');
  AManager.DeleteIdentityProvider('gitlab-test');
end;

// Generic OIDC and SAML providers bound to the master realm of the same Keycloak: only the redirect is
// checked, the login is not completed
procedure TestGenericProviders(const AManager: IIAM4DIdentityProviderManager);
var
  LImported: TIAM4DConfigMap;
  LRead: TIAM4DIdentityProvider;
  LResponse: IHTTPResponse;
  LLocation, LPage, LRequest, LMetadataURL, LExported: string;
  LMatch: TMatch;
begin
  // OIDC from the discovery document of the master realm
  LImported := ImportMasterDiscovery(AManager);
  AManager.CreateIdentityProvider(TIAM4DOidcIdPBuilder.New('oidc-test')
    .WithImportedConfig(LImported)
    .WithClient('broker-client', 'broker-secret')
    .WithClientAuthMethod(ocaClientSecretBasic)
    .WithPrompt('login')
    .WithTrustEmail
    .Build);
  LRead := AManager.GetIdentityProvider('oidc-test');
  Check('OIDC created', (LRead.ProviderID = IAM4D_IDP_PROVIDER_OIDC) and LRead.TrustEmail and
    (LRead.Config.Values['issuer'] = LImported.Values['issuer']) and
    (LRead.Config.Values['jwksUrl'] = LImported.Values['jwksUrl']) and
    LRead.Config.GetBool('validateSignature') and LRead.Config.GetBool('useJwksUrl') and
    LRead.Config.GetBool('pkceEnabled') and (LRead.Config.Values['pkceMethod'] = 'S256') and
    (LRead.Config.Values['clientAuthMethod'] = 'client_secret_basic') and
    (LRead.Config.Values['clientSecret'] = IAM4D_IDP_SECRET_MASK));
  Check('OIDC imported issuer is the master realm', LImported.Values['issuer'] = GKeycloakURL + '/realms/master');

  LResponse := Navigate(AppAuthURL('', 'oidc-test'), LImported.Values['authorizationUrl']);
  LLocation := LResponse.HeaderValue['Location'];
  Check('kc_idp_hint to the OIDC provider ' + Describe(LResponse), IsRedirect(LResponse) and
    LLocation.StartsWith(LImported.Values['authorizationUrl'] + '?') and
    LLocation.Contains('client_id=broker-client') and LLocation.Contains('scope=openid+profile+email') and
    LLocation.Contains('code_challenge_method=S256') and LLocation.Contains('prompt=login') and
    LLocation.Contains(TNetEncoding.URL.Encode('/broker/oidc-test/endpoint')));

  // private_key_jwt: no secret, Keycloak signs with a realm key
  AManager.SaveIdentityProvider(TIAM4DOidcIdPBuilder.New('oidc-test')
    .WithImportedConfig(LImported)
    .WithClient('broker-client', '')
    .WithClientAuthMethod(ocaPrivateKeyJwt, 'PS256')
    .Build);
  LRead := AManager.GetIdentityProvider('oidc-test');
  Check('OIDC private_key_jwt saved', (LRead.Config.Values['clientAuthMethod'] = 'private_key_jwt') and
    (LRead.Config.Values['clientAssertionSigningAlg'] = 'PS256') and not LRead.TrustEmail);
  AManager.DeleteIdentityProvider('oidc-test');

  // OAuth 2.0 with the endpoints of the master realm (no discovery: set by hand)
  AManager.CreateIdentityProvider(TIAM4DOAuth2IdPBuilder.New('oauth2-test')
    .WithEndpoints(LImported.Values['authorizationUrl'], LImported.Values['tokenUrl'], LImported.Values['userInfoUrl'])
    .WithClient('broker-client', 'broker-secret')
    .WithUserProfileClaims('sub', 'preferred_username', 'email')
    .WithNameClaims('', 'given_name', 'family_name')
    .WithScopes(['profile', 'email'])
    .Build);
  LRead := AManager.GetIdentityProvider('oauth2-test');
  Check('OAuth2 created', (LRead.ProviderID = IAM4D_IDP_PROVIDER_OAUTH2) and not LRead.TrustEmail and
    (LRead.Config.Values['userInfoUrl'] = LImported.Values['userInfoUrl']) and
    (LRead.Config.Values['userIDClaim'] = 'sub') and (LRead.Config.Values['givenNameClaim'] = 'given_name') and
    LRead.Config.GetBool('pkceEnabled') and (LRead.Config.Values['pkceMethod'] = 'S256') and
    not LRead.Config.Contains('validateSignature') and (LRead.Config.Values['clientSecret'] = IAM4D_IDP_SECRET_MASK));
  LResponse := Navigate(AppAuthURL('', 'oauth2-test'), LImported.Values['authorizationUrl']);
  LLocation := LResponse.HeaderValue['Location'];
  Check('kc_idp_hint to the OAuth2 provider ' + Describe(LResponse), IsRedirect(LResponse) and
    LLocation.StartsWith(LImported.Values['authorizationUrl'] + '?') and
    LLocation.Contains('client_id=broker-client') and LLocation.Contains('scope=profile+email') and
    LLocation.Contains('code_challenge_method=S256') and
    LLocation.Contains(TNetEncoding.URL.Encode('/broker/oauth2-test/endpoint')));
  // Keycloak refuses an OAuth 2.0 provider without user info URL: the builder does it first
  Check('OAuth2 without user info URL refused by the builder', Raises(
    procedure
    begin
      TIAM4DOAuth2IdPBuilder.New('oauth2-test').WithEndpoints(LImported.Values['authorizationUrl'],
        LImported.Values['tokenUrl'], '').WithClient('c', 's').Build;
    end, EIAM4DInvalidConfigurationException));
  AManager.DeleteIdentityProvider('oauth2-test');

  // SAML from the IdP descriptor of the master realm
  LImported := ImportMasterSamlDescriptor(AManager, LMetadataURL);
  Check('SAML descriptor imported', (LImported.Values['idpEntityId'] = GKeycloakURL + '/realms/master') and
    not LImported.Values['signingCertificate'].IsEmpty);
  AManager.CreateIdentityProvider(TIAM4DSamlIdPBuilder.New('saml-generic')
    .WithImportedConfig(LImported)
    .WithDisplayName('Corporate SAML')
    .Build);
  LRead := AManager.GetIdentityProvider('saml-generic');
  Check('SAML created', (LRead.ProviderID = IAM4D_IDP_PROVIDER_SAML) and
    LRead.Config.GetBool('wantAuthnRequestsSigned') and LRead.Config.GetBool('wantAssertionsSigned') and
    LRead.Config.GetBool('validateSignature') and LRead.Config.GetBool('postBindingAuthnRequest') and
    (LRead.Config.Values['principalType'] = 'SUBJECT') and
    (LRead.Config.Values['nameIDPolicyFormat'] = IAM4D_SAML_NAMEID_PERSISTENT) and
    (LRead.Config.Values['signingCertificate'] = LImported.Values['signingCertificate']));
  Check('SAML mapper created', AManager.CreateMapper(TIAM4DSamlIdPBuilder.AttributeMapper('saml-generic',
    'email', 'email')) <> '');
  LExported := AManager.ExportServiceProviderMetadata('saml-generic');
  Check('SAML SP metadata: signed requests, signed assertions', LExported.Contains('AuthnRequestsSigned="true"') and
    LExported.Contains('WantAssertionsSigned="true"') and LExported.Contains('/broker/saml-generic/endpoint'));

  // POST binding: Keycloak answers with a form posting a signed AuthnRequest to the master realm
  LResponse := Navigate(AppAuthURL('', 'saml-generic'));
  LPage := LResponse.ContentAsString(TEncoding.UTF8);
  LMatch := TRegEx.Match(LPage, 'name="SAMLRequest"\s+value="([^"]+)"', [roIgnoreCase]);
  if LMatch.Success then
    LRequest := TNetEncoding.Base64.Decode(LMatch.Groups[1].Value)
  else
    LRequest := '';
  Check('kc_idp_hint to the SAML provider ' + Describe(LResponse), (LResponse.StatusCode = 200) and
    LPage.Contains(LImported.Values['singleSignOnServiceUrl']) and LMatch.Success);
  Check('SAML AuthnRequest signed, to the imported endpoint', LRequest.Contains('AuthnRequest') and
    LRequest.Contains('SignatureValue') and
    LRequest.Contains('Destination="' + LImported.Values['singleSignOnServiceUrl'] + '"') and
    LRequest.Contains('/broker/saml-generic/endpoint') and LRequest.Contains(IAM4D_SAML_NAMEID_PERSISTENT));
  AManager.DeleteIdentityProvider('saml-generic');

  // Signing keys read by Keycloak from the metadata URL: no certificate in the config
  AManager.CreateIdentityProvider(TIAM4DSamlIdPBuilder.New('saml-metadata')
    .WithIdentityProviderEndpoints(LImported.Values['idpEntityId'], LImported.Values['singleSignOnServiceUrl'], '')
    .WithMetadataURL(LMetadataURL)
    .Build);
  LRead := AManager.GetIdentityProvider('saml-metadata');
  Check('SAML with metadata URL created', LRead.Config.GetBool('useMetadataDescriptorUrl') and
    (LRead.Config.Values['metadataDescriptorUrl'] = LMetadataURL) and LRead.Config.GetBool('validateSignature'));
  AManager.DeleteIdentityProvider('saml-metadata');
end;

procedure TestItalianProviders(const AManager: IIAM4DIdentityProviderManager);
var
  LSpid, LCie: TIAM4DIdentityProvider;
  LMapper: TIAM4DIdentityProviderMapper;
  LResponse: IHTTPResponse;
  LPage, LMetadata, LExported: string;
  LImported: TIAM4DConfigMap;
begin
  Check(Format('provider type check agrees with the server info (SPID %s/%s, CIE %s/%s)',
    [BoolToStr(AManager.IsProviderInstalled(IAM4D_IDP_PROVIDER_SPID), True),
     BoolToStr(ProviderInstalled(IAM4D_IDP_PROVIDER_SPID), True),
     BoolToStr(AManager.IsProviderInstalled(IAM4D_IDP_PROVIDER_CIE), True),
     BoolToStr(ProviderInstalled(IAM4D_IDP_PROVIDER_CIE), True)]),
    (AManager.IsProviderInstalled(IAM4D_IDP_PROVIDER_SPID) = ProviderInstalled(IAM4D_IDP_PROVIDER_SPID)) and
    (AManager.IsProviderInstalled(IAM4D_IDP_PROVIDER_CIE) = ProviderInstalled(IAM4D_IDP_PROVIDER_CIE)));
  if not AManager.IsProviderInstalled(IAM4D_IDP_PROVIDER_SPID) then
    Skip('SPID providers', 'extension spid-saml not installed in Keycloak')
  else
  begin
    // Poste endpoints by hand: no network needed
    LSpid := TIAM4DSpidIdPBuilder.New('spid-poste')
      .WithDisplayName('Poste ID')
      .WithIdentityProviderEndpoints('https://posteid.poste.it', 'https://posteid.poste.it/jod-fs/ssoservicepost',
        CTestCertificate)
      .WithAttributeConsumingService(1, 'Servizi online')
      .WithOrganization('Comune di Esempio', 'Comune di Esempio', 'https://www.comune.esempio.it')
      .WithPublicServiceProvider('c_x000', 'protocollo@comune.esempio.it')
      .WithHideOnLogin
      .Build;
    AManager.CreateIdentityProvider(LSpid);
    Check('SPID created', AManager.GetIdentityProvider('spid-poste').ProviderID = IAM4D_IDP_PROVIDER_SPID);

    LMapper := TIAM4DSpidIdPBuilder.AttributeMapper('spid-poste', 'fiscalNumber', 'fiscalNumber');
    Check('SPID mapper created', AManager.CreateMapper(LMapper) <> '');

    LMetadata := PublicGet(TIAM4DSpidIdPBuilder.ServiceProviderMetadataURL(GKeycloakURL, CRealm));
    Check('SPID SP metadata', LMetadata.Contains('EntityDescriptor') and LMetadata.Contains('c_x000') and
      LMetadata.Contains('/broker/spid-poste/endpoint'));
    Check('SPID SP metadata service name', LMetadata.Contains('xml:lang="it">Servizi online</'));
    Check('SPID SP metadata contacts', LMetadata.Contains('contactType="other"') and LMetadata.Contains('spid:IPACode'));
    // The per-provider export is Keycloak's generic SAML descriptor, without the contacts AgID requires
    LExported := AManager.ExportServiceProviderMetadata('spid-poste');
    Check('SPID export: generic descriptor of the provider, no contacts', LExported.Contains('EntityDescriptor') and
      LExported.Contains('/broker/spid-poste/endpoint') and not LExported.Contains('ContactPerson'));

    // POST binding: Keycloak answers with a form posting the AuthnRequest to the SPID provider
    LResponse := Navigate(AppAuthURL('', 'spid-poste'));
    LPage := LResponse.ContentAsString(TEncoding.UTF8);
    Check('kc_idp_hint to SPID ' + Describe(LResponse), (LResponse.StatusCode = 200) and
      LPage.Contains('https://posteid.poste.it/jod-fs/ssoservicepost') and LPage.Contains('SAMLRequest'));

    // Private service provider: billing contact in the SP metadata
    AManager.SaveIdentityProvider(
      TIAM4DSpidIdPBuilder.New('spid-poste')
        .WithDisplayName('Poste ID')
        .WithIdentityProviderEndpoints('https://posteid.poste.it', 'https://posteid.poste.it/jod-fs/ssoservicepost',
          CTestCertificate)
        .WithAttributeConsumingService(1, 'Servizi online')
        .WithOrganization('Esempio S.r.l.', 'Esempio', 'https://www.esempio.it')
        .WithPrivateServiceProvider('IT12345678901', '12345678901', 'Esempio S.r.l.', 'info@esempio.it')
        .WithBillingContact('Esempio S.r.l.', 'fatture@esempio.it', '+39061234567', 'Esempio S.r.l.', 'Via Roma',
          '1', '00100', 'Roma', 'RM')
        .WithHideOnLogin
        .Build);
    LMetadata := PublicGet(TIAM4DSpidIdPBuilder.ServiceProviderMetadataURL(GKeycloakURL, CRealm));
    Check('SPID SP metadata billing contact', LMetadata.Contains('contactType="billing"') and
      LMetadata.Contains('fpa:CessionarioCommittente') and LMetadata.Contains('>12345678901</fpa:IdCodice>') and
      LMetadata.Contains('>IT</fpa:IdPaese>') and LMetadata.Contains('>Esempio S.r.l.</fpa:Denominazione>') and
      LMetadata.Contains('>00100</fpa:CAP>') and LMetadata.Contains('>fatture@esempio.it</md:EmailAddress>'));
    AManager.DeleteIdentityProvider('spid-poste');
  end;

  if not AManager.IsProviderInstalled(IAM4D_IDP_PROVIDER_CIE) then
    Skip('CIE providers', 'extension cieid-saml not installed in Keycloak')
  else
  begin
    // Real pre-production metadata when reachable: the builder accepts it only for that identity server
    if TryImportCieMetadata(AManager, cePreProduction, LImported) then
    begin
      Check('CIE metadata import: pre-production entity and certificate', (LImported.Values['idpEntityId'] =
        'https://preproduzione.idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO') and
        not LImported.Values['signingCertificate'].IsEmpty);
      Check('CIE imported pre-production metadata rejected for production', Raises(
        procedure
        begin
          TIAM4DCieIdPBuilder.New.WithEnvironment(ceProduction).WithImportedConfig(LImported)
            .WithAttributeConsumingService(1, 'Servizi online').Build;
        end, EIAM4DInvalidConfigurationException));
    end
    else
      LImported := CieMetadata(cePreProduction);
    LCie := TIAM4DCieIdPBuilder.New
      .WithEnvironment(cePreProduction)
      .WithImportedConfig(LImported)
      .WithPublicServiceProvider('Comune di Esempio', 'c_x000', 'L6', 'protocollo@comune.esempio.it')
      .WithOrganization('Comune di Esempio', 'Comune di Esempio', 'https://www.comune.esempio.it')
      .WithAttributeConsumingService(1, 'Servizi online')
      .Build;
    AManager.CreateIdentityProvider(LCie);
    Check('CIE created', AManager.GetIdentityProvider('cie').ProviderID = IAM4D_IDP_PROVIDER_CIE);

    LMapper := TIAM4DCieIdPBuilder.AttributeMapper('cie', 'fiscalNumber', 'fiscalNumber');
    Check('CIE mapper created', AManager.CreateMapper(LMapper) <> '');

    LMetadata := PublicGet(TIAM4DCieIdPBuilder.ServiceProviderMetadataURL(GKeycloakURL, CRealm));
    Check('CIE SP metadata', LMetadata.Contains('EntityDescriptor') and LMetadata.Contains('/broker/cie/endpoint'));
    // The identity server sends only the requested attributes: fiscalNumber is the principal
    Check('CIE SP metadata requests the mapped attribute', LMetadata.Contains('RequestedAttribute Name="fiscalNumber"'));
    Check('CIE SP metadata service name', LMetadata.Contains('>Servizi online</') and not LMetadata.Contains('|Servizi'));
    Check('CIE SP metadata contacts', LMetadata.Contains('ContactPerson') and LMetadata.Contains('c_x000'));
    LExported := AManager.ExportServiceProviderMetadata('cie');
    Check('CIE export: generic descriptor of the provider, no contacts', LExported.Contains('EntityDescriptor') and
      LExported.Contains('/broker/cie/endpoint') and not LExported.Contains('ContactPerson'));

    LResponse := Navigate(AppAuthURL('cie', ''));
    LPage := LResponse.ContentAsString(TEncoding.UTF8);
    Check('kc_idp_hint to CIE ' + Describe(LResponse), (LResponse.StatusCode = 200) and
      LPage.Contains('https://preproduzione.idserver.servizicie.interno.gov.it/idp/profile/SAML2/POST/SSO'));
    AManager.DeleteIdentityProvider('cie');

    // Local test identity server: no environment, the imported metadata of the simulator decides
    if TryImportCieSimulatorMetadata(AManager, LImported) then
    begin
      LCie := TIAM4DCieIdPBuilder.New('cie-local')
        .WithImportedConfig(LImported)
        .WithAttributeConsumingService(1, 'Servizi online')
        .Build;
      AManager.CreateIdentityProvider(LCie);
      LResponse := Navigate(AppAuthURL('cie-local', ''));
      LPage := LResponse.ContentAsString(TEncoding.UTF8);
      Check('kc_idp_hint to the CIE simulator ' + Describe(LResponse), (LResponse.StatusCode = 200) and
        LPage.Contains(LImported.Values['singleSignOnServiceUrl']) and LPage.Contains('SAMLRequest'));
      AManager.DeleteIdentityProvider('cie-local');
    end;
  end;
end;

// User manager on names that need encoding (role with a space in the path, email with '+' in the query)
// and on an operation the service account may not perform
procedure TestUserManagerIntegration(const AAdminClient: IIAM4DClient);
var
  LUsers, LAdminUsers: IIAM4DUserManager;
  LCriteria: TIAM4DUserSearchCriteria;
  LUserID: string;
begin
  LUsers := TIAM4DKeycloakUserManager.Create(AAdminClient);
  Check('user by username', Safely(
    function: Boolean
    begin
      LUserID := LUsers.GetUserByUsername(CUsername).ID;
      Result := not LUserID.IsEmpty;
    end));
  Check('realm role with a space', Safely(
    function: Boolean
    begin
      Result := LUsers.GetRoleByName(CRoleWithSpace).Name = CRoleWithSpace;
    end));
  Check('TryGet realm role with a space', Safely(
    function: Boolean
    begin
      Result := LUsers.TryGetRoleByName(CRoleWithSpace).Found;
    end));
  Check('users with a role with a space', Safely(
    function: Boolean
    var
      LFound: TArray<TIAM4DUser>;
    begin
      LFound := LUsers.GetUsersWithRole(CRoleWithSpace);
      Result := (Length(LFound) = 1) and (LFound[0].Username = CUsername);
    end));
  Check('HasRole with a space', Safely(
    function: Boolean
    begin
      Result := LUsers.HasRole(LUserID, CRoleWithSpace);
    end));
  Check('user by email with "+"', Safely(
    function: Boolean
    begin
      Result := LUsers.GetUserByEmail(CUserEmail).ID = LUserID;
    end));
  Check('TryGet user by email with "+"', Safely(
    function: Boolean
    begin
      Result := LUsers.TryGetUserByEmail(CUserEmail).Found;
    end));
  LCriteria := TIAM4DUserSearchCriteria.Create;
  LCriteria.FirstName := CUserFirstName;
  Check('search by first name with a space', Safely(
    function: Boolean
    var
      LFound: TArray<TIAM4DUser>;
    begin
      LFound := LUsers.SearchUsers(LCriteria);
      Result := (Length(LFound) = 1) and (LFound[0].ID = LUserID);
    end));
  Check('user not locked', Safely(
    function: Boolean
    begin
      Result := not LUsers.IsUserLocked(LUserID);
    end));
  // Missing names: typed 404 exceptions, raised before any write
  CheckNotFound('assign a missing realm role',
    procedure
    begin
      LUsers.AssignRoleByName(LUserID, 'missing role');
    end, EIAM4DRoleNotFoundException, ecRoleNotFound);
  CheckNotFound('assign a missing client role',
    procedure
    begin
      LUsers.AssignClientRoleByClientID(LUserID, CAppClientID, 'missing role');
    end, EIAM4DRoleNotFoundException, ecRoleNotFound);
  CheckNotFound('roles of a missing client',
    procedure
    begin
      LUsers.GetClientRolesByClientID('missing-client');
    end, EIAM4DHTTPNotFoundException);
  CheckNotFound('add to a missing group',
    procedure
    begin
      LUsers.AddUserToGroupByPath(LUserID, '/missing group');
    end, EIAM4DGroupNotFoundException, ecGroupNotFound);

  // Links need manage-users: master admin token (static token provider; admin-cli tokens last one minute)
  TryGetAdminToken(GAdminUser, GAdminPassword);
  LAdminUsers := TIAM4DKeycloakUserManager.Create(GAdminToken, GKeycloakURL, CRealm);
  Check('link federated identity', Safely(
    function: Boolean
    var
      LLinks: TArray<TIAM4DFederatedIdentity>;
    begin
      LAdminUsers.LinkFederatedIdentity(LUserID,
        TIAM4DFederatedIdentity.Create('entra-test', 'entra-object-id', 'mario.rossi@contoso.com'));
      LLinks := LUsers.GetUserFederatedIdentities(LUserID);
      Result := (Length(LLinks) = 1) and (LLinks[0].IdentityProvider = 'entra-test') and
        (LLinks[0].UserID = 'entra-object-id') and (LLinks[0].UserName = 'mario.rossi@contoso.com') and
        LUsers.IsUserFederated(LUserID);
    end));
  CheckHTTPError('link twice (409)',
    procedure
    begin
      LAdminUsers.LinkFederatedIdentity(LUserID, TIAM4DFederatedIdentity.Create('entra-test', 'other', 'other'));
    end, EIAM4DHTTPConflictException, 409, 'already linked');
  CheckHTTPError('link without manage-users (403)',
    procedure
    begin
      LUsers.LinkFederatedIdentity(LUserID, TIAM4DFederatedIdentity.Create('saml-test', 'x', 'x'));
    end, EIAM4DInsufficientPermissionsException, 403, '');
  Check('unlink federated identity', Safely(
    function: Boolean
    begin
      LAdminUsers.UnlinkFederatedIdentity(LUserID, 'entra-test');
      Result := not LUsers.IsUserFederated(LUserID);
    end));
  CheckHTTPError('unlink a missing link (404)',
    procedure
    begin
      LAdminUsers.UnlinkFederatedIdentity(LUserID, 'entra-test');
    end, EIAM4DHTTPNotFoundException, 404, '');
  // Nested groups (Keycloak 23+ lists only the top level)
  Check('GetGroupByPath of a subgroup with a space', Safely(
    function: Boolean
    var
      LGroup: TIAM4DGroup;
    begin
      LGroup := LAdminUsers.GetGroupByPath('/Sales/Italia Nord');
      Result := (LGroup.Name = 'Italia Nord') and (LGroup.Path = '/Sales/Italia Nord') and not LGroup.ID.IsEmpty;
    end));
  Check('TryGetGroupByPath: path of another case not found', Safely(
    function: Boolean
    begin
      Result := not LAdminUsers.TryGetGroupByPath('/sales/italia nord').Found and
        not LAdminUsers.TryGetGroupByPath('/Sales/Missing').Found;
    end));
  Check('AddUserToGroupByPath, IsMemberOfGroup, GetUsersInGroupByPath, RemoveUserFromGroupByPath on a subgroup', Safely(
    function: Boolean
    var
      LMembers: TArray<TIAM4DUser>;
    begin
      LAdminUsers.AddUserToGroupByPath(LUserID, '/Sales/Italia Nord');
      LMembers := LAdminUsers.GetUsersInGroupByPath('/Sales/Italia Nord');
      Result := LAdminUsers.IsMemberOfGroup(LUserID, '/Sales/Italia Nord') and (Length(LMembers) = 1) and
        (LMembers[0].ID = LUserID);
      LAdminUsers.RemoveUserFromGroupByPath(LUserID, '/Sales/Italia Nord');
      Result := Result and not LAdminUsers.IsMemberOfGroup(LUserID, '/Sales/Italia Nord');
    end));
  Check('GetGroups: the group and its 12 subgroups', Safely(
    function: Boolean
    var
      LGroups: TArray<TIAM4DGroup>;
      LGroup: TIAM4DGroup;
      LCount: Integer;
    begin
      LGroups := LAdminUsers.GetGroups;
      LCount := 0;
      for LGroup in LGroups do
        if LGroup.Path.StartsWith('/Sales/') then
          Inc(LCount);
      Result := (LCount = 12) and (Length(LGroups) = 13);
    end));

  // Email as username; UpdateUser replaces the profile (an empty last name clears it)
  Check('username with "@" and "+": created (createdTimestamp in ms), found, last name cleared by UpdateUser, '
    + 'deleted', Safely(
    function: Boolean
    var
      LID: string;
      LUser: TIAM4DUser;
    begin
      LUser := TIAM4DUser.Create('anna+iam4d@example.com', 'anna+iam4d@example.com');
      LUser.FirstName := 'Anna';
      LUser.LastName := 'Bianchi';
      LUser.Enabled := True;
      LID := LAdminUsers.CreateUser(LUser);
      try
        LUser := LAdminUsers.GetUserByUsername('anna+iam4d@example.com');
        Result := (LUser.ID = LID) and (LUser.LastName = 'Bianchi') and
          (Abs(LUser.CreatedTimestamp - DateTimeToUnix(TDateTime.NowUTC) * MSecsPerSec) < 600000);
        LUser.LastName := '';
        LAdminUsers.UpdateUser(LUser);
        LUser := LAdminUsers.GetUser(LID);
        Result := Result and (LUser.LastName = '') and (LUser.FirstName = 'Anna') and LUser.Enabled;
      finally
        LAdminUsers.DeleteUser(LID);
      end;
    end));

  // The service account can read users, not create them
  CheckHTTPError('create user without manage-users (403)',
    procedure
    begin
      LUsers.CreateUser(TIAM4DUser.Create('not.allowed', 'not.allowed@example.com'));
    end, EIAM4DInsufficientPermissionsException, 403, '');
end;

function UserSessionCount(const AUserID: string): Integer;
var
  LResponse: IHTTPResponse;
  LArray: TJSONValue;
begin
  LResponse := AdminRequest('GET', '/admin/realms/' + CRealm + '/users/' + AUserID + '/sessions');
  EnsureStatus(LResponse, 'Get user sessions');
  LArray := TJSONObject.ParseJSONValue(LResponse.ContentAsString);
  try
    Result := (LArray as TJSONArray).Count;
  finally
    LArray.Free;
  end;
end;

/// <summary>Status of the userinfo endpoint of the realm for AAccessToken</summary>
function UserInfoStatus(const AAccessToken: string): Integer;
var
  LHTTP: THTTPClient;
begin
  LHTTP := THTTPClient.Create;
  try
    Result := LHTTP.Get(GKeycloakURL + '/realms/' + CRealm + '/protocol/openid-connect/userinfo', nil,
      [TNetHeader.Create('Authorization', 'Bearer ' + AAccessToken)]).StatusCode;
  finally
    LHTTP.Free;
  end;
end;

function PasswordLoginClass(const AClient: IIAM4DClient; const AUser, APassword: string): TClass;
begin
  Result := nil;
  try
    AClient.AuthenticatePassword(AUser, APassword);
  except
    on E: Exception do
      Result := E.ClassType;
  end;
end;

// Resource Owner Password Credentials against Keycloak: login, refresh, back-channel logout (no
// session left), Keycloak errors, and the required action cleared by an admin password reset
procedure TestPasswordGrantIntegration;
var
  LClient: IIAM4DClient;
  LAdminUsers: IIAM4DUserManager;
  LUser: TIAM4DUser;
  LUserID, LToken: string;
  LResponse: IHTTPResponse;
begin
  EnsureStatus(AdminRequest('POST', '/admin/realms/' + CRealm + '/clients',
    '{"clientId":"' + CPasswordClientID + '","enabled":true,"publicClient":true,"standardFlowEnabled":false,' +
    '"directAccessGrantsEnabled":true}'), 'Create password client');

  TryGetAdminToken(GAdminUser, GAdminPassword);
  LAdminUsers := TIAM4DKeycloakUserManager.Create(GAdminToken, GKeycloakURL, CRealm);
  LUser := LAdminUsers.GetUserByUsername(CUsername);
  LUserID := LUser.ID;
  Check('local user: no federation link', LUser.FederationLink = '');
  LAdminUsers.SetPassword(LUserID, CUserPassword, False);

  LClient := TIAM4DClientConfigBuilder.New.ForPassword(GKeycloakURL, CRealm, CPasswordClientID).Build;
  Check('password login', Safely(
    function: Boolean
    begin
      LToken := LClient.AuthenticatePassword(CUsername, CUserPassword);
      Result := (LToken <> '') and LClient.IsAuthenticated;
    end));
  Check('userinfo of the password login', Safely(
    function: Boolean
    begin
      Result := LClient.GetUserInfo.PreferredUsername = CUsername;
    end));
  Check('one Keycloak session after the login', UserSessionCount(LUserID) = 1);
  // Password grant: Keycloak sends acr 1 and no auth_time
  Check('id_token claims of the session: username, sid, acr', Safely(
    function: Boolean
    var
      LClaims: TIAM4DIDTokenClaims;
    begin
      LClaims := LClient.GetIDTokenClaims;
      Result := (LClaims.PreferredUsername = CUsername) and (LClaims.SessionID <> '') and
        (LClaims.Acr = '1') and (LClaims.Issuer = GKeycloakURL + '/realms/' + CRealm);
    end));
  Check('granted scopes of Keycloak: openid granted, an unknown one not', Safely(
    function: Boolean
    begin
      Result := LClient.HasGrantedScope('openid') and not LClient.HasGrantedScope('no-such-scope');
    end));
  Check('logout', Safely(
    function: Boolean
    begin
      LClient.Logout;
      Result := not LClient.IsAuthenticated;
    end));
  Check('no Keycloak session left after the logout', UserSessionCount(LUserID) = 0);

  // RFC 7009 on Keycloak: the revoked access token is refused by userinfo, the session ends
  LToken := LClient.AuthenticatePassword(CUsername, CUserPassword);
  Check('userinfo accepts the access token before the revocation', UserInfoStatus(LToken) = 200);
  Check('one Keycloak session before the revocation', UserSessionCount(LUserID) = 1);
  Check('revocation', Safely(
    function: Boolean
    begin
      LClient.RevokeTokens;
      Result := not LClient.IsAuthenticated;
    end));
  Check('revoked access token refused by userinfo', UserInfoStatus(LToken) = 401);
  Check('no Keycloak session left after the revocation', UserSessionCount(LUserID) = 0);

  Check('wrong password: EIAM4DInvalidCredentialsException',
    PasswordLoginClass(LClient, CUsername, 'wrong') = EIAM4DInvalidCredentialsException);
  Check('unknown user: EIAM4DInvalidCredentialsException',
    PasswordLoginClass(LClient, 'nobody', CUserPassword) = EIAM4DInvalidCredentialsException);

  // Pending UPDATE_PASSWORD: Keycloak checks the password first, then refuses
  LResponse := AdminRequest('PUT', '/admin/realms/' + CRealm + '/users/' + LUserID,
    '{"requiredActions":["UPDATE_PASSWORD"]}');
  EnsureStatus(LResponse, 'Set required action');
  Check('required action: EIAM4DAccountNotFullySetUpException',
    PasswordLoginClass(LClient, CUsername, CUserPassword) = EIAM4DAccountNotFullySetUpException);
  Check('required action with a wrong password: EIAM4DInvalidCredentialsException',
    PasswordLoginClass(LClient, CUsername, 'wrong') = EIAM4DInvalidCredentialsException);
  // A non temporary admin reset clears UPDATE_PASSWORD
  LAdminUsers.SetPassword(LUserID, CUserPassword, False);
  Check('admin reset clears UPDATE_PASSWORD', not LAdminUsers.GetUser(LUserID).HasRequiredAction(raUpdatePassword));
  Check('login after the reset', PasswordLoginClass(LClient, CUsername, CUserPassword) = nil);
  LClient.Logout;

  EnsureStatus(AdminRequest('PUT', '/admin/realms/' + CRealm + '/users/' + LUserID, '{"enabled":false}'),
    'Disable user');
  Check('disabled user: EIAM4DAccountDisabledException',
    PasswordLoginClass(LClient, CUsername, CUserPassword) = EIAM4DAccountDisabledException);
  EnsureStatus(AdminRequest('PUT', '/admin/realms/' + CRealm + '/users/' + LUserID, '{"enabled":true}'),
    'Enable user');

  Check('no Keycloak session left by the failed logins', UserSessionCount(LUserID) = 0);
end;

/// <summary>id of the client AClientID of the test realm</summary>
function ClientUUID(const AClientID: string): string;
var
  LResponse: IHTTPResponse;
  LClient: TJSONObject;
begin
  LResponse := AdminRequest('GET', '/admin/realms/' + CRealm + '/clients?clientId=' + AClientID);
  EnsureStatus(LResponse, 'Get client');
  LClient := FirstObject(LResponse);
  try
    Result := LClient.GetValue<string>('id');
  finally
    LClient.Free;
  end;
end;

function OfflineSessionCount(const AUserID, AClientUUID: string): Integer;
var
  LResponse: IHTTPResponse;
  LArray: TJSONValue;
begin
  LResponse := AdminRequest('GET', '/admin/realms/' + CRealm + '/users/' + AUserID + '/offline-sessions/' +
    AClientUUID);
  EnsureStatus(LResponse, 'Get offline sessions');
  LArray := TJSONObject.ParseJSONValue(LResponse.ContentAsString);
  try
    Result := (LArray as TJSONArray).Count;
  finally
    LArray.Free;
  end;
end;

/// <summary>typ of the JOSE header of AToken, '' when absent</summary>
function JWTHeaderTyp(const AToken: string): string;
var
  LHeader: TJSONObject;
begin
  LHeader := ParseObject(TEncoding.UTF8.GetString(TNetEncoding.Base64URL.DecodeStringToBytes(
    AToken.Split(['.'])[0])));
  try
    Result := LHeader.GetValue<string>('typ', '');
  finally
    LHeader.Free;
  end;
end;

/// <summary>
/// Validates AToken (signature from the JWKS of the realm, issuer, audience account) with
/// the header types ATypes; nil for the default. Result: the typ claim of the payload.
/// </summary>
function ValidateAccessToken(const AToken: string; const ATypes: TArray<string>): string;
var
  LObject: TIAM4DJWTValidator;
  LValidator: IIAM4DJWTValidator;
  LClaims: TJSONObject;
begin
  LObject := TIAM4DJWTValidator.Create(GKeycloakURL + '/realms/' + CRealm, 'account', svmStrict);
  LValidator := LObject;
  if ATypes <> nil then
    LObject.SetAllowedHeaderTypes(ATypes);
  if not LValidator.ValidateToken(AToken, LClaims) then
    raise Exception.Create('Token not valid');
  try
    Result := LClaims.GetValue<string>('typ', '');
  finally
    LClaims.Free;
  end;
end;

// RFC 9068 access tokens: Keycloak writes typ at+jwt in the header when the client asks for it,
// the validator refuses them by default and accepts them once at+jwt is allowed
procedure TestAccessTokenTypeIntegration;
var
  LAtJwtClient, LJwtClient: IIAM4DClient;
  LAtJwt, LJwt: string;
begin
  EnsureStatus(AdminRequest('POST', '/admin/realms/' + CRealm + '/clients',
    '{"clientId":"' + CAtJwtClientID + '","enabled":true,"publicClient":true,"standardFlowEnabled":false,' +
    '"directAccessGrantsEnabled":true,"attributes":{"access.token.header.type.rfc9068":"true"}}'),
    'Create at+jwt client');
  LAtJwtClient := TIAM4DClientConfigBuilder.New.ForPassword(GKeycloakURL, CRealm, CAtJwtClientID).Build;
  LJwtClient := TIAM4DClientConfigBuilder.New.ForPassword(GKeycloakURL, CRealm, CPasswordClientID).Build;
  LAtJwt := LAtJwtClient.AuthenticatePassword(CUsername, CUserPassword);
  LJwt := LJwtClient.AuthenticatePassword(CUsername, CUserPassword);
  try
    Check('at+jwt client: access token header typ at+jwt', JWTHeaderTyp(LAtJwt) = 'at+jwt');
    Check('other client: access token header typ JWT', JWTHeaderTyp(LJwt) = 'JWT');
    Check('at+jwt refused by the default header types (JWT)', Raises(
      procedure
      begin
        ValidateAccessToken(LAtJwt, nil);
      end, EIAM4DSecurityValidationException));
    Check('at+jwt accepted with SetAllowedHeaderTypes([JWT, at+jwt]), payload typ Bearer', Safely(
      function: Boolean
      begin
        Result := ValidateAccessToken(LAtJwt, ['JWT', 'at+jwt']) = 'Bearer';
      end));
    Check('typ JWT accepted with SetAllowedHeaderTypes([JWT, at+jwt])', Safely(
      function: Boolean
      begin
        Result := ValidateAccessToken(LJwt, ['JWT', 'at+jwt']) = 'Bearer';
      end));
    Check('typ JWT refused with SetAllowedHeaderTypes([at+jwt])', Raises(
      procedure
      begin
        ValidateAccessToken(LJwt, ['at+jwt']);
      end, EIAM4DSecurityValidationException));
  finally
    LAtJwtClient.Logout;
    LJwtClient.Logout;
  end;
end;

// Offline token (scope offline_access): RevokeTokens ends the offline session of the client,
// which outlives the user session
procedure TestOfflineRevocationIntegration;
var
  LClient: IIAM4DClient;
  LAdminUsers: IIAM4DUserManager;
  LUserID, LClientUUID: string;
begin
  TryGetAdminToken(GAdminUser, GAdminPassword);
  LAdminUsers := TIAM4DKeycloakUserManager.Create(GAdminToken, GKeycloakURL, CRealm);
  LUserID := LAdminUsers.GetUserByUsername(CUsername).ID;
  LClientUUID := ClientUUID(CPasswordClientID);
  LClient := TIAM4DClientConfigBuilder.New.ForPassword(GKeycloakURL, CRealm, CPasswordClientID)
    .WithScopes(['openid', 'offline_access'])
    .Build;

  Check('offline login', PasswordLoginClass(LClient, CUsername, CUserPassword) = nil);
  Check('offline_access granted', LClient.HasGrantedScope('offline_access'));
  Check('one offline session after the login', OfflineSessionCount(LUserID, LClientUUID) = 1);
  Check('revocation of the offline token', Safely(
    function: Boolean
    begin
      LClient.RevokeTokens;
      Result := not LClient.IsAuthenticated;
    end));
  Check('no offline session left after the revocation', OfflineSessionCount(LUserID, LClientUUID) = 0);
  Check('no Keycloak session left after the revocation', UserSessionCount(LUserID) = 0);

  // Keycloak 26.8: the back-channel logout with an offline refresh token ends the offline session too
  Check('offline login again', PasswordLoginClass(LClient, CUsername, CUserPassword) = nil);
  Check('one offline session before the logout', OfflineSessionCount(LUserID, LClientUUID) = 1);
  LClient.Logout;
  Check('no offline session left after the logout', OfflineSessionCount(LUserID, LClientUUID) = 0);
end;

// prompt=none through the local callback server: without a Keycloak session the login fails at
// once with error=login_required. A thread stands for the browser: it follows the redirects of
// the authorization URL, without cookies, up to the callback server.
procedure TestPromptNoneIntegration;
var
  LClient: IIAM4DClient;
  LSaved: TIAM4DOpenURLHandler;
  LOperation: IAsyncOperation<string>;
  LBrowser: TThread;
  LURL, LMessage: string;
  LErrorClass: TClass;
  LState: TAsyncOperationState;
begin
  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(GKeycloakURL, CRealm, CAppClientID)
    .WithCallbackPort(CCallbackPort)
    .WithLoopbackRedirectHost(lrhLoopbackIP)
    .WithPrompt(IAM4D_PROMPT_NONE)
    .Build;
  LBrowser := nil;
  LErrorClass := nil;
  LSaved := TIAM4DPlatformUtils.OpenURLHandler;
  TIAM4DPlatformUtils.OpenURLHandler :=
    function(const AURL: string): Boolean
    begin
      LURL := AURL;
      LBrowser := TThread.CreateAnonymousThread(
        procedure
        var
          LHTTP: THTTPClient;
        begin
          LHTTP := THTTPClient.Create;
          try
            LHTTP.AllowCookies := False;
            try
              LHTTP.Get(AURL);
            except
              // The callback page is all there is to read
            end;
          finally
            LHTTP.Free;
          end;
        end);
      LBrowser.FreeOnTerminate := False;
      LBrowser.Start;
      Result := True;
    end;
  try
    LOperation := LClient.StartAuthorizationFlowAsync
      .OnError(
        procedure(const E: Exception)
        begin
          LErrorClass := E.ClassType;
          LMessage := E.Message;
        end)
      .DispatchMode(TAsyncCallbackDispatchMode.dmInline)
      .Run;
    LState := LOperation.WaitForCompletion(30000);
  finally
    TIAM4DPlatformUtils.OpenURLHandler := LSaved;
    if Assigned(LBrowser) then
    begin
      LBrowser.WaitFor;
      LBrowser.Free;
    end;
  end;
  Check('prompt=none in the authorization URL', LURL.Contains('prompt=none'));
  Check('prompt=none without a session: the login fails', LState = TAsyncOperationState.Faulted);
  Check('prompt=none without a session: EIAM4DOAuth2CallbackException with login_required (' + LMessage + ')',
    (LErrorClass = EIAM4DOAuth2CallbackException) and LMessage.Contains('login_required'));
  Check('prompt=none without a session: not authenticated', not LClient.IsAuthenticated);
end;

// Keycloak 24+ lists at most 100 providers when first/max are not given
procedure TestProviderPaging(const AManager: IIAM4DIdentityProviderManager);
const
  CCount = 105;
var
  LIdP: TIAM4DIdentityProvider;
  LIndex: Integer;
  LAll: TArray<TIAM4DIdentityProvider>;
begin
  for LIndex := 0 to CCount - 1 do
  begin
    LIdP := TIAM4DIdentityProvider.Create(Format('page-%.3d', [LIndex]), IAM4D_IDP_PROVIDER_SAML);
    LIdP.Config.Values['singleSignOnServiceUrl'] := 'https://idp.example.com/sso';
    AManager.CreateIdentityProvider(LIdP);
  end;
  LAll := AManager.GetIdentityProviders;
  Check(Format('more than 100 providers listed (%d)', [Length(LAll)]), (Length(LAll) = CCount) and AliasesUnique(LAll));
  LAll := AManager.GetIdentityProviders('page-10', 0, 100);
  Check(Format('search by alias prefix (%d)', [Length(LAll)]), (Length(LAll) = 5) and (LAll[0].Alias = 'page-100'));
  LAll := AManager.GetIdentityProviders('', 100, 3);
  Check(Format('one page (%d)', [Length(LAll)]), (Length(LAll) = 3) and (LAll[0].Alias = 'page-100'));
end;

procedure TestIntegration;
var
  LAdminClient: IIAM4DClient;
  LManager: IIAM4DIdentityProviderManager;
  LAsync: IIAM4DIdentityProviderManagerAsync;
  LEntra, LSaml, LRead: TIAM4DIdentityProvider;
  LTry: TIAM4DIdentityProviderTryResult;
  LAll: TArray<TIAM4DIdentityProvider>;
  LMapper: TIAM4DIdentityProviderMapper;
  LMappers: TArray<TIAM4DIdentityProviderMapper>;
  LImported: TIAM4DConfigMap;
  LURL, LLocation, LPage, LMetadata: string;
  LResponse: IHTTPResponse;
  LUserManager: IIAM4DUserManager;
  LUserCount: Integer;
begin
  Writeln('Integration (', GKeycloakURL, ')');
  SetupRealm;
  try
    LAdminClient := TIAM4DClientConfigBuilder.New
      .ForClientCredentials(GKeycloakURL, CRealm, CAdminClientID, CAdminClientSecret)
      .Build;
    LAdminClient.AuthenticateClient;
    LManager := TIAM4DKeycloakIdentityProviderManager.Create(LAdminClient);

    Check('no providers', Length(LManager.GetIdentityProviders) = 0);

    // Entra (fake tenant: only the redirect is checked)
    LEntra := TIAM4DEntraIdPBuilder.New('entra-test')
      .WithTenant(CTenant)
      .WithClient('entra-client-id', 'entra-secret')
      .WithHideOnLogin
      .WithSyncMode(ismImport)
      .Build;
    LManager.CreateIdentityProvider(LEntra);
    LRead := LManager.GetIdentityProvider('entra-test');
    Check('Entra created', (LRead.ProviderID = 'oidc') and LRead.Enabled and LRead.HideOnLogin and
      (LRead.InternalID <> '') and (LRead.SyncMode = ismImport) and
      (LRead.Config.Values['authorizationUrl'] = LEntra.Config.Values['authorizationUrl']) and
      (LRead.Config.Values['clientId'] = 'entra-client-id'));
    Check('secret masked on read', LRead.Config.Values['clientSecret'] = IAM4D_IDP_SECRET_MASK);
    CheckHTTPError('duplicate create rejected (409)',
      procedure
      begin
        LManager.CreateIdentityProvider(LEntra);
      end, EIAM4DHTTPConflictException, 409, 'entra-test');

    // Update from the read representation (masked secret kept by Keycloak)
    LRead.DisplayName := 'Microsoft Entra ID';
    LManager.UpdateIdentityProvider(LRead);
    Check('updated', LManager.GetIdentityProvider('entra-test').DisplayName = 'Microsoft Entra ID');

    LTry := LManager.TryGetIdentityProvider('missing');
    Check('TryGet missing', not LTry.Found);
    CheckHTTPError('Get missing raises (404)',
      procedure
      begin
        LManager.GetIdentityProvider('missing');
      end, EIAM4DHTTPNotFoundException, 404, '');
    CheckHTTPError('mappers of a missing provider (404)',
      procedure
      begin
        LManager.GetMappers('missing');
      end, EIAM4DHTTPNotFoundException, 404, '');
    // Token not accepted: 401, HTTP client error with no more specific class
    CheckHTTPError('invalid token (401)',
      procedure
      begin
        (TIAM4DKeycloakIdentityProviderManager.Create('not-a-token', GKeycloakURL, CRealm) as
          IIAM4DIdentityProviderManager).GetIdentityProviders;
      end, EIAM4DHTTPClientErrorException, 401, '');

    // Generic SAML provider, created through Save
    LSaml := TIAM4DIdentityProvider.Create('saml-test', IAM4D_IDP_PROVIDER_SAML);
    LSaml.DisplayName := 'SAML test';
    LSaml.Config.Values['entityId'] := GKeycloakURL + '/realms/' + CRealm;
    LSaml.Config.Values['singleSignOnServiceUrl'] := 'https://idp.example.com/sso';
    LManager.SaveIdentityProvider(LSaml);
    LSaml.TrustEmail := True;
    LManager.SaveIdentityProvider(LSaml);
    LAll := LManager.GetIdentityProviders;
    Check('Save creates then updates', (Length(LAll) = 2) and LManager.GetIdentityProvider('saml-test').TrustEmail);

    LMetadata := LManager.ExportServiceProviderMetadata('saml-test');
    Check('SP metadata', LMetadata.Contains('EntityDescriptor') and LMetadata.Contains('/broker/saml-test/endpoint'));

    // Mappers
    LMapper := TIAM4DIdentityProviderMapper.Create('entra-test', 'upn', 'oidc-user-attribute-idp-mapper');
    LMapper.Config.Values['syncMode'] := 'INHERIT';
    LMapper.Config.Values['claim'] := 'upn';
    LMapper.Config.Values['user.attribute'] := 'upn';
    LMapper.ID := LManager.CreateMapper(LMapper);
    Check('mapper created', LMapper.ID <> '');
    LMapper.Config.Values['user.attribute'] := 'userPrincipalName';
    LManager.UpdateMapper(LMapper);
    LMappers := LManager.GetMappers('entra-test');
    Check('mapper updated', (Length(LMappers) = 1) and (LMappers[0].ID = LMapper.ID) and
      (LMappers[0].Config.Values['user.attribute'] = 'userPrincipalName'));
    Check('get mapper', Safely(
      function: Boolean
      var
        LOne: TIAM4DIdentityProviderMapper;
      begin
        LOne := LManager.GetMapper('entra-test', LMapper.ID);
        Result := (LOne.Name = 'upn') and (LOne.Config.Values['user.attribute'] = 'userPrincipalName');
      end));
    CheckHTTPError('get a mapper through another provider (404)',
      procedure
      begin
        LManager.GetMapper('saml-test', LMapper.ID);
      end, EIAM4DHTTPNotFoundException, 404, '');
    LManager.DeleteMapper('entra-test', LMapper.ID);
    Check('mapper deleted', Length(LManager.GetMappers('entra-test')) = 0);
    CheckHTTPError('get a deleted mapper (404)',
      procedure
      begin
        LManager.GetMapper('entra-test', LMapper.ID);
      end, EIAM4DHTTPNotFoundException, 404, '');
    Check('mapper types of an OIDC provider', Safely(
      function: Boolean
      var
        LType: TIAM4DIdentityProviderMapperType;
      begin
        Result := False;
        for LType in LManager.GetMapperTypes('entra-test') do
          if LType.ID = 'oidc-user-attribute-idp-mapper' then
            Result := (LType.Name <> '') and (Length(LType.Properties) > 0) and (LType.Properties[0].Name = 'claim');
      end));
    Check('provider types', LManager.IsProviderInstalled(IAM4D_IDP_PROVIDER_OIDC) and
      LManager.IsProviderInstalled(IAM4D_IDP_PROVIDER_SAML) and not LManager.IsProviderInstalled('not-a-provider'));
    // Keycloak 26 refuses to rename a provider, 400 (documented: create another and delete this one);
    // Keycloak 25 answers 404 to a new alias without the internal ID
    LResponse := AdminRequest('PUT', '/admin/realms/' + CRealm + '/identity-provider/instances/saml-test',
      '{"alias":"saml-renamed","providerId":"saml","config":{"singleSignOnServiceUrl":"https://idp.example.com/sso"}}');
    Check(Format('alias cannot be changed (%d)', [LResponse.StatusCode]),
      ((LResponse.StatusCode = 400) or (LResponse.StatusCode = 404)) and
      LManager.TryGetIdentityProvider('saml-test').Found and not LManager.TryGetIdentityProvider('saml-renamed').Found);

    // Copies of what Keycloak returns, created under another alias: Keycloak would reuse the internal
    // ID and the mapper ID (primary keys: 409)
    LRead := LManager.GetIdentityProvider('saml-test');
    LRead.Alias := 'saml-copy';
    Check('copy of a read provider created', Safely(
      function: Boolean
      begin
        LManager.CreateIdentityProvider(LRead);
        Result := LManager.GetIdentityProvider('saml-copy').InternalID <> LRead.InternalID;
      end));
    if LManager.TryGetIdentityProvider('saml-copy').Found then
      LManager.DeleteIdentityProvider('saml-copy');
    LMapper := TIAM4DIdentityProviderMapper.Create('saml-test', 'department', 'hardcoded-attribute-idp-mapper');
    LMapper.Config.Values['syncMode'] := 'INHERIT';
    LMapper.Config.Values['attribute'] := 'department';
    LMapper.Config.Values['attribute.value'] := 'sales';
    LManager.CreateMapper(LMapper);
    LMapper := LManager.GetMappers('saml-test')[0];
    LMapper.IdentityProviderAlias := 'entra-test';
    Check('copy of a read mapper created', Safely(
      function: Boolean
      begin
        Result := LManager.CreateMapper(LMapper) <> LMapper.ID;
      end));
    Check('copied mapper on the other provider', (Length(LManager.GetMappers('entra-test')) = 1) and
      (Length(LManager.GetMappers('saml-test')) = 1));
    for var LCopied in LManager.GetMappers('saml-test') + LManager.GetMappers('entra-test') do
      LManager.DeleteMapper(LCopied.IdentityProviderAlias, LCopied.ID);
    // The masked secret of a read provider would become the secret of the copy
    LRead := LManager.GetIdentityProvider('entra-test');
    LRead.Alias := 'entra-copy';
    Check('copy with the masked secret rejected', Raises(
      procedure
      begin
        LManager.CreateIdentityProvider(LRead);
      end, EIAM4DInvalidConfigurationException));
    Check('copy with the masked secret not created', not LManager.TryGetIdentityProvider('entra-copy').Found);
    if LManager.TryGetIdentityProvider('entra-copy').Found then
      LManager.DeleteIdentityProvider('entra-copy');

    // Import from an OIDC discovery document (the master realm: no internet needed)
    LImported := ImportMasterDiscovery(LManager);
    Check('ImportConfig', LImported.Values['authorizationUrl'].EndsWith('/realms/master/protocol/openid-connect/auth') and
      LImported.Values['tokenUrl'].EndsWith('/realms/master/protocol/openid-connect/token'));

    // Async wrapper
    LAsync := TIAM4DKeycloakIdentityProviderManagerAsync.Create(LManager);
    Check('async list', Length(LAsync.GetIdentityProvidersAsync.Run.WaitForResult) = 2);
    Check('async TryGet', LAsync.TryGetIdentityProviderAsync('saml-test').Run.WaitForResult.Found);

    // The refactored admin base still serves the user manager: the count agrees with the listing
    LUserManager := TIAM4DKeycloakUserManager.Create(LAdminClient);
    LUserCount := LUserManager.GetUsersCount;
    Check(Format('user manager on the shared admin base: count %d = users listed', [LUserCount]),
      LUserCount = Length(LUserManager.SearchUsers(TIAM4DUserSearchCriteria.Create('', 0, 1000))));
    LUserManager := nil;
    TestUserManagerIntegration(LAdminClient);
    TestPasswordGrantIntegration;
    TestAccessTokenTypeIntegration;
    TestOfflineRevocationIntegration;
    TestPromptNoneIntegration;

    // Login: kc_idp_hint from the configuration
    LURL := AppAuthURL('entra-test', '');
    Check('auth URL carries kc_idp_hint', LURL.Contains('kc_idp_hint=entra-test'));
    LResponse := Navigate(LURL);
    LLocation := LResponse.HeaderValue['Location'];
    Check('Keycloak redirects straight to Entra ' + Describe(LResponse), IsRedirect(LResponse) and
      LLocation.StartsWith('https://login.microsoftonline.com/' + CTenant + '/oauth2/v2.0/authorize?') and
      LLocation.Contains('client_id=entra-client-id') and LLocation.Contains('code_challenge_method=S256') and
      LLocation.Contains(TNetEncoding.URL.Encode('/broker/entra-test/endpoint')));

    // Login: the call argument wins over the configuration
    LResponse := Navigate(AppAuthURL('entra-test', 'saml-test'));
    Check('call hint overrides the configured one ' + Describe(LResponse), IsRedirect(LResponse) and
      LResponse.HeaderValue['Location'].StartsWith('https://idp.example.com/sso?'));

    // Login: no hint shows the Keycloak page, without the hidden provider
    LURL := AppAuthURL('', '');
    Check('no hint in the URL', not LURL.Contains('kc_idp_hint'));
    LResponse := Navigate(LURL);
    LPage := LResponse.ContentAsString(TEncoding.UTF8);
    Check('Keycloak login page', (LResponse.StatusCode = 200) and LPage.Contains('social-saml-test'));
    Check('hidden provider not on the page', not LPage.Contains('social-entra-test'));

    TestSocialProviders(LManager);
    TestMoreSocialProviders(LManager);
    TestGenericProviders(LManager);
    TestItalianProviders(LManager);

    LManager.DeleteIdentityProvider('entra-test');
    LManager.DeleteIdentityProvider('saml-test');
    Check('providers deleted', Length(LManager.GetIdentityProviders) = 0);

    TestProviderPaging(LManager);
  finally
    AdminRequest('DELETE', '/admin/realms/' + CRealm);
  end;
end;

// ============================================================================
// Validator from several threads (offline)
// ============================================================================

const
  CValidatorThreads = 4;
  CValidatorRounds = 50000;

// Even workers validate valid values, odd ones invalid values: a shared match state mixes them up
function ValidatorWorker(AIndex: Integer; AGo: TEvent; AWrong, AErrors: PInteger): TProc;
begin
  Result :=
    procedure
    var
      LRound: Integer;
      LValid: Boolean;
      LName: string;
    begin
      LValid := not Odd(AIndex);
      AGo.WaitFor(INFINITE);
      for LRound := 1 to CValidatorRounds do
      begin
        if LValid then
          LName := Format('user.%d.%d', [AIndex, LRound])
        else
          LName := Format('bad name %d %d', [AIndex, LRound]);
        try
          try
            TIAM4DUserManagementValidator.ValidateUsername(LName);
            TIAM4DUserManagementValidator.ValidateEmail(LName + '@example.com');
            if not LValid then
              TInterlocked.Increment(AWrong^);
          except
            on EIAM4DInvalidUserDataException do
              if LValid then
                TInterlocked.Increment(AWrong^);
          end;
        except
          TInterlocked.Increment(AErrors^);
        end;
      end;
    end;
end;

procedure TestValidatorThreads;
var
  LGo: TEvent;
  LThreads: array[0..CValidatorThreads - 1] of TThread;
  LWrong, LErrors, I: Integer;
begin
  Writeln('Validator from several threads');
  LWrong := 0;
  LErrors := 0;
  LGo := TEvent.Create(nil, True, False, '');
  try
    for I := 0 to High(LThreads) do
    begin
      LThreads[I] := TThread.CreateAnonymousThread(ValidatorWorker(I, LGo, @LWrong, @LErrors));
      LThreads[I].FreeOnTerminate := False;
      LThreads[I].Start;
    end;
    LGo.SetEvent;
    for I := 0 to High(LThreads) do
    begin
      LThreads[I].WaitFor;
      LThreads[I].Free;
    end;
  finally
    LGo.Free;
  end;
  Check(Format('%d threads x %d usernames and emails: every value classified right (%d wrong, %d other errors)',
    [CValidatorThreads, CValidatorRounds, LWrong, LErrors]), (LWrong = 0) and (LErrors = 0));
end;

begin
  ReportMemoryLeaksOnShutdown := True;
  try
    TestConfigMap;
    TestIdentityProviderRecord;
    TestJSON;
    TestEntraBuilder;
    TestOidcBuilder;
    TestSamlBuilder;
    TestGoogleBuilder;
    TestFacebookBuilder;
    TestOAuth2Builder;
    TestMicrosoftBuilder;
    TestLinkedInBuilder;
    TestGitHubBuilder;
    TestGitLabBuilder;
    TestSpidBuilder;
    TestCieBuilder;
    TestConfigurationErrors;
    TestLoginConfig;
    TestAdminRequests;
    TestIdentityProviderRequests;
    TestUserManagerRequests;
    TestAdminConnectionReuse;
    TestAdminPathsAndRedirects;
    TestGroupRequests;
    TestUserManagerPayloads;
    TestAliasAndTokenProvider;
    TestNewAdminRequests;
    TestValidatorThreads;

    GKeycloakURL := 'http://localhost:18080';
    GAdminUser := 'admin';
    GAdminPassword := 'admin';
    if ParamCount >= 1 then
      GKeycloakURL := ParamStr(1).TrimRight(['/']);
    if ParamCount >= 2 then
      GAdminUser := ParamStr(2);
    if ParamCount >= 3 then
      GAdminPassword := ParamStr(3);

    if TryGetAdminToken(GAdminUser, GAdminPassword) then
      TestIntegration
    else if GetEnvironmentVariable('IAM4D_ALLOW_SKIP') = '1' then
      Skip('Integration', 'Keycloak not reachable at ' + GKeycloakURL + ' (or wrong admin credentials), IAM4D_ALLOW_SKIP=1')
    else
      Check('Integration: Keycloak reachable at ' + GKeycloakURL + ' with the admin credentials ' +
        '(start tests\IdentityProvider\docker\up.cmd, or set IAM4D_ALLOW_SKIP=1 to run the unit checks alone)', False);

    Writeln;
    Writeln(Format('Passed: %d  Failed: %d  Skipped: %d', [GPassed, GFailed, GSkipped]));
    if GFailed > 0 then
      ExitCode := 1;
  except
    on E: Exception do
    begin
      Writeln('FATAL ', E.ClassName, ': ', E.Message);
      ExitCode := 2;
    end;
  end;
end.
