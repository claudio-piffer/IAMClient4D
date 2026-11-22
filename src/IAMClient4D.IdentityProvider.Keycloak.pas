{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.IdentityProvider.Keycloak.pas
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

  Keycloak identity provider management through the Admin REST API
  (/admin/realms/<realm>/identity-provider), synchronous.

  ---------------------------------------------------------------------------
}

unit IAMClient4D.IdentityProvider.Keycloak;

interface

uses
  System.SysUtils,
  System.JSON,
  System.Net.HttpClient,
  IAMClient4D.Core,
  IAMClient4D.Admin.Keycloak.Base,
  IAMClient4D.IdentityProvider.Core;

type
  /// <summary>
  /// JSON mapping of identity providers and mappers (Keycloak representations).
  /// </summary>
  TIAM4DIdentityProviderJSON = class
  public
    /// <summary>Caller owns the result.</summary>
    class function ConfigToJSON(const AConfig: TIAM4DConfigMap): TJSONObject; static;
    class function ConfigFromJSON(const AJSON: TJSONObject): TIAM4DConfigMap; static;
    /// <summary>
    /// IdentityProviderRepresentation. HideOnLogin is written both as hideOnLogin (Keycloak 26+)
    /// and as config hideOnLoginPage (earlier versions). Caller owns the result.
    /// </summary>
    class function IdentityProviderToJSON(const AIdentityProvider: TIAM4DIdentityProvider): TJSONObject; static;
    class function IdentityProviderFromJSON(const AJSON: TJSONObject): TIAM4DIdentityProvider; static;
    /// <summary>IdentityProviderMapperRepresentation. Caller owns the result.</summary>
    class function MapperToJSON(const AMapper: TIAM4DIdentityProviderMapper): TJSONObject; static;
    class function MapperFromJSON(const AJSON: TJSONObject): TIAM4DIdentityProviderMapper; static;
    /// <summary>IdentityProviderMapperTypeRepresentation.</summary>
    class function MapperTypeFromJSON(const AJSON: TJSONObject): TIAM4DIdentityProviderMapperType; static;
  end;

  /// <summary>
  /// Keycloak Admin API implementation of identity provider management (synchronous).
  /// </summary>
  /// <remarks>
  /// Constructors (inherited): auth provider, IIAM4DClient (base URL and realm from the issuer)
  /// or static access token. The token needs realm-management manage-identity-providers.
  /// Use case: server side, or on a worker thread. VCL/FMX: TIAM4DKeycloakIdentityProviderManagerAsync.
  /// </remarks>
  TIAM4DKeycloakIdentityProviderManager = class(TIAM4DKeycloakAdminBase, IIAM4DIdentityProviderManager)
  private
    function GetInstancesURL: string;
    function GetInstanceURL(const AAlias: string): string;
    function GetMappersURL(const AAlias: string): string;
    /// <summary>GET of the provider: False if it does not exist, raises on other errors.</summary>
    function GetInstance(const AHTTPClient: THTTPClient; const AAlias: string; out AResponse: IHTTPResponse): Boolean;
    function TryGetInternal(const AHTTPClient: THTTPClient; const AAlias: string;
      out AIdentityProvider: TIAM4DIdentityProvider): Boolean;
    function GetPage(const AHTTPClient: THTTPClient; const ASearch: string; const AFirst, AMax: Integer):
      TArray<TIAM4DIdentityProvider>;
    procedure SendIdentityProvider(const AHTTPClient: THTTPClient; const AURL, AMethod: string;
      const AJSON: TJSONObject; const AContext: string);
    procedure CreateInternal(const AHTTPClient: THTTPClient; const AIdentityProvider: TIAM4DIdentityProvider);
    procedure UpdateInternal(const AHTTPClient: THTTPClient; const AIdentityProvider: TIAM4DIdentityProvider);
  protected
    function GetIdentityProviders: TArray<TIAM4DIdentityProvider>; overload;
    function GetIdentityProviders(const ASearch: string; const AFirst, AMax: Integer): TArray<TIAM4DIdentityProvider>; overload;
    function GetIdentityProvider(const AAlias: string): TIAM4DIdentityProvider;
    function TryGetIdentityProvider(const AAlias: string): TIAM4DIdentityProviderTryResult;
    procedure CreateIdentityProvider(const AIdentityProvider: TIAM4DIdentityProvider);
    procedure UpdateIdentityProvider(const AIdentityProvider: TIAM4DIdentityProvider);
    procedure SaveIdentityProvider(const AIdentityProvider: TIAM4DIdentityProvider);
    procedure DeleteIdentityProvider(const AAlias: string);
    function IsProviderInstalled(const AProviderID: string): Boolean;
    function ImportConfig(const AProviderID: string; const AFromURL: string): TIAM4DConfigMap;
    function ExportServiceProviderMetadata(const AAlias: string): string;
    function GetMappers(const AIdentityProviderAlias: string): TArray<TIAM4DIdentityProviderMapper>;
    function GetMapper(const AIdentityProviderAlias: string; const AMapperID: string): TIAM4DIdentityProviderMapper;
    function GetMapperTypes(const AIdentityProviderAlias: string): TArray<TIAM4DIdentityProviderMapperType>;
    function CreateMapper(const AMapper: TIAM4DIdentityProviderMapper): string;
    procedure UpdateMapper(const AMapper: TIAM4DIdentityProviderMapper);
    procedure DeleteMapper(const AIdentityProviderAlias: string; const AMapperID: string);
  end;

implementation

uses
  System.Generics.Defaults,
  System.Generics.Collections,
  System.NetConsts,
  System.NetEncoding,
  IAMClient4D.Common.JSONUtils,
  IAMClient4D.Exceptions,
  IAMClient4D.Admin.Keycloak.Constants;

const
  // Keycloak < 26 reads HideOnLogin from this config key
  IAM4D_IDP_CONFIG_HIDE_ON_LOGIN_PAGE = 'hideOnLoginPage';
  // Keycloak 26+ field, unknown to earlier versions (they reject the request)
  IAM4D_IDP_FIELD_HIDE_ON_LOGIN = 'hideOnLogin';
  IAM4D_IDP_FIELD_INTERNAL_ID = 'internalId';
  IAM4D_IDP_MAPPER_FIELD_ID = 'id';

procedure ValidateAlias(const AAlias: string; const AWhat: string = 'Identity provider alias');
const
  // Characters that would break the admin URLs or kc_idp_hint
  CInvalidChars: array[0..6] of Char = ('/', '\', '?', '#', '%', ' ', '&');
var
  LChar: Char;
begin
  if AAlias.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(Format('%s cannot be empty', [AWhat]));
  for LChar in CInvalidChars do
    if AAlias.Contains(LChar) then
      raise EIAM4DInvalidConfigurationException.Create(Format('%s "%s" contains an invalid character: "%s"',
        [AWhat, AAlias, LChar]));
end;

procedure ValidateIdentityProvider(const AIdentityProvider: TIAM4DIdentityProvider);
begin
  ValidateAlias(AIdentityProvider.Alias);
  if AIdentityProvider.ProviderID.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      'Identity provider "%s": ProviderID cannot be empty', [AIdentityProvider.Alias]));
end;

// Keycloak stores a config value as sent: the secret mask of a read provider would become the secret.
// Only on update, and only for clientSecret, Keycloak puts back the stored value.
procedure ValidateNoSecretMask(const AIdentityProvider: TIAM4DIdentityProvider; const AUpdate: Boolean);
var
  LEntry: TIAM4DConfigEntry;
begin
  for LEntry in AIdentityProvider.Config.Entries do
    if (LEntry.Value = IAM4D_IDP_SECRET_MASK) and not (AUpdate and (LEntry.Key = IAM4D_IDP_CONFIG_CLIENT_SECRET)) then
      raise EIAM4DInvalidConfigurationException.Create(Format(
        'Identity provider "%s": config "%s" is %s, the mask Keycloak returns in place of secrets; ' +
        'Keycloak would store it as the value. Set the real value', [AIdentityProvider.Alias, LEntry.Key,
        IAM4D_IDP_SECRET_MASK]));
end;

procedure ValidateMapper(const AMapper: TIAM4DIdentityProviderMapper);
begin
  ValidateAlias(AMapper.IdentityProviderAlias);
  if AMapper.Name.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Identity provider mapper name cannot be empty');
  if AMapper.MapperType.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      'Identity provider mapper "%s": MapperType cannot be empty', [AMapper.Name]));
end;

// String value as is, any other JSON value as JSON text; empty if missing or null
function JSONText(const AJSON: TJSONObject; const AName: string): string;
var
  LValue: TJSONValue;
begin
  LValue := AJSON.GetValue(AName);
  if (LValue = nil) or (LValue is TJSONNull) then
    Result := ''
  else if LValue is TJSONString then
    Result := LValue.Value
  else
    Result := LValue.ToString;
end;

function ConfigPropertyFromJSON(const AJSON: TJSONObject): TIAM4DConfigProperty;
var
  LOptions: TJSONArray;
  LOption: TJSONValue;
begin
  Result := Default(TIAM4DConfigProperty);
  Result.Name := JSONText(AJSON, 'name');
  Result.DisplayLabel := JSONText(AJSON, 'label');
  Result.HelpText := JSONText(AJSON, 'helpText');
  Result.PropertyType := JSONText(AJSON, 'type');
  Result.DefaultValue := JSONText(AJSON, 'defaultValue');
  Result.Secret := AJSON.GetValue<Boolean>('secret', False);
  Result.Required := AJSON.GetValue<Boolean>('required', False);
  Result.ReadOnly := AJSON.GetValue<Boolean>('readOnly', False);
  if AJSON.TryGetValue<TJSONArray>('options', LOptions) then
    for LOption in LOptions do
      if not (LOption is TJSONNull) then
        Result.Options := Result.Options + [LOption.Value];
end;

{ TIAM4DIdentityProviderJSON }

class function TIAM4DIdentityProviderJSON.ConfigToJSON(const AConfig: TIAM4DConfigMap): TJSONObject;
var
  LEntry: TIAM4DConfigEntry;
begin
  Result := TJSONObject.Create;
  for LEntry in AConfig.Entries do
    Result.AddPair(LEntry.Key, LEntry.Value);
end;

class function TIAM4DIdentityProviderJSON.ConfigFromJSON(const AJSON: TJSONObject): TIAM4DConfigMap;
var
  LPair: TJSONPair;
begin
  Result := Default(TIAM4DConfigMap);
  if AJSON = nil then
    Exit;
  for LPair in AJSON do
    if LPair.JsonValue is TJSONString then
      Result.Values[LPair.JsonString.Value] := LPair.JsonValue.Value
    else if not (LPair.JsonValue is TJSONNull) then
      Result.Values[LPair.JsonString.Value] := LPair.JsonValue.ToString;
end;

class function TIAM4DIdentityProviderJSON.IdentityProviderToJSON(
  const AIdentityProvider: TIAM4DIdentityProvider): TJSONObject;
var
  LConfig: TIAM4DConfigMap;
begin
  Result := TJSONObject.Create;
  try
    Result.AddPair('alias', AIdentityProvider.Alias);
    if not AIdentityProvider.InternalID.IsEmpty then
      Result.AddPair(IAM4D_IDP_FIELD_INTERNAL_ID, AIdentityProvider.InternalID);
    if not AIdentityProvider.DisplayName.IsEmpty then
      Result.AddPair('displayName', AIdentityProvider.DisplayName);
    Result.AddPair('providerId', AIdentityProvider.ProviderID);
    Result.AddPair('enabled', TJSONBool.Create(AIdentityProvider.Enabled));
    Result.AddPair('trustEmail', TJSONBool.Create(AIdentityProvider.TrustEmail));
    Result.AddPair('storeToken', TJSONBool.Create(AIdentityProvider.StoreToken));
    Result.AddPair('addReadTokenRoleOnCreate', TJSONBool.Create(AIdentityProvider.AddReadTokenRoleOnCreate));
    Result.AddPair('linkOnly', TJSONBool.Create(AIdentityProvider.LinkOnly));
    Result.AddPair(IAM4D_IDP_FIELD_HIDE_ON_LOGIN, TJSONBool.Create(AIdentityProvider.HideOnLogin));
    if not AIdentityProvider.FirstBrokerLoginFlowAlias.IsEmpty then
      Result.AddPair('firstBrokerLoginFlowAlias', AIdentityProvider.FirstBrokerLoginFlowAlias);
    if not AIdentityProvider.PostBrokerLoginFlowAlias.IsEmpty then
      Result.AddPair('postBrokerLoginFlowAlias', AIdentityProvider.PostBrokerLoginFlowAlias);

    LConfig := AIdentityProvider.Config;
    LConfig.SetBool(IAM4D_IDP_CONFIG_HIDE_ON_LOGIN_PAGE, AIdentityProvider.HideOnLogin);
    Result.AddPair('config', ConfigToJSON(LConfig));
  except
    Result.Free;
    raise;
  end;
end;

class function TIAM4DIdentityProviderJSON.IdentityProviderFromJSON(const AJSON: TJSONObject): TIAM4DIdentityProvider;
var
  LConfig: TIAM4DConfigMap;
  LConfigJSON: TJSONObject;
  LHideOnLogin: Boolean;
begin
  Result := TIAM4DIdentityProvider.Create(
    AJSON.GetValue<string>('alias', ''),
    AJSON.GetValue<string>('providerId', ''));
  Result.InternalID := AJSON.GetValue<string>(IAM4D_IDP_FIELD_INTERNAL_ID, '');
  Result.DisplayName := AJSON.GetValue<string>('displayName', '');
  Result.Enabled := AJSON.GetValue<Boolean>('enabled', False);
  Result.TrustEmail := AJSON.GetValue<Boolean>('trustEmail', False);
  Result.StoreToken := AJSON.GetValue<Boolean>('storeToken', False);
  Result.AddReadTokenRoleOnCreate := AJSON.GetValue<Boolean>('addReadTokenRoleOnCreate', False);
  Result.LinkOnly := AJSON.GetValue<Boolean>('linkOnly', False);
  Result.FirstBrokerLoginFlowAlias := AJSON.GetValue<string>('firstBrokerLoginFlowAlias', '');
  Result.PostBrokerLoginFlowAlias := AJSON.GetValue<string>('postBrokerLoginFlowAlias', '');

  if AJSON.TryGetValue<TJSONObject>('config', LConfigJSON) then
    LConfig := ConfigFromJSON(LConfigJSON)
  else
    LConfig := Default(TIAM4DConfigMap);

  // Keycloak 26+: top-level field; earlier versions: config key
  if not AJSON.TryGetValue<Boolean>(IAM4D_IDP_FIELD_HIDE_ON_LOGIN, LHideOnLogin) then
    LHideOnLogin := LConfig.GetBool(IAM4D_IDP_CONFIG_HIDE_ON_LOGIN_PAGE);
  LConfig.Remove(IAM4D_IDP_CONFIG_HIDE_ON_LOGIN_PAGE);
  Result.HideOnLogin := LHideOnLogin;
  Result.Config := LConfig;
end;

class function TIAM4DIdentityProviderJSON.MapperToJSON(const AMapper: TIAM4DIdentityProviderMapper): TJSONObject;
begin
  Result := TJSONObject.Create;
  try
    if not AMapper.ID.IsEmpty then
      Result.AddPair(IAM4D_IDP_MAPPER_FIELD_ID, AMapper.ID);
    Result.AddPair('name', AMapper.Name);
    Result.AddPair('identityProviderAlias', AMapper.IdentityProviderAlias);
    Result.AddPair('identityProviderMapper', AMapper.MapperType);
    Result.AddPair('config', ConfigToJSON(AMapper.Config));
  except
    Result.Free;
    raise;
  end;
end;

class function TIAM4DIdentityProviderJSON.MapperFromJSON(const AJSON: TJSONObject): TIAM4DIdentityProviderMapper;
var
  LConfigJSON: TJSONObject;
begin
  Result := TIAM4DIdentityProviderMapper.Create(
    AJSON.GetValue<string>('identityProviderAlias', ''),
    AJSON.GetValue<string>('name', ''),
    AJSON.GetValue<string>('identityProviderMapper', ''));
  Result.ID := AJSON.GetValue<string>(IAM4D_IDP_MAPPER_FIELD_ID, '');
  if AJSON.TryGetValue<TJSONObject>('config', LConfigJSON) then
    Result.Config := ConfigFromJSON(LConfigJSON);
end;

class function TIAM4DIdentityProviderJSON.MapperTypeFromJSON(const AJSON: TJSONObject): TIAM4DIdentityProviderMapperType;
var
  LProperties: TJSONArray;
  LProperty: TJSONValue;
begin
  Result := Default(TIAM4DIdentityProviderMapperType);
  Result.ID := JSONText(AJSON, 'id');
  Result.Name := JSONText(AJSON, 'name');
  Result.Category := JSONText(AJSON, 'category');
  Result.HelpText := JSONText(AJSON, 'helpText');
  if AJSON.TryGetValue<TJSONArray>('properties', LProperties) then
    for LProperty in LProperties do
      if LProperty is TJSONObject then
        Result.Properties := Result.Properties + [ConfigPropertyFromJSON(TJSONObject(LProperty))];
end;

{ TIAM4DKeycloakIdentityProviderManager }

function TIAM4DKeycloakIdentityProviderManager.GetInstancesURL: string;
begin
  Result := GetAdminURL + '/identity-provider/instances';
end;

function TIAM4DKeycloakIdentityProviderManager.GetInstanceURL(const AAlias: string): string;
begin
  Result := GetInstancesURL + '/' + EncodePathSegment(AAlias);
end;

function TIAM4DKeycloakIdentityProviderManager.GetMappersURL(const AAlias: string): string;
begin
  Result := GetInstanceURL(AAlias) + '/mappers';
end;

function TIAM4DKeycloakIdentityProviderManager.GetInstance(const AHTTPClient: THTTPClient; const AAlias: string;
  out AResponse: IHTTPResponse): Boolean;
var
  LURL: string;
begin
  LURL := GetInstanceURL(AAlias);
  AResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
  if AResponse.StatusCode = IAM4D_HTTP_STATUS_NOT_FOUND then
    Exit(False);
  EnsureResponseSuccess(AResponse, 'Get identity provider', LURL, IAM4D_HTTP_METHOD_GET);
  Result := True;
end;

function TIAM4DKeycloakIdentityProviderManager.TryGetInternal(
  const AHTTPClient: THTTPClient;
  const AAlias: string;
  out AIdentityProvider: TIAM4DIdentityProvider): Boolean;
var
  LResponse: IHTTPResponse;
  LJSON: TJSONObject;
begin
  AIdentityProvider := Default(TIAM4DIdentityProvider);
  Result := GetInstance(AHTTPClient, AAlias, LResponse);
  if not Result then
    Exit;

  LJSON := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'identity provider response');
  try
    AIdentityProvider := TIAM4DIdentityProviderJSON.IdentityProviderFromJSON(LJSON);
  finally
    LJSON.Free;
  end;
end;

function TIAM4DKeycloakIdentityProviderManager.GetPage(const AHTTPClient: THTTPClient; const ASearch: string;
  const AFirst, AMax: Integer): TArray<TIAM4DIdentityProvider>;
var
  LURL: string;
  LResponse: IHTTPResponse;
begin
  LURL := GetInstancesURL + '?';
  if not ASearch.IsEmpty then
    LURL := LURL + 'search=' + TNetEncoding.URL.Encode(ASearch) + '&';
  LURL := LURL + 'first=' + AFirst.ToString + '&max=' + AMax.ToString;

  LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
  EnsureResponseSuccess(LResponse, 'Get identity providers', LURL, IAM4D_HTTP_METHOD_GET);
  Result := ParseJSONArray<TIAM4DIdentityProvider>(LResponse.ContentAsString, 'identity providers response',
    TIAM4DIdentityProviderJSON.IdentityProviderFromJSON);
end;

procedure TIAM4DKeycloakIdentityProviderManager.SendIdentityProvider(const AHTTPClient: THTTPClient;
  const AURL, AMethod: string; const AJSON: TJSONObject; const AContext: string);
var
  LResponse: IHTTPResponse;
begin
  LResponse := SendJSONRequest(AHTTPClient, AURL, AMethod, AJSON);
  // Keycloak < 26 rejects the unknown field (400 "Unrecognized field"): it reads config hideOnLoginPage
  if (LResponse.StatusCode = IAM4D_HTTP_STATUS_BAD_REQUEST) and
     LResponse.ContentAsString.Contains('Unrecognized field') and
     LResponse.ContentAsString.Contains(IAM4D_IDP_FIELD_HIDE_ON_LOGIN) then
  begin
    AJSON.RemovePair(IAM4D_IDP_FIELD_HIDE_ON_LOGIN).Free;
    LResponse := SendJSONRequest(AHTTPClient, AURL, AMethod, AJSON);
  end;
  EnsureResponseSuccess(LResponse, AContext, AURL, AMethod);
end;

procedure TIAM4DKeycloakIdentityProviderManager.CreateInternal(
  const AHTTPClient: THTTPClient;
  const AIdentityProvider: TIAM4DIdentityProvider);
var
  LJSON: TJSONObject;
begin
  ValidateNoSecretMask(AIdentityProvider, False);

  LJSON := TIAM4DIdentityProviderJSON.IdentityProviderToJSON(AIdentityProvider);
  try
    // Keycloak would reuse it (primary key): a copy of a read provider fails with 409
    LJSON.RemovePair(IAM4D_IDP_FIELD_INTERNAL_ID).Free;
    SendIdentityProvider(AHTTPClient, GetInstancesURL, IAM4D_HTTP_METHOD_POST, LJSON,
      Format('Create identity provider "%s"', [AIdentityProvider.Alias]));
  finally
    LJSON.Free;
  end;
end;

procedure TIAM4DKeycloakIdentityProviderManager.UpdateInternal(
  const AHTTPClient: THTTPClient;
  const AIdentityProvider: TIAM4DIdentityProvider);
var
  LJSON: TJSONObject;
begin
  ValidateNoSecretMask(AIdentityProvider, True);

  LJSON := TIAM4DIdentityProviderJSON.IdentityProviderToJSON(AIdentityProvider);
  try
    SendIdentityProvider(AHTTPClient, GetInstanceURL(AIdentityProvider.Alias), IAM4D_HTTP_METHOD_PUT, LJSON,
      Format('Update identity provider "%s"', [AIdentityProvider.Alias]));
  finally
    LJSON.Free;
  end;
end;

function TIAM4DKeycloakIdentityProviderManager.GetIdentityProviders: TArray<TIAM4DIdentityProvider>;
begin
  Result := ExecuteWithAuth<TArray<TIAM4DIdentityProvider>>(
    function(AHTTPClient: THTTPClient): TArray<TIAM4DIdentityProvider>
    var
      LPage: TArray<TIAM4DIdentityProvider>;
    begin
      // Keycloak 24+ returns 100 providers when first/max are missing
      Result := nil;
      repeat
        LPage := GetPage(AHTTPClient, '', Length(Result), IAM4D_DEFAULT_PAGE_SIZE);
        // A server that ignores first/max sends the first page again
        if (Length(Result) > 0) and (Length(LPage) > 0) and (LPage[0].Alias = Result[0].Alias) then
          Break;
        Result := Result + LPage;
      until Length(LPage) < IAM4D_DEFAULT_PAGE_SIZE;
    end);
end;

function TIAM4DKeycloakIdentityProviderManager.GetIdentityProviders(const ASearch: string;
  const AFirst, AMax: Integer): TArray<TIAM4DIdentityProvider>;
begin
  if AFirst < 0 then
    raise EIAM4DInvalidConfigurationException.Create(Format('First result cannot be negative (%d)', [AFirst]));
  if AMax < 1 then
    raise EIAM4DInvalidConfigurationException.Create(Format('Max results must be 1 or more (%d)', [AMax]));

  Result := ExecuteWithAuth<TArray<TIAM4DIdentityProvider>>(
    function(AHTTPClient: THTTPClient): TArray<TIAM4DIdentityProvider>
    begin
      Result := GetPage(AHTTPClient, ASearch.Trim, AFirst, AMax);
    end);
end;

function TIAM4DKeycloakIdentityProviderManager.GetIdentityProvider(const AAlias: string): TIAM4DIdentityProvider;
var
  LResult: TIAM4DIdentityProviderTryResult;
begin
  LResult := TryGetIdentityProvider(AAlias);
  if not LResult.Found then
    raise EIAM4DHTTPNotFoundException.CreateFromResponse(IAM4D_HTTP_STATUS_NOT_FOUND, '',
      Format('Identity provider "%s" not found', [AAlias]));
  Result := LResult.IdentityProvider;
end;

function TIAM4DKeycloakIdentityProviderManager.TryGetIdentityProvider(
  const AAlias: string): TIAM4DIdentityProviderTryResult;
begin
  ValidateAlias(AAlias);

  Result := ExecuteWithAuth<TIAM4DIdentityProviderTryResult>(
    function(AHTTPClient: THTTPClient): TIAM4DIdentityProviderTryResult
    begin
      Result.Found := TryGetInternal(AHTTPClient, AAlias, Result.IdentityProvider);
    end);
end;

procedure TIAM4DKeycloakIdentityProviderManager.CreateIdentityProvider(
  const AIdentityProvider: TIAM4DIdentityProvider);
begin
  ValidateIdentityProvider(AIdentityProvider);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    begin
      CreateInternal(AHTTPClient, AIdentityProvider);
    end);
end;

procedure TIAM4DKeycloakIdentityProviderManager.UpdateIdentityProvider(
  const AIdentityProvider: TIAM4DIdentityProvider);
begin
  ValidateIdentityProvider(AIdentityProvider);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    begin
      UpdateInternal(AHTTPClient, AIdentityProvider);
    end);
end;

procedure TIAM4DKeycloakIdentityProviderManager.SaveIdentityProvider(
  const AIdentityProvider: TIAM4DIdentityProvider);
begin
  ValidateIdentityProvider(AIdentityProvider);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LResponse: IHTTPResponse;
    begin
      if GetInstance(AHTTPClient, AIdentityProvider.Alias, LResponse) then
        UpdateInternal(AHTTPClient, AIdentityProvider)
      else
        CreateInternal(AHTTPClient, AIdentityProvider);
    end);
end;

procedure TIAM4DKeycloakIdentityProviderManager.DeleteIdentityProvider(const AAlias: string);
begin
  ValidateAlias(AAlias);

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LURL: string;
    begin
      LURL := GetInstanceURL(AAlias);
      EnsureResponseSuccess(TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodDelete, LURL),
        Format('Delete identity provider "%s"', [AAlias]), LURL, IAM4D_HTTP_METHOD_DELETE);
    end);
end;

function TIAM4DKeycloakIdentityProviderManager.IsProviderInstalled(const AProviderID: string): Boolean;
begin
  ValidateAlias(AProviderID, 'Provider ID');

  Result := ExecuteWithAuth<Boolean>(
    function(AHTTPClient: THTTPClient): Boolean
    var
      LURL: string;
      LResponse: IHTTPResponse;
    begin
      LURL := GetAdminURL + '/identity-provider/providers/' + EncodePathSegment(AProviderID.Trim);
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      // Keycloak answers 400 for a provider type it does not have
      if (LResponse.StatusCode = IAM4D_HTTP_STATUS_BAD_REQUEST) or
         (LResponse.StatusCode = IAM4D_HTTP_STATUS_NOT_FOUND) then
        Exit(False);
      EnsureResponseSuccess(LResponse, Format('Get identity provider type "%s"', [AProviderID]), LURL,
        IAM4D_HTTP_METHOD_GET);
      Result := True;
    end);
end;

function TIAM4DKeycloakIdentityProviderManager.ImportConfig(
  const AProviderID: string;
  const AFromURL: string): TIAM4DConfigMap;
begin
  if AProviderID.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('ProviderID cannot be empty');
  if AFromURL.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Metadata URL cannot be empty');

  Result := ExecuteWithAuth<TIAM4DConfigMap>(
    function(AHTTPClient: THTTPClient): TIAM4DConfigMap
    var
      LRequest: TJSONObject;
      LResponse: IHTTPResponse;
      LJSON: TJSONObject;
    begin
      LRequest := TJSONObject.Create;
      try
        LRequest.AddPair('providerId', AProviderID.Trim);
        LRequest.AddPair('fromUrl', AFromURL.Trim);
        LResponse := ExecuteJSONRequest(AHTTPClient, GetAdminURL + '/identity-provider/import-config',
          IAM4D_HTTP_METHOD_POST, LRequest, 'Import identity provider config');
      finally
        LRequest.Free;
      end;

      LJSON := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'import config response');
      try
        Result := TIAM4DIdentityProviderJSON.ConfigFromJSON(LJSON);
      finally
        LJSON.Free;
      end;
    end);
end;

function TIAM4DKeycloakIdentityProviderManager.ExportServiceProviderMetadata(const AAlias: string): string;
begin
  ValidateAlias(AAlias);

  Result := ExecuteWithAuth<string>(
    function(AHTTPClient: THTTPClient): string
    var
      LURL: string;
      LResponse: IHTTPResponse;
    begin
      LURL := GetInstanceURL(AAlias) + '/export';
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      EnsureResponseSuccess(LResponse,
        Format('Export service provider metadata of "%s"', [AAlias]), LURL, IAM4D_HTTP_METHOD_GET);
      Result := LResponse.ContentAsString(TEncoding.UTF8);
    end);
end;

function TIAM4DKeycloakIdentityProviderManager.GetMappers(
  const AIdentityProviderAlias: string): TArray<TIAM4DIdentityProviderMapper>;
begin
  ValidateAlias(AIdentityProviderAlias);

  Result := ExecuteWithAuth<TArray<TIAM4DIdentityProviderMapper>>(
    function(AHTTPClient: THTTPClient): TArray<TIAM4DIdentityProviderMapper>
    var
      LURL: string;
      LResponse: IHTTPResponse;
    begin
      LURL := GetMappersURL(AIdentityProviderAlias);
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      EnsureResponseSuccess(LResponse,
        Format('Get mappers of identity provider "%s"', [AIdentityProviderAlias]), LURL, IAM4D_HTTP_METHOD_GET);
      Result := ParseJSONArray<TIAM4DIdentityProviderMapper>(LResponse.ContentAsString,
        'identity provider mappers response', TIAM4DIdentityProviderJSON.MapperFromJSON);
    end);
end;

function TIAM4DKeycloakIdentityProviderManager.GetMapper(const AIdentityProviderAlias: string;
  const AMapperID: string): TIAM4DIdentityProviderMapper;
begin
  ValidateAlias(AIdentityProviderAlias);
  ValidateAlias(AMapperID, 'Identity provider mapper ID');

  Result := ExecuteWithAuth<TIAM4DIdentityProviderMapper>(
    function(AHTTPClient: THTTPClient): TIAM4DIdentityProviderMapper
    var
      LURL: string;
      LResponse: IHTTPResponse;
      LJSON: TJSONObject;
    begin
      LURL := GetMappersURL(AIdentityProviderAlias) + '/' + EncodePathSegment(AMapperID);
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      EnsureResponseSuccess(LResponse, Format('Get identity provider mapper "%s"', [AMapperID]), LURL,
        IAM4D_HTTP_METHOD_GET);

      LJSON := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'identity provider mapper response');
      try
        Result := TIAM4DIdentityProviderJSON.MapperFromJSON(LJSON);
      finally
        LJSON.Free;
      end;
      // Keycloak looks the ID up in the whole realm
      if Result.IdentityProviderAlias <> AIdentityProviderAlias then
        raise EIAM4DHTTPNotFoundException.CreateFromResponse(IAM4D_HTTP_STATUS_NOT_FOUND, '',
          Format('Identity provider "%s" has no mapper "%s"', [AIdentityProviderAlias, AMapperID]));
    end);
end;

function TIAM4DKeycloakIdentityProviderManager.GetMapperTypes(
  const AIdentityProviderAlias: string): TArray<TIAM4DIdentityProviderMapperType>;
begin
  ValidateAlias(AIdentityProviderAlias);

  Result := ExecuteWithAuth<TArray<TIAM4DIdentityProviderMapperType>>(
    function(AHTTPClient: THTTPClient): TArray<TIAM4DIdentityProviderMapperType>
    var
      LURL: string;
      LResponse: IHTTPResponse;
      LJSON: TJSONObject;
      LPair: TJSONPair;
    begin
      LURL := GetInstanceURL(AIdentityProviderAlias) + '/mapper-types';
      LResponse := TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodGet, LURL);
      EnsureResponseSuccess(LResponse,
        Format('Get mapper types of identity provider "%s"', [AIdentityProviderAlias]), LURL, IAM4D_HTTP_METHOD_GET);

      // Map of mapper type ID to its representation
      Result := nil;
      LJSON := TIAM4DJSONUtils.SafeParseJSONObject(LResponse.ContentAsString, 'mapper types response');
      try
        for LPair in LJSON do
          if LPair.JsonValue is TJSONObject then
            Result := Result + [TIAM4DIdentityProviderJSON.MapperTypeFromJSON(TJSONObject(LPair.JsonValue))];
      finally
        LJSON.Free;
      end;
      TArray.Sort<TIAM4DIdentityProviderMapperType>(Result, TComparer<TIAM4DIdentityProviderMapperType>.Construct(
        function(const ALeft, ARight: TIAM4DIdentityProviderMapperType): Integer
        begin
          Result := CompareStr(ALeft.ID, ARight.ID);
        end));
    end);
end;

function TIAM4DKeycloakIdentityProviderManager.CreateMapper(const AMapper: TIAM4DIdentityProviderMapper): string;
begin
  ValidateMapper(AMapper);

  Result := ExecuteWithAuth<string>(
    function(AHTTPClient: THTTPClient): string
    var
      LJSON: TJSONObject;
    begin
      LJSON := TIAM4DIdentityProviderJSON.MapperToJSON(AMapper);
      try
        // Keycloak would reuse it (primary key): a copy of a read mapper fails with 409
        LJSON.RemovePair(IAM4D_IDP_MAPPER_FIELD_ID).Free;
        Result := ExecuteJSONRequestWithLocation(AHTTPClient, GetMappersURL(AMapper.IdentityProviderAlias), LJSON,
          Format('Create identity provider mapper "%s"', [AMapper.Name]));
      finally
        LJSON.Free;
      end;
    end);
end;

procedure TIAM4DKeycloakIdentityProviderManager.UpdateMapper(const AMapper: TIAM4DIdentityProviderMapper);
begin
  ValidateMapper(AMapper);
  ValidateAlias(AMapper.ID, 'Identity provider mapper ID');

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LJSON: TJSONObject;
    begin
      LJSON := TIAM4DIdentityProviderJSON.MapperToJSON(AMapper);
      try
        ExecuteJSONRequest(AHTTPClient,
          GetMappersURL(AMapper.IdentityProviderAlias) + '/' + EncodePathSegment(AMapper.ID),
          IAM4D_HTTP_METHOD_PUT, LJSON, Format('Update identity provider mapper "%s"', [AMapper.Name]));
      finally
        LJSON.Free;
      end;
    end);
end;

procedure TIAM4DKeycloakIdentityProviderManager.DeleteMapper(
  const AIdentityProviderAlias: string;
  const AMapperID: string);
begin
  ValidateAlias(AIdentityProviderAlias);
  ValidateAlias(AMapperID, 'Identity provider mapper ID');

  ExecuteWithAuthVoid(
    procedure(AHTTPClient: THTTPClient)
    var
      LURL: string;
    begin
      LURL := GetMappersURL(AIdentityProviderAlias) + '/' + EncodePathSegment(AMapperID);
      EnsureResponseSuccess(TIAM4DHTTPClientFactory.Execute(AHTTPClient, sHTTPMethodDelete, LURL),
        Format('Delete identity provider mapper "%s"', [AMapperID]), LURL, IAM4D_HTTP_METHOD_DELETE);
    end);
end;

end.
