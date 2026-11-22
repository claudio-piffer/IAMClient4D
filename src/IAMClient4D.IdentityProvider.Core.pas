{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.IdentityProvider.Core.pas
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

  Identity brokering types: the identity providers Keycloak delegates the login
  to (Microsoft Entra ID, SPID, CIE, any OIDC/SAML provider) and their mappers.

  One record describes every provider, as Keycloak does: only ProviderID and the
  Config map change. Use the builders of IAMClient4D.IdentityProvider.Builders
  to fill it for a specific broker.

  ---------------------------------------------------------------------------
}

unit IAMClient4D.IdentityProvider.Core;

interface

uses
  System.SysUtils,
  Async.Core;

const
  /// <summary>Keycloak generic OpenID Connect provider (used for Microsoft Entra ID).</summary>
  IAM4D_IDP_PROVIDER_OIDC = 'oidc';
  /// <summary>Keycloak generic SAML 2.0 provider.</summary>
  IAM4D_IDP_PROVIDER_SAML = 'saml';
  /// <summary>Keycloak generic OAuth 2.0 provider (no id_token: the user profile comes from the user info endpoint).</summary>
  IAM4D_IDP_PROVIDER_OAUTH2 = 'oauth2';

  /// <summary>
  /// Value Keycloak returns in place of the client secret. Sent back on update (config clientSecret only),
  /// it keeps the stored secret; create rejects it, since Keycloak would store it as the secret.
  /// Keycloak 26.8.1+ answers 400 to the mask when client ID, token URL, client authentication or other
  /// destination settings change: send the real secret then.
  /// </summary>
  IAM4D_IDP_SECRET_MASK = '**********';
  /// <summary>Config key of the OIDC client secret: the only one Keycloak masks and restores.</summary>
  IAM4D_IDP_CONFIG_CLIENT_SECRET = 'clientSecret';

type
  /// <summary>
  /// How Keycloak updates the brokered user at each login (config key syncMode).
  /// </summary>
  /// <remarks>
  /// ismDefault leaves the key unset (Keycloak default).
  /// ismImport: data imported at first login only. ismForce: data updated at every login.
  /// ismLegacy: behaviour of Keycloak versions before sync modes. ismInherit: mappers only, follows the provider.
  /// </remarks>
  TIAM4DIdentityProviderSyncMode = (ismDefault, ismImport, ismLegacy, ismForce, ismInherit);

  TIAM4DIdentityProviderSyncModeHelper = record helper for TIAM4DIdentityProviderSyncMode
    /// <summary>Keycloak string ('IMPORT', 'LEGACY', 'FORCE', 'INHERIT'; empty for ismDefault).</summary>
    function ToString: string;
    /// <summary>Parses the Keycloak string (case-insensitive); empty or unknown gives ismDefault.</summary>
    class function FromString(const AValue: string): TIAM4DIdentityProviderSyncMode; static;
  end;

  /// <summary>
  /// Entry of a Keycloak config map.
  /// </summary>
  TIAM4DConfigEntry = record
    Key: string;
    Value: string;
  end;

  /// <summary>
  /// Keycloak config map (Map&lt;String, String&gt;) as a record: no objects to free.
  /// </summary>
  /// <remarks>
  /// Keys are case-sensitive, as in Keycloak. Copies are independent: writing one never changes another.
  /// Booleans are stored as 'true'/'false', lists as Keycloak expects them (see the builders).
  /// </remarks>
  TIAM4DConfigMap = record
  private
    FEntries: TArray<TIAM4DConfigEntry>;
    function IndexOf(const AKey: string): Integer;
    function GetValue(const AKey: string): string;
    procedure SetValue(const AKey: string; const AValue: string);
    function GetCount: Integer;
  public
    function Contains(const AKey: string): Boolean;
    function TryGetValue(const AKey: string; out AValue: string): Boolean;
    function GetBool(const AKey: string; const ADefault: Boolean = False): Boolean;
    procedure SetBool(const AKey: string; const AValue: Boolean);
    procedure Remove(const AKey: string);
    procedure Clear;
    /// <summary>Copies every entry of ASource, replacing the keys already present.</summary>
    procedure Merge(const ASource: TIAM4DConfigMap);

    /// <summary>Value of AKey; empty if missing. Writing adds or replaces the entry.</summary>
    property Values[const AKey: string]: string read GetValue write SetValue;
    property Entries: TArray<TIAM4DConfigEntry> read FEntries;
    property Count: Integer read GetCount;
  end;

  /// <summary>
  /// Keycloak identity provider (IdentityProviderRepresentation).
  /// </summary>
  /// <remarks>
  /// Alias identifies the provider in the realm: it is the value of kc_idp_hint and part of
  /// the broker redirect URI ({realm URL}/broker/{alias}/endpoint). Keycloak (26) cannot rename it:
  /// create a provider with the new alias and delete the old one (mappers and user links do not move).
  /// Create with TIAM4DIdentityProvider.Create (sets Enabled) or with a builder.
  /// Secrets read from Keycloak are masked (IAM4D_IDP_SECRET_MASK): updating with the mask keeps them,
  /// creating with it is rejected (set the real secret on a copy).
  /// </remarks>
  TIAM4DIdentityProvider = record
  private
    FAlias: string;
    FDisplayName: string;
    FProviderID: string;
    FInternalID: string;
    FEnabled: Boolean;
    FTrustEmail: Boolean;
    FStoreToken: Boolean;
    FAddReadTokenRoleOnCreate: Boolean;
    FLinkOnly: Boolean;
    FHideOnLogin: Boolean;
    FFirstBrokerLoginFlowAlias: string;
    FPostBrokerLoginFlowAlias: string;
    FConfig: TIAM4DConfigMap;
    function GetSyncMode: TIAM4DIdentityProviderSyncMode;
    procedure SetSyncMode(const AValue: TIAM4DIdentityProviderSyncMode);
  public
    /// <summary>
    /// Enabled provider with the given alias and Keycloak provider type (e.g. IAM4D_IDP_PROVIDER_OIDC).
    /// </summary>
    class function Create(const AAlias: string; const AProviderID: string): TIAM4DIdentityProvider; static;

    property Alias: string read FAlias write FAlias;
    /// <summary>Name on the Keycloak login page (the alias if empty).</summary>
    property DisplayName: string read FDisplayName write FDisplayName;
    /// <summary>Keycloak provider type: 'oidc', 'saml', 'spid', 'microsoft', ...</summary>
    property ProviderID: string read FProviderID write FProviderID;
    /// <summary>Keycloak internal ID (set by Keycloak; not sent on create, so a read provider can be copied).</summary>
    property InternalID: string read FInternalID write FInternalID;
    property Enabled: Boolean read FEnabled write FEnabled;
    /// <summary>Emails from this provider are considered verified.</summary>
    property TrustEmail: Boolean read FTrustEmail write FTrustEmail;
    /// <summary>Stores the provider tokens after login.</summary>
    property StoreToken: Boolean read FStoreToken write FStoreToken;
    property AddReadTokenRoleOnCreate: Boolean read FAddReadTokenRoleOnCreate write FAddReadTokenRoleOnCreate;
    /// <summary>Only for linking existing accounts: no login with this provider.</summary>
    property LinkOnly: Boolean read FLinkOnly write FLinkOnly;
    /// <summary>Hidden on the Keycloak login page: reachable only with kc_idp_hint.</summary>
    property HideOnLogin: Boolean read FHideOnLogin write FHideOnLogin;
    property FirstBrokerLoginFlowAlias: string read FFirstBrokerLoginFlowAlias write FFirstBrokerLoginFlowAlias;
    property PostBrokerLoginFlowAlias: string read FPostBrokerLoginFlowAlias write FPostBrokerLoginFlowAlias;
    /// <summary>Provider-specific settings (endpoints, client ID/secret, certificates, ...).</summary>
    property Config: TIAM4DConfigMap read FConfig write FConfig;
    /// <summary>Config key syncMode.</summary>
    property SyncMode: TIAM4DIdentityProviderSyncMode read GetSyncMode write SetSyncMode;
  end;

  TIAM4DIdentityProviderTryResult = record
    Found: Boolean;
    IdentityProvider: TIAM4DIdentityProvider;
  end;

  /// <summary>
  /// Keycloak identity provider mapper (IdentityProviderMapperRepresentation): imports claims or
  /// SAML attributes into user attributes, roles or groups.
  /// </summary>
  TIAM4DIdentityProviderMapper = record
  private
    FID: string;
    FName: string;
    FIdentityProviderAlias: string;
    FMapperType: string;
    FConfig: TIAM4DConfigMap;
  public
    /// <summary>
    /// Mapper of the given type for the provider AIdentityProviderAlias.
    /// </summary>
    class function Create(const AIdentityProviderAlias, AName, AMapperType: string): TIAM4DIdentityProviderMapper; static;

    /// <summary>Keycloak ID (set by Keycloak on create; not sent on create, so a read mapper can be copied).</summary>
    property ID: string read FID write FID;
    property Name: string read FName write FName;
    property IdentityProviderAlias: string read FIdentityProviderAlias write FIdentityProviderAlias;
    /// <summary>Keycloak mapper type, e.g. 'oidc-user-attribute-idp-mapper' (see GetMapperTypes).</summary>
    property MapperType: string read FMapperType write FMapperType;
    property Config: TIAM4DConfigMap read FConfig write FConfig;
  end;

  /// <summary>
  /// Setting of a mapper type (Keycloak ConfigPropertyRepresentation): a key of the mapper config.
  /// </summary>
  TIAM4DConfigProperty = record
    /// <summary>Config key.</summary>
    Name: string;
    DisplayLabel: string;
    HelpText: string;
    /// <summary>Keycloak property type: 'String', 'boolean', 'List', 'Role', ...</summary>
    PropertyType: string;
    DefaultValue: string;
    /// <summary>Allowed values of a 'List' property.</summary>
    Options: TArray<string>;
    Secret: Boolean;
    Required: Boolean;
    ReadOnly: Boolean;
  end;

  /// <summary>
  /// Mapper type available for an identity provider (Keycloak IdentityProviderMapperTypeRepresentation).
  /// </summary>
  TIAM4DIdentityProviderMapperType = record
    /// <summary>Value of TIAM4DIdentityProviderMapper.MapperType.</summary>
    ID: string;
    Name: string;
    Category: string;
    HelpText: string;
    Properties: TArray<TIAM4DConfigProperty>;
  end;

  /// <summary>
  /// Keycloak identity provider management (synchronous).
  /// </summary>
  /// <remarks>
  /// API: /admin/realms/{realm}/identity-provider. The admin token needs the realm-management
  /// roles view-identity-providers (read) and manage-identity-providers (write).
  /// For VCL/FMX use IIAM4DIdentityProviderManagerAsync.
  /// Errors: invalid arguments EIAM4DInvalidConfigurationException; HTTP failures
  /// EIAM4DHTTPClientErrorException (403 EIAM4DInsufficientPermissionsException, 404 EIAM4DHTTPNotFoundException,
  /// 409 EIAM4DHTTPConflictException, e.g. duplicate alias) or EIAM4DHTTPServerErrorException.
  /// Keycloak 26+ gets HideOnLogin as the hideOnLogin field; earlier versions, which reject that field,
  /// get it as config hideOnLoginPage (the request is sent again without the field).
  /// </remarks>
  IIAM4DIdentityProviderManager = interface
    ['{5E0C2A7D-3B8F-4C1E-9A64-7D2F0B8E1C35}']
    /// <summary>All providers of the realm, read page by page (Keycloak 24+ returns 100 per request).</summary>
    function GetIdentityProviders: TArray<TIAM4DIdentityProvider>; overload;
    /// <summary>
    /// One page of providers. ASearch: alias filter, prefix by default ('name*'), '*name*' contains,
    /// '"name"' exact; empty for all. AFirst: offset (0 or more); AMax: page size (1 or more).
    /// </summary>
    function GetIdentityProviders(const ASearch: string; const AFirst, AMax: Integer): TArray<TIAM4DIdentityProvider>; overload;
    /// <exception cref="EIAM4DHTTPNotFoundException">Raised when the provider does not exist</exception>
    function GetIdentityProvider(const AAlias: string): TIAM4DIdentityProvider;
    function TryGetIdentityProvider(const AAlias: string): TIAM4DIdentityProviderTryResult;
    /// <summary>
    /// Creates the provider. InternalID is not sent (Keycloak assigns a new one); a config value equal to
    /// IAM4D_IDP_SECRET_MASK raises EIAM4DInvalidConfigurationException.
    /// </summary>
    procedure CreateIdentityProvider(const AIdentityProvider: TIAM4DIdentityProvider);
    /// <summary>
    /// Updates the provider with that alias (the alias cannot change). IAM4D_IDP_SECRET_MASK is accepted
    /// in clientSecret only (Keycloak keeps the stored secret); in any other key it raises
    /// EIAM4DInvalidConfigurationException. Keycloak 26.8.1+ rejects the mask (400) when the update
    /// changes client ID, token URL, client authentication or other destination settings.
    /// </summary>
    procedure UpdateIdentityProvider(const AIdentityProvider: TIAM4DIdentityProvider);
    /// <summary>Creates the provider, or updates it if the alias exists (rules of Create and Update).</summary>
    procedure SaveIdentityProvider(const AIdentityProvider: TIAM4DIdentityProvider);
    procedure DeleteIdentityProvider(const AAlias: string);

    /// <summary>
    /// True if Keycloak has the provider type AProviderID (e.g. IAM4D_IDP_PROVIDER_SPID: the SPID extension
    /// is installed). Needs view-identity-providers.
    /// </summary>
    function IsProviderInstalled(const AProviderID: string): Boolean;

    /// <summary>
    /// Reads OIDC discovery or SAML metadata from AFromURL and returns the config Keycloak derives
    /// from it (endpoints, certificates), ready to merge into a provider config.
    /// </summary>
    function ImportConfig(const AProviderID: string; const AFromURL: string): TIAM4DConfigMap;

    /// <summary>
    /// Keycloak's SAML service provider descriptor of one SAML-based provider (identity-provider/instances/
    /// {alias}/export): the XML to register with a generic SAML identity provider.
    /// </summary>
    /// <remarks>
    /// Not for SPID and CIE: the export has none of the contacts (IPA code, VAT number, billing) AgID
    /// requires. Register the metadata the extensions publish instead, at
    /// TIAM4DSpidIdPBuilder.ServiceProviderMetadataURL (all SPID providers of the realm) and
    /// TIAM4DCieIdPBuilder.ServiceProviderMetadataURL.
    /// </remarks>
    function ExportServiceProviderMetadata(const AAlias: string): string;

    function GetMappers(const AIdentityProviderAlias: string): TArray<TIAM4DIdentityProviderMapper>;
    /// <exception cref="EIAM4DHTTPNotFoundException">Raised when the provider has no mapper with that ID</exception>
    function GetMapper(const AIdentityProviderAlias: string; const AMapperID: string): TIAM4DIdentityProviderMapper;
    /// <summary>Mapper types the provider supports, with their settings, ordered by ID.</summary>
    function GetMapperTypes(const AIdentityProviderAlias: string): TArray<TIAM4DIdentityProviderMapperType>;
    /// <summary>Creates the mapper and returns its ID. The ID of AMapper is not sent (Keycloak assigns one).</summary>
    function CreateMapper(const AMapper: TIAM4DIdentityProviderMapper): string;
    procedure UpdateMapper(const AMapper: TIAM4DIdentityProviderMapper);
    procedure DeleteMapper(const AIdentityProviderAlias: string; const AMapperID: string);
  end;

  /// <summary>
  /// Keycloak identity provider management (asynchronous), for VCL/FMX applications.
  /// </summary>
  IIAM4DIdentityProviderManagerAsync = interface
    ['{9B41D6E2-0F7A-4E83-B25C-6A1E3D9F4C70}']
    function GetIdentityProvidersAsync: IAsyncPromise<TArray<TIAM4DIdentityProvider>>; overload;
    function GetIdentityProvidersAsync(const ASearch: string; const AFirst, AMax: Integer): IAsyncPromise<TArray<TIAM4DIdentityProvider>>; overload;
    function GetIdentityProviderAsync(const AAlias: string): IAsyncPromise<TIAM4DIdentityProvider>;
    function TryGetIdentityProviderAsync(const AAlias: string): IAsyncPromise<TIAM4DIdentityProviderTryResult>;
    function CreateIdentityProviderAsync(const AIdentityProvider: TIAM4DIdentityProvider): IAsyncVoidPromise;
    function UpdateIdentityProviderAsync(const AIdentityProvider: TIAM4DIdentityProvider): IAsyncVoidPromise;
    function SaveIdentityProviderAsync(const AIdentityProvider: TIAM4DIdentityProvider): IAsyncVoidPromise;
    function DeleteIdentityProviderAsync(const AAlias: string): IAsyncVoidPromise;
    function IsProviderInstalledAsync(const AProviderID: string): IAsyncPromise<Boolean>;
    function ImportConfigAsync(const AProviderID: string; const AFromURL: string): IAsyncPromise<TIAM4DConfigMap>;
    function ExportServiceProviderMetadataAsync(const AAlias: string): IAsyncPromise<string>;
    function GetMappersAsync(const AIdentityProviderAlias: string): IAsyncPromise<TArray<TIAM4DIdentityProviderMapper>>;
    function GetMapperAsync(const AIdentityProviderAlias: string; const AMapperID: string): IAsyncPromise<TIAM4DIdentityProviderMapper>;
    function GetMapperTypesAsync(const AIdentityProviderAlias: string): IAsyncPromise<TArray<TIAM4DIdentityProviderMapperType>>;
    function CreateMapperAsync(const AMapper: TIAM4DIdentityProviderMapper): IAsyncPromise<string>;
    function UpdateMapperAsync(const AMapper: TIAM4DIdentityProviderMapper): IAsyncVoidPromise;
    function DeleteMapperAsync(const AIdentityProviderAlias: string; const AMapperID: string): IAsyncVoidPromise;
  end;

implementation

const
  IAM4D_IDP_CONFIG_SYNC_MODE = 'syncMode';

{ TIAM4DIdentityProviderSyncModeHelper }

function TIAM4DIdentityProviderSyncModeHelper.ToString: string;
begin
  case Self of
    ismImport: Result := 'IMPORT';
    ismLegacy: Result := 'LEGACY';
    ismForce: Result := 'FORCE';
    ismInherit: Result := 'INHERIT';
  else
    Result := '';
  end;
end;

class function TIAM4DIdentityProviderSyncModeHelper.FromString(const AValue: string): TIAM4DIdentityProviderSyncMode;
begin
  if SameText(AValue, 'IMPORT') then
    Result := ismImport
  else if SameText(AValue, 'LEGACY') then
    Result := ismLegacy
  else if SameText(AValue, 'FORCE') then
    Result := ismForce
  else if SameText(AValue, 'INHERIT') then
    Result := ismInherit
  else
    Result := ismDefault;
end;

{ TIAM4DConfigMap }

function TIAM4DConfigMap.IndexOf(const AKey: string): Integer;
begin
  for Result := 0 to High(FEntries) do
    if FEntries[Result].Key = AKey then
      Exit;
  Result := -1;
end;

function TIAM4DConfigMap.GetValue(const AKey: string): string;
begin
  if not TryGetValue(AKey, Result) then
    Result := '';
end;

procedure TIAM4DConfigMap.SetValue(const AKey: string; const AValue: string);
var
  LIndex: Integer;
begin
  if AKey.IsEmpty then
    raise EArgumentException.Create('Config key cannot be empty');

  // Dynamic arrays are shared between record copies: write to a private copy
  FEntries := Copy(FEntries);
  LIndex := IndexOf(AKey);
  if LIndex < 0 then
  begin
    LIndex := Length(FEntries);
    SetLength(FEntries, LIndex + 1);
    FEntries[LIndex].Key := AKey;
  end;
  FEntries[LIndex].Value := AValue;
end;

function TIAM4DConfigMap.GetCount: Integer;
begin
  Result := Length(FEntries);
end;

function TIAM4DConfigMap.Contains(const AKey: string): Boolean;
begin
  Result := IndexOf(AKey) >= 0;
end;

function TIAM4DConfigMap.TryGetValue(const AKey: string; out AValue: string): Boolean;
var
  LIndex: Integer;
begin
  LIndex := IndexOf(AKey);
  Result := LIndex >= 0;
  if Result then
    AValue := FEntries[LIndex].Value
  else
    AValue := '';
end;

function TIAM4DConfigMap.GetBool(const AKey: string; const ADefault: Boolean): Boolean;
var
  LValue: string;
begin
  if TryGetValue(AKey, LValue) and not LValue.Trim.IsEmpty then
    Result := SameText(LValue.Trim, 'true')
  else
    Result := ADefault;
end;

procedure TIAM4DConfigMap.SetBool(const AKey: string; const AValue: Boolean);
begin
  if AValue then
    SetValue(AKey, 'true')
  else
    SetValue(AKey, 'false');
end;

procedure TIAM4DConfigMap.Remove(const AKey: string);
var
  LIndex: Integer;
begin
  LIndex := IndexOf(AKey);
  if LIndex < 0 then
    Exit;
  FEntries := Copy(FEntries);
  Delete(FEntries, LIndex, 1);
end;

procedure TIAM4DConfigMap.Clear;
begin
  FEntries := nil;
end;

procedure TIAM4DConfigMap.Merge(const ASource: TIAM4DConfigMap);
var
  LEntry: TIAM4DConfigEntry;
begin
  for LEntry in ASource.FEntries do
    SetValue(LEntry.Key, LEntry.Value);
end;

{ TIAM4DIdentityProvider }

class function TIAM4DIdentityProvider.Create(const AAlias: string; const AProviderID: string): TIAM4DIdentityProvider;
begin
  Result := Default(TIAM4DIdentityProvider);
  Result.FAlias := AAlias.Trim;
  Result.FProviderID := AProviderID.Trim;
  Result.FEnabled := True;
end;

function TIAM4DIdentityProvider.GetSyncMode: TIAM4DIdentityProviderSyncMode;
begin
  Result := TIAM4DIdentityProviderSyncMode.FromString(FConfig.Values[IAM4D_IDP_CONFIG_SYNC_MODE]);
end;

procedure TIAM4DIdentityProvider.SetSyncMode(const AValue: TIAM4DIdentityProviderSyncMode);
begin
  if AValue = ismDefault then
    FConfig.Remove(IAM4D_IDP_CONFIG_SYNC_MODE)
  else
    FConfig.Values[IAM4D_IDP_CONFIG_SYNC_MODE] := AValue.ToString;
end;

{ TIAM4DIdentityProviderMapper }

class function TIAM4DIdentityProviderMapper.Create(
  const AIdentityProviderAlias, AName, AMapperType: string): TIAM4DIdentityProviderMapper;
begin
  Result := Default(TIAM4DIdentityProviderMapper);
  Result.FIdentityProviderAlias := AIdentityProviderAlias.Trim;
  Result.FName := AName;
  Result.FMapperType := AMapperType;
end;

end.
