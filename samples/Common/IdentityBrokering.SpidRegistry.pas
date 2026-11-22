unit IdentityBrokering.SpidRegistry;

// SPID identity providers from the AgID registry (IAM4D_SPID_REGISTRY_URL)

interface

uses
  System.SysUtils,
  Async.Core;

type
  TSpidRegistryEntry = record
    EntityID: string;
    OrganizationName: string;
    /// <summary>Registry entry as SAML metadata: the URL to pass to ImportConfig.</summary>
    MetadataURL: string;
    /// <summary>Keycloak alias: spid-{second-level domain of the entity ID}, e.g. spid-poste.</summary>
    Alias: string;
  end;

/// <summary>'spid-' + second-level domain of the entity ID: https://posteid.poste.it gives spid-poste.</summary>
function SpidAliasFromEntityID(const AEntityID: string): string;

/// <summary>Active SPID identity providers of the AgID registry, sorted by organization.</summary>
function LoadSpidRegistryAsync: IAsyncPromise<TArray<TSpidRegistryEntry>>;

const
  // Demo identity provider of spid-saml-check in the sample environment (Docker/, profile brokering),
  // not in the AgID registry: metadata URL as Keycloak reaches it (Docker network, SPID_CHECK_PORT),
  // entity ID and endpoints in it as the browser reaches them (http://localhost:18443/demo)
  CSpidCheckMetadataURL = 'http://spid-saml-check:18443/demo/metadata.xml';
  CSpidTestAlias = 'spid-test';

/// <summary>
/// The demo identity provider of the sample environment as a registry entry, alias spid-test (the
/// provider its realm file creates): it can be deleted and saved again like the others.
/// </summary>
function SpidLocalTestEntry: TSpidRegistryEntry;

implementation

uses
  System.JSON,
  System.Net.HttpClient,
  System.Generics.Collections,
  System.Generics.Defaults,
  IAMClient4D.IdentityProvider.Builders;

function SpidAliasFromEntityID(const AEntityID: string): string;
var
  LHost: string;
  LLabels: TArray<string>;
  LPos: Integer;
begin
  LHost := AEntityID.Trim.ToLower;
  LPos := LHost.IndexOf('://');
  if LPos >= 0 then
    LHost := LHost.Substring(LPos + 3);
  LPos := LHost.IndexOfAny(['/', ':', '?']);
  if LPos >= 0 then
    LHost := LHost.Substring(0, LPos);

  LLabels := LHost.Split(['.']);
  if Length(LLabels) >= 2 then
    Result := 'spid-' + LLabels[High(LLabels) - 1]
  else
    Result := 'spid-' + LHost;
end;

function SpidLocalTestEntry: TSpidRegistryEntry;
begin
  Result.EntityID := 'http://localhost:18443/demo';
  Result.OrganizationName := 'SPID test (spid-saml-check)';
  Result.MetadataURL := CSpidCheckMetadataURL;
  Result.Alias := CSpidTestAlias;
end;

// registry_link ends with ?output=json: without the query the registry serves the SAML metadata
function MetadataURLFromRegistryLink(const ALink: string): string;
var
  LPos: Integer;
begin
  Result := ALink.Trim;
  LPos := Result.IndexOf('?');
  if LPos >= 0 then
    Result := Result.Substring(0, LPos);
end;

function ParseRegistry(const AContent: string): TArray<TSpidRegistryEntry>;
var
  LJSON: TJSONValue;
  LItem: TJSONValue;
  LObject: TJSONObject;
  LEntry: TSpidRegistryEntry;
  LEntries: TList<TSpidRegistryEntry>;
begin
  LJSON := TJSONObject.ParseJSONValue(AContent);
  if not (LJSON is TJSONArray) then
  begin
    LJSON.Free;
    raise Exception.Create('AgID registry: unexpected response (JSON array expected)');
  end;

  LEntries := TList<TSpidRegistryEntry>.Create;
  try
    for LItem in TJSONArray(LJSON) do
    begin
      if not (LItem is TJSONObject) then
        Continue;
      LObject := TJSONObject(LItem);
      if SameText(LObject.GetValue<string>('_disabled', 'N'), 'Y') or
         SameText(LObject.GetValue<string>('_deleted', 'N'), 'Y') then
        Continue;

      LEntry.EntityID := LObject.GetValue<string>('entity_id', '');
      LEntry.OrganizationName := LObject.GetValue<string>('organization_name', '');
      LEntry.MetadataURL := MetadataURLFromRegistryLink(LObject.GetValue<string>('registry_link', ''));
      if LEntry.EntityID.IsEmpty or LEntry.MetadataURL.IsEmpty then
        Continue;
      if LEntry.OrganizationName.IsEmpty then
        LEntry.OrganizationName := LEntry.EntityID;
      LEntry.Alias := SpidAliasFromEntityID(LEntry.EntityID);
      LEntries.Add(LEntry);
    end;

    LEntries.Sort(TComparer<TSpidRegistryEntry>.Construct(
      function(const ALeft, ARight: TSpidRegistryEntry): Integer
      begin
        Result := CompareText(ALeft.OrganizationName, ARight.OrganizationName);
      end));
    Result := LEntries.ToArray;
  finally
    LEntries.Free;
    LJSON.Free;
  end;
end;

function LoadSpidRegistryAsync: IAsyncPromise<TArray<TSpidRegistryEntry>>;
begin
  Result := TAsyncCore.New<TArray<TSpidRegistryEntry>>(
    function(const AOperation: IAsyncOperation): TArray<TSpidRegistryEntry>
    var
      LHTTP: THTTPClient;
      LResponse: IHTTPResponse;
    begin
      LHTTP := THTTPClient.Create;
      try
        LHTTP.ConnectionTimeout := 10000;
        LHTTP.ResponseTimeout := 30000;
        LResponse := LHTTP.Get(IAM4D_SPID_REGISTRY_URL);
        if LResponse.StatusCode <> 200 then
          raise Exception.CreateFmt('AgID registry: HTTP %d %s', [LResponse.StatusCode, LResponse.StatusText]);
        Result := ParseRegistry(LResponse.ContentAsString(TEncoding.UTF8));
        LResponse := nil;
      finally
        LHTTP.Free;
      end;
    end);
end;

end.
