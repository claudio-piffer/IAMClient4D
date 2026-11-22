unit IdentityBrokering.Common;

// Helpers shared by the VCL and FMX IdentityBrokering samples

interface

uses
  IAMClient4D.IdentityProvider.Core;

const
  // CIE simulator of the sample environment (Docker/, profile brokering) as Keycloak reaches it
  // (Docker network); the endpoints in its metadata are browser URLs (http://localhost:18444)
  CCieSimulatorMetadataURL = 'http://cie-simulator:18444/demo/metadata.xml';

/// <summary>Pretty-printed JSON; the text itself if it is not JSON.</summary>
function FormatJSON(const AText: string): string;

/// <summary>Payload of a JWT as formatted JSON. Display only: it is decoded, not verified.</summary>
function DecodeJWTPayload(const AToken: string): string;

/// <summary>
/// True when the access token has the realm-management role view-identity-providers or
/// manage-identity-providers, either one lists the identity providers. realm-admin counts too: Keycloak
/// writes the roles of a composite role in the token.
/// </summary>
/// <remarks>
/// To show or hide the administration only: the token is decoded, not verified, and the Admin REST API
/// checks the permission at every call. A permission given with fine-grained admin permissions is not a role
/// in the token: such a user gets False.
/// </remarks>
function CanViewIdentityProviders(const AAccessToken: string): Boolean;

/// <summary>Attribute mappers of a SPID provider: fiscalNumber, email, firstName, lastName.</summary>
function SpidAttributeMappers(const AAlias: string): TArray<TIAM4DIdentityProviderMapper>;

/// <summary>Attribute mappers of a CIE ID provider: fiscalNumber, firstName, lastName.</summary>
function CieAttributeMappers(const AAlias: string): TArray<TIAM4DIdentityProviderMapper>;

implementation

uses
  System.SysUtils,
  System.JSON,
  System.NetEncoding,
  IAMClient4D.IdentityProvider.Builders;

function FormatJSON(const AText: string): string;
var
  LJSON: TJSONValue;
begin
  LJSON := TJSONObject.ParseJSONValue(AText);
  if LJSON = nil then
    Exit(AText);
  try
    Result := LJSON.Format(2);
  finally
    LJSON.Free;
  end;
end;

// JSON text of the payload of a JWT, decoded and not verified; empty if it is not a JWT
function JWTPayloadText(const AToken: string): string;
var
  LParts: TArray<string>;
  LPayload: string;
begin
  LParts := AToken.Split(['.']);
  if Length(LParts) < 2 then
    Exit('');
  LPayload := LParts[1].Replace('-', '+').Replace('_', '/');
  while LPayload.Length mod 4 <> 0 do
    LPayload := LPayload + '=';
  Result := TEncoding.UTF8.GetString(TNetEncoding.Base64.DecodeStringToBytes(LPayload));
end;

// Display only: the payload is decoded, not verified
function DecodeJWTPayload(const AToken: string): string;
var
  LPayload: string;
begin
  LPayload := JWTPayloadText(AToken);
  if LPayload.IsEmpty then
    Exit('(not a JWT)');
  Result := FormatJSON(LPayload);
end;

function CanViewIdentityProviders(const AAccessToken: string): Boolean;
var
  LJSON: TJSONValue;
  LResourceAccess, LRealmManagement: TJSONObject;
  LRoles: TJSONArray;
begin
  Result := False;
  try
    LJSON := TJSONObject.ParseJSONValue(JWTPayloadText(AAccessToken));
  except
    // Not Base64 or not UTF-8: not an access token of Keycloak
    Exit;
  end;
  if LJSON = nil then
    Exit;
  try
    // "resource_access": {"realm-management": {"roles": [...]}}
    if not (LJSON is TJSONObject) or
       not TJSONObject(LJSON).TryGetValue<TJSONObject>('resource_access', LResourceAccess) or
       not LResourceAccess.TryGetValue<TJSONObject>('realm-management', LRealmManagement) or
       not LRealmManagement.TryGetValue<TJSONArray>('roles', LRoles) then
      Exit;
    // Keycloak lists the identity providers to a user with either role
    for var LRole in LRoles do
      if SameText(LRole.Value, 'view-identity-providers') or SameText(LRole.Value, 'manage-identity-providers') then
        Exit(True);
  finally
    LJSON.Free;
  end;
end;

// SPID identity providers return only the attributes requested in the SP metadata, which Keycloak
// derives from the mappers: fiscalNumber is the principal, without its mapper the login fails
function SpidAttributeMappers(const AAlias: string): TArray<TIAM4DIdentityProviderMapper>;
begin
  Result := [
    TIAM4DSpidIdPBuilder.AttributeMapper(AAlias, 'fiscalNumber', 'fiscalNumber'),
    TIAM4DSpidIdPBuilder.AttributeMapper(AAlias, 'email', 'email'),
    TIAM4DSpidIdPBuilder.AttributeMapper(AAlias, 'name', 'firstName'),
    TIAM4DSpidIdPBuilder.AttributeMapper(AAlias, 'familyName', 'lastName')];
end;

// The same for CIE ID, which never returns the email: Keycloak asks for it at the first login
function CieAttributeMappers(const AAlias: string): TArray<TIAM4DIdentityProviderMapper>;
begin
  Result := [
    TIAM4DCieIdPBuilder.AttributeMapper(AAlias, 'fiscalNumber', 'fiscalNumber'),
    TIAM4DCieIdPBuilder.AttributeMapper(AAlias, 'name', 'firstName'),
    TIAM4DCieIdPBuilder.AttributeMapper(AAlias, 'familyName', 'lastName')];
end;

end.
