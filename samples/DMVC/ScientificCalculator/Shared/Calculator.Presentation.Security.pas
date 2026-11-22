unit Calculator.Presentation.Security;

{ Presentation layer, shared by both servers: the roles of the API and the
  bridge from the token validated by IAMClient4D to the application layer. }

interface

uses
  MVCFramework,
  Calculator.Application.Caller;

const
  // Client roles of the "api-server" client in Keycloak
  ROLE_CALCULATOR_USER = 'calculator-user';
  ROLE_CALCULATOR_ADVANCED = 'calculator-advanced';

type
  /// <summary>Who the token says the caller is (GET /api/me).</summary>
  TUserProfile = class
  private
    FSubject: string;
    FUserName: string;
    FName: string;
    FEmail: string;
    FClientId: string;
    FRoles: TArray<string>;
    FExpiresAt: string;
    FCanUseCalculator: Boolean;
    FCanUseAdvanced: Boolean;
  public
    property Subject: string read FSubject write FSubject;
    property UserName: string read FUserName write FUserName;
    property Name: string read FName write FName;
    property Email: string read FEmail write FEmail;
    /// <summary>Client that obtained the token (azp).</summary>
    property ClientId: string read FClientId write FClientId;
    /// <summary>Roles seen by the API: token roles, realm roles, roles of the audience client.</summary>
    property Roles: TArray<string> read FRoles write FRoles;
    /// <summary>ISO 8601 in UTC.</summary>
    property ExpiresAt: string read FExpiresAt write FExpiresAt;
    property CanUseCalculator: Boolean read FCanUseCalculator write FCanUseCalculator;
    property CanUseAdvanced: Boolean read FCanUseAdvanced write FCanUseAdvanced;
  end;

/// <summary>
/// The authenticated caller. Raises 401 (with a WWW-Authenticate challenge)
/// when the request carries no valid token.
/// </summary>
function CallerOf(const AContext: TWebContext): TCaller;

/// <summary>CallerOf, after checking that the caller has ARole (403 otherwise).</summary>
function CallerWithRole(const AContext: TWebContext; const ARole: string): TCaller;

/// <summary>The profile of the authenticated caller; the caller owns it.</summary>
function UserProfileOf(const AContext: TWebContext): TUserProfile;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  IAMClient4D.DMVC.Helpers;

function CallerOf(const AContext: TWebContext): TCaller;
var
  LUserName: string;
begin
  AContext.RequireAuthentication;
  LUserName := AContext.JWT.PreferredUsername;
  if LUserName.IsEmpty then
    LUserName := AContext.JWT.Email;
  if LUserName.IsEmpty then
    LUserName := AContext.JWT.Subject;
  Result := TCaller.Create(AContext.JWT.Subject, LUserName);
end;

function CallerWithRole(const AContext: TWebContext; const ARole: string): TCaller;
begin
  AContext.RequireAnyRole([ARole]);
  Result := CallerOf(AContext);
end;

function UserProfileOf(const AContext: TWebContext): TUserProfile;
var
  LCaller: TCaller;
begin
  LCaller := CallerOf(AContext);
  Result := TUserProfile.Create;
  Result.Subject := LCaller.Subject;
  Result.UserName := LCaller.UserName;
  Result.Name := AContext.JWT.Name;
  Result.Email := AContext.JWT.Email;
  Result.ClientId := AContext.JWT.AuthorizedParty;
  Result.Roles := AContext.LoggedUser.Roles.ToArray;
  Result.ExpiresAt := DateToISO8601(AContext.JWT.ExpirationTime, True);
  Result.CanUseCalculator := AContext.LoggedUser.Roles.Contains(ROLE_CALCULATOR_USER);
  Result.CanUseAdvanced := AContext.LoggedUser.Roles.Contains(ROLE_CALCULATOR_ADVANCED);
end;

end.
