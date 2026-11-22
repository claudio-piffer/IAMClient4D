unit RuntimeTestControllerU;

interface

uses
  MVCFramework,
  MVCFramework.Commons,
  IAMClient4D.DMVC.Attributes;

type
  [MVCPath('/api/ctrl')]
  TRuntimeTestController = class(TMVCController)
  public
    [MVCPath('/protected')]
    [MVCHTTPMethod([httpGET])]
    function GetProtected: IMVCResponse;

    [MVCPath('/public')]
    [MVCHTTPMethod([httpGET])]
    [IAM4DPublic]
    function GetPublic: IMVCResponse;

    // Public action enforcing authentication itself
    [MVCPath('/publicrequire')]
    [MVCHTTPMethod([httpGET])]
    [IAM4DPublic]
    function GetPublicRequire: IMVCResponse;

    [MVCPath('/admin')]
    [MVCHTTPMethod([httpGET])]
    function GetAdmin: IMVCResponse;

    [MVCPath('/superadmin')]
    [MVCHTTPMethod([httpGET])]
    function GetSuperAdmin: IMVCResponse;

    [MVCPath('/scope')]
    [MVCHTTPMethod([httpGET])]
    function GetScope: IMVCResponse;

    [MVCPath('/items/($id)')]
    [MVCHTTPMethod([httpGET])]
    function GetItem(const id: string): IMVCResponse;

    // No MVCHTTPMethod: answers every verb, OPTIONS included
    [MVCPath('/anyverb')]
    function AnyVerb: IMVCResponse;

    [MVCPath('/anyrole')]
    [MVCHTTPMethod([httpGET])]
    function GetAnyRole: IMVCResponse;

    [MVCPath('/allroles')]
    [MVCHTTPMethod([httpGET])]
    function GetAllRoles: IMVCResponse;

    [MVCPath('/otherclientrole')]
    [MVCHTTPMethod([httpGET])]
    function GetOtherClientRole: IMVCResponse;

    // Role added by the claims transformer of the middleware (not in the token)
    [MVCPath('/dbrole')]
    [MVCHTTPMethod([httpGET])]
    function GetDbRole: IMVCResponse;

    // Not JSON: a 401/503 of IAMClient4D must still be application/problem+json
    [MVCPath('/plain')]
    [MVCHTTPMethod([httpGET])]
    [MVCProduces(TMVCMediaType.TEXT_PLAIN)]
    function GetPlain: string;
  end;

/// <summary>
/// Controller declared in the implementation section: TRttiContext.FindType does not find it, its
/// [IAM4DPublic] cannot be read and the action stays protected
/// </summary>
function HiddenPublicControllerClass: TMVCControllerClazz;

implementation

uses
  System.SysUtils,
  System.DateUtils,
  System.Generics.Collections,
  System.Generics.Defaults,
  MVCFramework.Swagger.Commons,
  IAMClient4D.DMVC.Helpers;

type
  // Out of the Swagger documents: the DMVC generators raise ENonPublicType for this type
  [MVCPath('/api/hidden')]
  [IAM4DPublic]
  [MVCSwagIgnorePath]
  THiddenPublicController = class(TMVCController)
  public
    [MVCPath('/public')]
    [MVCHTTPMethod([httpGET])]
    [MVCSwagIgnorePath]
    function GetPublic: IMVCResponse;
  end;

function THiddenPublicController.GetPublic: IMVCResponse;
begin
  Result := Status(200, 'hidden public ok');
end;

function HiddenPublicControllerClass: TMVCControllerClazz;
begin
  Result := THiddenPublicController;
end;

// Keys of Context.Data, sorted and comma separated
function DataKeys(AContext: TWebContext): string;
var
  LKeys: TList<string>;
  LPair: TPair<string, string>;
begin
  LKeys := TList<string>.Create;
  try
    for LPair in AContext.Data do
      LKeys.Add(LPair.Key);
    LKeys.Sort(TComparer<string>.Construct(
      function(const A, B: string): Integer
      begin
        Result := CompareStr(A, B);
      end));
    Result := string.Join(',', LKeys.ToArray);
  finally
    LKeys.Free;
  end;
end;

function TRuntimeTestController.GetProtected: IMVCResponse;
var
  LUtcNow: TDateTime;
  LAuthTime, LSub: string;
begin
  LUtcNow := TDateTime.NowUTC;
  if not Context.LoggedUser.CustomData.TryGetValue('auth_time', LAuthTime) then
    LAuthTime := '';
  if not Context.LoggedUser.CustomData.TryGetValue('sub', LSub) then
    LSub := '';
  Result := Status(200, 'protected user=' + Context.JWT.PreferredUsername +
    ' logged=' + Context.LoggedUser.UserName +
    ' admin=' + BoolToStr(Context.LoggedUser.Roles.Contains('admin'), True) +
    ' apiRole=' + BoolToStr(Context.LoggedUser.Roles.Contains('api-reader'), True) +
    ' otherClientRole=' + BoolToStr(Context.LoggedUser.Roles.Contains('other-admin'), True) +
    ' group=' + BoolToStr(Context.Keycloak.HasGroup('/staff'), True) +
    ' sub=' + LSub +
    ' authTime=' + LAuthTime +
    ' loggedSinceUtc=' + BoolToStr(Abs(SecondsBetween(Context.LoggedUser.LoggedSince, LUtcNow)) < 120, True) +
    // Every key, so that one serialized and never read shows up
    ' dataKeys=' + DataKeys(Context) + ' ');
end;

function TRuntimeTestController.AnyVerb: IMVCResponse;
begin
  Result := Status(200, 'anyverb ok');
end;

function TRuntimeTestController.GetAnyRole: IMVCResponse;
begin
  Context.RequireAnyRole(['missing', 'user']);
  Result := Status(200, 'anyrole ok');
end;

function TRuntimeTestController.GetAllRoles: IMVCResponse;
begin
  // Realm role and client role of the audience
  Context.RequireAllRoles(['admin', 'api-reader']);
  Result := Status(200, 'allroles ok');
end;

function TRuntimeTestController.GetOtherClientRole: IMVCResponse;
begin
  Context.RequireAnyRole(['other-admin']);
  Result := Status(200, 'otherclientrole ok');
end;

function TRuntimeTestController.GetDbRole: IMVCResponse;
begin
  Context.RequireAnyRole(['db-auditor']);
  Result := Status(200, 'dbrole ok');
end;

function TRuntimeTestController.GetPlain: string;
begin
  Result := 'plain ok';
end;

function TRuntimeTestController.GetPublic: IMVCResponse;
var
  LCount: Integer;
  LSub: string;
begin
  LCount := 0;
  LSub := '';
  if Assigned(Context.LoggedUser.CustomData) then
  begin
    LCount := Context.LoggedUser.CustomData.Count;
    if not Context.LoggedUser.CustomData.TryGetValue('sub', LSub) then
      LSub := '';
  end;
  Result := Status(200, 'public ok authenticated=' + BoolToStr(Context.IsAuthenticated, True) +
    ' user=' + Context.LoggedUser.UserName + ' customData=' + IntToStr(LCount) + ' sub=' + LSub + ' ');
end;

function TRuntimeTestController.GetPublicRequire: IMVCResponse;
begin
  Context.RequireAuthentication;
  Result := Status(200, 'publicrequire ok');
end;

function TRuntimeTestController.GetAdmin: IMVCResponse;
begin
  Context.RequireRealmRole('admin');
  Result := Status(200, 'admin ok');
end;

function TRuntimeTestController.GetSuperAdmin: IMVCResponse;
begin
  Context.RequireRealmRole('superadmin');
  Result := Status(200, 'superadmin ok');
end;

function TRuntimeTestController.GetScope: IMVCResponse;
begin
  Context.RequireScope('write');
  Result := Status(200, 'scope ok');
end;

function TRuntimeTestController.GetItem(const id: string): IMVCResponse;
begin
  Result := Status(200, 'item ' + id);
end;

end.
