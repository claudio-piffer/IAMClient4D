unit MainModule;

interface

uses
  uniGUIMainModule,
  SysUtils,
  Classes,
  IAMClient4D.Core,
  ServerModule;

type
  TUniMainModule = class(TUniGUIMainModule)
    procedure UniGUIMainModuleBeforeLogin(Sender: TObject; var Handled: Boolean);
  private
    FIAMClient: IIAM4DClient;
    function GetIAMClientManager: TIAMClientManager;
  public
    property IAMClient: IIAM4DClient read FIAMClient write FIAMClient;
    property IAMClientManager: TIAMClientManager read GetIAMClientManager;
  end;

function UniMainModule: TUniMainModule;

implementation

{$R *.dfm}

uses
  UniGUIVars,
  uniGUIApplication,
  Async.Core,
  IAMClient4D.Config.Builder;

function UniMainModule: TUniMainModule;
begin
  Result := TUniMainModule(UniApplication.UniMainModule)
end;

function TUniMainModule.GetIAMClientManager: TIAMClientManager;
begin
  Result := UniServerModule.IAMClientManager;
end;

procedure TUniMainModule.UniGUIMainModuleBeforeLogin(Sender: TObject; var Handled: Boolean);
var
  LCallBackFrom: string;
  LCode: string;
  LState: string;
  LAccessToken: string;
begin
  LCallBackFrom := TUniGUIApplication(UniApplication).Parameters.Values['oauthcallback'];
  if not (LCallBackFrom.Trim.IsEmpty) and (LCallBackFrom = 'keycloak') then
  begin
    LCode := TUniGUIApplication(UniApplication).Parameters.Values['code'];
    LState := TUniGUIApplication(UniApplication).Parameters.Values['state'];
    if ((LCallBackFrom <> EmptyStr) and (LCode <> EmptyStr) and (LState <> EmptyStr)) then
    begin
      Self.IAMClient := Self.IAMClientManager.GetClient(LState);
      LAccessToken := UniMainModule.IAMClient.CompleteAuthorizationFlowAsync(LCode, LState)
        .Run
        .WaitForResult;
      Self.IAMClientManager.RemoveClient(LState);
      Handled := True;
    end;
  end;
end;

initialization
  RegisterMainModuleClass(TUniMainModule);
end.

