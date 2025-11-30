unit IAMClient.MainForm;

interface

uses
  Winapi.Windows,
  Winapi.Messages,
  System.SysUtils,
  System.Variants,
  System.Classes,
  Vcl.Graphics,
  Vcl.Controls,
  Vcl.Forms,
  Vcl.Dialogs,
  Vcl.StdCtrls,
  IAMClient4D.Core,
  IAMClient4D.UserManagement.Core,
  IAMClient4D.Config.Builder,
  Vcl.Mask,
  Vcl.ExtCtrls,
  Vcl.ComCtrls,
  System.Actions,
  Vcl.ActnList,
  Async.Core,
  Vcl.WinXCtrls,
  UserManagement;

type
  TMainForm = class(TForm)
    MainPageControl: TPageControl;
    PKCETabSheet: TTabSheet;
    CCTabSheet: TTabSheet;
    Panel1: TPanel;
    PKCEBaseURLLabel: TLabel;
    PKCEBaseURLEdit: TEdit;
    Panel3: TPanel;
    PKCERealmLabel: TLabel;
    PKCERealmEdit: TEdit;
    Panel4: TPanel;
    PKCEClientLabel: TLabel;
    PKCEClientEdit: TEdit;
    Bevel1: TBevel;
    Panel2: TPanel;
    LoginButton: TButton;
    Bevel2: TBevel;
    Panel6: TPanel;
    LoginURLLabel: TLabel;
    LoginURLEdit: TEdit;
    Bevel3: TBevel;
    PKCEMemo: TMemo;
    UserInfoButton: TButton;
    Button1: TButton;
    ActionList1: TActionList;
    LogoutAction: TAction;
    UserInfoAction: TAction;
    VerifyJWTButton: TButton;
    VerifyJWTAction: TAction;
    LoginAction: TAction;
    Button3: TButton;
    AccessTokenAsyncAction: TAction;
    Bevel4: TBevel;
    Bevel5: TBevel;
    CCMemo: TMemo;
    Panel7: TPanel;
    Label5: TLabel;
    CCBaseURLEdit: TEdit;
    Panel8: TPanel;
    Button2: TButton;
    Button5: TButton;
    Button6: TButton;
    Button7: TButton;
    Panel9: TPanel;
    Label6: TLabel;
    CCRealmEdit: TEdit;
    Panel10: TPanel;
    Label7: TLabel;
    CCClientEdit: TEdit;
    LoginCredentialAccess: TAction;
    Panel11: TPanel;
    Label8: TLabel;
    CCClientSecretEdit: TEdit;
    PKCEActivityIndicator: TActivityIndicator;
    UserManagementTabSheet: TTabSheet;
    Panel12: TPanel;
    ConnectToUserManagerAction: TAction;
    GetUserAction: TAction;
    Memo3: TMemo;
    CCActivityIndicator: TActivityIndicator;
    CCLogoutAction: TAction;
    CCAccessTokenAction: TAction;
    CCVerifyJWTAction: TAction;
    UserSampleCreateUserAction: TAction;
    UserByUserNameAction: TAction;
    Panel5: TPanel;
    Button13: TButton;
    Button14: TButton;
    Button15: TButton;
    Button16: TButton;
    Button17: TButton;
    Button18: TButton;
    UpdateUserAction: TAction;
    DeleteUserAction: TAction;
    Button4: TButton;
    CreateMultipleUsersAction: TAction;
    UpdateMultipleUsersAction: TAction;
    Button8: TButton;
    Button9: TButton;
    DeleteMultipleUserAction: TAction;
    Button10: TButton;
    ChangePasswordsAction: TAction;
    Button11: TButton;
    AssignRolesUsersAction: TAction;
    Button12: TButton;
    ClientsRealmAction: TAction;
    Panel13: TPanel;
    Button19: TButton;
    Button20: TButton;
    Button21: TButton;
    Button22: TButton;
    Button24: TButton;
    ChangePasswordAction: TAction;
    RealmRoleAction: TAction;
    UserRolesAction: TAction;
    SearchUserAction: TAction;
    UserFederatedAction: TAction;
    procedure FormDestroy(Sender: TObject);
    procedure AccessTokenAsyncActionExecute(Sender: TObject);
    procedure AccessTokenAsyncActionUpdate(Sender: TObject);
    procedure AssignRolesUsersActionExecute(Sender: TObject);
    procedure AssignRolesUsersActionUpdate(Sender: TObject);
    procedure UpdateMultipleUsersActionExecute(Sender: TObject);
    procedure UpdateMultipleUsersActionUpdate(Sender: TObject);
    procedure CCAccessTokenActionExecute(Sender: TObject);
    procedure CCAccessTokenActionUpdate(Sender: TObject);
    procedure CCLogoutActionExecute(Sender: TObject);
    procedure CCLogoutActionUpdate(Sender: TObject);
    procedure CCVerifyJWTActionExecute(Sender: TObject);
    procedure CCVerifyJWTActionUpdate(Sender: TObject);
    procedure ChangePasswordActionExecute(Sender: TObject);
    procedure ChangePasswordActionUpdate(Sender: TObject);
    procedure ChangePasswordsActionExecute(Sender: TObject);
    procedure ChangePasswordsActionUpdate(Sender: TObject);
    procedure ClientsRealmActionExecute(Sender: TObject);
    procedure ClientsRealmActionUpdate(Sender: TObject);
    procedure ConnectToUserManagerActionExecute(Sender: TObject);
    procedure ConnectToUserManagerActionUpdate(Sender: TObject);
    procedure CreateMultipleUsersActionExecute(Sender: TObject);
    procedure CreateMultipleUsersActionUpdate(Sender: TObject);
    procedure DeleteMultipleUserActionExecute(Sender: TObject);
    procedure DeleteMultipleUserActionUpdate(Sender: TObject);
    procedure DeleteUserActionExecute(Sender: TObject);
    procedure DeleteUserActionUpdate(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure GetUserActionExecute(Sender: TObject);
    procedure GetUserActionUpdate(Sender: TObject);
    procedure LoginActionExecute(Sender: TObject);
    procedure LoginActionUpdate(Sender: TObject);
    procedure LoginCredentialAccessExecute(Sender: TObject);
    procedure LogoutActionExecute(Sender: TObject);
    procedure LogoutActionUpdate(Sender: TObject);
    procedure RealmRoleActionExecute(Sender: TObject);
    procedure RealmRoleActionUpdate(Sender: TObject);
    procedure SearchUserActionExecute(Sender: TObject);
    procedure SearchUserActionUpdate(Sender: TObject);
    procedure UpdateUserActionExecute(Sender: TObject);
    procedure UpdateUserActionUpdate(Sender: TObject);
    procedure UserByUserNameActionExecute(Sender: TObject);
    procedure UserByUserNameActionUpdate(Sender: TObject);
    procedure UserFederatedActionExecute(Sender: TObject);
    procedure UserFederatedActionUpdate(Sender: TObject);
    procedure UserInfoActionExecute(Sender: TObject);
    procedure UserInfoActionUpdate(Sender: TObject);
    procedure UserRolesActionExecute(Sender: TObject);
    procedure UserRolesActionUpdate(Sender: TObject);
    procedure UserSampleCreateUserActionExecute(Sender: TObject);
    procedure UserSampleCreateUserActionUpdate(Sender: TObject);
    procedure VerifyJWTActionExecute(Sender: TObject);
    procedure VerifyJWTActionUpdate(Sender: TObject);
  private
    FKeycloakClientPKCE: IIAM4DClient;
    FKeycloakClientCredential: IIAM4DClient;
    FUserManagerSamples: TUserManagementSamples;
    FUser: TIAM4DUser;
    procedure DumpIAM4DUserToMemo(const AUser: TIAM4DUser; AMemo: TMemo);
    procedure DumpIAM4DOperationResultToMemo(const AResult: TIAM4DOperationResult; AMemo: TMemo);
    procedure DumpIAM4DUsersCreateResultToStrings(const AResult: TIAM4DUsersCreateResult; AMemo: TMemo);
    procedure DumpIAM4DRoleToMemo(const ARole: TIAM4DRole; AMemo: TMemo);
    procedure DumpIAM4DRealmClientToMemo(const AClient: TIAM4DRealmClient; AMemo: TMemo);
    procedure DoLogin;
    procedure DoLoginClientCredential;
    procedure ConnectToAdminAPI;
  public
    {Public declarations}
  end;

var
  MainForm: TMainForm;

implementation

{$R *.dfm}

uses
  System.DateUtils,
  System.JSON,
  System.UITypes,
  System.TypInfo,
  IAMClient4D.Keycloak,
  IAMClient4D.Storage.Core,
  IAMClient4D.UserManagement.Keycloak,
  IAMClient4D.Security.Core,
  IAMClient4D.Security.JWT,
  IAMClient4D.Security.JWT.Verifiers.RSA,
  IAMClient4D.Common.Security,
  IAMClient4D.Security.JWT.JWKS;

const
  BASE_MS_TIMEOUT = 10000;

procedure TMainForm.FormDestroy(Sender: TObject);
begin
  FUserManagerSamples.Free;
end;

procedure TMainForm.AccessTokenAsyncActionExecute(Sender: TObject);
begin
  PKCEMemo.Lines.Clear;
  FKeycloakClientPKCE.GetAccessTokenAsync
    .OnSuccess(procedure(const AResult: string)
    begin
      PKCEMemo.Lines.Add(AResult)
    end)
    .OnError(procedure(const E: Exception)
    begin
      ShowMessage(E.Message);
    end).Run;
end;

procedure TMainForm.AccessTokenAsyncActionUpdate(Sender: TObject);
begin
  AccessTokenAsyncAction.Enabled :=
    Assigned(FKeycloakClientPKCE)
    and FKeycloakClientPKCE.IsAuthenticated;
end;

procedure TMainForm.AssignRolesUsersActionExecute(Sender: TObject);
var
  LUsersRoles: TArray<TIAM4DRoleAssignment>;
  LUserID1, LUserID2, LUserID3: string;
  LRoles: TArray<TIAM4DRole>;
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 11: Assign Roles to Multiple Users ::.');
  Memo3.Lines.Add('--------------------------------------------------');
  Memo3.Lines.Add('');

  SetLength(LUsersRoles, 3);
  SetLength(LRoles, 3);

  LUserID1 := FUserManagerSamples.GetUserByUsername('alice.smith').Run.WaitForResult(BASE_MS_TIMEOUT).ID;
  LUserID2 := FUserManagerSamples.GetUserByUsername('bob.jones').Run.WaitForResult(BASE_MS_TIMEOUT).ID;
  LUserID3 := FUserManagerSamples.GetUserByUsername('carol.white').Run.WaitForResult(BASE_MS_TIMEOUT).ID;
  var LClientRoles := FUserManagerSamples.GetClientRoles.Run.WaitForResult(BASE_MS_TIMEOUT);

  LClientRoles.TryGetRoleByName('manage-users', LRoles[0]);
  LClientRoles.TryGetRoleByName('query-users', LRoles[1]);
  LClientRoles.TryGetRoleByName('view-users', LRoles[2]);

  LUsersRoles[0] := TIAM4DRoleAssignment.Create(LUserID1, LRoles);
  LUsersRoles[1] := TIAM4DRoleAssignment.Create(LUserID2, LRoles);
  LUsersRoles[2] := TIAM4DRoleAssignment.Create(LUserID3, LRoles);

  FUserManagerSamples.AssignRolesToMultipleUsers(LUsersRoles)
    .OnSuccess(
    procedure(const AResult: TArray<TIAM4DOperationResult>)
    begin
      for var LResult in AResult do
        DumpIAM4DOperationResultToMemo(LResult, Memo3);
    end)
    .OnError(
    procedure(const E: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to assign roles: %s', [E.Message]));
    end)
    .Run;

end;

procedure TMainForm.AssignRolesUsersActionUpdate(Sender: TObject);
begin
  AssignRolesUsersAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.UpdateMultipleUsersActionExecute(Sender: TObject);
var
  LUpdateItems: TArray<TIAM4DUser>;
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 7: Update Multiple Users with Different Data ::.');
  Memo3.Lines.Add('------------------------------------------------------------');
  Memo3.Lines.Add('');

  SetLength(LUpdateItems, 3);

  LUpdateItems[0] := FUserManagerSamples.GetUserByUsername('alice.smith').Run.WaitForResult(BASE_MS_TIMEOUT);
  LUpdateItems[1] := FUserManagerSamples.GetUserByUsername('bob.jones').Run.WaitForResult(BASE_MS_TIMEOUT);
  LUpdateItems[2] := FUserManagerSamples.GetUserByUsername('carol.white').Run.WaitForResult(BASE_MS_TIMEOUT);

  LUpdateItems[0].Email := 'alice.smith.new@example.com';
  LUpdateItems[0].Enabled := True;
  LUpdateItems[0].AddAttribute('department', ['Sales', 'Business Development']);

  LUpdateItems[1].FirstName := 'Robert';
  LUpdateItems[1].LastName := 'Jones Jr.';

  LUpdateItems[2].Enabled := False;
  LUpdateItems[2].AddAttribute('location', ['Remote']);
  LUpdateItems[2].AddAttribute('status', ['On Leave']);

  FUserManagerSamples.UpdateMultipleUsers(LUpdateItems)
    .OnSuccess(procedure(const AResult: TArray<TIAM4DOperationResult>)
    begin
      for var LResult in AResult do
        DumpIAM4DOperationResultToMemo(LResult, Memo3);
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to update users:%s%s', [sLineBreak, AException.Message]));
    end)
    .Run;
end;

procedure TMainForm.UpdateMultipleUsersActionUpdate(Sender: TObject);
begin
  UpdateMultipleUsersAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.DoLogin;
begin
  Screen.Cursor := crHourGlass;
  FKeycloakClientPKCE.StartAuthorizationFlowAsync()
    .OnSuccess(procedure(const AAccessToken: string)
    begin
      PKCEMemo.Lines.Clear;
      PKCEMemo.Lines.Add(AAccessToken);
    end)
    .OnError(procedure(const E: Exception)
    begin
      PKCEActivityIndicator.Animate := False;
      ShowMessage('Authentication error: ' + E.Message);
    end)
    .OnFinally(procedure
    begin
      PKCEActivityIndicator.Animate := False;
      Screen.Cursor := crDefault;
    end)
    .Run;
end;

procedure TMainForm.DoLoginClientCredential;
begin
  FKeycloakClientCredential.AuthenticateClientAsync
    .OnSuccess(procedure(const AAccessToken: string)
    begin
      CCMemo.Lines.Clear;
      CCMemo.Lines.Add(AAccessToken);
    end)
    .OnError(procedure(const E: Exception)
    begin
      ShowMessage('Authentication error: ' + E.Message);
    end)
    .OnFinally(
    procedure
    begin
      Screen.Cursor := crDefault;
      CCActivityIndicator.Enabled := False;
    end)
    .Run;
end;

procedure TMainForm.DumpIAM4DOperationResultToMemo(
  const AResult: TIAM4DOperationResult; AMemo: TMemo);
begin
  if AMemo = nil then
    Exit;

  AMemo.Lines.BeginUpdate;
  try
    AMemo.Lines.Add('Identifier   = ' + AResult.Identifier);
    AMemo.Lines.Add('Success      = ' + BoolToStr(AResult.Success, True));
    AMemo.Lines.Add('ErrorMessage = ' + AResult.ErrorMessage);
    AMemo.Lines.Add('-----------------------------------------------------------------');
  finally
    AMemo.Lines.EndUpdate;
  end;
end;

procedure TMainForm.DumpIAM4DRealmClientToMemo(const AClient: TIAM4DRealmClient; AMemo: TMemo);
var
  LIndex: Integer;
  LRole: TIAM4DRole;
begin
  if AMemo = nil then
    Exit;

  AMemo.Lines.BeginUpdate;
  try
    AMemo.Lines.Add('ID          = ' + AClient.ID);
    AMemo.Lines.Add('ClientID    = ' + AClient.ClientID);
    AMemo.Lines.Add('Name        = ' + AClient.Name);
    AMemo.Lines.Add('Description = ' + AClient.Description);
    AMemo.Lines.Add('Enabled     = ' + BoolToStr(AClient.Enabled, True));
    AMemo.Lines.Add('');

    AMemo.Lines.Add('Roles:');
    if Length(AClient.Roles) = 0 then
      AMemo.Lines.Add('  (none)')
    else
    begin
      for LIndex := Low(AClient.Roles) to High(AClient.Roles) do
      begin
        LRole := AClient.Roles[LIndex];
        AMemo.Lines.Add(Format('  [%d] Name=%s, ID=%s, Composite=%s',
          [LIndex,
            LRole.Name,
            LRole.ID,
            BoolToStr(LRole.Composite, True)]));
        if not LRole.Description.IsEmpty then
          AMemo.Lines.Add('       Description=' + LRole.Description);
      end;
    end;
    AMemo.Lines.Add('-----------------------------------------------------------------');
  finally
    AMemo.Lines.EndUpdate;
  end;
end;

procedure TMainForm.DumpIAM4DRoleToMemo(const ARole: TIAM4DRole; AMemo: TMemo);
begin
  if AMemo = nil then
    Exit;

  AMemo.Lines.BeginUpdate;
  try
    AMemo.Lines.Add('ID          = ' + ARole.ID);
    AMemo.Lines.Add('Name        = ' + ARole.Name);
    AMemo.Lines.Add('Description = ' + ARole.Description);
    AMemo.Lines.Add('Composite   = ' + BoolToStr(ARole.Composite, True));
    AMemo.Lines.Add('-----------------------------------------------------------------');
  finally
    AMemo.Lines.EndUpdate;
  end;
end;

procedure TMainForm.DumpIAM4DUsersCreateResultToStrings(const AResult: TIAM4DUsersCreateResult; AMemo: TMemo);
begin
  if AMemo = nil then
    Exit;

  AMemo.Lines.BeginUpdate;
  try
    AMemo.Lines.Add('Username     = ' + AResult.Username);
    AMemo.Lines.Add('ID           = ' + AResult.ID);
    AMemo.Lines.Add('Success      = ' + BoolToStr(AResult.Success, True));
    AMemo.Lines.Add('ErrorMessage = ' + AResult.ErrorMessage);
    AMemo.Lines.Add('-----------------------------------------------------------------');
  finally
    AMemo.Lines.EndUpdate;
  end;
end;

procedure TMainForm.DumpIAM4DUserToMemo(const AUser: TIAM4DUser; AMemo: TMemo);
var
  LAction: TIAM4DRequiredAction;
  LAttr: TIAM4DUserAttribute;
  LValues: string;
begin
  if AMemo = nil then
    Exit;

  AMemo.Lines.BeginUpdate;
  try
    AMemo.Lines.Add('ID                 = ' + AUser.ID);
    AMemo.Lines.Add('Username           = ' + AUser.Username);
    AMemo.Lines.Add('Email              = ' + AUser.Email);
    AMemo.Lines.Add('FirstName          = ' + AUser.FirstName);
    AMemo.Lines.Add('LastName           = ' + AUser.LastName);
    AMemo.Lines.Add('Enabled            = ' + BoolToStr(AUser.Enabled, True));
    AMemo.Lines.Add('EmailVerified      = ' + BoolToStr(AUser.EmailVerified, True));
    AMemo.Lines.Add('CreatedTimestamp   = ' + AUser.CreatedTimestamp.ToString);

    AMemo.Lines.Add('TemporaryPassword  = ' + AUser.TemporaryPassword);
    AMemo.Lines.Add('RequirePwdChange   = ' + BoolToStr(AUser.RequirePasswordChange, True));
    AMemo.Lines.Add('');

    AMemo.Lines.Add('RequiredActions:');
    if Length(AUser.RequiredActions) = 0 then
      AMemo.Lines.Add('  (none)')
    else
    begin
      for LAction in AUser.RequiredActions do
        AMemo.Lines.Add(
          '  - ' +
          GetEnumName(TypeInfo(TIAM4DRequiredAction), Ord(LAction))
          );
    end;
    AMemo.Lines.Add('');

    AMemo.Lines.Add('Attributes:');
    if Length(AUser.AllAttributes) = 0 then
      AMemo.Lines.Add('  (none)')
    else
    begin
      for LAttr in AUser.AllAttributes do
      begin
        if Length(LAttr.Values) > 0 then
          LValues := string.Join(', ', LAttr.Values)
        else
          LValues := '';

        AMemo.Lines.Add(
          Format('  %s = [%s]', [LAttr.Name, LValues])
          );
      end;
    end;
    AMemo.Lines.Add('-----------------------------------------------------------------');
  finally
    AMemo.Lines.EndUpdate;
  end;
end;

procedure TMainForm.FormCreate(Sender: TObject);
begin
  MainPageControl.ActivePageIndex := 0;
end;

procedure TMainForm.LoginActionExecute(Sender: TObject);
begin
  PKCEActivityIndicator.Animate := True;
  LoginButton.Enabled := False;

  TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(PKCEBaseURLEdit.Text, PKCERealmEdit.Text, PKCEClientEdit.Text)
    .WithAllowSelfSignedSSL
    .BuildAsync
    .OnSuccess(
    procedure(const AClient: IIAM4DClient)
    begin
      FKeycloakClientPKCE := AClient;
      DoLogin;
    end)
  .OnError(procedure(const E: Exception)
    begin
      LoginButton.Enabled := True;
      ShowMessage('Configuration error: ' + E.Message);
    end)
    .OnFinally(procedure
    begin
      Screen.Cursor := crDefault;
      PKCEActivityIndicator.Animate := False;
    end)
    .Run;
end;

procedure TMainForm.LoginActionUpdate(Sender: TObject);
begin
  if Assigned(FKeycloakClientPKCE) then
    LoginAction.Enabled := not (FKeycloakClientPKCE.IsAuthenticated)
  else
    LoginAction.Enabled := True;
end;

procedure TMainForm.LoginCredentialAccessExecute(Sender: TObject);
begin
  Screen.Cursor := crHourGlass;
  CCActivityIndicator.Animate := True;

  TIAM4DClientConfigBuilder.New
    .ForClientCredentials(CCBaseURLEdit.Text, CCRealmEdit.Text, CCClientEdit.Text, CCClientSecretEdit.Text)
    .WithAllowSelfSignedSSL
    .BuildAsync
    .OnSuccess(
    procedure(const AClient: IIAM4DClient)
    begin
      FKeycloakClientCredential := AClient;
      DoLoginClientCredential;
    end)
  .OnError(procedure(const E: Exception)
    begin
      ShowMessage('Configuration error: ' + E.Message);
      LoginButton.Enabled := True;
    end)
    .OnFinally(procedure
    begin
      CCActivityIndicator.Animate := False;
      Screen.Cursor := crDefault;
    end)
    .Run;
end;

procedure TMainForm.LogoutActionExecute(Sender: TObject);
begin
  PKCEMemo.Lines.Clear;
  Screen.Cursor := crHourGlass;

  FKeycloakClientPKCE.LogoutAsync
    .OnSuccess(procedure()
    begin
      Screen.Cursor := crDefault;
    end)
  .OnError(procedure(const E: Exception)
    begin
      ShowMessage(E.Message);
    end).Run
end;

procedure TMainForm.LogoutActionUpdate(Sender: TObject);
begin
  LogoutAction.Enabled :=
    Assigned(FKeycloakClientPKCE)
    and FKeycloakClientPKCE.IsAuthenticated;
end;

procedure TMainForm.UserInfoActionExecute(Sender: TObject);
begin
  PKCEMemo.Lines.Clear;
  FKeycloakClientPKCE.GetUserInfoAsync
    .OnSuccess(procedure(const AUserInfo: TIAM4DUserInfo)
    begin
      PKCEMemo.Lines.Add('=== User Info ===');
      PKCEMemo.Lines.Add('Sub: ' + AUserInfo.Sub);
      PKCEMemo.Lines.Add('Preferred Username: ' + AUserInfo.PreferredUsername);
      PKCEMemo.Lines.Add('Name: ' + AUserInfo.Name);
      PKCEMemo.Lines.Add('Email: ' + AUserInfo.Email);
      PKCEMemo.Lines.Add('Email Verified: ' + BoolToStr(AUserInfo.EmailVerified, True));
      PKCEMemo.Lines.Add('');
      PKCEMemo.Lines.Add('=== Raw JSON ===');
      PKCEMemo.Lines.Add(AUserInfo.RawJSON);
    end)
    .OnError(procedure(const E: Exception)
    begin
      ShowMessage('Errore: ' + E.Message);
    end)
    .Run;
end;

procedure TMainForm.UserInfoActionUpdate(Sender: TObject);
begin
  UserInfoAction.Enabled :=
    Assigned(FKeycloakClientPKCE)
    and FKeycloakClientPKCE.IsAuthenticated;
end;

procedure TMainForm.VerifyJWTActionExecute(Sender: TObject);
var
  LJWTValidator: IIAM4DJWTValidator;
  LJWKSProvider: IIAM4DJWKSProvider;
  LClaims: TJSONObject;
begin
  PKCEMemo.Lines.Clear;
  PKCEMemo.Lines.Add(FKeycloakClientPKCE.GetAccessTokenAsync.Run.WaitForResult(BASE_MS_TIMEOUT));

  LJWKSProvider := TIAM4DJWKSProvider.GetInstance;

  LJWKSProvider.SetSSLValidationMode(svmAllowSelfSigned);

  LJWTValidator := TIAM4DJWTValidator.Create(
    FKeycloakClientPKCE.Issuer,
    'api-server',
    LJWKSProvider,
    svmAllowSelfSigned);

  if LJWTValidator.ValidateToken(PKCEMemo.Lines.Text, LClaims) then
  begin
    try
      PKCEMemo.Lines.Clear;
      PKCEMemo.Lines.Add(LClaims.ToString);
    finally
      LClaims.Free;
    end;
  end;
end;

procedure TMainForm.VerifyJWTActionUpdate(Sender: TObject);
begin
  VerifyJWTAction.Enabled :=
    Assigned(FKeycloakClientPKCE)
    and FKeycloakClientPKCE.IsAuthenticated;
end;

{ User Management Methods }

procedure TMainForm.ConnectToAdminAPI;
begin
  if Assigned(FKeycloakClientPKCE) and (FKeycloakClientPKCE.IsAuthenticated) then
  begin
    if Assigned(FUserManagerSamples) then
      FUserManagerSamples.Free;
    FUserManagerSamples := TUserManagementSamples.Create(FKeycloakClientPKCE)
  end
  else
  begin
    MessageDlg('To access the user manager, you must be logged in and the user must have the required permissions.', TMsgDlgType.mtError, [TMsgDlgBtn.mbOK], 0);
  end;
end;

procedure TMainForm.CCAccessTokenActionExecute(Sender: TObject);
begin
  CCMemo.Lines.Clear;
  FKeycloakClientCredential.GetAccessTokenAsync
    .OnSuccess(procedure(const AResult: string)
    begin
      CCMemo.Lines.Add(AResult)
    end)
    .OnError(procedure(const E: Exception)
    begin
      ShowMessage(E.Message);
    end).Run;
end;

procedure TMainForm.CCAccessTokenActionUpdate(Sender: TObject);
begin
  CCAccessTokenAction.Enabled :=
    Assigned(FKeycloakClientCredential)
    and FKeycloakClientCredential.IsAuthenticated;
end;

procedure TMainForm.CCLogoutActionExecute(Sender: TObject);
begin
  CCMemo.Lines.Clear;
  Screen.Cursor := crHourGlass;

  FKeycloakClientCredential.LogoutAsync
    .OnError(procedure(const E: Exception)
    begin
      ShowMessage(E.Message);
    end)
    .OnFinally(
    procedure
    begin
      Screen.Cursor := crDefault;
    end)
    .Run
end;

procedure TMainForm.CCLogoutActionUpdate(Sender: TObject);
begin
  if Assigned(FKeycloakClientCredential) then
    CCLogoutAction.Enabled := FKeycloakClientCredential.IsAuthenticated
  else
    CCLogoutAction.Enabled := False;
end;

procedure TMainForm.CCVerifyJWTActionExecute(Sender: TObject);
var
  LJWTValidator: IIAM4DJWTValidator;
  LClaims: TJSONObject;
begin
  LJWTValidator := TIAM4DJWTValidator.Create(FKeycloakClientCredential.Issuer, 'api-server', svmAllowSelfSigned);
  LJWTValidator.ConfigureJWKSFromURL(FKeycloakClientCredential.JWKSUri);
  if LJWTValidator.ValidateToken(CCMemo.Lines.Text, LClaims) then
  begin
    try
      CCMemo.Lines.Clear;
      CCMemo.Lines.Add(LClaims.ToString);
    finally
      LClaims.Free;
    end;
  end;
end;

procedure TMainForm.CCVerifyJWTActionUpdate(Sender: TObject);
begin
  CCVerifyJWTAction.Enabled :=
    Assigned(FKeycloakClientCredential)
    and FKeycloakClientCredential.IsAuthenticated;
end;

procedure TMainForm.ChangePasswordActionExecute(Sender: TObject);
var
  LUserID: string;
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 12: Set User Password === ::.');
  Memo3.Lines.Add('-----------------------------------------');
  Memo3.Lines.Add('');

  LUserID := FUserManagerSamples.GetUserByUsername('alice.smith').Run.WaitForResult(BASE_MS_TIMEOUT).ID;

  FUserManagerSamples.SetUserPassword(LUserID, '12345678', True)
    .OnSuccess(
    procedure
    begin
      Memo3.Lines.Add('Password set as TEMPORARY (user must change on next login)');
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to set password: %s', [AException.Message]));
    end)
    .Run;
end;

procedure TMainForm.ChangePasswordActionUpdate(Sender: TObject);
begin
  ChangePasswordAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.ChangePasswordsActionExecute(Sender: TObject);
var
  LPasswords: TArray<TIAM4DPasswordReset>;
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 9: Set Passwords for Multiple Users ::.');
  Memo3.Lines.Add('---------------------------------------------------');
  Memo3.Lines.Add('');

  SetLength(LPasswords, 3);

  LPasswords[0].UserID := FUserManagerSamples.GetUserByUsername('alice.smith').Run.WaitForResult(BASE_MS_TIMEOUT).ID;
  if LPasswords[0].UserID.Trim.IsEmpty then
    raise Exception.Create('User alice.smith not found!');
  LPasswords[0].Password := 'abcdefgh$';
  LPasswords[0].Temporary := True;

  LPasswords[1].UserID := FUserManagerSamples.GetUserByUsername('bob.jones').Run.WaitForResult(BASE_MS_TIMEOUT).ID;
  if LPasswords[1].UserID.Trim.IsEmpty then
    raise Exception.Create('User bob.jones not found!');
  LPasswords[1].Password := 'abcdefgh$';
  LPasswords[1].Temporary := True;

  LPasswords[2].UserID := FUserManagerSamples.GetUserByUsername('bob.jones').Run.WaitForResult(BASE_MS_TIMEOUT).ID;
  if LPasswords[2].UserID.Trim.IsEmpty then
    raise Exception.Create('User jones not found!');
  LPasswords[2].Password := 'abcdefgh$';
  LPasswords[2].Temporary := True;

  FUserManagerSamples.SetPasswordsForMultipleUsers(LPasswords)
    .OnSuccess(
    procedure(const AResult: TArray<TIAM4DOperationResult>)
    begin
      for var LResult in AResult do
        DumpIAM4DOperationResultToMemo(LResult, Memo3);
    end)
    .OnError(
    procedure(const E: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to set passwords in batch: %s', [E.Message]));
    end)
    .Run;
end;

procedure TMainForm.ChangePasswordsActionUpdate(Sender: TObject);
begin
  ChangePasswordsAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.ClientsRealmActionExecute(Sender: TObject);
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 10: Get client roles ::.');
  Memo3.Lines.Add('------------------------------------');
  Memo3.Lines.Add('');

  FUserManagerSamples.GetClientRoles
    .OnSuccess(
    procedure(const AResponse: TIAM4DRealmClientArray)
    begin
      for var LClientRoles in AResponse do
        DumpIAM4DRealmClientToMemo(LClientRoles, Memo3);
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to get clients: %s', [AException.Message]));
    end)
    .Run;
end;

procedure TMainForm.ClientsRealmActionUpdate(Sender: TObject);
begin
  ClientsRealmAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.ConnectToUserManagerActionExecute(Sender: TObject);
begin
  ConnectToAdminAPI;
end;

procedure TMainForm.ConnectToUserManagerActionUpdate(Sender: TObject);
begin
  ConnectToUserManagerAction.Enabled := not Assigned(FUserManagerSamples);
end;

procedure TMainForm.CreateMultipleUsersActionExecute(Sender: TObject);
var
  LUsers: TArray<TIAM4DUser>;
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 6: Create Multiple Users in Batch ::.');
  Memo3.Lines.Add('-------------------------------------------------');
  Memo3.Lines.Add('');

  SetLength(LUsers, 3);

  LUsers[0] := TIAM4DUser.Create('alice.smith', 'alice@example.com');
  LUsers[0].FirstName := 'Alice';
  LUsers[0].LastName := 'Smith';
  LUsers[0].AddAttribute('department', ['Sales']);
  LUsers[0].AddAttribute('employee_id', ['EMP-20001']);

  LUsers[1] := TIAM4DUser.Create('bob.jones', 'bob@example.com');
  LUsers[1].FirstName := 'Bob';
  LUsers[1].LastName := 'Jones';
  LUsers[1].AddAttribute('department', ['Marketing']);
  LUsers[1].AddAttribute('employee_id', ['EMP-20002']);

  LUsers[2] := TIAM4DUser.Create('carol.white', 'carol@example.com');
  LUsers[2].FirstName := 'Carol';
  LUsers[2].LastName := 'White';
  LUsers[2].AddAttribute('department', ['Engineering']);
  LUsers[2].AddAttribute('employee_id', ['EMP-20003']);

  FUserManagerSamples.CreateMultipleUsers(LUsers)
    .OnSuccess(
    procedure(const AUsersResponse: TArray<TIAM4DUsersCreateResult>)
    begin
      for var LUser in AUsersResponse do
        DumpIAM4DUsersCreateResultToStrings(LUser, Memo3);
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to create users in batch: %s', [AException]));
    end)
    .Run;
end;

procedure TMainForm.CreateMultipleUsersActionUpdate(Sender: TObject);
begin
  CreateMultipleUsersAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.DeleteMultipleUserActionExecute(Sender: TObject);
var
  LUserIDs: TArray<string>;
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 8: Delete Multiple Users ::.');
  Memo3.Lines.Add('----------------------------------------');
  Memo3.Lines.Add('');

  SetLength(LUserIDs, 3);
  LUserIDs[0] := FUserManagerSamples.GetUserByUsername('alice.smith').Run.WaitForResult(BASE_MS_TIMEOUT).ID;
  if LUserIDs[0].Trim.IsEmpty then
    raise Exception.Create('User alice.smith not found!');

  LUserIDs[1] := FUserManagerSamples.GetUserByUsername('bob.jones').Run.WaitForResult(BASE_MS_TIMEOUT).ID;
  if LUserIDs[1].Trim.IsEmpty then
    raise Exception.Create('User bob.jones not found!');

  LUserIDs[2] := FUserManagerSamples.GetUserByUsername('carol.white').Run.WaitForResult(BASE_MS_TIMEOUT).ID;
  if LUserIDs[2].Trim.IsEmpty then
    raise Exception.Create('User carol.white not found!');

  FUserManagerSamples.DeleteMultipleUsers(LUserIDs)
    .OnSuccess(
    procedure(const AResult: TArray<TIAM4DOperationResult>)
    begin
      for var LResult in AResult do
        DumpIAM4DOperationResultToMemo(LResult, Memo3);
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to delete users in batch: %s', [AException.Message]));
    end)
    .Run;
end;

procedure TMainForm.DeleteMultipleUserActionUpdate(Sender: TObject);
begin
  DeleteMultipleUserAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.DeleteUserActionExecute(Sender: TObject);
var
  LIDUser: string;
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 5: Delete User ::.');
  Memo3.Lines.Add('------------------------------');
  Memo3.Lines.Add('');

  LIDUser := FUser.ID;
  if not InputQuery('Get user by ID', 'ID user:', LIDUser) then
    Exit;

  FUserManagerSamples.DeleteUser(LIDUser)
    .OnSuccess(
    procedure
    begin
      Memo3.Lines.Add(Format('User deleted successfully: %s', [LIDUser]));
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to delete user', [AException.Message]));
    end)
    .Run;
end;

procedure TMainForm.DeleteUserActionUpdate(Sender: TObject);
begin
  DeleteUserAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.GetUserActionExecute(Sender: TObject);
var
  LIDUser: string;
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 2: Get User by ID ::.');
  Memo3.Lines.Add('---------------------------------');
  Memo3.Lines.Add('');

  LIDUser := FUser.ID;
  if not InputQuery('Get user by ID', 'ID user:', LIDUser) then
    Exit;

  FUserManagerSamples.GetUserByID(LIDUser)
    .OnSuccess(
    procedure(const AUser: TIAM4DUser)
    begin
      FUser := AUser;

      DumpIAM4DUserToMemo(FUser, Memo3);
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to get user: %s', [AException.Message]));
    end)
    .Run;
end;

procedure TMainForm.GetUserActionUpdate(Sender: TObject);
begin
  GetUserAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.RealmRoleActionExecute(Sender: TObject);
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 13: Get All Realm Roles ::.');
  Memo3.Lines.Add('---------------------------------------');
  Memo3.Lines.Add('');

  FUserManagerSamples.GetAllRealmRoles
    .OnSuccess(
    procedure(const AResult: TArray<TIAM4DRole>)
    begin
      for var LRole in AResult do
        DumpIAM4DRoleToMemo(LRole, Memo3);
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to get user: %s', [AException.Message]));
    end)
    .Run;
end;

procedure TMainForm.RealmRoleActionUpdate(Sender: TObject);
begin
  RealmRoleAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.SearchUserActionExecute(Sender: TObject);
var
  LCriteria: TIAM4DUserSearchCriteria;
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 15/1: Search Users with Criteria (Partial Matching) ::.');
  Memo3.Lines.Add('-------------------------------------------------------------------');
  Memo3.Lines.Add('');

  LCriteria := TIAM4DUserSearchCriteria.Create('claudio', 0, 10);

  FUserManagerSamples.SearchUsers(LCriteria)
    .OnSuccess(
    procedure(const AUsers: TArray<TIAM4DUser>)
    begin
      for var LUser in AUsers do
        DumpIAM4DUserToMemo(LUser, Memo3);
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to update user: %s', [AException.Message]));
    end)
    .Run.WaitForResult(5000);

  Memo3.Lines.Add('.:: Example 15/2: Partial email search  ::.');
  Memo3.Lines.Add('-------------------------------------------');
  Memo3.Lines.Add('');

  LCriteria := TIAM4DUserSearchCriteria.Create;
  LCriteria.Email := 'gmail.com';
  LCriteria.Enabled := True;
  LCriteria.FirstResult := 0;
  LCriteria.MaxResults := 50;

  FUserManagerSamples.SearchUsers(LCriteria)
    .OnSuccess(
    procedure(const AUsers: TArray<TIAM4DUser>)
    begin
      for var LUser in AUsers do
        DumpIAM4DUserToMemo(LUser, Memo3);
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to update user: %s', [AException.Message]));
    end)
    .Run.WaitForResult(5000);
end;

procedure TMainForm.SearchUserActionUpdate(Sender: TObject);
begin
  SearchUserAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.UpdateUserActionExecute(Sender: TObject);
var
  LIDUser: string;
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 4: Update User with Attributes ::.');
  Memo3.Lines.Add('----------------------------------------------');
  Memo3.Lines.Add('');

  LIDUser := FUser.ID;
  if not InputQuery('Get user by ID', 'ID user:', LIDUser) then
    Exit;

  FUser.Email := 'john.doe.updated@example.com';
  FUser.FirstName := 'John';
  FUser.LastName := 'Doe Jr.';
  FUser.Enabled := True;
  FUser.EmailVerified := True;

  FUser.AddAttribute('department', ['Engineering', 'Management']);
  FUser.AddAttribute('employee_id', ['EMP-12345']);
  FUser.AddAttribute('location', ['San Francisco Office']);
  FUser.AddAttribute('phone', ['+1-555-1234']);

  FUserManagerSamples.UpdateUserWithAttributes(FUser)
    .OnSuccess(
    procedure
    begin
      Memo3.Lines.Add('User updated successfully');
      Memo3.Lines.Add('  Updated email to: john.doe.updated@example.com');
      Memo3.Lines.Add('  Updated last name to: Doe Jr.');
      Memo3.Lines.Add('  Updated department to: Engineering, Management');
      Memo3.Lines.Add('  Updated location to: San Francisco Office');
      Memo3.Lines.Add('  Added phone attribute');

      DumpIAM4DUserToMemo(FUser, Memo3);
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to update user: %s', [AException.Message]));
    end)
    .Run;
end;

procedure TMainForm.UpdateUserActionUpdate(Sender: TObject);
begin
  UpdateUserAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.UserByUserNameActionExecute(Sender: TObject);
var
  LUserName: string;
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 3: Get User by Username ::.');
  Memo3.Lines.Add('---------------------------------------');
  Memo3.Lines.Add('');

  LUserName := FUser.Username;
  if not InputQuery('Get user by username', 'User name:', LUserName) then
    Exit;

  FUserManagerSamples.GetUserByUsername(LUserName)
    .OnSuccess(
    procedure(const AUser: TIAM4DUser)
    begin
      if AUser.ID.IsEmpty then
      begin
        Memo3.Lines.Add(Format('[INFO] User not found with username: %s', [LUserName]));
      end
      else
      begin
        FUser := AUser;
        DumpIAM4DUserToMemo(FUser, Memo3);
      end;
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to search user by username: %s', [AException.Message]));
    end)
    .Run;
end;

procedure TMainForm.UserByUserNameActionUpdate(Sender: TObject);
begin
  UserByUserNameAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.UserFederatedActionExecute(Sender: TObject);
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 16: Check if User is Federated ::.');
  Memo3.Lines.Add('----------------------------------------------');
  Memo3.Lines.Add('');

  var LUserID := FUserManagerSamples.GetUserByUsername('claudio.piffer').Run.WaitForResult(BASE_MS_TIMEOUT).ID;

  FUserManagerSamples.CheckIfUserIsFederated(LUserID)
    .OnSuccess(
    procedure(const AIsFederated: Boolean)
    begin
      if AIsFederated then
        Memo3.Lines.Add('User is federated (has external identity providers)')
      else
        Memo3.Lines.Add('[INFO] User is NOT federated (local account only)');
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to get user roles: %s', [AException.Message]));
    end)
    .Run;
end;

procedure TMainForm.UserFederatedActionUpdate(Sender: TObject);
begin
  UserFederatedAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.UserRolesActionExecute(Sender: TObject);
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 14: Get User Roles ::.');
  Memo3.Lines.Add('----------------------------------');
  Memo3.Lines.Add('');

  var LUserID := FUserManagerSamples.GetUserByUsername('alice.smith').Run.WaitForResult(BASE_MS_TIMEOUT).ID;

  FUserManagerSamples.GetUserRoles(LUserID)
    .OnSuccess(
    procedure(const AResult: TArray<TIAM4DRole>)
    begin
      for var LRole in AResult do
        DumpIAM4DRoleToMemo(LRole, Memo3);
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to get user roles: %s', [AException.Message]));
    end)
    .Run;
end;

procedure TMainForm.UserRolesActionUpdate(Sender: TObject);
begin
  UserRolesAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.UserSampleCreateUserActionExecute(Sender: TObject);
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 1: Create User with Custom Attributes ::.');
  Memo3.Lines.Add('-----------------------------------------------------');
  Memo3.Lines.Add('');

  FUser := TIAM4DUser.Create(
    'john.doe',
    'john.doe@example.com');

  FUser.TemporaryPassword := '12345678';

  FUser.FirstName := 'John';
  FUser.LastName := 'Doe';
  FUser.EmailVerified := False;
  FUser.Enabled := True;

  FUser.AddAttribute('department', ['Engineering', 'R&D']);
  FUser.AddAttribute('employee_id', ['EMP-12345']);
  FUser.AddAttribute('location', ['New York Office']);
  FUser.AddAttribute('hire_date', ['2024-01-15']);
  FUser.AddAttribute('skills', ['Delphi', 'Pascal', 'REST APIs']);

  FUser.AddRequiredActions([raVerifyEmail, raUpdateProfile, raConfigureOTP, raTermsAndConditions]);

  FUserManagerSamples.CreateUserWithAttributes(FUser)
    .OnSuccess(
    procedure(const AUserID: string)
    begin
      FUser.ID := AUserID;

      Memo3.Lines.Add(Format('User created successfully with ID: %s', [FUser.ID]));
      Memo3.Lines.Add(Format('Username: %s', [FUser.Username]));
      Memo3.Lines.Add(Format('Email: %s', [FUser.Email]));
      Memo3.Lines.Add('Custom Attributes: department, employee_id, location, hire_date, skills');
      Memo3.Lines.Add('Required Actions (5 total):');
      Memo3.Lines.Add(' - UPDATE_PASSWORD: Change password on first login');
      Memo3.Lines.Add(' - VERIFY_EMAIL: Verify email address');
      Memo3.Lines.Add(' - UPDATE_PROFILE: Complete profile information');
      Memo3.Lines.Add(' - CONFIGURE_TOTP: Set up two-factor authentication');
      Memo3.Lines.Add(' - TERMS_AND_CONDITIONS: Accept terms and conditions');

      DumpIAM4DUserToMemo(FUser, Memo3);
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to create user: %s', [AException.Message]));
    end).Run;
end;

procedure TMainForm.UserSampleCreateUserActionUpdate(Sender: TObject);
begin
  UserSampleCreateUserAction.Enabled := Assigned(FUserManagerSamples);
end;

end.

