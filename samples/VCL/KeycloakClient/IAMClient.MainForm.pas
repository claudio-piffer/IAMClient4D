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
  IAMClient4D.IdentityProvider.Core,
  IAMClient4D.Config.Builder,
  Vcl.Mask,
  Vcl.ExtCtrls,
  Vcl.ComCtrls,
  System.Actions,
  Vcl.ActnList,
  Async.Core,
  Vcl.WinXCtrls,
  Samples.PendingOperations,
  UserManagement;

type
  // Admin example that needs existing users (looked up by TMainForm.RunWithUsers)
  TUsersExample = reference to procedure(const AUsers: TArray<TIAM4DUser>);

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
    RevokeButton: TButton;
    ActionList1: TActionList;
    LogoutAction: TAction;
    RevokeAction: TAction;
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
    IdPPanel: TPanel;
    IdPLabel: TLabel;
    IdPComboBox: TComboBox;
    IdPButtonsPanel: TPanel;
    IdPListButton: TButton;
    IdPSaveEntraButton: TButton;
    IdPDeleteButton: TButton;
    IdPListAction: TAction;
    IdPSaveEntraAction: TAction;
    IdPDeleteAction: TAction;
    Panel14: TPanel;
    Label1: TLabel;
    AUDEdit: TEdit;
    CancelLoginButton: TButton;
    CancelLoginAction: TAction;
    procedure FormDestroy(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure ActionList1Update(Action: TBasicAction; var Handled: Boolean);
    procedure AccessTokenAsyncActionExecute(Sender: TObject);
    procedure AccessTokenAsyncActionUpdate(Sender: TObject);
    procedure AssignRolesUsersActionExecute(Sender: TObject);
    procedure AssignRolesUsersActionUpdate(Sender: TObject);
    procedure UpdateMultipleUsersActionExecute(Sender: TObject);
    procedure UpdateMultipleUsersActionUpdate(Sender: TObject);
    procedure CancelLoginActionExecute(Sender: TObject);
    procedure CancelLoginActionUpdate(Sender: TObject);
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
    procedure RevokeActionExecute(Sender: TObject);
    procedure RevokeActionUpdate(Sender: TObject);
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
    procedure IdPListActionExecute(Sender: TObject);
    procedure IdPSaveEntraActionExecute(Sender: TObject);
    procedure IdPDeleteActionExecute(Sender: TObject);
    procedure IdPActionUpdate(Sender: TObject);
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
    FIdentityProviderManager: IIAM4DIdentityProviderManagerAsync;
    FUser: TIAM4DUser;
    FLoginOperation: IAsyncOperation<string>;
    // Every asynchronous call: the form closes when the last one has ended
    FPending: TPendingOperations;
    procedure DumpIAM4DUserToMemo(const AUser: TIAM4DUser; AMemo: TMemo);
    procedure DumpIAM4DOperationResultToMemo(const AResult: TIAM4DOperationResult; AMemo: TMemo);
    procedure DumpIAM4DUsersCreateResultToStrings(const AResult: TIAM4DUsersCreateResult; AMemo: TMemo);
    procedure DumpIAM4DRoleToMemo(const ARole: TIAM4DRole; AMemo: TMemo);
    procedure DumpIAM4DRealmClientToMemo(const AClient: TIAM4DRealmClient; AMemo: TMemo);
    procedure DoLogin;
    procedure ShowSession(const AAccessToken: string);
    procedure DoLoginClientCredential;
    procedure ConnectToAdminAPI;
    procedure RunWithUsers(const AUsernames: TArray<string>; const AExample: TUsersExample);
    procedure AssignClientRoles(const AUsers: TArray<TIAM4DUser>; const AClientRoles: TIAM4DRealmClientArray);
    procedure SearchUsersByEmail;
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
  IAMClient4D.IdentityProvider.Keycloak.Async,
  IAMClient4D.IdentityProvider.Builders,
  IAMClient4D.Security.Core,
  IAMClient4D.Security.JWT,
  IAMClient4D.Security.JWT.Verifiers.RSA,
  IAMClient4D.Common.Security,
  IAMClient4D.Security.JWT.JWKS;

procedure TMainForm.FormDestroy(Sender: TObject);
begin
  FUserManagerSamples.Free;
end;

procedure TMainForm.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  // Operations still running (login, logout, admin calls...): cancel the login and close when
  // the last OnFinally has run, so that no callback runs on a destroyed form
  CanClose := FPending.CloseQuery(FLoginOperation);
end;

procedure TMainForm.ActionList1Update(Action: TBasicAction; var Handled: Boolean);
begin
  // Closing: no new operation
  if FPending.CloseRequested then
  begin
    (Action as TCustomAction).Enabled := False;
    Handled := True;
  end;
end;

procedure TMainForm.AccessTokenAsyncActionExecute(Sender: TObject);
begin
  PKCEMemo.Lines.Clear;
  FPending.BeginOperation;
  FKeycloakClientPKCE.GetAccessTokenAsync
    .OnSuccess(procedure(const AResult: string)
    begin
      PKCEMemo.Lines.Add(AResult)
    end)
    .OnError(procedure(const E: Exception)
    begin
      ShowMessage(E.Message);
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.AccessTokenAsyncActionUpdate(Sender: TObject);
begin
  AccessTokenAsyncAction.Enabled :=
    Assigned(FKeycloakClientPKCE)
    and FKeycloakClientPKCE.IsAuthenticated;
end;

procedure TMainForm.AssignRolesUsersActionExecute(Sender: TObject);
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 11: Assign Roles to Multiple Users ::.');
  Memo3.Lines.Add('--------------------------------------------------');
  Memo3.Lines.Add('');

  RunWithUsers(['alice.smith', 'bob.jones', 'carol.white'],
    procedure(const AUsers: TArray<TIAM4DUser>)
    begin
      // Then the client roles: every step is asynchronous
      FPending.BeginOperation;
      FUserManagerSamples.GetClientRoles
        .OnSuccess(
        procedure(const AClientRoles: TIAM4DRealmClientArray)
        begin
          if not FPending.CloseRequested then
            AssignClientRoles(AUsers, AClientRoles);
        end)
        .OnError(
        procedure(const AException: Exception)
        begin
          Memo3.Lines.Add(Format('Failed to get clients: %s', [AException.Message]));
        end)
        .OnFinally(FPending.EndOperation)
        .Run;
    end);
end;

procedure TMainForm.AssignClientRoles(const AUsers: TArray<TIAM4DUser>; const AClientRoles: TIAM4DRealmClientArray);
var
  LUsersRoles: TArray<TIAM4DRoleAssignment>;
  LRoles: TArray<TIAM4DRole>;
  LIndex: Integer;
begin
  SetLength(LRoles, 3);
  AClientRoles.TryGetRoleByName('manage-users', LRoles[0]);
  AClientRoles.TryGetRoleByName('query-users', LRoles[1]);
  AClientRoles.TryGetRoleByName('view-users', LRoles[2]);

  SetLength(LUsersRoles, Length(AUsers));
  for LIndex := 0 to High(AUsers) do
    LUsersRoles[LIndex] := TIAM4DRoleAssignment.Create(AUsers[LIndex].ID, LRoles);

  FPending.BeginOperation;
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
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.AssignRolesUsersActionUpdate(Sender: TObject);
begin
  AssignRolesUsersAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.UpdateMultipleUsersActionExecute(Sender: TObject);
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 7: Update Multiple Users with Different Data ::.');
  Memo3.Lines.Add('------------------------------------------------------------');
  Memo3.Lines.Add('');

  RunWithUsers(['alice.smith', 'bob.jones', 'carol.white'],
    procedure(const AUsers: TArray<TIAM4DUser>)
    var
      LUpdateItems: TArray<TIAM4DUser>;
    begin
      LUpdateItems := Copy(AUsers);

      LUpdateItems[0].Email := 'alice.smith.new@example.com';
      LUpdateItems[0].Enabled := True;
      LUpdateItems[0].AddAttribute('department', ['Sales', 'Business Development']);

      LUpdateItems[1].FirstName := 'Robert';
      LUpdateItems[1].LastName := 'Jones Jr.';

      LUpdateItems[2].Enabled := False;
      LUpdateItems[2].AddAttribute('location', ['Remote']);
      LUpdateItems[2].AddAttribute('status', ['On Leave']);

      FPending.BeginOperation;
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
        .OnFinally(FPending.EndOperation)
        .Run;
    end);
end;

procedure TMainForm.UpdateMultipleUsersActionUpdate(Sender: TObject);
begin
  UpdateMultipleUsersAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.DoLogin;
begin
  FPending.BeginOperation;
  try
    // Empty: Keycloak login page; an alias (kc_idp_hint): straight to that identity provider
    FLoginOperation := FKeycloakClientPKCE.StartAuthorizationFlowAsync(Trim(IdPComboBox.Text))
      .OnSuccess(procedure(const AAccessToken: string)
      begin
        ShowSession(AAccessToken);
      end)
      .OnError(procedure(const E: Exception)
      begin
        ShowMessage('Authentication error: ' + E.Message);
      end)
      .OnFinally(procedure
      begin
        // Cancel runs OnFinally only, not OnError
        if Assigned(FLoginOperation) and (FLoginOperation.GetState = TAsyncOperationState.Cancelled) then
        begin
          PKCEMemo.Lines.Clear;
          PKCEMemo.Lines.Add('Login cancelled.');
        end;
        FLoginOperation := nil;
        FPending.EndOperation;
      end)
      .Run;
  except
    // Raised before Run (callback server, browser): no OnFinally ends this operation
    on E: Exception do
    begin
      ShowMessage('Authentication error: ' + E.Message);
      FPending.EndOperation;
    end;
  end;
end;

procedure TMainForm.ShowSession(const AAccessToken: string);
var
  LClaims: TIAM4DIDTokenClaims;

  function OrNone(const AValue: string): string;
  begin
    if AValue.IsEmpty then
      Result := '(none)'
    else
      Result := AValue;
  end;

begin
  // Claims of the id_token validated at the login; scopes of the token response
  LClaims := FKeycloakClientPKCE.GetIDTokenClaims;
  PKCEMemo.Lines.BeginUpdate;
  try
    PKCEMemo.Lines.Clear;
    PKCEMemo.Lines.Add('=== Session (id_token claims) ===');
    PKCEMemo.Lines.Add('User: ' + OrNone(LClaims.PreferredUsername));
    PKCEMemo.Lines.Add('acr (level reached): ' + OrNone(LClaims.Acr));
    PKCEMemo.Lines.Add('amr (methods): ' + OrNone(string.Join(' ', LClaims.Amr)));
    PKCEMemo.Lines.Add('sid (Keycloak session): ' + OrNone(LClaims.SessionID));
    if LClaims.AuthTime > 0 then
      PKCEMemo.Lines.Add('auth_time: ' + DateToISO8601(UnixToDateTime(LClaims.AuthTime), True))
    else
      PKCEMemo.Lines.Add('auth_time: (none)');
    PKCEMemo.Lines.Add('Granted scopes: ' + OrNone(string.Join(' ', FKeycloakClientPKCE.GetGrantedScopes)));
    PKCEMemo.Lines.Add('');
    PKCEMemo.Lines.Add('=== Access token ===');
    PKCEMemo.Lines.Add(AAccessToken);
  finally
    PKCEMemo.Lines.EndUpdate;
  end;
end;

procedure TMainForm.DoLoginClientCredential;
begin
  FPending.BeginOperation;
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
      FPending.EndOperation;
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
  FPending := TPendingOperations.Create(Self,
    procedure(ABusy: Boolean)
    begin
      PKCEActivityIndicator.Animate := ABusy;
      CCActivityIndicator.Animate := ABusy;
    end);
end;

procedure TMainForm.LoginActionExecute(Sender: TObject);
begin
  FPending.BeginOperation;
  try
    TIAM4DClientConfigBuilder.New
      .ForAuthorizationCode(PKCEBaseURLEdit.Text, PKCERealmEdit.Text, PKCEClientEdit.Text)
      .WithAllowSelfSignedSSL
      .BuildAsync
      .OnSuccess(
      procedure(const AClient: IIAM4DClient)
      begin
        FKeycloakClientPKCE := AClient;
        if not FPending.CloseRequested then
          DoLogin;
      end)
      .OnError(procedure(const E: Exception)
      begin
        ShowMessage('Configuration error: ' + E.Message);
      end)
      .OnFinally(FPending.EndOperation)
      .Run;
  except
    // Raised before Run (e.g. empty base URL or realm): no OnFinally ends this operation
    on E: Exception do
    begin
      ShowMessage('Configuration error: ' + E.Message);
      FPending.EndOperation;
    end;
  end;
end;

procedure TMainForm.LoginActionUpdate(Sender: TObject);
begin
  // Disabled while operations are running, also during the wait for the browser
  LoginAction.Enabled := FPending.Idle and
    not (Assigned(FKeycloakClientPKCE) and FKeycloakClientPKCE.IsAuthenticated);
end;

procedure TMainForm.CancelLoginActionExecute(Sender: TObject);
begin
  if Assigned(FLoginOperation) then
    FLoginOperation.Cancel;
end;

procedure TMainForm.CancelLoginActionUpdate(Sender: TObject);
begin
  // Only the wait for the browser can be cancelled, not the configuration
  CancelLoginAction.Enabled := Assigned(FLoginOperation);
end;

procedure TMainForm.LoginCredentialAccessExecute(Sender: TObject);
begin
  Screen.Cursor := crHourGlass;
  FPending.BeginOperation;
  try
    TIAM4DClientConfigBuilder.New
      .ForClientCredentials(CCBaseURLEdit.Text, CCRealmEdit.Text, CCClientEdit.Text, CCClientSecretEdit.Text)
      .WithAllowSelfSignedSSL
      .BuildAsync
      .OnSuccess(
      procedure(const AClient: IIAM4DClient)
      begin
        FKeycloakClientCredential := AClient;
        // DoLoginClientCredential restores the cursor when it ends
        if FPending.CloseRequested then
          Screen.Cursor := crDefault
        else
          DoLoginClientCredential;
      end)
      .OnError(procedure(const E: Exception)
      begin
        Screen.Cursor := crDefault;
        ShowMessage('Configuration error: ' + E.Message);
      end)
      .OnFinally(FPending.EndOperation)
      .Run;
  except
    // Raised before Run (e.g. empty base URL, realm or secret): no OnFinally ends this operation
    on E: Exception do
    begin
      Screen.Cursor := crDefault;
      ShowMessage('Configuration error: ' + E.Message);
      FPending.EndOperation;
    end;
  end;
end;

procedure TMainForm.LogoutActionExecute(Sender: TObject);
begin
  PKCEMemo.Lines.Clear;
  Screen.Cursor := crHourGlass;
  FPending.BeginOperation;
  FKeycloakClientPKCE.LogoutAsync
    .OnError(procedure(const E: Exception)
    begin
      ShowMessage(E.Message);
    end)
    .OnFinally(
    procedure
    begin
      // Also after an error
      Screen.Cursor := crDefault;
      FPending.EndOperation;
    end)
    .Run;
end;

procedure TMainForm.LogoutActionUpdate(Sender: TObject);
begin
  LogoutAction.Enabled :=
    Assigned(FKeycloakClientPKCE)
    and FKeycloakClientPKCE.IsAuthenticated;
end;

procedure TMainForm.RevokeActionExecute(Sender: TObject);
begin
  // RFC 7009: ends what this client holds (its Keycloak session, an offline token too) and
  // clears the tokens; Logout ends the whole user session instead
  PKCEMemo.Lines.Clear;
  Screen.Cursor := crHourGlass;
  FPending.BeginOperation;
  FKeycloakClientPKCE.RevokeTokensAsync
    .OnSuccess(procedure
    begin
      PKCEMemo.Lines.Add('Tokens revoked: the refresh and access tokens no longer work, and they are cleared.');
    end)
    .OnError(procedure(const E: Exception)
    begin
      ShowMessage('Revocation error: ' + E.Message);
    end)
    .OnFinally(
    procedure
    begin
      Screen.Cursor := crDefault;
      FPending.EndOperation;
    end)
    .Run;
end;

procedure TMainForm.RevokeActionUpdate(Sender: TObject);
begin
  RevokeAction.Enabled :=
    Assigned(FKeycloakClientPKCE)
    and FKeycloakClientPKCE.IsAuthenticated;
end;

procedure TMainForm.UserInfoActionExecute(Sender: TObject);
begin
  PKCEMemo.Lines.Clear;
  FPending.BeginOperation;
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
      ShowMessage('Error: ' + E.Message);
    end)
    .OnFinally(FPending.EndOperation)
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
  LClaims: TJSONObject;
  LToken: string;
begin
  LToken := FKeycloakClientPKCE.GetAccessToken;
  PKCEMemo.Lines.Clear;
  PKCEMemo.Lines.Add(LToken);

  LJWTValidator := TIAM4DJWTValidator.Create(
    FKeycloakClientPKCE.Issuer,
    Trim(AUDEdit.Text),
    svmAllowSelfSigned);

  if Trim(AUDEdit.Text) = EmptyStr then
    (LJWTValidator as IIAM4DJWTValidatorConfigurable).AudienceValidationEnabled := False;

  // The token itself: the memo text ends with a line break
  if LJWTValidator.ValidateToken(LToken, LClaims) then
  begin
    try
      PKCEMemo.Lines.Clear;
      PKCEMemo.Lines.Add(LClaims.Format(4));
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
    FUserManagerSamples := TUserManagementSamples.Create(FKeycloakClientPKCE);
    // Needs the realm-management roles view-identity-providers and manage-identity-providers
    FIdentityProviderManager := TIAM4DKeycloakIdentityProviderManagerAsync.Create(FKeycloakClientPKCE);
  end
  else
  begin
    MessageDlg('To access the user manager, you must be logged in and the user must have the required permissions.', TMsgDlgType.mtError, [TMsgDlgBtn.mbOK], 0);
  end;
end;

procedure TMainForm.RunWithUsers(const AUsernames: TArray<string>; const AExample: TUsersExample);
begin
  // No wait on the main thread: the example starts from the callback of the lookup
  FPending.BeginOperation;
  // Closing: no further lookup
  FPending.CancelOnClose(
    FUserManagerSamples.GetUsersByUsernames(AUsernames)
      .OnSuccess(
      procedure(const AUsers: TArray<TIAM4DUser>)
      begin
        // Closing: the example sends no request
        if not FPending.CloseRequested then
          AExample(AUsers);
      end)
      .OnError(
      procedure(const AException: Exception)
      begin
        // E.g. EIAM4DUserNotFoundException
        Memo3.Lines.Add(Format('Failed to look up the users: %s', [AException.Message]));
      end)
      .OnFinally(FPending.EndOperation)
      .Run);
end;

procedure TMainForm.CCAccessTokenActionExecute(Sender: TObject);
begin
  CCMemo.Lines.Clear;
  FPending.BeginOperation;
  FKeycloakClientCredential.GetAccessTokenAsync
    .OnSuccess(procedure(const AResult: string)
    begin
      CCMemo.Lines.Add(AResult)
    end)
    .OnError(procedure(const E: Exception)
    begin
      ShowMessage(E.Message);
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
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
  FPending.BeginOperation;
  FKeycloakClientCredential.LogoutAsync
    .OnError(procedure(const E: Exception)
    begin
      ShowMessage(E.Message);
    end)
    .OnFinally(
    procedure
    begin
      Screen.Cursor := crDefault;
      FPending.EndOperation;
    end)
    .Run;
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
  // api-server: the audience the realm of Docker/ gives to the tokens of iam4d-sample-service
  LJWTValidator := TIAM4DJWTValidator.Create(FKeycloakClientCredential.Issuer, 'api-server', svmAllowSelfSigned);
  if LJWTValidator.ValidateToken(FKeycloakClientCredential.GetAccessToken, LClaims) then
  begin
    try
      CCMemo.Lines.Clear;
      CCMemo.Lines.Add(LClaims.Format(4));
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
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 12: Set User Password === ::.');
  Memo3.Lines.Add('-----------------------------------------');
  Memo3.Lines.Add('');

  RunWithUsers(['alice.smith'],
    procedure(const AUsers: TArray<TIAM4DUser>)
    begin
      FPending.BeginOperation;
      FUserManagerSamples.SetUserPassword(AUsers[0].ID, '12345678', True)
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
        .OnFinally(FPending.EndOperation)
        .Run;
    end);
end;

procedure TMainForm.ChangePasswordActionUpdate(Sender: TObject);
begin
  ChangePasswordAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.ChangePasswordsActionExecute(Sender: TObject);
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 9: Set Passwords for Multiple Users ::.');
  Memo3.Lines.Add('---------------------------------------------------');
  Memo3.Lines.Add('');

  RunWithUsers(['alice.smith', 'bob.jones', 'carol.white'],
    procedure(const AUsers: TArray<TIAM4DUser>)
    var
      LPasswords: TArray<TIAM4DPasswordReset>;
      LIndex: Integer;
    begin
      SetLength(LPasswords, Length(AUsers));
      for LIndex := 0 to High(AUsers) do
      begin
        LPasswords[LIndex].UserID := AUsers[LIndex].ID;
        LPasswords[LIndex].Password := 'abcdefgh$';
        LPasswords[LIndex].Temporary := True;
      end;

      FPending.BeginOperation;
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
        .OnFinally(FPending.EndOperation)
        .Run;
    end);
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

  FPending.BeginOperation;
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
    .OnFinally(FPending.EndOperation)
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

  FPending.BeginOperation;
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
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.CreateMultipleUsersActionUpdate(Sender: TObject);
begin
  CreateMultipleUsersAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.DeleteMultipleUserActionExecute(Sender: TObject);
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 8: Delete Multiple Users ::.');
  Memo3.Lines.Add('----------------------------------------');
  Memo3.Lines.Add('');

  RunWithUsers(['alice.smith', 'bob.jones', 'carol.white'],
    procedure(const AUsers: TArray<TIAM4DUser>)
    var
      LUserIDs: TArray<string>;
      LIndex: Integer;
    begin
      SetLength(LUserIDs, Length(AUsers));
      for LIndex := 0 to High(AUsers) do
        LUserIDs[LIndex] := AUsers[LIndex].ID;

      FPending.BeginOperation;
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
        .OnFinally(FPending.EndOperation)
        .Run;
    end);
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

  FPending.BeginOperation;
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
    .OnFinally(FPending.EndOperation)
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

  FPending.BeginOperation;
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
    .OnFinally(FPending.EndOperation)
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

  FPending.BeginOperation;
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
    .OnFinally(FPending.EndOperation)
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

  LCriteria := TIAM4DUserSearchCriteria.Create('demo', 0, 10);

  FPending.BeginOperation;
  FUserManagerSamples.SearchUsers(LCriteria)
    .OnSuccess(
    procedure(const AUsers: TArray<TIAM4DUser>)
    begin
      for var LUser in AUsers do
        DumpIAM4DUserToMemo(LUser, Memo3);
      // The second search starts when the first one has succeeded
      if not FPending.CloseRequested then
        SearchUsersByEmail;
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add(Format('Failed to update user: %s', [AException.Message]));
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.SearchUsersByEmail;
var
  LCriteria: TIAM4DUserSearchCriteria;
begin
  Memo3.Lines.Add('.:: Example 15/2: Partial email search  ::.');
  Memo3.Lines.Add('-------------------------------------------');
  Memo3.Lines.Add('');

  LCriteria := TIAM4DUserSearchCriteria.Create;
  LCriteria.Email := 'example.com';
  // Only enabled users
  LCriteria.FilterByEnabled := True;
  LCriteria.Enabled := True;
  LCriteria.FirstResult := 0;
  LCriteria.MaxResults := 50;

  FPending.BeginOperation;
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
    .OnFinally(FPending.EndOperation)
    .Run;
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

  FPending.BeginOperation;
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
    .OnFinally(FPending.EndOperation)
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

  FPending.BeginOperation;
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
    .OnFinally(FPending.EndOperation)
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

  RunWithUsers(['demo'],
    procedure(const AUsers: TArray<TIAM4DUser>)
    begin
      FPending.BeginOperation;
      FUserManagerSamples.CheckIfUserIsFederated(AUsers[0].ID)
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
        .OnFinally(FPending.EndOperation)
        .Run;
    end);
end;

procedure TMainForm.UserFederatedActionUpdate(Sender: TObject);
begin
  UserFederatedAction.Enabled := Assigned(FUserManagerSamples);
end;

procedure TMainForm.IdPListActionExecute(Sender: TObject);
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Identity providers of the realm ::.');
  Memo3.Lines.Add('');

  FPending.BeginOperation;
  FIdentityProviderManager.GetIdentityProvidersAsync
    .OnSuccess(
    procedure(const AProviders: TArray<TIAM4DIdentityProvider>)
    begin
      for var LProvider in AProviders do
        Memo3.Lines.Add(Format('%-20s %-12s %-25s enabled=%s hidden=%s',
          [LProvider.Alias, LProvider.ProviderID, LProvider.DisplayName,
           BoolToStr(LProvider.Enabled, True), BoolToStr(LProvider.HideOnLogin, True)]));
      Memo3.Lines.Add(Format('%d provider(s)', [Length(AProviders)]));
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add('Failed to get identity providers: ' + AException.Message);
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.IdPSaveEntraActionExecute(Sender: TObject);
var
  LValues: TArray<string>;
  LProvider: TIAM4DIdentityProvider;
begin
  LValues := [IAM4D_IDP_ALIAS_ENTRA, '', '', ''];
  // A prompt starting with a control character masks its edit
  if not InputQuery('Microsoft Entra ID',
    ['Alias', 'Tenant (directory ID)', 'Application (client) ID', #1'Client secret'], LValues) then
    Exit;

  LProvider := TIAM4DEntraIdPBuilder.New(LValues[0])
    .WithTenant(LValues[1])
    .WithClient(LValues[2], LValues[3])
    .WithSyncMode(ismImport)
    .Build;

  Memo3.Lines.Clear;
  FPending.BeginOperation;
  FIdentityProviderManager.SaveIdentityProviderAsync(LProvider)
    .OnSuccess(
    procedure
    begin
      Memo3.Lines.Add(Format('Identity provider "%s" saved.', [LProvider.Alias]));
      Memo3.Lines.Add('Redirect URI to register in Entra ID: ' +
        FKeycloakClientPKCE.Issuer + '/broker/' + LProvider.Alias + '/endpoint');
      if IdPComboBox.Items.IndexOf(LProvider.Alias) < 0 then
        IdPComboBox.Items.Add(LProvider.Alias);
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add('Failed to save the identity provider: ' + AException.Message);
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.IdPDeleteActionExecute(Sender: TObject);
var
  LAlias: string;
begin
  LAlias := Trim(IdPComboBox.Text);
  if not InputQuery('Delete identity provider', 'Alias', LAlias) then
    Exit;

  Memo3.Lines.Clear;
  FPending.BeginOperation;
  FIdentityProviderManager.DeleteIdentityProviderAsync(LAlias)
    .OnSuccess(
    procedure
    begin
      Memo3.Lines.Add(Format('Identity provider "%s" deleted.', [LAlias]));
    end)
    .OnError(
    procedure(const AException: Exception)
    begin
      Memo3.Lines.Add('Failed to delete the identity provider: ' + AException.Message);
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.IdPActionUpdate(Sender: TObject);
begin
  (Sender as TAction).Enabled := Assigned(FIdentityProviderManager);
end;

procedure TMainForm.UserRolesActionExecute(Sender: TObject);
begin
  Memo3.Lines.Clear;
  Memo3.Lines.Add('.:: Example 14: Get User Roles ::.');
  Memo3.Lines.Add('----------------------------------');
  Memo3.Lines.Add('');

  RunWithUsers(['alice.smith'],
    procedure(const AUsers: TArray<TIAM4DUser>)
    begin
      FPending.BeginOperation;
      FUserManagerSamples.GetUserRoles(AUsers[0].ID)
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
        .OnFinally(FPending.EndOperation)
        .Run;
    end);
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

  FPending.BeginOperation;
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
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.UserSampleCreateUserActionUpdate(Sender: TObject);
begin
  UserSampleCreateUserAction.Enabled := Assigned(FUserManagerSamples);
end;

end.

