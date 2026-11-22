unit IdentityBrokering.MainForm;

interface

uses
  Winapi.Windows,
  Winapi.Messages,
  System.SysUtils,
  System.Variants,
  System.Classes,
  System.Actions,
  Vcl.Graphics,
  Vcl.Controls,
  Vcl.Forms,
  Vcl.Dialogs,
  Vcl.StdCtrls,
  Vcl.ExtCtrls,
  Vcl.ComCtrls,
  Vcl.ActnList,
  Vcl.Menus,
  Vcl.WinXCtrls,
  Async.Core,
  IAMClient4D.Core,
  IAMClient4D.IdentityProvider.Core,
  Samples.PendingOperations,
  IdentityBrokering.SpidRegistry,
  IdentityBrokering.Common;

const
  WM_SHOW_SPID_MENU = WM_APP + 1;

type
  TIdentityProviderFactory = reference to function(const AImportedConfig: TIAM4DConfigMap): TIAM4DIdentityProvider;

  TMainForm = class(TForm)
    MainPageControl: TPageControl;
    LoginTabSheet: TTabSheet;
    AdminTabSheet: TTabSheet;
    BaseURLPanel: TPanel;
    BaseURLLabel: TLabel;
    BaseURLEdit: TEdit;
    RealmPanel: TPanel;
    RealmLabel: TLabel;
    RealmEdit: TEdit;
    ClientPanel: TPanel;
    ClientLabel: TLabel;
    ClientEdit: TEdit;
    LoginBevel: TBevel;
    LoginButtonsPanel: TPanel;
    EntraLoginButton: TButton;
    MicrosoftLoginButton: TButton;
    GoogleLoginButton: TButton;
    FacebookLoginButton: TButton;
    SpidLoginButton: TButton;
    CieLoginButton: TButton;
    KeycloakLoginButton: TButton;
    CancelLoginButton: TButton;
    LoginActivityIndicator: TActivityIndicator;
    SessionBevel: TBevel;
    SessionPanel: TPanel;
    UserInfoButton: TButton;
    AccessTokenButton: TButton;
    LogoutButton: TButton;
    SessionLabel: TLabel;
    LoginMemo: TMemo;
    AdminStatusPanel: TPanel;
    AdminStatusLabel: TLabel;
    AdminActivityIndicator: TActivityIndicator;
    AdminTopPanel: TPanel;
    IdPGroupBox: TGroupBox;
    IdPListView: TListView;
    IdPButtonsPanel: TPanel;
    RefreshIdPsButton: TButton;
    DeleteIdPButton: TButton;
    URLGroupBox: TGroupBox;
    RedirectAliasPanel: TPanel;
    RedirectAliasLabel: TLabel;
    RedirectAliasEdit: TEdit;
    RedirectURIPanel: TPanel;
    RedirectURILabel: TLabel;
    RedirectURIEdit: TEdit;
    SpidSPMetadataPanel: TPanel;
    SpidSPMetadataLabel: TLabel;
    SpidSPMetadataEdit: TEdit;
    CieSPMetadataPanel: TPanel;
    CieSPMetadataLabel: TLabel;
    CieSPMetadataEdit: TEdit;
    BrokerPageControl: TPageControl;
    EntraTabSheet: TTabSheet;
    EntraAliasPanel: TPanel;
    EntraAliasLabel: TLabel;
    EntraAliasEdit: TEdit;
    EntraTenantPanel: TPanel;
    EntraTenantLabel: TLabel;
    EntraTenantEdit: TEdit;
    EntraClientIDPanel: TPanel;
    EntraClientIDLabel: TLabel;
    EntraClientIDEdit: TEdit;
    EntraSecretPanel: TPanel;
    EntraSecretLabel: TLabel;
    EntraSecretEdit: TEdit;
    EntraPromptPanel: TPanel;
    EntraPromptLabel: TLabel;
    EntraPromptComboBox: TComboBox;
    EntraPromptHintLabel: TLabel;
    EntraOptionsPanel: TPanel;
    EntraHideCheckBox: TCheckBox;
    SaveEntraButton: TButton;
    GoogleTabSheet: TTabSheet;
    GoogleAliasPanel: TPanel;
    GoogleAliasLabel: TLabel;
    GoogleAliasEdit: TEdit;
    GoogleClientIDPanel: TPanel;
    GoogleClientIDLabel: TLabel;
    GoogleClientIDEdit: TEdit;
    GoogleSecretPanel: TPanel;
    GoogleSecretLabel: TLabel;
    GoogleSecretEdit: TEdit;
    GoogleDomainsPanel: TPanel;
    GoogleDomainsLabel: TLabel;
    GoogleDomainsEdit: TEdit;
    GoogleOptionsPanel: TPanel;
    GoogleHideCheckBox: TCheckBox;
    GoogleTrustEmailCheckBox: TCheckBox;
    SaveGoogleButton: TButton;
    FacebookTabSheet: TTabSheet;
    FacebookAliasPanel: TPanel;
    FacebookAliasLabel: TLabel;
    FacebookAliasEdit: TEdit;
    FacebookAppIDPanel: TPanel;
    FacebookAppIDLabel: TLabel;
    FacebookAppIDEdit: TEdit;
    FacebookSecretPanel: TPanel;
    FacebookSecretLabel: TLabel;
    FacebookSecretEdit: TEdit;
    FacebookOptionsPanel: TPanel;
    FacebookHideCheckBox: TCheckBox;
    SaveFacebookButton: TButton;
    OidcTabSheet: TTabSheet;
    OidcAliasPanel: TPanel;
    OidcAliasLabel: TLabel;
    OidcAliasEdit: TEdit;
    OidcDiscoveryPanel: TPanel;
    OidcDiscoveryLabel: TLabel;
    OidcDiscoveryEdit: TEdit;
    OidcClientIDPanel: TPanel;
    OidcClientIDLabel: TLabel;
    OidcClientIDEdit: TEdit;
    OidcSecretPanel: TPanel;
    OidcSecretLabel: TLabel;
    OidcSecretEdit: TEdit;
    OidcOptionsPanel: TPanel;
    OidcLoginLabel: TLabel;
    SaveOidcButton: TButton;
    OtherTabSheet: TTabSheet;
    OtherLeftPanel: TPanel;
    OtherTypePanel: TPanel;
    OtherTypeLabel: TLabel;
    OtherTypeComboBox: TComboBox;
    OtherAliasPanel: TPanel;
    OtherAliasLabel: TLabel;
    OtherAliasEdit: TEdit;
    OtherClientIDPanel: TPanel;
    OtherClientIDLabel: TLabel;
    OtherClientIDEdit: TEdit;
    OtherSecretPanel: TPanel;
    OtherSecretLabel: TLabel;
    OtherSecretEdit: TEdit;
    OtherOptionsPanel: TPanel;
    OtherHideCheckBox: TCheckBox;
    OtherTrustEmailCheckBox: TCheckBox;
    SaveOtherButton: TButton;
    OtherRightPanel: TPanel;
    OtherTenantPanel: TPanel;
    OtherTenantLabel: TLabel;
    OtherTenantEdit: TEdit;
    OtherBaseURLPanel: TPanel;
    OtherBaseURLLabel: TLabel;
    OtherBaseURLEdit: TEdit;
    OtherApiURLPanel: TPanel;
    OtherApiURLLabel: TLabel;
    OtherApiURLEdit: TEdit;
    OtherAuthURLPanel: TPanel;
    OtherAuthURLLabel: TLabel;
    OtherAuthURLEdit: TEdit;
    OtherTokenURLPanel: TPanel;
    OtherTokenURLLabel: TLabel;
    OtherTokenURLEdit: TEdit;
    OtherUserInfoURLPanel: TPanel;
    OtherUserInfoURLLabel: TLabel;
    OtherUserInfoURLEdit: TEdit;
    OtherScopesPanel: TPanel;
    OtherScopesLabel: TLabel;
    OtherScopesEdit: TEdit;
    OtherClaimsPanel: TPanel;
    OtherClaimsLabel: TLabel;
    OtherClaimsEdit: TEdit;
    OtherNoteLabel: TLabel;
    SpidTabSheet: TTabSheet;
    SpidProviderPanel: TPanel;
    SpidProviderLabel: TLabel;
    SpidProviderComboBox: TComboBox;
    LoadRegistryButton: TButton;
    SpidAliasPanel: TPanel;
    SpidAliasLabel: TLabel;
    SpidAliasEdit: TEdit;
    SpidMetadataPanel: TPanel;
    SpidMetadataLabel: TLabel;
    SpidMetadataEdit: TEdit;
    SpidLevelPanel: TPanel;
    SpidLevelLabel: TLabel;
    SpidLevelComboBox: TComboBox;
    SpidOptionsPanel: TPanel;
    SpidHideCheckBox: TCheckBox;
    SaveSpidButton: TButton;
    CieTabSheet: TTabSheet;
    CieEnvironmentPanel: TPanel;
    CieEnvironmentLabel: TLabel;
    CieEnvironmentComboBox: TComboBox;
    CieAliasPanel: TPanel;
    CieAliasLabel: TLabel;
    CieAliasEdit: TEdit;
    CieMetadataPanel: TPanel;
    CieMetadataLabel: TLabel;
    CieMetadataEdit: TEdit;
    CieLevelPanel: TPanel;
    CieLevelLabel: TLabel;
    CieLevelComboBox: TComboBox;
    CieOptionsPanel: TPanel;
    CieHideCheckBox: TCheckBox;
    SaveCieButton: TButton;
    ServiceProviderTabSheet: TTabSheet;
    OrganizationPanel: TPanel;
    OrgNamePanel: TPanel;
    OrgNameLabel: TLabel;
    OrgNameEdit: TEdit;
    OrgDisplayNamePanel: TPanel;
    OrgDisplayNameLabel: TLabel;
    OrgDisplayNameEdit: TEdit;
    OrgURLPanel: TPanel;
    OrgURLLabel: TLabel;
    OrgURLEdit: TEdit;
    SPTypePanel: TPanel;
    SPTypeLabel: TLabel;
    SPTypeComboBox: TComboBox;
    ServiceNamePanel: TPanel;
    ServiceNameLabel: TLabel;
    ServiceNameEdit: TEdit;
    ContactsPanel: TPanel;
    IpaCodePanel: TPanel;
    IpaCodeLabel: TLabel;
    IpaCodeEdit: TEdit;
    IpaCategoryPanel: TPanel;
    IpaCategoryLabel: TLabel;
    IpaCategoryEdit: TEdit;
    VatNumberPanel: TPanel;
    VatNumberLabel: TLabel;
    VatNumberEdit: TEdit;
    FiscalCodePanel: TPanel;
    FiscalCodeLabel: TLabel;
    FiscalCodeEdit: TEdit;
    EmailPanel: TPanel;
    EmailLabel: TLabel;
    EmailEdit: TEdit;
    PhonePanel: TPanel;
    PhoneLabel: TLabel;
    PhoneEdit: TEdit;
    AdminMemo: TMemo;
    MainActionList: TActionList;
    EntraLoginAction: TAction;
    MicrosoftLoginAction: TAction;
    GoogleLoginAction: TAction;
    FacebookLoginAction: TAction;
    SpidLoginAction: TAction;
    CieLoginAction: TAction;
    KeycloakLoginAction: TAction;
    CancelLoginAction: TAction;
    UserInfoAction: TAction;
    AccessTokenAction: TAction;
    LogoutAction: TAction;
    RefreshIdPsAction: TAction;
    DeleteIdPAction: TAction;
    SaveEntraAction: TAction;
    SaveGoogleAction: TAction;
    SaveFacebookAction: TAction;
    SaveOidcAction: TAction;
    SaveOtherAction: TAction;
    LoadSpidRegistryAction: TAction;
    SaveSpidAction: TAction;
    SaveCieAction: TAction;
    SpidPopupMenu: TPopupMenu;
    procedure FormCreate(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure MainActionListUpdate(Action: TBasicAction; var Handled: Boolean);
    procedure MainPageControlChange(Sender: TObject);
    procedure EntraLoginActionExecute(Sender: TObject);
    procedure MicrosoftLoginActionExecute(Sender: TObject);
    procedure GoogleLoginActionExecute(Sender: TObject);
    procedure FacebookLoginActionExecute(Sender: TObject);
    procedure SpidLoginActionExecute(Sender: TObject);
    procedure CieLoginActionExecute(Sender: TObject);
    procedure KeycloakLoginActionExecute(Sender: TObject);
    procedure CancelLoginActionExecute(Sender: TObject);
    procedure UserInfoActionExecute(Sender: TObject);
    procedure AccessTokenActionExecute(Sender: TObject);
    procedure LogoutActionExecute(Sender: TObject);
    procedure RefreshIdPsActionExecute(Sender: TObject);
    procedure DeleteIdPActionExecute(Sender: TObject);
    procedure SaveEntraActionExecute(Sender: TObject);
    procedure SaveGoogleActionExecute(Sender: TObject);
    procedure SaveFacebookActionExecute(Sender: TObject);
    procedure SaveOidcActionExecute(Sender: TObject);
    procedure SaveOtherActionExecute(Sender: TObject);
    procedure LoadSpidRegistryActionExecute(Sender: TObject);
    procedure SaveSpidActionExecute(Sender: TObject);
    procedure SaveCieActionExecute(Sender: TObject);
    procedure IdPListViewSelectItem(Sender: TObject; Item: TListItem; Selected: Boolean);
    procedure BrokerPageControlChange(Sender: TObject);
    procedure AliasEditChange(Sender: TObject);
    procedure ConnectionEditChange(Sender: TObject);
    procedure SpidProviderComboBoxChange(Sender: TObject);
    procedure CieEnvironmentComboBoxChange(Sender: TObject);
    procedure SPTypeComboBoxChange(Sender: TObject);
    procedure OtherTypeComboBoxChange(Sender: TObject);
    procedure SpidLoginButtonDropDownClick(Sender: TObject);
  private
    FClient: IIAM4DClient;
    FIdentityProviderManager: IIAM4DIdentityProviderManagerAsync;
    FIdentityProviders: TArray<TIAM4DIdentityProvider>;
    FIdentityProvidersLoaded: Boolean;
    FLoginOperation: IAsyncOperation<string>;
    // Every asynchronous call: the form closes when the last one has ended
    FPending: TPendingOperations;
    FUserName: string;
    FSpidRegistry: TArray<TSpidRegistryEntry>;
    FSpidRegistryLoading: Boolean;
    FSpidRegistryLoaded: Boolean;
    FSpidMenuAliases: TArray<string>;
    FBrokerAlias: string;
    // Item of OtherTypeComboBox the fields are shown for
    FOtherType: Integer;
    procedure WMShowSpidMenu(var AMessage: TMessage); message WM_SHOW_SPID_MENU;
    function IsSignedIn: Boolean;
    procedure StartLogin(const AIdpHint: string);
    procedure RunAuthorizationFlow(const AIdpHint: string);
    procedure ShowSession(const AAccessToken: string);
    procedure AddUserInfo(const AUserInfo: TIAM4DUserInfo);
    procedure AddAccessToken(const AAccessToken: string);
    procedure UpdateSessionState;
    procedure UpdateAdminAccess(const AAccessToken: string);
    procedure LoadSpidRegistry(const AShowMenu: Boolean);
    procedure FillSpidProviders;
    procedure RebuildSpidMenu;
    procedure ShowSpidMenu;
    procedure SpidMenuItemClick(Sender: TObject);
    procedure SpidOtherAliasClick(Sender: TObject);
    procedure RefreshIdentityProviders;
    procedure FillIdentityProviderList;
    procedure SaveIdentityProvider(const AIdentityProvider: TIAM4DIdentityProvider;
      const AMappers: TArray<TIAM4DIdentityProviderMapper> = nil);
    procedure AddMissingMappers(const AAlias: string; const AMappers: TArray<TIAM4DIdentityProviderMapper>);
    procedure CreateMapper(const AMapper: TIAM4DIdentityProviderMapper);
    procedure ImportAndSave(const AProviderID, AMetadataURL: string; const AFactory: TIdentityProviderFactory;
      const AMappers: TArray<TIAM4DIdentityProviderMapper> = nil);
    function FindIdentityProvider(const AAlias: string; out AIdentityProvider: TIAM4DIdentityProvider): Boolean;
    function IsPublicServiceProvider: Boolean;
    function RealmURL: string;
    procedure UpdateBrokerURLs(const AAlias: string);
    procedure UpdateOtherFields;
    procedure AdminLog(const AText: string);
  end;

var
  MainForm: TMainForm;

implementation

{$R *.dfm}

uses
  System.Generics.Collections,
  System.JSON,
  System.NetEncoding,
  System.Types,
  System.UITypes,
  IAMClient4D.Config.Builder,
  IAMClient4D.Exceptions,
  IAMClient4D.IdentityProvider.Keycloak.Async,
  IAMClient4D.IdentityProvider.Builders;

const
  CYesNo: array[Boolean] of string = ('no', 'yes');
  // CIE environment combo: the TIAM4DCieEnvironment values, then the local CIE simulator
  CCieLocalTest = Ord(High(TIAM4DCieEnvironment)) + 1;
  // SPID providers: the demo identity provider of the sample environment (Docker/), then the AgID registry
  CSpidLocalTest = 0;
  // Other providers: items of OtherTypeComboBox
  COtherMicrosoft = 0;
  COtherLinkedIn = 1;
  COtherGitHub = 2;
  COtherGitLab = 3;
  COtherOAuth2 = 4;
  COtherAliases: array[COtherMicrosoft..COtherOAuth2] of string = (IAM4D_IDP_ALIAS_MICROSOFT, IAM4D_IDP_ALIAS_LINKEDIN,
    IAM4D_IDP_ALIAS_GITHUB, IAM4D_IDP_ALIAS_GITLAB, 'oauth2');

{ TMainForm }

procedure TMainForm.FormCreate(Sender: TObject);
begin
  FPending := TPendingOperations.Create(Self,
    procedure(ABusy: Boolean)
    begin
      LoginActivityIndicator.Animate := ABusy;
      AdminActivityIndicator.Animate := ABusy;
    end);
  MainPageControl.ActivePage := LoginTabSheet;
  // Shown after the login only to a user who can list the identity providers (UpdateAdminAccess)
  AdminTabSheet.TabVisible := False;
  BrokerPageControl.ActivePage := EntraTabSheet;
  SpidLevelComboBox.ItemIndex := Ord(slL2);
  CieLevelComboBox.ItemIndex := Ord(slL2);
  // The CIE simulator of the sample environment: the only CIE identity server that completes a local login
  CieEnvironmentComboBox.ItemIndex := CCieLocalTest;
  SPTypeComboBox.ItemIndex := 0;
  // Before the AgID registry is loaded too: spid-test can be deleted and saved again without it
  FSpidRegistry := [SpidLocalTestEntry];
  FillSpidProviders;
  OtherTypeComboBox.ItemIndex := COtherMicrosoft;
  FOtherType := COtherMicrosoft;
  UpdateOtherFields;
  CieEnvironmentComboBoxChange(nil);
  SPTypeComboBoxChange(nil);
  UpdateBrokerURLs(EntraAliasEdit.Text);
  UpdateSessionState;
end;

procedure TMainForm.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  // Operations still running: cancel the login and close when the last OnFinally has run,
  // so that no callback runs on a destroyed form
  CanClose := FPending.CloseQuery(FLoginOperation);
end;

function TMainForm.IsSignedIn: Boolean;
begin
  Result := Assigned(FClient) and FClient.IsAuthenticated;
end;

procedure TMainForm.MainActionListUpdate(Action: TBasicAction; var Handled: Boolean);
var
  LIdle, LCanLogin, LSignedIn, LAdmin: Boolean;
begin
  LIdle := FPending.Idle;
  LSignedIn := IsSignedIn;
  LCanLogin := LIdle and not LSignedIn;
  LAdmin := LIdle and LSignedIn and Assigned(FIdentityProviderManager);

  EntraLoginAction.Enabled := LCanLogin;
  MicrosoftLoginAction.Enabled := LCanLogin;
  GoogleLoginAction.Enabled := LCanLogin;
  FacebookLoginAction.Enabled := LCanLogin;
  SpidLoginAction.Enabled := LCanLogin;
  CieLoginAction.Enabled := LCanLogin;
  KeycloakLoginAction.Enabled := LCanLogin;
  CancelLoginAction.Enabled := Assigned(FLoginOperation) and not FPending.CloseRequested;
  UserInfoAction.Enabled := LIdle and LSignedIn;
  AccessTokenAction.Enabled := LIdle and LSignedIn;
  LogoutAction.Enabled := LIdle and LSignedIn;

  RefreshIdPsAction.Enabled := LAdmin;
  DeleteIdPAction.Enabled := LAdmin and Assigned(IdPListView.Selected);
  SaveEntraAction.Enabled := LAdmin;
  SaveGoogleAction.Enabled := LAdmin;
  SaveFacebookAction.Enabled := LAdmin;
  SaveOidcAction.Enabled := LAdmin;
  SaveOtherAction.Enabled := LAdmin;
  SaveSpidAction.Enabled := LAdmin and (SpidProviderComboBox.ItemIndex >= 0);
  SaveCieAction.Enabled := LAdmin;
  LoadSpidRegistryAction.Enabled := LIdle;

  // The connection cannot change during a session: the admin calls use its issuer
  BaseURLEdit.Enabled := LCanLogin;
  RealmEdit.Enabled := LCanLogin;
  ClientEdit.Enabled := LCanLogin;
  Handled := True;
end;

procedure TMainForm.MainPageControlChange(Sender: TObject);
begin
  if (MainPageControl.ActivePage = AdminTabSheet) and not FIdentityProvidersLoaded and
     (FPending.Count = 0) and IsSignedIn and Assigned(FIdentityProviderManager) then
    RefreshIdentityProviders;
end;

{ Login }

procedure TMainForm.EntraLoginActionExecute(Sender: TObject);
begin
  StartLogin(IAM4D_IDP_ALIAS_ENTRA);
end;

procedure TMainForm.MicrosoftLoginActionExecute(Sender: TObject);
begin
  // Personal Microsoft accounts (provider 'microsoft'); work accounts go to Entra ID
  StartLogin(IAM4D_IDP_ALIAS_MICROSOFT);
end;

procedure TMainForm.GoogleLoginActionExecute(Sender: TObject);
begin
  StartLogin(IAM4D_IDP_ALIAS_GOOGLE);
end;

procedure TMainForm.FacebookLoginActionExecute(Sender: TObject);
begin
  StartLogin(IAM4D_IDP_ALIAS_FACEBOOK);
end;

procedure TMainForm.SpidLoginActionExecute(Sender: TObject);
begin
  // One Keycloak provider per SPID identity provider: the user picks it from the menu
  if FSpidRegistryLoaded then
    ShowSpidMenu
  else
    LoadSpidRegistry(True);
end;

procedure TMainForm.CieLoginActionExecute(Sender: TObject);
begin
  StartLogin(IAM4D_IDP_ALIAS_CIE);
end;

procedure TMainForm.KeycloakLoginActionExecute(Sender: TObject);
begin
  StartLogin('');
end;

procedure TMainForm.CancelLoginActionExecute(Sender: TObject);
begin
  if Assigned(FLoginOperation) then
    FLoginOperation.Cancel;
end;

procedure TMainForm.StartLogin(const AIdpHint: string);
var
  LIdpHint: string;
begin
  if not FPending.Idle or IsSignedIn then
    Exit;

  LIdpHint := AIdpHint;
  LoginMemo.Clear;
  if LIdpHint.IsEmpty then
    LoginMemo.Lines.Add('Login from the Keycloak login page: complete it in the browser...')
  else
    LoginMemo.Lines.Add(Format('Login with the identity provider "%s" (kc_idp_hint): complete it in the browser...',
      [LIdpHint]));

  FPending.BeginOperation;
  try
    TIAM4DClientConfigBuilder.New
      .ForAuthorizationCode(Trim(BaseURLEdit.Text), Trim(RealmEdit.Text), Trim(ClientEdit.Text))
      .BuildAsync
      .OnSuccess(
      procedure(const AClient: IIAM4DClient)
      begin
        FClient := AClient;
        if not FPending.CloseRequested then
          RunAuthorizationFlow(LIdpHint);
      end)
      .OnError(
      procedure(const E: Exception)
      begin
        LoginMemo.Lines.Add('Configuration failed: ' + E.Message);
      end)
      .OnFinally(FPending.EndOperation)
      .Run;
  except
    // Raised before Run (e.g. empty base URL or realm): no OnFinally ends this operation
    on E: Exception do
    begin
      LoginMemo.Lines.Add('Configuration failed: ' + E.Message);
      FPending.EndOperation;
    end;
  end;
end;

procedure TMainForm.RunAuthorizationFlow(const AIdpHint: string);
begin
  FPending.BeginOperation;
  try
    // Empty: Keycloak login page; an alias (kc_idp_hint): straight to that identity provider
    FLoginOperation := FClient.StartAuthorizationFlowAsync(AIdpHint)
      .OnSuccess(
      procedure(const AAccessToken: string)
      begin
        UpdateAdminAccess(AAccessToken);
        ShowSession(AAccessToken);
      end)
      .OnError(
      procedure(const E: Exception)
      begin
        LoginMemo.Lines.Add('Login failed: ' + E.Message);
      end)
      .OnFinally(
      procedure
      begin
        if Assigned(FLoginOperation) and (FLoginOperation.GetState = TAsyncOperationState.Cancelled) then
          LoginMemo.Lines.Add('Login cancelled.');
        FLoginOperation := nil;
        UpdateSessionState;
        FPending.EndOperation;
      end)
      .Run;
  except
    // Raised before Run (callback server, browser): no OnFinally ends this operation
    on E: Exception do
    begin
      LoginMemo.Lines.Add('Login failed: ' + E.Message);
      UpdateSessionState;
      FPending.EndOperation;
    end;
  end;
end;

procedure TMainForm.ShowSession(const AAccessToken: string);
var
  LAccessToken: string;
begin
  LAccessToken := AAccessToken;
  LoginMemo.Clear;
  FPending.BeginOperation;
  FClient.GetUserInfoAsync
    .OnSuccess(
    procedure(const AUserInfo: TIAM4DUserInfo)
    begin
      FUserName := AUserInfo.PreferredUsername;
      AddUserInfo(AUserInfo);
    end)
    .OnError(
    procedure(const E: Exception)
    begin
      LoginMemo.Lines.Add('User info not available: ' + E.Message);
    end)
    .OnFinally(
    procedure
    begin
      AddAccessToken(LAccessToken);
      UpdateSessionState;
      FPending.EndOperation;
    end)
    .Run;
end;

procedure TMainForm.AddUserInfo(const AUserInfo: TIAM4DUserInfo);
begin
  LoginMemo.Lines.BeginUpdate;
  try
    LoginMemo.Lines.Add('=== User info ===');
    LoginMemo.Lines.Add('Username: ' + AUserInfo.PreferredUsername);
    LoginMemo.Lines.Add('Name:     ' + AUserInfo.Name);
    LoginMemo.Lines.Add('Email:    ' + AUserInfo.Email);
    LoginMemo.Lines.Add('Sub:      ' + AUserInfo.Sub);
    LoginMemo.Lines.Add(FormatJSON(AUserInfo.RawJSON));
    LoginMemo.Lines.Add('');
  finally
    LoginMemo.Lines.EndUpdate;
  end;
end;

procedure TMainForm.AddAccessToken(const AAccessToken: string);
begin
  LoginMemo.Lines.BeginUpdate;
  try
    LoginMemo.Lines.Add('=== Access token ===');
    LoginMemo.Lines.Add(AAccessToken);
    LoginMemo.Lines.Add('');
    LoginMemo.Lines.Add('=== Access token claims (decoded, not verified) ===');
    LoginMemo.Lines.Add(DecodeJWTPayload(AAccessToken));
  finally
    LoginMemo.Lines.EndUpdate;
  end;
end;

procedure TMainForm.UserInfoActionExecute(Sender: TObject);
begin
  LoginMemo.Clear;
  FPending.BeginOperation;
  FClient.GetUserInfoAsync
    .OnSuccess(
    procedure(const AUserInfo: TIAM4DUserInfo)
    begin
      AddUserInfo(AUserInfo);
    end)
    .OnError(
    procedure(const E: Exception)
    begin
      LoginMemo.Lines.Add('User info not available: ' + E.Message);
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.AccessTokenActionExecute(Sender: TObject);
begin
  LoginMemo.Clear;
  FPending.BeginOperation;
  // Refreshes the token when it is about to expire
  FClient.GetAccessTokenAsync
    .OnSuccess(
    procedure(const AAccessToken: string)
    begin
      AddAccessToken(AAccessToken);
    end)
    .OnError(
    procedure(const E: Exception)
    begin
      LoginMemo.Lines.Add('Access token not available: ' + E.Message);
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.LogoutActionExecute(Sender: TObject);
begin
  FPending.BeginOperation;
  FClient.LogoutAsync
    .OnSuccess(
    procedure
    begin
      LoginMemo.Clear;
      LoginMemo.Lines.Add('Signed out.');
    end)
    .OnError(
    procedure(const E: Exception)
    begin
      LoginMemo.Lines.Add('Sign-out failed: ' + E.Message);
    end)
    .OnFinally(
    procedure
    begin
      if not FClient.IsAuthenticated then
      begin
        UpdateAdminAccess('');
        FIdentityProviders := nil;
        FIdentityProvidersLoaded := False;
        FUserName := '';
        FillIdentityProviderList;
        RebuildSpidMenu;
      end;
      UpdateSessionState;
      FPending.EndOperation;
    end)
    .Run;
end;

procedure TMainForm.UpdateAdminAccess(const AAccessToken: string);
begin
  // Admin REST API with the same session: listing needs view-identity-providers or
  // manage-identity-providers, saving and deleting manage-identity-providers (the demo user has
  // realm-admin). Without them the tab stays hidden instead of failing with 403 at the first call.
  if CanViewIdentityProviders(AAccessToken) then
  begin
    FIdentityProviderManager := TIAM4DKeycloakIdentityProviderManagerAsync.Create(FClient);
    AdminTabSheet.TabVisible := True;
  end
  else
  begin
    FIdentityProviderManager := nil;
    // Hiding the active page would leave the page control on no page
    if MainPageControl.ActivePage = AdminTabSheet then
      MainPageControl.ActivePage := LoginTabSheet;
    AdminTabSheet.TabVisible := False;
  end;
end;

procedure TMainForm.UpdateSessionState;
begin
  if IsSignedIn then
  begin
    if FUserName.IsEmpty then
      SessionLabel.Caption := 'Signed in'
    else
      SessionLabel.Caption := Format('Signed in as %s', [FUserName]);
    if not AdminTabSheet.TabVisible then
      SessionLabel.Caption := SessionLabel.Caption + ' (no identity provider administration: the user lacks ' +
        'the realm-management role view-identity-providers)';
    AdminStatusLabel.Caption := Format('Session of %s on %s. Managing identity providers needs the realm-management roles ' +
      'view-identity-providers and manage-identity-providers.',
      [FUserName, RealmURL]);
  end
  else
  begin
    SessionLabel.Caption := 'Not signed in';
    AdminStatusLabel.Caption := 'Sign in from the Login tab with the Keycloak login page as demo / demo ' +
      '(realm-admin role): the administration uses that session.';
  end;
  UpdateBrokerURLs(FBrokerAlias);
end;

{ SPID registry and login menu }

procedure TMainForm.LoadSpidRegistryActionExecute(Sender: TObject);
begin
  LoadSpidRegistry(False);
end;

procedure TMainForm.LoadSpidRegistry(const AShowMenu: Boolean);
begin
  if FPending.CloseRequested or FSpidRegistryLoading then
    Exit;
  FSpidRegistryLoading := True;
  // Empty while loading: the arrow of the SPID button shows nothing until the menu is rebuilt
  SpidPopupMenu.Items.Clear;
  FSpidMenuAliases := nil;
  FPending.BeginOperation;
  LoadSpidRegistryAsync
    .OnSuccess(
    procedure(const AEntries: TArray<TSpidRegistryEntry>)
    begin
      FSpidRegistry := [SpidLocalTestEntry] + AEntries;
      FSpidRegistryLoaded := True;
      FillSpidProviders;
      AdminLog(Format('AgID registry: %d SPID identity providers.', [Length(AEntries)]));
    end)
    .OnError(
    procedure(const E: Exception)
    begin
      AdminLog('AgID registry not available: ' + E.Message);
      if AShowMenu then
        LoginMemo.Lines.Add('AgID registry not available: ' + E.Message);
    end)
    .OnFinally(
    procedure
    begin
      FSpidRegistryLoading := False;
      // Also without the registry: "Other alias..." reaches the SPID providers of the realm (spid-test)
      RebuildSpidMenu;
      FPending.EndOperation;
      // After EndOperation, from the message loop: the menu items can start the login
      if AShowMenu and not FPending.CloseRequested then
        PostMessage(Handle, WM_SHOW_SPID_MENU, 0, 0);
    end)
    .Run;
end;

procedure TMainForm.SpidLoginButtonDropDownClick(Sender: TObject);
begin
  // The arrow shows SpidPopupMenu right after this event: without the registry, load it first
  // (LoadSpidRegistry empties the menu and shows it when done)
  if not FSpidRegistryLoaded and SpidLoginAction.Enabled then
    LoadSpidRegistry(True);
end;

procedure TMainForm.FillSpidProviders;
var
  LEntry: TSpidRegistryEntry;
  LSelected: string;
begin
  LSelected := SpidAliasEdit.Text;
  SpidProviderComboBox.Items.BeginUpdate;
  try
    SpidProviderComboBox.Items.Clear;
    for LEntry in FSpidRegistry do
      SpidProviderComboBox.Items.Add(Format('%s - %s', [LEntry.OrganizationName, LEntry.EntityID]));
  finally
    SpidProviderComboBox.Items.EndUpdate;
  end;

  for var LIndex := 0 to High(FSpidRegistry) do
    if SameText(FSpidRegistry[LIndex].Alias, LSelected) then
    begin
      SpidProviderComboBox.ItemIndex := LIndex;
      Break;
    end;
  if (SpidProviderComboBox.ItemIndex < 0) and (SpidProviderComboBox.Items.Count > 0) then
    SpidProviderComboBox.ItemIndex := CSpidLocalTest;
  SpidProviderComboBoxChange(nil);
end;

procedure TMainForm.RebuildSpidMenu;

  function IsConfigured(const AAlias: string): Boolean;
  var
    LProvider: TIAM4DIdentityProvider;
  begin
    Result := FindIdentityProvider(AAlias, LProvider);
  end;

  procedure AddItem(const ACaption, AAlias: string);
  var
    LItem: TMenuItem;
  begin
    FSpidMenuAliases := FSpidMenuAliases + [AAlias];
    LItem := TMenuItem.Create(SpidPopupMenu);
    LItem.Caption := ACaption.Replace('&', '&&');
    LItem.Tag := High(FSpidMenuAliases);
    // Checked: provider found in the realm (list of the administration tab)
    LItem.Checked := IsConfigured(AAlias);
    LItem.OnClick := SpidMenuItemClick;
    SpidPopupMenu.Items.Add(LItem);
  end;

var
  LEntry: TSpidRegistryEntry;
  LProvider: TIAM4DIdentityProvider;
  LItem: TMenuItem;
begin
  SpidPopupMenu.Items.Clear;
  FSpidMenuAliases := nil;

  for LEntry in FSpidRegistry do
    AddItem(Format('%s  (%s)', [LEntry.OrganizationName, LEntry.Alias]), LEntry.Alias);

  // SPID providers of the realm not in the registry (e.g. a test identity provider)
  for LProvider in FIdentityProviders do
    if (LProvider.ProviderID = IAM4D_IDP_PROVIDER_SPID) and
       not TArray.Contains<string>(FSpidMenuAliases, LProvider.Alias) then
      AddItem(Format('%s  (%s)', [LProvider.DisplayName, LProvider.Alias]), LProvider.Alias);

  // Always: without the AgID registry it is the only way to a provider such as spid-test
  if Length(FSpidMenuAliases) > 0 then
    SpidPopupMenu.Items.Add(NewLine);
  LItem := TMenuItem.Create(SpidPopupMenu);
  LItem.Caption := 'Other alias...';
  LItem.OnClick := SpidOtherAliasClick;
  SpidPopupMenu.Items.Add(LItem);
end;

procedure TMainForm.WMShowSpidMenu(var AMessage: TMessage);
begin
  ShowSpidMenu;
end;

procedure TMainForm.ShowSpidMenu;
var
  LPoint: TPoint;
begin
  if FPending.CloseRequested or (SpidPopupMenu.Items.Count = 0) then
    Exit;
  LPoint := SpidLoginButton.ClientToScreen(Point(0, SpidLoginButton.Height));
  SpidPopupMenu.Popup(LPoint.X, LPoint.Y);
end;

procedure TMainForm.SpidMenuItemClick(Sender: TObject);
begin
  StartLogin(FSpidMenuAliases[(Sender as TMenuItem).Tag]);
end;

procedure TMainForm.SpidOtherAliasClick(Sender: TObject);
var
  LAlias: string;
begin
  // spid-test: SPID provider of the sample Keycloak, bound to the spid-saml-check demo identity provider
  LAlias := 'spid-test';
  if InputQuery('Sign in with SPID', 'SPID identity provider alias', LAlias) and not Trim(LAlias).IsEmpty then
    StartLogin(Trim(LAlias));
end;

{ Identity provider administration }

procedure TMainForm.RefreshIdPsActionExecute(Sender: TObject);
begin
  RefreshIdentityProviders;
end;

procedure TMainForm.RefreshIdentityProviders;
begin
  if FPending.CloseRequested or not Assigned(FIdentityProviderManager) then
    Exit;
  FPending.BeginOperation;
  FIdentityProviderManager.GetIdentityProvidersAsync
    .OnSuccess(
    procedure(const AProviders: TArray<TIAM4DIdentityProvider>)
    begin
      FIdentityProviders := AProviders;
      FIdentityProvidersLoaded := True;
      FillIdentityProviderList;
      RebuildSpidMenu;
      AdminLog(Format('Identity providers in the realm: %d.', [Length(AProviders)]));
    end)
    .OnError(
    procedure(const E: Exception)
    begin
      AdminLog('Listing the identity providers failed: ' + E.Message);
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.FillIdentityProviderList;
var
  LProvider: TIAM4DIdentityProvider;
  LItem: TListItem;
begin
  IdPListView.Items.BeginUpdate;
  try
    IdPListView.Items.Clear;
    for LProvider in FIdentityProviders do
    begin
      LItem := IdPListView.Items.Add;
      LItem.Caption := LProvider.Alias;
      LItem.SubItems.Add(LProvider.ProviderID);
      LItem.SubItems.Add(LProvider.DisplayName);
      LItem.SubItems.Add(CYesNo[LProvider.Enabled]);
      LItem.SubItems.Add(CYesNo[LProvider.HideOnLogin]);
    end;
  finally
    IdPListView.Items.EndUpdate;
  end;
end;

function TMainForm.FindIdentityProvider(const AAlias: string; out AIdentityProvider: TIAM4DIdentityProvider): Boolean;
var
  LProvider: TIAM4DIdentityProvider;
begin
  for LProvider in FIdentityProviders do
    if LProvider.Alias = AAlias then
    begin
      AIdentityProvider := LProvider;
      Exit(True);
    end;
  Result := False;
end;

procedure TMainForm.IdPListViewSelectItem(Sender: TObject; Item: TListItem; Selected: Boolean);
begin
  if Selected then
    UpdateBrokerURLs(Item.Caption);
end;

procedure TMainForm.DeleteIdPActionExecute(Sender: TObject);
var
  LAlias: string;
begin
  if IdPListView.Selected = nil then
    Exit;
  LAlias := IdPListView.Selected.Caption;
  if MessageDlg(Format('Delete the identity provider "%s"?', [LAlias]), mtConfirmation, [mbYes, mbNo], 0) <> mrYes then
    Exit;

  FPending.BeginOperation;
  FIdentityProviderManager.DeleteIdentityProviderAsync(LAlias)
    .OnSuccess(
    procedure
    begin
      AdminLog(Format('Identity provider "%s" deleted.', [LAlias]));
      RefreshIdentityProviders;
    end)
    .OnError(
    procedure(const E: Exception)
    begin
      AdminLog(Format('Deleting "%s" failed: %s', [LAlias, E.Message]));
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.SaveIdentityProvider(const AIdentityProvider: TIAM4DIdentityProvider;
  const AMappers: TArray<TIAM4DIdentityProviderMapper>);
var
  LAlias: string;
  LMappers: TArray<TIAM4DIdentityProviderMapper>;
begin
  if FPending.CloseRequested or not Assigned(FIdentityProviderManager) then
    Exit;
  LAlias := AIdentityProvider.Alias;
  LMappers := AMappers;
  FPending.BeginOperation;
  // Creates the provider, or updates it when the alias exists
  FIdentityProviderManager.SaveIdentityProviderAsync(AIdentityProvider)
    .OnSuccess(
    procedure
    begin
      AdminLog(Format('Identity provider "%s" saved.', [LAlias]));
      UpdateBrokerURLs(LAlias);
      AdminLog('Broker redirect URI: ' + RedirectURIEdit.Text);
      if Length(LMappers) > 0 then
        AddMissingMappers(LAlias, LMappers);
      RefreshIdentityProviders;
    end)
    .OnError(
    procedure(const E: Exception)
    begin
      AdminLog(Format('Saving "%s" failed: %s', [LAlias, E.Message]));
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.AddMissingMappers(const AAlias: string; const AMappers: TArray<TIAM4DIdentityProviderMapper>);
var
  LAlias: string;
  LMappers: TArray<TIAM4DIdentityProviderMapper>;
begin
  if FPending.CloseRequested or not Assigned(FIdentityProviderManager) then
    Exit;
  LAlias := AAlias;
  LMappers := AMappers;
  FPending.BeginOperation;
  FIdentityProviderManager.GetMappersAsync(LAlias)
    .OnSuccess(
    procedure(const AExisting: TArray<TIAM4DIdentityProviderMapper>)
    var
      LMapper, LExisting: TIAM4DIdentityProviderMapper;
      LFound: Boolean;
    begin
      for LMapper in LMappers do
      begin
        LFound := False;
        for LExisting in AExisting do
          LFound := LFound or (LExisting.Name = LMapper.Name);
        if not LFound then
          CreateMapper(LMapper);
      end;
    end)
    .OnError(
    procedure(const E: Exception)
    begin
      AdminLog(Format('Mappers of "%s" not available: %s', [LAlias, E.Message]));
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.CreateMapper(const AMapper: TIAM4DIdentityProviderMapper);
var
  LDescription: string;
begin
  if FPending.CloseRequested or not Assigned(FIdentityProviderManager) then
    Exit;
  LDescription := Format('"%s" of "%s"', [AMapper.Name, AMapper.IdentityProviderAlias]);
  FPending.BeginOperation;
  FIdentityProviderManager.CreateMapperAsync(AMapper)
    .OnSuccess(
    procedure(const AID: string)
    begin
      AdminLog('Mapper created: ' + LDescription);
    end)
    .OnError(
    procedure(const E: Exception)
    begin
      AdminLog(Format('Mapper %s not created: %s', [LDescription, E.Message]));
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.ImportAndSave(const AProviderID, AMetadataURL: string; const AFactory: TIdentityProviderFactory;
  const AMappers: TArray<TIAM4DIdentityProviderMapper>);
var
  LFactory: TIdentityProviderFactory;
  LMappers: TArray<TIAM4DIdentityProviderMapper>;
begin
  LFactory := AFactory;
  LMappers := AMappers;
  AdminLog('Importing the metadata from ' + AMetadataURL);
  FPending.BeginOperation;
  // Keycloak downloads the metadata itself and returns the config it derives from it
  FIdentityProviderManager.ImportConfigAsync(AProviderID, AMetadataURL)
    .OnSuccess(
    procedure(const AConfig: TIAM4DConfigMap)
    var
      LProvider: TIAM4DIdentityProvider;
    begin
      if FPending.CloseRequested then
        Exit;
      try
        LProvider := LFactory(AConfig);
      except
        on E: EIAM4DInvalidConfigurationException do
        begin
          AdminLog(E.Message);
          Exit;
        end;
      end;
      SaveIdentityProvider(LProvider, LMappers);
    end)
    .OnError(
    procedure(const E: Exception)
    begin
      AdminLog('Metadata import failed: ' + E.Message);
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

function TMainForm.IsPublicServiceProvider: Boolean;
begin
  Result := SPTypeComboBox.ItemIndex = 0;
end;

procedure TMainForm.SaveEntraActionExecute(Sender: TObject);
var
  LAlias, LSecret: string;
  LExisting, LProvider: TIAM4DIdentityProvider;
  LBuilder: IIAM4DEntraIdPBuilder;
begin
  LAlias := Trim(EntraAliasEdit.Text);
  LSecret := EntraSecretEdit.Text;
  // Empty secret on an existing provider: the mask keeps the stored one
  if LSecret.IsEmpty and FindIdentityProvider(LAlias, LExisting) then
    LSecret := IAM4D_IDP_SECRET_MASK;
  try
    LBuilder := TIAM4DEntraIdPBuilder.New(LAlias)
      .WithTenant(EntraTenantEdit.Text)
      .WithClient(EntraClientIDEdit.Text, LSecret)
      .WithSyncMode(ismImport)
      .WithHideOnLogin(EntraHideCheckBox.Checked);
    // Without a prompt an Entra ID session still open in the browser signs in again with no question,
    // also after Sign out (back-channel: it ends the Keycloak session, not the Entra ID one).
    // Item 0 (Not set): no prompt, the save removes the one stored in Keycloak
    if EntraPromptComboBox.ItemIndex > 0 then
      LBuilder.WithPrompt(EntraPromptComboBox.Items[EntraPromptComboBox.ItemIndex]);
    LProvider := LBuilder.Build;
  except
    on E: EIAM4DInvalidConfigurationException do
    begin
      MessageDlg(E.Message, mtWarning, [mbOK], 0);
      Exit;
    end;
  end;
  SaveIdentityProvider(LProvider);
end;

procedure TMainForm.SaveGoogleActionExecute(Sender: TObject);
var
  LAlias, LSecret: string;
  LExisting, LProvider: TIAM4DIdentityProvider;
begin
  LAlias := Trim(GoogleAliasEdit.Text);
  LSecret := GoogleSecretEdit.Text;
  // Empty secret on an existing provider: the mask keeps the stored one
  if LSecret.IsEmpty and FindIdentityProvider(LAlias, LExisting) then
    LSecret := IAM4D_IDP_SECRET_MASK;
  try
    LProvider := TIAM4DGoogleIdPBuilder.New(LAlias)
      .WithClient(GoogleClientIDEdit.Text, LSecret)
      .WithHostedDomains(Trim(GoogleDomainsEdit.Text).Split([','], TStringSplitOptions.ExcludeEmpty))
      .WithSyncMode(ismImport)
      .WithTrustEmail(GoogleTrustEmailCheckBox.Checked)
      .WithHideOnLogin(GoogleHideCheckBox.Checked)
      .Build;
  except
    on E: EIAM4DInvalidConfigurationException do
    begin
      MessageDlg(E.Message, mtWarning, [mbOK], 0);
      Exit;
    end;
  end;
  SaveIdentityProvider(LProvider);
end;

procedure TMainForm.SaveFacebookActionExecute(Sender: TObject);
var
  LAlias, LSecret: string;
  LExisting, LProvider: TIAM4DIdentityProvider;
begin
  LAlias := Trim(FacebookAliasEdit.Text);
  LSecret := FacebookSecretEdit.Text;
  // Empty secret on an existing provider: the mask keeps the stored one
  if LSecret.IsEmpty and FindIdentityProvider(LAlias, LExisting) then
    LSecret := IAM4D_IDP_SECRET_MASK;
  try
    // Trust email off: Meta does not state that the email is verified
    LProvider := TIAM4DFacebookIdPBuilder.New(LAlias)
      .WithClient(FacebookAppIDEdit.Text, LSecret)
      .WithSyncMode(ismImport)
      .WithHideOnLogin(FacebookHideCheckBox.Checked)
      .Build;
  except
    on E: EIAM4DInvalidConfigurationException do
    begin
      MessageDlg(E.Message, mtWarning, [mbOK], 0);
      Exit;
    end;
  end;
  SaveIdentityProvider(LProvider);
end;

procedure TMainForm.SaveOidcActionExecute(Sender: TObject);
var
  LAlias, LClientID, LSecret: string;
  LExisting: TIAM4DIdentityProvider;
begin
  LAlias := Trim(OidcAliasEdit.Text);
  LClientID := OidcClientIDEdit.Text;
  LSecret := OidcSecretEdit.Text;
  // Empty secret on an existing provider: the mask keeps the stored one
  if LSecret.IsEmpty and FindIdentityProvider(LAlias, LExisting) then
    LSecret := IAM4D_IDP_SECRET_MASK;
  if Trim(OidcDiscoveryEdit.Text).IsEmpty then
  begin
    MessageDlg('Enter the discovery URL of the provider.', mtWarning, [mbOK], 0);
    Exit;
  end;
  // Endpoints, JWKS and issuer from the discovery document; PKCE, signature and issuer checks by the builder
  ImportAndSave(IAM4D_IDP_PROVIDER_OIDC, Trim(OidcDiscoveryEdit.Text),
    function(const AImportedConfig: TIAM4DConfigMap): TIAM4DIdentityProvider
    begin
      Result := TIAM4DOidcIdPBuilder.New(LAlias)
        .WithImportedConfig(AImportedConfig)
        .WithClient(LClientID, LSecret)
        .WithSyncMode(ismImport)
        .Build;
    end);
end;

procedure TMainForm.SaveOtherActionExecute(Sender: TObject);
var
  LAlias, LClientID, LSecret: string;
  LClaims: TArray<string>;
  LExisting, LProvider: TIAM4DIdentityProvider;
begin
  LAlias := Trim(OtherAliasEdit.Text);
  LClientID := OtherClientIDEdit.Text;
  LSecret := OtherSecretEdit.Text;
  // Empty secret on an existing provider: the mask keeps the stored one
  if LSecret.IsEmpty and FindIdentityProvider(LAlias, LExisting) then
    LSecret := IAM4D_IDP_SECRET_MASK;
  try
    case FOtherType of
      COtherMicrosoft:
        LProvider := TIAM4DMicrosoftIdPBuilder.New(LAlias)
          .WithTenant(OtherTenantEdit.Text)
          .WithClient(LClientID, LSecret)
          .WithSyncMode(ismImport)
          .WithTrustEmail(OtherTrustEmailCheckBox.Checked)
          .WithHideOnLogin(OtherHideCheckBox.Checked)
          .Build;
      COtherLinkedIn:
        LProvider := TIAM4DLinkedInIdPBuilder.New(LAlias)
          .WithClient(LClientID, LSecret)
          .WithSyncMode(ismImport)
          .WithTrustEmail(OtherTrustEmailCheckBox.Checked)
          .WithHideOnLogin(OtherHideCheckBox.Checked)
          .Build;
      COtherGitHub:
        // No trust email: Keycloak does not check that the GitHub email is verified
        LProvider := TIAM4DGitHubIdPBuilder.New(LAlias)
          .WithClient(LClientID, LSecret)
          .WithEnterprise(OtherBaseURLEdit.Text, OtherApiURLEdit.Text)
          .WithSyncMode(ismImport)
          .WithHideOnLogin(OtherHideCheckBox.Checked)
          .Build;
      COtherGitLab:
        LProvider := TIAM4DGitLabIdPBuilder.New(LAlias)
          .WithClient(LClientID, LSecret)
          .WithSyncMode(ismImport)
          .WithTrustEmail(OtherTrustEmailCheckBox.Checked)
          .WithHideOnLogin(OtherHideCheckBox.Checked)
          .Build;
    else
      // User ID, username and email fields of the user info response; empty: Keycloak default
      LClaims := (Trim(OtherClaimsEdit.Text) + ',,').Split([',']);
      LProvider := TIAM4DOAuth2IdPBuilder.New(LAlias)
        .WithEndpoints(OtherAuthURLEdit.Text, OtherTokenURLEdit.Text, OtherUserInfoURLEdit.Text)
        .WithClient(LClientID, LSecret)
        .WithScopes(Trim(OtherScopesEdit.Text).Split([' ', ','], TStringSplitOptions.ExcludeEmpty))
        .WithUserProfileClaims(LClaims[0], LClaims[1], LClaims[2])
        .WithSyncMode(ismImport)
        .WithTrustEmail(OtherTrustEmailCheckBox.Checked)
        .WithHideOnLogin(OtherHideCheckBox.Checked)
        .Build;
    end;
  except
    on E: EIAM4DInvalidConfigurationException do
    begin
      MessageDlg(E.Message, mtWarning, [mbOK], 0);
      Exit;
    end;
  end;
  SaveIdentityProvider(LProvider);
end;

procedure TMainForm.SaveSpidActionExecute(Sender: TObject);
var
  LEntry: TSpidRegistryEntry;
  LBuilder: IIAM4DSpidIdPBuilder;
begin
  if SpidProviderComboBox.ItemIndex < 0 then
    Exit;
  LEntry := FSpidRegistry[SpidProviderComboBox.ItemIndex];
  // Local test: the URL of the field, which follows SPID_CHECK_PORT
  if SpidProviderComboBox.ItemIndex = CSpidLocalTest then
    LEntry.MetadataURL := Trim(SpidMetadataEdit.Text);
  // Service provider data first: invalid values are reported before the import
  try
    LBuilder := TIAM4DSpidIdPBuilder.New(Trim(SpidAliasEdit.Text))
      .WithDisplayName(LEntry.OrganizationName)
      .WithLevel(TIAM4DSpidLevel(SpidLevelComboBox.ItemIndex))
      .WithAttributeConsumingService(1, ServiceNameEdit.Text)
      .WithOrganization(OrgNameEdit.Text, OrgDisplayNameEdit.Text, OrgURLEdit.Text)
      .WithHideOnLogin(SpidHideCheckBox.Checked);
    if IsPublicServiceProvider then
      LBuilder.WithPublicServiceProvider(IpaCodeEdit.Text, EmailEdit.Text, PhoneEdit.Text)
    else
      LBuilder.WithPrivateServiceProvider(VatNumberEdit.Text, FiscalCodeEdit.Text, OrgNameEdit.Text,
        EmailEdit.Text, PhoneEdit.Text);
  except
    on E: EIAM4DInvalidConfigurationException do
    begin
      MessageDlg(E.Message, mtWarning, [mbOK], 0);
      Exit;
    end;
  end;

  ImportAndSave(IAM4D_IDP_PROVIDER_SPID, LEntry.MetadataURL,
    function(const AImportedConfig: TIAM4DConfigMap): TIAM4DIdentityProvider
    begin
      Result := LBuilder.WithImportedConfig(AImportedConfig).Build;
    end,
    SpidAttributeMappers(Trim(SpidAliasEdit.Text)));
end;

procedure TMainForm.SaveCieActionExecute(Sender: TObject);
var
  LBuilder: IIAM4DCieIdPBuilder;
begin
  try
    LBuilder := TIAM4DCieIdPBuilder.New(Trim(CieAliasEdit.Text))
      .WithLevel(TIAM4DSpidLevel(CieLevelComboBox.ItemIndex))
      .WithAttributeConsumingService(1, ServiceNameEdit.Text)
      .WithOrganization(OrgNameEdit.Text, OrgDisplayNameEdit.Text, OrgURLEdit.Text)
      .WithHideOnLogin(CieHideCheckBox.Checked);
    // Local test: no environment, the imported metadata of the simulator decides
    if CieEnvironmentComboBox.ItemIndex <> CCieLocalTest then
      LBuilder.WithEnvironment(TIAM4DCieEnvironment(CieEnvironmentComboBox.ItemIndex));
    if IsPublicServiceProvider then
      LBuilder.WithPublicServiceProvider(OrgNameEdit.Text, IpaCodeEdit.Text, IpaCategoryEdit.Text,
        EmailEdit.Text, PhoneEdit.Text)
    else
      LBuilder.WithPrivateServiceProvider(OrgNameEdit.Text, VatNumberEdit.Text, FiscalCodeEdit.Text,
        EmailEdit.Text, PhoneEdit.Text);
  except
    on E: EIAM4DInvalidConfigurationException do
    begin
      MessageDlg(E.Message, mtWarning, [mbOK], 0);
      Exit;
    end;
  end;

  ImportAndSave(IAM4D_IDP_PROVIDER_CIE, Trim(CieMetadataEdit.Text),
    function(const AImportedConfig: TIAM4DConfigMap): TIAM4DIdentityProvider
    begin
      Result := LBuilder.WithImportedConfig(AImportedConfig).Build;
    end,
    CieAttributeMappers(Trim(CieAliasEdit.Text)));
end;

{ Broker URLs and form fields }

function TMainForm.RealmURL: string;
begin
  if IsSignedIn and not FClient.Issuer.IsEmpty then
    Result := FClient.Issuer.TrimRight(['/'])
  else
    Result := Trim(BaseURLEdit.Text).TrimRight(['/']) + '/realms/' + Trim(RealmEdit.Text);
end;

procedure TMainForm.UpdateBrokerURLs(const AAlias: string);
begin
  FBrokerAlias := Trim(AAlias);
  RedirectAliasEdit.Text := FBrokerAlias;
  if FBrokerAlias.IsEmpty then
    RedirectURIEdit.Text := ''
  else
    // Register it with the provider (Entra ID: redirect URI of type Web)
    RedirectURIEdit.Text := RealmURL + '/broker/' + FBrokerAlias + '/endpoint';
  // Service provider metadata to register with AgID (SPID) and the Ministry of the Interior (CIE)
  SpidSPMetadataEdit.Text := TIAM4DSpidIdPBuilder.ServiceProviderMetadataURL(Trim(BaseURLEdit.Text), Trim(RealmEdit.Text));
  CieSPMetadataEdit.Text := TIAM4DCieIdPBuilder.ServiceProviderMetadataURL(Trim(BaseURLEdit.Text), Trim(RealmEdit.Text));
end;

procedure TMainForm.BrokerPageControlChange(Sender: TObject);
begin
  if BrokerPageControl.ActivePage = EntraTabSheet then
    UpdateBrokerURLs(EntraAliasEdit.Text)
  else if BrokerPageControl.ActivePage = GoogleTabSheet then
    UpdateBrokerURLs(GoogleAliasEdit.Text)
  else if BrokerPageControl.ActivePage = FacebookTabSheet then
    UpdateBrokerURLs(FacebookAliasEdit.Text)
  else if BrokerPageControl.ActivePage = OidcTabSheet then
    UpdateBrokerURLs(OidcAliasEdit.Text)
  else if BrokerPageControl.ActivePage = OtherTabSheet then
    UpdateBrokerURLs(OtherAliasEdit.Text)
  else if BrokerPageControl.ActivePage = SpidTabSheet then
    UpdateBrokerURLs(SpidAliasEdit.Text)
  else if BrokerPageControl.ActivePage = CieTabSheet then
    UpdateBrokerURLs(CieAliasEdit.Text);
end;

procedure TMainForm.AliasEditChange(Sender: TObject);
begin
  UpdateBrokerURLs((Sender as TEdit).Text);
end;

procedure TMainForm.ConnectionEditChange(Sender: TObject);
begin
  UpdateBrokerURLs(FBrokerAlias);
end;

procedure TMainForm.SpidProviderComboBoxChange(Sender: TObject);
var
  LIndex: Integer;
begin
  LIndex := SpidProviderComboBox.ItemIndex;
  if (LIndex < 0) or (LIndex > High(FSpidRegistry)) then
  begin
    SpidMetadataEdit.Text := '';
    Exit;
  end;
  SpidAliasEdit.Text := FSpidRegistry[LIndex].Alias;
  SpidMetadataEdit.Text := FSpidRegistry[LIndex].MetadataURL;
  // The URL of the demo identity provider follows SPID_CHECK_PORT: editable only there
  SpidMetadataEdit.ReadOnly := LIndex <> CSpidLocalTest;
  UpdateBrokerURLs(SpidAliasEdit.Text);
end;

procedure TMainForm.CieEnvironmentComboBoxChange(Sender: TObject);
begin
  if CieEnvironmentComboBox.ItemIndex < 0 then
    Exit;
  // The simulator URL follows CIE_CHECK_PORT: editable only there
  CieMetadataEdit.ReadOnly := CieEnvironmentComboBox.ItemIndex <> CCieLocalTest;
  if CieEnvironmentComboBox.ItemIndex = CCieLocalTest then
    CieMetadataEdit.Text := CCieSimulatorMetadataURL
  else
    CieMetadataEdit.Text := TIAM4DCieIdPBuilder.MetadataURL(TIAM4DCieEnvironment(CieEnvironmentComboBox.ItemIndex));
end;

procedure TMainForm.SPTypeComboBoxChange(Sender: TObject);
var
  LPublic: Boolean;
begin
  LPublic := IsPublicServiceProvider;
  IpaCodeEdit.Enabled := LPublic;
  IpaCategoryEdit.Enabled := LPublic;
  VatNumberEdit.Enabled := not LPublic;
  FiscalCodeEdit.Enabled := not LPublic;
end;

procedure TMainForm.OtherTypeComboBoxChange(Sender: TObject);
begin
  if OtherTypeComboBox.ItemIndex < 0 then
    Exit;
  // The alias follows the type while it is the default one
  if Trim(OtherAliasEdit.Text).IsEmpty or SameText(Trim(OtherAliasEdit.Text), COtherAliases[FOtherType]) then
    OtherAliasEdit.Text := COtherAliases[OtherTypeComboBox.ItemIndex];
  FOtherType := OtherTypeComboBox.ItemIndex;
  UpdateOtherFields;
end;

procedure TMainForm.UpdateOtherFields;
const
  CNotes: array[COtherMicrosoft..COtherOAuth2] of string = (
    'Personal Microsoft accounts, profile from Microsoft Graph (work accounts: Microsoft Entra ID tab). ' +
    'Trust email only with a directory ID as tenant.',
    'LinkedIn app with the product "Sign In with LinkedIn using OpenID Connect". Keycloak validates the id_token ' +
    'and, with trust email, trusts only the emails LinkedIn verified.',
    'GitHub OAuth app: register the redirect URI as authorization callback URL. No trust email: Keycloak does not ' +
    'check that the GitHub email is verified.',
    'gitlab.com only (a self-managed GitLab is a Generic OIDC provider). Confidential application with scopes ' +
    'openid, read_user and email.',
    '');
var
  LPanel: TPanel;
  LTop: Integer;
begin
  OtherTenantPanel.Visible := FOtherType = COtherMicrosoft;
  OtherBaseURLPanel.Visible := FOtherType = COtherGitHub;
  OtherApiURLPanel.Visible := FOtherType = COtherGitHub;
  OtherAuthURLPanel.Visible := FOtherType = COtherOAuth2;
  OtherTokenURLPanel.Visible := FOtherType = COtherOAuth2;
  OtherUserInfoURLPanel.Visible := FOtherType = COtherOAuth2;
  OtherScopesPanel.Visible := FOtherType = COtherOAuth2;
  OtherClaimsPanel.Visible := FOtherType = COtherOAuth2;
  // OAuth 2.0 fills the column: no room for the note
  OtherNoteLabel.Visible := FOtherType <> COtherOAuth2;
  OtherNoteLabel.Caption := CNotes[FOtherType];
  OtherTrustEmailCheckBox.Enabled := FOtherType <> COtherGitHub;
  if not OtherTrustEmailCheckBox.Enabled then
    OtherTrustEmailCheckBox.Checked := False;
  // Panels shown again go below the visible ones: restore the order, note last
  OtherRightPanel.DisableAlign;
  try
    LTop := 0;
    for LPanel in [OtherTenantPanel, OtherBaseURLPanel, OtherApiURLPanel, OtherAuthURLPanel, OtherTokenURLPanel,
      OtherUserInfoURLPanel, OtherScopesPanel, OtherClaimsPanel] do
      if LPanel.Visible then
      begin
        LPanel.Top := LTop;
        Inc(LTop, 28);
      end;
    OtherNoteLabel.Top := LTop;
  finally
    OtherRightPanel.EnableAlign;
  end;
end;

procedure TMainForm.AdminLog(const AText: string);
begin
  AdminMemo.Lines.Add(AText);
end;

end.
