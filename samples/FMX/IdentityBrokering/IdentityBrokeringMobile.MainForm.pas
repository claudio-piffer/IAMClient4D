unit IdentityBrokeringMobile.MainForm;

// Mobile (FMX) version of the IdentityBrokering sample: sign in with Keycloak, Microsoft Entra ID, a personal
// Microsoft account, Google, Facebook, SPID and CIE ID, and administer the identity providers of the realm with the session of the signed-in user.
// On Android and iOS the login redirects to a private-use URI scheme (RFC 8252 7.1) that the operating
// system hands to the app (TIAM4DAppRedirectListener); on Windows it uses the loopback server.

interface

uses
  System.SysUtils,
  System.Types,
  System.UITypes,
  System.Classes,
  System.Math,
  System.Messaging,
  FMX.Types,
  FMX.Controls,
  FMX.Forms,
  FMX.Graphics,
  FMX.Dialogs,
  FMX.StdCtrls,
  FMX.Edit,
  FMX.ListBox,
  FMX.Layouts,
  FMX.Memo,
  FMX.Memo.Types,
  FMX.ScrollBox,
  FMX.Objects,
  FMX.Skia,
  FMX.TabControl,
  FMX.Controls.Presentation,
  FMX.Ani,
  FMX.Effects,
  Async.Core,
  IAMClient4D.Core,
  IAMClient4D.IdentityProvider.Core,
  Samples.PendingOperations.FMX,
  IdentityBrokering.SpidRegistry,
  IdentityBrokering.Common, System.Skia;

type
  TIdentityProviderFactory = reference to function(const AImportedConfig: TIAM4DConfigMap): TIAM4DIdentityProvider;

  TMainForm = class(TForm)
    PageBackground: TRectangle;
    DecoCircle1: TCircle;
    DecoCircle2: TCircle;
    HeaderBackdrop: TRectangle;
    BackdropLayer: TLayout;
    SafeTop: TLayout;
    SafeBottom: TLayout;
    KeyboardSpacer: TLayout;
    NavLayer: TLayout;
    NavFade: TRectangle;
    NavPill: TRectangle;
    NavLoginIcon: TSkSvg;
    NavLoginLabel: TSkLabel;
    NavLoginItem: TLayout;
    NavAdminIcon: TSkSvg;
    NavAdminLabel: TSkLabel;
    NavAdminItem: TLayout;
    BottomNav: TRectangle;
    LoginScrollTop: TLayout;
    LogoIcon: TSkSvg;
    LogoBox: TRectangle;
    TitleLabel: TSkLabel;
    SubtitleLabel: TSkLabel;
    StatusDot: TCircle;
    StatusCheck: TSkAnimatedImage;
    SessionLabel: TSkLabel;
    StatusChip: TRectangle;
    HeroLayout: TLayout;
    ConnIcon: TSkSvg;
    ConnChevron: TSkSvg;
    ConnTitle: TSkLabel;
    ConnSummary: TSkLabel;
    ConnText: TLayout;
    ConnHeader: TLayout;
    BaseURLLabel: TSkLabel;
    BaseURLEdit: TEdit;
    BaseURLField: TLayout;
    RealmLabel: TSkLabel;
    RealmEdit: TEdit;
    RealmField: TLayout;
    ClientLabel: TSkLabel;
    ClientEdit: TEdit;
    ClientField: TLayout;
    RedirectCaption: TSkLabel;
    RedirectLabel: TSkLabel;
    RedirectInfo: TLayout;
    ConnBody: TLayout;
    ConnectionCard: TRectangle;
    SignInTitle: TSkLabel;
    KeycloakTileIcon: TSkSvg;
    KeycloakTileTitle: TSkLabel;
    KeycloakTileSubtitle: TSkLabel;
    KeycloakTile: TRectangle;
    EntraTileIcon: TSkSvg;
    EntraTileTitle: TSkLabel;
    EntraTileSubtitle: TSkLabel;
    EntraTile: TRectangle;
    MicrosoftTileIcon: TSkSvg;
    MicrosoftTileTitle: TSkLabel;
    MicrosoftTileSubtitle: TSkLabel;
    MicrosoftTile: TRectangle;
    TileRow1: TLayout;
    TileRow2: TLayout;
    GoogleTileIcon: TSkSvg;
    GoogleTileTitle: TSkLabel;
    GoogleTileSubtitle: TSkLabel;
    GoogleTile: TRectangle;
    FacebookTileIcon: TSkSvg;
    FacebookTileTitle: TSkLabel;
    FacebookTileSubtitle: TSkLabel;
    FacebookTile: TRectangle;
    TileRow3: TLayout;
    SpidTileIcon: TSkSvg;
    SpidTileTitle: TSkLabel;
    SpidTileSubtitle: TSkLabel;
    SpidTile: TRectangle;
    CieTileIcon: TSkSvg;
    CieTileTitle: TSkLabel;
    CieTileSubtitle: TSkLabel;
    CieTile: TRectangle;
    TileRow4: TLayout;
    LoginIndicator: TSkAnimatedImage;
    CancelLoginButtonCaption: TSkLabel;
    CancelLoginButton: TRectangle;
    WaitLabel: TSkLabel;
    CancelPanel: TLayout;
    SignInCard: TRectangle;
    SessionTitle: TSkLabel;
    UserInfoButtonCaption: TSkLabel;
    UserInfoButton: TRectangle;
    AccessTokenButtonCaption: TSkLabel;
    AccessTokenButton: TRectangle;
    LogoutButtonCaption: TSkLabel;
    LogoutButton: TRectangle;
    SessionRow: TLayout;
    SessionCard: TRectangle;
    OutputTitle: TSkLabel;
    LoginMemo: TMemo;
    OutputCard: TRectangle;
    LoginScrollBottom: TLayout;
    LoginScroll: TVertScrollBox;
    LoginTab: TLayout;
    AdminTitle: TSkLabel;
    AdminStatusLabel: TSkLabel;
    AdminHead: TLayout;
    AdminChip1Label: TSkLabel;
    AdminChip1: TRectangle;
    AdminChip2Label: TSkLabel;
    AdminChip2: TRectangle;
    AdminChip3Label: TSkLabel;
    AdminChip3: TRectangle;
    AdminChip4Label: TSkLabel;
    AdminChip4: TRectangle;
    AdminChip5Label: TSkLabel;
    AdminChip5: TRectangle;
    AdminChip6Label: TSkLabel;
    AdminChip6: TRectangle;
    AdminChip7Label: TSkLabel;
    AdminChip7: TRectangle;
    AdminChip8Label: TSkLabel;
    AdminChip8: TRectangle;
    AdminChip9Label: TSkLabel;
    AdminChip9: TRectangle;
    AdminChip10Label: TSkLabel;
    AdminChip10: TRectangle;
    AdminChips: THorzScrollBox;
    AdminIndicator: TSkAnimatedImage;
    IdPTitle: TSkLabel;
    IdPList: TListBox;
    RefreshIdPsButtonIcon: TSkSvg;
    RefreshIdPsButtonCaption: TSkLabel;
    RefreshIdPsButton: TRectangle;
    DeleteIdPButtonIcon: TSkSvg;
    DeleteIdPButtonCaption: TSkLabel;
    DeleteIdPButton: TRectangle;
    IdPButtons: TLayout;
    IdPCard: TRectangle;
    URLTitle: TSkLabel;
    RedirectAliasLabel: TSkLabel;
    RedirectAliasEdit: TEdit;
    RedirectAliasField: TLayout;
    RedirectURILabel: TSkLabel;
    RedirectURIEdit: TEdit;
    RedirectURIField: TLayout;
    SpidSPMetadataLabel: TSkLabel;
    SpidSPMetadataEdit: TEdit;
    SpidSPMetadataField: TLayout;
    CieSPMetadataLabel: TSkLabel;
    CieSPMetadataEdit: TEdit;
    CieSPMetadataField: TLayout;
    URLCard: TRectangle;
    ProvidersScroll: TVertScrollBox;
    ProvidersTab: TLayout;
    EntraTitle: TSkLabel;
    EntraAliasLabel: TSkLabel;
    EntraAliasEdit: TEdit;
    EntraAliasField: TLayout;
    EntraTenantLabel: TSkLabel;
    EntraTenantEdit: TEdit;
    EntraTenantField: TLayout;
    EntraClientIDLabel: TSkLabel;
    EntraClientIDEdit: TEdit;
    EntraClientIDField: TLayout;
    EntraSecretLabel: TSkLabel;
    EntraSecretEdit: TEdit;
    EntraSecretField: TLayout;
    EntraPromptField: TLayout;
    EntraPromptLabel: TSkLabel;
    EntraPromptBox: TRectangle;
    EntraPromptComboBox: TComboBox;
    EntraHideSwitch: TSwitch;
    EntraHideSwitchLabel: TSkLabel;
    EntraHideRow: TLayout;
    SaveEntraButtonCaption: TSkLabel;
    SaveEntraButton: TRectangle;
    EntraCard: TRectangle;
    EntraScroll: TVertScrollBox;
    EntraTab: TLayout;
    GoogleTitle: TSkLabel;
    GoogleAliasLabel: TSkLabel;
    GoogleAliasEdit: TEdit;
    GoogleAliasField: TLayout;
    GoogleClientIDLabel: TSkLabel;
    GoogleClientIDEdit: TEdit;
    GoogleClientIDField: TLayout;
    GoogleSecretLabel: TSkLabel;
    GoogleSecretEdit: TEdit;
    GoogleSecretField: TLayout;
    GoogleDomainsLabel: TSkLabel;
    GoogleDomainsEdit: TEdit;
    GoogleDomainsField: TLayout;
    GoogleHideSwitch: TSwitch;
    GoogleHideSwitchLabel: TSkLabel;
    GoogleHideRow: TLayout;
    GoogleTrustEmailSwitch: TSwitch;
    GoogleTrustEmailSwitchLabel: TSkLabel;
    GoogleTrustEmailRow: TLayout;
    SaveGoogleButtonCaption: TSkLabel;
    SaveGoogleButton: TRectangle;
    GoogleCard: TRectangle;
    GoogleScroll: TVertScrollBox;
    GoogleTab: TLayout;
    FacebookTitle: TSkLabel;
    FacebookAliasLabel: TSkLabel;
    FacebookAliasEdit: TEdit;
    FacebookAliasField: TLayout;
    FacebookAppIDLabel: TSkLabel;
    FacebookAppIDEdit: TEdit;
    FacebookAppIDField: TLayout;
    FacebookSecretLabel: TSkLabel;
    FacebookSecretEdit: TEdit;
    FacebookSecretField: TLayout;
    FacebookHideSwitch: TSwitch;
    FacebookHideSwitchLabel: TSkLabel;
    FacebookHideRow: TLayout;
    SaveFacebookButtonCaption: TSkLabel;
    SaveFacebookButton: TRectangle;
    FacebookCard: TRectangle;
    FacebookScroll: TVertScrollBox;
    FacebookTab: TLayout;
    OidcTitle: TSkLabel;
    OidcAliasLabel: TSkLabel;
    OidcAliasEdit: TEdit;
    OidcAliasField: TLayout;
    OidcDiscoveryLabel: TSkLabel;
    OidcDiscoveryEdit: TEdit;
    OidcDiscoveryField: TLayout;
    OidcClientIDLabel: TSkLabel;
    OidcClientIDEdit: TEdit;
    OidcClientIDField: TLayout;
    OidcSecretLabel: TSkLabel;
    OidcSecretEdit: TEdit;
    OidcSecretField: TLayout;
    OidcLoginNote: TSkLabel;
    SaveOidcButtonCaption: TSkLabel;
    SaveOidcButton: TRectangle;
    OidcCard: TRectangle;
    OidcScroll: TVertScrollBox;
    OidcTab: TLayout;
    OtherTitle: TSkLabel;
    OtherTypeLabel: TSkLabel;
    OtherTypeComboBox: TComboBox;
    OtherTypeField: TLayout;
    OtherAliasLabel: TSkLabel;
    OtherAliasEdit: TEdit;
    OtherAliasField: TLayout;
    OtherClientIDLabel: TSkLabel;
    OtherClientIDEdit: TEdit;
    OtherClientIDField: TLayout;
    OtherSecretLabel: TSkLabel;
    OtherSecretEdit: TEdit;
    OtherSecretField: TLayout;
    OtherTenantLabel: TSkLabel;
    OtherTenantEdit: TEdit;
    OtherTenantField: TLayout;
    OtherBaseURLLabel: TSkLabel;
    OtherBaseURLEdit: TEdit;
    OtherBaseURLField: TLayout;
    OtherApiURLLabel: TSkLabel;
    OtherApiURLEdit: TEdit;
    OtherApiURLField: TLayout;
    OtherAuthURLLabel: TSkLabel;
    OtherAuthURLEdit: TEdit;
    OtherAuthURLField: TLayout;
    OtherTokenURLLabel: TSkLabel;
    OtherTokenURLEdit: TEdit;
    OtherTokenURLField: TLayout;
    OtherUserInfoURLLabel: TSkLabel;
    OtherUserInfoURLEdit: TEdit;
    OtherUserInfoURLField: TLayout;
    OtherScopesLabel: TSkLabel;
    OtherScopesEdit: TEdit;
    OtherScopesField: TLayout;
    OtherClaimsLabel: TSkLabel;
    OtherClaimsEdit: TEdit;
    OtherClaimsField: TLayout;
    OtherNote: TSkLabel;
    OtherHideSwitch: TSwitch;
    OtherHideSwitchLabel: TSkLabel;
    OtherHideRow: TLayout;
    OtherTrustEmailSwitch: TSwitch;
    OtherTrustEmailSwitchLabel: TSkLabel;
    OtherTrustEmailRow: TLayout;
    SaveOtherButtonCaption: TSkLabel;
    SaveOtherButton: TRectangle;
    OtherCard: TRectangle;
    OtherScroll: TVertScrollBox;
    OtherTab: TLayout;
    SpidTitle: TSkLabel;
    SpidProviderLabel: TSkLabel;
    SpidProviderComboBox: TComboBox;
    SpidProviderField: TLayout;
    LoadRegistryButtonCaption: TSkLabel;
    LoadRegistryButton: TRectangle;
    SpidAliasLabel: TSkLabel;
    SpidAliasEdit: TEdit;
    SpidAliasField: TLayout;
    SpidMetadataLabel: TSkLabel;
    SpidMetadataEdit: TEdit;
    SpidMetadataField: TLayout;
    SpidLevelLabel: TSkLabel;
    SpidLevelComboBox: TComboBox;
    SpidLevelField: TLayout;
    SpidHideSwitch: TSwitch;
    SpidHideSwitchLabel: TSkLabel;
    SpidHideRow: TLayout;
    SaveSpidButtonCaption: TSkLabel;
    SaveSpidButton: TRectangle;
    SpidCard: TRectangle;
    SpidScroll: TVertScrollBox;
    SpidTab: TLayout;
    CieTitle: TSkLabel;
    CieEnvironmentLabel: TSkLabel;
    CieEnvironmentComboBox: TComboBox;
    CieEnvironmentField: TLayout;
    CieAliasLabel: TSkLabel;
    CieAliasEdit: TEdit;
    CieAliasField: TLayout;
    CieMetadataLabel: TSkLabel;
    CieMetadataEdit: TEdit;
    CieMetadataField: TLayout;
    CieLevelLabel: TSkLabel;
    CieLevelComboBox: TComboBox;
    CieLevelField: TLayout;
    CieHideSwitch: TSwitch;
    CieHideSwitchLabel: TSkLabel;
    CieHideRow: TLayout;
    SaveCieButtonCaption: TSkLabel;
    SaveCieButton: TRectangle;
    CieCard: TRectangle;
    CieScroll: TVertScrollBox;
    CieTab: TLayout;
    SPTitle: TSkLabel;
    OrgNameLabel: TSkLabel;
    OrgNameEdit: TEdit;
    OrgNameField: TLayout;
    OrgDisplayNameLabel: TSkLabel;
    OrgDisplayNameEdit: TEdit;
    OrgDisplayNameField: TLayout;
    OrgURLLabel: TSkLabel;
    OrgURLEdit: TEdit;
    OrgURLField: TLayout;
    SPTypeLabel: TSkLabel;
    SPTypeComboBox: TComboBox;
    SPTypeField: TLayout;
    ServiceNameLabel: TSkLabel;
    ServiceNameEdit: TEdit;
    ServiceNameField: TLayout;
    IpaCodeLabel: TSkLabel;
    IpaCodeEdit: TEdit;
    IpaCodeField: TLayout;
    IpaCategoryLabel: TSkLabel;
    IpaCategoryEdit: TEdit;
    IpaCategoryField: TLayout;
    VatNumberLabel: TSkLabel;
    VatNumberEdit: TEdit;
    VatNumberField: TLayout;
    FiscalCodeLabel: TSkLabel;
    FiscalCodeEdit: TEdit;
    FiscalCodeField: TLayout;
    EmailLabel: TSkLabel;
    EmailEdit: TEdit;
    EmailField: TLayout;
    PhoneLabel: TSkLabel;
    PhoneEdit: TEdit;
    PhoneField: TLayout;
    SPCard: TRectangle;
    ServiceProviderScroll: TVertScrollBox;
    ServiceProviderTab: TLayout;
    LogTitle: TSkLabel;
    AdminMemo: TMemo;
    LogCard: TRectangle;
    LogScroll: TVertScrollBox;
    LogTab: TLayout;
    AdminPages: TLayout;
    AdminTab: TLayout;
    MainTabs: TLayout;
    ContentLayer: TLayout;
    SpidPickerScrim: TRectangle;
    SpidPickerGrip: TLayout;
    SpidPickerHandle: TRectangle;
    SpidPickerHeader: TLayout;
    SpidPickerClose: TRectangle;
    SpidPickerCloseIcon: TSkSvg;
    SpidPickerTitle: TSkLabel;
    SpidPickerHint: TSkLabel;
    SpidPickerList: TListBox;
    SpidPickerSheet: TRectangle;
    SpidPickerLayer: TLayout;
    UpdateTimer: TTimer;
    CancelWatchTimer: TTimer;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure FormKeyUp(Sender: TObject; var Key: Word; var KeyChar: Char; Shift: TShiftState);
    procedure LayoutNavItems(const AAnimate: Boolean);
    procedure NavLayerResized(Sender: TObject);
    procedure AnimateTabIn(const ATab: TControl; const ADirection: Integer);
    procedure EnsureFocusedVisible;
    procedure SetupReadOnlyFields;
    procedure SetupPrompts;
    procedure UpdatePrompt(const AEdit: TEdit);
    procedure ShowEditTextStart(const AParent: TFmxObject);
    procedure ReadOnlyFieldClick(Sender: TObject);
    procedure ShowToast(const AText: string);
    procedure FormFocusChanged(Sender: TObject);
    procedure AddNavClearance;
    procedure ApplyAndroidStatusBar;
    procedure FormSafeAreaChanged(Sender: TObject; const AInsets: TRectF);
    procedure FormVirtualKeyboardShown(Sender: TObject; KeyboardVisible: Boolean; const Bounds: TRect);
    procedure FormVirtualKeyboardHidden(Sender: TObject; KeyboardVisible: Boolean; const Bounds: TRect);
    procedure UpdateTimerTimer(Sender: TObject);
    procedure CancelWatchTimerTimer(Sender: TObject);
    procedure EvenRowResized(Sender: TObject);
    procedure PressMouseDown(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Single);
    procedure PressMouseUp(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Single);
    procedure NavLoginClick(Sender: TObject);
    procedure NavAdminClick(Sender: TObject);
    procedure AdminChipClick(Sender: TObject);
    procedure ConnHeaderClick(Sender: TObject);
    procedure KeycloakTileClick(Sender: TObject);
    procedure EntraTileClick(Sender: TObject);
    procedure MicrosoftTileClick(Sender: TObject);
    procedure GoogleTileClick(Sender: TObject);
    procedure FacebookTileClick(Sender: TObject);
    procedure SpidTileClick(Sender: TObject);
    procedure CieTileClick(Sender: TObject);
    procedure CancelLoginButtonClick(Sender: TObject);
    procedure UserInfoButtonClick(Sender: TObject);
    procedure AccessTokenButtonClick(Sender: TObject);
    procedure LogoutButtonClick(Sender: TObject);
    procedure RefreshIdPsButtonClick(Sender: TObject);
    procedure DeleteIdPButtonClick(Sender: TObject);
    procedure SaveEntraButtonClick(Sender: TObject);
    procedure SaveGoogleButtonClick(Sender: TObject);
    procedure SaveFacebookButtonClick(Sender: TObject);
    procedure SaveOidcButtonClick(Sender: TObject);
    procedure SaveOtherButtonClick(Sender: TObject);
    procedure OtherNoteResized(Sender: TObject);
    procedure LoadRegistryButtonClick(Sender: TObject);
    procedure SaveSpidButtonClick(Sender: TObject);
    procedure SaveCieButtonClick(Sender: TObject);
    procedure IdPListChange(Sender: TObject);
    procedure EditChangeTracking(Sender: TObject);
    procedure ComboChange(Sender: TObject);
    procedure SpidPickerScrimClick(Sender: TObject);
    procedure SpidPickerDragDown(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Single);
    procedure SpidPickerDragMove(Sender: TObject; Shift: TShiftState; X, Y: Single);
    procedure SpidPickerDragUp(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Single);
    procedure SpidPickerListItemClick(const Sender: TCustomListBox; const Item: TListBoxItem);
    procedure ChoiceBoxClick(Sender: TObject);
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
    FBrokerAlias: string;
    // Item of OtherTypeComboBox the fields are shown for
    FOtherType: Integer;
    FConnExpanded: Boolean;
    FMainPage: Integer;
    FSafeBottom: Single;
    // Drag of the SPID sheet: finger position in form coordinates (the sheet moves under the finger)
    FSpidDragging: Boolean;
    FSpidDragStartY: Single;
    FSpidDragLastY: Single;
    FSpidDragLastTick: Cardinal;
    FSpidDragVelocity: Single;
    FSpidSlideOut: TFloatAnimation;
    // Combo box of the Providers page whose choice the sheet shows; nil: the sheet signs in with SPID
    FSpidPickerCombo: TComboBox;
    FKeyboardVisible: Boolean;
    FToast: TRectangle;
    FToastLabel: TSkLabel;
    FAppEventSubscription: TMessageSubscriptionId;
    function IsSignedIn: Boolean;
    procedure ApplyIcons;
    procedure SetIcon(const ASvg: TSkSvg; const APathData: string; const AViewBox: Integer = 24);
    procedure SetSpinner(const AImage: TSkAnimatedImage; const ABusy: Boolean);
    procedure SetRichText(const ALabel: TSkLabel; const AParts: array of string; const ABold: array of Boolean;
      const AStrong, AWeak: TAlphaColor);
    procedure ShowSessionCheck(const ASignedIn: Boolean);
    procedure ApplyFonts;
    procedure SelectMainTab(const AIndex: Integer);
    procedure SelectAdminChip(const AIndex: Integer);
    procedure UpdateControls;
    procedure UpdateConnectionSummary;
    procedure SetEnabledLook(const AControl: TControl; const AEnabled: Boolean);
    procedure ApplicationEventMessage(const ASender: TObject; const AMessage: TMessage);
    procedure AppRedirectReceived(const AURL: string; const ATaken: Boolean);
    procedure StartLogin(const AIdpHint: string);
    procedure RunAuthorizationFlow(const AIdpHint: string);
    procedure ShowSession(const AAccessToken: string);
    procedure AddUserInfo(const AUserInfo: TIAM4DUserInfo);
    procedure AddAccessToken(const AAccessToken: string);
    procedure UpdateSessionState;
    procedure UpdateAdminAccess(const AAccessToken: string);
    procedure LoadSpidRegistry(const AShowPicker: Boolean; const AForAdmin: Boolean = False);
    procedure ChoiceTexts(const ACombo: TComboBox; out ATitle, AHint: string; out ADetails: TArray<string>);
    procedure FillSpidProviders;
    procedure RebuildSpidPicker;
    procedure FitSpidPickerSheet;
    procedure ShowSpidPicker(const ACombo: TComboBox = nil);
    procedure HideSpidPicker;
    procedure CloseSpidPicker;
    procedure SpidPickerSlideOutFinished(Sender: TObject);
    procedure AskSpidAlias;
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
    procedure FitOtherCard;
    procedure AdminLog(const AText: string);
    procedure LoginLog(const AText: string);
    procedure Warn(const AText: string);
  end;

var
  MainForm: TMainForm;

implementation

{$R *.fmx}

uses
  System.Generics.Collections,
  FMX.Platform,
  FMX.DialogService.Async,
  IdentityBrokeringMobile.Animations,
  IAMClient4D.Config.Builder,
  IAMClient4D.Exceptions,
  IAMClient4D.Callback.Handler.AppRedirect,
  IAMClient4D.FMX.AppRedirect,
  IAMClient4D.IdentityProvider.Keycloak.Async,
  IAMClient4D.IdentityProvider.Builders
  {$IF Defined(ANDROID)},
  Androidapi.Helpers,
  Androidapi.JNI.App,
  Androidapi.JNI.GraphicsContentViewText,
  Androidapi.JNIBridge
  {$ENDIF};

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
  // Redirect URI of the mobile app: private-use scheme (reverse domain name), one slash (RFC 8252 7.1).
  // It must be a valid redirect URI of the client and match the intent filter / CFBundleURLTypes
  CAppRedirectURI = 'it.iam4d.identitybrokering:/oauth2callback';

  // Palette
  CIndigo = $FF4F46E5;
  // Dark indigo of the navigation dock: the active chip stands out on the violet header
  CDockDark = $FF1E1B4B;
  CMuted = $FF6B7280;
  CText = $FF111827;
  CSoftWhite = $CCFFFFFF;
  CGreen = $FF22C55E;
  CRed = $FFEF4444;
  CWhite = $FFFFFFFF;
  // Floating navigation dock
  CNavWidth = 280;
  CNavActive = $FFFFFFFF;
  CNavInactive = $FFD2CEF7;
  // First two stops of the header gradient (HeaderBackdrop in the .fmx)
  HeaderGradientStart = $FF4338CA;
  HeaderGradientMiddle = $FF7C3AED;
  HeaderStatusBarColor = $FF5F39DB;
  CFieldBackground = $FFF3F4F8;

  // Height of the floating bar and its margin from the bottom, plus a gap
  CNavClearance = 96;

  // Read-only fields (values to copy)
  CReadOnlyBackground = $FFE6E8F1;
  CReadOnlyText = $FF4B5563;

  // Prompt of the empty fields: color and left inset of the text in the transparentedit style
  CPromptText = $FF82868F;
  CPromptInset = 2;

  CConnCollapsed = 80;
  CConnExpanded = 16 + 64 + 72 * 3 + 56 + 4 + 16;

  // Material Design icons (24 x 24), as path data of an SVG
  // Shield and padlock of the IAMClient4D logo (100 x 100), padlock cut out (even-odd)
  CIconBrand = 'M50,5 C62,13 74,16 86,17 L86,48 C86,70 71,86 50,95 C29,86 14,70 14,48 L14,17 C26,16 38,13 50,5 Z ' +
    'M36,47 V40 A14,14 0 0 1 64,40 V47 H58 V40 A8,8 0 0 0 42,40 V47 Z ' +
    'M33,47 H67 V73 Q67,76 64,76 H36 Q33,76 33,73 Z ' +
    'M50,53 A4.5,4.5 0 1 1 50,62 A4.5,4.5 0 1 1 50,53 Z M48,60 H52 V68 H48 Z';
  CIconKey = 'M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z';
  CIconMicrosoft = 'M3 3h8.5v8.5H3zM12.5 3H21v8.5h-8.5zM3 12.5h8.5V21H3zM12.5 12.5H21V21h-8.5z';
  CIconGoogle = 'M21.35,11.1H12.18V13.83H18.69C18.36,17.64 15.19,19.27 12.19,19.27C8.36,19.27 5,16.25 5,12C5,7.9 8.2,4.73 12.2,4.73C15.29,4.73 17.1,6.7 17.1,6.7L19,4.72C19,4.72 16.56,2 12.1,2C6.42,2 2.03,6.8 2.03,12C2.03,17.05 6.16,22 12.25,22C17.6,22 21.5,18.33 21.5,12.91C21.5,11.76 21.35,11.1 21.35,11.1V11.1Z';
  CIconFacebook = 'M12 2.04C6.5 2.04 2 6.53 2 12.06C2 17.06 5.66 21.21 10.44 21.96V14.96H7.9V12.06H10.44V9.85C10.44 7.34 11.93 5.96 14.22 5.96C15.31 5.96 16.45 6.15 16.45 6.15V8.62H15.19C13.95 8.62 13.56 9.39 13.56 10.18V12.06H16.34L15.89 14.96H13.56V21.96A10 10 0 0 0 22 12.06C22 6.53 17.5 2.04 12 2.04Z';
  CIconPerson = 'M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z';
  CIconCard = 'M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 14H4V6h16v12zM6 9h6v2H6zm0 4h4v2H6zm8-4h4v6h-4z';
  CIconServers = 'M20 13H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1v-6c0-.55-.45-1-1-1zM7 19c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM20 3H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1V4c0-.55-.45-1-1-1zM7 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z';
  CIconRefresh = 'M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z';
  CIconDelete = 'M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z';
  CIconChevron = 'M7.41 8.59L12 13.17l4.59-4.58L18 10l-6 6-6-6 1.41-1.41z';
  CIconClose = 'M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z';
  CIconCopy ='M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z';
  CIconLink = 'M3.9 12c0-1.71 1.39-3.1 3.1-3.1h4V7H7c-2.76 0-5 2.24-5 5s2.24 5 5 5h4v-1.9H7c-1.71 0-3.1-1.39-3.1-3.1zM8 13h8v-2H8v2zm9-6h-4v1.9h4c1.71 0 3.1 1.39 3.1 3.1s-1.39 3.1-3.1 3.1h-4V17h4c2.76 0 5-2.24 5-5s-2.24-5-5-5z';

{ TMainForm }

procedure TMainForm.SetSpinner(const AImage: TSkAnimatedImage; const ABusy: Boolean);
begin
  AImage.Visible := ABusy;
  if ABusy then
    AImage.Animation.Start
  else
    AImage.Animation.Stop;
end;

procedure TMainForm.SetRichText(const ALabel: TSkLabel; const AParts: array of string; const ABold: array of Boolean;
  const AStrong, AWeak: TAlphaColor);
var
  I: Integer;
begin
  // Runs of text with their own weight and colour: strong parts bold, the rest regular and muted
  ALabel.Words.BeginUpdate;
  try
    ALabel.Words.Clear;
    for I := 0 to High(AParts) do
      if ABold[I] then
        ALabel.Words.Add(AParts[I], AStrong, ALabel.TextSettings.Font.Size, TFontWeight.Bold)
      else
        ALabel.Words.Add(AParts[I], AWeak, ALabel.TextSettings.Font.Size, TFontWeight.Regular);
  finally
    ALabel.Words.EndUpdate;
  end;
end;

procedure TMainForm.ShowSessionCheck(const ASignedIn: Boolean);
begin
  // Signed in: the dot turns into a check that draws itself; signed out: back to the red dot
  StatusDot.Visible := not ASignedIn;
  if ASignedIn = StatusCheck.Visible then
    Exit;
  StatusCheck.Visible := ASignedIn;
  if ASignedIn then
    StatusCheck.Animation.Start;
end;

procedure TMainForm.SetIcon(const ASvg: TSkSvg; const APathData: string; const AViewBox: Integer);
var
  LMargin: Integer;
begin
  // The colour comes from the control (Svg.OverrideColor, set in the .fmx or by the caller).
  // Material icons keep a 1-unit empty margin: crop it so they fill the control like a TPath did
  LMargin := IfThen(AViewBox = 24, 1, 0);
  ASvg.Svg.WrapMode := TSkSvgWrapMode.Fit;
  ASvg.Svg.Source := Format('<svg xmlns="http://www.w3.org/2000/svg" viewBox="%0:d %0:d %1:d %1:d">' +
    '<path fill-rule="evenodd" d="%2:s"/></svg>', [LMargin, AViewBox - 2 * LMargin, APathData]);
end;

procedure TMainForm.ApplyAndroidStatusBar;
begin
  // FMX implements SystemStatusBar only on iOS. On Android the status bar gets the average colour of the
  // top edge of the header gradient (indigo to violet); where the system draws it transparent, the
  // window background behind it is that same gradient
  {$IF Defined(ANDROID)}
  var LColors := TJavaArray<Integer>.Create(2);
  LColors.Items[0] := Integer(HeaderGradientStart);
  LColors.Items[1] := Integer(HeaderGradientMiddle);
  var LWindow := TAndroidHelper.Activity.getWindow;
  LWindow.clearFlags(TJWindowManager_LayoutParams.JavaClass.FLAG_TRANSLUCENT_STATUS);
  LWindow.addFlags(TJWindowManager_LayoutParams.JavaClass.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
  LWindow.setBackgroundDrawable(TJGradientDrawable.JavaClass.init(
    TJGradientDrawable_Orientation.JavaClass.LEFT_RIGHT, LColors));
  LWindow.setStatusBarColor(Integer(HeaderStatusBarColor));
  LWindow.getDecorView.setSystemUiVisibility(
    TJView.JavaClass.SYSTEM_UI_FLAG_LAYOUT_STABLE or TJView.JavaClass.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN);
  {$ENDIF}
end;

procedure TMainForm.FormCreate(Sender: TObject);
begin
  ApplyAndroidStatusBar;
  FPending := TPendingOperations.Create(Self,
    procedure(ABusy: Boolean)
    begin
      SetSpinner(AdminIndicator, ABusy);
      SetSpinner(LoginIndicator, ABusy);
      UpdateControls;
    end);

  // The controls of the pages that start hidden get their style (and show their text) now
  for var LIndex := 0 to ComponentCount - 1 do
    if Components[LIndex] is TStyledControl then
      TStyledControl(Components[LIndex]).ApplyStyleLookup;

  NavLayer.OnResized := NavLayerResized;
  SetupReadOnlyFields;
  SetupPrompts;
  OnFocusChanged := FormFocusChanged;
  AddNavClearance;
  ApplyIcons;
  ApplyFonts;
  SpidLevelComboBox.ItemIndex := Ord(slL2);
  CieLevelComboBox.ItemIndex := Ord(slL2);
  // The CIE simulator of the sample environment: the only CIE identity server that completes a local login
  CieEnvironmentComboBox.ItemIndex := CCieLocalTest;
  SPTypeComboBox.ItemIndex := 0;
  // Before the AgID registry is loaded too: spid-test can be deleted and saved again without it
  FSpidRegistry := [SpidLocalTestEntry];
  FillSpidProviders;
  FOtherType := COtherMicrosoft;
  OtherTypeComboBox.ItemIndex := COtherMicrosoft;
  ComboChange(CieEnvironmentComboBox);
  ComboChange(SPTypeComboBox);
  UpdateOtherFields;

  {$IF Defined(ANDROID) or Defined(IOS)}
  SetRichText(RedirectLabel, [CAppRedirectURI, #10 + '(private-use scheme, RFC 8252)'], [True, False], CText, CMuted);
  {$ELSE}
  SetRichText(RedirectLabel, ['http://localhost:<port>/oauth2callback', #10 + '(loopback server, desktop)'], [True, False], CText, CMuted);
  {$ENDIF}
  ConnectionCard.Height := CConnCollapsed;
  UpdateConnectionSummary;
  UpdateBrokerURLs(EntraAliasEdit.Text);
  UpdateSessionState;
  // The Providers page is shown after the login only to a user who can list the identity providers
  UpdateAdminAccess('');
  SelectMainTab(0);
  SelectAdminChip(0);
  UpdateControls;

  // Android and iOS: the redirect of the login arrives as an intent / open URL event
  TIAM4DAppRedirectListener.Install(AppRedirectReceived);
  FAppEventSubscription := TMessageManager.DefaultManager.SubscribeToMessage(TApplicationEventMessage,
    ApplicationEventMessage);
end;

procedure TMainForm.FormDestroy(Sender: TObject);
begin
  TMessageManager.DefaultManager.Unsubscribe(TApplicationEventMessage, FAppEventSubscription);
  TIAM4DAppRedirectListener.Uninstall;
end;

procedure TMainForm.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  // Operations still running: cancel the login and close when the last OnFinally has run,
  // so that no callback runs on a destroyed form
  CanClose := FPending.CloseQuery(FLoginOperation);
end;

procedure TMainForm.FormKeyUp(Sender: TObject; var Key: Word; var KeyChar: Char; Shift: TShiftState);
begin
  if Key <> vkHardwareBack then
    Exit;
  // With the keyboard up, Back is left to FMX: after this handler it closes the keyboard (HideVKB) and
  // nothing else. Clearing Key here would keep the keyboard open
  if FKeyboardVisible then
    Exit;
  // Back: closes the SPID picker, then returns to the login page; from there it leaves the app
  if SpidPickerLayer.Visible then
  begin
    CloseSpidPicker;
    Key := 0;
  end
  else if FMainPage <> 0 then
  begin
    SelectMainTab(0);
    Key := 0;
  end;
end;

procedure TMainForm.FormSafeAreaChanged(Sender: TObject; const AInsets: TRectF);
begin
  // On Android the form already starts below the status bar
  {$IF not Defined(ANDROID)}
  SafeTop.Height := AInsets.Top;
  {$ENDIF}
  SafeBottom.Height := AInsets.Bottom;
  NavLayer.Padding.Bottom := AInsets.Bottom;
  FSafeBottom := AInsets.Bottom;
end;

procedure TMainForm.FormVirtualKeyboardShown(Sender: TObject; KeyboardVisible: Boolean; const Bounds: TRect);
begin
  // The bar goes away and the content shrinks above the keyboard
  FKeyboardVisible := True;
  BottomNav.Visible := False;
  NavFade.Visible := False;
  KeyboardSpacer.Height := Max(0, Bounds.Height - FSafeBottom);
  // The pages shrink when the layout is realigned: the focused control is brought into view after that
  TThread.ForceQueue(nil, EnsureFocusedVisible);
end;

procedure TMainForm.FormFocusChanged(Sender: TObject);
begin
  for var LIndex := 0 to ComponentCount - 1 do
    if Components[LIndex] is TEdit then
      UpdatePrompt(TEdit(Components[LIndex]));
  // Moving from one field to another while the keyboard is up
  if FKeyboardVisible then
    TThread.ForceQueue(nil, EnsureFocusedVisible);
end;

procedure TMainForm.SetupPrompts;
var
  LEdit: TEdit;
  LPrompt: TSkLabel;
begin
  // With Skia the TLabel that shows TextPrompt in the edit style is painted out of place, like the TLabels of
  // the form were: a TSkLabel inside each field shows the prompt instead
  for var LIndex := 0 to ComponentCount - 1 do
  begin
    if not (Components[LIndex] is TEdit) or TEdit(Components[LIndex]).TextPrompt.IsEmpty then
      Continue;
    LEdit := TEdit(Components[LIndex]);
    LPrompt := TSkLabel.Create(Self);
    LPrompt.Parent := LEdit;
    LPrompt.Align := TAlignLayout.Client;
    LPrompt.Margins.Left := CPromptInset;
    LPrompt.HitTest := False;
    LPrompt.AutoSize := False;
    LPrompt.StyledSettings := [TStyledSetting.Family];
    LPrompt.TextSettings.Font.Size := LEdit.TextSettings.Font.Size;
    LPrompt.TextSettings.FontColor := CPromptText;
    LPrompt.TextSettings.VertAlign := TTextAlign.Center;
    LPrompt.TextSettings.MaxLines := 1;
    LPrompt.TextSettings.Trimming := TTextTrimming.Character;
    LPrompt.Text := LEdit.TextPrompt;
    LEdit.TextPrompt := '';
    LEdit.TagObject := LPrompt;
    if not Assigned(LEdit.OnChangeTracking) then
      LEdit.OnChangeTracking := EditChangeTracking;
    UpdatePrompt(LEdit);
  end;
end;

procedure TMainForm.UpdatePrompt(const AEdit: TEdit);
begin
  // Hidden while the field has the focus: during the composition of the IME the text is still empty
  if AEdit.TagObject is TSkLabel then
    TSkLabel(AEdit.TagObject).Visible := AEdit.Text.IsEmpty and not AEdit.IsFocused;
end;

procedure TMainForm.ShowEditTextStart(const AParent: TFmxObject);
begin
  // A field styled or filled while its page is hidden is a few pixels wide: the text scrolls to keep the caret
  // in view and stays scrolled out once the field is shown at full width
  if (AParent is TEdit) and not TEdit(AParent).IsFocused then
    TEdit(AParent).GoToTextBegin;
  if AParent.Children <> nil then
    for var LChild in AParent.Children do
      ShowEditTextStart(LChild);
end;

procedure TMainForm.SetupReadOnlyFields;
var
  LEdit: TEdit;
  LBox: TRectangle;
  LIcon: TSkSvg;
begin
  // The read-only fields hold values to register elsewhere: they look different from the editable ones and
  // a tap copies the value
  for LEdit in [RedirectAliasEdit, RedirectURIEdit, SpidSPMetadataEdit, CieSPMetadataEdit, SpidMetadataEdit] do
  begin
    LBox := LEdit.Parent as TRectangle;
    LBox.Fill.Color := CReadOnlyBackground;
    LBox.OnClick := ReadOnlyFieldClick;
    LEdit.TextSettings.FontColor := CReadOnlyText;
    LEdit.OnClick := ReadOnlyFieldClick;
    LIcon := TSkSvg.Create(Self);
    LIcon.Parent := LBox;
    LIcon.Align := TAlignLayout.Right;
    LIcon.Width := 20;
    LIcon.Margins.Rect := RectF(4, 13, 12, 13);
    LIcon.HitTest := False;
    SetIcon(LIcon, CIconCopy);
    LIcon.Svg.OverrideColor := CMuted;
  end;
end;

procedure TMainForm.ReadOnlyFieldClick(Sender: TObject);
var
  LEdit: TEdit;
  LChild: TFmxObject;
  LClipboard: IFMXClipboardService;
begin
  LEdit := nil;
  if Sender is TEdit then
    LEdit := TEdit(Sender)
  else if Sender is TControl then
    for LChild in TControl(Sender).Children do
      if LChild is TEdit then
        LEdit := TEdit(LChild);
  if (LEdit = nil) or LEdit.Text.IsEmpty then
    Exit;
  if TPlatformServices.Current.SupportsPlatformService(IFMXClipboardService, LClipboard) then
  begin
    LClipboard.SetClipboard(LEdit.Text);
    ShowToast('Copied to the clipboard');
  end;
end;

procedure TMainForm.ShowToast(const AText: string);
const
  CHeight = 40;
  CWidth = 220;
begin
  if FToast = nil then
  begin
    FToast := TRectangle.Create(Self);
    FToast.Parent := NavLayer;
    FToast.Align := TAlignLayout.None;
    FToast.HitTest := False;
    FToast.Size.Size := TSizeF.Create(CWidth, CHeight);
    FToast.Fill.Color := CDockDark;
    FToast.Stroke.Kind := TBrushKind.None;
    FToast.XRadius := 14;
    FToast.YRadius := 14;
    FToast.Opacity := 0;
    FToastLabel := TSkLabel.Create(Self);
    FToastLabel.AutoSize := False;
    FToastLabel.Parent := FToast;
    FToastLabel.Align := TAlignLayout.Client;
    FToastLabel.HitTest := False;
    FToastLabel.StyledSettings := [TStyledSetting.Family];
    FToastLabel.TextSettings.Font.Size := 13;
    FToastLabel.TextSettings.Font.Weight := TFontWeight.Bold;
    FToastLabel.TextSettings.FontColor := CWhite;
    FToastLabel.TextSettings.HorzAlign := TSkTextHorzAlign.Center;
  end;
  FToastLabel.Text := AText;
  // Above the navigation dock, centred
  FToast.Position.X := (NavLayer.Width - CWidth) / 2;
  FToast.Position.Y := NavLayer.Height - NavLayer.Padding.Bottom - BottomNav.Margins.Bottom - BottomNav.Height -
    CHeight - 12;
  FToast.BringToFront;
  TAnimator.StopPropertyAnimation(FToast, 'Opacity');
  TAnimator.AnimateFloat(FToast, 'Opacity', 1, 0.15);
  TAnimator.AnimateFloatDelay(FToast, 'Opacity', 0, 0.3, 1.4);
end;

procedure TMainForm.EnsureFocusedVisible;
const
  CMargin = 16;
var
  LControl: TControl;
  LBox: TCustomScrollBox;
  LParent: TFmxObject;
  LFocusRect, LBoxRect: TRectF;
  LDelta: Single;
begin
  if not FKeyboardVisible or not (Focused <> nil) then
    Exit;
  if not (Focused.GetObject is TControl) then
    Exit;
  LControl := TControl(Focused.GetObject);
  LBox := nil;
  LParent := LControl.Parent;
  while (LParent <> nil) and (LBox = nil) do
  begin
    if LParent is TCustomScrollBox then
      LBox := TCustomScrollBox(LParent);
    LParent := LParent.Parent;
  end;
  if LBox = nil then
    Exit;
  LFocusRect := LControl.AbsoluteRect;
  LBoxRect := LBox.AbsoluteRect;
  // Down when the field is below the visible area, up when it is above it
  if LFocusRect.Bottom + CMargin > LBoxRect.Bottom then
    LDelta := LFocusRect.Bottom + CMargin - LBoxRect.Bottom
  else if LFocusRect.Top - CMargin < LBoxRect.Top then
    LDelta := LFocusRect.Top - CMargin - LBoxRect.Top
  else
    Exit;
  LBox.ViewportPosition := PointF(LBox.ViewportPosition.X, Max(0, LBox.ViewportPosition.Y + LDelta));
end;

procedure TMainForm.FormVirtualKeyboardHidden(Sender: TObject; KeyboardVisible: Boolean; const Bounds: TRect);
begin
  FKeyboardVisible := False;
  BottomNav.Visible := True;
  NavFade.Visible := True;
  KeyboardSpacer.Height := 0;
end;

{ Look }

procedure TMainForm.ApplyIcons;
begin
  SetIcon(LogoIcon, CIconBrand, 100);
  SetIcon(ConnIcon, CIconLink);
  SetIcon(KeycloakTileIcon, CIconKey);
  SetIcon(EntraTileIcon, CIconMicrosoft);
  SetIcon(MicrosoftTileIcon, CIconMicrosoft);
  SetIcon(GoogleTileIcon, CIconGoogle);
  SetIcon(FacebookTileIcon, CIconFacebook);
  SetIcon(SpidTileIcon, CIconPerson);
  SetIcon(CieTileIcon, CIconCard);
  SetIcon(NavLoginIcon, CIconKey);
  SetIcon(NavAdminIcon, CIconServers);
  SetIcon(RefreshIdPsButtonIcon, CIconRefresh);
  SetIcon(DeleteIdPButtonIcon, CIconDelete);
  SetIcon(ConnChevron, CIconChevron);
  SetIcon(SpidPickerCloseIcon, CIconClose);
  LoadSpinner(LoginIndicator);
  LoadSpinner(AdminIndicator);
  LoadSuccess(StatusCheck);
end;

procedure TMainForm.ApplyFonts;
var
  LMono: string;
begin
  {$IF Defined(ANDROID)}
  LMono := 'monospace';
  {$ELSEIF Defined(IOS)}
  LMono := 'Menlo';
  {$ELSE}
  LMono := 'Consolas';
  {$ENDIF}
  LoginMemo.TextSettings.Font.Family := LMono;
  AdminMemo.TextSettings.Font.Family := LMono;
end;

procedure TMainForm.SetEnabledLook(const AControl: TControl; const AEnabled: Boolean);
begin
  AControl.Enabled := AEnabled;
  if AEnabled then
    AControl.Opacity := 1
  else
    AControl.Opacity := 0.45;
end;

procedure TMainForm.AddNavClearance;
begin
  // The pages scroll under the floating bar: at the end of each one there is room to bring the last
  // card above it
  for var LIndex := 0 to ComponentCount - 1 do
    if Components[LIndex] is TVertScrollBox then
    begin
      var LSpacer := TLayout.Create(Self);
      // Align Top controls are stacked by position: this one goes last
      LSpacer.Position.Y := 1000000;
      LSpacer.Align := TAlignLayout.Top;
      LSpacer.HitTest := False;
      LSpacer.Height := CNavClearance;
      TVertScrollBox(Components[LIndex]).AddObject(LSpacer);
    end;
end;

procedure TMainForm.LayoutNavItems(const AAnimate: Boolean);

  procedure Place(const AItem: TLayout; const AIcon: TSkSvg; const ALabel: TSkLabel; const AActive: Boolean);
  const
    CGap = 8;
  var
    LIconX, LTextWidth: Single;
  begin
    // Active item: icon and label side by side, centred on the capsule; inactive: the icon alone, centred
    Canvas.Font.Size := ALabel.TextSettings.Font.Size;
    Canvas.Font.Style := [TFontStyle.fsBold];
    LTextWidth := Canvas.TextWidth(ALabel.Text);
    if AActive then
      LIconX := (AItem.Width - (AIcon.Width + CGap + LTextWidth)) / 2
    else
      LIconX := (AItem.Width - AIcon.Width) / 2;
    ALabel.Position.X := (AItem.Width - (AIcon.Width + CGap + LTextWidth)) / 2 + AIcon.Width + CGap;
    ALabel.Width := LTextWidth + 4;
    if AAnimate then
      TAnimator.AnimateFloat(AIcon, 'Position.X', LIconX, 0.22, TAnimationType.InOut, TInterpolationType.Cubic)
    else
      AIcon.Position.X := LIconX;
    if AActive then
    begin
      if AAnimate and not ALabel.Visible then
        ALabel.Opacity := 0;
      ALabel.Visible := True;
      if AAnimate then
        TAnimator.AnimateFloat(ALabel, 'Opacity', 1, 0.22)
      else
        ALabel.Opacity := 1;
    end
    else
      ALabel.Visible := False;
  end;

var
  LActive: TLayout;
  LPillX: Single;
begin
  Place(NavLoginItem, NavLoginIcon, NavLoginLabel, FMainPage = 0);
  Place(NavAdminItem, NavAdminIcon, NavAdminLabel, FMainPage = 1);
  if FMainPage = 0 then
    LActive := NavLoginItem
  else
    LActive := NavAdminItem;
  // Same gap from the dock edge on every side (the dock padding): the corners stay concentric
  NavPill.Width := LActive.Width;
  LPillX := LActive.Position.X + (LActive.Width - NavPill.Width) / 2;
  if AAnimate then
    TAnimator.AnimateFloat(NavPill, 'Position.X', LPillX, 0.22, TAnimationType.InOut, TInterpolationType.Cubic)
  else
    NavPill.Position.X := LPillX;
end;

procedure TMainForm.NavLayerResized(Sender: TObject);
begin
  // The dock keeps its width and stays centred
  var LMargin := Max(16, (NavLayer.Width - CNavWidth) / 2);
  BottomNav.Margins.Left := LMargin;
  BottomNav.Margins.Right := LMargin;
end;

procedure TMainForm.EvenRowResized(Sender: TObject);
const
  CGap = 10;
var
  LRow: TControl;
  LGap: Single;
  LItems: TList<TControl>;
  LChild: TFmxObject;
  I: Integer;
  LWidth: Single;
begin
  LRow := Sender as TControl;
  if LRow = BottomNav then
    LGap := 0
  else
    LGap := CGap;
  LItems := TList<TControl>.Create;
  try
    for LChild in LRow.Children do
      if (LChild is TControl) and TControl(LChild).Visible and (TControl(LChild).Align in [TAlignLayout.Left, TAlignLayout.Client]) then
        LItems.Add(TControl(LChild));
    if LItems.Count = 0 then
      Exit;
    LWidth := (LRow.Width - LRow.Padding.Left - LRow.Padding.Right - LGap * (LItems.Count - 1)) / LItems.Count;
    for I := 0 to LItems.Count - 1 do
    begin
      LItems[I].Margins.Left := IfThen(I > 0, LGap, 0);
      if LItems[I].Align = TAlignLayout.Left then
        LItems[I].Width := LWidth;
    end;
    if LRow = BottomNav then
      LayoutNavItems(False);
  finally
    LItems.Free;
  end;
end;

procedure TMainForm.PressMouseDown(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Single);
begin
  TAnimator.AnimateFloat(TFmxObject(Sender), 'Scale.X', 0.96, 0.08);
  TAnimator.AnimateFloat(TFmxObject(Sender), 'Scale.Y', 0.96, 0.08);
end;

procedure TMainForm.PressMouseUp(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Single);
begin
  TAnimator.AnimateFloat(TFmxObject(Sender), 'Scale.X', 1, 0.12);
  TAnimator.AnimateFloat(TFmxObject(Sender), 'Scale.Y', 1, 0.12);
end;

procedure TMainForm.AnimateTabIn(const ATab: TControl; const ADirection: Integer);
const
  CSlide = 32;
begin
  // The new page fades in while it slides a few points in from the side of the direction of the change
  ATab.Opacity := 0;
  ATab.Margins.Left := ADirection * CSlide;
  ATab.Margins.Right := -ADirection * CSlide;
  TAnimator.AnimateFloat(ATab, 'Opacity', 1, 0.25);
  TAnimator.AnimateFloat(ATab, 'Margins.Left', 0, 0.25, TAnimationType.Out, TInterpolationType.Cubic);
  TAnimator.AnimateFloat(ATab, 'Margins.Right', 0, 0.25, TAnimationType.Out, TInterpolationType.Cubic);
end;

procedure TMainForm.SelectMainTab(const AIndex: Integer);

  function NavColor(const AActive: Boolean): TAlphaColor;
  begin
    // The active item is on the gradient capsule of the dark dock
    if AActive then
      Result := CNavActive
    else
      Result := CNavInactive;
  end;

var
  LChanged: Boolean;
  LDirection: Integer;
begin
  LChanged := AIndex <> FMainPage;
  LDirection := IfThen(AIndex > FMainPage, 1, -1);
  FMainPage := AIndex;
  LoginTab.Visible := AIndex = 0;
  AdminTab.Visible := AIndex = 1;
  if LChanged then
    if AIndex = 0 then
      AnimateTabIn(LoginTab, LDirection)
    else
      AnimateTabIn(AdminTab, LDirection);
  NavLoginIcon.Svg.OverrideColor := NavColor(AIndex = 0);
  NavLoginLabel.TextSettings.FontColor := NavColor(AIndex = 0);
  NavAdminIcon.Svg.OverrideColor := NavColor(AIndex = 1);
  NavAdminLabel.TextSettings.FontColor := NavColor(AIndex = 1);
  LayoutNavItems(True);
  ShowEditTextStart(MainTabs);
  // Header: the status bar overlaps the form, so the gradient continues under it
  if (AIndex = 1) and not FIdentityProvidersLoaded and (FPending.Count = 0) and IsSignedIn and
     Assigned(FIdentityProviderManager) then
    RefreshIdentityProviders;
end;

procedure TMainForm.SelectAdminChip(const AIndex: Integer);
var
  I: Integer;
  LChip: TRectangle;
  LCaption: TSkLabel;
begin
  ProvidersTab.Visible := AIndex = 0;
  EntraTab.Visible := AIndex = 1;
  GoogleTab.Visible := AIndex = 2;
  FacebookTab.Visible := AIndex = 3;
  OidcTab.Visible := AIndex = 4;
  OtherTab.Visible := AIndex = 5;
  SpidTab.Visible := AIndex = 6;
  CieTab.Visible := AIndex = 7;
  ServiceProviderTab.Visible := AIndex = 8;
  LogTab.Visible := AIndex = 9;
  for I := 1 to 10 do
  begin
    LChip := FindComponent('AdminChip' + I.ToString) as TRectangle;
    LCaption := FindComponent('AdminChip' + I.ToString + 'Label') as TSkLabel;
    if I - 1 = AIndex then
    begin
      LChip.Fill.Color := CDockDark;
      LCaption.TextSettings.FontColor := CWhite;
    end
    else
    begin
      LChip.Fill.Color := CWhite;
      LCaption.TextSettings.FontColor := CMuted;
    end;
  end;
  case AIndex of
    1: UpdateBrokerURLs(EntraAliasEdit.Text);
    2: UpdateBrokerURLs(GoogleAliasEdit.Text);
    3: UpdateBrokerURLs(FacebookAliasEdit.Text);
    4: UpdateBrokerURLs(OidcAliasEdit.Text);
    5: UpdateBrokerURLs(OtherAliasEdit.Text);
    6: UpdateBrokerURLs(SpidAliasEdit.Text);
    7: UpdateBrokerURLs(CieAliasEdit.Text);
  end;
  ShowEditTextStart(AdminPages);
end;

procedure TMainForm.NavLoginClick(Sender: TObject);
begin
  SelectMainTab(0);
end;

procedure TMainForm.NavAdminClick(Sender: TObject);
begin
  SelectMainTab(1);
end;

procedure TMainForm.AdminChipClick(Sender: TObject);
begin
  SelectAdminChip((Sender as TFmxObject).Tag);
end;

procedure TMainForm.ConnHeaderClick(Sender: TObject);
begin
  FConnExpanded := not FConnExpanded;
  TAnimator.AnimateFloat(ConnectionCard, 'Size.Height', IfThen(FConnExpanded, CConnExpanded, CConnCollapsed), 0.28,
    TAnimationType.InOut, TInterpolationType.Cubic);
  TAnimator.AnimateFloat(ConnChevron, 'RotationAngle', IfThen(FConnExpanded, 180, 0), 0.28,
    TAnimationType.InOut, TInterpolationType.Cubic);
end;

procedure TMainForm.UpdateConnectionSummary;
begin
  SetRichText(ConnSummary, [Trim(BaseURLEdit.Text), '  ' + #$00B7 + '  realm ', Trim(RealmEdit.Text)],
    [True, False, True], CText, CMuted);
end;

procedure TMainForm.UpdateTimerTimer(Sender: TObject);
begin
  // The state of the controls follows the state of the operations (the VCL sample does it in OnUpdate)
  UpdateControls;
end;

procedure TMainForm.UpdateControls;
var
  LIdle, LCanLogin, LSignedIn, LAdmin, LCancelVisible: Boolean;
  LHeight: Single;
begin
  LIdle := FPending.Idle;
  LSignedIn := IsSignedIn;
  LCanLogin := LIdle and not LSignedIn;
  LAdmin := LIdle and LSignedIn and Assigned(FIdentityProviderManager);

  // Not tied to LIdle: dimming the tiles while a login starts (and failing fast) made them all flicker;
  // StartLogin ignores taps while an operation is pending
  SetEnabledLook(KeycloakTile, not LSignedIn);
  SetEnabledLook(EntraTile, not LSignedIn);
  SetEnabledLook(MicrosoftTile, not LSignedIn);
  SetEnabledLook(GoogleTile, not LSignedIn);
  SetEnabledLook(FacebookTile, not LSignedIn);
  SetEnabledLook(SpidTile, not LSignedIn);
  SetEnabledLook(CieTile, not LSignedIn);
  SetEnabledLook(UserInfoButton, LIdle and LSignedIn);
  SetEnabledLook(AccessTokenButton, LIdle and LSignedIn);
  SetEnabledLook(LogoutButton, LIdle and LSignedIn);

  LCancelVisible := Assigned(FLoginOperation) and not FPending.CloseRequested;
  CancelLoginButton.Enabled := LCancelVisible;
  if CancelPanel.Visible <> LCancelVisible then
  begin
    CancelPanel.Visible := LCancelVisible;
    LHeight := 16 + 28 + (88 + 10) * 4 + 16;
    if LCancelVisible then
      LHeight := LHeight + CancelPanel.Height;
    TAnimator.AnimateFloat(SignInCard, 'Size.Height', LHeight, 0.2);
  end;

  SetEnabledLook(RefreshIdPsButton, LAdmin);
  SetEnabledLook(DeleteIdPButton, LAdmin and Assigned(IdPList.Selected));
  SetEnabledLook(SaveEntraButton, LAdmin);
  SetEnabledLook(SaveGoogleButton, LAdmin);
  SetEnabledLook(SaveFacebookButton, LAdmin);
  SetEnabledLook(SaveOidcButton, LAdmin);
  SetEnabledLook(SaveOtherButton, LAdmin);
  SetEnabledLook(SaveSpidButton, LAdmin and (SpidProviderComboBox.ItemIndex >= 0));
  SetEnabledLook(SaveCieButton, LAdmin);
  SetEnabledLook(LoadRegistryButton, LIdle);

  // The connection cannot change during a session: the admin calls use its issuer
  BaseURLEdit.Enabled := LCanLogin;
  RealmEdit.Enabled := LCanLogin;
  ClientEdit.Enabled := LCanLogin;
end;

{ Login }

function TMainForm.IsSignedIn: Boolean;
begin
  Result := Assigned(FClient) and FClient.IsAuthenticated;
end;

procedure TMainForm.LoginLog(const AText: string);
begin
  LoginMemo.Lines.Add(AText);
  LoginMemo.GoToTextEnd;
end;

procedure TMainForm.Warn(const AText: string);
begin
  TDialogServiceAsync.ShowMessage(AText,
    procedure(const AResult: TModalResult)
    begin
    end);
end;

procedure TMainForm.KeycloakTileClick(Sender: TObject);
begin
  StartLogin('');
end;

procedure TMainForm.EntraTileClick(Sender: TObject);
begin
  StartLogin(IAM4D_IDP_ALIAS_ENTRA);
end;

procedure TMainForm.MicrosoftTileClick(Sender: TObject);
begin
  // Personal Microsoft accounts (provider 'microsoft'); work accounts go to Entra ID
  StartLogin(IAM4D_IDP_ALIAS_MICROSOFT);
end;

procedure TMainForm.GoogleTileClick(Sender: TObject);
begin
  StartLogin(IAM4D_IDP_ALIAS_GOOGLE);
end;

procedure TMainForm.FacebookTileClick(Sender: TObject);
begin
  StartLogin(IAM4D_IDP_ALIAS_FACEBOOK);
end;

procedure TMainForm.CieTileClick(Sender: TObject);
begin
  StartLogin(IAM4D_IDP_ALIAS_CIE);
end;

procedure TMainForm.SpidTileClick(Sender: TObject);
begin
  if not FPending.Idle or IsSignedIn then
    Exit;
  // One Keycloak provider per SPID identity provider: the user picks it from the list
  if FSpidRegistryLoaded then
    ShowSpidPicker
  else
    LoadSpidRegistry(True);
end;

procedure TMainForm.CancelLoginButtonClick(Sender: TObject);
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
  LoginMemo.Lines.Clear;
  if LIdpHint.IsEmpty then
    LoginLog('Login from the Keycloak login page: complete it in the browser...')
  else
    LoginLog(Format('Login with the identity provider "%s" (kc_idp_hint): complete it in the browser...', [LIdpHint]));

  FPending.BeginOperation;
  try
    TIAM4DClientConfigBuilder.New
      .ForAuthorizationCode(Trim(BaseURLEdit.Text), Trim(RealmEdit.Text), Trim(ClientEdit.Text))
      {$IFDEF DEBUG}
      // The sample Keycloak (Docker/) is plain HTTP, on the phone through adb reverse: never in a release
      .WithAllowInsecureHTTP
      {$ENDIF}
      {$IF Defined(ANDROID) or Defined(IOS)}
      // The browser redirects to the private-use scheme of the app (intent filter / CFBundleURLTypes)
      .WithAppRedirect(CAppRedirectURI)
      {$ENDIF}
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
        LoginLog('Configuration failed: ' + E.Message);
      end)
      .OnFinally(FPending.EndOperation)
      .Run;
  except
    // Raised before Run (e.g. empty base URL or realm): no OnFinally ends this operation
    on E: Exception do
    begin
      LoginLog('Configuration failed: ' + E.Message);
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
        if not Assigned(FIdentityProviderManager) then
          ShowToast('No identity provider administration for this user');
      end)
      .OnError(
      procedure(const E: Exception)
      begin
        LoginLog('Login failed: ' + E.Message);
      end)
      .OnFinally(
      procedure
      begin
        if Assigned(FLoginOperation) and (FLoginOperation.GetState = TAsyncOperationState.Cancelled) then
          LoginLog('Login cancelled.');
        FLoginOperation := nil;
        CancelWatchTimer.Enabled := False;
        UpdateSessionState;
        FPending.EndOperation;
      end)
      .Run;
    UpdateControls;
  except
    // Raised before Run (callback handler, browser): no OnFinally ends this operation
    on E: Exception do
    begin
      LoginLog('Login failed: ' + E.Message);
      UpdateSessionState;
      FPending.EndOperation;
    end;
  end;
end;

procedure TMainForm.AppRedirectReceived(const AURL: string; const ATaken: Boolean);
var
  LBase: string;
  LCut: Integer;
begin
  // The URL holds the authorization code and the state: only its scheme and path are shown
  LBase := AURL;
  LCut := LBase.IndexOfAny(['?', '#']);
  if LCut >= 0 then
    LBase := LBase.Substring(0, LCut);

  if ATaken then
    LoginLog(Format('Redirect received (%s): completing the login...', [LBase]))
  else if not Assigned(FLoginOperation) then
    LoginLog(Format('Redirect received (%s) but no login is waiting: the app was restarted while the browser ' +
      'was open, so the login is interrupted. Sign in again.', [LBase]))
  else
    LoginLog(Format('Redirect ignored (%s): it is not the one of this login.', [LBase]));
end;

procedure TMainForm.ApplicationEventMessage(const ASender: TObject; const AMessage: TMessage);
begin
  // Back from the browser: if the redirect does not arrive within a second, the user closed the
  // browser tab (the login is still waiting): cancel it. Heuristic, documented in the README
  if (AMessage is TApplicationEventMessage) and
     (TApplicationEventMessage(AMessage).Value.Event = TApplicationEvent.BecameActive) and
     Assigned(FLoginOperation) and TIAM4DAppRedirect.IsWaiting then
  begin
    CancelWatchTimer.Enabled := False;
    CancelWatchTimer.Enabled := True;
  end;
end;

procedure TMainForm.CancelWatchTimerTimer(Sender: TObject);
begin
  CancelWatchTimer.Enabled := False;
  if Assigned(FLoginOperation) and TIAM4DAppRedirect.IsWaiting then
  begin
    LoginLog('Back from the browser without the redirect: login cancelled.');
    FLoginOperation.Cancel;
  end;
end;

procedure TMainForm.ShowSession(const AAccessToken: string);
var
  LAccessToken: string;
begin
  LAccessToken := AAccessToken;
  LoginMemo.Lines.Clear;
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
      LoginLog('User info not available: ' + E.Message);
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

procedure TMainForm.UserInfoButtonClick(Sender: TObject);
begin
  LoginMemo.Lines.Clear;
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
      LoginLog('User info not available: ' + E.Message);
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.AccessTokenButtonClick(Sender: TObject);
begin
  LoginMemo.Lines.Clear;
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
      LoginLog('Access token not available: ' + E.Message);
    end)
    .OnFinally(FPending.EndOperation)
    .Run;
end;

procedure TMainForm.LogoutButtonClick(Sender: TObject);
begin
  FPending.BeginOperation;
  FClient.LogoutAsync
    .OnSuccess(
    procedure
    begin
      LoginMemo.Lines.Clear;
      LoginLog('Signed out.');
    end)
    .OnError(
    procedure(const E: Exception)
    begin
      LoginLog('Sign-out failed: ' + E.Message);
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
        RebuildSpidPicker;
      end;
      UpdateSessionState;
      FPending.EndOperation;
    end)
    .Run;
end;

procedure TMainForm.UpdateAdminAccess(const AAccessToken: string);
var
  LAllowed: Boolean;
begin
  // Admin REST API with the same session: listing needs view-identity-providers or
  // manage-identity-providers, saving and deleting manage-identity-providers (the demo user has
  // realm-admin). Without them the Providers page stays hidden instead of failing with 403 at the first call.
  LAllowed := CanViewIdentityProviders(AAccessToken);
  if LAllowed then
    FIdentityProviderManager := TIAM4DKeycloakIdentityProviderManagerAsync.Create(FClient)
  else
  begin
    FIdentityProviderManager := nil;
    if FMainPage = 1 then
      SelectMainTab(0);
  end;
  // A single page: no dock (the toast keeps its place above where the dock is)
  BottomNav.Visible := LAllowed;
  NavFade.Visible := LAllowed;
end;

procedure TMainForm.UpdateSessionState;
begin
  if IsSignedIn then
  begin
    if FUserName.IsEmpty then
      SetRichText(SessionLabel, ['Signed in'], [True], CWhite, CWhite)
    else
      SetRichText(SessionLabel, ['Signed in as ', FUserName], [False, True], CWhite, CSoftWhite);
    ShowSessionCheck(True);
    AdminStatusLabel.Text := Format('Session of %s on %s. Managing identity providers needs the realm-management ' +
      'roles view-identity-providers and manage-identity-providers.', [FUserName, RealmURL]);
  end
  else
  begin
    SetRichText(SessionLabel, ['Not signed in'], [True], CWhite, CWhite);
    ShowSessionCheck(False);
    AdminStatusLabel.Text := 'Sign in from the first page with the Keycloak login page as demo / demo ' +
      '(realm-admin role): the administration uses that session.';
  end;
  UpdateBrokerURLs(FBrokerAlias);
  UpdateControls;
end;

{ SPID registry and picker }

procedure TMainForm.LoadRegistryButtonClick(Sender: TObject);
begin
  LoadSpidRegistry(False);
end;

procedure TMainForm.LoadSpidRegistry(const AShowPicker: Boolean; const AForAdmin: Boolean);
begin
  if FPending.CloseRequested or FSpidRegistryLoading then
    Exit;
  FSpidRegistryLoading := True;
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
      if AShowPicker and AForAdmin then
        Warn('AgID registry not available: ' + E.Message)
      else if AShowPicker then
        LoginLog('AgID registry not available: ' + E.Message);
    end)
    .OnFinally(
    procedure
    begin
      FSpidRegistryLoading := False;
      // Also without the registry: "Other alias..." reaches the SPID providers of the realm (spid-test)
      RebuildSpidPicker;
      FPending.EndOperation;
      // After EndOperation, from the message loop: the items can start the login
      if AShowPicker then
        TThread.ForceQueue(nil,
          procedure
          begin
            if not FPending.CloseRequested then
              if AForAdmin then
                ShowSpidPicker(SpidProviderComboBox)
              else
                ShowSpidPicker;
          end);
    end)
    .Run;
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
  if (SpidProviderComboBox.ItemIndex < 0) and (SpidProviderComboBox.Count > 0) then
    SpidProviderComboBox.ItemIndex := CSpidLocalTest;
  ComboChange(SpidProviderComboBox);
end;

procedure TMainForm.RebuildSpidPicker;
var
  LAliases: TArray<string>;

  procedure AddItem(const ACaption, AAlias: string);
  var
    LItem: TListBoxItem;
    LProvider: TIAM4DIdentityProvider;
  begin
    LAliases := LAliases + [AAlias];
    LItem := TListBoxItem.Create(SpidPickerList);
    LItem.StyleLookup := 'listboxitembottomdetail';
    LItem.Text := ACaption;
    LItem.TagString := AAlias;
    // Provider found in the realm (list of the administration page): checkmark
    if FindIdentityProvider(AAlias, LProvider) then
    begin
      LItem.ItemData.Detail := AAlias + '  -  configured in the realm';
      LItem.ItemData.Accessory := TListBoxItemData.TAccessory.aCheckmark;
    end
    else
      LItem.ItemData.Detail := AAlias;
    SpidPickerList.AddObject(LItem);
  end;

  procedure AddComboChoices;
  var
    LItem: TListBoxItem;
    LTitle, LHint: string;
    LDetails: TArray<string>;
  begin
    ChoiceTexts(FSpidPickerCombo, LTitle, LHint, LDetails);
    SpidPickerTitle.Text := LTitle;
    SpidPickerHint.Text := LHint;
    for var LIndex := 0 to FSpidPickerCombo.Count - 1 do
    begin
      LItem := TListBoxItem.Create(SpidPickerList);
      LItem.StyleLookup := 'listboxitembottomdetail';
      LItem.Text := FSpidPickerCombo.Items[LIndex];
      LItem.Tag := LIndex;
      if LIndex <= High(LDetails) then
        LItem.ItemData.Detail := LDetails[LIndex];
      if LIndex = FSpidPickerCombo.ItemIndex then
        LItem.ItemData.Accessory := TListBoxItemData.TAccessory.aCheckmark;
      SpidPickerList.AddObject(LItem);
    end;
  end;

  procedure AddRegistryChoices;
  var
    LItem: TListBoxItem;
    LProvider: TIAM4DIdentityProvider;
  begin
    // Only the registry: the SPID page saves a provider from its metadata. Checkmark: the current choice
    for var LIndex := 0 to High(FSpidRegistry) do
    begin
      LItem := TListBoxItem.Create(SpidPickerList);
      LItem.StyleLookup := 'listboxitembottomdetail';
      LItem.Text := FSpidRegistry[LIndex].OrganizationName;
      LItem.Tag := LIndex;
      LItem.TagString := FSpidRegistry[LIndex].Alias;
      if FindIdentityProvider(LItem.TagString, LProvider) then
        LItem.ItemData.Detail := LItem.TagString + '  -  already in the realm'
      else
        LItem.ItemData.Detail := LItem.TagString;
      if LIndex = SpidProviderComboBox.ItemIndex then
        LItem.ItemData.Accessory := TListBoxItemData.TAccessory.aCheckmark;
      SpidPickerList.AddObject(LItem);
    end;
  end;

var
  LEntry: TSpidRegistryEntry;
  LProvider: TIAM4DIdentityProvider;
  LOther: TListBoxItem;
begin
  SpidPickerList.BeginUpdate;
  try
    SpidPickerList.Clear;
    LAliases := nil;

    if FSpidPickerCombo = SpidProviderComboBox then
    begin
      SpidPickerTitle.Text := 'SPID identity provider';
      SpidPickerHint.Text := 'Choose the identity provider to add to the realm';
      AddRegistryChoices;
    end
    else if Assigned(FSpidPickerCombo) then
      AddComboChoices
    else
    begin
      SpidPickerTitle.Text := 'Sign in with SPID';
      SpidPickerHint.Text := 'Choose your SPID identity provider';
      for LEntry in FSpidRegistry do
        AddItem(LEntry.OrganizationName, LEntry.Alias);

      // SPID providers of the realm not in the registry (e.g. a test identity provider)
      for LProvider in FIdentityProviders do
        if (LProvider.ProviderID = IAM4D_IDP_PROVIDER_SPID) and
           not TArray.Contains<string>(LAliases, LProvider.Alias) then
          AddItem(LProvider.DisplayName, LProvider.Alias);

      // Always: without the AgID registry it is the only way to a provider such as spid-test
      LOther := TListBoxItem.Create(SpidPickerList);
      LOther.StyleLookup := 'listboxitembottomdetail';
      LOther.Text := 'Other alias...';
      LOther.ItemData.Detail := 'Type the alias of a SPID provider of the realm, e.g. spid-test';
      LOther.ItemData.Accessory := TListBoxItemData.TAccessory.aMore;
      SpidPickerList.AddObject(LOther);
    end;
  finally
    SpidPickerList.EndUpdate;
  end;
  if SpidPickerLayer.Visible then
    FitSpidPickerSheet;
end;

procedure TMainForm.FitSpidPickerSheet;
var
  LContent: Single;
begin
  // The sheet is as tall as its content (header + one row per provider), up to 85% of the screen
  // (then the list scrolls); the bottom padding keeps the last row above the system bar
  SpidPickerSheet.Padding.Bottom := 28 + FSafeBottom;
  LContent := SpidPickerSheet.Padding.Top + SpidPickerSheet.Padding.Bottom + SpidPickerGrip.Height +
    SpidPickerHeader.Height + SpidPickerHint.Height + SpidPickerHint.Margins.Bottom +
    SpidPickerList.Count * SpidPickerList.ItemHeight + 2;
  SpidPickerSheet.Height := Min(LContent, SpidPickerLayer.Height * 0.85);
end;

procedure TMainForm.ShowSpidPicker(const ACombo: TComboBox);
begin
  if FPending.CloseRequested then
    Exit;
  if Assigned(FSpidSlideOut) then
    FSpidSlideOut.Stop;
  FSpidPickerCombo := ACombo;
  RebuildSpidPicker;
  if SpidPickerList.Count = 0 then
  begin
    HideSpidPicker;
    Exit;
  end;
  SpidPickerLayer.Visible := True;
  SpidPickerLayer.BringToFront;
  FitSpidPickerSheet;
  SpidPickerScrim.Opacity := 0;
  SpidPickerSheet.Margins.Bottom := -SpidPickerSheet.Height;
  TAnimator.AnimateFloat(SpidPickerScrim, 'Opacity', 1, 0.2);
  TAnimator.AnimateFloat(SpidPickerSheet, 'Margins.Bottom', 0, 0.3, TAnimationType.Out, TInterpolationType.Cubic);
end;

procedure TMainForm.HideSpidPicker;
begin
  SpidPickerLayer.Visible := False;
end;

procedure TMainForm.CloseSpidPicker;
begin
  if not SpidPickerLayer.Visible then
    Exit;
  // Slides down and fades out, like the swipe: the layer is hidden when the sheet is out
  TAnimator.AnimateFloat(SpidPickerScrim, 'Opacity', 0, 0.2);
  if FSpidSlideOut = nil then
  begin
    // TAnimator has no completion callback: one animation of the sheet, owned by it and started again each time
    FSpidSlideOut := TFloatAnimation.Create(SpidPickerSheet);
    FSpidSlideOut.Parent := SpidPickerSheet;
    FSpidSlideOut.PropertyName := 'Margins.Bottom';
    FSpidSlideOut.StartFromCurrent := True;
    FSpidSlideOut.Duration := 0.22;
    FSpidSlideOut.AnimationType := TAnimationType.In;
    FSpidSlideOut.Interpolation := TInterpolationType.Cubic;
    FSpidSlideOut.OnFinish := SpidPickerSlideOutFinished;
  end;
  FSpidSlideOut.StopValue := -SpidPickerSheet.Height;
  FSpidSlideOut.Start;
end;

procedure TMainForm.SpidPickerSlideOutFinished(Sender: TObject);
begin
  // Stop (a new drag, a new Show) also ends the animation: hide only when the sheet is really out
  if SpidPickerSheet.Margins.Bottom <= -SpidPickerSheet.Height + 0.5 then
    HideSpidPicker;
end;

procedure TMainForm.SpidPickerScrimClick(Sender: TObject);
begin
  CloseSpidPicker;
end;

procedure TMainForm.SpidPickerDragDown(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Single);
begin
  // Stops a slide in progress: the finger takes over
  if Assigned(FSpidSlideOut) then
    FSpidSlideOut.Stop;
  TAnimator.StopPropertyAnimation(SpidPickerSheet, 'Margins.Bottom');
  TAnimator.StopPropertyAnimation(SpidPickerScrim, 'Opacity');
  FSpidDragging := True;
  FSpidDragStartY := (Sender as TControl).LocalToAbsolute(PointF(X, Y)).Y;
  FSpidDragLastY := FSpidDragStartY;
  FSpidDragLastTick := TThread.GetTickCount;
  FSpidDragVelocity := 0;
end;

procedure TMainForm.SpidPickerDragMove(Sender: TObject; Shift: TShiftState; X, Y: Single);
var
  LY, LDelta: Single;
  LTick: Cardinal;
begin
  if not FSpidDragging then
    Exit;
  // Form coordinates: the local ones would not change while the sheet follows the finger
  LY := (Sender as TControl).LocalToAbsolute(PointF(X, Y)).Y;
  LTick := TThread.GetTickCount;
  if LTick > FSpidDragLastTick then
  begin
    // Points per millisecond, smoothed: a flick matters more than the distance
    FSpidDragVelocity := 0.6 * (LY - FSpidDragLastY) / (LTick - FSpidDragLastTick) + 0.4 * FSpidDragVelocity;
    FSpidDragLastTick := LTick;
  end;
  FSpidDragLastY := LY;
  // Only downwards: the sheet does not go above its resting position
  LDelta := Max(0, LY - FSpidDragStartY);
  SpidPickerSheet.Margins.Bottom := -LDelta;
  SpidPickerScrim.Opacity := 1 - Min(1, LDelta / SpidPickerSheet.Height);
end;

procedure TMainForm.SpidPickerDragUp(Sender: TObject; Button: TMouseButton; Shift: TShiftState; X, Y: Single);
const
  CCloseFraction = 0.3;
  CFlickVelocity = 0.7;
var
  LDelta: Single;
begin
  if not FSpidDragging then
    Exit;
  FSpidDragging := False;
  LDelta := -SpidPickerSheet.Margins.Bottom;
  // Dragged far enough, or flicked down: closes; otherwise it springs back
  if (LDelta > SpidPickerSheet.Height * CCloseFraction) or ((LDelta > 8) and (FSpidDragVelocity > CFlickVelocity)) then
    CloseSpidPicker
  else
  begin
    TAnimator.AnimateFloat(SpidPickerScrim, 'Opacity', 1, 0.2);
    TAnimator.AnimateFloat(SpidPickerSheet, 'Margins.Bottom', 0, 0.2, TAnimationType.Out, TInterpolationType.Cubic);
  end;
end;

procedure TMainForm.SpidPickerListItemClick(const Sender: TCustomListBox; const Item: TListBoxItem);
var
  LAlias: string;
begin
  if Assigned(FSpidPickerCombo) then
  begin
    CloseSpidPicker;
    FSpidPickerCombo.ItemIndex := Item.Tag;
    ComboChange(FSpidPickerCombo);
    UpdateControls;
    Exit;
  end;
  LAlias := Item.TagString;
  HideSpidPicker;
  if LAlias.IsEmpty then
    AskSpidAlias
  else
    StartLogin(LAlias);
end;

procedure TMainForm.ChoiceBoxClick(Sender: TObject);
var
  LCombo: TComboBox;
begin
  // Same sheet as the SPID tile, instead of the platform list of the combo box (HitTest off: the tap
  // reaches its rectangle)
  LCombo := nil;
  for var LChild in (Sender as TControl).Controls do
    if LChild is TComboBox then
      LCombo := TComboBox(LChild);
  if FPending.CloseRequested or not Assigned(LCombo) or not LCombo.Enabled then
    Exit;
  if LCombo <> SpidProviderComboBox then
    ShowSpidPicker(LCombo)
  else if FSpidRegistryLoaded and (Length(FSpidRegistry) > 0) then
    ShowSpidPicker(LCombo)
  else if not FSpidRegistryLoading then
    LoadSpidRegistry(True, True);
end;

procedure TMainForm.ChoiceTexts(const ACombo: TComboBox; out ATitle, AHint: string; out ADetails: TArray<string>);
const
  CLevels: array[0..2] of string = ('User name and password', 'Password and a second factor (OTP, app)',
    'Smart card or other hardware device');
begin
  if (ACombo = SpidLevelComboBox) or (ACombo = CieLevelComboBox) then
  begin
    ATitle := 'Authentication level';
    AHint := 'Level requested from the identity provider';
    ADetails := [CLevels[0], CLevels[1], CLevels[2]];
  end
  else if ACombo = CieEnvironmentComboBox then
  begin
    ATitle := 'CIE ID environment';
    AHint := 'Metadata imported into the cie provider';
    ADetails := ['Ministry of the Interior, real identities', 'Ministry of the Interior, test identities',
      'CIE simulator of Docker/ (profile brokering), port 18444'];
  end
  else if ACombo = SPTypeComboBox then
  begin
    ATitle := 'Service provider type';
    AHint := 'It decides the data published in the metadata';
    ADetails := ['IPA code and category', 'VAT number and fiscal code'];
  end
  else if ACombo = EntraPromptComboBox then
  begin
    // Without a prompt an Entra ID session still open in the browser signs in again with no question,
    // also after the sign out of the app (back-channel: the Entra ID session is not closed)
    ATitle := 'Prompt';
    AHint := 'What Entra ID asks at every login';
    ADetails := ['Nothing: an open Entra ID session signs in straight away', 'Account picker, also with an open session',
      'Credentials every time', 'Consent screen every time'];
  end
  else if ACombo = OtherTypeComboBox then
  begin
    ATitle := 'Provider type';
    AHint := 'Identity provider to add to the realm';
    ADetails := ['Personal account: outlook.com, hotmail.com, live.com', 'Sign In with LinkedIn (OpenID Connect)',
      'github.com or GitHub Enterprise', 'gitlab.com', 'Endpoints, scopes and profile fields set by hand'];
  end
  else
  begin
    ATitle := '';
    AHint := '';
    ADetails := nil;
  end;
end;

procedure TMainForm.AskSpidAlias;
begin
  // spid-test: SPID provider of the sample Keycloak, bound to the spid-saml-check demo identity provider
  TDialogServiceAsync.InputQuery('Sign in with SPID', ['SPID identity provider alias'], ['spid-test'],
    procedure(const AResult: TModalResult; const AValues: array of string)
    begin
      if (AResult = mrOk) and (Length(AValues) > 0) and not Trim(AValues[0]).IsEmpty then
        StartLogin(Trim(AValues[0]));
    end);
end;

{ Identity provider administration }

procedure TMainForm.RefreshIdPsButtonClick(Sender: TObject);
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
      RebuildSpidPicker;
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
  LItem: TListBoxItem;
begin
  IdPList.BeginUpdate;
  try
    IdPList.Clear;
    for LProvider in FIdentityProviders do
    begin
      LItem := TListBoxItem.Create(IdPList);
      LItem.StyleLookup := 'listboxitembottomdetail';
      LItem.Text := LProvider.Alias;
      LItem.TagString := LProvider.Alias;
      LItem.ItemData.Detail := Format('%s  -  %s  -  enabled: %s, hidden: %s',
        [LProvider.ProviderID, LProvider.DisplayName, CYesNo[LProvider.Enabled], CYesNo[LProvider.HideOnLogin]]);
      IdPList.AddObject(LItem);
    end;
  finally
    IdPList.EndUpdate;
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

procedure TMainForm.IdPListChange(Sender: TObject);
begin
  if Assigned(IdPList.Selected) then
    UpdateBrokerURLs(IdPList.Selected.TagString);
end;

procedure TMainForm.DeleteIdPButtonClick(Sender: TObject);
var
  LAlias: string;
begin
  if IdPList.Selected = nil then
    Exit;
  LAlias := IdPList.Selected.TagString;
  TDialogServiceAsync.MessageDialog(Format('Delete the identity provider "%s"?', [LAlias]), TMsgDlgType.mtConfirmation,
    [TMsgDlgBtn.mbYes, TMsgDlgBtn.mbNo], TMsgDlgBtn.mbNo, 0,
    procedure(const AResult: TModalResult)
    begin
      if (AResult <> mrYes) or FPending.CloseRequested or not Assigned(FIdentityProviderManager) then
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
    end);
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

procedure TMainForm.SaveEntraButtonClick(Sender: TObject);
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
      .WithHideOnLogin(EntraHideSwitch.IsChecked);
    // Item 0 (Not set): no prompt, the save removes the one stored in Keycloak
    if EntraPromptComboBox.ItemIndex > 0 then
      LBuilder.WithPrompt(EntraPromptComboBox.Items[EntraPromptComboBox.ItemIndex]);
    LProvider := LBuilder.Build;
  except
    on E: EIAM4DInvalidConfigurationException do
    begin
      Warn(E.Message);
      Exit;
    end;
  end;
  SaveIdentityProvider(LProvider);
end;

procedure TMainForm.SaveGoogleButtonClick(Sender: TObject);
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
      .WithTrustEmail(GoogleTrustEmailSwitch.IsChecked)
      .WithHideOnLogin(GoogleHideSwitch.IsChecked)
      .Build;
  except
    on E: EIAM4DInvalidConfigurationException do
    begin
      Warn(E.Message);
      Exit;
    end;
  end;
  SaveIdentityProvider(LProvider);
end;

procedure TMainForm.SaveFacebookButtonClick(Sender: TObject);
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
      .WithHideOnLogin(FacebookHideSwitch.IsChecked)
      .Build;
  except
    on E: EIAM4DInvalidConfigurationException do
    begin
      Warn(E.Message);
      Exit;
    end;
  end;
  SaveIdentityProvider(LProvider);
end;

procedure TMainForm.SaveOidcButtonClick(Sender: TObject);
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
    Warn('Enter the discovery URL of the provider.');
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

procedure TMainForm.SaveOtherButtonClick(Sender: TObject);
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
          .WithTrustEmail(OtherTrustEmailSwitch.IsChecked)
          .WithHideOnLogin(OtherHideSwitch.IsChecked)
          .Build;
      COtherLinkedIn:
        LProvider := TIAM4DLinkedInIdPBuilder.New(LAlias)
          .WithClient(LClientID, LSecret)
          .WithSyncMode(ismImport)
          .WithTrustEmail(OtherTrustEmailSwitch.IsChecked)
          .WithHideOnLogin(OtherHideSwitch.IsChecked)
          .Build;
      COtherGitHub:
        // No trust email: Keycloak does not check that the GitHub email is verified
        LProvider := TIAM4DGitHubIdPBuilder.New(LAlias)
          .WithClient(LClientID, LSecret)
          .WithEnterprise(OtherBaseURLEdit.Text, OtherApiURLEdit.Text)
          .WithSyncMode(ismImport)
          .WithHideOnLogin(OtherHideSwitch.IsChecked)
          .Build;
      COtherGitLab:
        LProvider := TIAM4DGitLabIdPBuilder.New(LAlias)
          .WithClient(LClientID, LSecret)
          .WithSyncMode(ismImport)
          .WithTrustEmail(OtherTrustEmailSwitch.IsChecked)
          .WithHideOnLogin(OtherHideSwitch.IsChecked)
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
        .WithTrustEmail(OtherTrustEmailSwitch.IsChecked)
        .WithHideOnLogin(OtherHideSwitch.IsChecked)
        .Build;
    end;
  except
    on E: EIAM4DInvalidConfigurationException do
    begin
      Warn(E.Message);
      Exit;
    end;
  end;
  SaveIdentityProvider(LProvider);
end;

procedure TMainForm.SaveSpidButtonClick(Sender: TObject);
var
  LEntry: TSpidRegistryEntry;
  LBuilder: IIAM4DSpidIdPBuilder;
begin
  if (SpidProviderComboBox.ItemIndex < 0) or (SpidProviderComboBox.ItemIndex > High(FSpidRegistry)) then
    Exit;
  LEntry := FSpidRegistry[SpidProviderComboBox.ItemIndex];
  // Service provider data first: invalid values are reported before the import
  try
    LBuilder := TIAM4DSpidIdPBuilder.New(Trim(SpidAliasEdit.Text))
      .WithDisplayName(LEntry.OrganizationName)
      .WithLevel(TIAM4DSpidLevel(SpidLevelComboBox.ItemIndex))
      .WithAttributeConsumingService(1, ServiceNameEdit.Text)
      .WithOrganization(OrgNameEdit.Text, OrgDisplayNameEdit.Text, OrgURLEdit.Text)
      .WithHideOnLogin(SpidHideSwitch.IsChecked);
    if IsPublicServiceProvider then
      LBuilder.WithPublicServiceProvider(IpaCodeEdit.Text, EmailEdit.Text, PhoneEdit.Text)
    else
      LBuilder.WithPrivateServiceProvider(VatNumberEdit.Text, FiscalCodeEdit.Text, OrgNameEdit.Text,
        EmailEdit.Text, PhoneEdit.Text);
  except
    on E: EIAM4DInvalidConfigurationException do
    begin
      Warn(E.Message);
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

procedure TMainForm.SaveCieButtonClick(Sender: TObject);
var
  LBuilder: IIAM4DCieIdPBuilder;
begin
  try
    LBuilder := TIAM4DCieIdPBuilder.New(Trim(CieAliasEdit.Text))
      .WithLevel(TIAM4DSpidLevel(CieLevelComboBox.ItemIndex))
      .WithAttributeConsumingService(1, ServiceNameEdit.Text)
      .WithOrganization(OrgNameEdit.Text, OrgDisplayNameEdit.Text, OrgURLEdit.Text)
      .WithHideOnLogin(CieHideSwitch.IsChecked);
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
      Warn(E.Message);
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

procedure TMainForm.EditChangeTracking(Sender: TObject);
begin
  UpdatePrompt(Sender as TEdit);
  if (Sender = EntraAliasEdit) or (Sender = GoogleAliasEdit) or (Sender = FacebookAliasEdit) or
     (Sender = OidcAliasEdit) or (Sender = OtherAliasEdit) or (Sender = SpidAliasEdit) or (Sender = CieAliasEdit) then
    UpdateBrokerURLs((Sender as TEdit).Text)
  else if (Sender = BaseURLEdit) or (Sender = RealmEdit) then
  begin
    UpdateConnectionSummary;
    UpdateBrokerURLs(FBrokerAlias);
  end;
end;

procedure TMainForm.ComboChange(Sender: TObject);
var
  LIndex: Integer;
  LPublic: Boolean;
begin
  if Sender = SpidProviderComboBox then
  begin
    LIndex := SpidProviderComboBox.ItemIndex;
    if (LIndex < 0) or (LIndex > High(FSpidRegistry)) then
    begin
      SpidMetadataEdit.Text := '';
      Exit;
    end;
    SpidAliasEdit.Text := FSpidRegistry[LIndex].Alias;
    SpidMetadataEdit.Text := FSpidRegistry[LIndex].MetadataURL;
    UpdateBrokerURLs(SpidAliasEdit.Text);
  end
  else if Sender = CieEnvironmentComboBox then
  begin
    if CieEnvironmentComboBox.ItemIndex < 0 then
      Exit;
    // The simulator URL follows CIE_CHECK_PORT: editable only there
    CieMetadataEdit.ReadOnly := CieEnvironmentComboBox.ItemIndex <> CCieLocalTest;
    if CieEnvironmentComboBox.ItemIndex = CCieLocalTest then
      CieMetadataEdit.Text := CCieSimulatorMetadataURL
    else
      CieMetadataEdit.Text := TIAM4DCieIdPBuilder.MetadataURL(TIAM4DCieEnvironment(CieEnvironmentComboBox.ItemIndex));
  end
  else if Sender = SPTypeComboBox then
  begin
    LPublic := IsPublicServiceProvider;
    IpaCodeEdit.Enabled := LPublic;
    IpaCategoryEdit.Enabled := LPublic;
    VatNumberEdit.Enabled := not LPublic;
    FiscalCodeEdit.Enabled := not LPublic;
  end
  else if Sender = OtherTypeComboBox then
  begin
    if OtherTypeComboBox.ItemIndex < 0 then
      Exit;
    // The alias follows the type while it is the default one
    if Trim(OtherAliasEdit.Text).IsEmpty or SameText(Trim(OtherAliasEdit.Text), COtherAliases[FOtherType]) then
      OtherAliasEdit.Text := COtherAliases[OtherTypeComboBox.ItemIndex];
    FOtherType := OtherTypeComboBox.ItemIndex;
    UpdateOtherFields;
    UpdateBrokerURLs(OtherAliasEdit.Text);
  end;
end;

procedure TMainForm.UpdateOtherFields;
const
  CNotes: array[COtherMicrosoft..COtherOAuth2] of string = (
    'Personal Microsoft accounts, profile from Microsoft Graph (work accounts: Entra ID page). ' +
    'Trust email only with a directory ID as tenant.',
    'LinkedIn app with the product "Sign In with LinkedIn using OpenID Connect". Keycloak validates the id_token ' +
    'and, with trust email, trusts only the emails LinkedIn verified.',
    'GitHub OAuth app: register the redirect URI as authorization callback URL. No trust email: Keycloak does not ' +
    'check that the GitHub email is verified.',
    'gitlab.com only (a self-managed GitLab is a Generic OIDC provider). Confidential application with scopes ' +
    'openid, read_user and email.',
    '');
var
  LControl: TControl;
  LY: Single;
begin
  OtherTenantField.Visible := FOtherType = COtherMicrosoft;
  OtherBaseURLField.Visible := FOtherType = COtherGitHub;
  OtherApiURLField.Visible := FOtherType = COtherGitHub;
  OtherAuthURLField.Visible := FOtherType = COtherOAuth2;
  OtherTokenURLField.Visible := FOtherType = COtherOAuth2;
  OtherUserInfoURLField.Visible := FOtherType = COtherOAuth2;
  OtherScopesField.Visible := FOtherType = COtherOAuth2;
  OtherClaimsField.Visible := FOtherType = COtherOAuth2;
  OtherNote.Text := CNotes[FOtherType];
  OtherNote.Visible := not OtherNote.Text.IsEmpty;
  // GitHub: no trust email
  SetEnabledLook(OtherTrustEmailRow, FOtherType <> COtherGitHub);
  if FOtherType = COtherGitHub then
    OtherTrustEmailSwitch.IsChecked := False;
  // Align = Top stacks by position: a field shown again would land below the visible ones
  OtherCard.BeginUpdate;
  try
    LY := 0;
    for LControl in TArray<TControl>.Create(OtherTitle, OtherTypeField, OtherAliasField, OtherClientIDField, OtherSecretField,
      OtherTenantField, OtherBaseURLField, OtherApiURLField, OtherAuthURLField, OtherTokenURLField,
      OtherUserInfoURLField, OtherScopesField, OtherClaimsField, OtherNote, OtherHideRow, OtherTrustEmailRow,
      SaveOtherButton) do
    begin
      LControl.Position.Y := LY;
      LY := LY + LControl.Height + LControl.Margins.Top + LControl.Margins.Bottom;
    end;
  finally
    OtherCard.EndUpdate;
  end;
  FitOtherCard;
  ShowEditTextStart(OtherCard);
end;

procedure TMainForm.FitOtherCard;
var
  LChild: TFmxObject;
  LHeight: Single;
begin
  // The card is as tall as its visible fields (the note wraps with the width)
  LHeight := OtherCard.Padding.Top + OtherCard.Padding.Bottom;
  for LChild in OtherCard.Children do
    if (LChild is TControl) and TControl(LChild).Visible and (TControl(LChild).Align = TAlignLayout.Top) then
      LHeight := LHeight + TControl(LChild).Height + TControl(LChild).Margins.Top + TControl(LChild).Margins.Bottom;
  OtherCard.Height := LHeight;
end;

procedure TMainForm.OtherNoteResized(Sender: TObject);
begin
  // The note resizes while the card aligns its children: a height set now would not realign the white face
  TThread.ForceQueue(nil, FitOtherCard);
end;

procedure TMainForm.AdminLog(const AText: string);
begin
  AdminMemo.Lines.Add(AText);
  AdminMemo.GoToTextEnd;
end;

end.
