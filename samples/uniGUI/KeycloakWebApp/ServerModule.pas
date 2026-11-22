unit ServerModule;

interface

uses
  Classes,
  SysUtils,
  uniGUIServer,
  uniGUIMainModule,
  uniGUIApplication,
  uIdCustomHTTPServer,
  uniGUITypes,
  uIdContext,
  System.Generics.Collections,
  System.SyncObjs,
  IAMClient4D.Core;

const
  /// <summary>Minutes a login may wait for the Keycloak callback.</summary>
  PENDING_LOGIN_MINUTES = 10;
  /// <summary>Logins waiting for the callback at the same time; one more is refused.</summary>
  MAX_PENDING_LOGINS = 500;

type
  TIAMClientManager = class;

  TUniServerModule = class(TUniGUIServerModule)
    procedure UniGUIServerModuleDestroy(Sender: TObject);
    procedure UniGUIServerModuleCreate(Sender: TObject);
  private
    FIAMClientManager: TIAMClientManager;
  protected
    procedure FirstInit; override;
  public
    property IAMClientManager: TIAMClientManager read FIAMClientManager;
  end;

  /// <summary>
  /// Clients of the logins waiting for the Keycloak callback, by OAuth2 state.
  /// </summary>
  /// <remarks>
  /// Shared by the sessions (the callback opens a new uniGUI session) and thread-safe. A login
  /// expires after PENDING_LOGIN_MINUTES; at most MAX_PENDING_LOGINS are kept.
  /// </remarks>
  TIAMClientManager = class
  private type
    TPendingLogin = record
      Client: IIAM4DClient;
      CreatedAt: TDateTime;
    end;
  private
    FClients: TDictionary<string, TPendingLogin>;
    FLock: TCriticalSection;
    procedure PurgeExpired;
  public
    constructor Create;
    destructor Destroy; override;

    /// <summary>
    /// False when MAX_PENDING_LOGINS logins are waiting: checked before building a client.
    /// </summary>
    function HasRoom: Boolean;

    /// <summary>
    /// Stores the client of a login; False when MAX_PENDING_LOGINS logins are waiting.
    /// </summary>
    function TryAddClient(const AState: string; const AClient: IIAM4DClient): Boolean;

    /// <summary>
    /// Removes the client of AState and returns it, if it has not expired: a state is used once.
    /// </summary>
    function TryTakeClient(const AState: string; out AClient: IIAM4DClient): Boolean;
  end;

function UniServerModule: TUniServerModule;

implementation

{$R *.dfm}

uses
  System.DateUtils,
  uniGUIVars;

function UniServerModule: TUniServerModule;
begin
  Result := TUniServerModule(UniGUIServerInstance);
end;

procedure TUniServerModule.UniGUIServerModuleDestroy(Sender: TObject);
begin
  FIAMClientManager.Free;
end;

procedure TUniServerModule.UniGUIServerModuleCreate(Sender: TObject);
begin
  FIAMClientManager := TIAMClientManager.Create;
end;

procedure TUniServerModule.FirstInit;
begin
  InitServerModule(Self);
end;

{ TIAMClientManager }

constructor TIAMClientManager.Create;
begin
  inherited Create;

  FClients := TDictionary<string, TPendingLogin>.Create;
  FLock := TCriticalSection.Create;
end;

destructor TIAMClientManager.Destroy;
begin
  FLock.Enter;
  try
    FClients.Clear;
    FClients.Free;
  finally
    FLock.Leave;
  end;

  FLock.Free;
  inherited;
end;

procedure TIAMClientManager.PurgeExpired;
var
  LPair: TPair<string, TPendingLogin>;
  LOldest: TDateTime;
begin
  LOldest := IncMinute(Now, -PENDING_LOGIN_MINUTES);
  for LPair in FClients.ToArray do
    if LPair.Value.CreatedAt < LOldest then
      FClients.Remove(LPair.Key);
end;

function TIAMClientManager.HasRoom: Boolean;
begin
  FLock.Enter;
  try
    PurgeExpired;
    Result := FClients.Count < MAX_PENDING_LOGINS;
  finally
    FLock.Leave;
  end;
end;

function TIAMClientManager.TryAddClient(const AState: string; const AClient: IIAM4DClient): Boolean;
var
  LLogin: TPendingLogin;
begin
  if AState.Trim.IsEmpty or not Assigned(AClient) then
    raise EArgumentException.Create('State and client are required');

  FLock.Enter;
  try
    PurgeExpired;
    Result := FClients.Count < MAX_PENDING_LOGINS;
    if Result then
    begin
      LLogin.Client := AClient;
      LLogin.CreatedAt := Now;
      FClients.AddOrSetValue(AState, LLogin);
    end;
  finally
    FLock.Leave;
  end;
end;

function TIAMClientManager.TryTakeClient(const AState: string; out AClient: IIAM4DClient): Boolean;
var
  LLogin: TPendingLogin;
begin
  AClient := nil;
  Result := False;
  if AState.IsEmpty then
    Exit;

  FLock.Enter;
  try
    PurgeExpired;
    Result := FClients.TryGetValue(AState, LLogin);
    if Result then
    begin
      FClients.Remove(AState);
      AClient := LLogin.Client;
    end;
  finally
    FLock.Leave;
  end;
end;

initialization
  RegisterServerModuleClass(TUniServerModule);
end.

