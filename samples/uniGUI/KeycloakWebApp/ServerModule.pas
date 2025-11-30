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
  /// Gestisce i client IAM usando State OAuth come chiave.
  /// Thread-safe singleton accessibile da qualsiasi sessione.
  /// </summary>
  TIAMClientManager = class
  private
    FClients: TDictionary<string, IIAM4DClient>;
    FLock: TCriticalSection;
  public
    constructor Create;
    destructor Destroy; override;

    /// <summary>
    /// Salva un client usando lo State OAuth come chiave
    /// </summary>
    procedure SetClient(const AState: string; AClient: IIAM4DClient);

    /// <summary>
    /// Recupera un client usando lo State OAuth
    /// </summary>
    function GetClient(const AState: string): IIAM4DClient;

    /// <summary>
    /// Rimuove un client dalla cache (dopo CompleteAuthorizationFlow)
    /// </summary>
    procedure RemoveClient(const AState: string);
  end;

function UniServerModule: TUniServerModule;

implementation

{$R *.dfm}

uses
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

{ TIAMClientManager }

constructor TIAMClientManager.Create;
begin
  inherited Create;

  FClients := TDictionary<string, IIAM4DClient>.Create;
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

function TIAMClientManager.GetClient(const AState: string): IIAM4DClient;
begin
  Result := nil;

  if AState.Trim.IsEmpty then
    Exit;

  FLock.Enter;
  try
    if not FClients.TryGetValue(AState, Result) then
      Result := nil;
  finally
    FLock.Leave;
  end;
end;

procedure TIAMClientManager.RemoveClient(const AState: string);
begin
  if AState.Trim.IsEmpty then
    Exit;

  FLock.Enter;
  try
    FClients.Remove(AState);
  finally
    FLock.Leave;
  end;
end;

procedure TIAMClientManager.SetClient(const AState: string; AClient: IIAM4DClient);
begin
  if AState.Trim.IsEmpty then
    raise Exception.Create('State cannot be empty');

  FLock.Enter;
  try
    FClients.AddOrSetValue(AState, AClient);
  finally
    FLock.Leave;
  end;
end;

initialization
  RegisterServerModuleClass(TUniServerModule);
end.

