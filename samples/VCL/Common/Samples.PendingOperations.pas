unit Samples.PendingOperations;

// Pending asynchronous operations of a VCL form, shared by the VCL samples: the form closes only
// when the last one has ended, so that no callback runs on a destroyed form.

interface

uses
  System.SysUtils,
  System.Classes,
  Vcl.Forms,
  Async.Core;

type
  /// <summary>
  ///   Counts the pending operations of a form and defers its closing until they have ended.
  /// </summary>
  /// <remarks>
  ///   Main thread only. Every BeginOperation needs exactly one EndOperation: pass EndOperation to
  ///   OnFinally (the last callback of an operation), or call it when the call raises before Run.
  /// </remarks>
  TPendingOperations = class(TComponent)
  private
    FForm: TCustomForm;
    FCount: Integer;
    FCloseRequested: Boolean;
    FOnBusyChange: TProc<Boolean>;
    FCancelOnClose: TArray<IAsyncOperation>;
    function GetIdle: Boolean;
  public
    /// <param name="AOnBusyChange">Called with True when the first operation starts and with False
    /// when the last one ends (e.g. activity indicators).</param>
    constructor Create(AForm: TCustomForm; const AOnBusyChange: TProc<Boolean> = nil); reintroduce;
    procedure BeginOperation;
    /// <summary>Ends an operation; after the last one, closes the form if a close was requested.</summary>
    procedure EndOperation;
    /// <summary>
    ///   Cancels AOperation, a pending operation, when a close is requested: e.g. a chain of requests
    ///   that stops before the next one. At once if the close was already requested.
    /// </summary>
    procedure CancelOnClose(const AOperation: IAsyncOperation);
    /// <summary>
    ///   For OnCloseQuery: True when nothing is pending. Otherwise remembers the request, cancels
    ///   ACancel (e.g. a login waiting for the browser) and the CancelOnClose operations and returns
    ///   False: the form closes when the last operation ends.
    /// </summary>
    function CloseQuery(const ACancel: IAsyncOperation = nil): Boolean;
    property Count: Integer read FCount;
    property CloseRequested: Boolean read FCloseRequested;
    /// <summary>Nothing pending and no close requested.</summary>
    property Idle: Boolean read GetIdle;
  end;

implementation

constructor TPendingOperations.Create(AForm: TCustomForm; const AOnBusyChange: TProc<Boolean>);
begin
  inherited Create(AForm);
  FForm := AForm;
  FOnBusyChange := AOnBusyChange;
end;

function TPendingOperations.GetIdle: Boolean;
begin
  Result := (FCount = 0) and not FCloseRequested;
end;

procedure TPendingOperations.BeginOperation;
begin
  Inc(FCount);
  if (FCount = 1) and Assigned(FOnBusyChange) then
    FOnBusyChange(True);
end;

procedure TPendingOperations.EndOperation;
begin
  Assert(FCount > 0, 'EndOperation without BeginOperation');
  Dec(FCount);
  if FCount > 0 then
    Exit;
  // Every operation has ended
  FCancelOnClose := nil;
  if Assigned(FOnBusyChange) then
    FOnBusyChange(False);
  if FCloseRequested then
    FForm.Close;
end;

procedure TPendingOperations.CancelOnClose(const AOperation: IAsyncOperation);
begin
  Assert(FCount > 0, 'CancelOnClose without BeginOperation');
  if FCloseRequested then
    AOperation.Cancel
  else
    FCancelOnClose := FCancelOnClose + [AOperation];
end;

function TPendingOperations.CloseQuery(const ACancel: IAsyncOperation): Boolean;
var
  LOperations: TArray<IAsyncOperation>;
  LOperation: IAsyncOperation;
begin
  Result := FCount = 0;
  if Result then
    Exit;
  FCloseRequested := True;
  // A copy: a Cancel may end the last operation at once, which clears the list
  LOperations := FCancelOnClose;
  if Assigned(ACancel) then
    ACancel.Cancel;
  for LOperation in LOperations do
    LOperation.Cancel;
end;

end.
