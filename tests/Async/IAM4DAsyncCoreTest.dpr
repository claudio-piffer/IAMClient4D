program IAM4DAsyncCoreTest;

{ Runtime test of Async.Core.

  The checks run on the main thread of a console program: every wait serves CheckSynchronize,
  so dmSynchronize and dmQueue callbacks run on the main thread as in a GUI application.

  Usage : IAM4DAsyncCoreTest
          Builds for Win32, Win64 and Linux64.
  Exit  : number of failed checks (0 = all passed). Memory leaks are reported on stderr (Windows). }

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Classes,
  System.Diagnostics,
  System.SyncObjs,
  System.Threading,
  Async.Core,
  IAMClient4D.Exceptions,
  IAMClient4D.Storage.Crypto.Interfaces;

type
  // No cloner registered: its copies keep only class and message
  ETestFieldException = class(Exception)
  public
    Code: Integer;
    constructor Create(ACode: Integer);
  end;

  IReleaseProbe = interface
    ['{0B7C3B52-8E5A-4C1D-9F43-6A2D17C0E9B4}']
    procedure Touch;
  end;

  // Sets a flag when the last reference goes: proves that the closures holding it were released
  TReleaseProbe = class(TInterfacedObject, IReleaseProbe)
  private
    FReleased: PBoolean;
  public
    constructor Create(AReleased: PBoolean);
    destructor Destroy; override;
    procedure Touch;
  end;

  // Foreign IAsyncOperation over an inner operation: sets a flag when released
  TProbeOperation = class(TInterfacedObject, IAsyncOperation)
  private
    FInner: IAsyncOperation;
    FReleased: PBoolean;
  public
    constructor Create(const AInner: IAsyncOperation; AReleased: PBoolean);
    destructor Destroy; override;
    procedure Cancel;
    function IsCancellationRequested: Boolean;
    procedure OnCancelled(const ACallback: TAsyncCoreCancelledCallback);
    function WaitForCompletion(ATimeout: Cardinal = INFINITE; ARaiseOnError: Boolean = False): TAsyncOperationState;
    function GetState: TAsyncOperationState;
    procedure OnCompletion(const ACallback: TAsyncCoreFinallyCallback);
  end;

var
  GPassed: Integer = 0;
  GFailed: Integer = 0;
  GRaised: Integer = 0;

constructor ETestFieldException.Create(ACode: Integer);
begin
  inherited CreateFmt('Test error %d', [ACode]);
  Code := ACode;
end;

constructor TReleaseProbe.Create(AReleased: PBoolean);
begin
  inherited Create;
  FReleased := AReleased;
end;

destructor TReleaseProbe.Destroy;
begin
  FReleased^ := True;
  inherited;
end;

procedure TReleaseProbe.Touch;
begin
end;

constructor TProbeOperation.Create(const AInner: IAsyncOperation; AReleased: PBoolean);
begin
  inherited Create;
  FInner := AInner;
  FReleased := AReleased;
end;

destructor TProbeOperation.Destroy;
begin
  FReleased^ := True;
  inherited;
end;

procedure TProbeOperation.Cancel;
begin
  FInner.Cancel;
end;

function TProbeOperation.IsCancellationRequested: Boolean;
begin
  Result := FInner.IsCancellationRequested;
end;

procedure TProbeOperation.OnCancelled(const ACallback: TAsyncCoreCancelledCallback);
begin
  FInner.OnCancelled(ACallback);
end;

function TProbeOperation.WaitForCompletion(ATimeout: Cardinal; ARaiseOnError: Boolean): TAsyncOperationState;
begin
  Result := FInner.WaitForCompletion(ATimeout, ARaiseOnError);
end;

function TProbeOperation.GetState: TAsyncOperationState;
begin
  Result := FInner.State;
end;

procedure TProbeOperation.OnCompletion(const ACallback: TAsyncCoreFinallyCallback);
begin
  FInner.OnCompletion(ACallback);
end;

// Exception.GetExceptionStackInfoProc runs for every raised exception, on every platform
function CountRaise(P: PExceptionRecord): Pointer;
begin
  TInterlocked.Increment(GRaised);
  Result := nil;
end;

procedure Check(ACondition: Boolean; const AName: string);
begin
  if ACondition then
  begin
    Inc(GPassed);
    Writeln('  PASS ', AName);
  end
  else
  begin
    Inc(GFailed);
    Writeln('  FAIL ', AName);
  end;
end;

// Serves the main thread queue until ACondition holds or the timeout expires
function PumpUntil(const ACondition: TFunc<Boolean>; ATimeoutMs: Integer = 5000): Boolean;
var
  LStopwatch: TStopwatch;
begin
  LStopwatch := TStopwatch.StartNew;
  while not ACondition() do
  begin
    if LStopwatch.ElapsedMilliseconds > ATimeoutMs then
      Exit(False);
    CheckSynchronize(10);
  end;
  Result := True;
end;

// Busy wait without serving the main thread queue: dmInline callbacks run on other threads
function SpinUntil(const ACondition: TFunc<Boolean>; ATimeoutMs: Integer = 5000): Boolean;
var
  LStopwatch: TStopwatch;
begin
  LStopwatch := TStopwatch.StartNew;
  while not ACondition() do
  begin
    if LStopwatch.ElapsedMilliseconds > ATimeoutMs then
      Exit(False);
    TThread.Yield;
  end;
  Result := True;
end;

procedure TestOnErrorReceivesOriginal(AMode: TAsyncCallbackDispatchMode);
var
  LDone, LClassOk: Boolean;
  LStatusCode: Integer;
  LBody: string;
  LErrorCode: TIAM4DErrorCode;
  LOp: IAsyncOperation<Integer>;
begin
  LDone := False;
  LClassOk := False;
  LStatusCode := 0;
  LErrorCode := ecUnknown;
  LOp := TAsyncCore.Run<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      raise EIAM4DHTTPClientErrorException.Create(404, 'not found body');
    end,
    nil,
    procedure(const E: Exception)
    begin
      LClassOk := E is EIAM4DHTTPClientErrorException;
      if LClassOk then
      begin
        LStatusCode := EIAM4DHTTPClientErrorException(E).StatusCode;
        LBody := EIAM4DHTTPClientErrorException(E).ResponseBody;
        LErrorCode := EIAM4DHTTPClientErrorException(E).ErrorCode;
      end;
      LDone := True;
    end,
    nil,
    AMode);

  Check(PumpUntil(function: Boolean begin Result := LDone; end), 'OnError called');
  Check(LClassOk, 'class preserved');
  Check(LStatusCode = 404, 'StatusCode preserved');
  Check(LBody = 'not found body', 'ResponseBody preserved');
  Check(LErrorCode = ecHTTPClientError, 'ErrorCode preserved');
end;

procedure TestOnErrorSynchronize;
begin
  TestOnErrorReceivesOriginal(TAsyncCallbackDispatchMode.dmSynchronize);
end;

procedure TestOnErrorQueue;
begin
  TestOnErrorReceivesOriginal(TAsyncCallbackDispatchMode.dmQueue);
end;

procedure TestWaitForResultRaisesFaithfulCopy;
var
  LOp: IAsyncOperation<Integer>;
  LRaised: Integer;
  LValue: string;
  LCopy: Exception;
  I: Integer;
begin
  LOp := TAsyncCore.Run<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      raise EIAM4DHTTPServerErrorException.Create(503, 30);
    end);

  // Each waiter gets its own copy
  LRaised := 0;
  for I := 1 to 2 do
    try
      LOp.WaitForResult(5000);
    except
      on E: EIAM4DHTTPServerErrorException do
      begin
        Inc(LRaised);
        Check(E.StatusCode = 503, Format('waiter %d: StatusCode preserved', [I]));
        Check(E.RetryAfterSeconds = 30, Format('waiter %d: RetryAfterSeconds preserved', [I]));
        Check(E.ErrorCode = ecHTTPServerError, Format('waiter %d: ErrorCode preserved', [I]));
        Check(E.Context.TryGetValue('retry_after_seconds', LValue) and (LValue = '30'),
          Format('waiter %d: Context preserved', [I]));
      end;
    end;
  Check(LRaised = 2, 'EIAM4DHTTPServerErrorException raised to both waiters');

  LCopy := LOp.GetException;
  try
    Check((LCopy is EIAM4DHTTPServerErrorException) and (EIAM4DHTTPServerErrorException(LCopy).StatusCode = 503),
      'GetException returns a faithful copy');
  finally
    LCopy.Free;
  end;
end;

procedure TestNestedWaitKeepsFields;
var
  LSource: IAsyncTaskCompletionSource<string>;
  LInner: IAsyncOperation<string>;
  LDone: Boolean;
  LUser: string;
begin
  // A task waits on a completion source
  LSource := TAsyncTaskCompletionSource<string>.Create;
  LInner := LSource.Operation;
  LDone := False;
  TAsyncCore.New<string>(
    function(const AOp: IAsyncOperation): string
    begin
      Result := LInner.WaitForResult;
    end)
    .OnError(
      procedure(const E: Exception)
      begin
        if E is EIAM4DUserNotFoundException then
          LUser := EIAM4DUserNotFoundException(E).UserIdentifier;
        LDone := True;
      end)
    .Run;

  LSource.SetException(EIAM4DUserNotFoundException.Create('bob'));
  Check(PumpUntil(function: Boolean begin Result := LDone; end), 'outer OnError called');
  Check(LUser = 'bob', 'UserIdentifier survives the nested wait');
end;

procedure TestUnregisteredExceptionFallback;
var
  LOp: IAsyncOperation<Integer>;
  LDone: Boolean;
  LOriginalCode: Integer;
begin
  LDone := False;
  LOriginalCode := 0;
  LOp := TAsyncCore.Run<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      raise ETestFieldException.Create(7);
    end,
    nil,
    procedure(const E: Exception)
    begin
      LOriginalCode := ETestFieldException(E).Code;
      LDone := True;
    end);

  Check(PumpUntil(function: Boolean begin Result := LDone; end), 'OnError called');
  Check(LOriginalCode = 7, 'OnError gets the original, fields included');
  try
    LOp.WaitForResult(5000);
    Check(False, 'WaitForResult raises');
  except
    on E: ETestFieldException do
      Check(E.Message = 'Test error 7', 'copy without cloner keeps class and message');
  end;
end;

procedure TestCompletionSourceKeepsOperationAlive;
var
  LSource: IAsyncTaskCompletionSource<Integer>;
  LOp: IAsyncOperation<Integer>;
begin
  LSource := TAsyncTaskCompletionSource<Integer>.Create;
  LOp := LSource.Operation;
  LOp := nil; // the consumer is gone: only the source references the operation
  Check(LSource.TrySetResult(42), 'TrySetResult after the consumer released the operation');
  Check(LSource.Operation.WaitForResult(1000) = 42, 'result still readable');
end;

procedure TestCompletionSourceErrors;
var
  LSource: IAsyncTaskCompletionSource<Integer>;
  LVoid: IAsyncTaskCompletionSource;
  LRaised: Boolean;
begin
  LSource := TAsyncTaskCompletionSource<Integer>.Create;
  LSource.SetResult(1);
  Check(not LSource.TrySetResult(2), 'TrySetResult on a completed source returns False');
  LRaised := False;
  try
    LSource.SetCancelled;
  except
    on EAsyncException do
      LRaised := True;
  end;
  Check(LRaised, 'SetCancelled on a completed source raises EAsyncException');
  Check(LSource.Operation.WaitForResult(0) = 1, 'first result kept');

  LSource := TAsyncTaskCompletionSource<Integer>.Create;
  LSource.SetException(nil);
  LRaised := False;
  try
    LSource.Operation.WaitForResult(1000);
  except
    on EAsyncException do
      LRaised := True;
  end;
  Check(LRaised, 'SetException(nil): WaitForResult raises EAsyncException instead of an access violation');

  LVoid := TAsyncTaskCompletionSource.Create;
  LVoid.SetResult;
  LVoid.Operation.OnCompletion(nil);
  Check(LVoid.Operation.State = TAsyncOperationState.Completed, 'OnCompletion(nil) on a completed operation is ignored');
end;

procedure TestUserOnCancelledKeepsDelayCancellable;
var
  LDelay: IAsyncOperation;
  LUserCalled: Boolean;
  LStopwatch: TStopwatch;
begin
  LDelay := TAsyncCore.Delay(10000);
  Sleep(100); // lets the delay task register its own cancellation handler
  LUserCalled := False;
  LDelay.OnCancelled(
    procedure
    begin
      LUserCalled := True;
    end);

  LStopwatch := TStopwatch.StartNew;
  LDelay.Cancel;
  Check(LDelay.WaitForCompletion(3000) = TAsyncOperationState.Cancelled, 'delay cancelled');
  Check(LStopwatch.ElapsedMilliseconds < 2000, 'cancellation interrupts the wait');
  Check(PumpUntil(function: Boolean begin Result := LUserCalled; end), 'user OnCancelled called');
end;

procedure TestFailingOnSuccessKeepsCompletedState;
var
  LOp: IAsyncOperation<Integer>;
  LErrorCalled: Boolean;
  LUnhandled: string;
begin
  LErrorCalled := False;
  LUnhandled := '';
  TAsyncCore.OnUnhandledError :=
    procedure(const E: Exception)
    begin
      LUnhandled := E.Message;
    end;
  try
    LOp := TAsyncCore.Run<Integer>(
      function(const AOp: IAsyncOperation): Integer
      begin
        Result := 42;
      end,
      procedure(const AValue: Integer)
      begin
        raise Exception.Create('callback failure');
      end,
      procedure(const E: Exception)
      begin
        LErrorCalled := True;
      end,
      nil,
      TAsyncCallbackDispatchMode.dmSynchronize);

    Check(LOp.WaitForResult(5000) = 42, 'result available');
    Check(LOp.State = TAsyncOperationState.Completed, 'state stays Completed');
    Check(PumpUntil(function: Boolean begin Result := LUnhandled = 'callback failure'; end),
      'callback error reported to OnUnhandledError');
    Check(not LErrorCalled, 'OnError not called for a callback failure');
  finally
    TAsyncCore.OnUnhandledError := nil;
  end;
end;

procedure TestCallbacksQueue;
var
  LOp: IAsyncOperation<Integer>;
  LSuccessValue: Integer;
  LFinally: Boolean;
begin
  LSuccessValue := 0;
  LFinally := False;
  LOp := TAsyncCore.Run<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      Result := 5;
    end,
    procedure(const AValue: Integer)
    begin
      LSuccessValue := AValue;
    end,
    nil,
    procedure
    begin
      LFinally := True;
    end,
    TAsyncCallbackDispatchMode.dmQueue);

  Check(LOp.WaitForResult(5000) = 5, 'result available');
  Check(PumpUntil(function: Boolean begin Result := (LSuccessValue = 5) and LFinally; end),
    'OnSuccess and OnFinally run on the main thread');
end;

procedure TestRetryLinearZeroDelay;
var
  LAttempts: Integer;
  LOp: IAsyncOperation<Integer>;
begin
  LAttempts := 0;
  LOp := TAsyncCore.RunWithRetry<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      if TInterlocked.Increment(LAttempts) < 3 then
        raise Exception.Create('transient');
      Result := LAttempts;
    end,
    3, 0, TBackoffStrategy.Linear);

  Check(LOp.WaitForResult(5000) = 3, 'Linear backoff with zero delay retries (no EDivByZero)');
end;

procedure TestRetryCancelInterruptsBackoff;
var
  LAttempts: Integer;
  LOp: IAsyncOperation<Integer>;
  LStopwatch: TStopwatch;
begin
  LAttempts := 0;
  LOp := TAsyncCore.RunWithRetry<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      TInterlocked.Increment(LAttempts);
      raise Exception.Create('always fails');
    end,
    5, 10000, TBackoffStrategy.Fixed);

  PumpUntil(function: Boolean begin Result := TInterlocked.CompareExchange(LAttempts, 0, 0) > 0; end);
  Sleep(50); // the task is now waiting for the backoff delay
  LStopwatch := TStopwatch.StartNew;
  LOp.Cancel;
  Check(LOp.WaitForCompletion(3000) = TAsyncOperationState.Cancelled, 'cancelled during backoff');
  Check(LStopwatch.ElapsedMilliseconds < 2000, 'backoff wait interrupted');
  Check(LAttempts = 1, 'no further attempt after cancellation');
end;

procedure TestRetryPredicate;
var
  LAttempts, LStatusCode: Integer;
  LOp: IAsyncOperation<Integer>;
begin
  LAttempts := 0;
  LStatusCode := 0;
  LOp := TAsyncCore.RunWithRetry<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      TInterlocked.Increment(LAttempts);
      raise EIAM4DHTTPClientErrorException.Create(400, 'invalid_grant');
    end,
    3, 10, TBackoffStrategy.Fixed, 1000,
    function(const E: Exception): Boolean
    begin
      Result := not (E is EIAM4DHTTPClientErrorException);
    end);

  try
    LOp.WaitForResult(5000);
  except
    on E: EIAM4DHTTPClientErrorException do
      LStatusCode := E.StatusCode;
  end;
  Check(LAttempts = 1, 'error rejected by AShouldRetry is not retried');
  Check(LStatusCode = 400, 'original error raised with its fields');
end;

procedure TestRetryNegativeMaxRetries;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TAsyncCore.RunWithRetry<Integer>(
      function(const AOp: IAsyncOperation): Integer
      begin
        Result := 0;
      end,
      -1);
  except
    on EArgumentOutOfRangeException do
      LRaised := True;
  end;
  Check(LRaised, 'negative AMaxRetries raises EArgumentOutOfRangeException');
end;

procedure TestWaitTimeoutAlwaysRaises;
var
  LDelay: IAsyncOperation;
  LRaised: Boolean;
begin
  LDelay := TAsyncCore.Delay(2000);
  LRaised := False;
  try
    LDelay.WaitForCompletion(50, False);
  except
    on EAsyncTimeoutException do
      LRaised := True;
  end;
  Check(LRaised, 'timeout raises EAsyncTimeoutException even with ARaiseOnError = False');
  LDelay.Cancel;
  Check(LDelay.WaitForCompletion(3000) = TAsyncOperationState.Cancelled, 'delay cancelled afterwards');
end;

function RunValue(AValue, ADelayMs: Integer): IAsyncOperation<Integer>;
begin
  Result := TAsyncCore.Run<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      Sleep(ADelayMs);
      Result := AValue;
    end);
end;

procedure TestCombinators;
var
  LAll: TArray<Integer>;
  LSource: IAsyncTaskCompletionSource<Integer>;
  LContinuation: IAsyncOperation<Integer>;
begin
  LAll := TAsyncCore.WhenAll<Integer>([RunValue(1, 150), RunValue(2, 50), RunValue(3, 100)]).WaitForResult(5000);
  Check((Length(LAll) = 3) and (LAll[0] = 1) and (LAll[1] = 2) and (LAll[2] = 3), 'WhenAll keeps the order of the results');

  Check(TAsyncCore.WhenAny<Integer>([RunValue(1, 1000), RunValue(2, 20)]).WaitForResult(5000) = 2,
    'WhenAny returns the first result');

  LSource := TAsyncTaskCompletionSource<Integer>.Create(TAsyncCallbackDispatchMode.dmSynchronize);
  LContinuation := TAsyncCore.ContinueWith<Integer, Integer>(LSource.Operation,
    function(const AValue: Integer): Integer
    begin
      Result := AValue * 2;
    end);
  LSource.SetResult(21);
  Check(LContinuation.WaitForResult(5000) = 42, 'ContinueWith transforms the result');

  LSource := TAsyncTaskCompletionSource<Integer>.Create(TAsyncCallbackDispatchMode.dmSynchronize);
  LContinuation := TAsyncCore.ContinueWith<Integer, Integer>(LSource.Operation,
    function(const AValue: Integer): Integer
    begin
      raise EAsyncCancelException.Create;
    end);
  LSource.SetResult(1);
  Check(LContinuation.WaitForCompletion(5000) = TAsyncOperationState.Cancelled,
    'EAsyncCancelException in a continuation cancels it');
end;

// Waits like a server main thread: no CheckSynchronize, Synchronize/Queue requests are never served
function WaitWithoutMainThread(AEvent: TEvent; ATimeoutMs: Cardinal = 10000): Boolean;
begin
  Result := AEvent.WaitFor(ATimeoutMs) = wrSignaled;
end;

procedure TestInlineCallbacks;
var
  LEvent: TEvent;
  LSuccessThread, LErrorThread, LFinallyThread: TThreadID;
  LErrorClassOk: Boolean;
begin
  LEvent := TEvent.Create;
  LSuccessThread := MainThreadID;
  TAsyncCore.Run<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      Result := 7;
    end,
    procedure(const AValue: Integer)
    begin
      LSuccessThread := TThread.Current.ThreadID;
    end,
    nil,
    procedure
    begin
      LEvent.SetEvent;
    end,
    TAsyncCallbackDispatchMode.dmInline);
  Check(WaitWithoutMainThread(LEvent), 'OnSuccess/OnFinally run without the main thread');
  Check(LSuccessThread <> MainThreadID, 'OnSuccess runs on the pool thread');

  LEvent.ResetEvent;
  LErrorThread := MainThreadID;
  LFinallyThread := MainThreadID;
  LErrorClassOk := False;
  TAsyncCore.New<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      raise EIAM4DHTTPClientErrorException.Create(401, '');
    end)
    .DispatchMode(TAsyncCallbackDispatchMode.dmInline)
    .OnError(
      procedure(const E: Exception)
      begin
        LErrorClassOk := E is EIAM4DHTTPClientErrorException;
        LErrorThread := TThread.Current.ThreadID;
      end)
    .OnFinally(
      procedure
      begin
        LFinallyThread := TThread.Current.ThreadID;
        LEvent.SetEvent;
      end)
    .Run;
  Check(WaitWithoutMainThread(LEvent), 'OnError/OnFinally run without the main thread');
  Check(LErrorClassOk and (LErrorThread <> MainThreadID) and (LFinallyThread <> MainThreadID),
    'OnError and OnFinally run on the pool thread');
  LEvent.Free;
end;

procedure TestCombinatorsWithoutMainThread;
var
  LDone: TEvent;
  LAll, LAny, LContinued, LTimed: Integer;
  LError: string;
begin
  LDone := TEvent.Create;
  LAll := 0;
  LAny := 0;
  LContinued := 0;
  LTimed := 0;
  LError := '';
  // As in a server: a worker thread waits while the main thread never serves Synchronize
  TThread.CreateAnonymousThread(
    procedure
    begin
      try
        LAll := Length(TAsyncCore.WhenAll<Integer>([RunValue(1, 30), RunValue(2, 10)]).WaitForResult(3000));
        LAny := TAsyncCore.WhenAny<Integer>([RunValue(5, 10), RunValue(6, 500)]).WaitForResult(3000);
        LContinued := TAsyncCore.ContinueWith<Integer, Integer>(RunValue(20, 10),
          function(const AValue: Integer): Integer
          begin
            Result := AValue + 1;
          end).WaitForResult(3000);
        LTimed := TAsyncCore.RunWithTimeout<Integer>(
          function(const AOp: IAsyncOperation): Integer
          begin
            Result := 3;
          end, 3000).WaitForResult(3000);
      except
        on E: Exception do
          LError := E.ClassName + ': ' + E.Message;
      end;
      LDone.SetEvent;
    end).Start;

  Check(WaitWithoutMainThread(LDone, 20000), 'worker finished');
  Check(LError = '', 'no error ' + LError);
  Check(LAll = 2, 'WhenAll completes without the main thread');
  Check(LAny = 5, 'WhenAny completes without the main thread');
  Check(LContinued = 21, 'ContinueWith completes without the main thread');
  Check(LTimed = 3, 'RunWithTimeout completes without the main thread');
  LDone.Free;
end;

function RunUntilCancelled: IAsyncOperation<Integer>;
begin
  Result := TAsyncCore.Run<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      while not AOp.IsCancellationRequested do
        Sleep(5);
      raise EAsyncCancelException.Create;
    end);
end;

procedure TestCombinatorCancel;
var
  LA, LB: IAsyncOperation<Integer>;
  LAll: IAsyncOperation<TArray<Integer>>;
  LAny, LContinued, LTimed: IAsyncOperation<Integer>;
begin
  LA := RunUntilCancelled;
  LB := RunUntilCancelled;
  LAll := TAsyncCore.WhenAll<Integer>([LA, LB]);
  LAll.Cancel;
  Check(LAll.State = TAsyncOperationState.Cancelled, 'WhenAll cancelled at once');
  Check((LA.WaitForCompletion(2000) = TAsyncOperationState.Cancelled) and
    (LB.WaitForCompletion(2000) = TAsyncOperationState.Cancelled), 'WhenAll cancels its operations');

  LA := RunUntilCancelled;
  LAny := TAsyncCore.WhenAny<Integer>([LA]);
  LAny.Cancel;
  Check(LAny.State = TAsyncOperationState.Cancelled, 'WhenAny cancelled at once');
  Check(LA.WaitForCompletion(2000) = TAsyncOperationState.Cancelled, 'WhenAny cancels its operations');

  LA := RunUntilCancelled;
  LContinued := TAsyncCore.ContinueWith<Integer, Integer>(LA,
    function(const AValue: Integer): Integer
    begin
      Result := AValue;
    end);
  LContinued.Cancel;
  Check(LContinued.State = TAsyncOperationState.Cancelled, 'ContinueWith cancelled at once');
  Check(LA.WaitForCompletion(2000) = TAsyncOperationState.Cancelled, 'ContinueWith cancels its source');

  // The task ignores cancellation: the result is cancelled anyway
  LTimed := TAsyncCore.RunWithTimeout<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      Sleep(1000);
      Result := 1;
    end, 10000);
  LTimed.Cancel;
  Check(LTimed.WaitForCompletion(500) = TAsyncOperationState.Cancelled, 'RunWithTimeout cancelled at once');
end;

procedure TestRunWithTimeoutRaisesTimeout;
var
  LTimed: IAsyncOperation<Integer>;
  LRaised, LCancelSeen: Boolean;
begin
  LCancelSeen := False;
  LTimed := TAsyncCore.RunWithTimeout<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      while not AOp.IsCancellationRequested do
        Sleep(5);
      LCancelSeen := True;
      Result := 0;
    end, 100);

  LRaised := False;
  try
    LTimed.WaitForResult(3000);
  except
    on EAsyncTimeoutException do
      LRaised := True;
  end;
  Check(LRaised, 'timeout raises EAsyncTimeoutException');
  Check(LTimed.State = TAsyncOperationState.Faulted, 'state Faulted');
  Check(PumpUntil(function: Boolean begin Result := LCancelSeen; end), 'the task receives the cancellation');
end;

function IsSignaled(AEvent: TEvent): Boolean;
begin
  Result := AEvent.WaitFor(0) = wrSignaled;
end;

procedure TestRunWithTimeoutInlineCancelsTask;
var
  LCancelled, LTaskEnded, LDone: TEvent;
  LHandlerThread: TThreadID;
  LTimed: IAsyncOperation<Integer>;
  LError: Exception;
begin
  LCancelled := TEvent.Create;
  LTaskEnded := TEvent.Create;
  LDone := TEvent.Create;
  LHandlerThread := MainThreadID;
  try
    LTimed := TAsyncCore.RunWithTimeout<Integer>(
      function(const AOp: IAsyncOperation): Integer
      begin
        try
          // Blocked as on I/O that only a cancellation handler can abort
          AOp.OnCancelled(
            procedure
            begin
              LHandlerThread := TThread.Current.ThreadID;
              LCancelled.SetEvent;
            end);
          LCancelled.WaitFor(10000);
          raise EAsyncCancelException.Create;
        finally
          LTaskEnded.SetEvent;
        end;
      end, 100, TAsyncCallbackDispatchMode.dmInline);
    LTimed.OnCompletion(
      procedure
      begin
        LDone.SetEvent;
      end);

    Check(WaitWithoutMainThread(LCancelled, 3000), 'the timeout runs the OnCancelled of the task without the main thread');
    Check(LHandlerThread <> MainThreadID, 'OnCancelled runs on the timer thread');
    Check(WaitWithoutMainThread(LTaskEnded, 3000), 'the task ends');
    Check(WaitWithoutMainThread(LDone, 3000) and (LTimed.State = TAsyncOperationState.Faulted), 'result Faulted');
    LError := LTimed.GetException;
    try
      Check(LError is EAsyncTimeoutException, 'with EAsyncTimeoutException');
    finally
      LError.Free;
    end;
  finally
    // A timer thread stuck in Synchronize (regression) is served here, before the events are freed
    PumpUntil(function: Boolean begin Result := IsSignaled(LCancelled) and IsSignaled(LTaskEnded); end, 15000);
    LDone.Free;
    LTaskEnded.Free;
    LCancelled.Free;
  end;
end;

procedure TestRunWithTimeoutQueueDoesNotBlockTimer;
var
  LTaskEnded: TEvent;
  LFirst, LSecond: Boolean;
  LTimed: IAsyncOperation<Integer>;
begin
  LTaskEnded := TEvent.Create;
  LFirst := False;
  LSecond := False;
  try
    LTimed := TAsyncCore.RunWithTimeout<Integer>(
      function(const AOp: IAsyncOperation): Integer
      begin
        try
          AOp.OnCancelled(
            procedure
            begin
              LFirst := True;
            end);
          AOp.OnCancelled(
            procedure
            begin
              LSecond := True;
            end);
          while not AOp.IsCancellationRequested do
            Sleep(5);
          raise EAsyncCancelException.Create;
        finally
          LTaskEnded.SetEvent;
        end;
      end, 100, TAsyncCallbackDispatchMode.dmQueue);

    Check(WaitWithoutMainThread(LTaskEnded, 3000), 'the task receives the cancellation without the main thread');
    Sleep(100); // the timer thread dispatches the handlers
    Check(LTimed.State = TAsyncOperationState.Faulted, 'result Faulted');
    Check(not LFirst and not LSecond, 'the handlers wait for the main thread');
    // Synchronize would post the second handler only after the first has run
    CheckSynchronize(0);
    Check(LFirst and LSecond, 'the timer queues all the handlers without waiting for the main thread');
  finally
    PumpUntil(function: Boolean begin Result := LFirst and LSecond; end);
    LTaskEnded.Free;
  end;
end;

procedure TestRunWithTimeoutInlineTaskError;
var
  LDone: TEvent;
  LTimed: IAsyncOperation<Integer>;
  LError: Exception;
begin
  LDone := TEvent.Create;
  // As a server logging the errors: the error of the task is dispatched before the result completes
  TAsyncCore.OnUnhandledError :=
    procedure(const E: Exception)
    begin
    end;
  try
    LTimed := TAsyncCore.RunWithTimeout<Integer>(
      function(const AOp: IAsyncOperation): Integer
      begin
        Sleep(50);
        raise EIAM4DHTTPClientErrorException.Create(401, '');
      end, 3000, TAsyncCallbackDispatchMode.dmInline);
    LTimed.OnCompletion(
      procedure
      begin
        LDone.SetEvent;
      end);

    Check(WaitWithoutMainThread(LDone, 2000), 'a task error ends the result without the main thread');
    LError := LTimed.GetException;
    try
      Check(LError is EIAM4DHTTPClientErrorException, 'with the error of the task, not a timeout');
    finally
      LError.Free;
    end;
  finally
    PumpUntil(function: Boolean begin Result := IsSignaled(LDone); end, 10000);
    TAsyncCore.OnUnhandledError := nil;
    LDone.Free;
  end;
end;

procedure TestRetryDispatchMode;
var
  LDone: TEvent;
  LAttempts: Integer;
  LThread: TThreadID;
  LOp: IAsyncOperation<Integer>;
begin
  LDone := TEvent.Create;
  LAttempts := 0;
  LThread := MainThreadID;
  try
    LOp := TAsyncCore.RunWithRetry<Integer>(
      function(const AOp: IAsyncOperation): Integer
      begin
        if TInterlocked.Increment(LAttempts) < 2 then
          raise Exception.Create('transient');
        Result := LAttempts;
      end,
      1, 200, TBackoffStrategy.Fixed, 1000, nil, TAsyncCallbackDispatchMode.dmInline);
    LOp.OnCompletion(
      procedure
      begin
        LThread := TThread.Current.ThreadID;
        LDone.SetEvent;
      end);

    Check(WaitWithoutMainThread(LDone, 3000), 'dmInline: OnCompletion runs without the main thread');
    Check(LThread <> MainThreadID, 'on the pool thread');
    Check(LOp.WaitForResult(0) = 2, 'result after one retry');
  finally
    PumpUntil(function: Boolean begin Result := IsSignaled(LDone); end);
    LDone.Free;
  end;
end;

procedure TestDelayDispatchMode;
var
  LDone: TEvent;
  LThread: TThreadID;
  LDelay: IAsyncOperation;
begin
  LDone := TEvent.Create;
  LThread := MainThreadID;
  try
    LDelay := TAsyncCore.Delay(100, TAsyncCallbackDispatchMode.dmInline);
    LDelay.OnCompletion(
      procedure
      begin
        LThread := TThread.Current.ThreadID;
        LDone.SetEvent;
      end);

    Check(WaitWithoutMainThread(LDone, 3000), 'dmInline: OnCompletion runs without the main thread');
    Check(LThread <> MainThreadID, 'on the pool thread');
    Check(LDelay.State = TAsyncOperationState.Completed, 'state Completed');
  finally
    PumpUntil(function: Boolean begin Result := IsSignaled(LDone); end);
    LDone.Free;
  end;
end;

procedure TestDefaultDispatchModeUnchanged;
var
  LCalled: Boolean;
  LThread: TThreadID;
  LOp: IAsyncOperation<Integer>;
begin
  LCalled := False;
  LThread := 0;
  TAsyncCore.Delay(100).OnCompletion(
    procedure
    begin
      LThread := TThread.Current.ThreadID;
      LCalled := True;
    end);
  Check(PumpUntil(function: Boolean begin Result := LCalled; end) and (LThread = MainThreadID),
    'Delay: callbacks on the main thread');

  LCalled := False;
  LThread := 0;
  LOp := TAsyncCore.RunWithRetry<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      Sleep(100);
      Result := 1;
    end);
  LOp.OnCompletion(
    procedure
    begin
      LThread := TThread.Current.ThreadID;
      LCalled := True;
    end);
  Check(PumpUntil(function: Boolean begin Result := LCalled; end) and (LThread = MainThreadID),
    'RunWithRetry: callbacks on the main thread');

  LCalled := False;
  LThread := 0;
  LOp := TAsyncCore.RunWithTimeout<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      AOp.OnCancelled(
        procedure
        begin
          LThread := TThread.Current.ThreadID;
          LCalled := True;
        end);
      while not AOp.IsCancellationRequested do
        Sleep(5);
      Result := 0;
    end, 100);
  Check(PumpUntil(function: Boolean begin Result := LCalled; end) and (LThread = MainThreadID),
    'RunWithTimeout: OnCancelled of the task on the main thread');
  Check(LOp.WaitForCompletion(3000) = TAsyncOperationState.Faulted, 'RunWithTimeout: result Faulted');
end;

procedure TestRetryJitter;
var
  LAttempts: Integer;
  LStopwatch: TStopwatch;
  LElapsed: Int64;
  LOp: IAsyncOperation<Integer>;
begin
  LAttempts := 0;
  LStopwatch := TStopwatch.StartNew;
  LOp := TAsyncCore.RunWithRetry<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      if TInterlocked.Increment(LAttempts) < 3 then
        raise Exception.Create('transient');
      Result := LAttempts;
    end,
    3, 100, TBackoffStrategy.ExponentialJitter);

  Check(LOp.WaitForResult(5000) = 3, 'retried until success');
  LElapsed := LStopwatch.ElapsedMilliseconds;
  // Delays in [50, 100] and [100, 200] ms
  Check((LElapsed >= 140) and (LElapsed < 1000), Format('total backoff within the jitter range (%d ms)', [LElapsed]));
end;

procedure TestStorageCryptoExceptionClone;
var
  LOp: IAsyncOperation<Integer>;
  LProvider: string;
  LCode: TIAM4DErrorCode;
begin
  LOp := TAsyncCore.Run<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      raise EIAM4DStorageDecryptionException.Create('TMS', 'authentication tag mismatch');
    end);

  LProvider := '';
  LCode := ecUnknown;
  try
    LOp.WaitForResult(5000);
  except
    on E: EIAM4DStorageDecryptionException do
    begin
      LProvider := E.ProviderName;
      LCode := E.ErrorCode;
    end;
  end;
  Check(LProvider = 'TMS', 'ProviderName survives WaitForResult');
  // An EIAM4DException: one handler catches every library error
  Check(LCode = ecStorageDecryptionFailed, 'storage crypto exception is an EIAM4DException with its error code');
end;

procedure TestFromOperationSuccess;
var
  LSource: IAsyncTaskCompletionSource<Integer>;
  LOp: IAsyncOperation<Integer>;
  LValue: Integer;
  LFinally: Boolean;
begin
  LSource := TAsyncTaskCompletionSource<Integer>.Create;
  LValue := 0;
  LFinally := False;
  LOp := TAsyncCore.FromOperation<Integer>(LSource.Operation)
    .OnSuccess(
      procedure(const AValue: Integer)
      begin
        LValue := AValue;
      end)
    .OnFinally(
      procedure
      begin
        LFinally := True;
      end)
    .Run;
  Check(LOp.State = TAsyncOperationState.Running, 'running while the source is pending');

  LSource.SetResult(42);
  Check(PumpUntil(function: Boolean begin Result := LFinally; end), 'OnFinally called');
  Check(LValue = 42, 'OnSuccess receives the result');
  Check(LOp.WaitForResult(1000) = 42, 'WaitForResult returns the result');

  // Source already completed, operation not kept by the caller
  LFinally := False;
  TAsyncCore.FromOperation<Integer>(LSource.Operation)
    .OnFinally(
      procedure
      begin
        LFinally := True;
      end)
    .Run;
  Check(PumpUntil(function: Boolean begin Result := LFinally; end), 'completed source: OnFinally called');
end;

procedure TestFromOperationError;
var
  LSource: IAsyncTaskCompletionSource<string>;
  LOp: IAsyncOperation<string>;
  LUser: string;
  LFinally, LSuccess: Boolean;
begin
  LSource := TAsyncTaskCompletionSource<string>.Create;
  LUser := '';
  LFinally := False;
  LSuccess := False;
  LOp := TAsyncCore.FromOperation<string>(LSource.Operation)
    .OnSuccess(
      procedure(const AValue: string)
      begin
        LSuccess := True;
      end)
    .OnError(
      procedure(const E: Exception)
      begin
        if E is EIAM4DUserNotFoundException then
          LUser := EIAM4DUserNotFoundException(E).UserIdentifier;
      end)
    .OnFinally(
      procedure
      begin
        LFinally := True;
      end)
    .Run;

  LSource.SetException(EIAM4DUserNotFoundException.Create('bob'));
  Check(PumpUntil(function: Boolean begin Result := LFinally; end), 'OnFinally called');
  Check(LUser = 'bob', 'OnError gets the exception with its fields');
  Check(not LSuccess, 'OnSuccess not called');
  Check(LOp.State = TAsyncOperationState.Faulted, 'state Faulted');
end;

procedure TestFromOperationCancel;
var
  LSource: IAsyncTaskCompletionSource<string>;
  LOp: IAsyncOperation<string>;
  LSuccess, LError, LFinally: Boolean;
  LOldProc: function(P: PExceptionRecord): Pointer;
begin
  // The producer ends the operation when asked, as StartAuthorizationFlowAsync does
  LSource := TAsyncTaskCompletionSource<string>.Create(TAsyncCallbackDispatchMode.dmInline);
  LSource.Operation.OnCancelled(
    procedure
    begin
      LSource.TrySetCancelled;
    end);

  LSuccess := False;
  LError := False;
  LFinally := False;
  LOp := TAsyncCore.FromOperation<string>(LSource.Operation)
    .OnSuccess(
      procedure(const AValue: string)
      begin
        LSuccess := True;
      end)
    .OnError(
      procedure(const E: Exception)
      begin
        LError := True;
      end)
    .OnFinally(
      procedure
      begin
        LFinally := True;
      end)
    .Run;

  LOldProc := Exception.GetExceptionStackInfoProc;
  GRaised := 0;
  Exception.GetExceptionStackInfoProc := CountRaise;
  try
    try
      raise EAsyncCancelException.Create;
    except
      on EAsyncCancelException do
        ;
    end;
    Check(GRaised = 1, 'raised exceptions are counted');
    GRaised := 0;

    LOp.Cancel;
    Check(not LFinally, 'no callback runs inside Cancel');
    Check(LSource.Operation.State = TAsyncOperationState.Cancelled, 'Cancel reaches the producer');
    Check(PumpUntil(function: Boolean begin Result := LFinally; end), 'OnFinally called');
    Check(GRaised = 0, 'no exception raised');
  finally
    Exception.GetExceptionStackInfoProc := LOldProc;
  end;
  Check(LOp.State = TAsyncOperationState.Cancelled, 'state Cancelled');
  Check(not LSuccess and not LError, 'neither OnSuccess nor OnError');

  // Without a cancellation handler the producer ignores Cancel: the operation ends as the source does
  LSource := TAsyncTaskCompletionSource<string>.Create;
  LOp := TAsyncCore.FromOperation<string>(LSource.Operation).Run;
  LOp.Cancel;
  Check(LSource.Operation.IsCancellationRequested, 'Cancel forwarded to the source');
  Check(LOp.State = TAsyncOperationState.Running, 'still running');
  LSource.SetResult('late');
  Check(LOp.WaitForResult(5000) = 'late', 'ends with the result of the source');
end;

procedure TestFromOperationInline;
var
  LSource: IAsyncTaskCompletionSource<Integer>;
  LEvent: TEvent;
  LValue: Integer;
begin
  LEvent := TEvent.Create;
  LValue := 0;
  LSource := TAsyncTaskCompletionSource<Integer>.Create(TAsyncCallbackDispatchMode.dmInline);
  TAsyncCore.FromOperation<Integer>(LSource.Operation)
    .DispatchMode(TAsyncCallbackDispatchMode.dmInline)
    .OnSuccess(
      procedure(const AValue: Integer)
      begin
        LValue := AValue;
      end)
    .OnFinally(
      procedure
      begin
        LEvent.SetEvent;
      end)
    .Run;
  LSource.SetResult(3);
  Check(WaitWithoutMainThread(LEvent), 'callbacks run without the main thread');
  Check(LValue = 3, 'OnSuccess receives the result');
  LEvent.Free;
end;

function FollowWithProbe(const ASource: IAsyncOperation<Integer>; AReleased: PBoolean): IAsyncOperation<Integer>;
var
  LProbe: IReleaseProbe;
begin
  LProbe := TReleaseProbe.Create(AReleased);
  Result := TAsyncCore.FromOperation<Integer>(ASource)
    .OnFinally(
      procedure
      begin
        LProbe.Touch;
      end)
    .Run;
end;

procedure TestFromOperationReleasesCallbacks;
var
  LSource: IAsyncTaskCompletionSource<Integer>;
  LOp: IAsyncOperation<Integer>;
  LReleased: Boolean;
begin
  LReleased := False;
  LSource := TAsyncTaskCompletionSource<Integer>.Create;
  LOp := FollowWithProbe(LSource.Operation, @LReleased);
  LSource.SetResult(1);
  Check(LOp.WaitForResult(5000) = 1, 'completed');
  LOp := nil;
  Check(PumpUntil(function: Boolean begin Result := LReleased; end), 'callbacks released after completion');

  LReleased := False;
  LSource := TAsyncTaskCompletionSource<Integer>.Create(TAsyncCallbackDispatchMode.dmInline);
  LSource.Operation.OnCancelled(
    procedure
    begin
      LSource.TrySetCancelled;
    end);
  LOp := FollowWithProbe(LSource.Operation, @LReleased);
  LOp.Cancel;
  Check(LOp.WaitForCompletion(5000) = TAsyncOperationState.Cancelled, 'cancelled');
  LOp := nil;
  Check(PumpUntil(function: Boolean begin Result := LReleased; end), 'callbacks released after cancellation');
end;

procedure TestQueueNotReentrant;
var
  LDone: Boolean;
  LA, LB: IAsyncOperation<Integer>;
  LAll: IAsyncOperation<TArray<Integer>>;
  LContinued, LTimed: IAsyncOperation<Integer>;
  LSource: IAsyncTaskCompletionSource<Integer>;
begin
  // Cancel from the main thread (a UI event): the dmQueue callbacks run later, from the message loop
  LA := RunUntilCancelled;
  LB := RunUntilCancelled;
  LDone := False;
  LAll := TAsyncCore.WhenAll<Integer>([LA, LB], TAsyncCallbackDispatchMode.dmQueue);
  LAll.OnCompletion(
    procedure
    begin
      LDone := True;
    end);
  LAll.Cancel;
  Check(not LDone, 'WhenAll: no callback inside Cancel');
  Check(PumpUntil(function: Boolean begin Result := LDone; end), 'WhenAll: callback run by the main thread loop');
  LA.WaitForCompletion(2000);
  LB.WaitForCompletion(2000);

  LA := RunUntilCancelled;
  LDone := False;
  LContinued := TAsyncCore.ContinueWith<Integer, Integer>(LA,
    function(const AValue: Integer): Integer
    begin
      Result := AValue;
    end, TAsyncCallbackDispatchMode.dmQueue);
  LContinued.OnCompletion(
    procedure
    begin
      LDone := True;
    end);
  LContinued.Cancel;
  Check(not LDone, 'ContinueWith: no callback inside Cancel');
  Check(PumpUntil(function: Boolean begin Result := LDone; end), 'ContinueWith: callback run by the main thread loop');
  LA.WaitForCompletion(2000);

  LDone := False;
  LTimed := TAsyncCore.RunWithTimeout<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      while not AOp.IsCancellationRequested do
        Sleep(5);
      Result := 0;
    end, 10000, TAsyncCallbackDispatchMode.dmQueue);
  LTimed.OnCompletion(
    procedure
    begin
      LDone := True;
    end);
  LTimed.Cancel;
  Check(not LDone, 'RunWithTimeout: no callback inside Cancel');
  Check(PumpUntil(function: Boolean begin Result := LDone; end), 'RunWithTimeout: callback run by the main thread loop');

  LSource := TAsyncTaskCompletionSource<Integer>.Create(TAsyncCallbackDispatchMode.dmQueue);
  LDone := False;
  LSource.Operation.OnCompletion(
    procedure
    begin
      LDone := True;
    end);
  LSource.SetResult(1);
  Check(not LDone, 'completion source: no callback inside SetResult');
  Check(PumpUntil(function: Boolean begin Result := LDone; end), 'completion source: callback run by the main thread loop');

  LDone := False;
  LSource.Operation.OnCompletion(
    procedure
    begin
      LDone := True;
    end);
  Check(not LDone, 'completed operation: no callback inside OnCompletion');
  Check(PumpUntil(function: Boolean begin Result := LDone; end), 'completed operation: callback run by the main thread loop');

  LSource := TAsyncTaskCompletionSource<Integer>.Create(TAsyncCallbackDispatchMode.dmQueue);
  LDone := False;
  LSource.Operation.OnCancelled(
    procedure
    begin
      LDone := True;
    end);
  LSource.Operation.Cancel;
  Check(not LDone, 'OnCancelled: no callback inside Cancel');
  Check(PumpUntil(function: Boolean begin Result := LDone; end), 'OnCancelled: callback run by the main thread loop');
  LSource.SetCancelled;
end;

function BusyPoolThreads: Integer;
var
  LStats: TThreadPoolStats;
begin
  LStats := TThreadPoolStats.Default;
  Result := LStats.WorkerThreadCount - LStats.IdleWorkerThreadCount;
end;

procedure TestTimersHoldNoPoolThread;
const
  DELAY_COUNT = 20;
var
  LDelays: TArray<IAsyncOperation>;
  LToken: IAsyncOperation;
  LTimed: IAsyncOperation<Integer>;
  LGate: TEvent;
  LBase, LBusy, I: Integer;
begin
  LGate := TEvent.Create;
  try
    Sleep(200); // the tasks of the previous tests go idle
    LBase := BusyPoolThreads;
    SetLength(LDelays, DELAY_COUNT);
    for I := 0 to DELAY_COUNT - 1 do
      LDelays[I] := TAsyncCore.Delay(10000, TAsyncCallbackDispatchMode.dmInline);
    LToken := TAsyncCore.CreateCancellationTokenWithTimeout(10000);
    LTimed := TAsyncCore.RunWithTimeout<Integer>(
      function(const AOp: IAsyncOperation): Integer
      begin
        LGate.WaitFor(10000);
        Result := 1;
      end, 10000, TAsyncCallbackDispatchMode.dmInline);
    Sleep(300);
    LBusy := BusyPoolThreads - LBase;
    Check(LBusy <= 1, Format('%d delays, a token and RunWithTimeout keep %d pool threads busy (only the task may)',
      [DELAY_COUNT, LBusy]));
  finally
    for I := 0 to High(LDelays) do
      LDelays[I].Cancel;
    if Assigned(LToken) then
      LToken.Cancel;
    LGate.SetEvent;
    for I := 0 to High(LDelays) do
      LDelays[I].WaitForCompletion(5000);
    if Assigned(LToken) then
      LToken.WaitForCompletion(5000);
    if Assigned(LTimed) then
      LTimed.WaitForCompletion(5000);
    LGate.Free;
  end;
end;

procedure TestTimersRaiseNothing;
var
  LOldProc: function(P: PExceptionRecord): Pointer;
  LDelay, LToken: IAsyncOperation;
  LTimed: IAsyncOperation<Integer>;
begin
  Sleep(100); // the tasks of the previous tests have ended
  LOldProc := Exception.GetExceptionStackInfoProc;
  GRaised := 0;
  Exception.GetExceptionStackInfoProc := CountRaise;
  try
    LDelay := TAsyncCore.Delay(10000, TAsyncCallbackDispatchMode.dmInline);
    Sleep(50);
    LDelay.Cancel;
    Check(LDelay.WaitForCompletion(3000) = TAsyncOperationState.Cancelled, 'Delay cancelled');

    LToken := TAsyncCore.CreateCancellationTokenWithTimeout(10000);
    Sleep(50);
    LToken.Cancel;
    Check(LToken.WaitForCompletion(3000) = TAsyncOperationState.Cancelled, 'timeout token cancelled');

    LTimed := TAsyncCore.RunWithTimeout<Integer>(
      function(const AOp: IAsyncOperation): Integer
      begin
        Sleep(50);
        Result := 1;
      end, 10000, TAsyncCallbackDispatchMode.dmInline);
    Check(LTimed.WaitForResult(3000) = 1, 'RunWithTimeout completed before the timeout');

    Sleep(200); // a woken timer would raise here
    Check(GRaised = 0, Format('no exception raised (%d)', [GRaised]));
  finally
    Exception.GetExceptionStackInfoProc := LOldProc;
  end;
end;

procedure LinkProbe(const AInner, AToken: IAsyncOperation; AReleased: PBoolean);
var
  LProbe: IAsyncOperation;
begin
  LProbe := TProbeOperation.Create(AInner, AReleased);
  TAsyncCore.LinkCancellationToken(LProbe, AToken);
end;

procedure TestLinkReleasesOperation;
var
  LSource: IAsyncTaskCompletionSource;
  LToken: IAsyncOperation;
  LReleased: Boolean;
begin
  LReleased := False;
  LSource := TAsyncTaskCompletionSource.Create(TAsyncCallbackDispatchMode.dmInline);
  LToken := TAsyncCore.CreateCancellationTokenWithTimeout(3000);
  LinkProbe(LSource.Operation, LToken, @LReleased);
  Check(not LReleased, 'the link keeps the pending operation');
  LSource.SetResult;
  Check(PumpUntil(function: Boolean begin Result := LReleased; end, 1000),
    'the operation is released when it completes, not when the token expires');
  Check(LToken.State = TAsyncOperationState.Running, 'the token is still pending');
  LToken.Cancel;
  Check(LToken.WaitForCompletion(3000) = TAsyncOperationState.Cancelled, 'token cancelled');
  PumpUntil(function: Boolean begin Result := LReleased; end); // the probe writes to this frame
end;

procedure TestTimeoutTokenDispatchMode;
var
  LEvent: TEvent;
  LThread: TThreadID;
  LToken: IAsyncOperation;
  LCalled: Boolean;
begin
  LEvent := TEvent.Create;
  LThread := MainThreadID;
  try
    LToken := TAsyncCore.CreateCancellationTokenWithTimeout(50, TAsyncCallbackDispatchMode.dmInline);
    LToken.OnCompletion(
      procedure
      begin
        LThread := TThread.Current.ThreadID;
        LEvent.SetEvent;
      end);
    Check(WaitWithoutMainThread(LEvent, 3000), 'dmInline: the token expires without the main thread');
    Check(LThread <> MainThreadID, 'on a pool thread');
    Check(LToken.State = TAsyncOperationState.Completed, 'state Completed');
  finally
    PumpUntil(function: Boolean begin Result := IsSignaled(LEvent); end);
    LEvent.Free;
  end;

  LCalled := False;
  LThread := 0;
  TAsyncCore.CreateCancellationTokenWithTimeout(50).OnCompletion(
    procedure
    begin
      LThread := TThread.Current.ThreadID;
      LCalled := True;
    end);
  Check(PumpUntil(function: Boolean begin Result := LCalled; end) and (LThread = MainThreadID),
    'default: callbacks on the main thread');
end;

procedure TestTimerDisposal;
const
  MANY = 1000;
var
  LBase, I: Integer;
  LDelay, LToken: IAsyncOperation;
  LDelays: TArray<IAsyncOperation>;
  LTimed: IAsyncOperation<Integer>;
begin
  LBase := TAsyncCore.PendingTimerCount;

  LDelay := TAsyncCore.Delay(10000, TAsyncCallbackDispatchMode.dmInline);
  Check(TAsyncCore.PendingTimerCount = LBase + 1, 'Delay: one timer');
  LDelay.Cancel;
  Check(TAsyncCore.PendingTimerCount = LBase, 'Delay: Cancel disposes the timer');
  Check(LDelay.State = TAsyncOperationState.Cancelled, 'Delay: cancelled at once');

  LDelay := TAsyncCore.Delay(20, TAsyncCallbackDispatchMode.dmInline);
  Check(LDelay.WaitForCompletion(3000) = TAsyncOperationState.Completed, 'Delay: completed');
  Check(TAsyncCore.PendingTimerCount = LBase, 'Delay: no timer once fired');

  LTimed := TAsyncCore.RunWithTimeout<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      Sleep(20);
      Result := 1;
    end, 10000, TAsyncCallbackDispatchMode.dmInline);
  Check(TAsyncCore.PendingTimerCount = LBase + 1, 'RunWithTimeout: one timer');
  Check(LTimed.WaitForResult(3000) = 1, 'RunWithTimeout: completed');
  Check(TAsyncCore.PendingTimerCount = LBase, 'RunWithTimeout: the task disposes the timer');

  LTimed := TAsyncCore.RunWithTimeout<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      while not AOp.IsCancellationRequested do
        Sleep(5);
      Result := 0;
    end, 10000, TAsyncCallbackDispatchMode.dmInline);
  LTimed.Cancel;
  Check(TAsyncCore.PendingTimerCount = LBase, 'RunWithTimeout: Cancel disposes the timer');

  LTimed := TAsyncCore.RunWithTimeout<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      while not AOp.IsCancellationRequested do
        Sleep(5);
      Result := 0;
    end, 30, TAsyncCallbackDispatchMode.dmInline);
  Check(LTimed.WaitForCompletion(3000) = TAsyncOperationState.Faulted, 'RunWithTimeout: timed out');
  Check(TAsyncCore.PendingTimerCount = LBase, 'RunWithTimeout: no timer once fired');

  LToken := TAsyncCore.CreateCancellationTokenWithTimeout(10000, TAsyncCallbackDispatchMode.dmInline);
  Check(TAsyncCore.PendingTimerCount = LBase + 1, 'token: one timer');
  LToken.Cancel;
  Check(TAsyncCore.PendingTimerCount = LBase, 'token: Cancel disposes the timer');

  SetLength(LDelays, MANY);
  for I := 0 to MANY - 1 do
    LDelays[I] := TAsyncCore.Delay(10000 + Cardinal(I mod 7), TAsyncCallbackDispatchMode.dmInline);
  Check(TAsyncCore.PendingTimerCount = LBase + MANY, Format('%d delays: %d timers', [MANY, MANY]));
  for I := MANY - 1 downto 0 do
    LDelays[I].Cancel;
  Check(TAsyncCore.PendingTimerCount = LBase, Format('%d delays cancelled: no timer left', [MANY]));
  for I := 0 to MANY - 1 do
    LDelays[I].WaitForCompletion(3000);
end;

procedure TestLinkCancellationToken;
var
  LBase: Integer;
  LOp: IAsyncOperation<Integer>;
  LToken: IAsyncOperation;
  LSource, LOther: IAsyncTaskCompletionSource;
begin
  LBase := TAsyncCore.PendingTimerCount;

  LOp := RunUntilCancelled;
  LToken := TAsyncCore.CreateCancellationTokenWithTimeout(50, TAsyncCallbackDispatchMode.dmInline);
  TAsyncCore.LinkCancellationToken(LOp, LToken);
  Check(LOp.WaitForCompletion(3000) = TAsyncOperationState.Cancelled, 'an expired token cancels the operation');
  Check(TAsyncCore.PendingTimerCount = LBase, 'no timer left');

  LSource := TAsyncTaskCompletionSource.Create(TAsyncCallbackDispatchMode.dmInline);
  LToken := TAsyncCore.CreateCancellationTokenWithTimeout(10000, TAsyncCallbackDispatchMode.dmInline);
  TAsyncCore.LinkCancellationToken(LSource.Operation, LToken);
  LToken.Cancel;
  Check(TAsyncCore.PendingTimerCount = LBase, 'a cancelled token disposes its timer');
  Sleep(50);
  Check(not LSource.Operation.IsCancellationRequested, 'a cancelled token does not cancel the operation');
  LSource.SetResult;

  LToken := TAsyncCore.CreateCancellationTokenWithTimeout(0, TAsyncCallbackDispatchMode.dmInline);
  LToken.WaitForCompletion(3000);
  LSource := TAsyncTaskCompletionSource.Create(TAsyncCallbackDispatchMode.dmInline);
  TAsyncCore.LinkCancellationToken(LSource.Operation, LToken);
  Check(LSource.Operation.IsCancellationRequested, 'a token already expired cancels at once');
  LSource.SetCancelled;

  // One token, two operations: the one that completes first does not unlink the other
  LToken := TAsyncCore.CreateCancellationTokenWithTimeout(100, TAsyncCallbackDispatchMode.dmInline);
  LSource := TAsyncTaskCompletionSource.Create(TAsyncCallbackDispatchMode.dmInline);
  LOther := TAsyncTaskCompletionSource.Create(TAsyncCallbackDispatchMode.dmInline);
  TAsyncCore.LinkCancellationToken(LSource.Operation, LToken);
  TAsyncCore.LinkCancellationToken(LOther.Operation, LToken);
  LSource.SetResult;
  Check(SpinUntil(function: Boolean begin Result := LOther.Operation.IsCancellationRequested; end, 3000),
    'the token still cancels the other operation');
  Check(not LSource.Operation.IsCancellationRequested, 'the completed operation is not cancelled');
  LOther.SetCancelled;
  Check(TAsyncCore.PendingTimerCount = LBase, 'no timer left at the end');
end;

var
  GLeftAtShutdown: Boolean = False;

// Left pending on purpose: the timer thread releases them at shutdown, the leak report must stay empty
procedure TestPendingTimersAtShutdown;
var
  LSource: IAsyncTaskCompletionSource;
  LBase: Integer;
begin
  LBase := TAsyncCore.PendingTimerCount;
  TAsyncCore.Delay(INFINITE).OnCompletion(
    procedure
    begin
      GLeftAtShutdown := True;
    end);
  TAsyncCore.Delay(600000, TAsyncCallbackDispatchMode.dmInline);
  LSource := TAsyncTaskCompletionSource.Create(TAsyncCallbackDispatchMode.dmInline);
  TAsyncCore.LinkCancellationToken(LSource.Operation, TAsyncCore.CreateCancellationTokenWithTimeout(600000));
  LSource.SetResult;
  // Waits for its next attempt: no pool thread may keep the program from ending
  TAsyncCore.RunWithRetry<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      raise Exception.Create('transient');
    end, 1, 600000, TBackoffStrategy.Fixed, 600000, nil, TAsyncCallbackDispatchMode.dmInline);
  Check(SpinUntil(function: Boolean begin Result := TAsyncCore.PendingTimerCount >= LBase + 4; end),
    'four timers left pending, one of RunWithRetry');
  Check(not GLeftAtShutdown, 'not fired');
end;

procedure TestDelayInfinite;
var
  LDelay: IAsyncOperation;
begin
  LDelay := TAsyncCore.Delay(INFINITE, TAsyncCallbackDispatchMode.dmInline);
  Sleep(50);
  Check(LDelay.State = TAsyncOperationState.Running, 'Delay(INFINITE) waits');
  LDelay.Cancel;
  Check(LDelay.WaitForCompletion(3000) = TAsyncOperationState.Cancelled, 'Delay(INFINITE) cancelled');
end;

procedure TestRetryExhausted;
var
  LOp: IAsyncOperation<Integer>;
  LOperation: IAsyncOperation;
  LDone: TEvent;
  LAttempts, LUnhandledCode, I: Integer;
  LSeen: array[0..2] of Pointer;
  LSame: Boolean;
  LError: Exception;
begin
  LDone := TEvent.Create;
  LAttempts := 0;
  LUnhandledCode := 0;
  FillChar(LSeen, SizeOf(LSeen), 0);
  TAsyncCore.OnUnhandledError :=
    procedure(const E: Exception)
    begin
      if E is ETestFieldException then
        LUnhandledCode := ETestFieldException(E).Code;
      LDone.SetEvent;
    end;
  try
    LOp := TAsyncCore.RunWithRetry<Integer>(
      function(const AOp: IAsyncOperation): Integer
      var
        LAttempt: Integer;
      begin
        LAttempt := TInterlocked.Increment(LAttempts);
        if LAttempt <= Length(LSeen) then
          LSeen[LAttempt - 1] := Pointer(AOp);
        raise ETestFieldException.Create(LAttempt);
      end, 2, 10, TBackoffStrategy.Linear, 1000, nil, TAsyncCallbackDispatchMode.dmInline);

    Check(LOp.WaitForCompletion(5000) = TAsyncOperationState.Faulted, 'Faulted once the retries are exhausted');
    Check(LAttempts = 3, Format('AMaxRetries = 2: three attempts (%d)', [LAttempts]));
    LError := LOp.GetException;
    try
      Check((LError is ETestFieldException) and (LError.Message = 'Test error 3'), 'with the error of the last attempt');
    finally
      LError.Free;
    end;
    Check(WaitWithoutMainThread(LDone, 5000) and (LUnhandledCode = 3),
      'OnUnhandledError receives the original error, fields included');
    LOperation := LOp;
    LSame := True;
    for I := 0 to High(LSeen) do
      LSame := LSame and (LSeen[I] = Pointer(LOperation));
    Check(LSame, 'every attempt receives the operation returned by RunWithRetry');
  finally
    TAsyncCore.OnUnhandledError := nil;
    LDone.Free;
  end;
end;

procedure TestRetryCancelSemantics;
var
  LOp: IAsyncOperation<Integer>;
  LStarted, LRelease: TEvent;
  LAttempts: Integer;
  LError: Exception;
begin
  LStarted := TEvent.Create;
  LRelease := TEvent.Create;
  try
    LAttempts := 0;
    LOp := TAsyncCore.RunWithRetry<Integer>(
      function(const AOp: IAsyncOperation): Integer
      begin
        TInterlocked.Increment(LAttempts);
        raise EAsyncCancelException.Create;
      end, 3, 0, TBackoffStrategy.Fixed, 1000, nil, TAsyncCallbackDispatchMode.dmInline);
    Check(LOp.WaitForCompletion(5000) = TAsyncOperationState.Cancelled, 'EAsyncCancelException of the task: Cancelled');
    Sleep(50);
    Check(LAttempts = 1, 'EAsyncCancelException of the task: not retried');

    // The attempt runs until it ends: Cancel is cooperative
    LAttempts := 0;
    LOp := TAsyncCore.RunWithRetry<Integer>(
      function(const AOp: IAsyncOperation): Integer
      begin
        TInterlocked.Increment(LAttempts);
        LStarted.SetEvent;
        LRelease.WaitFor(5000);
        raise Exception.Create('aborted');
      end, 3, 0, TBackoffStrategy.Fixed, 1000, nil, TAsyncCallbackDispatchMode.dmInline);
    Check(WaitWithoutMainThread(LStarted, 5000), 'attempt started');
    LOp.Cancel;
    Check(LOp.State = TAsyncOperationState.Running, 'Cancel during an attempt: running until the attempt ends');
    LRelease.SetEvent;
    Check(LOp.WaitForCompletion(5000) = TAsyncOperationState.Cancelled, 'a failure after Cancel: Cancelled');
    Sleep(50);
    Check(LAttempts = 1, 'a failure after Cancel: not retried');

    LStarted.ResetEvent;
    LRelease.ResetEvent;
    LOp := TAsyncCore.RunWithRetry<Integer>(
      function(const AOp: IAsyncOperation): Integer
      begin
        LStarted.SetEvent;
        LRelease.WaitFor(5000);
        Result := 7;
      end, 3, 0, TBackoffStrategy.Fixed, 1000, nil, TAsyncCallbackDispatchMode.dmInline);
    Check(WaitWithoutMainThread(LStarted, 5000), 'attempt started');
    LOp.Cancel;
    LRelease.SetEvent;
    Check(LOp.WaitForResult(5000) = 7, 'a success after Cancel: Completed with the result');

    LAttempts := 0;
    LOp := TAsyncCore.RunWithRetry<Integer>(
      function(const AOp: IAsyncOperation): Integer
      begin
        TInterlocked.Increment(LAttempts);
        raise Exception.Create('transient');
      end, 3, 0, TBackoffStrategy.Fixed, 1000,
      function(const E: Exception): Boolean
      begin
        if Assigned(E) then
          raise EInvalidOpException.Create('predicate failure');
        Result := True;
      end, TAsyncCallbackDispatchMode.dmInline);
    Check(LOp.WaitForCompletion(5000) = TAsyncOperationState.Faulted, 'AShouldRetry raising: Faulted');
    LError := LOp.GetException;
    try
      Check((LError is EInvalidOpException) and (LError.Message = 'predicate failure'), 'with the error of AShouldRetry');
    finally
      LError.Free;
    end;
    Check(LAttempts = 1, 'AShouldRetry raising: not retried');
  finally
    LRelease.SetEvent;
    if Assigned(LOp) then
      LOp.WaitForCompletion(5000);
    LRelease.Free;
    LStarted.Free;
  end;
end;

function RetryWithProbe(AReleased: PBoolean; AAttempts: PInteger; AFailures: Integer;
  ADelay: Cardinal): IAsyncOperation<Integer>;
var
  LProbe: IReleaseProbe;
begin
  LProbe := TReleaseProbe.Create(AReleased);
  Result := TAsyncCore.RunWithRetry<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      LProbe.Touch;
      Result := TInterlocked.Increment(AAttempts^);
      if Result <= AFailures then
        raise Exception.Create('transient');
    end, 3, ADelay, TBackoffStrategy.Fixed, 30000, nil, TAsyncCallbackDispatchMode.dmInline);
end;

procedure TestRetryReleasesTask;
var
  LOp: IAsyncOperation<Integer>;
  LReleased: Boolean;
  LAttempts: Integer;
begin
  LReleased := False;
  LAttempts := 0;
  LOp := RetryWithProbe(@LReleased, @LAttempts, 1, 10);
  Check(LOp.WaitForResult(5000) = 2, 'completed after one retry');
  Check(SpinUntil(function: Boolean begin Result := LReleased; end),
    'the task is released once the operation has completed');

  LReleased := False;
  LAttempts := 0;
  LOp := RetryWithProbe(@LReleased, @LAttempts, 5, 30000);
  SpinUntil(function: Boolean begin Result := TInterlocked.CompareExchange(LAttempts, 0, 0) = 1; end);
  Sleep(50); // waiting for the next attempt
  LOp.Cancel;
  Check(LOp.WaitForCompletion(5000) = TAsyncOperationState.Cancelled, 'cancelled while waiting');
  Check(SpinUntil(function: Boolean begin Result := LReleased; end),
    'the task is released once Cancel has ended the wait');
  LOp := nil;
end;

// The task references its own operation: the cycle ends with the operation, the leak report stays empty
procedure TestRetryTaskReferencesItsOperation;
var
  LOp: IAsyncOperation<Integer>;
  LAttempts: Integer;
begin
  LAttempts := 0;
  LOp := TAsyncCore.RunWithRetry<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      if not Assigned(AOp) then
        LOp.Cancel; // never runs: it only captures LOp
      Result := TInterlocked.Increment(LAttempts);
      if Result = 1 then
        raise Exception.Create('transient');
    end, 1, 10, TBackoffStrategy.Fixed, 1000, nil, TAsyncCallbackDispatchMode.dmInline);
  Check(LOp.WaitForResult(5000) = 2, 'completed after one retry');
end;

procedure TestRetryWaitHoldsNoPoolThread;
const
  RETRY_COUNT = 20;
var
  LOps: TArray<IAsyncOperation<Integer>>;
  LAttempts, LBase, LBaseTimers, LBusy, LCancelled, I: Integer;
begin
  Sleep(200); // the tasks of the previous tests go idle
  LBase := BusyPoolThreads;
  LBaseTimers := TAsyncCore.PendingTimerCount;
  LAttempts := 0;
  SetLength(LOps, RETRY_COUNT);
  try
    for I := 0 to RETRY_COUNT - 1 do
      LOps[I] := TAsyncCore.RunWithRetry<Integer>(
        function(const AOp: IAsyncOperation): Integer
        begin
          TInterlocked.Increment(LAttempts);
          raise Exception.Create('transient');
        end, 1, 30000, TBackoffStrategy.Fixed, 30000, nil, TAsyncCallbackDispatchMode.dmInline);

    Check(SpinUntil(function: Boolean begin Result := TInterlocked.CompareExchange(LAttempts, 0, 0) = RETRY_COUNT; end,
      15000), Format('%d first attempts failed', [RETRY_COUNT]));
    Check(SpinUntil(function: Boolean begin Result := TAsyncCore.PendingTimerCount = LBaseTimers + RETRY_COUNT; end),
      Format('%d waits for the next attempt: %d timers', [RETRY_COUNT, TAsyncCore.PendingTimerCount - LBaseTimers]));
    // A pool thread goes idle a little after its task
    SpinUntil(function: Boolean begin Result := BusyPoolThreads - LBase <= 1; end);
    LBusy := BusyPoolThreads - LBase;
    Check(LBusy <= 1, Format('%d retries waiting for the next attempt keep %d pool threads busy', [RETRY_COUNT, LBusy]));
  finally
    for I := 0 to High(LOps) do
      if Assigned(LOps[I]) then
        LOps[I].Cancel;
    LCancelled := 0;
    for I := 0 to High(LOps) do
      if Assigned(LOps[I]) and (LOps[I].WaitForCompletion(5000) = TAsyncOperationState.Cancelled) then
        Inc(LCancelled);
    Check(LCancelled = RETRY_COUNT, Format('%d retries cancelled', [LCancelled]));
  end;
end;

procedure TestRetryCancelWait;
var
  LOldProc: function(P: PExceptionRecord): Pointer;
  LOp: IAsyncOperation<Integer>;
  LDone: TEvent;
  LAttempts, LBaseTimers, LRaised: Integer;
  LHandlerCalled: Boolean;
  LThread: TThreadID;
begin
  Sleep(100); // the tasks of the previous tests have ended
  LDone := TEvent.Create;
  LAttempts := 0;
  LHandlerCalled := False;
  LThread := MainThreadID;
  LBaseTimers := TAsyncCore.PendingTimerCount;
  LOldProc := Exception.GetExceptionStackInfoProc;
  GRaised := 0;
  Exception.GetExceptionStackInfoProc := CountRaise;
  try
    LOp := TAsyncCore.RunWithRetry<Integer>(
      function(const AOp: IAsyncOperation): Integer
      begin
        AOp.OnCancelled(
          procedure
          begin
            LHandlerCalled := True;
          end);
        TInterlocked.Increment(LAttempts);
        raise ETestFieldException.Create(1);
      end, 3, 30000, TBackoffStrategy.Fixed, 30000, nil, TAsyncCallbackDispatchMode.dmInline);
    LOp.OnCompletion(
      procedure
      begin
        LThread := TThread.Current.ThreadID;
        LDone.SetEvent;
      end);

    Check(SpinUntil(function: Boolean begin Result := TAsyncCore.PendingTimerCount = LBaseTimers + 1; end),
      'the wait for the next attempt is a timer');
    SpinUntil(function: Boolean begin Result := TInterlocked.CompareExchange(LAttempts, 0, 0) = 1; end);
    Sleep(100); // the failed attempt has ended
    LRaised := GRaised;
    LOp.Cancel;
    Check(LOp.State = TAsyncOperationState.Cancelled, 'Cancel ends the operation at once');
    Check(TAsyncCore.PendingTimerCount = LBaseTimers, 'Cancel disposes the timer');
    Check(LHandlerCalled, 'the OnCancelled of the task runs');
    Check(WaitWithoutMainThread(LDone, 5000), 'the completion callbacks run');
    Check(LThread <> MainThreadID, 'on a pool thread, not inside Cancel');
    Sleep(200); // a late attempt or exception would show up here
    Check(LRaised = 1, 'the failed attempt raised its exception');
    Check(GRaised = LRaised, Format('the cancellation raises no exception (%d)', [GRaised - LRaised]));
    Check(LAttempts = 1, 'no further attempt');
  finally
    Exception.GetExceptionStackInfoProc := LOldProc;
    PumpUntil(function: Boolean begin Result := IsSignaled(LDone); end);
    LDone.Free;
  end;
end;

type
  TRaceOutcome = (roCompleted, roCancelled, roFaulted, roInconsistent);

  // Runs the other side of every race: no thread start between the two sides
  TRacer = class(TThread)
  private
    FWork: TProc;
    FRound: Integer;
    FArrived: Integer;
    FDone: Integer;
  protected
    procedure Execute; override;
  public
    procedure Race(const AOther, ALocal: TProc);
    procedure Stop;
  end;

var
  GRaceCallbacks: Integer = 0;
  GRacer: TRacer;

procedure TRacer.Execute;
var
  LRound: Integer;
begin
  LRound := 0;
  while True do
  begin
    while TInterlocked.CompareExchange(FRound, 0, 0) = LRound do
      TThread.Yield;
    LRound := TInterlocked.CompareExchange(FRound, 0, 0);
    if Terminated then
      Exit;
    // Spin barrier: both sides start together
    TInterlocked.Increment(FArrived);
    while TInterlocked.CompareExchange(FArrived, 0, 0) < 2 do
      ;
    try
      FWork();
    except
      // Reported by the checks of the race
    end;
    TInterlocked.Exchange(FDone, 1);
  end;
end;

procedure TRacer.Race(const AOther, ALocal: TProc);
begin
  FWork := AOther;
  FArrived := 0;
  FDone := 0;
  TInterlocked.Increment(FRound); // publishes the round
  TInterlocked.Increment(FArrived);
  while TInterlocked.CompareExchange(FArrived, 0, 0) < 2 do
    ;
  ALocal();
  while TInterlocked.CompareExchange(FDone, 0, 0) = 0 do
    TThread.Yield;
  FWork := nil;
end;

procedure TRacer.Stop;
begin
  Terminate;
  TInterlocked.Increment(FRound);
  WaitFor;
end;

// Burns a few microseconds: shifts the cancellation against the completion
procedure Spin(ACount: Integer);
var
  I: Integer;
  LSink: Integer;
begin
  LSink := 0;
  for I := 1 to ACount * 50 do
    LSink := TInterlocked.Increment(LSink);
end;

// Runs AOther on the racer thread and ALocal on the calling thread, released together.
// The skew of the race varies with AValue: either side may start a little later
procedure Race(AValue: Integer; const AOther, ALocal: TProc);
var
  LSkew: Integer;
begin
  LSkew := AValue mod 33 - 16;
  GRacer.Race(
    procedure
    begin
      if LSkew < 0 then
        Spin(-LSkew);
      AOther();
    end,
    procedure
    begin
      if LSkew > 0 then
        Spin(LSkew);
      ALocal();
    end);
end;

// Final state, callback counted exactly once, result or error consistent with the state
function OutcomeOf(const AOp: IAsyncOperation; ACalls: PInteger; AAllowFaulted: Boolean): TRaceOutcome;
var
  LState: TAsyncOperationState;
begin
  // Not WaitForCompletion: on the main thread it serves CheckSynchronize in 10 ms slices
  if not SpinUntil(
    function: Boolean
    begin
      Result := AOp.State in [TAsyncOperationState.Completed, TAsyncOperationState.Faulted,
        TAsyncOperationState.Cancelled];
    end) then
    Exit(roInconsistent);
  LState := AOp.State;
  if not SpinUntil(function: Boolean begin Result := TInterlocked.CompareExchange(ACalls^, 0, 0) >= 1; end) or
    (ACalls^ <> 1) then
    Exit(roInconsistent);
  case LState of
    TAsyncOperationState.Completed:
      Result := roCompleted;
    TAsyncOperationState.Cancelled:
      Result := roCancelled;
    TAsyncOperationState.Faulted:
      if AAllowFaulted then
        Result := roFaulted
      else
        Result := roInconsistent;
  else
    Result := roInconsistent;
  end;
end;

function ValueOutcome(const AOp: IAsyncOperation<Integer>; AExpected: Integer; ACalls: PInteger;
  AAllowFaulted: Boolean = False): TRaceOutcome;
var
  LValue: Integer;
  LError: Exception;
begin
  Result := OutcomeOf(AOp, ACalls, AAllowFaulted);
  if (Result = roCompleted) and not (AOp.TryGetResult(LValue) and (LValue = AExpected)) then
    Result := roInconsistent;
  if Result = roFaulted then
  begin
    LError := AOp.GetException;
    try
      if not (LError is EAsyncTimeoutException) then
        Result := roInconsistent;
    finally
      LError.Free;
    end;
  end;
end;

function RaceCompletionSource(AValue: Integer): TRaceOutcome;
var
  LSource: IAsyncTaskCompletionSource<Integer>;
  LCalls, LWins: Integer;
begin
  LCalls := 0;
  LWins := 0;
  LSource := TAsyncTaskCompletionSource<Integer>.Create(TAsyncCallbackDispatchMode.dmInline);
  LSource.Operation.OnCompletion(
    procedure
    begin
      TInterlocked.Increment(LCalls);
      TInterlocked.Increment(GRaceCallbacks);
    end);
  Race(AValue,
    procedure
    begin
      if LSource.TrySetResult(AValue) then
        TInterlocked.Increment(LWins);
    end,
    procedure
    begin
      if LSource.TrySetCancelled then
        TInterlocked.Increment(LWins);
    end);
  Result := ValueOutcome(LSource.Operation, AValue, @LCalls);
  if LWins <> 1 then
    Result := roInconsistent;
end;

function RaceFromOperation(AValue: Integer): TRaceOutcome;
var
  LSource: IAsyncTaskCompletionSource<Integer>;
  LOp: IAsyncOperation<Integer>;
  LSuccess, LFinally: Integer;
begin
  LSuccess := 0;
  LFinally := 0;
  LSource := TAsyncTaskCompletionSource<Integer>.Create(TAsyncCallbackDispatchMode.dmInline);
  LSource.Operation.OnCancelled(
    procedure
    begin
      LSource.TrySetCancelled;
    end);
  LOp := TAsyncCore.FromOperation<Integer>(LSource.Operation)
    .DispatchMode(TAsyncCallbackDispatchMode.dmInline)
    .OnSuccess(
      procedure(const AResult: Integer)
      begin
        TInterlocked.Increment(LSuccess);
      end)
    .OnFinally(
      procedure
      begin
        TInterlocked.Increment(LFinally);
        TInterlocked.Increment(GRaceCallbacks);
      end)
    .Run;
  Race(AValue,
    procedure
    begin
      LSource.TrySetResult(AValue);
    end,
    procedure
    begin
      LOp.Cancel;
    end);
  Result := ValueOutcome(LOp, AValue, @LFinally);
  if (Result = roCompleted) <> (LSuccess = 1) then
    Result := roInconsistent;
end;

function RaceWhenAny(AValue: Integer): TRaceOutcome;
var
  LSource: IAsyncTaskCompletionSource<Integer>;
  LAny: IAsyncOperation<Integer>;
  LCalls: Integer;
begin
  LCalls := 0;
  LSource := TAsyncTaskCompletionSource<Integer>.Create(TAsyncCallbackDispatchMode.dmInline);
  LAny := TAsyncCore.WhenAny<Integer>([LSource.Operation], TAsyncCallbackDispatchMode.dmInline);
  LAny.OnCompletion(
    procedure
    begin
      TInterlocked.Increment(LCalls);
      TInterlocked.Increment(GRaceCallbacks);
    end);
  Race(AValue,
    procedure
    begin
      LSource.TrySetResult(AValue);
    end,
    procedure
    begin
      LAny.Cancel;
    end);
  Result := ValueOutcome(LAny, AValue, @LCalls);
end;

function RaceContinueWith(AValue: Integer): TRaceOutcome;
var
  LSource: IAsyncTaskCompletionSource<Integer>;
  LContinued: IAsyncOperation<Integer>;
  LCalls: Integer;
begin
  LCalls := 0;
  LSource := TAsyncTaskCompletionSource<Integer>.Create(TAsyncCallbackDispatchMode.dmInline);
  LContinued := TAsyncCore.ContinueWith<Integer, Integer>(LSource.Operation,
    function(const AResult: Integer): Integer
    begin
      Result := AResult * 2;
    end, TAsyncCallbackDispatchMode.dmInline);
  LContinued.OnCompletion(
    procedure
    begin
      TInterlocked.Increment(LCalls);
      TInterlocked.Increment(GRaceCallbacks);
    end);
  Race(AValue,
    procedure
    begin
      LSource.TrySetResult(AValue);
    end,
    procedure
    begin
      // The continuation has more to run than Cancel: every other race Cancel starts later,
      // so both outcomes come up
      if Odd(AValue) then
        Spin((AValue mod 64) * 8);
      LContinued.Cancel;
    end);
  Result := ValueOutcome(LContinued, AValue * 2, @LCalls);
end;

function RaceRun(AValue: Integer): TRaceOutcome;
var
  LOp: IAsyncOperation<Integer>;
  LSuccess, LFinally: Integer;
begin
  LSuccess := 0;
  LFinally := 0;
  LOp := TAsyncCore.Run<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      Result := AValue;
    end,
    procedure(const AResult: Integer)
    begin
      TInterlocked.Increment(LSuccess);
    end,
    nil,
    procedure
    begin
      TInterlocked.Increment(LFinally);
      TInterlocked.Increment(GRaceCallbacks);
    end,
    TAsyncCallbackDispatchMode.dmInline);
  Spin(AValue mod 16);
  LOp.Cancel;
  Result := ValueOutcome(LOp, AValue, @LFinally);
  if (Result = roCompleted) <> (LSuccess = 1) then
    Result := roInconsistent;
end;

function RaceDelay(AValue: Integer): TRaceOutcome;
var
  LDelay: IAsyncOperation;
  LCalls: Integer;
begin
  LCalls := 0;
  LDelay := TAsyncCore.Delay(0, TAsyncCallbackDispatchMode.dmInline);
  LDelay.OnCompletion(
    procedure
    begin
      TInterlocked.Increment(LCalls);
      TInterlocked.Increment(GRaceCallbacks);
    end);
  Spin(AValue mod 64);
  LDelay.Cancel;
  Result := OutcomeOf(LDelay, @LCalls, False);
end;

function RaceRunWithTimeout(AValue: Integer): TRaceOutcome;
var
  LTimed: IAsyncOperation<Integer>;
  LCalls: Integer;
begin
  LCalls := 0;
  // Task, timer and (every other time) Cancel race to end the operation
  LTimed := TAsyncCore.RunWithTimeout<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      Result := AValue;
    end, 0, TAsyncCallbackDispatchMode.dmInline);
  LTimed.OnCompletion(
    procedure
    begin
      TInterlocked.Increment(LCalls);
      TInterlocked.Increment(GRaceCallbacks);
    end);
  if Odd(AValue) then
  begin
    Spin(AValue mod 32);
    LTimed.Cancel;
  end;
  Result := ValueOutcome(LTimed, AValue, @LCalls, True);
end;

function RaceRetry(AValue: Integer): TRaceOutcome;
var
  LOp: IAsyncOperation<Integer>;
  LCalls, LAttempts, LValue: Integer;
  LDelay: Cardinal;
  LFailAlways: Boolean;
  LError: Exception;
begin
  LCalls := 0;
  LAttempts := 0;
  // The first attempt fails; the retry, after a zero, short or long wait, succeeds or (every fifth time) fails too
  case AValue mod 3 of
    0: LDelay := 0;
    1: LDelay := 1;
  else
    LDelay := 10000;
  end;
  LFailAlways := AValue mod 5 = 0;
  LOp := TAsyncCore.RunWithRetry<Integer>(
    function(const AOp: IAsyncOperation): Integer
    begin
      if (TInterlocked.Increment(LAttempts) = 1) or LFailAlways then
        raise ETestFieldException.Create(AValue);
      Result := AValue;
    end, 1, LDelay, TBackoffStrategy.Fixed, 10000, nil, TAsyncCallbackDispatchMode.dmInline);
  LOp.OnCompletion(
    procedure
    begin
      TInterlocked.Increment(LCalls);
      TInterlocked.Increment(GRaceCallbacks);
    end);
  // Odd: Cancel races the timer of the wait and the retry, with a wider skew; even: also the first attempt
  if Odd(AValue) then
  begin
    SpinUntil(function: Boolean begin Result := TInterlocked.CompareExchange(LAttempts, 0, 0) > 0; end);
    Spin((AValue mod 64) * 8);
  end
  else
    Spin(AValue mod 64);
  LOp.Cancel;

  Result := OutcomeOf(LOp, @LCalls, True);
  // A long wait always ends cancelled: the timer never fires
  case Result of
    roCompleted:
      if LFailAlways or (LDelay = 10000) or (LAttempts <> 2) or not (LOp.TryGetResult(LValue) and (LValue = AValue)) then
        Result := roInconsistent;
    roFaulted:
      begin
        LError := LOp.GetException;
        try
          if not LFailAlways or (LDelay = 10000) or (LAttempts <> 2) or not (LError is ETestFieldException) then
            Result := roInconsistent;
        finally
          LError.Free;
        end;
      end;
    roCancelled:
      if LAttempts > 2 then
        Result := roInconsistent;
  end;
end;

procedure RunRaces(const AName: string; AIterations: Integer; const ARace: TFunc<Integer, TRaceOutcome>);
var
  LCounts: array[TRaceOutcome] of Integer;
  LStopwatch: TStopwatch;
  I: Integer;
begin
  FillChar(LCounts, SizeOf(LCounts), 0);
  GRaceCallbacks := 0;
  LStopwatch := TStopwatch.StartNew;
  for I := 1 to AIterations do
    Inc(LCounts[ARace(I)]);
  Sleep(50); // a duplicate callback would show up here
  Check((LCounts[roInconsistent] = 0) and (GRaceCallbacks = AIterations),
    Format('%s: one outcome, callback once, in %d races (%d completed, %d cancelled, %d timed out, %d inconsistent, %d callbacks, %d ms)',
    [AName, AIterations, LCounts[roCompleted], LCounts[roCancelled], LCounts[roFaulted], LCounts[roInconsistent],
    GRaceCallbacks, LStopwatch.ElapsedMilliseconds]));
  // Races that always end the same way test one path only
  Check((LCounts[roCompleted] > 0) and (LCounts[roCancelled] > 0),
    Format('%s: both outcomes reached (%d completed, %d cancelled)', [AName, LCounts[roCompleted], LCounts[roCancelled]]));
end;

procedure TestCancelRacesCompletion;
var
  LBase: Integer;
begin
  GRacer := TRacer.Create(False);
  try
    RunRaces('completion source', 2000, RaceCompletionSource);
    RunRaces('FromOperation', 2000, RaceFromOperation);
    RunRaces('WhenAny', 2000, RaceWhenAny);
    RunRaces('ContinueWith', 2000, RaceContinueWith);
  finally
    GRacer.Stop;
    FreeAndNil(GRacer);
  end;
  RunRaces('Run', 2000, RaceRun);
  RunRaces('Delay', 2000, RaceDelay);
  RunRaces('RunWithTimeout', 2000, RaceRunWithTimeout);
  LBase := TAsyncCore.PendingTimerCount;
  RunRaces('RunWithRetry', 2000, RaceRetry);
  Check(SpinUntil(function: Boolean begin Result := TAsyncCore.PendingTimerCount <= LBase; end),
    'RunWithRetry: no timer left after the races');
end;

procedure RunTest(const AName: string; const ATest: TProc);
begin
  Writeln(AName);
  try
    ATest();
  except
    on E: Exception do
    begin
      Inc(GFailed);
      Writeln('  FAIL unexpected ', E.ClassName, ': ', E.Message);
    end;
  end;
end;

begin
  ReportMemoryLeaksOnShutdown := True;
  RunTest('OnError receives the original exception (dmSynchronize)', TestOnErrorSynchronize);
  RunTest('OnError receives the original exception (dmQueue)', TestOnErrorQueue);
  RunTest('WaitForResult and GetException copy the exception with its fields', TestWaitForResultRaisesFaithfulCopy);
  RunTest('Nested wait keeps the exception fields', TestNestedWaitKeepsFields);
  RunTest('Exception class without cloner', TestUnregisteredExceptionFallback);
  RunTest('Completion source keeps its operation alive', TestCompletionSourceKeepsOperationAlive);
  RunTest('Completion source errors', TestCompletionSourceErrors);
  RunTest('A user OnCancelled does not break Delay', TestUserOnCancelledKeepsDelayCancellable);
  RunTest('A failing OnSuccess does not change the state', TestFailingOnSuccessKeepsCompletedState);
  RunTest('dmQueue callbacks', TestCallbacksQueue);
  RunTest('RunWithRetry: Linear with zero delay', TestRetryLinearZeroDelay);
  RunTest('RunWithRetry: cancel during backoff', TestRetryCancelInterruptsBackoff);
  RunTest('RunWithRetry: AShouldRetry', TestRetryPredicate);
  RunTest('RunWithRetry: negative AMaxRetries', TestRetryNegativeMaxRetries);
  RunTest('WaitForCompletion timeout', TestWaitTimeoutAlwaysRaises);
  RunTest('WhenAll, WhenAny, ContinueWith', TestCombinators);
  RunTest('dmInline callbacks', TestInlineCallbacks);
  RunTest('Combinators without the main thread', TestCombinatorsWithoutMainThread);
  RunTest('Cancel on combinators', TestCombinatorCancel);
  RunTest('RunWithTimeout timeout', TestRunWithTimeoutRaisesTimeout);
  RunTest('RunWithTimeout dmInline: the timeout cancels the task without the main thread', TestRunWithTimeoutInlineCancelsTask);
  RunTest('RunWithTimeout dmQueue: the timeout does not block the timer thread', TestRunWithTimeoutQueueDoesNotBlockTimer);
  RunTest('RunWithTimeout dmInline: task error with OnUnhandledError', TestRunWithTimeoutInlineTaskError);
  RunTest('RunWithRetry: dispatch mode', TestRetryDispatchMode);
  RunTest('Delay: dispatch mode', TestDelayDispatchMode);
  RunTest('RunWithRetry, RunWithTimeout, Delay: default dispatch mode', TestDefaultDispatchModeUnchanged);
  RunTest('RunWithRetry: ExponentialJitter', TestRetryJitter);
  RunTest('RunWithRetry: retries exhausted', TestRetryExhausted);
  RunTest('RunWithRetry: cancellation of the task', TestRetryCancelSemantics);
  RunTest('RunWithRetry: the task is released', TestRetryReleasesTask);
  RunTest('RunWithRetry: a task referencing its operation', TestRetryTaskReferencesItsOperation);
  RunTest('Storage crypto exception copy', TestStorageCryptoExceptionClone);
  RunTest('FromOperation: result', TestFromOperationSuccess);
  RunTest('FromOperation: error', TestFromOperationError);
  RunTest('FromOperation: cancel', TestFromOperationCancel);
  RunTest('FromOperation: dmInline', TestFromOperationInline);
  RunTest('FromOperation: callbacks released', TestFromOperationReleasesCallbacks);
  RunTest('dmQueue: no callback inside Cancel on the main thread', TestQueueNotReentrant);
  RunTest('Timers hold no pool thread', TestTimersHoldNoPoolThread);
  RunTest('Timers raise no exception', TestTimersRaiseNothing);
  RunTest('RunWithRetry: the wait between attempts holds no pool thread', TestRetryWaitHoldsNoPoolThread);
  RunTest('RunWithRetry: Cancel during the wait', TestRetryCancelWait);
  RunTest('LinkCancellationToken releases a completed operation', TestLinkReleasesOperation);
  RunTest('Delay(INFINITE)', TestDelayInfinite);
  RunTest('CreateCancellationTokenWithTimeout: dispatch mode', TestTimeoutTokenDispatchMode);
  RunTest('Timers disposed', TestTimerDisposal);
  RunTest('LinkCancellationToken', TestLinkCancellationToken);
  RunTest('Cancel racing completion', TestCancelRacesCompletion);
  RunTest('Timers pending at shutdown', TestPendingTimersAtShutdown);

  Writeln;
  Writeln(Format('Passed: %d  Failed: %d', [GPassed, GFailed]));
  ExitCode := GFailed;
end.
