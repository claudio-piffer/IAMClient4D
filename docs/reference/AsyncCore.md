# Async.Core

Unit `Async.Core` (`src/Async.Core.pas`): promises and operations over the RTL thread pool, with callbacks on the main thread or on the completing thread, cancellation, waits with timeouts, combinators, retry, timeouts and delays. IAMClient4D uses it for every `*Async` method (they return `IAsyncPromise<T>` or `IAsyncVoidPromise`: see [Core.md](Core.md)); it depends only on the RTL and can be used alone. Changes from 2.x: [MIGRATION_3.0.md, section 7](../MIGRATION_3.0.md#7-asynccore).

The enumerations are scoped (`{$SCOPEDENUMS ON}`): write `TAsyncCallbackDispatchMode.dmInline`, `TAsyncOperationState.Completed`.

## Contents

- [Starting a task](#starting-a-task)
- [Promises](#promises)
- [Callback order](#callback-order)
- [Dispatch modes](#dispatch-modes)
- [Operations](#operations)
- [Waiting](#waiting)
- [Cancellation](#cancellation)
- [Errors](#errors)
- [Completion sources](#completion-sources)
- [Combinators](#combinators)
- [Retry](#retry)
- [Timeouts and delays](#timeouts-and-delays)
- [Exceptions](#exceptions)
- [Thread-safety and lifetime](#thread-safety-and-lifetime)

## Starting a task

`TAsyncCore` (sealed, class methods only) is the entry point.

| Method | Description |
|--------|-------------|
| `New<T>(ATask): IAsyncPromise<T>` | Promise for a function task; nothing runs until `Run` |
| `New(ATask): IAsyncVoidPromise` | Promise for a procedure task |
| `FromOperation<T>(AOperation): IAsyncPromise<T>` | Promise over an operation completed elsewhere (see [Completion sources](#completion-sources)). `nil` raises `EArgumentNilException` |
| `Run<T>(OnAsyncTask, OnSuccess = nil, OnError = nil, OnFinally = nil, ADispatchMode = dmSynchronize): IAsyncOperation<T>` | Starts at once, callbacks as parameters |
| `Run(OnAsyncTask, OnSuccess = nil, OnError = nil, OnFinally = nil, ADispatchMode = dmSynchronize): IAsyncOperation` | Same, procedure task |

The task runs on the RTL thread pool (`TTask.Run`) and receives its own operation, to check for cancellation:

| Type | Signature |
|------|-----------|
| `TAsyncCoreFunctionTask<T>` | `function(const AOperationController: IAsyncOperation): T` |
| `TAsyncCoreProcedureTask` | `procedure(const AOperationController: IAsyncOperation)` |
| `TAsyncCoreSuccessCallback<T>` | `procedure(const ATaskResult: T)` |
| `TAsyncCoreProcedureSuccessCallback` | `procedure` |
| `TAsyncCoreErrorCallback` | `procedure(const AException: Exception)` |
| `TAsyncCoreFinallyCallback`, `TAsyncCoreCancelledCallback` | `procedure` |
| `TAsyncCoreContinuationFunc<T, TResult>` | `function(const AValue: T): TResult` |
| `TAsyncCoreRetryPredicate` | `function(const AException: Exception): Boolean` |
| `TAsyncExceptionCloner` | `function(const ASource: Exception): Exception` |

## Promises

`IAsyncPromise<T>` and `IAsyncVoidPromise`: configure, then `Run`.

| Method | Description |
|--------|-------------|
| `OnSuccess(ACallback)` | Called with the result (`IAsyncVoidPromise`: without) |
| `OnError(ACallback)` | Called with the exception when the task faults |
| `OnFinally(ACallback)` | Called after every outcome: success, fault, cancellation |
| `DispatchMode(AMode)` | Thread of all the callbacks; default `dmSynchronize` |
| `Run` | Starts the task; returns `IAsyncOperation<T>` (`IAsyncVoidPromise`: `IAsyncOperation`) |

Each `On*` keeps one callback: a second call replaces the first. Every `Run` starts a new task. `Run` without a task raises `EArgumentNilException`.

<!-- snippet ver=3.0 kind=body ctx=async,ui -->
```delphi
var LOperation := TAsyncCore.New<Integer>(
  function(const AOperation: IAsyncOperation): Integer
  begin
    Result := 0;
    for var I := 1 to 1000 do
    begin
      if AOperation.IsCancellationRequested then
        raise EAsyncCancelException.Create; // ends as Cancelled
      Inc(Result, I);
    end;
  end)
  .OnSuccess(
    procedure(const AValue: Integer)
    begin
      ShowMessage('Sum: ' + AValue.ToString);
    end)
  .OnError(
    procedure(const AException: Exception)
    begin
      ShowMessage('Error: ' + AException.Message); // do not free or keep AException
    end)
  .OnFinally(
    procedure
    begin
      ShowMessage('Done'); // also after a cancellation
    end)
  .DispatchMode(TAsyncCallbackDispatchMode.dmQueue)
  .Run;

// e.g. from a Cancel button
LOperation.Cancel;
```

## Callback order

For a task started with `Run` or `New`:

| Outcome | Order |
|---------|-------|
| Completed | `OnSuccess`, `OnCompletion` callbacks, waiters released, `OnFinally` |
| Faulted | `OnError` (or `OnUnhandledError`), `OnCompletion` callbacks, waiters released, `OnFinally` |
| Cancelled | `OnCompletion` callbacks, waiters released, `OnFinally`. Neither `OnSuccess` nor `OnError` |

`OnCancelled` handlers run when `Cancel` is called, not when the state becomes Cancelled. A wait (`WaitForResult`, `WaitForCompletion`) can return before `OnFinally` has run, and, with `dmQueue`, before the queued callbacks have run.

## Dispatch modes

`TAsyncCallbackDispatchMode`:

| Mode | How | On the main thread |
|------|-----|--------------------|
| `dmSynchronize` (default) | `TThread.Synchronize`: the completing thread waits until the main thread has run the callback | Runs at once, inside the call that ends the operation (e.g. `Cancel` on a `WhenAll` result) |
| `dmQueue` | `TThread.ForceQueue`: queued to the main thread, the completing thread does not wait | Always queued, run at the next turn of the message loop: never inside `Cancel`, `TrySetResult` or `OnCompletion` |
| `dmInline` | Runs on the thread that completes the operation: a pool thread, or the thread that calls `Cancel` or `TrySetResult` | No main thread involved |

What to use:

| Application | Mode | Notes |
|-------------|------|-------|
| VCL, FMX | `dmSynchronize` or `dmQueue` | Callbacks may touch the UI. `dmQueue` does not hold pool threads while the UI is busy |
| Console, service, DMVC server, other code without a message loop | `dmInline` | Callbacks must be thread-safe and must not touch a UI |

Without a message loop, a `dmSynchronize` callback blocks its pool thread and a `dmQueue` callback never runs, unless the main thread calls `CheckSynchronize` or waits with `WaitForCompletion`/`WaitForResult` (which serve the queue). A `dmQueue` callback queued when the main thread no longer serves the queue (e.g. a `Cancel` during shutdown, in the `OnDestroy` of the main form or in a `finalization` section) never runs: end the operations while the message loop runs (e.g. in `OnClose`).

<!-- snippet ver=3.0 kind=body ctx=async -->
```delphi
// Console: OnSuccess on a pool thread, the main thread waits
var LOperation := TAsyncCore.Run<string>(
  function(const AOperation: IAsyncOperation): string
  begin
    Result := 'done';
  end,
  procedure(const AValue: string)
  begin
    Writeln('OnSuccess: ', AValue);
  end,
  nil, nil, TAsyncCallbackDispatchMode.dmInline);
try
  Writeln(LOperation.WaitForResult(5000));
except
  on E: EAsyncTimeoutException do
    Writeln('Still running after 5 s');
end;
```

## Operations

`IAsyncOperation`, returned by `Run` and by the other `TAsyncCore` methods. All members are thread-safe.

| Member | Description |
|--------|-------------|
| `Cancel` | Requests cancellation (see [Cancellation](#cancellation)). No effect on a final operation or a second time |
| `IsCancellationRequested: Boolean` | |
| `OnCancelled(ACallback)` | Several handlers allowed, dispatched with the mode of the operation. Already cancelled: dispatched at once. Already final without cancellation: never runs |
| `OnCompletion(ACallback)` | Called once the operation is final, whatever the outcome; already final: dispatched at once. Mode of the operation |
| `WaitForCompletion(ATimeout = INFINITE, ARaiseOnError = False): TAsyncOperationState` | See [Waiting](#waiting) |
| `State` / `GetState` | `TAsyncOperationState` |

`IAsyncOperation<T>` adds:

| Member | Description |
|--------|-------------|
| `WaitForResult(ATimeout = INFINITE): T` | See [Waiting](#waiting) |
| `TryWaitForResult(ATimeout; out AResult): Boolean` | Waits up to `ATimeout`; `False` when still running, faulted or cancelled. Never raises |
| `TryGetResult(out AResult): Boolean` | No wait; `True` only when Completed |
| `GetException: Exception` | A copy owned by the caller (free it), or `nil` when not faulted |

`TAsyncOperationState`: `Pending` (created, not started), `Running`, `Completed`, `Faulted`, `Cancelled`. The last three are final: an operation reaches one only once.

## Waiting

| Call | Completed | Faulted | Cancelled | Timeout |
|------|-----------|---------|-----------|---------|
| `WaitForCompletion(T)` | returns `Completed` | returns `Faulted` | returns `Cancelled` | `EAsyncTimeoutException` |
| `WaitForCompletion(T, True)` | returns `Completed` | raises a copy of the exception | returns `Cancelled` | `EAsyncTimeoutException` |
| `WaitForResult(T)` | the result | raises a copy of the exception | `EAsyncCancelException` | `EAsyncTimeoutException` |
| `TryWaitForResult(T, R)` | `True` | `False` | `False` | `False` |

The timeout is in milliseconds (`INFINITE` by default). On the main thread the wait serves `Synchronize` and `Queue` (`CheckSynchronize` in 10 ms slices), so `dmSynchronize` and `dmQueue` callbacks do not deadlock it; they run inside the wait. On other threads it blocks on an event. A timeout does not cancel the operation.

## Cancellation

Cancellation is a request. What it does depends on the operation:

| Operation | Effect of `Cancel` |
|-----------|--------------------|
| `Run`, `New` | Cooperative. Before the task starts: Cancelled without running it. While it runs: the task checks `IsCancellationRequested` and raises `EAsyncCancelException` (Cancelled). A task that returns normally ends Completed; another exception ends Faulted |
| `ContinueWith`, `WhenAll`, `WhenAny`, `RunWithTimeout` | Cancelled at once; forwarded to the operations it depends on |
| `Delay`, `CreateCancellationTokenWithTimeout` | Cancelled at once, timer disposed; callbacks on a pool thread, never inside `Cancel` |
| `RunWithRetry` | During an attempt: cooperative, as `Run`. During the wait between attempts: Cancelled at once, timer disposed, callbacks on a pool thread |
| `FromOperation` | Forwarded to the followed operation; ends when that one does |
| Completion source | Only `OnCancelled` handlers run: the producer ends the operation (e.g. `TrySetCancelled`) |

Cancelling never raises in the caller. `EAsyncCancelException` comes from `WaitForResult` on a cancelled operation, or from the task itself.

## Errors

- An exception raised by the task ends the operation Faulted. `OnError` receives the original object, owned by the operation: do not free it or keep it after the callback.
- **No `OnError`**: the fault goes to `TAsyncCore.OnUnhandledError`, when assigned, dispatched with the mode of the operation. This applies to `Run`, `New`, `FromOperation`, `RunWithRetry` and to the task of `RunWithTimeout` (even when the caller waits on the result). The completion sources and the results of `ContinueWith`, `WhenAll` and `WhenAny` do not report.
- **Exceptions raised by callbacks** (`OnSuccess`, `OnError`, `OnFinally`, `OnCompletion`, `OnCancelled`) never reach the dispatching thread and never change the state: they go to `OnUnhandledError`; without it, to `ApplicationHandleException` (VCL/FMX) when the callback ran on the main thread; otherwise they are dropped. An exception raised by `OnUnhandledError` itself is ignored.
- **Copies**: `WaitForResult`, `WaitForCompletion(..., True)` and `GetException` hand out copies, since the operation owns its exception. Without a registered cloner the copy keeps class, message and `HelpContext` only. `IAMClient4D.Exceptions` registers a cloner for `EIAM4DException`, so library exceptions keep all their fields.

| Member | Description |
|--------|-------------|
| `class property OnUnhandledError: TAsyncCoreErrorCallback` | Global handler. Runs on the thread of the callback (a pool thread with `dmInline`). Set it at startup |
| `RegisterExceptionCloner(AClass, ACloner)` | Copies of `AClass` and descendants; the most specific registered ancestor wins; `nil` removes the registration. A cloner that raises or returns `nil` falls back to the default copy. Register at startup |

<!-- snippet ver=3.0 kind=decl ctx=async -->
```delphi
type
  EServiceError = class(Exception)
  public
    Code: Integer;
  end;

procedure ConfigureAsyncErrors;
begin
  // Copies handed out by WaitForResult and GetException keep Code
  TAsyncCore.RegisterExceptionCloner(EServiceError,
    function(const ASource: Exception): Exception
    var
      LCopy: EServiceError;
    begin
      LCopy := EServiceError.Create(ASource.Message);
      LCopy.Code := EServiceError(ASource).Code;
      Result := LCopy;
    end);

  // Faults without OnError, and exceptions raised by callbacks
  TAsyncCore.OnUnhandledError :=
    procedure(const AException: Exception)
    begin
      Writeln(ErrOutput, AException.ClassName, ': ', AException.Message);
    end;
end;
```

## Completion sources

`TAsyncTaskCompletionSource<T>` (`IAsyncTaskCompletionSource<T>`) and `TAsyncTaskCompletionSource` (`IAsyncTaskCompletionSource`) turn a callback or event API into an operation. Thread-safe. Hold them through the interface.

| Member | Description |
|--------|-------------|
| `Create(ADispatchMode = dmQueue)` | Mode of the callbacks registered on `Operation` |
| `Operation` | The operation to hand out |
| `TrySetResult(AValue)` / `TrySetResult` | Completed; `False` when already final |
| `TrySetException(AException)` | Faulted. Takes ownership of `AException` in any case (freed when already final) |
| `TrySetCancelled` | Cancelled |
| `SetResult`, `SetException`, `SetCancelled` | As the `Try*` versions; `EAsyncException` when already final |

The callbacks of `Operation` are dispatched from the thread that calls `Try*`/`Set*`. To attach promise callbacks, wrap the operation with `FromOperation`: no thread is blocked while it waits, and a cancellation raises nothing.

<!-- snippet ver=3.0 kind=body ctx=async -->
```delphi
var LSource: IAsyncTaskCompletionSource<string> :=
  TAsyncTaskCompletionSource<string>.Create(TAsyncCallbackDispatchMode.dmInline);
// Cancel on the promise operation is forwarded here: the producer decides how to end it
LSource.Operation.OnCancelled(
  procedure
  begin
    LSource.TrySetCancelled;
  end);

TAsyncCore.FromOperation<string>(LSource.Operation)
  .OnSuccess(
    procedure(const AValue: string)
    begin
      Writeln('Received ', AValue);
    end)
  .DispatchMode(TAsyncCallbackDispatchMode.dmInline)
  .Run;

// Later, e.g. from an event handler
LSource.TrySetResult('value');
```

## Combinators

They need no main thread: their internal continuations run on the completing thread or on pool threads. `ADispatchMode` (default `dmSynchronize`) is the mode of the callbacks registered on the returned operation (`OnCompletion`, `OnCancelled`). The returned operation has no `OnSuccess`: use `FromOperation(...)`, `OnCompletion` with `TryGetResult`, or a wait.

| Method | Result |
|--------|--------|
| `ContinueWith<T, TResult>(AOperation, AContinuation, ADispatchMode)` | `AContinuation` runs on a pool thread with the result of `AOperation`. A faulted source gives a Faulted result (copy of the exception), a cancelled one a Cancelled result; `EAsyncCancelException` raised by the continuation gives Cancelled |
| `WhenAll<T>(AOperations, ADispatchMode)` | The results in the order of `AOperations`. The first fault (copy) or cancellation ends it at once; the other operations go on. No operations: completed with an empty array |
| `WhenAny<T>(AOperations, ADispatchMode)` | The outcome of the first operation that ends (result, fault or cancellation); the others go on. No operations: Faulted (`EAsyncException`) |

`Cancel` on the result cancels it at once and cancels the operations it depends on.

<!-- snippet ver=3.0 kind=body ctx=async -->
```delphi
var LA := TAsyncCore.Run<Integer>(
  function(const AOperation: IAsyncOperation): Integer
  begin
    Result := 1;
  end);
var LB := TAsyncCore.Run<Integer>(
  function(const AOperation: IAsyncOperation): Integer
  begin
    Result := 2;
  end);
var LSum := TAsyncCore.ContinueWith<TArray<Integer>, Integer>(
  TAsyncCore.WhenAll<Integer>([LA, LB], TAsyncCallbackDispatchMode.dmInline),
  function(const AValues: TArray<Integer>): Integer
  begin
    Result := 0;
    for var LValue in AValues do
      Inc(Result, LValue);
  end,
  TAsyncCallbackDispatchMode.dmInline);
Writeln(LSum.WaitForResult(10000)); // 3
```

## Retry

`RunWithRetry<T>(ATask, AMaxRetries = 3, AInitialDelay = 1000, ABackoffStrategy = Exponential, AMaxDelay = 30000, AShouldRetry = nil, ADispatchMode = dmSynchronize): IAsyncOperation<T>`

- One attempt plus up to `AMaxRetries` retries (0 = one attempt). `AMaxRetries` < 0 raises `EArgumentOutOfRangeException` at the call.
- Each attempt is a pool task; between attempts no thread waits, the shared timer thread serves the delay.
- A failed attempt is retried unless `AShouldRetry` returns `False`. Never retried: `EAsyncCancelException` (Cancelled), and any exception raised after `Cancel` (Cancelled). An exception raised by `AShouldRetry` ends the operation Faulted with it.
- When the retries are exhausted the operation is Faulted with the last exception.
- `ADispatchMode` is the mode of the returned operation, which is also the operation passed to `ATask`.

Delay before retry `n` (0 for the first retry), capped at `AMaxDelay`:

| `TBackoffStrategy` | Delay |
|--------------------|-------|
| `Fixed` | `AInitialDelay` |
| `Linear` | `AInitialDelay * (n + 1)` |
| `Exponential` | `AInitialDelay * 2^n` |
| `ExponentialJitter` | Exponential (capped), then random between 50% and 100% of it |

<!-- snippet ver=3.0 kind=body ctx=async -->
```delphi
var LOperation := TAsyncCore.RunWithRetry<string>(
  function(const AOperation: IAsyncOperation): string
  begin
    Result := 'status'; // e.g. an HTTP call that may fail
  end,
  3, 500, TBackoffStrategy.ExponentialJitter, 10000,
  function(const AException: Exception): Boolean
  begin
    Result := not (AException is EArgumentException); // not worth retrying
  end,
  TAsyncCallbackDispatchMode.dmInline);
Writeln(LOperation.WaitForResult);
```

## Timeouts and delays

One shared timer thread serves `Delay`, `RunWithTimeout`, `CreateCancellationTokenWithTimeout` and the waits of `RunWithRetry`; a fired timer runs its work on a pool thread. Timers still pending at unit finalization never fire: what they hold is released.

| Method | Description |
|--------|-------------|
| `RunWithTimeout<T>(ATask, ATimeoutMs, ADispatchMode = dmSynchronize)` | Runs `ATask`. After `ATimeoutMs`: Faulted with `EAsyncTimeoutException` (`Operation timed out after N ms`), and `Cancel` on the task, which should check `IsCancellationRequested`. Otherwise the outcome of the task (a fault as a copy). `ADispatchMode` applies to the result and to the task operation, whose `OnCancelled` handlers run on a pool thread at timeout: where the main thread does not serve `Synchronize`, use `dmInline` or `dmQueue` |
| `Delay(AMilliseconds, ADispatchMode = dmSynchronize): IAsyncOperation` | Completed after the delay; `INFINITE` never completes. A `Cancel` before completion always wins (Cancelled) |
| `CreateCancellationTokenWithTimeout(ATimeoutMs, ADispatchMode = dmSynchronize)` | A `Delay`, used as a token. Cancel it to dispose its timer earlier |
| `LinkCancellationToken(AOperation, AToken)` | When `AToken` completes (expires), calls `AOperation.Cancel`. A cancelled token does nothing. The link is dropped when either one ends; the token is not cancelled, since it may be linked to other operations. Nothing happens for a final `AOperation` |
| `PendingTimerCount: Integer` | Timers waiting in the timer thread. Diagnostics |

<!-- snippet ver=3.0 kind=body ctx=async -->
```delphi
var LOperation := TAsyncCore.RunWithTimeout<string>(
  function(const AOperation: IAsyncOperation): string
  begin
    while not AOperation.IsCancellationRequested do
      Sleep(50); // long work, checking for cancellation
    raise EAsyncCancelException.Create;
  end, 2000, TAsyncCallbackDispatchMode.dmInline);
try
  LOperation.WaitForResult;
except
  on E: EAsyncTimeoutException do
    Writeln(E.Message); // Operation timed out after 2000 ms
end;

// Completes after 1 s, callbacks on a pool thread
TAsyncCore.Delay(1000, TAsyncCallbackDispatchMode.dmInline).OnCompletion(
  procedure
  begin
    Writeln('One second later');
  end);
```

A timeout for any operation:

<!-- snippet ver=3.0 kind=body ctx=async -->
```delphi
var LOperation := TAsyncCore.Run(
  procedure(const AOperation: IAsyncOperation)
  begin
    while not AOperation.IsCancellationRequested do
      Sleep(50);
  end);
var LToken := TAsyncCore.CreateCancellationTokenWithTimeout(10000, TAsyncCallbackDispatchMode.dmInline);
TAsyncCore.LinkCancellationToken(LOperation, LToken); // Cancel after 10 s
```

## Exceptions

| Class | Raised by |
|-------|-----------|
| `EAsyncException` | Base class. Also: `Set*` on a completed source, an operation completed without a result, `WhenAny` with no operations |
| `EAsyncCancelException` | `WaitForResult` on a cancelled operation (`Asynchronous operation was cancelled`); raise it in a task to end it Cancelled |
| `EAsyncTimeoutException` | Waits that time out (`Operation timed out`), `RunWithTimeout` (`Operation timed out after N ms`) |

## Thread-safety and lifetime

- Operations and completion sources are thread-safe. A promise is not: configure it on one thread, then call `Run`.
- Operations are interfaces: a running task keeps its operation alive, so the caller may drop the reference. Callbacks registered on an operation are released when it ends.
- `OnUnhandledError` and `RegisterExceptionCloner` are global: set them at startup.
- `TAsyncOperationController` and `TAsyncOperationController<T>` implement the operations; a subclass completes them with the protected `TrySetResult`, `TryComplete` and `SignalCompletion`. `TAsyncCorePromise<T>`, `TAsyncCoreVoidPromise` and `TAsyncRetryOperation<T>` are implementation classes: use `TAsyncCore`.
