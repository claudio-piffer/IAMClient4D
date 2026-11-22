{
  ---------------------------------------------------------------------------
  Unit Name  : Async.Core.pas
  Project    : IAMClient4D
  Author     : Claudio Piffer
  Copyright  : Copyright (c) 2018-2025 Claudio Piffer
  License    : Apache License, Version 2.0, January 2004
  Source URL : https://github.com/claudio-piffer/IAMClient4D

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  ---------------------------------------------------------------------------
}

unit Async.Core;

{$SCOPEDENUMS ON}

interface

uses
  System.SysUtils,
  System.Threading,
  System.SyncObjs,
  System.Generics.Collections;

type

  /// <summary>
  ///   Callback invoked when an asynchronous operation is cancelled.
  /// </summary>
  TAsyncCoreCancelledCallback = reference to procedure;

  /// <summary>
  ///   Callback invoked after task completion, regardless of success or failure.
  /// </summary>
  TAsyncCoreFinallyCallback = reference to procedure;

  /// <summary>
  ///   Callback invoked when an error occurs during task execution.
  /// </summary>
  /// <remarks>
  ///   The exception is owned by the operation: do not free it or keep it after the callback returns.
  /// </remarks>
  TAsyncCoreErrorCallback = reference to procedure(const AException: Exception);

  /// <summary>
  ///   Callback invoked on successful completion with the task result.
  /// </summary>
  TAsyncCoreSuccessCallback<T> = reference to procedure(const ATaskResult: T);

  /// <summary>
  ///   Callback invoked on successful completion of a void task.
  /// </summary>
  TAsyncCoreProcedureSuccessCallback = reference to procedure;

  /// <summary>
  ///   Decides whether a failed attempt of RunWithRetry is retried.
  /// </summary>
  TAsyncCoreRetryPredicate = reference to function(const AException: Exception): Boolean;

  /// <summary>
  ///   Creates an independent copy of an exception, including the fields of its class.
  /// </summary>
  TAsyncExceptionCloner = reference to function(const ASource: Exception): Exception;

  /// <summary>
  ///   Defines on which thread callbacks are executed.
  /// </summary>
  /// <remarks>
  ///   <para>dmSynchronize: Blocks the worker thread until the main thread executes the callback. On the main thread
  ///   the callback runs at once, inside the call that ends the operation (e.g. Cancel on WhenAll).</para>
  ///   <para>dmQueue: Queues the callback for execution on the main thread without blocking. Always queued
  ///   (TThread.ForceQueue), also on the main thread: callbacks never run inside Cancel, SetResult or OnCompletion.</para>
  ///   <para>dmInline: Runs the callback on the thread that completes the operation (usually a pool thread),
  ///   without involving the main thread. For console applications, services and servers; the callbacks must be thread-safe.</para>
  /// </remarks>
  TAsyncCallbackDispatchMode = (dmSynchronize, dmQueue, dmInline);

  /// <summary>
  ///   Base class for all exceptions raised by the Async.Core library.
  /// </summary>
  EAsyncException = class(Exception);

  /// <summary>
  ///   Exception raised when an asynchronous operation is cancelled.
  /// </summary>
  EAsyncCancelException = class(EAsyncException)
  public
    constructor Create; overload;
  end;

  /// <summary>
  ///   Exception raised when an asynchronous operation times out.
  /// </summary>
  EAsyncTimeoutException = class(EAsyncException)
  public
    constructor Create(const AMessage: string);
  end;

  /// <summary>
  ///   Represents the state of an asynchronous operation.
  /// </summary>
  TAsyncOperationState = (
    /// <summary>Operation created but not yet started</summary>
    Pending,
    /// <summary>Operation is currently executing</summary>
    Running,
    /// <summary>Operation completed successfully</summary>
    Completed,
    /// <summary>Operation failed with an exception</summary>
    Faulted,
    /// <summary>Operation was cancelled</summary>
    Cancelled);

  /// <summary>
  ///   Backoff strategy for retry operations.
  /// </summary>
  TBackoffStrategy = (
    /// <summary>Fixed delay between retries</summary>
    Fixed,
    /// <summary>Linearly increasing delay (delay * attempt)</summary>
    Linear,
    /// <summary>Exponentially increasing delay (delay * 2^attempt)</summary>
    Exponential,
    /// <summary>Exponential delay randomized between 50% and 100%: spreads the retries of many clients</summary>
    ExponentialJitter);

  /// <summary>
  ///   Interface for controlling and monitoring an asynchronous operation.
  /// </summary>
  IAsyncOperation = interface
    ['{E11866CF-8245-45A3-846C-70F54DAC945E}']
    /// <summary>
    ///   Requests cancellation of the asynchronous operation.
    /// </summary>
    /// <remarks>
    ///   <para>Run/New tasks: cooperative, the task must check IsCancellationRequested.</para>
    ///   <para>ContinueWith, WhenAll, WhenAny and RunWithTimeout: the operation is cancelled at once and the
    ///   cancellation is forwarded to the operations it depends on.</para>
    ///   <para>Delay and CreateCancellationTokenWithTimeout: the operation is cancelled at once and its timer disposed;
    ///   the callbacks run on a pool thread.</para>
    ///   <para>RunWithRetry: cooperative during an attempt, as for Run; during the wait between attempts the operation is
    ///   cancelled at once and its timer disposed, the callbacks run on a pool thread.</para>
    ///   <para>FromOperation: forwarded to the followed operation, the operation ends when that one does.</para>
    /// </remarks>
    procedure Cancel;

    /// <summary>
    ///   Checks if cancellation has been requested for this operation.
    /// </summary>
    /// <returns>True if cancellation was requested, False otherwise.</returns>
    function IsCancellationRequested: Boolean;

    /// <summary>
    ///   Registers a callback to be invoked when the operation is cancelled.
    /// </summary>
    /// <param name="ACallback">The callback to execute on cancellation.</param>
    /// <remarks>
    ///   Several callbacks can be registered. If cancellation was already requested the callback is dispatched at once.
    /// </remarks>
    procedure OnCancelled(const ACallback: TAsyncCoreCancelledCallback);

    /// <summary>
    ///   Waits for the operation to complete.
    /// </summary>
    /// <param name="ATimeout">Timeout in milliseconds. Use INFINITE for no timeout.</param>
    /// <param name="ARaiseOnError">If True, raises a copy of the exception when the operation faulted. Cancelled state never raises. Default: False for backward compatibility.</param>
    /// <returns>The final state of the operation.</returns>
    /// <exception cref="EAsyncTimeoutException">Raised if the timeout expires, whatever ARaiseOnError.</exception>
    /// <exception cref="Exception">Raised if ARaiseOnError=True and the operation faulted.</exception>
    function WaitForCompletion(ATimeout: Cardinal = INFINITE; ARaiseOnError: Boolean = False): TAsyncOperationState;

    /// <summary>
    ///   Gets the current state of the operation.
    /// </summary>
    /// <returns>The current operation state.</returns>
    function GetState: TAsyncOperationState;

    /// <summary>
    ///   Registers a callback to be invoked when the operation completes (success, failure, or cancellation).
    /// </summary>
    /// <param name="ACallback">The callback to execute on completion.</param>
    procedure OnCompletion(const ACallback: TAsyncCoreFinallyCallback);

    /// <summary>
    ///   Current state of the operation.
    /// </summary>
    property State: TAsyncOperationState read GetState;
  end;

  /// <summary>
  ///   Generic interface for asynchronous operations that return a value of type T.
  /// </summary>
  IAsyncOperation<T> = interface(IAsyncOperation)
    ['{B08F9E5E-DB54-406D-89A4-C0904788DD53}']
    /// <summary>
    ///   Waits for the operation to complete and returns the result.
    /// </summary>
    /// <param name="ATimeout">Timeout in milliseconds. Use INFINITE for no timeout.</param>
    /// <returns>The result of the operation.</returns>
    /// <exception cref="EAsyncTimeoutException">Raised if the timeout expires.</exception>
    /// <exception cref="EAsyncCancelException">Raised if the operation was cancelled.</exception>
    /// <exception cref="Exception">Raises a copy of the exception if the operation faulted.</exception>
    function WaitForResult(ATimeout: Cardinal = INFINITE): T;

    /// <summary>
    ///   Attempts to get the result with optional timeout without blocking indefinitely.
    /// </summary>
    /// <param name="ATimeout">Timeout in milliseconds. Use 0 for immediate check.</param>
    /// <param name="AResult">Receives the result if available.</param>
    /// <returns>True if the result was retrieved successfully, False if still pending or timeout.</returns>
    /// <remarks>
    ///   <para>Unlike WaitForResult, this does not raise exceptions.</para>
    ///   <para>Returns False if operation is still running, faulted, or cancelled.</para>
    ///   <para>Use State property to check why it returned False.</para>
    /// </remarks>
    function TryWaitForResult(ATimeout: Cardinal; out AResult: T): Boolean;

    /// <summary>
    ///   Attempts to retrieve the cached result without waiting.
    /// </summary>
    /// <param name="AResult">Receives the result if available.</param>
    /// <returns>True if the result was available (operation completed successfully), False otherwise.</returns>
    function TryGetResult(out AResult: T): Boolean;

    /// <summary>
    ///   Gets a copy of the exception if the operation faulted.
    /// </summary>
    /// <returns>A new exception owned by the caller (free it), or nil if the operation did not fault.</returns>
    function GetException: Exception;
  end;

  /// <summary>
  ///   Thread-safe implementation of IAsyncOperation: state, cancellation, callbacks and waiters.
  /// </summary>
  TAsyncOperationController = class(TInterfacedObject, IAsyncOperation)
  private type
    TCancelHandler = record
      Callback: TAsyncCoreCancelledCallback;
      DispatchMode: TAsyncCallbackDispatchMode;
    end;
  private
    FCancelled: Integer;
    FCancelHandlers: TList<TCancelHandler>;
    FCompletionCallbacks: TList<TAsyncCoreFinallyCallback>;
    FCompletionEvent: TEvent;
    FContinuations: TList<TAsyncCoreFinallyCallback>;
    FCriticalSection: TCriticalSection;
    FDispatchMode: TAsyncCallbackDispatchMode;
    FException: Exception;
    FSignalled: Boolean;
    FState: TAsyncOperationState;
    procedure AddCancelHandler(const ACallback: TAsyncCoreCancelledCallback; ADispatchMode: TAsyncCallbackDispatchMode);
    procedure RunCancelHandler(const AHandler: TCancelHandler);
  protected
    // IAsyncOperation
    procedure Cancel;
    function IsCancellationRequested: Boolean;
    procedure OnCancelled(const ACallback: TAsyncCoreCancelledCallback);
    procedure OnCompletion(const ACallback: TAsyncCoreFinallyCallback);
    function WaitForCompletion(ATimeout: Cardinal = INFINITE; ARaiseOnError: Boolean = False): TAsyncOperationState;
    function GetState: TAsyncOperationState;
    function GetException: Exception;

    class function IsFinal(AState: TAsyncOperationState): Boolean; static; inline;

    /// <summary>
    ///   Waits until the operation is completed and signalled. Returns False on timeout, without raising.
    /// </summary>
    function WaitSignaled(ATimeout: Cardinal): Boolean;

    /// <summary>
    ///   Moves a pending operation to the Running state.
    /// </summary>
    procedure SetRunning;

    /// <summary>
    ///   Moves the operation to a final state. Returns False if it already reached one.
    /// </summary>
    /// <remarks>
    ///   Takes ownership of AException in any case. A nil exception for Faulted is replaced by an EAsyncException.
    /// </remarks>
    function TryComplete(AState: TAsyncOperationState; AException: Exception = nil): Boolean;

    /// <summary>
    ///   Dispatches the completion callbacks (once) and releases the waiters.
    /// </summary>
    procedure SignalCompletion;

    /// <summary>
    ///   Dispatches ACallback with the stored exception; the operation stays alive until the callback has run.
    /// </summary>
    procedure DispatchException(const ACallback: TAsyncCoreErrorCallback);

    /// <summary>
    ///   Registers a cancellation handler run on the cancelling thread, for internal signalling.
    /// </summary>
    procedure OnCancelledInline(const ACallback: TAsyncCoreCancelledCallback);

    /// <summary>
    ///   Registers an internal continuation, run on the completing thread after the waiters are released.
    /// </summary>
    /// <remarks>
    ///   Used by the combinators: they must work even when the main thread does not serve Synchronize/Queue.
    /// </remarks>
    procedure OnCompletionInline(const ACallback: TAsyncCoreFinallyCallback);

    /// <summary>
    ///   Removes a continuation registered with OnCompletionInline that has not run yet.
    /// </summary>
    procedure RemoveCompletionInline(const ACallback: TAsyncCoreFinallyCallback);
  public
    constructor Create(ADispatchMode: TAsyncCallbackDispatchMode);
    destructor Destroy; override;
  end;

  /// <summary>
  ///   Generic controller for asynchronous operations that return a value.
  /// </summary>
  TAsyncOperationController<T> = class(TAsyncOperationController, IAsyncOperation<T>)
  private
    FResult: T;
    FHasResult: Boolean;
  protected
    /// <summary>
    ///   Stores the result and completes the operation. Returns False if it already reached a final state.
    /// </summary>
    function TrySetResult(const AValue: T): Boolean;
  public
    // IAsyncOperation<T>
    function WaitForResult(ATimeout: Cardinal = INFINITE): T;
    function TryWaitForResult(ATimeout: Cardinal; out AResult: T): Boolean;
    function TryGetResult(out AResult: T): Boolean;
  end;

  /// <summary>
  ///   Function task that returns a value of type T and can be cancelled via the operation controller.
  /// </summary>
  TAsyncCoreFunctionTask<T> = reference to function(const AOperationController: IAsyncOperation): T;

  /// <summary>
  ///   Procedure task that can be cancelled via the operation controller.
  /// </summary>
  TAsyncCoreProcedureTask = reference to procedure(const AOperationController: IAsyncOperation);

  /// <summary>
  ///   Continuation function that transforms a value of type T to type TResult.
  /// </summary>
  TAsyncCoreContinuationFunc<T, TResult> = reference to function(const AValue: T): TResult;

  /// <summary>
  ///   Interface for manual control over the completion of an asynchronous operation.
  /// </summary>
  IAsyncTaskCompletionSource<T> = interface
    ['{B973E209-6828-48AC-B656-111F6FE760C8}']
    procedure SetResult(const AValue: T);
    procedure SetException(AException: Exception);
    procedure SetCancelled;
    function TrySetResult(const AValue: T): Boolean;
    function TrySetException(AException: Exception): Boolean;
    function TrySetCancelled: Boolean;
    function GetOperation: IAsyncOperation<T>;
    property Operation: IAsyncOperation<T> read GetOperation;
  end;

  /// <summary>
  ///   Interface for manual control over the completion of an asynchronous operation (void).
  /// </summary>
  IAsyncTaskCompletionSource = interface
    ['{C75C6AF5-5EA5-47AE-BF89-4F132FEDF842}']
    procedure SetResult;
    procedure SetException(AException: Exception);
    procedure SetCancelled;
    function TrySetResult: Boolean;
    function TrySetException(AException: Exception): Boolean;
    function TrySetCancelled: Boolean;
    function GetOperation: IAsyncOperation;
    property Operation: IAsyncOperation read GetOperation;
  end;

  /// <summary>
  ///   Promise interface for asynchronous operations that return a value of type T.
  /// </summary>
  IAsyncPromise<T> = interface
    ['{5AFE3EAF-D1B7-49CD-8AEC-E4496CC83CAE}']
    /// <summary>
    ///   Registers a success callback to be invoked when the task completes successfully.
    /// </summary>
    /// <param name="ACallback">The callback to execute with the task result.</param>
    /// <returns>The promise instance for method chaining.</returns>
    function OnSuccess(const ACallback: TAsyncCoreSuccessCallback<T>): IAsyncPromise<T>;

    /// <summary>
    ///   Registers an error callback to be invoked when the task fails.
    /// </summary>
    /// <param name="ACallback">The callback to execute with the exception.</param>
    /// <returns>The promise instance for method chaining.</returns>
    function OnError(const ACallback: TAsyncCoreErrorCallback): IAsyncPromise<T>;

    /// <summary>
    ///   Registers a finally callback to be invoked after task completion.
    /// </summary>
    /// <param name="ACallback">The callback to execute regardless of task outcome.</param>
    /// <returns>The promise instance for method chaining.</returns>
    function OnFinally(const ACallback: TAsyncCoreFinallyCallback): IAsyncPromise<T>;

    /// <summary>
    ///   Sets the dispatch mode for all callbacks.
    /// </summary>
    /// <param name="AMode">The dispatch mode to use.</param>
    /// <returns>The promise instance for method chaining.</returns>
    function DispatchMode(const AMode: TAsyncCallbackDispatchMode): IAsyncPromise<T>;

    /// <summary>
    ///   Starts the asynchronous operation.
    /// </summary>
    /// <returns>An operation controller for monitoring and cancelling the task.</returns>
    function Run: IAsyncOperation<T>;
  end;

  /// <summary>
  ///   Promise interface for asynchronous operations that do not return a value.
  /// </summary>
  IAsyncVoidPromise = interface
    ['{A16D8988-EFAA-4DF7-BDCC-90932CC8699E}']
    /// <summary>
    ///   Registers a success callback to be invoked when the task completes successfully.
    /// </summary>
    /// <param name="ACallback">The callback to execute on success.</param>
    /// <returns>The promise instance for method chaining.</returns>
    function OnSuccess(const ACallback: TAsyncCoreProcedureSuccessCallback): IAsyncVoidPromise;

    /// <summary>
    ///   Registers an error callback to be invoked when the task fails.
    /// </summary>
    /// <param name="ACallback">The callback to execute with the exception.</param>
    /// <returns>The promise instance for method chaining.</returns>
    function OnError(const ACallback: TAsyncCoreErrorCallback): IAsyncVoidPromise;

    /// <summary>
    ///   Registers a finally callback to be invoked after task completion.
    /// </summary>
    /// <param name="ACallback">The callback to execute regardless of task outcome.</param>
    /// <returns>The promise instance for method chaining.</returns>
    function OnFinally(const ACallback: TAsyncCoreFinallyCallback): IAsyncVoidPromise;

    /// <summary>
    ///   Sets the dispatch mode for all callbacks.
    /// </summary>
    /// <param name="AMode">The dispatch mode to use.</param>
    /// <returns>The promise instance for method chaining.</returns>
    function DispatchMode(const AMode: TAsyncCallbackDispatchMode): IAsyncVoidPromise;

    /// <summary>
    ///   Starts the asynchronous operation.
    /// </summary>
    /// <returns>An operation controller for monitoring and cancelling the task.</returns>
    function Run: IAsyncOperation;
  end;

  TAsyncCorePromise<T> = class(TInterfacedObject, IAsyncPromise<T>)
  private
    FTask: TAsyncCoreFunctionTask<T>;
    FSource: IAsyncOperation<T>;
    FOnSuccess: TAsyncCoreSuccessCallback<T>;
    FOnError: TAsyncCoreErrorCallback;
    FOnFinally: TAsyncCoreFinallyCallback;
    FDispatchMode: TAsyncCallbackDispatchMode;
  protected
    function OnSuccess(const ACallback: TAsyncCoreSuccessCallback<T>): IAsyncPromise<T>;
    function OnError(const ACallback: TAsyncCoreErrorCallback): IAsyncPromise<T>;
    function OnFinally(const ACallback: TAsyncCoreFinallyCallback): IAsyncPromise<T>;
    function DispatchMode(const AMode: TAsyncCallbackDispatchMode): IAsyncPromise<T>;
    function Run: IAsyncOperation<T>;
    constructor Create(const ATask: TAsyncCoreFunctionTask<T>);
    constructor CreateFromOperation(const ASource: IAsyncOperation<T>);
  end;

  TAsyncCoreVoidPromise = class(TInterfacedObject, IAsyncVoidPromise)
  private
    FTask: TAsyncCoreProcedureTask;
    FOnSuccess: TAsyncCoreProcedureSuccessCallback;
    FOnError: TAsyncCoreErrorCallback;
    FOnFinally: TAsyncCoreFinallyCallback;
    FDispatchMode: TAsyncCallbackDispatchMode;
  protected
    function OnSuccess(const ACallback: TAsyncCoreProcedureSuccessCallback): IAsyncVoidPromise;
    function OnError(const ACallback: TAsyncCoreErrorCallback): IAsyncVoidPromise;
    function OnFinally(const ACallback: TAsyncCoreFinallyCallback): IAsyncVoidPromise;
    function DispatchMode(const AMode: TAsyncCallbackDispatchMode): IAsyncVoidPromise;
    function Run: IAsyncOperation;
    constructor Create(const ATask: TAsyncCoreProcedureTask);
  end;

  /// <summary>
  ///   Allows manual control over the completion of an asynchronous operation that returns a value.
  /// </summary>
  /// <remarks>
  ///   <para>Use this to wrap callback-based APIs into async/await pattern.</para>
  ///   <para>Useful for converting event-based code to async operations.</para>
  ///   <para>Thread-safe - can be set from any thread.</para>
  /// </remarks>
  TAsyncTaskCompletionSource<T> = class(TInterfacedObject, IAsyncTaskCompletionSource<T>)
  private
    FController: TAsyncOperationController<T>;
    FOperation: IAsyncOperation<T>; // keeps FController alive as long as the source
    function GetOperation: IAsyncOperation<T>;
  public
    constructor Create(ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmQueue);

    /// <summary>
    ///   Sets the result and marks the operation as completed successfully.
    /// </summary>
    /// <param name="AValue">The result value.</param>
    /// <exception cref="Exception">Raised if the operation was already completed.</exception>
    procedure SetResult(const AValue: T);

    /// <summary>
    ///   Sets an exception and marks the operation as faulted.
    /// </summary>
    /// <param name="AException">The exception (ownership is transferred).</param>
    /// <exception cref="Exception">Raised if the operation was already completed.</exception>
    procedure SetException(AException: Exception);

    /// <summary>
    ///   Marks the operation as cancelled.
    /// </summary>
    /// <exception cref="Exception">Raised if the operation was already completed.</exception>
    procedure SetCancelled;

    /// <summary>
    ///   Attempts to set the result. Returns false if already completed.
    /// </summary>
    function TrySetResult(const AValue: T): Boolean;

    /// <summary>
    ///   Attempts to set an exception. Returns false if already completed.
    /// </summary>
    function TrySetException(AException: Exception): Boolean;

    /// <summary>
    ///   Attempts to set cancelled. Returns false if already completed.
    /// </summary>
    function TrySetCancelled: Boolean;

    /// <summary>
    ///   Gets the operation that can be returned to callers.
    /// </summary>
    property Operation: IAsyncOperation<T> read GetOperation;
  end;

  /// <summary>
  ///   Allows manual control over the completion of an asynchronous operation that does not return a value.
  /// </summary>
  TAsyncTaskCompletionSource = class(TInterfacedObject, IAsyncTaskCompletionSource)
  private
    FController: TAsyncOperationController;
    FOperation: IAsyncOperation; // keeps FController alive as long as the source
    function GetOperation: IAsyncOperation;
  public
    constructor Create(ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmQueue);

    /// <summary>
    ///   Marks the operation as completed successfully.
    /// </summary>
    /// <exception cref="Exception">Raised if the operation was already completed.</exception>
    procedure SetResult;

    /// <summary>
    ///   Sets an exception and marks the operation as faulted.
    /// </summary>
    /// <param name="AException">The exception (ownership is transferred).</param>
    /// <exception cref="Exception">Raised if the operation was already completed.</exception>
    procedure SetException(AException: Exception);

    /// <summary>
    ///   Marks the operation as cancelled.
    /// </summary>
    /// <exception cref="Exception">Raised if the operation was already completed.</exception>
    procedure SetCancelled;

    /// <summary>
    ///   Attempts to set the result. Returns false if already completed.
    /// </summary>
    function TrySetResult: Boolean;

    /// <summary>
    ///   Attempts to set an exception. Returns false if already completed.
    /// </summary>
    function TrySetException(AException: Exception): Boolean;

    /// <summary>
    ///   Attempts to set cancelled. Returns false if already completed.
    /// </summary>
    function TrySetCancelled: Boolean;

    /// <summary>
    ///   Gets the operation that can be returned to callers.
    /// </summary>
    property Operation: IAsyncOperation read GetOperation;
  end;

  /// <summary>
  ///   Operation of TAsyncCore.RunWithRetry: each attempt is a pool task, each wait between attempts a timer of the
  ///   shared timer thread. Internal: use RunWithRetry.
  /// </summary>
  TAsyncRetryOperation<T> = class(TAsyncOperationController<T>)
  private
    FTask: TAsyncCoreFunctionTask<T>;
    FShouldRetry: TAsyncCoreRetryPredicate;
    FMaxRetries: Integer;
    FInitialDelay: Cardinal;
    FMaxDelay: Cardinal;
    FStrategy: TBackoffStrategy;
    FAttempt: Integer; // only the running attempt uses it
    FTimer: Int64;     // last backoff timer, guarded by FCriticalSection
    function AttemptProc: TProc;
    function FinishProc: TProc;
    function CancelHandler: TAsyncCoreCancelledCallback;
    procedure Start;
    procedure RunAttempt;
    function ScheduleRetry: Boolean;
    procedure CancelWait;
    procedure Finish;
  public
    constructor Create(const ATask: TAsyncCoreFunctionTask<T>; AMaxRetries: Integer; AInitialDelay: Cardinal;
      AStrategy: TBackoffStrategy; AMaxDelay: Cardinal; const AShouldRetry: TAsyncCoreRetryPredicate;
      ADispatchMode: TAsyncCallbackDispatchMode);
  end;

  /// <summary>
  ///   Main entry point for creating and executing asynchronous operations.
  /// </summary>
  TAsyncCore = class sealed
  private
    class var FOnUnhandledError: TAsyncCoreErrorCallback;
    class procedure DispatchCallback(ADispatchMode: TAsyncCallbackDispatchMode; const ACallback: TAsyncCoreFinallyCallback); static;
    class function ReportUnhandledError(AException: Exception): Boolean; static;
    class function CloneException(ASource: Exception): Exception; static;
    class function RetryDelay(AStrategy: TBackoffStrategy; AInitialDelay, AMaxDelay: Cardinal; AAttempt: Integer): Cardinal; static;
    class procedure AddContinuation(const AOperation: IAsyncOperation; const AContinuation: TAsyncCoreFinallyCallback); static;
    class procedure RemoveContinuation(const AOperation: IAsyncOperation; const AContinuation: TAsyncCoreFinallyCallback); static;
    class function ScheduleTimer(ADelayMs: Cardinal; const ACallback: TProc): Int64; static;
    class function CancelTimer(AId: Int64): Boolean; static;
    class procedure AddCancelHandler(const AOperation: IAsyncOperation; const AHandler: TAsyncCoreCancelledCallback); static;
    class procedure SetFaulted(AController: TAsyncOperationController; AException: Exception;
      const OnError: TAsyncCoreErrorCallback); static;
    class function Follow<T>(const ASource: IAsyncOperation<T>; OnSuccess: TAsyncCoreSuccessCallback<T>;
      OnError: TAsyncCoreErrorCallback; OnFinally: TAsyncCoreFinallyCallback;
      ADispatchMode: TAsyncCallbackDispatchMode): IAsyncOperation<T>; static;
  public
    /// <summary>
    ///   Executes an asynchronous function task that returns a value.
    /// </summary>
    /// <param name="OnAsyncTask">The task to execute asynchronously.</param>
    /// <param name="OnSuccess">Optional callback invoked on successful completion.</param>
    /// <param name="OnError">Optional callback invoked on error.</param>
    /// <param name="OnFinally">Optional callback invoked after completion.</param>
    /// <param name="ADispatchMode">Callback dispatch mode (default: dmSynchronize).</param>
    /// <returns>An operation controller for monitoring and cancelling the task.</returns>
    class function Run<T>(
      OnAsyncTask: TAsyncCoreFunctionTask<T>;
      OnSuccess: TAsyncCoreSuccessCallback<T> = nil;
      OnError: TAsyncCoreErrorCallback = nil;
      OnFinally: TAsyncCoreFinallyCallback = nil;
      ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation<T>; overload; static;

    /// <summary>
    ///   Executes an asynchronous procedure task that does not return a value.
    /// </summary>
    /// <param name="OnAsyncTask">The task to execute asynchronously.</param>
    /// <param name="OnSuccess">Optional callback invoked on successful completion.</param>
    /// <param name="OnError">Optional callback invoked on error.</param>
    /// <param name="OnFinally">Optional callback invoked after completion.</param>
    /// <param name="ADispatchMode">Callback dispatch mode (default: dmSynchronize).</param>
    /// <returns>An operation controller for monitoring and cancelling the task.</returns>
    class function Run(
      OnAsyncTask: TAsyncCoreProcedureTask;
      OnSuccess: TAsyncCoreProcedureSuccessCallback = nil;
      OnError: TAsyncCoreErrorCallback = nil;
      OnFinally: TAsyncCoreFinallyCallback = nil;
      ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation; overload; static;

    /// <summary>
    ///   Creates a new promise for an asynchronous function task with fluent interface.
    /// </summary>
    /// <param name="ATask">The task to execute.</param>
    /// <returns>A promise that can be configured with callbacks and executed.</returns>
    class function New<T>(const ATask: TAsyncCoreFunctionTask<T>): IAsyncPromise<T>; overload; static;

    /// <summary>
    ///   Creates a new promise for an asynchronous procedure task with fluent interface.
    /// </summary>
    /// <param name="ATask">The task to execute.</param>
    /// <returns>A promise that can be configured with callbacks and executed.</returns>
    class function New(const ATask: TAsyncCoreProcedureTask): IAsyncVoidPromise; overload; static;

    /// <summary>
    ///   Creates a promise for an operation completed elsewhere, typically by a TAsyncTaskCompletionSource.
    /// </summary>
    /// <param name="AOperation">The operation to follow.</param>
    /// <returns>A promise whose Run returns an operation that ends as AOperation does.</returns>
    /// <remarks>
    ///   <para>Unlike a New task that waits on AOperation, no thread is blocked and no exception is raised
    ///   when AOperation is cancelled. The callbacks are dispatched from a pool thread, as for New.</para>
    ///   <para>Cancel on the operation returned by Run is forwarded to AOperation: its producer ends it,
    ///   e.g. with OnCancelled and TrySetCancelled on the completion source.</para>
    /// </remarks>
    class function FromOperation<T>(const AOperation: IAsyncOperation<T>): IAsyncPromise<T>; static;

    /// <summary>
    ///   Creates a continuation that executes when the source operation completes successfully.
    /// </summary>
    /// <param name="AOperation">The source operation to chain from.</param>
    /// <param name="AContinuation">Function that transforms the result to a new type.</param>
    /// <param name="ADispatchMode">Dispatch mode of the callbacks registered on the returned operation.</param>
    /// <returns>A new operation representing the continuation.</returns>
    /// <remarks>
    ///   <para>If the source operation fails or is cancelled, the continuation is not executed and the error propagates.</para>
    ///   <para>The continuation runs on a pool thread. Cancel cancels the continuation at once and the source operation.</para>
    /// </remarks>
    class function ContinueWith<T, TResult>(const AOperation: IAsyncOperation<T>;
      const AContinuation: TAsyncCoreContinuationFunc<T, TResult>;
      ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation<TResult>; static;

    /// <summary>
    ///   Waits for all operations to complete successfully.
    /// </summary>
    /// <param name="AOperations">Array of operations to wait for.</param>
    /// <param name="ADispatchMode">Dispatch mode of the callbacks registered on the returned operation.</param>
    /// <returns>An operation that completes when all operations complete, returning an array of results.</returns>
    /// <remarks>
    ///   If any operation fails or is cancelled, WhenAll fails immediately with that error.
    ///   All operations execute in parallel. Cancel cancels the result at once and all the operations.
    /// </remarks>
    class function WhenAll<T>(const AOperations: array of IAsyncOperation<T>;
      ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation<TArray<T>>; static;

    /// <summary>
    ///   Waits for the first operation to complete.
    /// </summary>
    /// <param name="AOperations">Array of operations to race.</param>
    /// <param name="ADispatchMode">Dispatch mode of the callbacks registered on the returned operation.</param>
    /// <returns>An operation that completes when the first operation completes, returning its result.</returns>
    /// <remarks>
    ///   Returns the result of the first operation that completes (success, error, or cancellation).
    ///   Other operations continue running in the background. Cancel cancels the result at once and all the operations.
    /// </remarks>
    class function WhenAny<T>(const AOperations: array of IAsyncOperation<T>;
      ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation<T>; static;

    /// <summary>
    ///   Executes an asynchronous task with automatic retry on failure.
    /// </summary>
    /// <param name="ATask">The task to execute.</param>
    /// <param name="AMaxRetries">Maximum number of retry attempts (0 = no retry, just one attempt).</param>
    /// <param name="AInitialDelay">Initial delay between retries in milliseconds.</param>
    /// <param name="ABackoffStrategy">Backoff strategy for calculating delays.</param>
    /// <param name="AMaxDelay">Maximum delay between retries in milliseconds (default: 30000ms = 30s).</param>
    /// <param name="AShouldRetry">Optional filter: a failed attempt is retried only if it returns True. Default: retry any error.</param>
    /// <param name="ADispatchMode">Dispatch mode of the callbacks registered on the returned operation, which is also
    /// the controller passed to ATask (default: dmSynchronize).</param>
    /// <returns>An operation that completes when the task succeeds or all retries are exhausted.</returns>
    /// <exception cref="EArgumentOutOfRangeException">Raised if AMaxRetries is negative.</exception>
    /// <remarks>
    ///   <para>Fixed: Always waits AInitialDelay between retries.</para>
    ///   <para>Linear: Delay = AInitialDelay * attempt (1x, 2x, 3x, ...).</para>
    ///   <para>Exponential: Delay = AInitialDelay * 2^attempt (1x, 2x, 4x, 8x, ...).</para>
    ///   <para>ExponentialJitter: exponential delay (capped) randomized between 50% and 100%.</para>
    ///   <para>All delays are capped at AMaxDelay.</para>
    ///   <para>Each attempt runs as a pool task; no thread waits between attempts: the shared timer thread serves the
    ///   delay. Cancel during the delay disposes the timer and ends the operation as Cancelled at once, without raising
    ///   exceptions; the callbacks run on a pool thread. During an attempt cancellation is cooperative, as for Run.</para>
    ///   <para>If all retries fail, raises the last exception encountered.</para>
    /// </remarks>
    class function RunWithRetry<T>(
      ATask: TAsyncCoreFunctionTask<T>;
      AMaxRetries: Integer = 3;
      AInitialDelay: Cardinal = 1000;
      ABackoffStrategy: TBackoffStrategy = TBackoffStrategy.Exponential;
      AMaxDelay: Cardinal = 30000;
      AShouldRetry: TAsyncCoreRetryPredicate = nil;
      ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation<T>; static;

    /// <summary>
    ///   Executes an asynchronous task with automatic cancellation after timeout.
    /// </summary>
    /// <param name="ATask">The task to execute.</param>
    /// <param name="ATimeoutMs">Timeout in milliseconds after which the task is automatically cancelled.</param>
    /// <param name="ADispatchMode">Dispatch mode of the callbacks registered on the returned operation and on the
    /// controller passed to ATask (default: dmSynchronize).</param>
    /// <returns>An operation that completes when the task finishes or the timeout expires.</returns>
    /// <remarks>
    ///   <para>If the task completes before timeout, returns normally.</para>
    ///   <para>If timeout expires, the operation faults with EAsyncTimeoutException and cancellation is requested
    ///   to the task, which should check IsCancellationRequested.</para>
    ///   <para>Only the task takes a pool thread: the timeout is served by the shared timer thread and disposed as soon
    ///   as the task ends.</para>
    ///   <para>The timeout cancels the task from a pool thread: where the main thread does not serve Synchronize
    ///   (console, service, server) use dmInline or dmQueue, or the OnCancelled callbacks of the task never run.</para>
    ///   <para>Cancel cancels the operation at once and the task.</para>
    /// </remarks>
    class function RunWithTimeout<T>(
      ATask: TAsyncCoreFunctionTask<T>;
      ATimeoutMs: Cardinal;
      ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation<T>; static;

    /// <summary>
    ///   Creates an asynchronous delay operation.
    /// </summary>
    /// <param name="AMilliseconds">The delay duration in milliseconds.</param>
    /// <param name="ADispatchMode">Dispatch mode of the callbacks registered on the returned operation (default: dmSynchronize).</param>
    /// <returns>An operation that completes after the specified delay.</returns>
    /// <remarks>
    ///   <para>This is a non-blocking alternative to Sleep(). No thread waits: a shared timer thread serves every
    ///   delay and completes it from a pool thread. INFINITE never completes.</para>
    ///   <para>Cancel disposes the timer and ends the delay as Cancelled (at once while the timer is pending), without
    ///   raising exceptions; the callbacks run on a pool thread. A Cancel that comes before the delay has completed always wins.</para>
    ///   <para>Useful for testing, throttling, or introducing delays in task chains.</para>
    /// </remarks>
    class function Delay(AMilliseconds: Cardinal;
      ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation; static;

    /// <summary>
    ///   Creates a cancellation token that automatically signals after a timeout.
    /// </summary>
    /// <param name="ATimeoutMs">Timeout in milliseconds before the token signals completion.</param>
    /// <param name="ADispatchMode">Dispatch mode of the callbacks registered on the token (default: dmSynchronize).</param>
    /// <returns>An operation that completes when timeout expires.</returns>
    /// <remarks>
    ///   <para>Use this to create time-based cancellation tokens; it is a Delay.</para>
    ///   <para>Check State property to see if timeout has expired.</para>
    ///   <para>Cancel the token to dispose its timer before it expires.</para>
    ///   <para>Can be combined with WhenAny or LinkCancellationToken to implement timeout patterns.</para>
    /// </remarks>
    class function CreateCancellationTokenWithTimeout(ATimeoutMs: Cardinal;
      ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation; static;

    /// <summary>
    ///   Links a cancellation token to an operation, automatically cancelling the operation when the token completes.
    /// </summary>
    /// <param name="AOperation">The operation to monitor and cancel.</param>
    /// <param name="ACancellationToken">The token that triggers cancellation when it completes.</param>
    /// <remarks>
    ///   <para>When ACancellationToken completes, AOperation.Cancel is called automatically. A cancelled token
    ///   does not cancel the operation.</para>
    ///   <para>The link is dropped as soon as either one ends: a pending token does not keep a completed operation
    ///   alive. The token is not cancelled, since it may be linked to other operations: cancel it to dispose its timer.</para>
    ///   <para>Useful for implementing automatic timeout cancellation.</para>
    /// </remarks>
    class procedure LinkCancellationToken(const AOperation: IAsyncOperation; const ACancellationToken: IAsyncOperation); static;

    /// <summary>
    ///   Number of timers waiting in the shared timer thread (Delay, RunWithRetry, RunWithTimeout, timeout tokens). Diagnostics.
    /// </summary>
    class function PendingTimerCount: Integer; static;

    /// <summary>
    ///   Registers how to copy exceptions of AClass (and descendants) when they are re-raised.
    /// </summary>
    /// <param name="AClass">Exception class handled by the cloner.</param>
    /// <param name="ACloner">Function returning a new, independent copy. Nil removes the registration.</param>
    /// <remarks>
    ///   <para>WaitForResult, WaitForCompletion and GetException hand out copies, since the operation owns its exception.</para>
    ///   <para>Without a cloner the copy keeps only class and message: the fields of the class are lost.</para>
    ///   <para>The most specific registered ancestor wins. Register at startup.</para>
    /// </remarks>
    class procedure RegisterExceptionCloner(AClass: ExceptClass; const ACloner: TAsyncExceptionCloner); static;

    /// <summary>
    ///   Global handler for unhandled errors in asynchronous operations.
    /// </summary>
    /// <remarks>
    ///   <para>Invoked when a task fails and no OnError callback was registered.</para>
    ///   <para>Also receives the exceptions raised by callbacks; without a handler they go to the application
    ///   exception handler (VCL/FMX, main thread only) or are discarded, and never change the state of the operation.</para>
    ///   <para>Runs on the thread of the callback: a pool thread for dmInline.</para>
    /// </remarks>
    class property OnUnhandledError: TAsyncCoreErrorCallback read FOnUnhandledError write FOnUnhandledError;
  end;

implementation

uses
  System.Classes,
  System.Diagnostics,
  System.Math;

const
  // While waiting, the main thread serves Synchronize/Queue requests at least this often
  MAIN_THREAD_WAIT_SLICE_MS = 10;

type
  /// <summary>
  ///   Shared timer of Delay, RunWithRetry, RunWithTimeout and the timeout tokens: one thread serves all of them.
  /// </summary>
  /// <remarks>
  ///   The callback of a due timer runs on a pool thread: a slow callback (e.g. dmSynchronize) never delays the others.
  /// </remarks>
  TAsyncTimerQueue = class
  private type
    TEntry = record
      Id: Int64;
      Due: Int64;
      Callback: TProc;
    end;

    TTimerThread = class(TThread)
    private
      FQueue: TAsyncTimerQueue;
    protected
      procedure Execute; override;
    public
      constructor Create(AQueue: TAsyncTimerQueue);
    end;
  private const
    NEVER = High(Int64);
  private
    FLock: TCriticalSection;
    FWakeUp: TEvent;
    FEntries: TList<TEntry>; // descending by (Due, Id): the next timer to fire is the last one
    FClock: TStopwatch;
    FLastId: Int64;
    FThread: TTimerThread;
    FShutdown: Boolean;
    procedure Run;
  public
    constructor Create;
    destructor Destroy; override;

    /// <summary>
    ///   Runs ACallback on a pool thread after ADelayMs (INFINITE: never). Returns the timer ID.
    /// </summary>
    function Schedule(ADelayMs: Cardinal; const ACallback: TProc): Int64;

    /// <summary>
    ///   Disposes a timer and releases its callback. False if it already fired or was cancelled.
    /// </summary>
    function Cancel(AId: Int64): Boolean;

    function Count: Integer;
  end;

  ICancellationLink = interface
    procedure TokenEnded;
    procedure OperationEnded;
  end;

  /// <summary>
  ///   Lets a token cancel an operation (LinkCancellationToken). Dropped by both as soon as either one ends.
  /// </summary>
  TCancellationLink = class(TInterfacedObject, ICancellationLink)
  private
    FLock: TCriticalSection;
    FOperation: IAsyncOperation;
    FToken: IAsyncOperation;
    FTrigger: TAsyncCoreFinallyCallback;
  public
    constructor Create(const AOperation, AToken: IAsyncOperation);
    destructor Destroy; override;
    procedure Start;
    procedure TokenEnded;
    procedure OperationEnded;
  end;

{$IFDEF MSWINDOWS}
function AsyncTerminateThread(AThread: THandle; AExitCode: Cardinal): LongBool; stdcall;
  external 'kernel32.dll' name 'TerminateThread';
{$ENDIF}

var
  GClonerLock: TCriticalSection;
  GCloners: TDictionary<TClass, TAsyncExceptionCloner>;
  GJitterState: Int64;
  GTimers: TAsyncTimerQueue;

{$IFOPT Q+}{$DEFINE ASYNC_CORE_Q_ON}{$Q-}{$ENDIF}
{$IFOPT R+}{$DEFINE ASYNC_CORE_R_ON}{$R-}{$ENDIF}
// SplitMix64: thread-safe and independent of RandSeed, which applications rarely randomize
function NextRandom: UInt64;
begin
  Result := UInt64(TInterlocked.Add(GJitterState, Int64($9E3779B97F4A7C15)));
  Result := (Result xor (Result shr 30)) * $BF58476D1CE4E5B9;
  Result := (Result xor (Result shr 27)) * $94D049BB133111EB;
  Result := Result xor (Result shr 31);
end;
{$IFDEF ASYNC_CORE_R_ON}{$R+}{$ENDIF}
{$IFDEF ASYNC_CORE_Q_ON}{$Q+}{$ENDIF}

{ TAsyncTimerQueue.TTimerThread }

constructor TAsyncTimerQueue.TTimerThread.Create(AQueue: TAsyncTimerQueue);
begin
  inherited Create(False);
  // Set before AfterConstruction starts the thread
  FQueue := AQueue;
end;

procedure TAsyncTimerQueue.TTimerThread.Execute;
begin
  NameThreadForDebugging('Async.Core timer');
  FQueue.Run;
end;

{ TAsyncTimerQueue }

constructor TAsyncTimerQueue.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FWakeUp := TEvent.Create(nil, False, False, '');
  FEntries := TList<TEntry>.Create;
  FClock := TStopwatch.StartNew;
end;

destructor TAsyncTimerQueue.Destroy;
begin
  FLock.Acquire;
  try
    FShutdown := True;
  finally
    FLock.Release;
  end;
  FWakeUp.SetEvent;

  if Assigned(FThread) then
  begin
{$IFDEF MSWINDOWS}
    // DLL unload: no thread can end while the loader lock is held (the RTL thread pool does the same)
    if IsLibrary then
      AsyncTerminateThread(FThread.Handle, 0);
{$ENDIF}
    FThread.Free; // waits for the thread
  end;

  // Pending timers never fire: their callbacks, and the operations they hold, are released
  FEntries.Free;
  FWakeUp.Free;
  FLock.Free;
  inherited;
end;

function TAsyncTimerQueue.Schedule(ADelayMs: Cardinal; const ACallback: TProc): Int64;
var
  LEntry: TEntry;
  LLow, LHigh, LMid: Integer;
begin
  FLock.Acquire;
  try
    if FShutdown then
      Exit(0);

    // Started with the first timer: no thread for applications that never use one
    if not Assigned(FThread) then
      FThread := TTimerThread.Create(Self);

    Inc(FLastId);
    LEntry.Id := FLastId;
    LEntry.Callback := ACallback;
    if ADelayMs = INFINITE then
      LEntry.Due := NEVER
    else
      LEntry.Due := FClock.ElapsedMilliseconds + ADelayMs;

    // The newest ID sorts after the timers with the same due time: they fire first
    LLow := 0;
    LHigh := FEntries.Count;
    while LLow < LHigh do
    begin
      LMid := (LLow + LHigh) div 2;
      if FEntries[LMid].Due > LEntry.Due then
        LLow := LMid + 1
      else
        LHigh := LMid;
    end;
    FEntries.Insert(LLow, LEntry);

    // A new first timer: the thread waits for a later one
    if LLow = FEntries.Count - 1 then
      FWakeUp.SetEvent;
    Result := LEntry.Id;
  finally
    FLock.Release;
  end;
end;

function TAsyncTimerQueue.Cancel(AId: Int64): Boolean;
var
  I: Integer;
  LCallback: TProc;
begin
  Result := False;
  if AId = 0 then
    Exit;

  FLock.Acquire;
  try
    for I := FEntries.Count - 1 downto 0 do
      if FEntries[I].Id = AId then
      begin
        // Released outside the lock: it may free the operation it holds
        LCallback := FEntries[I].Callback;
        FEntries.Delete(I);
        Result := True;
        Break;
      end;
  finally
    FLock.Release;
  end;
end;

function TAsyncTimerQueue.Count: Integer;
begin
  FLock.Acquire;
  try
    Result := FEntries.Count;
  finally
    FLock.Release;
  end;
end;

procedure TAsyncTimerQueue.Run;
var
  LFired: TArray<TProc>;
  LCount, I: Integer;
  LNow, LWait: Int64;
begin
  while True do
  begin
    LCount := 0;
    LWait := INFINITE;
    FLock.Acquire;
    try
      if FShutdown then
        Exit;

      LNow := FClock.ElapsedMilliseconds;
      while FEntries.Count > 0 do
      begin
        if FEntries.Last.Due > LNow then
        begin
          if FEntries.Last.Due <> NEVER then
            LWait := Min(FEntries.Last.Due - LNow, Int64(INFINITE) - 1);
          Break;
        end;
        if LCount = Length(LFired) then
          SetLength(LFired, LCount * 2 + 8);
        LFired[LCount] := FEntries.Last.Callback;
        Inc(LCount);
        FEntries.Delete(FEntries.Count - 1);
      end;
    finally
      FLock.Release;
    end;

    for I := 0 to LCount - 1 do
    begin
      try
        TTask.Run(LFired[I]);
      except
        // The thread must survive (e.g. out of memory): the operation of this timer stays pending
      end;
      LFired[I] := nil;
    end;

    if LCount = 0 then
      FWakeUp.WaitFor(Cardinal(LWait));
  end;
end;

{ TCancellationLink }

function LinkTrigger(const ALink: ICancellationLink): TAsyncCoreFinallyCallback;
begin
  Result :=
    procedure
    begin
      ALink.TokenEnded;
    end;
end;

function LinkEnder(const ALink: ICancellationLink): TAsyncCoreFinallyCallback;
begin
  Result :=
    procedure
    begin
      ALink.OperationEnded;
    end;
end;

constructor TCancellationLink.Create(const AOperation, AToken: IAsyncOperation);
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FOperation := AOperation;
  FToken := AToken;
end;

destructor TCancellationLink.Destroy;
begin
  FLock.Free;
  inherited;
end;

procedure TCancellationLink.Start;
var
  LSelf: ICancellationLink;
  LOperation, LToken: IAsyncOperation;
  LTrigger: TAsyncCoreFinallyCallback;
begin
  LSelf := Self;
  LTrigger := LinkTrigger(LSelf);
  FLock.Acquire;
  try
    FTrigger := LTrigger;
    LOperation := FOperation;
    LToken := FToken;
  finally
    FLock.Release;
  end;

  // Token first: an operation already ended removes the trigger at once
  TAsyncCore.AddContinuation(LToken, LTrigger);
  TAsyncCore.AddContinuation(LOperation, LinkEnder(LSelf));
end;

procedure TCancellationLink.TokenEnded;
var
  LOperation, LToken: IAsyncOperation;
  LTrigger: TAsyncCoreFinallyCallback;
begin
  FLock.Acquire;
  try
    LOperation := FOperation;
    LToken := FToken;
    LTrigger := FTrigger;
    FOperation := nil;
    FToken := nil;
    FTrigger := nil;
  finally
    FLock.Release;
  end;

  // Only an expired token cancels: a cancelled one just goes away
  if Assigned(LOperation) and (LToken.State = TAsyncOperationState.Completed) then
    LOperation.Cancel;
end;

procedure TCancellationLink.OperationEnded;
var
  LOperation, LToken: IAsyncOperation;
  LTrigger: TAsyncCoreFinallyCallback;
begin
  FLock.Acquire;
  try
    LOperation := FOperation;
    LToken := FToken;
    LTrigger := FTrigger;
    FOperation := nil;
    FToken := nil;
    FTrigger := nil;
  finally
    FLock.Release;
  end;

  // The token no longer references the link, nor the operation
  if Assigned(LToken) then
    TAsyncCore.RemoveContinuation(LToken, LTrigger);
end;

{ TAsyncOperationController }

constructor TAsyncOperationController.Create(ADispatchMode: TAsyncCallbackDispatchMode);
begin
  inherited Create;

  FCriticalSection := TCriticalSection.Create;
  FCompletionEvent := TEvent.Create;
  FCompletionCallbacks := TList<TAsyncCoreFinallyCallback>.Create;
  FContinuations := TList<TAsyncCoreFinallyCallback>.Create;
  FCancelHandlers := TList<TCancelHandler>.Create;
  FDispatchMode := ADispatchMode;
  FState := TAsyncOperationState.Pending;
end;

destructor TAsyncOperationController.Destroy;
begin
  FException.Free;
  FCancelHandlers.Free;
  FContinuations.Free;
  FCompletionCallbacks.Free;
  FCompletionEvent.Free;
  FCriticalSection.Free;

  inherited;
end;

class function TAsyncOperationController.IsFinal(AState: TAsyncOperationState): Boolean;
begin
  Result := AState in [TAsyncOperationState.Completed, TAsyncOperationState.Faulted, TAsyncOperationState.Cancelled];
end;

procedure TAsyncOperationController.Cancel;
var
  LHandlers: TArray<TCancelHandler>;
  LHandler: TCancelHandler;
begin
  FCriticalSection.Acquire;
  try
    if IsFinal(FState) or (FCancelled <> 0) then
      Exit;

    TInterlocked.Exchange(FCancelled, 1);
    LHandlers := FCancelHandlers.ToArray;
    FCancelHandlers.Clear;
  finally
    FCriticalSection.Release;
  end;

  for LHandler in LHandlers do
    RunCancelHandler(LHandler);
end;

function TAsyncOperationController.IsCancellationRequested: Boolean;
begin
  Result := TInterlocked.CompareExchange(FCancelled, 0, 0) = 1;
end;

procedure TAsyncOperationController.AddCancelHandler(const ACallback: TAsyncCoreCancelledCallback; ADispatchMode: TAsyncCallbackDispatchMode);
var
  LHandler: TCancelHandler;
  LAlreadyCancelled: Boolean;
begin
  if not Assigned(ACallback) then
    Exit;

  LHandler.Callback := ACallback;
  LHandler.DispatchMode := ADispatchMode;

  FCriticalSection.Acquire;
  try
    LAlreadyCancelled := FCancelled <> 0;
    // Final without cancellation: the handler could never run
    if not LAlreadyCancelled and not IsFinal(FState) then
      FCancelHandlers.Add(LHandler);
  finally
    FCriticalSection.Release;
  end;

  if LAlreadyCancelled then
    RunCancelHandler(LHandler);
end;

procedure TAsyncOperationController.RunCancelHandler(const AHandler: TCancelHandler);
var
  LCallback: TAsyncCoreCancelledCallback;
begin
  LCallback := AHandler.Callback;
  TAsyncCore.DispatchCallback(AHandler.DispatchMode,
    procedure
    begin
      LCallback();
    end);
end;

procedure TAsyncOperationController.OnCancelled(const ACallback: TAsyncCoreCancelledCallback);
begin
  AddCancelHandler(ACallback, FDispatchMode);
end;

procedure TAsyncOperationController.OnCancelledInline(const ACallback: TAsyncCoreCancelledCallback);
begin
  AddCancelHandler(ACallback, TAsyncCallbackDispatchMode.dmInline);
end;

procedure TAsyncOperationController.OnCompletionInline(const ACallback: TAsyncCoreFinallyCallback);
var
  LIsFinal: Boolean;
begin
  if not Assigned(ACallback) then
    Exit;

  FCriticalSection.Acquire;
  try
    LIsFinal := IsFinal(FState);
    if not LIsFinal then
      FContinuations.Add(ACallback);
  finally
    FCriticalSection.Release;
  end;

  if LIsFinal then
    TAsyncCore.DispatchCallback(TAsyncCallbackDispatchMode.dmInline, ACallback);
end;

procedure TAsyncOperationController.RemoveCompletionInline(const ACallback: TAsyncCoreFinallyCallback);
var
  I: Integer;
  LItem: TAsyncCoreFinallyCallback;
  LRemoved: TAsyncCoreFinallyCallback;
begin
  if not Assigned(ACallback) then
    Exit;

  FCriticalSection.Acquire;
  try
    for I := FContinuations.Count - 1 downto 0 do
    begin
      LItem := FContinuations[I];
      if PPointer(@LItem)^ = PPointer(@ACallback)^ then
      begin
        // Released outside the lock
        LRemoved := LItem;
        FContinuations.Delete(I);
        Break;
      end;
    end;
  finally
    FCriticalSection.Release;
  end;
end;

procedure TAsyncOperationController.OnCompletion(const ACallback: TAsyncCoreFinallyCallback);
var
  LIsFinal: Boolean;
begin
  if not Assigned(ACallback) then
    Exit;

  FCriticalSection.Acquire;
  try
    LIsFinal := IsFinal(FState);
    if not LIsFinal then
      FCompletionCallbacks.Add(ACallback);
  finally
    FCriticalSection.Release;
  end;

  if LIsFinal then
    TAsyncCore.DispatchCallback(FDispatchMode, ACallback);
end;

function TAsyncOperationController.WaitSignaled(ATimeout: Cardinal): Boolean;
var
  LStopwatch: TStopwatch;
  LSlice: Int64;
begin
  if IsFinal(GetState) then
    Exit(True);

  if TThread.Current.ThreadID <> MainThreadID then
    Exit(FCompletionEvent.WaitFor(ATimeout) = wrSignaled);

  // The callbacks of the operation may need the main thread: keep serving them
  LStopwatch := TStopwatch.StartNew;
  repeat
    LSlice := MAIN_THREAD_WAIT_SLICE_MS;
    if ATimeout <> INFINITE then
      LSlice := Min(LSlice, Int64(ATimeout) - LStopwatch.ElapsedMilliseconds);
    if LSlice > 0 then
      CheckSynchronize(Integer(LSlice));
    Result := FCompletionEvent.WaitFor(0) = wrSignaled;
  until Result or ((ATimeout <> INFINITE) and (LStopwatch.ElapsedMilliseconds >= ATimeout));
end;

function TAsyncOperationController.WaitForCompletion(ATimeout: Cardinal; ARaiseOnError: Boolean): TAsyncOperationState;
var
  LException: Exception;
begin
  if not WaitSignaled(ATimeout) then
    raise EAsyncTimeoutException.Create('Operation timed out');

  FCriticalSection.Acquire;
  try
    Result := FState;
    LException := FException;
  finally
    FCriticalSection.Release;
  end;

  // FException is set once and lives as long as the operation: copy it outside the lock
  if ARaiseOnError and (Result = TAsyncOperationState.Faulted) and Assigned(LException) then
    raise TAsyncCore.CloneException(LException);
end;

function TAsyncOperationController.GetState: TAsyncOperationState;
begin
  FCriticalSection.Acquire;
  try
    Result := FState;
  finally
    FCriticalSection.Release;
  end;
end;

procedure TAsyncOperationController.SetRunning;
begin
  FCriticalSection.Acquire;
  try
    if FState = TAsyncOperationState.Pending then
      FState := TAsyncOperationState.Running;
  finally
    FCriticalSection.Release;
  end;
end;

function TAsyncOperationController.TryComplete(AState: TAsyncOperationState; AException: Exception): Boolean;
begin
  Assert(IsFinal(AState));
  if (AState = TAsyncOperationState.Faulted) and not Assigned(AException) then
    AException := EAsyncException.Create('Operation faulted without exception information');

  FCriticalSection.Acquire;
  try
    Result := not IsFinal(FState);
    if Result then
    begin
      FState := AState;
      if AState = TAsyncOperationState.Faulted then
      begin
        FException := AException;
        AException := nil;
      end;
    end;
  finally
    FCriticalSection.Release;
  end;

  AException.Free;
end;

procedure TAsyncOperationController.SignalCompletion;
var
  LCallbacks: TArray<TAsyncCoreFinallyCallback>;
  LContinuations: TArray<TAsyncCoreFinallyCallback>;
  LCallback: TAsyncCoreFinallyCallback;
begin
  FCriticalSection.Acquire;
  try
    if FSignalled then
      Exit;

    FSignalled := True;
    LCallbacks := FCompletionCallbacks.ToArray;
    FCompletionCallbacks.Clear;
    LContinuations := FContinuations.ToArray;
    FContinuations.Clear;
    // Cancellation is no longer possible: release what the handlers captured
    FCancelHandlers.Clear;
  finally
    FCriticalSection.Release;
  end;

  try
    for LCallback in LCallbacks do
      TAsyncCore.DispatchCallback(FDispatchMode, LCallback);
  finally
    FCompletionEvent.SetEvent;
  end;

  // After the waiters: a continuation blocked on its own callbacks does not hold them
  for LCallback in LContinuations do
    TAsyncCore.DispatchCallback(TAsyncCallbackDispatchMode.dmInline, LCallback);
end;

procedure TAsyncOperationController.DispatchException(const ACallback: TAsyncCoreErrorCallback);
var
  LOwner: IAsyncOperation;
begin
  LOwner := Self;
  TAsyncCore.DispatchCallback(FDispatchMode,
    procedure
    begin
      ACallback((LOwner as TAsyncOperationController).FException);
    end);
end;

function TAsyncOperationController.GetException: Exception;
var
  LException: Exception;
begin
  FCriticalSection.Acquire;
  try
    LException := FException;
  finally
    FCriticalSection.Release;
  end;

  Result := TAsyncCore.CloneException(LException);
end;

{ TAsyncOperationController<T> }

function TAsyncOperationController<T>.TrySetResult(const AValue: T): Boolean;
begin
  FCriticalSection.Acquire;
  try
    Result := not IsFinal(FState);
    if Result then
    begin
      FResult := AValue;
      FHasResult := True;
      FState := TAsyncOperationState.Completed;
    end;
  finally
    FCriticalSection.Release;
  end;
end;

function TAsyncOperationController<T>.WaitForResult(ATimeout: Cardinal): T;
begin
  case WaitForCompletion(ATimeout, True) of
    TAsyncOperationState.Completed:
      if not TryGetResult(Result) then
        raise EAsyncException.Create('Operation completed without a result');
    TAsyncOperationState.Cancelled:
      raise EAsyncCancelException.Create;
  else
    raise EAsyncException.Create('Unexpected operation state');
  end;
end;

function TAsyncOperationController<T>.TryWaitForResult(ATimeout: Cardinal; out AResult: T): Boolean;
begin
  if TryGetResult(AResult) then
    Exit(True);

  // No exception on timeout: polling loops would flood the debugger with them
  WaitSignaled(ATimeout);
  Result := TryGetResult(AResult);
end;

function TAsyncOperationController<T>.TryGetResult(out AResult: T): Boolean;
begin
  FCriticalSection.Acquire;
  try
    Result := FHasResult and (FState = TAsyncOperationState.Completed);
    if Result then
      AResult := FResult;
  finally
    FCriticalSection.Release;
  end;
end;

{ TAsyncCore }

class procedure TAsyncCore.DispatchCallback(ADispatchMode: TAsyncCallbackDispatchMode; const ACallback: TAsyncCoreFinallyCallback);
var
  LGuarded: TThreadProcedure;
begin
  if not Assigned(ACallback) then
    Exit;

  // A failing callback never reaches the dispatching thread nor changes the operation
  LGuarded :=
    procedure
    begin
      try
        ACallback();
      except
        on E: Exception do
          if not ReportUnhandledError(E) and Assigned(ApplicationHandleException) and
            (TThread.Current.ThreadID = MainThreadID) then
            ApplicationHandleException(nil);
      end;
    end;

  case ADispatchMode of
    TAsyncCallbackDispatchMode.dmQueue:
      // Queue runs at once on the main thread: e.g. inside a Cancel called by the UI
      TThread.ForceQueue(nil, LGuarded);
    TAsyncCallbackDispatchMode.dmSynchronize:
      TThread.Synchronize(nil, LGuarded);
    TAsyncCallbackDispatchMode.dmInline:
      LGuarded();
  end;
end;

class procedure TAsyncCore.AddContinuation(const AOperation: IAsyncOperation; const AContinuation: TAsyncCoreFinallyCallback);
var
  LObject: TObject;
begin
  LObject := AOperation as TObject;
  if LObject is TAsyncOperationController then
    TAsyncOperationController(LObject).OnCompletionInline(AContinuation)
  else
    AOperation.OnCompletion(AContinuation); // foreign implementation: its own dispatch
end;

class procedure TAsyncCore.RemoveContinuation(const AOperation: IAsyncOperation; const AContinuation: TAsyncCoreFinallyCallback);
var
  LObject: TObject;
begin
  // A foreign implementation keeps the continuation until it completes
  LObject := AOperation as TObject;
  if LObject is TAsyncOperationController then
    TAsyncOperationController(LObject).RemoveCompletionInline(AContinuation);
end;

class function TAsyncCore.ScheduleTimer(ADelayMs: Cardinal; const ACallback: TProc): Int64;
begin
  Result := GTimers.Schedule(ADelayMs, ACallback);
end;

class function TAsyncCore.CancelTimer(AId: Int64): Boolean;
begin
  Result := GTimers.Cancel(AId);
end;

class procedure TAsyncCore.AddCancelHandler(const AOperation: IAsyncOperation; const AHandler: TAsyncCoreCancelledCallback);
var
  LObject: TObject;
begin
  LObject := AOperation as TObject;
  if LObject is TAsyncOperationController then
    TAsyncOperationController(LObject).OnCancelledInline(AHandler)
  else
    AOperation.OnCancelled(AHandler);
end;

class function TAsyncCore.ReportUnhandledError(AException: Exception): Boolean;
var
  LHandler: TAsyncCoreErrorCallback;
begin
  LHandler := FOnUnhandledError;
  Result := Assigned(LHandler);
  if Result then
  try
    LHandler(AException);
  except
    // A failing error handler is ignored: there is nowhere left to report it
  end;
end;

class function TAsyncCore.CloneException(ASource: Exception): Exception;
var
  LClass: TClass;
  LCloner: TAsyncExceptionCloner;
begin
  if not Assigned(ASource) then
    Exit(nil);

  LCloner := nil;
  GClonerLock.Acquire;
  try
    LClass := ASource.ClassType;
    while Assigned(LClass) and not GCloners.TryGetValue(LClass, LCloner) do
      LClass := LClass.ClassParent;
  finally
    GClonerLock.Release;
  end;

  Result := nil;
  if Assigned(LCloner) then
  try
    Result := LCloner(ASource);
  except
    Result := nil;
  end;

  if not Assigned(Result) then
  begin
    // Exception constructors are not virtual: only class and message survive
    Result := ExceptClass(ASource.ClassType).Create(ASource.Message);
    Result.HelpContext := ASource.HelpContext;
  end;
end;

class procedure TAsyncCore.RegisterExceptionCloner(AClass: ExceptClass; const ACloner: TAsyncExceptionCloner);
begin
  GClonerLock.Acquire;
  try
    if Assigned(ACloner) then
      GCloners.AddOrSetValue(AClass, ACloner)
    else
      GCloners.Remove(AClass);
  finally
    GClonerLock.Release;
  end;
end;

class function TAsyncCore.RetryDelay(AStrategy: TBackoffStrategy; AInitialDelay, AMaxDelay: Cardinal; AAttempt: Integer): Cardinal;
var
  LDelay: UInt64;
begin
  // 64-bit arithmetic: no overflow, and no division, for any input
  case AStrategy of
    TBackoffStrategy.Linear:
      LDelay := UInt64(AInitialDelay) * UInt64(AAttempt + 1);
    TBackoffStrategy.Exponential, TBackoffStrategy.ExponentialJitter:
      LDelay := UInt64(AInitialDelay) shl Min(AAttempt, 31);
  else
    LDelay := AInitialDelay;
  end;

  if LDelay > AMaxDelay then
    LDelay := AMaxDelay;

  // Equal jitter: at least half of the delay, the rest random
  if AStrategy = TBackoffStrategy.ExponentialJitter then
    LDelay := LDelay div 2 + NextRandom mod (LDelay - LDelay div 2 + 1);

  Result := Cardinal(LDelay);
end;

class function TAsyncCore.Run<T>(OnAsyncTask: TAsyncCoreFunctionTask<T>; OnSuccess: TAsyncCoreSuccessCallback<T>; OnError: TAsyncCoreErrorCallback; OnFinally: TAsyncCoreFinallyCallback; ADispatchMode: TAsyncCallbackDispatchMode): IAsyncOperation<T>;
var
  LController: TAsyncOperationController<T>;
  LOperation: IAsyncOperation<T>;
begin
  LController := TAsyncOperationController<T>.Create(ADispatchMode);
  // Captured by the task: keeps the controller alive until the task has finished
  LOperation := LController;

  TTask.Run(
    procedure
    var
      LTaskResult: T;
      LSucceeded: Boolean;
    begin
      try
        if LController.IsCancellationRequested then
        begin
          LController.TryComplete(TAsyncOperationState.Cancelled);
          Exit;
        end;

        LController.SetRunning;
        LSucceeded := False;
        try
          LTaskResult := OnAsyncTask(LOperation);
          LSucceeded := LController.TrySetResult(LTaskResult);
        except
          on EAsyncCancelException do
            LController.TryComplete(TAsyncOperationState.Cancelled);
          on Exception do
            SetFaulted(LController, Exception(AcquireExceptionObject), OnError);
        end;

        // Outside the try: a failing OnSuccess cannot turn a completed operation into a faulted one
        if LSucceeded and Assigned(OnSuccess) then
          DispatchCallback(ADispatchMode,
            procedure
            begin
              OnSuccess(LTaskResult);
            end);
      finally
        LController.SignalCompletion;
        DispatchCallback(ADispatchMode, OnFinally);
      end;
    end);

  Result := LOperation;
end;

class procedure TAsyncCore.SetFaulted(AController: TAsyncOperationController; AException: Exception;
  const OnError: TAsyncCoreErrorCallback);
var
  LErrorHandler: TAsyncCoreErrorCallback;
begin
  if not AController.TryComplete(TAsyncOperationState.Faulted, AException) then
    Exit;

  LErrorHandler := OnError;
  if not Assigned(LErrorHandler) then
    LErrorHandler := FOnUnhandledError;
  if Assigned(LErrorHandler) then
    AController.DispatchException(LErrorHandler);
end;

class function TAsyncCore.Follow<T>(const ASource: IAsyncOperation<T>; OnSuccess: TAsyncCoreSuccessCallback<T>;
  OnError: TAsyncCoreErrorCallback; OnFinally: TAsyncCoreFinallyCallback;
  ADispatchMode: TAsyncCallbackDispatchMode): IAsyncOperation<T>;
var
  LController: TAsyncOperationController<T>;
  LOperation: IAsyncOperation<T>;
begin
  LController := TAsyncOperationController<T>.Create(ADispatchMode);
  // Captured by the continuation: keeps the controller alive until the source has completed
  LOperation := LController;
  LController.SetRunning;

  // As for a task, the producer of the source decides how to end it
  AddCancelHandler(LOperation,
    procedure
    begin
      ASource.Cancel;
    end);

  AddContinuation(ASource,
    procedure
    begin
      // Not on the completing thread: it may be the main thread inside Cancel or a destructor
      TTask.Run(
        procedure
        var
          LFollower: TAsyncOperationController<T>;
          LValue: T;
          LSucceeded: Boolean;
        begin
          LFollower := LOperation as TAsyncOperationController<T>;
          LSucceeded := False;
          try
            case ASource.State of
              TAsyncOperationState.Completed:
                if ASource.TryGetResult(LValue) then
                  LSucceeded := LFollower.TrySetResult(LValue)
                else
                  SetFaulted(LFollower, EAsyncException.Create('Operation completed without a result'), OnError);
              TAsyncOperationState.Faulted:
                SetFaulted(LFollower, ASource.GetException, OnError);
            else
              LFollower.TryComplete(TAsyncOperationState.Cancelled);
            end;

            if LSucceeded and Assigned(OnSuccess) then
              DispatchCallback(ADispatchMode,
                procedure
                begin
                  OnSuccess(LValue);
                end);
          finally
            LFollower.SignalCompletion;
            DispatchCallback(ADispatchMode, OnFinally);
          end;
        end);
    end);

  Result := LOperation;
end;

class function TAsyncCore.Run(OnAsyncTask: TAsyncCoreProcedureTask; OnSuccess: TAsyncCoreProcedureSuccessCallback; OnError: TAsyncCoreErrorCallback; OnFinally: TAsyncCoreFinallyCallback; ADispatchMode: TAsyncCallbackDispatchMode): IAsyncOperation;

  function DefaultOnSuccess: TAsyncCoreSuccessCallback<Boolean>;
  begin
    Result := procedure(const AValue: Boolean)
    begin
      OnSuccess();
    end;
  end;

var
  LSuccessCallback: TAsyncCoreSuccessCallback<Boolean>;
begin
  if Assigned(OnSuccess) then
    LSuccessCallback := DefaultOnSuccess()
  else
    LSuccessCallback := nil;

  Result := TAsyncCore.Run<Boolean>(
    function(const AController: IAsyncOperation): Boolean
    begin
      OnAsyncTask(AController);
      Result := True;
    end,
    LSuccessCallback,
    OnError,
    OnFinally,
    ADispatchMode);
end;

class function TAsyncCore.New<T>(const ATask: TAsyncCoreFunctionTask<T>): IAsyncPromise<T>;
begin
  Result := TAsyncCorePromise<T>.Create(ATask);
end;

class function TAsyncCore.New(const ATask: TAsyncCoreProcedureTask): IAsyncVoidPromise;
begin
  Result := TAsyncCoreVoidPromise.Create(ATask);
end;

class function TAsyncCore.FromOperation<T>(const AOperation: IAsyncOperation<T>): IAsyncPromise<T>;
begin
  if not Assigned(AOperation) then
    raise EArgumentNilException.Create('AsyncCore: Operation not assigned');
  Result := TAsyncCorePromise<T>.CreateFromOperation(AOperation);
end;

{ TAsyncTaskCompletionSource<T> }

constructor TAsyncTaskCompletionSource<T>.Create(ADispatchMode: TAsyncCallbackDispatchMode);
begin
  inherited Create;
  FController := TAsyncOperationController<T>.Create(ADispatchMode);
  FOperation := FController;
end;

procedure TAsyncTaskCompletionSource<T>.SetResult(const AValue: T);
begin
  if not TrySetResult(AValue) then
    raise EAsyncException.Create('TaskCompletionSource already completed');
end;

procedure TAsyncTaskCompletionSource<T>.SetException(AException: Exception);
begin
  if not TrySetException(AException) then
    raise EAsyncException.Create('TaskCompletionSource already completed');
end;

procedure TAsyncTaskCompletionSource<T>.SetCancelled;
begin
  if not TrySetCancelled then
    raise EAsyncException.Create('TaskCompletionSource already completed');
end;

function TAsyncTaskCompletionSource<T>.TrySetResult(const AValue: T): Boolean;
begin
  Result := FController.TrySetResult(AValue);
  if Result then
    FController.SignalCompletion;
end;

function TAsyncTaskCompletionSource<T>.TrySetException(AException: Exception): Boolean;
begin
  Result := FController.TryComplete(TAsyncOperationState.Faulted, AException);
  if Result then
    FController.SignalCompletion;
end;

function TAsyncTaskCompletionSource<T>.TrySetCancelled: Boolean;
begin
  Result := FController.TryComplete(TAsyncOperationState.Cancelled);
  if Result then
    FController.SignalCompletion;
end;

function TAsyncTaskCompletionSource<T>.GetOperation: IAsyncOperation<T>;
begin
  Result := FOperation;
end;

{ TAsyncTaskCompletionSource }

constructor TAsyncTaskCompletionSource.Create(ADispatchMode: TAsyncCallbackDispatchMode);
begin
  inherited Create;
  FController := TAsyncOperationController.Create(ADispatchMode);
  FOperation := FController;
end;

procedure TAsyncTaskCompletionSource.SetResult;
begin
  if not TrySetResult then
    raise EAsyncException.Create('TaskCompletionSource already completed');
end;

procedure TAsyncTaskCompletionSource.SetException(AException: Exception);
begin
  if not TrySetException(AException) then
    raise EAsyncException.Create('TaskCompletionSource already completed');
end;

procedure TAsyncTaskCompletionSource.SetCancelled;
begin
  if not TrySetCancelled then
    raise EAsyncException.Create('TaskCompletionSource already completed');
end;

function TAsyncTaskCompletionSource.TrySetResult: Boolean;
begin
  Result := FController.TryComplete(TAsyncOperationState.Completed);
  if Result then
    FController.SignalCompletion;
end;

function TAsyncTaskCompletionSource.TrySetException(AException: Exception): Boolean;
begin
  Result := FController.TryComplete(TAsyncOperationState.Faulted, AException);
  if Result then
    FController.SignalCompletion;
end;

function TAsyncTaskCompletionSource.TrySetCancelled: Boolean;
begin
  Result := FController.TryComplete(TAsyncOperationState.Cancelled);
  if Result then
    FController.SignalCompletion;
end;

function TAsyncTaskCompletionSource.GetOperation: IAsyncOperation;
begin
  Result := FOperation;
end;

{ TAsyncCorePromise<T> }

constructor TAsyncCorePromise<T>.Create(const ATask: TAsyncCoreFunctionTask<T>);
begin
  inherited Create;
  FTask := ATask;
  FDispatchMode := TAsyncCallbackDispatchMode.dmSynchronize;
end;

constructor TAsyncCorePromise<T>.CreateFromOperation(const ASource: IAsyncOperation<T>);
begin
  inherited Create;
  FSource := ASource;
  FDispatchMode := TAsyncCallbackDispatchMode.dmSynchronize;
end;

function TAsyncCorePromise<T>.OnSuccess(const ACallback: TAsyncCoreSuccessCallback<T>): IAsyncPromise<T>;
begin
  FOnSuccess := ACallback;
  Result := Self;
end;

function TAsyncCorePromise<T>.DispatchMode(const AMode: TAsyncCallbackDispatchMode): IAsyncPromise<T>;
begin
  FDispatchMode := AMode;
  Result := Self;
end;

function TAsyncCorePromise<T>.OnError(const ACallback: TAsyncCoreErrorCallback): IAsyncPromise<T>;
begin
  FOnError := ACallback;
  Result := Self;
end;

function TAsyncCorePromise<T>.OnFinally(const ACallback: TAsyncCoreFinallyCallback): IAsyncPromise<T>;
begin
  FOnFinally := ACallback;
  Result := Self;
end;

function TAsyncCorePromise<T>.Run: IAsyncOperation<T>;
begin
  if Assigned(FSource) then
    Exit(TAsyncCore.Follow<T>(FSource, FOnSuccess, FOnError, FOnFinally, FDispatchMode));

  if not Assigned(FTask) then
    raise EArgumentNilException.Create('AsyncCore: Task not assigned');
  Result := TAsyncCore.Run<T>(FTask, FOnSuccess, FOnError, FOnFinally, FDispatchMode);
end;

{ TAsyncCoreVoidPromise }

constructor TAsyncCoreVoidPromise.Create(const ATask: TAsyncCoreProcedureTask);
begin
  inherited Create;
  FTask := ATask;
  FDispatchMode := TAsyncCallbackDispatchMode.dmSynchronize;
end;

function TAsyncCoreVoidPromise.OnSuccess(const ACallback: TAsyncCoreProcedureSuccessCallback): IAsyncVoidPromise;
begin
  FOnSuccess := ACallback;
  Result := Self;
end;

function TAsyncCoreVoidPromise.DispatchMode(const AMode: TAsyncCallbackDispatchMode): IAsyncVoidPromise;
begin
  FDispatchMode := AMode;
  Result := Self;
end;

function TAsyncCoreVoidPromise.OnError(const ACallback: TAsyncCoreErrorCallback): IAsyncVoidPromise;
begin
  FOnError := ACallback;
  Result := Self;
end;

function TAsyncCoreVoidPromise.OnFinally(const ACallback: TAsyncCoreFinallyCallback): IAsyncVoidPromise;
begin
  FOnFinally := ACallback;
  Result := Self;
end;

function TAsyncCoreVoidPromise.Run: IAsyncOperation;
begin
  if not Assigned(FTask) then
    raise EArgumentNilException.Create('AsyncCore: Task not assigned');

  Result := TAsyncCore.Run(FTask, FOnSuccess, FOnError, FOnFinally, FDispatchMode);
end;

class function TAsyncCore.ContinueWith<T, TResult>(const AOperation: IAsyncOperation<T>;
  const AContinuation: TAsyncCoreContinuationFunc<T, TResult>;
  ADispatchMode: TAsyncCallbackDispatchMode): IAsyncOperation<TResult>;
var
  LCompletionSource: IAsyncTaskCompletionSource<TResult>;
begin
  LCompletionSource := TAsyncTaskCompletionSource<TResult>.Create(ADispatchMode);

  AddCancelHandler(LCompletionSource.Operation,
    procedure
    begin
      LCompletionSource.TrySetCancelled;
      AOperation.Cancel;
    end);

  AddContinuation(AOperation,
    procedure
    begin
      case AOperation.State of
        TAsyncOperationState.Completed:
          // The continuation may be slow: not on the completing thread
          TTask.Run(
            procedure
            var
              LValue: T;
            begin
              if LCompletionSource.Operation.State <> TAsyncOperationState.Pending then
                Exit; // cancelled in the meantime

              try
                if AOperation.TryGetResult(LValue) then
                  LCompletionSource.TrySetResult(AContinuation(LValue))
                else
                  LCompletionSource.TrySetException(EAsyncException.Create('Failed to get result from completed operation'));
              except
                on EAsyncCancelException do
                  LCompletionSource.TrySetCancelled;
                on Exception do
                  LCompletionSource.TrySetException(Exception(AcquireExceptionObject));
              end;
            end);

        TAsyncOperationState.Faulted:
          LCompletionSource.TrySetException(AOperation.GetException);

        TAsyncOperationState.Cancelled:
          LCompletionSource.TrySetCancelled;
      end;
    end);

  Result := LCompletionSource.Operation;
end;

class function TAsyncCore.WhenAll<T>(const AOperations: array of IAsyncOperation<T>;
  ADispatchMode: TAsyncCallbackDispatchMode): IAsyncOperation<TArray<T>>;
var
  LCompletionSource: IAsyncTaskCompletionSource<TArray<T>>;
  LCount: Integer;
  LTotal: Integer;
  LOperationsCopy: TArray<IAsyncOperation<T>>;
  LIndex: Integer;
begin
  LCompletionSource := TAsyncTaskCompletionSource<TArray<T>>.Create(ADispatchMode);

  LTotal := Length(AOperations);
  if LTotal = 0 then
  begin
    LCompletionSource.SetResult([]);
    Exit(LCompletionSource.Operation);
  end;

  LCount := LTotal;

  SetLength(LOperationsCopy, LTotal);
  for LIndex := 0 to LTotal - 1 do
    LOperationsCopy[LIndex] := AOperations[LIndex];

  AddCancelHandler(LCompletionSource.Operation,
    procedure
    var
      LOp: IAsyncOperation<T>;
    begin
      LCompletionSource.TrySetCancelled;
      for LOp in LOperationsCopy do
        LOp.Cancel;
    end);

  for LIndex := 0 to LTotal - 1 do
  begin
    (procedure(AIndex: Integer)
      var
        LOp: IAsyncOperation<T>;
      begin
        LOp := LOperationsCopy[AIndex];

        AddContinuation(LOp,
          procedure
          var
            LResults: TArray<T>;
            LResultIndex: Integer;
            LResultVal: T;
          begin
            if LOp.State = TAsyncOperationState.Faulted then
              LCompletionSource.TrySetException(LOp.GetException)
            else if LOp.State = TAsyncOperationState.Cancelled then
              LCompletionSource.TrySetCancelled;

            if (TInterlocked.Decrement(LCount) = 0) and
              (LCompletionSource.Operation.State = TAsyncOperationState.Pending) then
            begin
              SetLength(LResults, LTotal);
              try
                for LResultIndex := 0 to LTotal - 1 do
                begin
                  if not LOperationsCopy[LResultIndex].TryGetResult(LResultVal) then
                  begin
                    LCompletionSource.TrySetException(EAsyncException.Create('WhenAll: an operation completed without a result'));
                    Exit;
                  end;
                  LResults[LResultIndex] := LResultVal;
                end;
                LCompletionSource.TrySetResult(LResults);
              except
                on Exception do
                  LCompletionSource.TrySetException(Exception(AcquireExceptionObject));
              end;
            end;
          end);
      end)(LIndex);
  end;

  Result := LCompletionSource.Operation;
end;

class function TAsyncCore.WhenAny<T>(const AOperations: array of IAsyncOperation<T>;
  ADispatchMode: TAsyncCallbackDispatchMode): IAsyncOperation<T>;
var
  LCompletionSource: IAsyncTaskCompletionSource<T>;
  LOperationsCopy: TArray<IAsyncOperation<T>>;
  LTotal: Integer;
  LIndex: Integer;
begin
  LCompletionSource := TAsyncTaskCompletionSource<T>.Create(ADispatchMode);

  LTotal := Length(AOperations);
  if LTotal = 0 then
  begin
    LCompletionSource.SetException(EAsyncException.Create('WhenAny requires at least one operation'));
    Exit(LCompletionSource.Operation);
  end;

  SetLength(LOperationsCopy, LTotal);
  for LIndex := 0 to LTotal - 1 do
    LOperationsCopy[LIndex] := AOperations[LIndex];

  AddCancelHandler(LCompletionSource.Operation,
    procedure
    var
      LOp: IAsyncOperation<T>;
    begin
      LCompletionSource.TrySetCancelled;
      for LOp in LOperationsCopy do
        LOp.Cancel;
    end);

  for LIndex := 0 to LTotal - 1 do
  begin
    (procedure(AIndex: Integer)
      var
        LOp: IAsyncOperation<T>;
      begin
        LOp := LOperationsCopy[AIndex];
        AddContinuation(LOp,
          procedure
          var
            LRes: T;
          begin
            case LOp.State of
              TAsyncOperationState.Completed:
                if LOp.TryGetResult(LRes) then
                  LCompletionSource.TrySetResult(LRes);
              TAsyncOperationState.Faulted:
                LCompletionSource.TrySetException(LOp.GetException);
              TAsyncOperationState.Cancelled:
                LCompletionSource.TrySetCancelled;
            end;
          end);
      end)(LIndex);
  end;

  Result := LCompletionSource.Operation;
end;

{ TAsyncRetryOperation<T> }

constructor TAsyncRetryOperation<T>.Create(const ATask: TAsyncCoreFunctionTask<T>; AMaxRetries: Integer;
  AInitialDelay: Cardinal; AStrategy: TBackoffStrategy; AMaxDelay: Cardinal; const AShouldRetry: TAsyncCoreRetryPredicate;
  ADispatchMode: TAsyncCallbackDispatchMode);
begin
  inherited Create(ADispatchMode);
  FTask := ATask;
  FShouldRetry := AShouldRetry;
  FMaxRetries := AMaxRetries;
  FInitialDelay := AInitialDelay;
  FMaxDelay := AMaxDelay;
  FStrategy := AStrategy;
end;

// Keeps the operation alive until the attempt has run
function TAsyncRetryOperation<T>.AttemptProc: TProc;
var
  LOperation: IAsyncOperation;
begin
  LOperation := Self;
  Result :=
    procedure
    begin
      (LOperation as TAsyncRetryOperation<T>).RunAttempt;
    end;
end;

function TAsyncRetryOperation<T>.FinishProc: TProc;
var
  LOperation: IAsyncOperation;
begin
  LOperation := Self;
  Result :=
    procedure
    begin
      (LOperation as TAsyncRetryOperation<T>).Finish;
    end;
end;

// Stored in the operation: it captures Self, not an interface, or a pending retry would never be freed
function TAsyncRetryOperation<T>.CancelHandler: TAsyncCoreCancelledCallback;
begin
  Result :=
    procedure
    begin
      CancelWait;
    end;
end;

procedure TAsyncRetryOperation<T>.Start;
begin
  OnCancelledInline(CancelHandler());
  TTask.Run(AttemptProc());
end;

procedure TAsyncRetryOperation<T>.RunAttempt;
var
  LOperation: IAsyncOperation<T>;
  LValue: T;
  LState: TAsyncOperationState;
  LError: Exception;
begin
  LValue := Default(T);
  LError := nil;
  // A Cancel that came first wins, even if the timer fired in the meantime
  if IsCancellationRequested then
    LState := TAsyncOperationState.Cancelled
  else
  begin
    SetRunning;
    // The reference returned by RunWithRetry
    LOperation := Self;
    try
      try
        LValue := FTask(LOperation);
        LState := TAsyncOperationState.Completed;
      except
        on EAsyncCancelException do
          LState := TAsyncOperationState.Cancelled;
        on E: Exception do
          if IsCancellationRequested then
            LState := TAsyncOperationState.Cancelled
          else if (FAttempt < FMaxRetries) and (not Assigned(FShouldRetry) or FShouldRetry(E)) then
            LState := TAsyncOperationState.Running // retried after the delay
          else
          begin
            LError := Exception(AcquireExceptionObject);
            LState := TAsyncOperationState.Faulted;
          end;
      end;
    except
      // Raised by AShouldRetry
      on EAsyncCancelException do
        LState := TAsyncOperationState.Cancelled;
      on Exception do
      begin
        LError := Exception(AcquireExceptionObject);
        LState := TAsyncOperationState.Faulted;
      end;
    end;
  end;

  if LState = TAsyncOperationState.Running then
  begin
    if ScheduleRetry then
      Exit; // the timer runs the next attempt
    LState := TAsyncOperationState.Cancelled;
  end;

  case LState of
    TAsyncOperationState.Completed:
      TrySetResult(LValue);
    TAsyncOperationState.Faulted:
      TAsyncCore.SetFaulted(Self, LError, nil);
  else
    TryComplete(TAsyncOperationState.Cancelled);
  end;
  Finish;
end;

// False if a Cancel came first: then no timer is scheduled
function TAsyncRetryOperation<T>.ScheduleRetry: Boolean;
var
  LDelay: Cardinal;
  LAttempt: TProc;
begin
  LDelay := TAsyncCore.RetryDelay(FStrategy, FInitialDelay, FMaxDelay, FAttempt);
  Inc(FAttempt);
  LAttempt := AttemptProc();
  FCriticalSection.Acquire;
  try
    // Under the lock of CancelWait: either Cancel finds the timer or it is not scheduled
    Result := not IsCancellationRequested;
    if Result then
      FTimer := TAsyncCore.ScheduleTimer(LDelay, LAttempt);
  finally
    FCriticalSection.Release;
  end;
end;

procedure TAsyncRetryOperation<T>.CancelWait;
var
  LTimer: Int64;
begin
  FCriticalSection.Acquire;
  try
    LTimer := FTimer;
    FTimer := 0;
  finally
    FCriticalSection.Release;
  end;

  // A timer that already fired is not found: its attempt sees the cancellation.
  // Otherwise cancelled at once; the callbacks run on a pool thread, never inside Cancel
  if TAsyncCore.CancelTimer(LTimer) and TryComplete(TAsyncOperationState.Cancelled) then
    TTask.Run(FinishProc());
end;

procedure TAsyncRetryOperation<T>.Finish;
begin
  // Released at once, as Run does: the task may reference the operation
  FTask := nil;
  FShouldRetry := nil;
  SignalCompletion;
end;

class function TAsyncCore.RunWithRetry<T>(
  ATask: TAsyncCoreFunctionTask<T>;
  AMaxRetries: Integer;
  AInitialDelay: Cardinal;
  ABackoffStrategy: TBackoffStrategy;
  AMaxDelay: Cardinal;
  AShouldRetry: TAsyncCoreRetryPredicate;
  ADispatchMode: TAsyncCallbackDispatchMode): IAsyncOperation<T>;
var
  LOperation: TAsyncRetryOperation<T>;
begin
  if AMaxRetries < 0 then
    raise EArgumentOutOfRangeException.Create('AsyncCore: AMaxRetries must be zero or positive');

  LOperation := TAsyncRetryOperation<T>.Create(ATask, AMaxRetries, AInitialDelay, ABackoffStrategy, AMaxDelay,
    AShouldRetry, ADispatchMode);
  Result := LOperation;
  LOperation.Start;
end;

class function TAsyncCore.RunWithTimeout<T>(
  ATask: TAsyncCoreFunctionTask<T>;
  ATimeoutMs: Cardinal;
  ADispatchMode: TAsyncCallbackDispatchMode): IAsyncOperation<T>;
var
  LCompletionSource: IAsyncTaskCompletionSource<T>;
  LActualTask: IAsyncOperation<T>;
  LTimer: Int64;
begin
  LCompletionSource := TAsyncTaskCompletionSource<T>.Create(ADispatchMode);

  // The OnCancelled callbacks of the task run on a pool thread at timeout: same mode as the result
  LActualTask := TAsyncCore.Run<T>(ATask, nil, nil, nil, ADispatchMode);

  LTimer := ScheduleTimer(ATimeoutMs,
    procedure
    begin
      if LCompletionSource.TrySetException(EAsyncTimeoutException.Create(Format('Operation timed out after %d ms', [ATimeoutMs]))) then
        LActualTask.Cancel;
    end);

  AddCancelHandler(LCompletionSource.Operation,
    procedure
    begin
      CancelTimer(LTimer);
      LCompletionSource.TrySetCancelled;
      LActualTask.Cancel;
    end);

  AddContinuation(LActualTask,
    procedure
    var
      LRes: T;
    begin
      // The timer is disposed as soon as the task is done
      CancelTimer(LTimer);

      case LActualTask.State of
        TAsyncOperationState.Completed:
          if LActualTask.TryGetResult(LRes) then
            LCompletionSource.TrySetResult(LRes);

        TAsyncOperationState.Faulted:
          LCompletionSource.TrySetException(LActualTask.GetException);

        TAsyncOperationState.Cancelled:
          LCompletionSource.TrySetCancelled;
      end;
    end);

  Result := LCompletionSource.Operation;
end;

// Runs on a pool thread when the timer of a delay fires
function DelayFired(const AOperation: IAsyncOperation): TProc;
begin
  Result :=
    procedure
    var
      LController: TAsyncOperationController;
    begin
      LController := AOperation as TAsyncOperationController;
      // A Cancel that came first wins, even if the timer fired in the meantime
      if LController.IsCancellationRequested then
      begin
        if LController.TryComplete(TAsyncOperationState.Cancelled) then
          LController.SignalCompletion;
      end
      else if LController.TryComplete(TAsyncOperationState.Completed) then
        LController.SignalCompletion;
    end;
end;

function SignalLater(const AOperation: IAsyncOperation): TProc;
begin
  Result :=
    procedure
    begin
      (AOperation as TAsyncOperationController).SignalCompletion;
    end;
end;

// Stored in the controller: no interface reference to it, or a pending delay would never be freed
function DelayCancelled(AController: TAsyncOperationController; ATimer: Int64): TAsyncCoreCancelledCallback;
begin
  Result :=
    procedure
    begin
      // Cancelled at once; the callbacks run on a pool thread, never inside Cancel
      if GTimers.Cancel(ATimer) and AController.TryComplete(TAsyncOperationState.Cancelled) then
        TTask.Run(SignalLater(AController));
    end;
end;

class function TAsyncCore.Delay(AMilliseconds: Cardinal; ADispatchMode: TAsyncCallbackDispatchMode): IAsyncOperation;
var
  LController: TAsyncOperationController;
  LTimer: Int64;
begin
  LController := TAsyncOperationController.Create(ADispatchMode);
  Result := LController;
  LController.SetRunning;

  // The timer holds the operation until it fires or is cancelled; no thread waits
  LTimer := GTimers.Schedule(AMilliseconds, DelayFired(Result));
  LController.OnCancelledInline(DelayCancelled(LController, LTimer));
end;

class function TAsyncCore.CreateCancellationTokenWithTimeout(ATimeoutMs: Cardinal;
  ADispatchMode: TAsyncCallbackDispatchMode): IAsyncOperation;
begin
  Result := Delay(ATimeoutMs, ADispatchMode);
end;

class procedure TAsyncCore.LinkCancellationToken(const AOperation: IAsyncOperation; const ACancellationToken: IAsyncOperation);
var
  LLink: TCancellationLink;
  LReference: ICancellationLink;
begin
  if TAsyncOperationController.IsFinal(AOperation.State) then
    Exit;

  LLink := TCancellationLink.Create(AOperation, ACancellationToken);
  LReference := LLink;
  LLink.Start;
end;

class function TAsyncCore.PendingTimerCount: Integer;
begin
  Result := GTimers.Count;
end;

{ EAsyncCancelException }

constructor EAsyncCancelException.Create;
begin
  inherited Create('Asynchronous operation was cancelled');
end;

{ EAsyncTimeoutException }

constructor EAsyncTimeoutException.Create(const AMessage: string);
begin
  inherited Create(AMessage);
end;

initialization
  GClonerLock := TCriticalSection.Create;
  GCloners := TDictionary<TClass, TAsyncExceptionCloner>.Create;
  GJitterState := TStopwatch.GetTimeStamp;
  GTimers := TAsyncTimerQueue.Create;

finalization
  GTimers.Free;
  GCloners.Free;
  GClonerLock.Free;

end.
