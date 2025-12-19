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
  System.Math,
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
  ///   Defines how callbacks are dispatched to the main thread.
  /// </summary>
  /// <remarks>
  ///   <para>dmSynchronize: Blocks the worker thread until the main thread executes the callback.</para>
  ///   <para>dmQueue: Queues the callback for execution on the main thread without blocking.</para>
  /// </remarks>
  TAsyncCallbackDispatchMode = (dmSynchronize, dmQueue);

  /// <summary>
  ///   Reference-counted wrapper for TEvent to prevent use-after-free in async callbacks.
  /// </summary>
  IEventWrapper = interface
    ['{4E5E41AC-A4C4-4B06-A450-97195C9FF3A7}']
    procedure Signal;
    function WaitFor(ATimeout: Cardinal): TWaitResult;
  end;

  /// <summary>
  ///   Implementation of IEventWrapper that ensures thread-safe event lifetime management.
  /// </summary>
  TEventWrapper = class(TInterfacedObject, IEventWrapper)
  private
    FEvent: TEvent;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Signal;
    function WaitFor(ATimeout: Cardinal): TWaitResult;
  end;

  /// <summary>
  ///   Exception raised when an asynchronous operation is cancelled.
  /// </summary>
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
    Exponential);

  /// <summary>
  ///   Interface for controlling and monitoring an asynchronous operation.
  /// </summary>
  IAsyncOperation = interface
    ['{E11866CF-8245-45A3-846C-70F54DAC945E}']
    /// <summary>
    ///   Requests cancellation of the asynchronous operation.
    /// </summary>
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
    procedure OnCancelled(const ACallback: TAsyncCoreCancelledCallback);

    /// <summary>
    ///   Waits for the operation to complete.
    /// </summary>
    /// <param name="ATimeout">Timeout in milliseconds. Use INFINITE for no timeout.</param>
    /// <param name="ARaiseOnError">If True, raises exceptions for Faulted and Timeout states. Cancelled state never raises. Default: False for backward compatibility.</param>
    /// <returns>The final state of the operation.</returns>
    /// <exception cref="EAsyncTimeoutException">Raised if the timeout expires.</exception>
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
    /// <exception cref="Exception">Re-raises the exception if the operation faulted.</exception>
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
    ///   Gets the exception if the operation faulted.
    /// </summary>
    /// <returns>The exception, or nil if the operation did not fault.</returns>
    function GetException: Exception;
  end;

  TAsyncOperationController = class(TInterfacedObject, IAsyncOperation)
  private
    FCancelled: Integer;
    FCancelledCallback: TAsyncCoreCancelledCallback;
    FCriticalSection: TCriticalSection;
    FDispatchMode: TAsyncCallbackDispatchMode;
    FState: TAsyncOperationState;
    FCompletionEvent: TEvent;
    FException: Exception;
    FCompletionCallbacks: TList<TAsyncCoreFinallyCallback>;

  protected
    // IAsyncOperation
    procedure Cancel;
    function IsCancellationRequested: Boolean;
    procedure OnCancelled(const ACallback: TAsyncCoreCancelledCallback);
    procedure OnCompletion(const ACallback: TAsyncCoreFinallyCallback);
    function WaitForCompletion(ATimeout: Cardinal = INFINITE; ARaiseOnError: Boolean = False): TAsyncOperationState;
    function GetState: TAsyncOperationState;

    procedure SetState(AState: TAsyncOperationState);
    procedure SignalCompletion;
    procedure SetException(AException: Exception);
    function GetException: Exception;
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
    procedure SetResult(const AValue: T);
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
    FCompleted: Boolean;
    FCriticalSection: TCriticalSection;
    function GetOperation: IAsyncOperation<T>;
  public
    constructor Create(ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmQueue);
    destructor Destroy; override;

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
    FCompleted: Boolean;
    FCriticalSection: TCriticalSection;
    function GetOperation: IAsyncOperation;
  public
    constructor Create(ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmQueue);
    destructor Destroy; override;

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
  ///   Main entry point for creating and executing asynchronous operations.
  /// </summary>
  TAsyncCore = class sealed
  private
    class var FOnUnhandledError: TAsyncCoreErrorCallback;
    class function GetElapsedTime(AStartTime: Cardinal): Cardinal; static;
    class procedure DispatchIfAssigned(ADispatchMode: TAsyncCallbackDispatchMode; const ACallback: TAsyncCoreFinallyCallback); overload; static;
    class procedure DispatchIfAssigned<T>(ADispatchMode: TAsyncCallbackDispatchMode; const ACallback: TAsyncCoreSuccessCallback<T>; const AValue: T); overload; static;
    class procedure DispatchAcquiredException(ADispatchMode: TAsyncCallbackDispatchMode; const ACallback: TAsyncCoreErrorCallback; AException: Exception); static;
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
    ///   Creates a continuation that executes when the source operation completes successfully.
    /// </summary>
    /// <param name="AOperation">The source operation to chain from.</param>
    /// <param name="AContinuation">Function that transforms the result to a new type.</param>
    /// <returns>A new operation representing the continuation.</returns>
    /// <remarks>
    ///   If the source operation fails or is cancelled, the continuation is not executed and the error propagates.
    /// </remarks>
    class function ContinueWith<T, TResult>(const AOperation: IAsyncOperation<T>;
      const AContinuation: TAsyncCoreContinuationFunc<T, TResult>): IAsyncOperation<TResult>; static;

    /// <summary>
    ///   Waits for all operations to complete successfully.
    /// </summary>
    /// <param name="AOperations">Array of operations to wait for.</param>
    /// <returns>An operation that completes when all operations complete, returning an array of results.</returns>
    /// <remarks>
    ///   If any operation fails or is cancelled, WhenAll fails immediately with that error.
    ///   All operations execute in parallel.
    /// </remarks>
    class function WhenAll<T>(const AOperations: array of IAsyncOperation<T>): IAsyncOperation<TArray<T>>; static;

    /// <summary>
    ///   Waits for the first operation to complete.
    /// </summary>
    /// <param name="AOperations">Array of operations to race.</param>
    /// <returns>An operation that completes when the first operation completes, returning its result.</returns>
    /// <remarks>
    ///   Returns the result of the first operation that completes (success, error, or cancellation).
    ///   Other operations continue running in the background.
    /// </remarks>
    class function WhenAny<T>(const AOperations: array of IAsyncOperation<T>): IAsyncOperation<T>; static;

    /// <summary>
    ///   Executes an asynchronous task with automatic retry on failure.
    /// </summary>
    /// <param name="ATask">The task to execute.</param>
    /// <param name="AMaxRetries">Maximum number of retry attempts (0 = no retry, just one attempt).</param>
    /// <param name="AInitialDelay">Initial delay between retries in milliseconds.</param>
    /// <param name="ABackoffStrategy">Backoff strategy for calculating delays.</param>
    /// <param name="AMaxDelay">Maximum delay between retries in milliseconds (default: 30000ms = 30s).</param>
    /// <returns>An operation that completes when the task succeeds or all retries are exhausted.</returns>
    /// <remarks>
    ///   <para>Fixed: Always waits AInitialDelay between retries.</para>
    ///   <para>Linear: Delay = AInitialDelay * attempt (1x, 2x, 3x, ...).</para>
    ///   <para>Exponential: Delay = AInitialDelay * 2^attempt (1x, 2x, 4x, 8x, ...).</para>
    ///   <para>All delays are capped at AMaxDelay.</para>
    ///   <para>If all retries fail, raises the last exception encountered.</para>
    /// </remarks>
    class function RunWithRetry<T>(
      ATask: TAsyncCoreFunctionTask<T>;
      AMaxRetries: Integer = 3;
      AInitialDelay: Cardinal = 1000;
      ABackoffStrategy: TBackoffStrategy = TBackoffStrategy.Exponential;
      AMaxDelay: Cardinal = 30000): IAsyncOperation<T>; static;

    /// <summary>
    ///   Executes an asynchronous task with automatic cancellation after timeout.
    /// </summary>
    /// <param name="ATask">The task to execute.</param>
    /// <param name="ATimeoutMs">Timeout in milliseconds after which the task is automatically cancelled.</param>
    /// <returns>An operation that completes when the task finishes or is cancelled by timeout.</returns>
    /// <remarks>
    ///   <para>If the task completes before timeout, returns normally.</para>
    ///   <para>If timeout expires, the task is automatically cancelled and raises EAsyncCancelException.</para>
    ///   <para>The task should check IsCancellationRequested to respond to timeout cancellation.</para>
    /// </remarks>
    class function RunWithTimeout<T>(
      ATask: TAsyncCoreFunctionTask<T>;
      ATimeoutMs: Cardinal): IAsyncOperation<T>; static;

    /// <summary>
    ///   Creates an asynchronous delay operation.
    /// </summary>
    /// <param name="AMilliseconds">The delay duration in milliseconds.</param>
    /// <returns>An operation that completes after the specified delay.</returns>
    /// <remarks>
    ///   <para>This is a non-blocking alternative to Sleep().</para>
    ///   <para>The delay can be cancelled by calling Cancel on the returned operation.</para>
    ///   <para>Useful for testing, throttling, or introducing delays in task chains.</para>
    /// </remarks>
    class function Delay(AMilliseconds: Cardinal): IAsyncOperation; static;

    /// <summary>
    ///   Creates a cancellation token that automatically signals after a timeout.
    /// </summary>
    /// <param name="ATimeoutMs">Timeout in milliseconds before the token signals completion.</param>
    /// <returns>An operation that completes when timeout expires.</returns>
    /// <remarks>
    ///   <para>Use this to create time-based cancellation tokens.</para>
    ///   <para>Check State property to see if timeout has expired.</para>
    ///   <para>Can be combined with WhenAny to implement timeout patterns.</para>
    /// </remarks>
    class function CreateCancellationTokenWithTimeout(ATimeoutMs: Cardinal): IAsyncOperation; static;

    /// <summary>
    ///   Links a cancellation token to an operation, automatically cancelling the operation when the token completes.
    /// </summary>
    /// <param name="AOperation">The operation to monitor and cancel.</param>
    /// <param name="ACancellationToken">The token that triggers cancellation when it completes.</param>
    /// <remarks>
    ///   <para>When ACancellationToken completes, AOperation.Cancel is called automatically.</para>
    ///   <para>Useful for implementing automatic timeout cancellation.</para>
    /// </remarks>
    class procedure LinkCancellationToken(const AOperation: IAsyncOperation; const ACancellationToken: IAsyncOperation); static;

    /// <summary>
    ///   Global handler for unhandled errors in asynchronous operations.
    /// </summary>
    /// <remarks>
    ///   This callback is invoked when an error occurs and no OnError callback was registered.
    /// </remarks>
    class property OnUnhandledError: TAsyncCoreErrorCallback read FOnUnhandledError write FOnUnhandledError;
  end;

implementation

uses
  System.Classes;

{ TEventWrapper }

constructor TEventWrapper.Create;
begin
  inherited Create;
  FEvent := TEvent.Create(nil, True, False, '');
end;

destructor TEventWrapper.Destroy;
begin
  FEvent.Free;
  inherited;
end;

procedure TEventWrapper.Signal;
begin
  FEvent.SetEvent;
end;

function TEventWrapper.WaitFor(ATimeout: Cardinal): TWaitResult;
begin
  Result := FEvent.WaitFor(ATimeout);
end;

{ TAsyncCore - Helper Methods }

class function TAsyncCore.GetElapsedTime(AStartTime: Cardinal): Cardinal;
var
  LCurrentTime: Cardinal;
begin
  LCurrentTime := TThread.GetTickCount;
  if LCurrentTime >= AStartTime then
    Result := LCurrentTime - AStartTime
  else
    Result := (High(Cardinal) - AStartTime) + LCurrentTime + 1;
end;

{ TAsyncOperationController }

procedure TAsyncOperationController.Cancel;
var
  LCallback: TAsyncCoreCancelledCallback;
  LWasAlreadyCancelled: Boolean;
begin
  FCriticalSection.Acquire;
  try
    if FState in [TAsyncOperationState.Completed, TAsyncOperationState.Faulted, TAsyncOperationState.Cancelled] then
      Exit;

    LWasAlreadyCancelled := (TInterlocked.CompareExchange(FCancelled, 1, 0) = 1);
    if LWasAlreadyCancelled then
      Exit;

    LCallback := FCancelledCallback;
    FCancelledCallback := nil;
  finally
    FCriticalSection.Release;
  end;

  if Assigned(LCallback) then
  begin
    (procedure(ACapturedCallback: TAsyncCoreCancelledCallback)
      begin
        case FDispatchMode of
          TAsyncCallbackDispatchMode.dmQueue:
            TThread.Queue(nil,
              procedure
              begin
                ACapturedCallback();
              end);
          TAsyncCallbackDispatchMode.dmSynchronize:
            TThread.Synchronize(nil,
              procedure
              begin
                ACapturedCallback();
              end);
        end;
      end)(LCallback);
  end;
end;

constructor TAsyncOperationController.Create(ADispatchMode: TAsyncCallbackDispatchMode);
begin
  inherited Create;

  FCriticalSection := TCriticalSection.Create;
  FCompletionEvent := TEvent.Create;
  FCompletionCallbacks := TList<TAsyncCoreFinallyCallback>.Create;
  FDispatchMode := ADispatchMode;
  FState := TAsyncOperationState.Pending;
end;

destructor TAsyncOperationController.Destroy;
begin
  FCancelledCallback := nil;

  if Assigned(FException) then
    FException.Free;
  FCompletionEvent.Free;
  FCompletionCallbacks.Free;
  FCriticalSection.Free;

  inherited;
end;

function TAsyncOperationController.IsCancellationRequested: Boolean;
begin
  Result := TInterlocked.CompareExchange(FCancelled, 0, 0) = 1;
end;

procedure TAsyncOperationController.OnCancelled(const ACallback: TAsyncCoreCancelledCallback);
var
  LAlreadyCancelled: Boolean;
begin
  FCriticalSection.Acquire;
  try
    LAlreadyCancelled := (TInterlocked.CompareExchange(FCancelled, 0, 0) = 1);
    if not LAlreadyCancelled then
      FCancelledCallback := ACallback;
  finally
    FCriticalSection.Release;
  end;

  if LAlreadyCancelled and Assigned(ACallback) then
  begin
    case FDispatchMode of
      TAsyncCallbackDispatchMode.dmQueue:
        TThread.Queue(nil, procedure
          begin
            ACallback();
          end);
      TAsyncCallbackDispatchMode.dmSynchronize:
        TThread.Synchronize(nil, procedure
          begin
            ACallback();
          end);
    end;
  end;
end;

procedure TAsyncOperationController.OnCompletion(const ACallback: TAsyncCoreFinallyCallback);
var
  LIsCompleted: Boolean;
begin
  FCriticalSection.Acquire;
  try
    LIsCompleted := FState in [TAsyncOperationState.Completed, TAsyncOperationState.Faulted, TAsyncOperationState.Cancelled];
    if not LIsCompleted then
      FCompletionCallbacks.Add(ACallback);
  finally
    FCriticalSection.Release;
  end;

  if LIsCompleted then
  begin
    case FDispatchMode of
      TAsyncCallbackDispatchMode.dmQueue:
        TThread.Queue(nil, procedure
          begin
            ACallback();
          end);
      TAsyncCallbackDispatchMode.dmSynchronize:
        TThread.Synchronize(nil, procedure
          begin
            ACallback();
          end);
    end;
  end;
end;

function TAsyncOperationController.WaitForCompletion(ATimeout: Cardinal; ARaiseOnError: Boolean): TAsyncOperationState;

  function CreateExceptionCopy(ASource: Exception): Exception;
  var
    LExceptionClass: ExceptClass;
  begin
    try
      LExceptionClass := ExceptClass(ASource.ClassType);
      Result := LExceptionClass.Create(ASource.Message);
    except
      Result := Exception.Create(ASource.ClassName + ': ' + ASource.Message);
    end;
  end;

var
  LStartTime: Cardinal;
  LElapsed: Cardinal;
  LRemainingTimeout: Cardinal;
  LWaitTime: Cardinal;
  LIsMainThread: Boolean;
  LExceptionToRaise: Exception;
  LCurrentState: TAsyncOperationState;
begin
  LExceptionToRaise := nil;

  FCriticalSection.Acquire;
  try
    LCurrentState := FState;
    if LCurrentState in [TAsyncOperationState.Completed, TAsyncOperationState.Faulted, TAsyncOperationState.Cancelled] then
    begin
      if ARaiseOnError and (LCurrentState = TAsyncOperationState.Faulted) and Assigned(FException) then
        LExceptionToRaise := CreateExceptionCopy(FException);
    end;
  finally
    FCriticalSection.Release;
  end;

  if LCurrentState in [TAsyncOperationState.Completed, TAsyncOperationState.Faulted, TAsyncOperationState.Cancelled] then
  begin
    if Assigned(LExceptionToRaise) then
      raise LExceptionToRaise;
    Result := LCurrentState;
    Exit;
  end;

  LIsMainThread := TThread.Current.ThreadID = MainThreadID;
  LStartTime := TThread.GetTickCount;

  while True do
  begin
    if ATimeout <> INFINITE then
    begin
      LElapsed := TAsyncCore.GetElapsedTime(LStartTime);
      if LElapsed >= ATimeout then
        raise EAsyncTimeoutException.Create('Operation timed out');
      LRemainingTimeout := ATimeout - LElapsed;
      LWaitTime := Min(LRemainingTimeout, 50);
    end
    else
      LWaitTime := 50;

    if LIsMainThread then
      CheckSynchronize(10);

    if FCompletionEvent.WaitFor(LWaitTime) = wrSignaled then
    begin
      FCriticalSection.Acquire;
      try
        Result := FState;

        if ARaiseOnError and (FState = TAsyncOperationState.Faulted) and Assigned(FException) then
          LExceptionToRaise := CreateExceptionCopy(FException);
      finally
        FCriticalSection.Release;
      end;

      if Assigned(LExceptionToRaise) then
        raise LExceptionToRaise;

      Exit;
    end;
  end;
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

procedure TAsyncOperationController.SetState(AState: TAsyncOperationState);
begin
  FCriticalSection.Acquire;
  try
    FState := AState;
  finally
    FCriticalSection.Release;
  end;
end;

procedure TAsyncOperationController.SignalCompletion;
var
  LCallbacks: TArray<TAsyncCoreFinallyCallback>;
  LIndex: Integer;
  LCapturedException: Exception;
begin
  FCriticalSection.Acquire;
  try
    LCallbacks := FCompletionCallbacks.ToArray;
    FCompletionCallbacks.Clear;
  finally
    FCriticalSection.Release;
  end;

  for LIndex := 0 to High(LCallbacks) do
  begin
    if Assigned(LCallbacks[LIndex]) then
    begin
      try
        (procedure(ACallback: TAsyncCoreFinallyCallback)
          begin
            case FDispatchMode of
              TAsyncCallbackDispatchMode.dmQueue:
                TThread.Queue(nil, procedure
                  begin
                    ACallback();
                  end);
              TAsyncCallbackDispatchMode.dmSynchronize:
                TThread.Synchronize(nil, procedure
                  begin
                    ACallback();
                  end);
            end;
          end)(LCallbacks[LIndex]);
      except
        on E: Exception do
        begin
          if Assigned(TAsyncCore.OnUnhandledError) then
          begin
            LCapturedException := Exception(AcquireExceptionObject);
            try
              TAsyncCore.OnUnhandledError(LCapturedException);
            finally
              LCapturedException.Free;
            end;
          end;
        end;
      end;
    end;
  end;

  FCompletionEvent.SetEvent;
end;

procedure TAsyncOperationController.SetException(AException: Exception);
begin
  FCriticalSection.Acquire;
  try
    FException := AException;
  finally
    FCriticalSection.Release;
  end;
end;

function TAsyncOperationController.GetException: Exception;
var
  LExceptionClass: ExceptClass;
begin
  FCriticalSection.Acquire;
  try
    if Assigned(FException) then
    begin
      try
        LExceptionClass := ExceptClass(FException.ClassType);
        Result := LExceptionClass.Create(FException.Message);
      except
        Result := Exception.Create(FException.ClassName + ': ' + FException.Message);
      end;
    end
    else
      Result := nil;
  finally
    FCriticalSection.Release;
  end;
end;

{TAsyncOperationController<T>}

procedure TAsyncOperationController<T>.SetResult(const AValue: T);
begin
  FCriticalSection.Acquire;
  try
    FResult := AValue;
    FHasResult := True;
  finally
    FCriticalSection.Release;
  end;
end;

function TAsyncOperationController<T>.WaitForResult(ATimeout: Cardinal): T;
var
  LState: TAsyncOperationState;
  LExceptionToRaise: Exception;
  LExceptionClass: ExceptClass;
begin
  LExceptionToRaise := nil;

  FCriticalSection.Acquire;
  try
    if FHasResult and (FState = TAsyncOperationState.Completed) then
      Exit(FResult);

    if FState = TAsyncOperationState.Faulted then
    begin
      try
        LExceptionClass := ExceptClass(FException.ClassType);
        LExceptionToRaise := LExceptionClass.Create(FException.Message);
      except
        LExceptionToRaise := Exception.Create(FException.ClassName + ': ' + FException.Message);
      end;
    end;

    if FState = TAsyncOperationState.Cancelled then
      raise EAsyncCancelException.Create;
  finally
    FCriticalSection.Release;
  end;

  if Assigned(LExceptionToRaise) then
    raise LExceptionToRaise;

  LState := WaitForCompletion(ATimeout, True);

  FCriticalSection.Acquire;
  try
    case LState of
      TAsyncOperationState.Completed:
        Result := FResult;
      TAsyncOperationState.Cancelled:
        raise EAsyncCancelException.Create;
    else
      raise EAsyncException.Create('Unexpected operation state');
    end;
  finally
    FCriticalSection.Release;
  end;
end;

function TAsyncOperationController<T>.TryWaitForResult(ATimeout: Cardinal; out AResult: T): Boolean;
var
  LState: TAsyncOperationState;
begin
  Result := False;

  if TryGetResult(AResult) then
    Exit(True);

  try
    LState := WaitForCompletion(ATimeout);

    if LState = TAsyncOperationState.Completed then
    begin
      FCriticalSection.Acquire;
      try
        if FHasResult then
        begin
          AResult := FResult;
          Result := True;
        end;
      finally
        FCriticalSection.Release;
      end;
    end;
  except
    on EAsyncTimeoutException do
      Result := False;
  end;
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

{TAsyncCore}

class function TAsyncCore.Run<T>(OnAsyncTask: TAsyncCoreFunctionTask<T>; OnSuccess: TAsyncCoreSuccessCallback<T>; OnError: TAsyncCoreErrorCallback; OnFinally: TAsyncCoreFinallyCallback; ADispatchMode: TAsyncCallbackDispatchMode): IAsyncOperation<T>;
var
  LOperationController: TAsyncOperationController<T>;
  LSelfReference: IAsyncOperation<T>;
begin
  LOperationController := TAsyncOperationController<T>.Create(ADispatchMode);

  LSelfReference := LOperationController as IAsyncOperation<T>;

  TTask.Run(
    procedure
    var
      LTaskResult: T;
      LKeepAlive: IAsyncOperation<T>;
      LAcquiredException: Exception;
    begin
      LKeepAlive := LSelfReference;

      if LOperationController.IsCancellationRequested then
      begin
        LOperationController.SetState(TAsyncOperationState.Cancelled);
        LOperationController.SignalCompletion;
        TAsyncCore.DispatchIfAssigned(ADispatchMode, OnFinally);
        Exit;
      end;

      LOperationController.SetState(TAsyncOperationState.Running);
      try
        try
          LTaskResult := OnAsyncTask(LOperationController as IAsyncOperation);

          LOperationController.SetResult(LTaskResult);
          LOperationController.SetState(TAsyncOperationState.Completed);

          TAsyncCore.DispatchIfAssigned<T>(ADispatchMode, OnSuccess, LTaskResult);
        except
          on E: EAsyncCancelException do
          begin
            LOperationController.SetState(TAsyncOperationState.Cancelled);
          end;
          on E: Exception do
          begin
            LAcquiredException := Exception(AcquireExceptionObject);
            LOperationController.SetException(LAcquiredException);
            LOperationController.SetState(TAsyncOperationState.Faulted);

            if Assigned(OnError) then
              TAsyncCore.DispatchAcquiredException(ADispatchMode, OnError, LAcquiredException)
            else if Assigned(FOnUnhandledError) then
              TAsyncCore.DispatchAcquiredException(ADispatchMode, FOnUnhandledError, LAcquiredException);
          end;
        end;
      finally
        LOperationController.SignalCompletion;
        TAsyncCore.DispatchIfAssigned(ADispatchMode, OnFinally);
      end;
    end);

  Result := LOperationController;
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

class procedure TAsyncCore.DispatchIfAssigned(ADispatchMode: TAsyncCallbackDispatchMode; const ACallback: TAsyncCoreFinallyCallback);
begin
  if not (Assigned(ACallback)) then
    Exit;

  case ADispatchMode of
    TAsyncCallbackDispatchMode.dmQueue:
      TThread.Queue(nil,
        procedure
        begin
          ACallback();
        end);
    TAsyncCallbackDispatchMode.dmSynchronize:
      TThread.Synchronize(nil,
        procedure
        begin
          ACallback();
        end);
  end;
end;

class procedure TAsyncCore.DispatchAcquiredException(ADispatchMode: TAsyncCallbackDispatchMode; const ACallback: TAsyncCoreErrorCallback; AException: Exception);
var
  LExceptionCopy: Exception;
  LExceptionClass: ExceptClass;
begin
  if not Assigned(ACallback) then
  begin
    AException.Free;
    Exit;
  end;

  try
    LExceptionClass := ExceptClass(AException.ClassType);
    LExceptionCopy := LExceptionClass.Create(AException.Message);
  except
    LExceptionCopy := Exception.Create(AException.ClassName + ': ' + AException.Message);
  end;

  case ADispatchMode of
    TAsyncCallbackDispatchMode.dmQueue:
      TThread.Queue(nil,
        procedure
        begin
          try
            ACallback(LExceptionCopy);
          finally
            LExceptionCopy.Free;
          end;
        end);
    TAsyncCallbackDispatchMode.dmSynchronize:
      TThread.Synchronize(nil,
        procedure
        begin
          try
            ACallback(LExceptionCopy);
          finally
            LExceptionCopy.Free;
          end;
        end);
  end;
end;

class procedure TAsyncCore.DispatchIfAssigned<T>(ADispatchMode: TAsyncCallbackDispatchMode; const ACallback: TAsyncCoreSuccessCallback<T>; const AValue: T);
begin
  if not (Assigned(ACallback)) then
    Exit;

  case ADispatchMode of
    TAsyncCallbackDispatchMode.dmQueue:
      TThread.Queue(nil,
        procedure
        begin
          ACallback(AValue);
        end);
    TAsyncCallbackDispatchMode.dmSynchronize:
      TThread.Synchronize(nil,
        procedure
        begin
          ACallback(AValue);
        end);
  end;
end;

class function TAsyncCore.New(const ATask: TAsyncCoreProcedureTask): IAsyncVoidPromise;
begin
  Result := TAsyncCoreVoidPromise.Create(ATask);
end;

{TAsyncTaskCompletionSource<T>}

constructor TAsyncTaskCompletionSource<T>.Create(ADispatchMode: TAsyncCallbackDispatchMode);
begin
  inherited Create;
  FController := TAsyncOperationController<T>.Create(ADispatchMode);
  FCriticalSection := TCriticalSection.Create;
  FCompleted := False;
end;

destructor TAsyncTaskCompletionSource<T>.Destroy;
begin
  FCriticalSection.Free;
  if Assigned(FController) then
    FController := nil;

  inherited;
end;

procedure TAsyncTaskCompletionSource<T>.SetResult(const AValue: T);
begin
  FCriticalSection.Acquire;
  try
    if FCompleted then
      raise EAsyncException.Create('TaskCompletionSource already completed');

    FCompleted := True;
    FController.SetResult(AValue);
    FController.SetState(TAsyncOperationState.Completed);
    FController.SignalCompletion;
  finally
    FCriticalSection.Release;
  end;
end;

procedure TAsyncTaskCompletionSource<T>.SetException(AException: Exception);
begin
  FCriticalSection.Acquire;
  try
    if FCompleted then
    begin
      AException.Free;
      raise EAsyncException.Create('TaskCompletionSource already completed');
    end;

    FCompleted := True;
    FController.SetException(AException);
    FController.SetState(TAsyncOperationState.Faulted);
    FController.SignalCompletion;
  finally
    FCriticalSection.Release;
  end;
end;

procedure TAsyncTaskCompletionSource<T>.SetCancelled;
begin
  FCriticalSection.Acquire;
  try
    if FCompleted then
      raise EAsyncException.Create('TaskCompletionSource already completed');

    FCompleted := True;
    FController.SetState(TAsyncOperationState.Cancelled);
    FController.SignalCompletion;
  finally
    FCriticalSection.Release;
  end;
end;

function TAsyncTaskCompletionSource<T>.TrySetResult(const AValue: T): Boolean;
begin
  FCriticalSection.Acquire;
  try
    if FCompleted then
      Exit(False);

    FCompleted := True;
    FController.SetResult(AValue);
    FController.SetState(TAsyncOperationState.Completed);
    FController.SignalCompletion;
    Result := True;
  finally
    FCriticalSection.Release;
  end;
end;

function TAsyncTaskCompletionSource<T>.TrySetException(AException: Exception): Boolean;
begin
  FCriticalSection.Acquire;
  try
    if FCompleted then
    begin
      AException.Free;
      Exit(False);
    end;

    FCompleted := True;
    FController.SetException(AException);
    FController.SetState(TAsyncOperationState.Faulted);
    FController.SignalCompletion;
    Result := True;
  finally
    FCriticalSection.Release;
  end;
end;

function TAsyncTaskCompletionSource<T>.TrySetCancelled: Boolean;
begin
  FCriticalSection.Acquire;
  try
    if FCompleted then
      Exit(False);

    FCompleted := True;
    FController.SetState(TAsyncOperationState.Cancelled);
    FController.SignalCompletion;
    Result := True;
  finally
    FCriticalSection.Release;
  end;
end;

function TAsyncTaskCompletionSource<T>.GetOperation: IAsyncOperation<T>;
begin
  Result := FController;
end;

{TAsyncTaskCompletionSource}

constructor TAsyncTaskCompletionSource.Create(ADispatchMode: TAsyncCallbackDispatchMode);
begin
  inherited Create;
  FController := TAsyncOperationController.Create(ADispatchMode);
  FCriticalSection := TCriticalSection.Create;
  FCompleted := False;
end;

destructor TAsyncTaskCompletionSource.Destroy;
begin
  FCriticalSection.Free;
  if Assigned(FController) then
    FController := nil;

  inherited;
end;

procedure TAsyncTaskCompletionSource.SetResult;
begin
  FCriticalSection.Acquire;
  try
    if FCompleted then
      raise EAsyncException.Create('TaskCompletionSource already completed');

    FCompleted := True;
    FController.SetState(TAsyncOperationState.Completed);
    FController.SignalCompletion;
  finally
    FCriticalSection.Release;
  end;
end;

procedure TAsyncTaskCompletionSource.SetException(AException: Exception);
begin
  FCriticalSection.Acquire;
  try
    if FCompleted then
    begin
      AException.Free;
      raise EAsyncException.Create('TaskCompletionSource already completed');
    end;

    FCompleted := True;
    FController.SetException(AException);
    FController.SetState(TAsyncOperationState.Faulted);
    FController.SignalCompletion;
  finally
    FCriticalSection.Release;
  end;
end;

procedure TAsyncTaskCompletionSource.SetCancelled;
begin
  FCriticalSection.Acquire;
  try
    if FCompleted then
      raise EAsyncException.Create('TaskCompletionSource already completed');

    FCompleted := True;
    FController.SetState(TAsyncOperationState.Cancelled);
    FController.SignalCompletion;
  finally
    FCriticalSection.Release;
  end;
end;

function TAsyncTaskCompletionSource.TrySetResult: Boolean;
begin
  FCriticalSection.Acquire;
  try
    if FCompleted then
      Exit(False);

    FCompleted := True;
    FController.SetState(TAsyncOperationState.Completed);
    FController.SignalCompletion;
    Result := True;
  finally
    FCriticalSection.Release;
  end;
end;

function TAsyncTaskCompletionSource.TrySetException(AException: Exception): Boolean;
begin
  FCriticalSection.Acquire;
  try
    if FCompleted then
    begin
      AException.Free;
      Exit(False);
    end;

    FCompleted := True;
    FController.SetException(AException);
    FController.SetState(TAsyncOperationState.Faulted);
    FController.SignalCompletion;
    Result := True;
  finally
    FCriticalSection.Release;
  end;
end;

function TAsyncTaskCompletionSource.TrySetCancelled: Boolean;
begin
  FCriticalSection.Acquire;
  try
    if FCompleted then
      Exit(False);

    FCompleted := True;
    FController.SetState(TAsyncOperationState.Cancelled);
    FController.SignalCompletion;
    Result := True;
  finally
    FCriticalSection.Release;
  end;
end;

function TAsyncTaskCompletionSource.GetOperation: IAsyncOperation;
begin
  Result := FController;
end;

{TAsyncCorePromise<T>}

constructor TAsyncCorePromise<T>.Create(const ATask: TAsyncCoreFunctionTask<T>);
begin
  inherited Create;
  FTask := ATask;
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
  if not Assigned(FTask) then
    raise EArgumentNilException.Create('AsyncCore: Task not assigned');
  Result := TAsyncCore.Run<T>(FTask, FOnSuccess, FOnError, FOnFinally, FDispatchMode);
end;

{TAsyncCoreVoidPromise}

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
  const AContinuation: TAsyncCoreContinuationFunc<T, TResult>): IAsyncOperation<TResult>;
var
  LCompletionSource: IAsyncTaskCompletionSource<TResult>;
begin
  LCompletionSource := TAsyncTaskCompletionSource<TResult>.Create(TAsyncCallbackDispatchMode.dmSynchronize);

  AOperation.OnCompletion(
    procedure
    begin
      TTask.Run(
        procedure
        var
          LValue: T;
          LRes: TResult;
          LException: Exception;
          LEx: Exception;
        begin
          try
            case AOperation.State of
              TAsyncOperationState.Completed:
                begin
                  if AOperation.TryGetResult(LValue) then
                  begin
                    try
                      LRes := AContinuation(LValue);
                      LCompletionSource.SetResult(LRes);
                    except
                      on E: Exception do
                      begin
                        LEx := Exception(AcquireExceptionObject);
                        LCompletionSource.SetException(LEx);
                      end;
                    end;
                  end
                  else
                    LCompletionSource.SetException(Exception.Create('Failed to get result from completed operation'));
                end;

              TAsyncOperationState.Faulted:
                begin
                  LException := AOperation.GetException;
                  if Assigned(LException) then
                    LCompletionSource.SetException(LException)
                  else
                    LCompletionSource.SetException(Exception.Create('Previous operation faulted without exception information'));
                end;

              TAsyncOperationState.Cancelled:
                LCompletionSource.SetCancelled;
            end;
          except
            on E: Exception do
            begin
              LEx := Exception(AcquireExceptionObject);
              LCompletionSource.SetException(LEx);
            end;
          end;
        end);
    end);

  Result := LCompletionSource.Operation;
end;

class function TAsyncCore.WhenAll<T>(const AOperations: array of IAsyncOperation<T>): IAsyncOperation<TArray<T>>;
var
  LCompletionSource: IAsyncTaskCompletionSource<TArray<T>>;
  LCount: Integer;
  LTotal: Integer;
  LOperationsCopy: TArray<IAsyncOperation<T>>;
  LIndex: Integer;
begin
  LTotal := Length(AOperations);
  if LTotal = 0 then
  begin
    LCompletionSource := TAsyncTaskCompletionSource < TArray<T> > .Create;
    LCompletionSource.SetResult([]);
    Exit(LCompletionSource.Operation);
  end;

  LCompletionSource := TAsyncTaskCompletionSource < TArray<T> > .Create(TAsyncCallbackDispatchMode.dmSynchronize);

  LCount := LTotal;

  SetLength(LOperationsCopy, LTotal);
  for LIndex := 0 to LTotal - 1 do
    LOperationsCopy[LIndex] := AOperations[LIndex];

  for LIndex := 0 to LTotal - 1 do
  begin
    (procedure(AIndex: Integer)
      var
        LOp: IAsyncOperation<T>;
      begin
        LOp := LOperationsCopy[AIndex];

        LOp.OnCompletion(
          procedure
          var
            LResults: TArray<T>;
            LIndex: Integer;
            LResultVal: T;
            LEx: Exception;
          begin
            if LOp.State = TAsyncOperationState.Faulted then
              LCompletionSource.TrySetException(LOp.GetException)
            else if LOp.State = TAsyncOperationState.Cancelled then
              LCompletionSource.TrySetCancelled;

            if TInterlocked.Decrement(LCount) = 0 then
            begin
              if LCompletionSource.Operation.State = TAsyncOperationState.Pending then
              begin
                SetLength(LResults, LTotal);
                try
                  for LIndex := 0 to LTotal - 1 do
                  begin
                    if LOperationsCopy[LIndex].TryGetResult(LResultVal) then
                      LResults[LIndex] := LResultVal
                    else
                    begin
                      Exit;
                    end;
                  end;
                  LCompletionSource.TrySetResult(LResults);
                except
                  on E: Exception do
                  begin
                    LEx := Exception(AcquireExceptionObject);
                    LCompletionSource.TrySetException(LEx);
                  end;
                end;
              end;
            end;
          end);
      end)(LIndex);
  end;

  Result := LCompletionSource.Operation;
end;

class function TAsyncCore.WhenAny<T>(const AOperations: array of IAsyncOperation<T>): IAsyncOperation<T>;
var
  LCompletionSource: IAsyncTaskCompletionSource<T>;
  LOperationsCopy: TArray<IAsyncOperation<T>>;
  LTotal: Integer;
  LIndex: Integer;
begin
  LTotal := Length(AOperations);
  if LTotal = 0 then
  begin
    LCompletionSource := TAsyncTaskCompletionSource<T>.Create;
    LCompletionSource.SetException(Exception.Create('WhenAny requires at least one operation'));
    Exit(LCompletionSource.Operation);
  end;

  LCompletionSource := TAsyncTaskCompletionSource<T>.Create(TAsyncCallbackDispatchMode.dmSynchronize);

  SetLength(LOperationsCopy, LTotal);
  for LIndex := 0 to LTotal - 1 do
    LOperationsCopy[LIndex] := AOperations[LIndex];

  for LIndex := 0 to LTotal - 1 do
  begin
    (procedure(AIndex: Integer)
      var
        LOp: IAsyncOperation<T>;
      begin
        LOp := LOperationsCopy[AIndex];
        LOp.OnCompletion(
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

class function TAsyncCore.RunWithRetry<T>(
  ATask: TAsyncCoreFunctionTask<T>;
  AMaxRetries: Integer;
  AInitialDelay: Cardinal;
  ABackoffStrategy: TBackoffStrategy;
  AMaxDelay: Cardinal): IAsyncOperation<T>;
begin
  Result := TAsyncCore.Run<T>(
    function(const AController: IAsyncOperation): T
    var
      LAttempt: Integer;
      LDelay: Cardinal;
      LExceptionMessage: string;
      LExceptionClass: string;
      LHadException: Boolean;
      LMultiplier: Cardinal;
    begin
      LHadException := False;
      LExceptionMessage := '';
      LExceptionClass := '';

      for LAttempt := 0 to AMaxRetries do
      begin
        try
          Result := ATask(AController);

          Exit;
        except
          on E: Exception do
          begin
            LExceptionClass := E.ClassName;
            LExceptionMessage := E.Message;
            LHadException := True;

            if LAttempt >= AMaxRetries then
              Break;

            case ABackoffStrategy of
              TBackoffStrategy.Fixed:
                LDelay := AInitialDelay;

              TBackoffStrategy.Linear:
                begin
                  if Cardinal(LAttempt) >= (High(Cardinal) div AInitialDelay) then
                    LDelay := AMaxDelay
                  else
                    LDelay := AInitialDelay * Cardinal(LAttempt + 1);
                end;

              TBackoffStrategy.Exponential:
                begin
                  if (LAttempt = 0) or (LAttempt > 20) then
                  begin
                    if LAttempt = 0 then
                      LDelay := AInitialDelay
                    else
                      LDelay := AMaxDelay;
                  end
                  else
                  begin
                    LMultiplier := Cardinal(1 shl LAttempt);
                    if AInitialDelay > (High(Cardinal) div LMultiplier) then
                      LDelay := AMaxDelay
                    else
                      LDelay := AInitialDelay * LMultiplier;
                  end;
                end;
            else
              LDelay := AInitialDelay;
            end;

            if LDelay > AMaxDelay then
              LDelay := AMaxDelay;

            Sleep(LDelay);

            if AController.IsCancellationRequested then
              raise EAsyncCancelException.Create;
          end;
        end;
      end;

      if LHadException then
      begin
        raise EAsyncException.Create(LExceptionClass + ': ' + LExceptionMessage +
          ' (failed after ' + IntToStr(AMaxRetries + 1) + ' attempts)');
      end
      else
        raise EAsyncException.Create('Task failed after ' + IntToStr(AMaxRetries + 1) + ' attempts');
    end);
end;

class function TAsyncCore.RunWithTimeout<T>(
  ATask: TAsyncCoreFunctionTask<T>;
  ATimeoutMs: Cardinal): IAsyncOperation<T>;
var
  LCompletionSource: IAsyncTaskCompletionSource<T>;
  LActualTask: IAsyncOperation<T>;
  LTimeoutTask: IAsyncOperation;
begin
  LCompletionSource := TAsyncTaskCompletionSource<T>.Create(TAsyncCallbackDispatchMode.dmSynchronize);

  LActualTask := TAsyncCore.Run<T>(ATask);

  LTimeoutTask := TAsyncCore.Delay(ATimeoutMs);

  LActualTask.OnCompletion(
    procedure
    var
      LRes: T;
    begin
      case LActualTask.State of
        TAsyncOperationState.Completed:
          if LActualTask.TryGetResult(LRes) then
            if LCompletionSource.TrySetResult(LRes) then
              LTimeoutTask.Cancel;

        TAsyncOperationState.Faulted:
          if LCompletionSource.TrySetException(LActualTask.GetException) then
            LTimeoutTask.Cancel;

        TAsyncOperationState.Cancelled:
          if LCompletionSource.TrySetCancelled then
            LTimeoutTask.Cancel;
      end;
    end);

  LTimeoutTask.OnCompletion(
    procedure
    begin
      if LTimeoutTask.State = TAsyncOperationState.Completed then
      begin
        if LCompletionSource.TrySetCancelled then
          LActualTask.Cancel;
      end;
    end);

  LCompletionSource.Operation.OnCancelled(
    procedure
    begin
      LActualTask.Cancel;
      LTimeoutTask.Cancel;
    end);

  Result := LCompletionSource.Operation;
end;

class function TAsyncCore.Delay(AMilliseconds: Cardinal): IAsyncOperation;
begin
  Result := TAsyncCore.Run(
    procedure(const AController: IAsyncOperation)
    var
      LEventWrapper: IEventWrapper;
    begin
      LEventWrapper := TEventWrapper.Create;

      AController.OnCancelled(
        procedure
        begin
          LEventWrapper.Signal;
        end);

      if AController.IsCancellationRequested then
        raise EAsyncCancelException.Create;

      LEventWrapper.WaitFor(AMilliseconds);

      if AController.IsCancellationRequested then
        raise EAsyncCancelException.Create;
    end);
end;

class function TAsyncCore.CreateCancellationTokenWithTimeout(ATimeoutMs: Cardinal): IAsyncOperation;
begin
  Result := Delay(ATimeoutMs);
end;

class procedure TAsyncCore.LinkCancellationToken(const AOperation: IAsyncOperation; const ACancellationToken: IAsyncOperation);
begin
  if ACancellationToken.State = TAsyncOperationState.Completed then
  begin
    AOperation.Cancel;
    Exit;
  end;

  if AOperation.State in [TAsyncOperationState.Completed, TAsyncOperationState.Faulted, TAsyncOperationState.Cancelled] then
    Exit;

  ACancellationToken.OnCompletion(
    procedure
    begin
      if ACancellationToken.State = TAsyncOperationState.Completed then
        AOperation.Cancel;
    end);
end;

{EAsyncCancelException}

constructor EAsyncCancelException.Create;
begin
  inherited Create('Asynchronous operation was cancelled');
end;

{EAsyncTimeoutException}

constructor EAsyncTimeoutException.Create(const AMessage: string);
begin
  inherited Create(AMessage);
end;

initialization

  TAsyncCore.OnUnhandledError := nil;

end.