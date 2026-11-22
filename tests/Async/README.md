# Async.Core Runtime Test

Console program that checks `Async.Core` on the main thread: every wait serves `CheckSynchronize`, so `dmSynchronize` and `dmQueue` callbacks run on the main thread as in a GUI application. No server or identity provider is needed.

## What it checks

| Area | Checks |
|------|--------|
| Exceptions | `OnError` receives the original exception (fields included) in both dispatch modes; `WaitForResult`, `GetException` and nested waits hand out copies that keep the fields of `EIAM4DException` and `EIAM4DStorageCryptoException` descendants; classes without a registered cloner keep class and message |
| Completion source | The source keeps its operation alive after the consumer released it; `Set*` on a completed source; `SetException(nil)`; `OnCompletion(nil)` |
| Callbacks | A user `OnCancelled` does not replace the internal handler of `Delay`; a failing `OnSuccess` leaves the operation `Completed` and goes to `OnUnhandledError`; `dmQueue` callbacks; `dmInline` callbacks run on the pool thread while the main thread serves nothing |
| RunWithRetry | `Linear` with zero delay; cancellation interrupts the backoff wait; `AShouldRetry` (also one that raises); negative `AMaxRetries`; `ExponentialJitter` delay range; exhausted retries fault with the error of the last attempt, which reaches `OnUnhandledError` with its fields; every attempt receives the returned operation; `EAsyncCancelException` of the task and a failure after `Cancel` end as `Cancelled` without retry, a success after `Cancel` completes; the task is released when the operation ends, also when it references its own operation |
| Waits and combinators | Timeout always raises `EAsyncTimeoutException`; `WhenAll`, `WhenAny`, `ContinueWith` (including a cancelled continuation); the combinators complete on a worker thread while the main thread serves nothing (server scenario); `Cancel` on `WhenAll`, `WhenAny`, `ContinueWith`, `RunWithTimeout` is immediate and reaches the operations they depend on; `RunWithTimeout` faults with `EAsyncTimeoutException` and cancels the task |
| Dispatch modes | Without the main thread: `RunWithTimeout` with `dmInline` runs the `OnCancelled` of the task on a pool thread at timeout, and a task error reaches the result at once even with `OnUnhandledError` assigned; with `dmQueue` the timeout queues the handlers without waiting for the main thread; `RunWithRetry`, `Delay` and `CreateCancellationTokenWithTimeout` honour `ADispatchMode`; without it their callbacks stay on the main thread (`dmSynchronize`); `dmQueue` callbacks never run inside `Cancel`, `SetResult`, `OnCompletion` or `OnCancelled` called on the main thread (`WhenAll`, `ContinueWith`, `RunWithTimeout`, completion source) |
| FromOperation | Result, error (fields included) and cancellation of the followed operation reach the callbacks; `Cancel` reaches the producer, runs no callback inside the call and raises no exception; a producer ignoring `Cancel` decides the outcome; `dmInline` without the main thread; the callbacks are released once the operation ends |
| Timers | 20 `Delay`, a timeout token and a `RunWithTimeout` keep no pool thread busy but the task (thread pool statistics); 20 `RunWithRetry` waiting for their next attempt keep no pool thread busy and use one timer each; cancelling a delay or a token, or a task ending before its timeout, raises no exception; `Cancel` while `RunWithRetry` waits disposes the timer and ends the operation at once, raises no exception and runs the callbacks on a pool thread; `PendingTimerCount`: the timer goes when the delay fires or is cancelled, when the task of `RunWithTimeout` ends or the operation is cancelled, when a token is cancelled (also 1000 delays); `Delay(INFINITE)`; timers still pending at exit, one of them a `RunWithRetry` waiting for its next attempt, are released (empty leak report, no hang) |
| LinkCancellationToken | An expired token cancels the operation; a cancelled one does not and disposes its timer; a token already expired cancels at once; a completed operation is released at once, not when the token expires, and does not unlink the other operations of the same token |
| Races | `Cancel` racing the completion of a completion source, `FromOperation`, `WhenAny`, `ContinueWith` (two threads released together by a spin barrier), `Run`, `Delay`, `RunWithTimeout` (also against its timeout) and `RunWithRetry` (against the first attempt, the timer of the wait and the retry), 2000 times each: exactly one final state, result consistent with it, completion callback exactly once; no `RunWithRetry` timer left |

## Run

From a command prompt (RAD Studio 13, Win64 by default):

```bat
tests\Async\run_tests.bat
tests\Async\run_tests.bat Win32
tests\Async\run_tests.bat Linux64
```

`Linux64` runs through WSL; without WSL the script only builds. Exit code: number of failed checks (`0` = all passed). On Windows memory leaks are reported on stderr at exit. Build output goes to `tests/bin` and `tests/dcu`.
