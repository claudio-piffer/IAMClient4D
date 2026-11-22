# Token storage reference

Where the Keycloak client keeps its tokens: the storage interface, the AES-encrypted in-memory storage of the library, its crypto providers, key handling, and how to plug a storage of your own. The client flows are in [Core.md](Core.md); the compile-time choice of the crypto provider is described in [Security.md](Security.md#crypto-providers).

## Contents

- [Interface](#interface)
- [How the client uses the storage](#how-the-client-uses-the-storage)
- [AES in-memory storage](#aes-in-memory-storage)
- [Storage crypto providers](#storage-crypto-providers)
- [Keys and AAD](#keys-and-aad)
- [Custom storage](#custom-storage)
- [Platforms](#platforms)

## Interface

Unit `IAMClient4D.Storage.Core`. `IIAM4DTokenStorage`:

| Method | Contract |
|---|---|
| `SaveTokens(const Tokens: TIAM4DTokens)` | Replaces the stored tokens. |
| `LoadTokens: TIAM4DTokens` | The stored tokens; an empty record (`Default(TIAM4DTokens)`) when there are none. |
| `ClearTokens` | Removes the tokens. |
| `HasTokens: Boolean` | Tokens are stored. |
| `IsAccessTokenValid: Boolean` | Tokens stored and `AccessTokenExpiry` not reached, minus the expiry buffer. |
| `IsRefreshTokenValid: Boolean` | Same for `RefreshTokenExpiry`. |

`TIAM4DTokens` (unit `IAMClient4D.Core`) holds `AccessToken`, `RefreshToken`, `IDToken`, `ExpiresIn`, `RefreshExpiresIn`, `AccessTokenExpiry`, `RefreshTokenExpiry` (UTC `TDateTime`) and `Scope` (granted scopes, space-separated). `TIAM4DTokens.ToJSONObject` / `FromJSONObject` serialize it; `TIAM4DTokenSerializer` (unit `IAMClient4D.Common.TokenSerializer`) also has `ToJSONString`, `FromJSONString`, `ToBytes`, `FromBytes`. Expiry dates are serialized in ISO 8601 UTC.

## How the client uses the storage

What `TIAM4DKeycloakClient` does with an `IIAM4DTokenStorage`, which a custom storage must support:

- **No storage given** (`TIAM4DKeycloakClient.Create` with `nil`): an AES in-memory storage with a random 32-byte key, AAD `IAMClient4D/v1`, buffer 120 s. The builder does the same when no storage method is called, with the buffer of `WithTokenExpiryBuffer`.
- **Cleared at configuration**: the client calls `ClearTokens` when it is created and when it is configured (`Build`, `BuildAsync`). Tokens left in a storage by a previous run or another client are discarded: the library offers no persistence of a session across restarts.
- **Writes**: `SaveTokens` and `ClearTokens` run under a lock of the client (login, refresh, logout, revocation). Keep them short.
- **Reads without lock**: `GetAccessToken` and the other getters call `IsAccessTokenValid`, `HasTokens` and `LoadTokens` from any thread, also while another thread saves or clears. `LoadTokens` must then return a consistent record, empty when the tokens were cleared in the meantime.
- **Expiry buffer**: the client trusts `IsAccessTokenValid` and `IsRefreshTokenValid`. When the access token is not valid it refreshes (Authorization Code, Password) or requests a new one (Client Credentials). `IsAuthenticated` is `IsRefreshTokenValid` for Authorization Code and Password, `IsAccessTokenValid` for Client Credentials.
- **Invalidation**: after a 401 (`InvalidateAccessToken`) the client saves the same tokens with `AccessTokenExpiry := 0`: `IsAccessTokenValid` must then be `False`.

## AES in-memory storage

Unit `IAMClient4D.Storage.AESMemoryTokenStorage`. `TIAM4DAESMemoryTokenStorageRawKey32` implements `IIAM4DTokenStorage`. Tokens are kept only in process memory, encrypted; they are never written to disk and are lost when the process ends.

| Constructor | Description |
|---|---|
| `Create(AKey32, AAAD: TBytes; ATokenExpiryBufferSeconds = 120)` | Compiled storage crypto provider with `AKey32`. A key that is not 32 bytes: `EIAM4DStorageException`. |
| `Create(ACryptoProvider: IIAM4DStorageCryptoProvider; AAAD: TBytes; ATokenExpiryBufferSeconds = 120)` | Any storage crypto provider. `nil` provider or a negative buffer: `EIAM4DStorageException`. |

The storage keeps a copy of `AAAD`; the key stays inside the crypto provider.

Behaviour:

- **Save**: the tokens are serialized to JSON (UTF-8), prefixed with a 4-byte big-endian length, encrypted with the AAD, and stored as a blob: 2 version bytes (format 1.0) followed by the provider output. The previous blob is wiped. Payloads over 10 MB (`MAX_FRAME_SIZE`) are refused.
- **Load**: version checked (major 1), decrypted and authenticated by the provider, parsed.
- **Expiry checks without decryption**: `AccessTokenExpiry` and `RefreshTokenExpiry` are also kept in clear, next to the blob, so that `IsAccessTokenValid` and `IsRefreshTokenValid` do not decrypt. They compare with `TDateTime.NowUTC`.
- **Errors**: any failure of `SaveTokens` or `LoadTokens` (encryption, authentication, corrupted blob, unsupported version) clears the tokens and raises `EIAM4DStorageException` ("Failed to save tokens (RawKey32): ..." / "Failed to load tokens (RawKey32): ..."), with the reason of the provider in the message.
- **Wiping**: plaintext buffers, the serialized JSON string, the old blob on save, and blob and AAD on destruction are overwritten (the byte buffers with zeros, `$FF`, zeros).
- **Thread safety**: safe for concurrent use (`TLightweightMREW`). `HasTokens` and the expiry checks take the shared lock; `SaveTokens`, `LoadTokens` and `ClearTokens` the exclusive one (a failed load clears the tokens). The provider is called only under the exclusive lock, so it need not be thread-safe.

## Storage crypto providers

Units `IAMClient4D.Storage.Crypto.Interfaces` (contract), `IAMClient4D.Storage.Crypto.Factory` (selection). The provider is the one compiled in with the JWT crypto provider (`IAM4D_TMS`, `IAM4D_TAURUSTLS` or neither: [Security.md](Security.md#crypto-providers)).

| | LockBox3 (default) | TMS (`IAM4D_TMS`) | TaurusTLS (`IAM4D_TAURUSTLS`) |
|---|---|---|---|
| Class (unit) | `TIAM4DLockBox3StorageCryptoProvider` (`IAMClient4D.Storage.Crypto.LockBox3`) | `TIAM4DTMSStorageCryptoProvider` (`IAMClient4D.Storage.Crypto.TMS`) | `TIAM4DTaurusTLSStorageCryptoProvider` (`IAMClient4D.Storage.Crypto.TaurusTLS`) |
| `GetAlgorithm` | `AES-256-CBC-HMAC-SHA256` | `AES-256-GCM` | `AES-256-GCM` |
| Construction | Encrypt-then-MAC | AEAD | AEAD (OpenSSL `EVP_aes_256_gcm`) |
| Keys | `Kenc = HMAC-SHA256(Key32, 'enc')`, `Kmac = HMAC-SHA256(Key32, 'mac')` | `Key32` as is | `Key32` as is |
| Frame | `[IV seed 8][ciphertext][HMAC tag 32]` | `[nonce 12][ciphertext][tag 16]` | `[nonce 12][ciphertext][tag 16]` |
| Random | IV = 8-byte seed from the CSPRNG + 8 zero bytes | nonce from the CSPRNG | nonce from `RAND_bytes` |
| Thread-safe | no | no | yes |

- LockBox3: the ciphertext is as long as the plaintext (LockBox3 ciphertext stealing). The tag is `HMAC-SHA256(Kmac, AAD || IV seed || ciphertext || length of AAD as 8-byte big-endian)`, compared in constant time and checked before decrypting.
- TMS: the plaintext written by the library is wiped when the tag does not match.
- TaurusTLS: creating the provider loads OpenSSL; missing or older than 3.0: `EIAM4DOpenSSLException`.
- Each provider wipes its key material on destruction.

The frame formats differ: a blob written with one provider cannot be read by another. With an in-memory storage this has no effect.

`TIAM4DStorageCryptoProviderFactory`:

| Method | Description |
|---|---|
| `CreateProvider(AKey32; AType = scpDefault)` | New provider of the compiled type. Key not 32 bytes, or `scpCustom`: `EArgumentException`. |
| `GetDefaultProviderName` | `LockBox3`, `TMS Cryptography Pack` or `TaurusTLS (OpenSSL)`. |
| `GetDefaultAlgorithmName` | `AES-256-CBC-HMAC-SHA256` or `AES-256-GCM`. |

`IIAM4DStorageCryptoProvider`, for a provider of your own:

| Method | Contract |
|---|---|
| `Encrypt(APlaintext, AAAD): TBytes` | Output self-contained (IV or nonce, tag). Failure: `EIAM4DStorageEncryptionException`. |
| `Decrypt(ACiphertext, AAAD): TBytes` | Authenticates ciphertext and AAD before returning the plaintext. Tampered data, wrong key or AAD: `EIAM4DStorageDecryptionException`. |
| `GetProviderName`, `GetAlgorithm` | For messages and logs. |

Thread safety is not required (the AES storage serializes its calls). Wipe key material on destruction.

Exceptions (unit `IAMClient4D.Storage.Crypto.Interfaces`): `EIAM4DStorageCryptoException` (an `EIAM4DException`, property `ProviderName`, `ErrorCode` `ecUnknown`), with descendants `EIAM4DStorageEncryptionException` (`ecStorageEncryptionFailed`) and `EIAM4DStorageDecryptionException` (`ecStorageDecryptionFailed`). The AES storage wraps them in `EIAM4DStorageException`.

## Keys and AAD

The key protects the tokens against a reader of the process memory that does not also read the key (crash dumps, swapped pages): it lives in the same process.

| Builder call | Key | AAD |
|---|---|---|
| none, or `WithIAMClient4DAESStorage` | random, 32 bytes from the CSPRNG, generated at `Build` | `IAMClient4D/v1` |
| `WithIAMClient4DAESStorage(AKey32, AAAD = nil)` | a copy of `AKey32`; not 32 bytes: `EArgumentException` | `AAAD`, or `IAMClient4D/v1` when empty |
| `WithCustomStorage(AStorage)` | the storage's own | the storage's own |

- The builder keeps its copy of the key and AAD until it is destroyed, then zeroes them. Wipe your own copy after `Build` (`SecureZero` of `IAMClient4D.Common.SecureMemory`).
- Random bytes come from `TIAM4DCryptoUtils.GenerateSecureRandomBytes` (unit `IAMClient4D.Common.CryptoUtils`, DelphiCSPRNG: system APIs).
- The AAD is authenticated, not encrypted: decryption fails if it differs. It binds the blob to a context (application, format version).
- `WithTokenExpiryBuffer` (default 120 s) becomes the buffer of the AES storage the builder creates. It does not reach a storage passed to `WithCustomStorage`, which applies its own.

<!-- snippet ver=3.0 kind=body ctx=client uses=IAMClient4D.Common.CryptoUtils,IAMClient4D.Common.SecureMemory -->
```delphi
var LKey := TIAM4DCryptoUtils.GenerateSecureRandomBytes(32);
try
  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode('http://localhost:18180/auth', 'iamclient4d', 'iam4d-sample-app')
    .WithIAMClient4DAESStorage(LKey, TEncoding.UTF8.GetBytes('my-app/tokens/v1'))
    .WithTokenExpiryBuffer(60)
    .Build;
finally
  SecureZero(LKey); // the builder and the storage keep their own copies
end;
```

## Custom storage

`WithCustomStorage(AStorage)` (builder) uses `AStorage` instead of the AES storage. `nil`: `EArgumentNilException`. A later `WithIAMClient4DAESStorage` call drops it; otherwise the custom storage wins whatever the order of the calls.

A custom storage must follow the contract of [How the client uses the storage](#how-the-client-uses-the-storage): thread-safe reads, an empty record from `LoadTokens` without tokens, expiry checks in UTC with a buffer, `IsAccessTokenValid = False` after `AccessTokenExpiry := 0`. It should keep the tokens encrypted: they grant access to the user's resources until they expire.

The AES storage with a crypto provider chosen in code:

<!-- snippet ver=3.0 kind=body ctx=client,storage uses=IAMClient4D.Storage.AESMemoryTokenStorage,IAMClient4D.Storage.Crypto.Interfaces,IAMClient4D.Storage.Crypto.Factory,IAMClient4D.Common.CryptoUtils -->
```delphi
var LProvider: IIAM4DStorageCryptoProvider :=
  TIAM4DStorageCryptoProviderFactory.CreateProvider(TIAM4DCryptoUtils.GenerateSecureRandomBytes(32));
Writeln(LProvider.GetProviderName, ': ', LProvider.GetAlgorithm);
LClient := TIAM4DClientConfigBuilder.New
  .ForClientCredentials('http://localhost:18180/auth', 'iamclient4d', 'iam4d-sample-service', 'iam4d-test-only-secret')
  .WithCustomStorage(TIAM4DAESMemoryTokenStorageRawKey32.Create(LProvider, TEncoding.UTF8.GetBytes('my-service/v1'), 60))
  .Build;
```

A storage of your own: here a decorator that keeps the tokens in the AES storage and tells the application when a session starts or ends.

<!-- snippet ver=3.0 kind=decl ctx=client,storage uses=IAMClient4D.Storage.AESMemoryTokenStorage,IAMClient4D.Common.CryptoUtils -->
```delphi
type
  TNotifyingTokenStorage = class(TInterfacedObject, IIAM4DTokenStorage)
  private
    FInner: IIAM4DTokenStorage;
    FOnChange: TProc<Boolean>;
  public
    constructor Create(const AInner: IIAM4DTokenStorage; const AOnChange: TProc<Boolean>);
    procedure SaveTokens(const Tokens: TIAM4DTokens);
    function LoadTokens: TIAM4DTokens;
    procedure ClearTokens;
    function HasTokens: Boolean;
    function IsAccessTokenValid: Boolean;
    function IsRefreshTokenValid: Boolean;
  end;

constructor TNotifyingTokenStorage.Create(const AInner: IIAM4DTokenStorage; const AOnChange: TProc<Boolean>);
begin
  inherited Create;
  FInner := AInner;
  FOnChange := AOnChange;
end;

procedure TNotifyingTokenStorage.SaveTokens(const Tokens: TIAM4DTokens);
begin
  FInner.SaveTokens(Tokens);
  // Called under the token lock of the client: keep the handler short
  FOnChange(True);
end;

function TNotifyingTokenStorage.LoadTokens: TIAM4DTokens;
begin
  Result := FInner.LoadTokens;
end;

procedure TNotifyingTokenStorage.ClearTokens;
begin
  FInner.ClearTokens;
  FOnChange(False);
end;

function TNotifyingTokenStorage.HasTokens: Boolean;
begin
  Result := FInner.HasTokens;
end;

function TNotifyingTokenStorage.IsAccessTokenValid: Boolean;
begin
  Result := FInner.IsAccessTokenValid;
end;

function TNotifyingTokenStorage.IsRefreshTokenValid: Boolean;
begin
  Result := FInner.IsRefreshTokenValid;
end;

procedure BuildClient;
var
  LKey: TBytes;
begin
  LKey := TIAM4DCryptoUtils.GenerateSecureRandomBytes(32);
  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode('http://localhost:18180/auth', 'iamclient4d', 'iam4d-sample-app')
    .WithCustomStorage(TNotifyingTokenStorage.Create(
      TIAM4DAESMemoryTokenStorageRawKey32.Create(LKey, TEncoding.UTF8.GetBytes('my-app/v1')),
      procedure(AHasTokens: Boolean)
      begin
        // Any thread: a UI must queue the update to the main thread
        Writeln('Session ', BoolToStr(AHasTokens, True));
      end))
    .Build;
end;
```

## Platforms

The AES in-memory storage has no platform-specific code: it runs wherever the library compiles (Windows, Linux, Android, iOS, macOS). The random source is the CSPRNG of the system (the POSIX provider of DelphiCSPRNG on iOS). The requirements of the compiled crypto provider apply: TaurusTLS needs the OpenSSL libraries deployed on the target, TMS its sources and license ([Security.md](Security.md#crypto-providers)).
