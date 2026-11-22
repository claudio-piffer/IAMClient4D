{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Common.Security.pas
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

unit IAMClient4D.Common.Security;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  System.SyncObjs,
  System.Net.URLClient,
  System.Hash;

type
  IIAM4DSSLCertificateValidator = interface;

  /// <summary>
  /// Reason for certificate rejection during validation
  /// </summary>
  TIAM4DCertificateRejectionReason = (
    crrNone,
    crrEmptySubject,
    crrNotYetValid,
    crrExpired,
    crrPublicKeyPinningFailed,
    crrSystemValidationFailed,
    crrUnknown);

  /// <summary>
  /// Event handler for certificate validation notifications
  /// </summary>
  TIAM4DCertificateValidationEvent = procedure(
    Sender: TObject;
    const Certificate: TCertificate;
    Accepted: Boolean;
    Reason: TIAM4DCertificateRejectionReason;
    const Message: string
    ) of object;

  /// <summary>
  /// SSL certificate validation mode
  /// </summary>
  /// <remarks>
  /// svmStrict: Standard validation (system certificate store).
  /// svmAllowSelfSigned: Accepts any certificate within its validity dates, without checking
  /// chain or host name (INSECURE without pinned keys - use only for testing).
  /// Pinned public keys are checked in both modes.
  /// </remarks>
  TIAM4DSSLValidationMode = (
    svmStrict,

    svmAllowSelfSigned);

  /// <summary>
  /// Interface for SSL certificate validation.
  /// </summary>
  /// <remarks>
  /// Supports multiple validation modes and public key pinning.
  /// Thread-safe implementation.
  /// Use for custom certificate validation in HTTPS connections.
  /// </remarks>
  IIAM4DSSLCertificateValidator = interface
    ['{5FF8B6BC-8AF5-433F-9415-57F2ECC9F011}']

    /// <summary>
    /// Sets SSL validation mode
    /// </summary>
    procedure SetValidationMode(AMode: TIAM4DSSLValidationMode);

    /// <summary>
    /// Gets current SSL validation mode
    /// </summary>
    function GetValidationMode: TIAM4DSSLValidationMode;

    /// <summary>
    /// Adds public key hashes for certificate pinning (format: see TIAM4DSSLCertificateValidator.CalculatePublicKeyHash)
    /// </summary>
    procedure AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);

    /// <summary>
    /// Clears all pinned public keys
    /// </summary>
    procedure ClearPinnedPublicKeys;

    /// <summary>
    /// True when at least one public key is pinned
    /// </summary>
    function HasPinnedPublicKeys: Boolean;

    /// <summary>
    /// Validates certificate according to current mode and pinned keys. ASystemAccepted is the
    /// verdict of the platform (chain, host name, dates): svmStrict requires it
    /// </summary>
    function ValidateCertificate(const Certificate: TCertificate; ASystemAccepted: Boolean): Boolean;
  end;

  /// <summary>
  /// SSL certificate validator with support for pinning and custom validation modes.
  /// </summary>
  /// <remarks>
  /// Thread-safe: All public methods are protected by critical section.
  /// Validation modes: Strict (platform verdict), AllowSelfSigned (validity dates only).
  /// Public key pinning, in both modes: SHA-256 of TCertificate.PublicKey as the platform reports
  /// it (64 hex chars, any case). On Windows and Android it is the RSA modulus in hex: other key
  /// types cannot be pinned. A rejected certificate reports its hash in OnCertificateValidation.
  /// On Linux the platform validates the certificate without calling back: pinning is refused.
  /// Events: OnCertificateValidation provides detailed validation information. It is raised only
  /// when the library installs the certificate callback: svmAllowSelfSigned, pinned keys, or
  /// Android; in svmStrict without pins the platform alone validates (no event).
  /// Security: Exceptions in event handlers are silently caught to prevent disruption.
  /// </remarks>
  TIAM4DSSLCertificateValidator = class(TInterfacedObject, IIAM4DSSLCertificateValidator)
  private
    FValidationMode: TIAM4DSSLValidationMode;
    FPinnedPublicKeyHashes: TDictionary<string, Boolean>;
    FLock: TCriticalSection;
    FOnCertificateValidation: TIAM4DCertificateValidationEvent;

    procedure DoOnCertificateValidation(const Certificate: TCertificate;
      Accepted: Boolean; Reason: TIAM4DCertificateRejectionReason; const Message: string);

  public
    constructor Create;
    destructor Destroy; override;

    /// <summary>
    /// Sets SSL validation mode
    /// </summary>
    procedure SetValidationMode(AMode: TIAM4DSSLValidationMode);

    /// <summary>
    /// Gets current SSL validation mode
    /// </summary>
    function GetValidationMode: TIAM4DSSLValidationMode;

    /// <summary>
    /// Adds SHA-256 hashes of public keys for pinning: 64 hex characters, any case (see CalculatePublicKeyHash)
    /// </summary>
    /// <exception cref="ENotSupportedException">On Linux: libcurl does not call back for a certificate
    /// the system accepted, a pin could not be enforced.</exception>
    procedure AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);

    /// <summary>
    /// Clears all pinned public key hashes
    /// </summary>
    procedure ClearPinnedPublicKeys;

    /// <summary>
    /// True when at least one public key is pinned
    /// </summary>
    function HasPinnedPublicKeys: Boolean;

    /// <summary>
    /// Validates certificate based on current mode and pinning rules
    /// </summary>
    function ValidateCertificate(const Certificate: TCertificate; ASystemAccepted: Boolean): Boolean;

    /// <summary>
    /// Calculates SHA-256 hash of a public key string (whitespace and PEM headers removed);
    /// for a pin, pass TCertificate.PublicKey of the server certificate
    /// </summary>
    /// <remarks>
    /// A pin is not the RFC 7469 SPKI hash: THTTPClient reports no DER, only the RSA modulus as
    /// uppercase hex (Windows, Android, macOS/iOS). The pin is SHA-256 of that text, so it can be
    /// computed from the certificate without IAMClient4D:
    ///   openssl x509 -in server.pem -noout -modulus | cut -d= -f2 | tr -d '\r\n' | openssl dgst -sha256
    /// Only RSA keys can be pinned (an EC key reports no PublicKey: the certificate is refused);
    /// on macOS/iOS only 2048-bit RSA keys are reported. Verified by tests\TLS.
    /// </remarks>
    class function CalculatePublicKeyHash(const APublicKeyString: string): string;

    /// <summary>
    /// Normalizes public key format by removing PEM headers and whitespace
    /// </summary>
    class function NormalizePublicKeyFormat(const APublicKey: string): string;

    property OnCertificateValidation: TIAM4DCertificateValidationEvent
      read FOnCertificateValidation write FOnCertificateValidation;
  end;

implementation

uses
  IAMClient4D.Common.CryptoHashUtils;

{ TIAM4DSSLCertificateValidator }

constructor TIAM4DSSLCertificateValidator.Create;
begin
  inherited Create;
  FValidationMode := svmStrict;
  FPinnedPublicKeyHashes := TDictionary<string, Boolean>.Create;
  FLock := TCriticalSection.Create;
  FOnCertificateValidation := nil;
end;

procedure TIAM4DSSLCertificateValidator.DoOnCertificateValidation(
  const Certificate: TCertificate;
  Accepted: Boolean;
  Reason: TIAM4DCertificateRejectionReason;
  const Message: string);
begin
  if Assigned(FOnCertificateValidation) then
  begin
    try
      FOnCertificateValidation(Self, Certificate, Accepted, Reason, Message);
    except
      //ignore
    end;
  end;
end;

destructor TIAM4DSSLCertificateValidator.Destroy;
begin
  FreeAndNil(FPinnedPublicKeyHashes);
  FreeAndNil(FLock);
  inherited;
end;

procedure TIAM4DSSLCertificateValidator.SetValidationMode(AMode: TIAM4DSSLValidationMode);
begin
  FLock.Enter;
  try
    FValidationMode := AMode;
  finally
    FLock.Leave;
  end;
end;

function TIAM4DSSLCertificateValidator.GetValidationMode: TIAM4DSSLValidationMode;
begin
  FLock.Enter;
  try
    Result := FValidationMode;
  finally
    FLock.Leave;
  end;
end;

procedure TIAM4DSSLCertificateValidator.AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);
const
  SHA256_HEX_LENGTH = 64;
var
  LHash: string;
  LNormalizedHash: string;
  LIndex: Integer;
begin
  if Length(APublicKeyHashes) = 0 then
    Exit;

{$IFDEF LINUX}
  // THTTPClient (libcurl) calls OnValidateServerCertificate only for a certificate the system
  // refused: a pin could not be enforced
  raise ENotSupportedException.Create('Public key pinning is not supported on Linux');
{$ENDIF}

  for LHash in APublicKeyHashes do
  begin
    if LHash.Trim.IsEmpty then
      raise EArgumentException.Create('Public key hash cannot be empty');

    LNormalizedHash := LHash.Trim.ToLower;

    if Length(LNormalizedHash) <> SHA256_HEX_LENGTH then
      raise EArgumentException.CreateFmt(
        'Invalid public key hash length. Expected %d hexadecimal characters (SHA-256), got %d. ' +
        'Use TIAM4DSSLCertificateValidator.CalculatePublicKeyHash() to generate valid hashes.',
        [SHA256_HEX_LENGTH, Length(LNormalizedHash)]);

    for LIndex := 1 to Length(LNormalizedHash) do
    begin
      if not CharInSet(LNormalizedHash[LIndex], ['0'..'9', 'a'..'f']) then
        raise EArgumentException.CreateFmt(
          'Invalid character "%s" at position %d in public key hash. ' +
          'Hash must contain only hexadecimal characters (0-9, a-f).',
          [LNormalizedHash[LIndex], LIndex]);
    end;
  end;

  FLock.Enter;
  try
    for LHash in APublicKeyHashes do
    begin
      LNormalizedHash := LHash.Trim.ToLower;
      FPinnedPublicKeyHashes.AddOrSetValue(LNormalizedHash, True);
    end;
  finally
    FLock.Leave;
  end;
end;

function TIAM4DSSLCertificateValidator.HasPinnedPublicKeys: Boolean;
begin
  FLock.Enter;
  try
    Result := FPinnedPublicKeyHashes.Count > 0;
  finally
    FLock.Leave;
  end;
end;

procedure TIAM4DSSLCertificateValidator.ClearPinnedPublicKeys;
begin
  FLock.Enter;
  try
    FPinnedPublicKeyHashes.Clear;
  finally
    FLock.Leave;
  end;
end;

class function TIAM4DSSLCertificateValidator.NormalizePublicKeyFormat(const APublicKey: string): string;
begin
  Result := TIAM4DPublicKeyHashUtils.NormalizePublicKeyFormat(APublicKey);
end;

class function TIAM4DSSLCertificateValidator.CalculatePublicKeyHash(const APublicKeyString: string): string;
begin
  Result := TIAM4DPublicKeyHashUtils.CalculatePublicKeyHash(APublicKeyString);
end;

function TIAM4DSSLCertificateValidator.ValidateCertificate(const Certificate: TCertificate;
  ASystemAccepted: Boolean): Boolean;
var
  LNow: TDateTime;
  LCertHash: string;
  LReason: TIAM4DCertificateRejectionReason;
  LMessage: string;
begin
  Result := False;
  LReason := crrNone;
  LMessage := '';
  LNow := Now;

  FLock.Enter;
  try
    case FValidationMode of
      svmAllowSelfSigned:
        begin
          if Certificate.Subject = '' then
          begin
            LReason := crrEmptySubject;
            LMessage := 'Certificate subject is empty';
          end
          else if Certificate.Start > LNow then
          begin
            LReason := crrNotYetValid;
            LMessage := Format('Certificate not yet valid (starts: %s, now: %s)',
              [DateTimeToStr(Certificate.Start), DateTimeToStr(LNow)]);
          end
          else if Certificate.Expiry < LNow then
          begin
            LReason := crrExpired;
            LMessage := Format('Certificate expired (expiry: %s, now: %s)',
              [DateTimeToStr(Certificate.Expiry), DateTimeToStr(LNow)]);
          end;
        end;
      svmStrict:
        if not ASystemAccepted then
        begin
          LReason := crrSystemValidationFailed;
          LMessage := 'Certificate refused by the system validation';
        end;
    end;

    if LMessage.IsEmpty and (FPinnedPublicKeyHashes.Count > 0) then
    begin
      // The pins are stored in lowercase; no key reported (not RSA on Windows/Android) matches none
      if Certificate.PublicKey.Trim.IsEmpty then
        LCertHash := ''
      else
        LCertHash := CalculatePublicKeyHash(Certificate.PublicKey).ToLower;

      if LCertHash.IsEmpty then
      begin
        LReason := crrPublicKeyPinningFailed;
        LMessage := Format('Public key pinning failed: no public key reported (%d pins configured)',
          [FPinnedPublicKeyHashes.Count]);
      end
      else if not FPinnedPublicKeyHashes.ContainsKey(LCertHash) then
      begin
        LReason := crrPublicKeyPinningFailed;
        LMessage := Format('Public key pinning failed (hash: %s, %d pins configured)',
          [LCertHash, FPinnedPublicKeyHashes.Count]);
      end;
    end;

    if LMessage.IsEmpty then
    begin
      Result := True;
      LMessage := 'Certificate accepted';
    end;
  finally
    FLock.Leave;
  end;

  DoOnCertificateValidation(Certificate, Result, LReason, LMessage);
end;

end.

