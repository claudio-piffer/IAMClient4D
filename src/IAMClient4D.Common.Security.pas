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
    crrStrictModeBypass,
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
  /// svmAllowSelfSigned: Accepts self-signed certificates with basic checks.
  /// svmDisabled: No validation (INSECURE - use only for testing).
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
    /// Adds public key hashes for certificate pinning
    /// </summary>
    procedure AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);

    /// <summary>
    /// Clears all pinned public keys
    /// </summary>
    procedure ClearPinnedPublicKeys;

    /// <summary>
    /// Validates certificate according to current mode
    /// </summary>
    function ValidateCertificate(const Certificate: TCertificate): Boolean;
  end;

  /// <summary>
  /// SSL certificate validator with support for pinning and custom validation modes.
  /// </summary>
  /// <remarks>
  /// Thread-safe: All public methods are protected by critical section.
  /// Validation modes: Strict (system store), AllowSelfSigned (basic checks + pinning), Disabled (no checks).
  /// Public key pinning: Uses SHA-256 hashes of public keys (64 hex chars).
  /// Events: OnCertificateValidation provides detailed validation information.
  /// Security: Exceptions in event handlers are silently caught to prevent disruption.
  /// Hash format: Use CalculatePublicKeyHash() to generate valid hashes from PEM keys.
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
    /// Adds SHA-256 hashes of public keys for pinning
    /// </summary>
    procedure AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);

    /// <summary>
    /// Clears all pinned public key hashes
    /// </summary>
    procedure ClearPinnedPublicKeys;

    /// <summary>
    /// Validates certificate based on current mode and pinning rules
    /// </summary>
    function ValidateCertificate(const Certificate: TCertificate): Boolean;

    /// <summary>
    /// Calculates SHA-256 hash of public key string (PEM format)
    /// </summary>
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

function TIAM4DSSLCertificateValidator.ValidateCertificate(const Certificate: TCertificate): Boolean;
var
  LNow: TDateTime;
  LCertHash: string;
  LMode: TIAM4DSSLValidationMode;
  LReason: TIAM4DCertificateRejectionReason;
  LMessage: string;
begin
  Result := False;
  LMessage := '';

  FLock.Enter;
  try
    LMode := FValidationMode;

    case LMode of
      svmAllowSelfSigned:
        begin
          if Certificate.Subject = '' then
          begin
            LReason := crrEmptySubject;
            LMessage := 'Certificate subject is empty';
            DoOnCertificateValidation(Certificate, False, LReason, LMessage);
            Exit(False);
          end;

          LNow := Now;
          if Certificate.Start > LNow then
          begin
            LReason := crrNotYetValid;
            LMessage := Format('Certificate not yet valid (starts: %s, now: %s)',
              [DateTimeToStr(Certificate.Start), DateTimeToStr(LNow)]);
            DoOnCertificateValidation(Certificate, False, LReason, LMessage);
            Exit(False);
          end;

          if Certificate.Expiry < LNow then
          begin
            LReason := crrExpired;
            LMessage := Format('Certificate expired (expiry: %s, now: %s)',
              [DateTimeToStr(Certificate.Expiry), DateTimeToStr(LNow)]);
            DoOnCertificateValidation(Certificate, False, LReason, LMessage);
            Exit(False);
          end;

          if FPinnedPublicKeyHashes.Count > 0 then
          begin
            LCertHash := CalculatePublicKeyHash(Certificate.PublicKey);

            if not FPinnedPublicKeyHashes.ContainsKey(LCertHash) then
            begin
              LReason := crrPublicKeyPinningFailed;
              LMessage := Format('Public key pinning failed (hash: %s, %d pins configured)',
                [LCertHash, FPinnedPublicKeyHashes.Count]);
              DoOnCertificateValidation(Certificate, False, LReason, LMessage);
              Exit(False);
            end;
          end;

          Result := True;
          LReason := crrNone;
          LMessage := 'Certificate accepted (svmAllowSelfSigned)';
          DoOnCertificateValidation(Certificate, True, LReason, LMessage);
        end;

      svmStrict:
        begin
          Result := False;
          LReason := crrStrictModeBypass;
          LMessage := 'ValidateCertificate called in svmStrict mode (should not happen)';
          DoOnCertificateValidation(Certificate, False, LReason, LMessage);
        end;
    end;
  finally
    FLock.Leave;
  end;
end;

end.