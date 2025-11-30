{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Common.PKCEGenerator.pas
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

unit IAMClient4D.Common.PKCEGenerator;

interface

uses
  System.SysUtils,
  System.Hash,
  System.NetEncoding;

type
  /// <summary>
  /// PKCE (Proof Key for Code Exchange) generator for OAuth2 Authorization Code flow.
  /// </summary>
  /// <remarks>
  /// Implements RFC 7636 PKCE extension to protect against authorization code interception.
  /// Uses SHA-256 for challenge calculation (code_challenge_method=S256).
  /// Verifier: 32 cryptographically secure random bytes, Base64URL encoded (43-128 chars).
  /// Challenge: SHA-256 hash of verifier, Base64URL encoded.
  /// All methods are static and thread-safe.
  /// Security: Always use GenerateVerifier() for new flows - never reuse verifiers.
  /// </remarks>
  TIAM4DPKCEGenerator = class
  public
    /// <summary>
    /// Generates both PKCE verifier and challenge
    /// </summary>
    class procedure Generate(out AVerifier, AChallenge: string); static;

    /// <summary>
    /// Generates cryptographically secure PKCE verifier
    /// </summary>
    class function GenerateVerifier: string; static;

    /// <summary>
    /// Calculates PKCE challenge from verifier using SHA-256
    /// </summary>
    class function CalculateChallenge(const AVerifier: string): string; static;

    /// <summary>
    /// Validates PKCE verifier format per RFC 7636
    /// </summary>
    class function IsValidVerifier(const AVerifier: string): Boolean; static;
  end;

implementation

uses
  IAMClient4D.Common.CryptoUtils;

const
  PKCE_VERIFIER_BYTES = 32;

  { TIAM4DPKCEGenerator }

class function TIAM4DPKCEGenerator.GenerateVerifier: string;
var
  LRandomBytes: TBytes;
begin
  LRandomBytes := TIAM4DCryptoUtils.GenerateSecureRandomBytes(PKCE_VERIFIER_BYTES);

  Result := TNetEncoding.Base64URL.EncodeBytesToString(LRandomBytes);

  Result := Result.Replace('=', EmptyStr, [rfReplaceAll]);
end;

class function TIAM4DPKCEGenerator.CalculateChallenge(const AVerifier: string): string;
var
  LVerifierBytes: TBytes;
  LHashBytes: TBytes;
  LHash: THashSHA2;
begin
  if AVerifier.Trim.IsEmpty then
    raise EArgumentException.Create('PKCE verifier cannot be empty');

  LVerifierBytes := TEncoding.UTF8.GetBytes(AVerifier);

  LHash := THashSHA2.Create;
  LHash.Update(LVerifierBytes, Length(LVerifierBytes));
  LHashBytes := LHash.HashAsBytes;

  Result := TNetEncoding.Base64URL.EncodeBytesToString(LHashBytes);
  Result := Result.Replace('=', EmptyStr, [rfReplaceAll]);
end;

class procedure TIAM4DPKCEGenerator.Generate(out AVerifier, AChallenge: string);
begin
  AVerifier := GenerateVerifier;

  AChallenge := CalculateChallenge(AVerifier);
end;

class function TIAM4DPKCEGenerator.IsValidVerifier(const AVerifier: string): Boolean;
var
  LLen: Integer;
  LIndex: Integer;
  LChar: Char;
const
  MIN_LENGTH = 43;
  MAX_LENGTH = 128;
  BASE64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
begin
  Result := False;

  LLen := Length(AVerifier);

  if (LLen < MIN_LENGTH) or (LLen > MAX_LENGTH) then
    Exit;

  for LIndex := 1 to LLen do
  begin
    LChar := AVerifier[LIndex];
    if Pos(LChar, BASE64URL_CHARS) = 0 then
      Exit;
  end;

  Result := True;
end;

end.