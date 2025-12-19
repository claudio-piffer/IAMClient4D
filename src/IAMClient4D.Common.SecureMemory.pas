unit IAMClient4D.Common.SecureMemory;

interface

uses
  System.SysUtils, System.Classes;

/// <summary>
/// Constant-time byte array comparison to prevent timing attacks.
/// </summary>
/// <param name="A">First byte array to compare</param>
/// <param name="B">Second byte array to compare</param>
/// <returns>True if arrays are equal, False otherwise</returns>
/// <remarks>
/// SECURITY: Uses constant-time comparison algorithm to prevent timing side-channel attacks.
/// Always compares ALL bytes regardless of differences found.
/// Critical for: JWT signatures, HMAC verification, password hashes, cryptographic tokens.
/// Performance: O(max(len(A), len(B))) - no early exit optimization.
/// Thread-safe: Yes (no shared state).
/// TIMING ATTACK PREVENTION: Length difference is accumulated into the diff byte,
/// not used for early exit. The loop always iterates over the maximum length.
///
/// LIMITATION: The loop iteration count varies with input lengths. While the comparison
/// result does not leak early, an attacker may infer length information via timing
/// analysis. For most OAuth2/JWT use cases (where lengths are predictable), this is
/// acceptable. For highly sensitive applications, consider padding inputs to equal
/// lengths before comparison.
/// </remarks>
function SecureEquals(const A, B: TBytes): Boolean;

/// <summary>
/// Constant-time string comparison to prevent timing attacks.
/// </summary>
/// <param name="A">First string to compare</param>
/// <param name="B">Second string to compare</param>
/// <returns>True if strings are equal, False otherwise</returns>
/// <remarks>
/// SECURITY: Uses constant-time comparison algorithm to prevent timing side-channel attacks.
/// Converts strings to UTF-8 bytes and uses SecureEquals for comparison.
/// Critical for: State parameters, authorization codes, CSRF tokens.
/// Thread-safe: Yes (no shared state).
/// </remarks>
function SecureStringEquals(const A, B: string): Boolean;

/// <summary>
/// Securely wipes byte array content from memory before deallocation.
/// </summary>
/// <param name="A">Byte array to wipe (passed by reference)</param>
/// <remarks>
/// SECURITY: Overwrites memory with zeros before deallocation to prevent data remnants.
/// Use for: Private keys, passwords, tokens, sensitive cryptographic material.
/// Implementation: Multi-pass wipe with compiler optimization disabled.
/// Thread-safe: Yes (operates on caller's variable).
///
/// LIMITATION (DELPHI LANGUAGE): The {$O-} directive disables some optimizations but
/// does NOT prevent Dead Store Elimination (DSE) in all cases. The Delphi compiler may
/// still optimize away memory writes if it determines the values are never read.
/// This implementation uses pointer-based writes (VolatileWrite) to mitigate DSE, but
/// complete prevention cannot be guaranteed without platform-specific APIs like
/// Windows RtlSecureZeroMemory. For maximum security in production environments,
/// consider using platform-specific secure wipe functions.
/// </remarks>
procedure SecureZero(var A: TBytes);

/// <summary>
/// Securely wipes string content from memory.
/// </summary>
/// <param name="S">String to wipe (passed by reference)</param>
/// <remarks>
/// SECURITY: Overwrites string memory with zeros before clearing.
/// Use for: Passwords, tokens, sensitive text data.
/// Thread-safe: Yes (operates on caller's variable).
///
/// WARNING (DELPHI LANGUAGE LIMITATION): Delphi strings are immutable and reference-counted.
/// This function calls UniqueString() before wiping, which creates a COPY of the string
/// if the reference count is greater than 1. In such cases:
/// - Only the copy is wiped; the original data may remain in memory
/// - Previous string locations (before reallocations) are NOT wiped
/// - String literals are stored in read-only memory and CANNOT be wiped
///
/// This is a fundamental limitation of the Delphi string implementation.
/// For truly sensitive data, prefer using TBytes with SecureZero() instead of strings.
/// After calling this function, the string variable will be empty, but complete memory
/// erasure of all copies cannot be guaranteed.
/// </remarks>
procedure SecureZeroString(var S: string);

implementation

{$O-} // Disable optimization for security-critical functions

function SecureEquals(const A, B: TBytes): Boolean;
var
  LIndex: Integer;
  LDiff: Cardinal;
  LLenA, LLenB, LMaxLen: Integer;
  LByteA, LByteB: Byte;
begin
  LLenA := Length(A);
  LLenB := Length(B);

  // Accumulate length difference into diff (constant-time, no early exit)
  LDiff := Cardinal(LLenA xor LLenB);

  // Determine maximum length for iteration
  if LLenA > LLenB then
    LMaxLen := LLenA
  else
    LMaxLen := LLenB;

  // Always iterate over maximum length to prevent timing attacks
  for LIndex := 0 to LMaxLen - 1 do
  begin
    // Safe access: use 0 for out-of-bounds indices
    if LIndex < LLenA then
      LByteA := A[LIndex]
    else
      LByteA := 0;

    if LIndex < LLenB then
      LByteB := B[LIndex]
    else
      LByteB := 0;

    LDiff := LDiff or Cardinal(LByteA xor LByteB);
  end;

  Result := LDiff = 0;
end;

function SecureStringEquals(const A, B: string): Boolean;
var
  LBytesA, LBytesB: TBytes;
begin
  LBytesA := TEncoding.UTF8.GetBytes(A);
  LBytesB := TEncoding.UTF8.GetBytes(B);
  try
    Result := SecureEquals(LBytesA, LBytesB);
  finally
    SecureZero(LBytesA);
    SecureZero(LBytesB);
  end;
end;

/// <summary>
/// Internal volatile write to prevent compiler optimization.
/// </summary>
/// <remarks>
/// NOTE: Delphi does not have a true "volatile" keyword like C/C++.
/// Writing through a pointer helps prevent optimization, but the compiler
/// may still eliminate the write in some circumstances. This is a
/// best-effort approach within Delphi's language constraints.
/// </remarks>
procedure VolatileWrite(APtr: PByte; AValue: Byte); inline;
begin
  APtr^ := AValue;
end;

procedure SecureZero(var A: TBytes);
var
  LIndex: Integer;
  LLen: Integer;
  LPtr: PByte;
begin
  LLen := Length(A);
  if LLen > 0 then
  begin
    LPtr := @A[0];

    for LIndex := 0 to LLen - 1 do
    begin
      VolatileWrite(LPtr, $FF);
      Inc(LPtr);
    end;

    LPtr := @A[0];
    for LIndex := 0 to LLen - 1 do
    begin
      VolatileWrite(LPtr, 0);
      Inc(LPtr);
    end;

    SetLength(A, 0);
  end;
end;

procedure SecureZeroString(var S: string);
var
  LIndex: Integer;
  LLen: Integer;
  LPtr: PChar;
begin
  LLen := Length(S);
  if LLen > 0 then
  begin
    UniqueString(S);
    LPtr := PChar(S);

    for LIndex := 0 to LLen - 1 do
    begin
      LPtr^ := #0;
      Inc(LPtr);
    end;

    S := '';
  end;
end;

{$O+} // Re-enable optimization

end.