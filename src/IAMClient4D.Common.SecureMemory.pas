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
/// Performance: O(n) where n is array length - no early exit optimization.
/// Thread-safe: Yes (no shared state).
/// </remarks>
function SecureEquals(const A, B: TBytes): Boolean;

/// <summary>
/// Securely wipes byte array content from memory before deallocation.
/// </summary>
/// <param name="A">Byte array to wipe (passed by reference)</param>
/// <remarks>
/// SECURITY: Overwrites memory with zeros before deallocation to prevent data remnants.
/// Use for: Private keys, passwords, tokens, sensitive cryptographic material.
/// Implementation: FillChar + SetLength(0) for secure cleanup.
/// Note: Compiler optimizations may affect effectiveness; implementation uses best-effort approach.
/// Thread-safe: Yes (operates on caller's variable).
/// </remarks>
procedure SecureZero(var A: TBytes);

implementation

function SecureEquals(const A, B: TBytes): Boolean;
var
  LIndex: Integer;
  LDiff: Byte;
begin
  if Length(A) <> Length(B) then
    Exit(False);
  LDiff := 0;
  for LIndex := 0 to High(A) do
    LDiff := LDiff or (A[LIndex] xor B[LIndex]);
  Result := LDiff = 0;
end;

procedure SecureZero(var A: TBytes);
begin
  if Length(A) > 0 then
  begin
    FillChar(A[0], Length(A), 0);
    SetLength(A, 0);
  end;
end;

end.