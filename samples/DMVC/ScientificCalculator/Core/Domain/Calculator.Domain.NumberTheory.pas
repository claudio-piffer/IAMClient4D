unit Calculator.Domain.NumberTheory;

{ Domain layer: primality, factorization and combinatorics. }

interface

type
  TNumberTheory = record
  public const
    // Trial division up to 10^6: answers in a few milliseconds
    MAX_FACTORIZABLE = 1000000000000;
    MAX_COMBINATORICS_N = 1000;
  public
    class function IsPrime(const AN: Int64): Boolean; static;
    /// <summary>Prime factors in ascending order, with repetitions (12 -> 2, 2, 3).</summary>
    class function PrimeFactors(const AN: Int64): TArray<Int64>; static;
    /// <summary>n choose k.</summary>
    class function Combinations(const AN, AK: Integer): Double; static;
    /// <summary>Ordered arrangements of k out of n.</summary>
    class function Permutations(const AN, AK: Integer): Double; static;
  end;

implementation

uses
  System.SysUtils,
  System.Generics.Collections,
  Calculator.Domain.Errors;

const
  EXACT_INTEGER_LIMIT = 9007199254740992.0;

procedure CheckFactorizable(const AN: Int64; const AOperation: string);
begin
  if (AN < 2) or (AN > TNumberTheory.MAX_FACTORIZABLE) then
    raise ECalculatorDomainError.CreateFmt('%s: n must be between 2 and %d',
      [AOperation, TNumberTheory.MAX_FACTORIZABLE]);
end;

procedure CheckCombinatorics(const AN, AK: Integer);
begin
  if (AN < 0) or (AN > TNumberTheory.MAX_COMBINATORICS_N) then
    raise ECalculatorDomainError.CreateFmt('combinatorics: n must be between 0 and %d',
      [TNumberTheory.MAX_COMBINATORICS_N]);
  if (AK < 0) or (AK > AN) then
    raise ECalculatorDomainError.Create('combinatorics: k must be between 0 and n');
end;

{ TNumberTheory }

class function TNumberTheory.IsPrime(const AN: Int64): Boolean;
var
  LDivisor: Int64;
begin
  CheckFactorizable(AN, 'prime');
  if AN < 4 then
    Exit(True);
  if AN mod 2 = 0 then
    Exit(False);
  LDivisor := 3;
  while LDivisor * LDivisor <= AN do
  begin
    if AN mod LDivisor = 0 then
      Exit(False);
    Inc(LDivisor, 2);
  end;
  Result := True;
end;

class function TNumberTheory.PrimeFactors(const AN: Int64): TArray<Int64>;
var
  LFactors: TList<Int64>;
  LRest, LDivisor: Int64;
begin
  CheckFactorizable(AN, 'prime');
  LFactors := TList<Int64>.Create;
  try
    LRest := AN;
    LDivisor := 2;
    while LDivisor * LDivisor <= LRest do
    begin
      while LRest mod LDivisor = 0 do
      begin
        LFactors.Add(LDivisor);
        LRest := LRest div LDivisor;
      end;
      if LDivisor = 2 then
        LDivisor := 3
      else
        Inc(LDivisor, 2);
    end;
    if LRest > 1 then
      LFactors.Add(LRest);
    Result := LFactors.ToArray;
  finally
    LFactors.Free;
  end;
end;

class function TNumberTheory.Combinations(const AN, AK: Integer): Double;
var
  LK, LIndex: Integer;
begin
  CheckCombinatorics(AN, AK);
  // C(n, k) = C(n, n - k): fewer, smaller factors
  LK := AK;
  if LK > AN - LK then
    LK := AN - LK;
  Result := 1;
  for LIndex := 1 to LK do
    Result := Result * (AN - LK + LIndex) / LIndex;
  // Exact integer while a Double can hold it (2^53)
  if Result < EXACT_INTEGER_LIMIT then
    Result := Round(Result);
  Result := EnsureFinite(Result, 'combinations');
end;

class function TNumberTheory.Permutations(const AN, AK: Integer): Double;
var
  LIndex: Integer;
begin
  CheckCombinatorics(AN, AK);
  Result := 1;
  for LIndex := AN - AK + 1 to AN do
    Result := Result * LIndex;
  Result := EnsureFinite(Result, 'permutations');
end;

end.
