program IAM4DCryptoTest;

// Crypto provider test: JWS vectors (RFC 7515/7520 + OpenSSL), AES-256-GCM vectors,
// storage provider and AES token storage, for the provider selected by the defines.
// Usage: IAM4DCryptoTest [OpenSSL folder]   (folder used by TaurusTLS builds only)

{$APPTYPE CONSOLE}

{$I IAMClient4D.Config.inc}

uses
  System.SysUtils,
  System.JSON,
  System.NetEncoding,
  System.Hash,
  System.Classes,
  System.Diagnostics,
  System.Threading,
  System.SyncObjs,
  {$IF DEFINED(IAM4D_CRYPTO_TAURUSTLS) AND DEFINED(MSWINDOWS)}
  Winapi.Windows,
  Winapi.PsAPI,
  {$ENDIF}
  IAMClient4D.Core,
  IAMClient4D.Exceptions,
  IAMClient4D.Storage.Core,
  IAMClient4D.Storage.Crypto.Interfaces,
  IAMClient4D.Storage.Crypto.Factory,
  IAMClient4D.Storage.AESMemoryTokenStorage,
  IAMClient4D.Security.Core,
  IAMClient4D.Security.Crypto.Interfaces,
  IAMClient4D.Security.Crypto.Factory,
  IAMClient4D.Security.JWT.Verifiers.RSA,
  IAMClient4D.Security.JWT.Verifiers.RSAPSS,
  IAMClient4D.Security.JWT.Verifiers.ECDSA,
  IAMClient4D.Security.JWT.Verifiers.Universal,
  {$IFDEF IAM4D_CRYPTO_TAURUSTLS}
  IAMClient4D.Crypto.TaurusTLS.Common,
  IAMClient4D.Security.Crypto.TaurusTLS,
  {$ENDIF}
  CryptoTestVectorsU in 'CryptoTestVectorsU.pas';

const
  // Group orders (SEC 2)
  P256_ORDER = 'FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551';
  P384_ORDER = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973';
  P521_ORDER = '01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409';

var
  GPassed: Integer = 0;
  GFailed: Integer = 0;

procedure Check(const AName: string; ACondition: Boolean);
begin
  if ACondition then
    Inc(GPassed)
  else
  begin
    Inc(GFailed);
    Writeln('  FAIL ', AName);
  end;
end;

// AFunc must return AExpected without raising
procedure Expect(const AName: string; const AFunc: TFunc<Boolean>; AExpected: Boolean);
begin
  try
    Check(AName, AFunc() = AExpected);
  except
    on E: Exception do
      Check(AName + ' (' + E.ClassName + ': ' + E.Message + ')', False);
  end;
end;

function Raises(const AProc: TProc; AClass: ExceptClass): Boolean;
begin
  try
    AProc();
    Result := False;
  except
    on E: Exception do
      Result := E is AClass;
  end;
end;

function HexToBytes(const AHex: string): TBytes;
var
  I: Integer;
begin
  SetLength(Result, Length(AHex) div 2);
  for I := 0 to High(Result) do
    Result[I] := StrToInt('$' + Copy(AHex, I * 2 + 1, 2));
end;

function Base64URLDecode(const AInput: string): TBytes;
var
  LBase64: string;
begin
  LBase64 := AInput.Replace('-', '+').Replace('_', '/');
  if Length(LBase64) mod 4 > 0 then
    LBase64 := LBase64 + StringOfChar('=', 4 - Length(LBase64) mod 4);
  Result := TNetEncoding.Base64.DecodeStringToBytes(LBase64);
end;

function BytesEqual(const A, B: TBytes): Boolean;
begin
  Result := (Length(A) = Length(B)) and ((Length(A) = 0) or CompareMem(@A[0], @B[0], Length(A)));
end;

function Flipped(const A: TBytes; AIndex: Integer): TBytes;
begin
  Result := Copy(A);
  Result[AIndex] := Result[AIndex] xor $01;
end;

function Zeros(ACount: Integer): TBytes;
begin
  SetLength(Result, ACount);
  FillChar(Result[0], ACount, 0);
end;

// Big-endian A + B, same length; nil on overflow
function AddBigEndian(const A, B: TBytes): TBytes;
var
  I, LSum: Integer;
begin
  SetLength(Result, Length(A));
  LSum := 0;
  for I := High(A) downto 0 do
  begin
    LSum := LSum + A[I] + B[I];
    Result[I] := Byte(LSum);
    LSum := LSum shr 8;
  end;
  if LSum <> 0 then
    Result := nil;
end;

function HashOf(const AAlg: string): TIAM4DHashAlgorithm;
begin
  if AAlg.EndsWith('384') then
    Result := haSHA384
  else if AAlg.EndsWith('512') then
    Result := haSHA512
  else
    Result := haSHA256;
end;

function HashSize(AHashAlg: TIAM4DHashAlgorithm): Integer;
const
  SIZES: array[TIAM4DHashAlgorithm] of Integer = (32, 48, 64);
begin
  Result := SIZES[AHashAlg];
end;

function SHA2(const AData: TBytes; AHashAlg: TIAM4DHashAlgorithm): TBytes;
const
  VERSIONS: array[TIAM4DHashAlgorithm] of THashSHA2.TSHA2Version = (
    THashSHA2.TSHA2Version.SHA256, THashSHA2.TSHA2Version.SHA384, THashSHA2.TSHA2Version.SHA512);
var
  LHash: THashSHA2;
begin
  LHash := THashSHA2.Create(VERSIONS[AHashAlg]);
  LHash.Update(AData);
  Result := LHash.HashAsBytes;
end;

// EMSA-PKCS1-v1_5 (RFC 8017 9.2)
function PKCS1EncodedMessage(const AMessage: TBytes; AHashAlg: TIAM4DHashAlgorithm; AK: Integer): TBytes;
const
  DIGEST_INFO: array[TIAM4DHashAlgorithm] of string = (
    '3031300d060960864801650304020105000420',
    '3041300d060960864801650304020205000430',
    '3051300d060960864801650304020305000440');
var
  LT: TBytes;
begin
  LT := HexToBytes(DIGEST_INFO[AHashAlg]) + SHA2(AMessage, AHashAlg);
  SetLength(Result, AK);
  FillChar(Result[0], AK, $FF);
  Result[0] := 0;
  Result[1] := 1;
  Result[AK - Length(LT) - 1] := 0;
  Move(LT[0], Result[AK - Length(LT)], Length(LT));
end;

function DerInteger(const AValue: TBytes): TBytes;
var
  LStart: Integer;
begin
  LStart := 0;
  while (LStart < High(AValue)) and (AValue[LStart] = 0) do
    Inc(LStart);
  Result := Copy(AValue, LStart, MaxInt);
  if Result[0] >= $80 then
    Result := [0] + Result;
  Result := [$02, Byte(Length(Result))] + Result;
end;

// ECDSA-Sig-Value as produced by OpenSSL
function DerSignature(const AR, AS_: TBytes): TBytes;
begin
  Result := DerInteger(AR) + DerInteger(AS_);
  if Length(Result) < $80 then
    Result := [$30, Byte(Length(Result))] + Result
  else
    Result := [$30, $81, Byte(Length(Result))] + Result;
end;

function JWKField(const AJWK, AName: string): TBytes;
var
  LJWK: TJSONObject;
begin
  LJWK := TJSONObject.ParseJSONValue(AJWK) as TJSONObject;
  try
    Result := Base64URLDecode(LJWK.GetValue<string>(AName));
  finally
    LJWK.Free;
  end;
end;

function RSAJWK(const AModulus, AExponent: TBytes): string;
begin
  Result := Format('{"kty":"RSA","n":"%s","e":"%s"}',
    [TNetEncoding.Base64URL.EncodeBytesToString(AModulus), TNetEncoding.Base64URL.EncodeBytesToString(AExponent)]);
end;

function FindVector(const ASource, AAlg: string): TJWSVector;
var
  LVector: TJWSVector;
begin
  for LVector in JWS_VECTORS do
    if (LVector.Source = ASource) and (LVector.Alg = AAlg) then
      Exit(LVector);
  raise Exception.CreateFmt('Vector %s %s not found', [ASource, AAlg]);
end;

function VerifySignature(const AVerifier: IIAM4DJWTSignatureVerifier; const ASigningInput: string;
  const ASignature: TBytes; const AJWK, AAlg: string): Boolean;
var
  LJWK: TJSONObject;
begin
  LJWK := TJSONObject.ParseJSONValue(AJWK) as TJSONObject;
  try
    Result := AVerifier.Verify(ASigningInput, ASignature, LJWK, AAlg);
  finally
    LJWK.Free;
  end;
end;

function VerifyVector(const AVerifier: IIAM4DJWTSignatureVerifier; const AVector: TJWSVector;
  const AJWK, AAlg: string): Boolean;
begin
  Result := VerifySignature(AVerifier, AVector.SigningInput, Base64URLDecode(AVector.Signature), AJWK, AAlg);
end;

// ECDSA through the provider, bypassing the verifier size checks
function ProviderECDSAVerify(const AProvider: IIAM4DCryptoProvider; const AMessage, AR, AS_, AX, AY: TBytes;
  ACurve: TIAM4DECCurve; AHashAlg: TIAM4DHashAlgorithm): Boolean;
var
  LMessageVerifier: IIAM4DECDSAMessageVerifier;
begin
  if Supports(AProvider, IIAM4DECDSAMessageVerifier, LMessageVerifier) then
    Result := LMessageVerifier.ECDSAVerifyMessage(AMessage, AR, AS_, AX, AY, ACurve)
  else
    Result := AProvider.ECDSAVerify(SHA2(AMessage, AHashAlg), AR, AS_, AX, AY, ACurve);
end;

procedure TestFactories;
begin
  Writeln('Factories');
  Check('cpCustom rejected', Raises(
    procedure begin TIAM4DCryptoProviderFactory.CreateProvider(cpCustom) end, EArgumentException));
  Check('scpCustom rejected', Raises(
    procedure begin TIAM4DStorageCryptoProviderFactory.CreateProvider(HexToBytes(StringOfChar('0', 64)), scpCustom) end,
    EArgumentException));
  Check('storage key length enforced', Raises(
    procedure begin TIAM4DStorageCryptoProviderFactory.CreateProvider(HexToBytes('00')) end, EArgumentException));
  Check('JWT provider name', TIAM4DCryptoProviderFactory.CreateProvider.GetProviderName =
    TIAM4DCryptoProviderFactory.GetDefaultProviderName);
end;

// The provider built supports what it must: a missing algorithm fails here instead of turning
// the checks of the other tests into "rejected as unsupported" or an early Exit
procedure TestExpectedAlgorithms;
const
  ALL_ALGS: array[0..8] of string = ('RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512');
var
  LProvider: IIAM4DCryptoProvider;
  LExpected: string;
  LStorage: string;
  LAlg: string;
  LMust: Boolean;
begin
  Writeln('Expected algorithms');
  {$IF DEFINED(IAM4D_CRYPTO_TMS) OR DEFINED(IAM4D_CRYPTO_TAURUSTLS)}
  LExpected := ' RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512 ';
  LStorage := 'AES-256-GCM';
  {$ELSE}
  // LockBox3: RSA only
  LExpected := ' RS256 RS384 RS512 PS256 PS384 PS512 ';
  LStorage := 'AES-256-CBC-HMAC-SHA256';
  {$ENDIF}
  LProvider := TIAM4DCryptoProviderFactory.CreateProvider;
  for LAlg in ALL_ALGS do
  begin
    LMust := LExpected.Contains(' ' + LAlg + ' ');
    if LMust then
      Check(LAlg + ' supported', LProvider.SupportsAlgorithm(LAlg))
    else
      Check(LAlg + ' not supported', not LProvider.SupportsAlgorithm(LAlg));
  end;
  Check('storage algorithm ' + LStorage,
    TIAM4DStorageCryptoProviderFactory.CreateProvider(HexToBytes(StringOfChar('0', 64))).GetAlgorithm = LStorage);
end;

procedure TestJWSVectors;
var
  LProvider: IIAM4DCryptoProvider;
  LVerifier: IIAM4DJWTSignatureVerifier;
  LVector: TJWSVector;
  LJWK: TJSONObject;
  LSig: TBytes;
  LName: string;
begin
  Writeln('JWS vectors');
  LProvider := TIAM4DCryptoProviderFactory.CreateProvider;
  LVerifier := TUniversalJWTSignatureVerifier.Create(LProvider);

  for LVector in JWS_VECTORS do
  begin
    LName := LVector.Source + ' ' + LVector.Alg;
    LSig := Base64URLDecode(LVector.Signature);
    LJWK := TJSONObject.ParseJSONValue(LVector.JWK) as TJSONObject;
    try
      if LProvider.SupportsAlgorithm(LVector.Alg) then
      begin
        Check(LName + ' valid', LVerifier.Verify(LVector.SigningInput, LSig, LJWK, LVector.Alg));
        Check(LName + ' tampered signature',
          not LVerifier.Verify(LVector.SigningInput, Flipped(LSig, Length(LSig) div 2), LJWK, LVector.Alg));
        Check(LName + ' tampered input',
          not LVerifier.Verify(LVector.SigningInput + 'A', LSig, LJWK, LVector.Alg));
      end
      else
        Check(LName + ' rejected as unsupported', Raises(
          procedure begin LVerifier.Verify(LVector.SigningInput, LSig, LJWK, LVector.Alg) end,
          EIAM4DSecurityValidationException));
    finally
      LJWK.Free;
    end;
  end;
end;

procedure TestKeyConfusion;
var
  LProvider: IIAM4DCryptoProvider;
  LVerifier: IIAM4DJWTSignatureVerifier;
  LRS, LES, LES384: TJWSVector;
  LBadPoint: string;
begin
  Writeln('Key/algorithm confusion');
  LProvider := TIAM4DCryptoProviderFactory.CreateProvider;
  LVerifier := TUniversalJWTSignatureVerifier.Create(LProvider);
  LRS := FindVector('RFC 7515 A.2', 'RS256');

  Check('RS256 signature as PS256', not VerifyVector(LVerifier, LRS, LRS.JWK, 'PS256'));

  if not LProvider.SupportsAlgorithm('ES256') then
    Exit;

  LES := FindVector('RFC 7515 A.3', 'ES256');
  LES384 := FindVector('OpenSSL P-384', 'ES384');
  Check('EC key with RS256', not VerifyVector(LVerifier, LES, LES.JWK, 'RS256'));
  Check('RSA key with ES256', not VerifyVector(LVerifier, LES, LRS.JWK, 'ES256'));
  Check('ES256 signature as ES384', not VerifyVector(LVerifier, LES, LES.JWK, 'ES384'));
  Check('P-384 key with ES256', not VerifyVector(LVerifier, LES, LES384.JWK, 'ES256'));
  Check('curve relabeled', not VerifyVector(LVerifier, LES, LES.JWK.Replace('P-256', 'P-384'), 'ES256'));

  // x changed: point no longer on the curve
  LBadPoint := LES.JWK.Replace('"x":"f83O', '"x":"f83P');
  Check('point not on curve', not VerifyVector(LVerifier, LES, LBadPoint, 'ES256'));
end;

procedure TestAlgorithmNames;
var
  LProvider: IIAM4DCryptoProvider;
  LVerifier, LRSA, LPSS, LECDSA: IIAM4DJWTSignatureVerifier;
  LRS, LPS, LES: TJWSVector;
  LAlg: string;
begin
  Writeln('Algorithm names (case-sensitive, RFC 7515 4.1.1)');
  LProvider := TIAM4DCryptoProviderFactory.CreateProvider;
  LVerifier := TUniversalJWTSignatureVerifier.Create(LProvider);
  LRS := FindVector('RFC 7515 A.2', 'RS256');
  LPS := FindVector('RFC 7520 4.2', 'PS384');

  for LAlg in TArray<string>.Create('rs256', 'Rs256', 'RS256 ', 'none', 'None', 'NONE', 'HS256', 'hs256', '') do
    Check('universal verifier rejects "' + LAlg + '"', Raises(
      procedure begin VerifyVector(LVerifier, LRS, LRS.JWK, LAlg) end, EIAM4DSecurityValidationException));
  Check('universal verifier rejects "ps384"', Raises(
    procedure begin VerifyVector(LVerifier, LPS, LPS.JWK, 'ps384') end, EIAM4DSecurityValidationException));

  // Held in interface variables: an object passed straight to a const interface parameter leaks
  LRSA := TRSAJWTSignatureVerifier.Create(LProvider);
  LPSS := TRSAPSSJWTSignatureVerifier.Create(LProvider);
  Check('RSA verifier "rs256"', not VerifyVector(LRSA, LRS, LRS.JWK, 'rs256'));
  Check('RSA-PSS verifier "ps384"', not VerifyVector(LPSS, LPS, LPS.JWK, 'ps384'));
  Check('provider does not support "rs256"', not LProvider.SupportsAlgorithm('rs256'));

  if not LProvider.SupportsAlgorithm('ES256') then
    Exit;

  LES := FindVector('RFC 7515 A.3', 'ES256');
  LECDSA := TECDSAJWTSignatureVerifier.Create(LProvider);
  Check('universal verifier rejects "es256"', Raises(
    procedure begin VerifyVector(LVerifier, LES, LES.JWK, 'es256') end, EIAM4DSecurityValidationException));
  Check('ECDSA verifier "es256"', not VerifyVector(LECDSA, LES, LES.JWK, 'es256'));
end;

// RSA key vector through the verifier
function VerifierAcceptsKey(const AVerifier: IIAM4DJWTSignatureVerifier; const AVector: TRSAKeyVector): Boolean;
begin
  Result := VerifySignature(AVerifier, AVector.SigningInput, Base64URLDecode(AVector.Signature), AVector.JWK, AVector.Alg);
end;

// RSA key vector through the provider directly: its own checks, not the verifier ones
function ProviderAcceptsKey(const AProvider: IIAM4DCryptoProvider; const AVector: TRSAKeyVector): Boolean;
var
  LMessage, LSig, LN, LE: TBytes;
  LHashAlg: TIAM4DHashAlgorithm;
begin
  LMessage := TEncoding.UTF8.GetBytes(AVector.SigningInput);
  LSig := Base64URLDecode(AVector.Signature);
  LN := JWKField(AVector.JWK, 'n');
  LE := JWKField(AVector.JWK, 'e');
  LHashAlg := HashOf(AVector.Alg);
  if AVector.Alg.StartsWith('RS') then
    Result := AProvider.RSAVerifyPKCS1(PKCS1EncodedMessage(LMessage, LHashAlg, Length(LSig)), LSig, LN, LE)
  else
    Result := AProvider.RSAVerifyPSS(LMessage, LSig, LN, LE, LHashAlg, HashSize(LHashAlg));
end;

// Verifier and provider must both return AExpected without raising
procedure ExpectKey(const AName: string; const AVerifier: IIAM4DJWTSignatureVerifier;
  const AProvider: IIAM4DCryptoProvider; const AVector: TRSAKeyVector; AExpected: Boolean);
var
  LVerifier: IIAM4DJWTSignatureVerifier;
  LProvider: IIAM4DCryptoProvider;
  LVector: TRSAKeyVector;
begin
  LVerifier := AVerifier;
  LProvider := AProvider;
  LVector := AVector;
  Expect(AName + ' verifier',
    function: Boolean
    begin
      Result := VerifierAcceptsKey(LVerifier, LVector);
    end, AExpected);
  Expect(AName + ' provider',
    function: Boolean
    begin
      Result := ProviderAcceptsKey(LProvider, LVector);
    end, AExpected);
end;

procedure TestRSAKeys;
var
  LProvider: IIAM4DCryptoProvider;
  LVerifier: IIAM4DJWTSignatureVerifier;
  LVector: TRSAKeyVector;
  LExpected: Boolean;
begin
  Writeln('RSA public key checks');
  LProvider := TIAM4DCryptoProviderFactory.CreateProvider;
  LVerifier := TUniversalJWTSignatureVerifier.Create(LProvider);

  for LVector in RSA_KEY_VECTORS do
  begin
    LExpected := LVector.Valid;
    {$IFDEF IAM4D_CRYPTO_TMS}
    // TMS integers hold moduli up to 8192 bits: larger keys fail verification, without raising
    if LVector.Bits > 8192 then
      LExpected := False;
    {$ENDIF}
    ExpectKey(LVector.Source + ' ' + LVector.Alg, LVerifier, LProvider, LVector, LExpected);
  end;
end;

// RFC 7518 3.3/4.2: RSA keys of 2048 bits or larger; MinModulusBits lowers it for legacy keys
procedure TestRSAMinimumSize;
var
  LProvider: IIAM4DCryptoProvider;
  LVerifier: IIAM4DJWTSignatureVerifier;
  LVector: TRSAKeyVector;
  LName: string;
  LJWS: TJWSVector;
begin
  Writeln('RSA minimum modulus size');
  LProvider := TIAM4DCryptoProviderFactory.CreateProvider;
  LVerifier := TUniversalJWTSignatureVerifier.Create(LProvider);

  Check('default minimum 2048 bits', TIAM4DRSAPublicKey.MinModulusBits = 2048);
  Check('minimum 1023 bits rejected', Raises(
    procedure begin TIAM4DRSAPublicKey.MinModulusBits := 1023 end, EArgumentOutOfRangeException));
  Check('minimum 16385 bits rejected', Raises(
    procedure begin TIAM4DRSAPublicKey.MinModulusBits := 16385 end, EArgumentOutOfRangeException));
  Check('minimum unchanged by rejected values', TIAM4DRSAPublicKey.MinModulusBits = 2048);

  try
    // Keys below 2048 bits in the vectors are otherwise valid
    for LVector in RSA_KEY_VECTORS do
    begin
      if LVector.Bits >= TIAM4DRSAPublicKey.DEFAULT_MIN_MODULUS_BITS then
        Continue;
      LName := LVector.Source + ' ' + LVector.Alg;
      TIAM4DRSAPublicKey.MinModulusBits := LVector.Bits;
      ExpectKey(LName + ' with minimum = size', LVerifier, LProvider, LVector, True);
      TIAM4DRSAPublicKey.MinModulusBits := LVector.Bits + 1;
      ExpectKey(LName + ' with minimum = size + 1', LVerifier, LProvider, LVector, False);
    end;

    // Raised minimum
    TIAM4DRSAPublicKey.MinModulusBits := 3072;
    LJWS := FindVector('RFC 7515 A.2', 'RS256');
    Check('2048-bit RS256 key with minimum 3072', not VerifyVector(LVerifier, LJWS, LJWS.JWK, LJWS.Alg));
    LJWS := FindVector('Leading zero', 'PS256');
    Check('2048-bit PS256 key with minimum 3072', not VerifyVector(LVerifier, LJWS, LJWS.JWK, LJWS.Alg));
    LJWS := FindVector('OpenSSL RSA-3072', 'PS384');
    Check('3072-bit PS384 key with minimum 3072', VerifyVector(LVerifier, LJWS, LJWS.JWK, LJWS.Alg));
  finally
    TIAM4DRSAPublicKey.MinModulusBits := TIAM4DRSAPublicKey.DEFAULT_MIN_MODULUS_BITS;
  end;
end;

procedure TestRSALengths;
var
  LProvider: IIAM4DCryptoProvider;
  LVerifier: IIAM4DJWTSignatureVerifier;
  LVector: TJWSVector;
  LName: string;
  LSig, LN, LE: TBytes;
begin
  Writeln('RSA signature and modulus lengths');
  LProvider := TIAM4DCryptoProviderFactory.CreateProvider;
  LVerifier := TUniversalJWTSignatureVerifier.Create(LProvider);

  // Signature k bytes long, first byte zero: any other length is rejected
  for LVector in TArray<TJWSVector>.Create(FindVector('Leading zero', 'RS256'), FindVector('Leading zero', 'PS256')) do
  begin
    LName := LVector.Source + ' ' + LVector.Alg;
    LSig := Base64URLDecode(LVector.Signature);
    Check(LName + ' first byte is zero', LSig[0] = 0);
    Check(LName + ' zero stripped',
      not VerifySignature(LVerifier, LVector.SigningInput, Copy(LSig, 1, MaxInt), LVector.JWK, LVector.Alg));
    Check(LName + ' extra zero',
      not VerifySignature(LVerifier, LVector.SigningInput, [0] + LSig, LVector.JWK, LVector.Alg));
  end;

  LVector := FindVector('Leading zero', 'PS256');
  LSig := Base64URLDecode(LVector.Signature);
  Check('provider PS256 zero stripped', not LProvider.RSAVerifyPSS(TEncoding.UTF8.GetBytes(LVector.SigningInput),
    Copy(LSig, 1, MaxInt), JWKField(LVector.JWK, 'n'), JWKField(LVector.JWK, 'e'), haSHA256, 32));

  // JWK n with a sign byte (00 || n): k is the length of n without it
  for LVector in JWS_VECTORS do
  begin
    if not (LVector.Alg.StartsWith('RS') or LVector.Alg.StartsWith('PS')) then
      Continue;
    LName := LVector.Source + ' ' + LVector.Alg;
    LN := JWKField(LVector.JWK, 'n');
    LE := JWKField(LVector.JWK, 'e');
    Check(LName + ' n with leading zero byte', VerifyVector(LVerifier, LVector, RSAJWK([0] + LN, LE), LVector.Alg));
    Check(LName + ' n with leading zero byte, tampered input', not VerifySignature(LVerifier,
      LVector.SigningInput + 'A', Base64URLDecode(LVector.Signature), RSAJWK([0] + LN, LE), LVector.Alg));
  end;
end;

procedure TestECDSAEncoding;
var
  LProvider: IIAM4DCryptoProvider;
  LVerifier: IIAM4DJWTSignatureVerifier;
  LVector: TJWSVector;
  LName: string;
  LSig, LR, LS, LX, LY, LOrder, LMessage, LSum: TBytes;
  {$IFNDEF IAM4D_CRYPTO_TMS}
  LHash: TBytes;
  {$ENDIF}
  LSize: Integer;
  LCurve: TIAM4DECCurve;
  LHashAlg: TIAM4DHashAlgorithm;

  function Rejected(const ASignature: TBytes): Boolean;
  begin
    Result := not VerifySignature(LVerifier, LVector.SigningInput, ASignature, LVector.JWK, LVector.Alg);
  end;

  function ProviderAccepts(const AR, AS_, AX, AY: TBytes): Boolean;
  begin
    Result := ProviderECDSAVerify(LProvider, LMessage, AR, AS_, AX, AY, LCurve, LHashAlg);
  end;

begin
  LProvider := TIAM4DCryptoProviderFactory.CreateProvider;
  if not LProvider.SupportsAlgorithm('ES256') then
    Exit;

  Writeln('ECDSA signature and key encoding');
  LVerifier := TUniversalJWTSignatureVerifier.Create(LProvider);
  {$IFDEF IAM4D_CRYPTO_TAURUSTLS}
  // The verifier passes the signing input: OpenSSL hashes it (EVP_DigestVerify)
  Check('TaurusTLS verifies ECDSA over the message', Supports(LProvider, IIAM4DECDSAMessageVerifier));
  {$ENDIF}

  for LVector in JWS_VECTORS do
  begin
    if not LVector.Alg.StartsWith('ES') then
      Continue;
    LName := LVector.Source + ' ' + LVector.Alg;
    LSig := Base64URLDecode(LVector.Signature);
    LSize := Length(LSig) div 2;
    LR := Copy(LSig, 0, LSize);
    LS := Copy(LSig, LSize, LSize);
    LX := JWKField(LVector.JWK, 'x');
    LY := JWKField(LVector.JWK, 'y');
    LMessage := TEncoding.UTF8.GetBytes(LVector.SigningInput);
    LHashAlg := HashOf(LVector.Alg);
    case LSize of
      32:
      begin
        LCurve := eccP256;
        LOrder := HexToBytes(P256_ORDER);
      end;
      48:
      begin
        LCurve := eccP384;
        LOrder := HexToBytes(P384_ORDER);
      end;
    else
      LCurve := eccP521;
      LOrder := HexToBytes(P521_ORDER);
    end;

    // JWS signature: raw R || S, 2 * size bytes (RFC 7518 3.4)
    Check(LName + ' DER signature', Rejected(DerSignature(LR, LS)));
    Check(LName + ' signature one byte longer', Rejected(LSig + [0]));
    Check(LName + ' signature one byte shorter', Rejected(Copy(LSig, 0, Length(LSig) - 1)));
    Check(LName + ' r = 0', Rejected(Zeros(LSize) + LS));
    Check(LName + ' s = 0', Rejected(LR + Zeros(LSize)));
    Check(LName + ' r = n', Rejected(LOrder + LS));
    Check(LName + ' s = n', Rejected(LR + LOrder));
    // r + n, s + n: same values mod n (fit only on P-521)
    LSum := AddBigEndian(LR, LOrder);
    if LSum <> nil then
      Check(LName + ' r + n', Rejected(LSum + LS));
    LSum := AddBigEndian(LS, LOrder);
    if LSum <> nil then
      Check(LName + ' s + n', Rejected(LR + LSum));

    // Provider: R, S, x, y exactly the coordinate size
    Check(LName + ' provider exact sizes', ProviderAccepts(LR, LS, LX, LY));
    Check(LName + ' provider tampered message',
      not ProviderECDSAVerify(LProvider, LMessage + [Ord('A')], LR, LS, LX, LY, LCurve, LHashAlg));
    Check(LName + ' provider R and S swapped', not ProviderAccepts(LS, LR, LX, LY));
    Check(LName + ' provider R with leading zero byte', not ProviderAccepts([0] + LR, LS, LX, LY));
    Check(LName + ' provider S with leading zero byte', not ProviderAccepts(LR, [0] + LS, LX, LY));
    Check(LName + ' provider x with leading zero byte', not ProviderAccepts(LR, LS, [0] + LX, LY));
    Check(LName + ' provider y with leading zero byte', not ProviderAccepts(LR, LS, LX, [0] + LY));
    if LR[0] = 0 then
      Check(LName + ' provider R stripped', not ProviderAccepts(Copy(LR, 1, MaxInt), LS, LX, LY));
    if LS[0] = 0 then
      Check(LName + ' provider S stripped', not ProviderAccepts(LR, Copy(LS, 1, MaxInt), LX, LY));
    if LX[0] = 0 then
      Check(LName + ' provider x stripped', not ProviderAccepts(LR, LS, Copy(LX, 1, MaxInt), LY));
    if LY[0] = 0 then
      Check(LName + ' provider y stripped', not ProviderAccepts(LR, LS, LX, Copy(LY, 1, MaxInt)));

    // Digest path (TMS verifies messages only): digest size of the curve hash
    {$IFNDEF IAM4D_CRYPTO_TMS}
    LHash := SHA2(LMessage, LHashAlg);
    Check(LName + ' provider digest', LProvider.ECDSAVerify(LHash, LR, LS, LX, LY, LCurve));
    Check(LName + ' provider digest tampered', not LProvider.ECDSAVerify(Flipped(LHash, 0), LR, LS, LX, LY, LCurve));
    Check(LName + ' provider digest, R with leading zero byte',
      not LProvider.ECDSAVerify(LHash, [0] + LR, LS, LX, LY, LCurve));
    Check(LName + ' provider digest one byte longer',
      not LProvider.ECDSAVerify(LHash + [0], LR, LS, LX, LY, LCurve));
    Check(LName + ' provider digest one byte shorter',
      not LProvider.ECDSAVerify(Copy(LHash, 0, Length(LHash) - 1), LR, LS, LX, LY, LCurve));
    {$ENDIF}
  end;
end;

// Index of the first frame that ADecrypt accepts (-1: every frame rejected)
function FirstAccepted(const AFrames: TArray<TBytes>; const AProvider: IIAM4DStorageCryptoProvider;
  const AAAD: TBytes): Integer;
var
  I: Integer;
begin
  for I := 0 to High(AFrames) do
    try
      AProvider.Decrypt(AFrames[I], AAAD);
      Exit(I);
    except
      on EIAM4DStorageDecryptionException do
        ;
    end;
  Result := -1;
end;

procedure TestStorageProvider;
var
  LKey, LAAD, LPlain, LSealed: TBytes;
  LProvider, LGCM: IIAM4DStorageCryptoProvider;
  LVector: TGCMVector;
  LFrames: TArray<TBytes>;
  I, LFirst: Integer;
begin
  Writeln('Storage crypto provider');
  LKey := HexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  LAAD := TEncoding.UTF8.GetBytes('iam4d-aad');
  LPlain := TEncoding.UTF8.GetBytes('{"access_token":"eyJ.test","refresh_token":"r"}');
  LProvider := TIAM4DStorageCryptoProviderFactory.CreateProvider(LKey);

  Check('algorithm', LProvider.GetAlgorithm = TIAM4DStorageCryptoProviderFactory.GetDefaultAlgorithmName);
  Check('provider name', LProvider.GetProviderName = TIAM4DStorageCryptoProviderFactory.GetDefaultProviderName);

  LSealed := LProvider.Encrypt(LPlain, LAAD);
  Check('roundtrip', BytesEqual(LProvider.Decrypt(LSealed, LAAD), LPlain));
  Check('fresh IV per encryption', not BytesEqual(LSealed, LProvider.Encrypt(LPlain, LAAD)));
  Check('empty AAD roundtrip', BytesEqual(LProvider.Decrypt(LProvider.Encrypt(LPlain, nil), nil), LPlain));

  // Short plaintexts: the LockBox3 frame is IV seed (8) + plaintext length + tag (32)
  for I in [0, 1, 7, 8, 15, 16, 17, 33] do
    Expect(Format('%d-byte plaintext roundtrip', [I]),
      function: Boolean
      begin
        Result := BytesEqual(LProvider.Decrypt(LProvider.Encrypt(Copy(LPlain, 0, I), LAAD), LAAD), Copy(LPlain, 0, I));
      end, True);

  Check('wrong AAD rejected', Raises(
    procedure begin LProvider.Decrypt(LSealed, TEncoding.UTF8.GetBytes('other')) end,
    EIAM4DStorageDecryptionException));
  Check('tampered ciphertext rejected', Raises(
    procedure begin LProvider.Decrypt(Flipped(LSealed, Length(LSealed) div 2), LAAD) end,
    EIAM4DStorageDecryptionException));
  Check('tampered tag rejected', Raises(
    procedure begin LProvider.Decrypt(Flipped(LSealed, High(LSealed)), LAAD) end,
    EIAM4DStorageDecryptionException));
  Check('truncated rejected', Raises(
    procedure begin LProvider.Decrypt(Copy(LSealed, 0, 10), LAAD) end,
    EIAM4DStorageDecryptionException));

  // Every byte of the frame is authenticated: IV or nonce, ciphertext and tag
  SetLength(LFrames, Length(LSealed));
  for I := 0 to High(LSealed) do
    LFrames[I] := Flipped(LSealed, I);
  LFirst := FirstAccepted(LFrames, LProvider, LAAD);
  Check(Format('a bit flipped in any of the %d bytes rejected (first accepted: %d)', [Length(LSealed), LFirst]),
    LFirst = -1);
  // Every truncation, down to the empty frame, and one byte more
  SetLength(LFrames, Length(LSealed) + 1);
  for I := 0 to High(LSealed) do
    LFrames[I] := Copy(LSealed, 0, I);
  LFrames[Length(LSealed)] := LSealed + [0];
  LFirst := FirstAccepted(LFrames, LProvider, LAAD);
  Check(Format('every truncation and an appended byte rejected (first accepted: %d)', [LFirst]), LFirst = -1);
  Expect('decryption failure: EIAM4DException with ecStorageDecryptionFailed and the provider name',
    function: Boolean
    begin
      Result := False;
      try
        LProvider.Decrypt(Copy(LSealed, 0, 10), LAAD);
      except
        on E: EIAM4DException do
          Result := (E.ErrorCode = ecStorageDecryptionFailed) and (E is EIAM4DStorageDecryptionException) and
            (EIAM4DStorageDecryptionException(E).ProviderName = LProvider.GetProviderName);
      end;
    end, True);
  Check('other key rejected', Raises(
    procedure
    begin
      TIAM4DStorageCryptoProviderFactory.CreateProvider(HexToBytes(StringOfChar('a', 64))).Decrypt(LSealed, LAAD);
    end,
    EIAM4DStorageDecryptionException));

  if LProvider.GetAlgorithm <> 'AES-256-GCM' then
    Exit;

  for LVector in GCM_VECTORS do
  begin
    // Frame: nonce || ciphertext || tag
    LGCM := TIAM4DStorageCryptoProviderFactory.CreateProvider(HexToBytes(LVector.Key));
    Check('GCM vector ' + LVector.Nonce, BytesEqual(
      LGCM.Decrypt(HexToBytes(LVector.Nonce + LVector.Sealed), HexToBytes(LVector.AAD)),
      HexToBytes(LVector.Plaintext)));
  end;
end;

procedure TestTokenStorage;
var
  LKey, LAAD: TBytes;
  LTokens, LLoaded: TIAM4DTokens;
  LStorage: IIAM4DTokenStorage;
begin
  Writeln('AES token storage');
  LKey := HexToBytes('1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100');
  LAAD := TEncoding.UTF8.GetBytes('client-id');

  LTokens := Default(TIAM4DTokens);
  LTokens.AccessToken := 'access.token.value';
  LTokens.RefreshToken := 'refresh-token-value';
  LTokens.IDToken := 'id.token.value';
  LTokens.AccessTokenExpiry := Now + 1;
  LTokens.RefreshTokenExpiry := Now + 2;

  LStorage := TIAM4DAESMemoryTokenStorageRawKey32.Create(LKey, LAAD);
  LStorage.SaveTokens(LTokens);
  LLoaded := LStorage.LoadTokens;
  Check('factory provider roundtrip', LStorage.HasTokens and (LLoaded.AccessToken = LTokens.AccessToken) and
    (LLoaded.RefreshToken = LTokens.RefreshToken) and (LLoaded.IDToken = LTokens.IDToken));
  LStorage.ClearTokens;
  Check('cleared', not LStorage.HasTokens);

  LStorage := TIAM4DAESMemoryTokenStorageRawKey32.Create(
    TIAM4DStorageCryptoProviderFactory.CreateProvider(LKey), LAAD);
  LStorage.SaveTokens(LTokens);
  Check('custom provider roundtrip', LStorage.LoadTokens.AccessToken = LTokens.AccessToken);

  Check('nil provider rejected', Raises(
    procedure begin TIAM4DAESMemoryTokenStorageRawKey32.Create(IIAM4DStorageCryptoProvider(nil), LAAD) end,
    EIAM4DStorageException));
  Check('bad key rejected', Raises(
    procedure begin TIAM4DAESMemoryTokenStorageRawKey32.Create(HexToBytes('00'), LAAD) end,
    EIAM4DStorageException));
end;

{$IFDEF MSWINDOWS}
// The plaintext of a frame failing authentication must not stay in freed memory.
// The memory manager hands freed blocks of the same size back first: probe them.
procedure TestDecryptWipe;
const
  PLAIN_SIZE = 1000;
  BLOCK_SIZE = PLAIN_SIZE + 2 * SizeOf(NativeInt); // dynamic array header + data
  PROBES = 64;
var
  LProvider: IIAM4DStorageCryptoProvider;
  LPlain, LSealed: TBytes;
  LBlocks: array[0..PROBES - 1] of PByte;
  I, J, LRun: Integer;
  LFound: Boolean;

  // Overwrites the freed blocks of this size class
  procedure ClearFreedBlocks;
  var
    K: Integer;
  begin
    for K := 0 to PROBES - 1 do
    begin
      GetMem(LBlocks[K], BLOCK_SIZE);
      FillChar(LBlocks[K]^, BLOCK_SIZE, 0);
    end;
    for K := 0 to PROBES - 1 do
      FreeMem(LBlocks[K]);
  end;

begin
  Writeln('Storage plaintext wipe');
  LProvider := TIAM4DStorageCryptoProviderFactory.CreateProvider(HexToBytes(StringOfChar('7', 64)));
  SetLength(LPlain, PLAIN_SIZE);
  FillChar(LPlain[0], PLAIN_SIZE, Ord('P'));
  LSealed := LProvider.Encrypt(LPlain, nil);
  FillChar(LPlain[0], PLAIN_SIZE, 0);
  LSealed[High(LSealed)] := LSealed[High(LSealed)] xor $01;

  ClearFreedBlocks;
  Check('tampered tag rejected', Raises(
    procedure begin LProvider.Decrypt(LSealed, nil) end, EIAM4DStorageDecryptionException));

  LFound := False;
  for I := 0 to PROBES - 1 do
    GetMem(LBlocks[I], BLOCK_SIZE);
  for I := 0 to PROBES - 1 do
  begin
    LRun := 0;
    for J := 0 to BLOCK_SIZE - 1 do
    begin
      if LBlocks[I][J] = Ord('P') then
        Inc(LRun)
      else
        LRun := 0;
      if LRun >= 64 then
        LFound := True;
    end;
    FreeMem(LBlocks[I]);
  end;
  Check('plaintext wiped after failed authentication', not LFound);
end;
{$ENDIF}

{$IFDEF IAM4D_CRYPTO_LOCKBOX3}
{$IFOPT Q+}{$DEFINE TEST_Q_ON}{$Q-}{$ENDIF}
// The frame starts with the 8-byte CBC IV seed (IV = seed || 8 zero bytes). It must come
// from the CSPRNG: LockBox3 fills it from its global 64-bit LCG, next = value * 6364136223846793005 + 1
procedure TestLockBox3IVSeed;
const
  LCG_FACTOR: UInt64 = 6364136223846793005;
var
  LProvider: IIAM4DStorageCryptoProvider;
  LPlain, LFrame: TBytes;
  LSeed, LNext: UInt64;
  I: Integer;
  LPredicted: Boolean;
begin
  Writeln('LockBox3 storage IV seed');
  LProvider := TIAM4DStorageCryptoProviderFactory.CreateProvider(HexToBytes(StringOfChar('3', 64)));
  LPlain := TEncoding.UTF8.GetBytes('iv seed check');
  LFrame := LProvider.Encrypt(LPlain, nil);
  Move(LFrame[0], LSeed, SizeOf(LSeed));
  LPredicted := False;
  for I := 1 to 8 do
  begin
    LFrame := LProvider.Encrypt(LPlain, nil);
    Move(LFrame[0], LNext, SizeOf(LNext));
    LPredicted := LPredicted or (LNext = LSeed * LCG_FACTOR + 1);
    LSeed := LNext;
  end;
  Check('IV seed not predictable from the previous frame', not LPredicted);
end;
{$IFDEF TEST_Q_ON}{$Q+}{$ENDIF}
{$ENDIF}

{$IFDEF IAM4D_CRYPTO_TAURUSTLS}
// Memory held by the process, OpenSSL allocations included (not seen by the leak report)
function ProcessMemory: Int64;
{$IFDEF MSWINDOWS}
var
  LCounters: TProcessMemoryCountersEx;
begin
  FillChar(LCounters, SizeOf(LCounters), 0);
  LCounters.cb := SizeOf(LCounters);
  if GetProcessMemoryInfo(GetCurrentProcess, @LCounters, SizeOf(LCounters)) then
    Result := LCounters.PrivateUsage
  else
    Result := 0;
end;
{$ELSE}
var
  LStream: TFileStream;
  LBuffer: TBytes;
  LCount: Integer;
begin
  // /proc/self/statm, in pages: size resident shared text lib data dt (size 0: read, not sized)
  SetLength(LBuffer, 512);
  LStream := TFileStream.Create('/proc/self/statm', fmOpenRead or fmShareDenyNone);
  try
    LCount := LStream.Read(LBuffer[0], Length(LBuffer));
  finally
    LStream.Free;
  end;
  Result := StrToInt64(TEncoding.ASCII.GetString(LBuffer, 0, LCount).Trim.Split([' '])[5]) * 4096;
end;
{$ENDIF}

function VerifiedVector(const AVerifier: IIAM4DJWTSignatureVerifier; const AVector: TJWSVector): Boolean;
begin
  Result := VerifyVector(AVerifier, AVector, AVector.JWK, AVector.Alg);
end;

// Valid, tampered signature and tampered input of every vector
function AllVectorResults(const AVerifier: IIAM4DJWTSignatureVerifier): TArray<Boolean>;
var
  LVector: TJWSVector;
  LSig: TBytes;
begin
  Result := nil;
  for LVector in JWS_VECTORS do
  begin
    LSig := Base64URLDecode(LVector.Signature);
    Result := Result + [VerifiedVector(AVerifier, LVector),
      VerifySignature(AVerifier, LVector.SigningInput, Flipped(LSig, Length(LSig) div 2), LVector.JWK, LVector.Alg),
      VerifySignature(AVerifier, LVector.SigningInput + 'A', LSig, LVector.JWK, LVector.Alg)];
  end;
end;

function SameResults(const A, B: TArray<Boolean>): Boolean;
var
  I: Integer;
begin
  Result := Length(A) = Length(B);
  for I := 0 to High(A) do
    Result := Result and (A[I] = B[I]);
end;

function CacheStats: TIAM4DKeyCacheStats;
begin
  Result := TIAM4DTaurusTLSCryptoProvider.KeyCacheStats;
end;

function CacheHitsSince(const ABase: TIAM4DKeyCacheStats): Int64;
begin
  Result := CacheStats.Hits - ABase.Hits;
end;

function CacheMissesSince(const ABase: TIAM4DKeyCacheStats): Int64;
begin
  Result := CacheStats.Misses - ABase.Misses;
end;

// Parsed public keys (EVP_PKEY) cached by key material: same results, LRU eviction, keys freed
procedure TestKeyCache;
const
  CYCLES = 3000;
  LEAK_LIMIT = 2 * 1024 * 1024;
var
  LProvider: IIAM4DCryptoProvider;
  LVerifier: IIAM4DJWTSignatureVerifier;
  LA, LB, LC, LD, LRS, LBad: TJWSVector;
  LKeys: TArray<TJWSVector>;
  LBase: TIAM4DKeyCacheStats;
  LUncached, LFilling, LCached: TArray<Boolean>;
  LLookups, LFailures, I: Integer;
  LMemory: Int64;
  LWatch: TStopwatch;
  LTime: array[Boolean] of Double;
  LEnabled: Boolean;
begin
  Writeln('TaurusTLS public key cache');
  LProvider := TIAM4DCryptoProviderFactory.CreateProvider;
  LVerifier := TUniversalJWTSignatureVerifier.Create(LProvider);
  LA := FindVector('OpenSSL RSA-2048', 'PS256');
  LB := FindVector('RFC 7515 A.3', 'ES256');
  LC := FindVector('OpenSSL P-384', 'ES384');
  LD := FindVector('OpenSSL RSA-3072', 'PS384');
  LRS := FindVector('RFC 7515 A.2', 'RS256');

  Check('default capacity', TIAM4DTaurusTLSCryptoProvider.KeyCacheCapacity =
    TIAM4DTaurusTLSCryptoProvider.DEFAULT_KEY_CACHE_CAPACITY);
  Check('capacity -1 rejected', Raises(
    procedure begin TIAM4DTaurusTLSCryptoProvider.KeyCacheCapacity := -1 end, EArgumentOutOfRangeException));
  Check('capacity above maximum rejected', Raises(
    procedure
    begin
      TIAM4DTaurusTLSCryptoProvider.KeyCacheCapacity := TIAM4DTaurusTLSCryptoProvider.MAX_KEY_CACHE_CAPACITY + 1;
    end, EArgumentOutOfRangeException));

  try
    // Same results without the cache, while filling it and from it
    TIAM4DTaurusTLSCryptoProvider.KeyCacheCapacity := 0;
    LBase := CacheStats;
    LUncached := AllVectorResults(LVerifier);
    Check('capacity 0: nothing cached', (CacheStats.Count = 0) and (CacheHitsSince(LBase) = 0));
    LLookups := CacheMissesSince(LBase);
    TIAM4DTaurusTLSCryptoProvider.KeyCacheCapacity := TIAM4DTaurusTLSCryptoProvider.DEFAULT_KEY_CACHE_CAPACITY;
    TIAM4DTaurusTLSCryptoProvider.ClearKeyCache;
    LFilling := AllVectorResults(LVerifier);
    LBase := CacheStats;
    LCached := AllVectorResults(LVerifier);
    Check('PS* and ES* keys looked up', LLookups > 0);
    Check('results unchanged while filling the cache', SameResults(LUncached, LFilling));
    Check('results unchanged from the cache', SameResults(LUncached, LCached));
    Check('second pass served from the cache', (CacheMissesSince(LBase) = 0) and (CacheHitsSince(LBase) = LLookups));

    // RS*: BN_mod_exp on n and e, no EVP key
    LBase := CacheStats;
    Check('RS256 valid', VerifiedVector(LVerifier, LRS));
    Check('RS256 not looked up', (CacheHitsSince(LBase) = 0) and (CacheMissesSince(LBase) = 0));

    // Least recently used dropped first
    TIAM4DTaurusTLSCryptoProvider.ClearKeyCache;
    TIAM4DTaurusTLSCryptoProvider.KeyCacheCapacity := 2;
    LBase := CacheStats;
    Check('LRU: A, B, A, C verified', VerifiedVector(LVerifier, LA) and VerifiedVector(LVerifier, LB) and
      VerifiedVector(LVerifier, LA) and VerifiedVector(LVerifier, LC));
    Check('LRU: 3 misses, 1 hit, B evicted', (CacheMissesSince(LBase) = 3) and (CacheHitsSince(LBase) = 1) and
      (CacheStats.Evictions - LBase.Evictions = 1) and (CacheStats.Count = 2));
    LBase := CacheStats;
    Check('LRU: A still cached', VerifiedVector(LVerifier, LA) and (CacheHitsSince(LBase) = 1));
    LBase := CacheStats;
    Check('LRU: B decoded again', VerifiedVector(LVerifier, LB) and (CacheMissesSince(LBase) = 1));
    LBase := CacheStats;
    Check('LRU: C evicted by B', VerifiedVector(LVerifier, LC) and (CacheMissesSince(LBase) = 1));

    // Capacity lowered: extra keys freed at once
    TIAM4DTaurusTLSCryptoProvider.KeyCacheCapacity := 64;
    Check('capacity 64: A, B, C, D verified', VerifiedVector(LVerifier, LA) and VerifiedVector(LVerifier, LB) and
      VerifiedVector(LVerifier, LC) and VerifiedVector(LVerifier, LD));
    Check('capacity 64 holds A, B, C, D', CacheStats.Count = 4);
    TIAM4DTaurusTLSCryptoProvider.KeyCacheCapacity := 1;
    Check('capacity lowered to 1', CacheStats.Count = 1);
    TIAM4DTaurusTLSCryptoProvider.ClearKeyCache;
    Check('cleared', CacheStats.Count = 0);

    // Keys OpenSSL rejects are not cached
    TIAM4DTaurusTLSCryptoProvider.KeyCacheCapacity := 64;
    LBad := LB;
    LBad.JWK := LB.JWK.Replace('"x":"f83O', '"x":"f83P');
    LBase := CacheStats;
    Check('point not on curve rejected twice',
      not VerifiedVector(LVerifier, LBad) and not VerifiedVector(LVerifier, LBad));
    Check('point not on curve not cached', (CacheMissesSince(LBase) = 2) and (CacheStats.Count = 0));

    // Same key material, n with a sign byte: same DER, same entry
    VerifiedVector(LVerifier, LA);
    LBase := CacheStats;
    Check('n with leading zero byte: same entry', VerifyVector(LVerifier, LA,
      RSAJWK([0] + JWKField(LA.JWK, 'n'), JWKField(LA.JWK, 'e')), LA.Alg) and (CacheHitsSince(LBase) = 1));

    // Keys dropped while other threads use them: every thread holds its own reference
    TIAM4DTaurusTLSCryptoProvider.KeyCacheCapacity := 1;
    LKeys := [LA, LB, LC, LD];
    LFailures := 0;
    TParallel.For(0, 399,
      procedure(AIndex: Integer)
      begin
        try
          if not VerifiedVector(LVerifier, LKeys[AIndex mod Length(LKeys)]) then
            TInterlocked.Increment(LFailures);
        except
          TInterlocked.Increment(LFailures);
        end;
      end);
    Check('parallel verification with constant eviction', LFailures = 0);

    // Keys dropped or cleared are freed: OpenSSL memory is not in the leak report
    LKeys := [LA, LB, LD];
    for I := 1 to 300 do
      VerifiedVector(LVerifier, LKeys[I mod Length(LKeys)]);
    LMemory := ProcessMemory;
    for I := 1 to CYCLES do
      VerifiedVector(LVerifier, LKeys[I mod Length(LKeys)]);
    LMemory := ProcessMemory - LMemory;
    Writeln(Format('  %d keys evicted, memory growth %d KB', [CYCLES, LMemory div 1024]));
    Check('evicted keys freed', LMemory < LEAK_LIMIT);

    TIAM4DTaurusTLSCryptoProvider.KeyCacheCapacity := 64;
    LMemory := ProcessMemory;
    for I := 1 to CYCLES div Length(LKeys) do
    begin
      VerifiedVector(LVerifier, LA);
      VerifiedVector(LVerifier, LB);
      VerifiedVector(LVerifier, LD);
      TIAM4DTaurusTLSCryptoProvider.ClearKeyCache;
    end;
    LMemory := ProcessMemory - LMemory;
    Writeln(Format('  %d keys cleared, memory growth %d KB', [CYCLES, LMemory div 1024]));
    Check('cleared keys freed', LMemory < LEAK_LIMIT);

    // Timing (information only): PS256 and ES256 with and without the cache
    for LEnabled in [False, True] do
    begin
      if LEnabled then
        TIAM4DTaurusTLSCryptoProvider.KeyCacheCapacity := 64
      else
        TIAM4DTaurusTLSCryptoProvider.KeyCacheCapacity := 0;
      VerifiedVector(LVerifier, LA);
      VerifiedVector(LVerifier, LB);
      LWatch := TStopwatch.StartNew;
      for I := 1 to 200 do
      begin
        VerifiedVector(LVerifier, LA);
        VerifiedVector(LVerifier, LB);
      end;
      LTime[LEnabled] := LWatch.Elapsed.TotalMilliseconds * 1000 / 400;
    end;
    Writeln(Format('  PS256 + ES256: %.0f us per verification without cache, %.0f with cache',
      [LTime[False], LTime[True]]));
  finally
    TIAM4DTaurusTLSCryptoProvider.KeyCacheCapacity := TIAM4DTaurusTLSCryptoProvider.DEFAULT_KEY_CACHE_CAPACITY;
  end;
end;
{$ENDIF}

// One verifier shared by parallel tasks, as TIAM4DJWTValidator does
procedure TestConcurrency;
var
  LProvider: IIAM4DCryptoProvider;
  LVerifier: IIAM4DJWTSignatureVerifier;
  {$IFDEF IAM4D_CRYPTO_TAURUSTLS}
  LStorage: IIAM4DStorageCryptoProvider;
  LVersion: Cardinal;
  {$ENDIF}
  LFailures: Integer;
begin
  Writeln('Concurrency (shared provider instances)');
  LProvider := TIAM4DCryptoProviderFactory.CreateProvider;
  LVerifier := TUniversalJWTSignatureVerifier.Create(LProvider);
  {$IFDEF IAM4D_CRYPTO_TAURUSTLS}
  LStorage := TIAM4DStorageCryptoProviderFactory.CreateProvider(HexToBytes(StringOfChar('5', 64)));
  {$ENDIF}
  LFailures := 0;

  TParallel.For(0, 399,
    procedure(AIndex: Integer)
    var
      LVector: TJWSVector;
      {$IFDEF IAM4D_CRYPTO_TAURUSTLS}
      LPlain: TBytes;
      {$ENDIF}
    begin
      try
        LVector := JWS_VECTORS[AIndex mod Length(JWS_VECTORS)];
        if LProvider.SupportsAlgorithm(LVector.Alg) and not VerifyVector(LVerifier, LVector, LVector.JWK, LVector.Alg) then
          TInterlocked.Increment(LFailures);

        // Storage providers need not be thread-safe (the token storage serializes them): TaurusTLS is
        {$IFDEF IAM4D_CRYPTO_TAURUSTLS}
        LPlain := TEncoding.UTF8.GetBytes('payload ' + IntToStr(AIndex));
        if not BytesEqual(LStorage.Decrypt(LStorage.Encrypt(LPlain, nil), nil), LPlain) then
          TInterlocked.Increment(LFailures);
        {$ENDIF}
      except
        TInterlocked.Increment(LFailures);
      end;
    end);

  Check('parallel verification' {$IFDEF IAM4D_CRYPTO_TAURUSTLS} + ', encryption and decryption' {$ENDIF}, LFailures = 0);

  {$IFDEF IAM4D_CRYPTO_TAURUSTLS}
  // EnsureLoaded once loaded: lock-free path from parallel tasks
  LVersion := TIAM4DOpenSSL.VersionNumber;
  LFailures := 0;
  TParallel.For(0, 63,
    procedure(AIndex: Integer)
    var
      I: Integer;
    begin
      try
        for I := 1 to 10000 do
          TIAM4DOpenSSL.EnsureLoaded;
        if TIAM4DOpenSSL.VersionNumber <> LVersion then
          TInterlocked.Increment(LFailures);
      except
        TInterlocked.Increment(LFailures);
      end;
    end);
  Check('EnsureLoaded from parallel tasks', LFailures = 0);
  {$ENDIF}
end;

begin
  ReportMemoryLeaksOnShutdown := True;
  try
    {$IFDEF IAM4D_CRYPTO_TAURUSTLS}
    if ParamCount > 0 then
      TIAM4DOpenSSL.LibraryPath := ParamStr(1);
    {$ENDIF}

    Writeln('Provider: ', TIAM4DCryptoProviderFactory.GetDefaultProviderName,
      ' (storage ', TIAM4DStorageCryptoProviderFactory.GetDefaultAlgorithmName, ')');
    {$IFDEF IAM4D_CRYPTO_TAURUSTLS}
    Writeln('OpenSSL: ', TIAM4DOpenSSL.VersionText);
    {$ENDIF}

    TestFactories;
    TestExpectedAlgorithms;
    TestJWSVectors;
    TestKeyConfusion;
    TestAlgorithmNames;
    TestRSAKeys;
    TestRSAMinimumSize;
    TestRSALengths;
    TestECDSAEncoding;
    TestStorageProvider;
    {$IFDEF MSWINDOWS}
    TestDecryptWipe;
    {$ENDIF}
    {$IFDEF IAM4D_CRYPTO_LOCKBOX3}
    TestLockBox3IVSeed;
    {$ENDIF}
    TestTokenStorage;
    TestConcurrency;
    {$IFDEF IAM4D_CRYPTO_TAURUSTLS}
    TestKeyCache;
    {$ENDIF}

    Writeln(Format('Passed: %d  Failed: %d', [GPassed, GFailed]));
    if GFailed > 0 then
      ExitCode := 1;
  except
    on E: Exception do
    begin
      Writeln('FATAL ', E.ClassName, ': ', E.Message);
      ExitCode := 2;
    end;
  end;
end.
