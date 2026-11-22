{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Security.Crypto.TaurusTLS.pas
  Project    : IAMClient4D
  Author     : Claudio Piffer
  Copyright  : Copyright (c) 2018-2026 Claudio Piffer
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

unit IAMClient4D.Security.Crypto.TaurusTLS;

{$I IAMClient4D.Config.inc}

{$IFDEF IAM4D_CRYPTO_TAURUSTLS}
interface

uses
  System.SysUtils,
  IAMClient4D.Security.Crypto.Interfaces;

type
  /// <summary>
  /// Counters of the TaurusTLS public key cache.
  /// </summary>
  TIAM4DKeyCacheStats = record
    /// <summary>Keys held</summary>
    Count: Integer;
    /// <summary>Largest number of keys held (0: cache disabled)</summary>
    Capacity: Integer;
    /// <summary>Lookups served from the cache, since start</summary>
    Hits: Int64;
    /// <summary>Lookups that decoded the key, since start</summary>
    Misses: Int64;
    /// <summary>Least recently used keys dropped, since start</summary>
    Evictions: Int64;
  end;

  /// <summary>
  /// Cryptographic provider backed by OpenSSL 3.x/4.x through TaurusTLS.
  /// </summary>
  /// <remarks>
  /// RS*: raw RSA public operation (BN_mod_exp), EM compared in constant time.
  /// PS*: EVP_DigestVerify. ES*: EVP_DigestVerify over the message (IIAM4DECDSAMessageVerifier,
  /// used by the ECDSA JWT verifier), EVP_PKEY_verify over a digest (ECDSAVerify).
  /// RSA keys checked with TIAM4DRSAPublicKey.IsValid first; RSA signatures exactly k bytes;
  /// ECDSA R, S, x, y of the coordinate size and digest of the curve hash.
  /// Public keys are imported as DER SubjectPublicKeyInfo (no deprecated RSA/EC_KEY API)
  /// and cached by key material (PS*, ES*): see KeyCacheCapacity.
  /// Thread-safety: safe for concurrent use; the key cache is shared by all instances.
  /// </remarks>
  TIAM4DTaurusTLSCryptoProvider = class(TInterfacedObject, IIAM4DCryptoProvider, IIAM4DECDSAMessageVerifier)
  public const
    /// <summary>Default KeyCacheCapacity</summary>
    DEFAULT_KEY_CACHE_CAPACITY = 64;
    /// <summary>Largest KeyCacheCapacity</summary>
    MAX_KEY_CACHE_CAPACITY = 4096;
  private
    function ECDSASignature(ACurve: TIAM4DECCurve; const AR, AS_, AX, AY: TBytes;
      out ASignature: TBytes): Boolean;
    class function GetKeyCacheCapacity: Integer; static;
    class procedure SetKeyCacheCapacity(AValue: Integer); static;
  public
    /// <summary>
    /// Creates the provider, loading OpenSSL if needed.
    /// </summary>
    /// <exception cref="EIAM4DOpenSSLException">OpenSSL not available or older than 3.0</exception>
    constructor Create;

    { IIAM4DCryptoProvider }
    function ECDSAVerify(const AHash, AR, AS_, AX, AY: TBytes;
      ACurve: TIAM4DECCurve): Boolean;
    function RSAVerifyPKCS1(const AExpectedEM, ASignature, AModulus, AExponent: TBytes): Boolean;
    function RSAVerifyPSS(const AMessage, ASignature, AModulus, AExponent: TBytes;
      AHashAlg: TIAM4DHashAlgorithm; ASaltLen: Integer): Boolean;
    function GetSupportedAlgorithms: TArray<string>;
    function SupportsAlgorithm(const AAlg: string): Boolean;
    function GetProviderName: string;

    { IIAM4DECDSAMessageVerifier }
    function ECDSAVerifyMessage(const AMessage, AR, AS_, AX, AY: TBytes;
      ACurve: TIAM4DECCurve): Boolean;

    /// <summary>
    /// Counters of the public key cache.
    /// </summary>
    class function KeyCacheStats: TIAM4DKeyCacheStats; static;

    /// <summary>
    /// Frees the cached keys (counters are kept).
    /// </summary>
    class procedure ClearKeyCache; static;

    /// <summary>
    /// Parsed public keys (EVP_PKEY) kept for PS* and ES*, least recently used dropped first.
    /// </summary>
    /// <remarks>
    /// Keyed by the key material (DER SubjectPublicKeyInfo): a rotated key is a new entry.
    /// Default DEFAULT_KEY_CACHE_CAPACITY, 0 disables the cache. Keys are freed when dropped,
    /// at unit finalization and when TaurusTLS unloads OpenSSL.
    /// </remarks>
    /// <exception cref="EArgumentOutOfRangeException">Value outside 0..MAX_KEY_CACHE_CAPACITY</exception>
    class property KeyCacheCapacity: Integer read GetKeyCacheCapacity write SetKeyCacheCapacity;
  end;

implementation

uses
  System.Generics.Defaults,
  System.Generics.Collections,
  System.Hash,
  System.SyncObjs,
  TaurusTLSLoader,
  TaurusTLSHeaders_types,
  TaurusTLSHeaders_bn,
  TaurusTLSHeaders_evp,
  TaurusTLSHeaders_x509,
  TaurusTLSHeaders_err,
  IAMClient4D.Common.SecureMemory,
  IAMClient4D.Crypto.TaurusTLS.Common;

const
  // AlgorithmIdentifier { rsaEncryption, NULL }
  DER_RSA_ALGORITHM_ID: TBytes = [$30, $0D, $06, $09, $2A, $86, $48, $86, $F7, $0D, $01, $01, $01, $05, $00];
  // OID id-ecPublicKey
  DER_EC_PUBLIC_KEY_OID: TBytes = [$06, $07, $2A, $86, $48, $CE, $3D, $02, $01];
  // Named curve OIDs
  DER_P256_OID: TBytes = [$06, $08, $2A, $86, $48, $CE, $3D, $03, $01, $07];
  DER_P384_OID: TBytes = [$06, $05, $2B, $81, $04, $00, $22];
  DER_P521_OID: TBytes = [$06, $05, $2B, $81, $04, $00, $23];

{ DER helpers }

function DerLength(ALength: Integer): TBytes;
begin
  if ALength < $80 then
    Result := [Byte(ALength)]
  else if ALength <= $FF then
    Result := [$81, Byte(ALength)]
  else if ALength <= $FFFF then
    Result := [$82, Byte(ALength shr 8), Byte(ALength)]
  else
    Result := [$83, Byte(ALength shr 16), Byte(ALength shr 8), Byte(ALength)];
end;

function DerTLV(ATag: Byte; const AValue: TBytes): TBytes;
begin
  Result := [ATag] + DerLength(Length(AValue)) + AValue;
end;

// INTEGER from unsigned big-endian bytes (minimal encoding)
function DerUnsignedInteger(const AValue: TBytes): TBytes;
var
  LStart: Integer;
  LBody: TBytes;
begin
  LStart := 0;
  while (LStart < High(AValue)) and (AValue[LStart] = 0) do
    Inc(LStart);

  LBody := Copy(AValue, LStart, MaxInt);
  if Length(LBody) = 0 then
    LBody := [0]
  else if (LBody[0] and $80) <> 0 then
    LBody := [0] + LBody;

  Result := DerTLV($02, LBody);
end;

function DerBitString(const AValue: TBytes): TBytes;
begin
  Result := DerTLV($03, [0] + AValue);
end;

function CurveCoordinateSize(ACurve: TIAM4DECCurve): Integer;
begin
  case ACurve of
    eccP256: Result := 32;
    eccP384: Result := 48;
    eccP521: Result := 66;
  else
    Result := 0;
  end;
end;

// Curve hash (RFC 7518 3.4)
function CurveHash(ACurve: TIAM4DECCurve): TIAM4DHashAlgorithm;
begin
  case ACurve of
    eccP384: Result := haSHA384;
    eccP521: Result := haSHA512;
  else
    Result := haSHA256;
  end;
end;

function CurveHashSize(ACurve: TIAM4DECCurve): Integer;
begin
  case CurveHash(ACurve) of
    haSHA384: Result := 48;
    haSHA512: Result := 64;
  else
    Result := 32;
  end;
end;

function CurveOID(ACurve: TIAM4DECCurve): TBytes;
begin
  case ACurve of
    eccP256: Result := DER_P256_OID;
    eccP384: Result := DER_P384_OID;
    eccP521: Result := DER_P521_OID;
  else
    Result := nil;
  end;
end;

function BuildRSASubjectPublicKeyInfo(const AModulus, AExponent: TBytes): TBytes;
begin
  Result := DerTLV($30, DER_RSA_ALGORITHM_ID +
    DerBitString(DerTLV($30, DerUnsignedInteger(AModulus) + DerUnsignedInteger(AExponent))));
end;

// AX, AY: full coordinate size
function BuildECSubjectPublicKeyInfo(ACurve: TIAM4DECCurve; const AX, AY: TBytes): TBytes;
begin
  // Uncompressed point: 04 || X || Y
  Result := DerTLV($30,
    DerTLV($30, DER_EC_PUBLIC_KEY_OID + CurveOID(ACurve)) +
    DerBitString([$04] + AX + AY));
end;

// Caller frees with EVP_PKEY_free; nil if the DER is rejected (e.g. point not on curve)
function DecodePublicKey(const ASubjectPublicKeyInfo: TBytes): PEVP_PKEY;
var
  LPtr: PByte;
begin
  if Length(ASubjectPublicKeyInfo) = 0 then
    Exit(nil);

  LPtr := @ASubjectPublicKeyInfo[0];
  Result := d2i_PUBKEY(nil, @LPtr, Length(ASubjectPublicKeyInfo));
end;

type
  TKeyCacheEntry = record
    Key: PEVP_PKEY;
    LastUse: UInt64;
  end;

  /// <summary>
  /// Parsed public keys by DER SubjectPublicKeyInfo, least recently used dropped first.
  /// </summary>
  /// <remarks>
  /// Callers get their own reference (EVP_PKEY_up_ref) and free it: dropping a key
  /// in use by another thread only releases the cache reference.
  /// </remarks>
  TPublicKeyCache = class
  private
    FLock: TCriticalSection;
    FEntries: TDictionary<TBytes, TKeyCacheEntry>;
    FCapacity: Integer;
    FTick: UInt64;
    FHits: Int64;
    FMisses: Int64;
    FEvictions: Int64;
    // Lock held: drops least recently used keys down to AMaxCount
    procedure Trim(AMaxCount: Integer);
  public
    constructor Create;
    destructor Destroy; override;
    // Key referenced for the caller (EVP_PKEY_free when done); nil if the DER is rejected
    function Acquire(const ASubjectPublicKeyInfo: TBytes): PEVP_PKEY;
    procedure Clear;
    function Stats: TIAM4DKeyCacheStats;
    procedure SetCapacity(AValue: Integer);
  end;

var
  GKeyCache: TPublicKeyCache;

{ TPublicKeyCache }

constructor TPublicKeyCache.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
  FCapacity := TIAM4DTaurusTLSCryptoProvider.DEFAULT_KEY_CACHE_CAPACITY;
  FEntries := TDictionary<TBytes, TKeyCacheEntry>.Create(TEqualityComparer<TBytes>.Construct(
    function(const ALeft, ARight: TBytes): Boolean
    begin
      Result := (Length(ALeft) = Length(ARight)) and
        ((Length(ALeft) = 0) or CompareMem(@ALeft[0], @ARight[0], Length(ALeft)));
    end,
    function(const AValue: TBytes): Integer
    begin
      if Length(AValue) = 0 then
        Result := 0
      else
        Result := THashBobJenkins.GetHashValue(AValue[0], Length(AValue));
    end));
end;

destructor TPublicKeyCache.Destroy;
begin
  Clear;
  FEntries.Free;
  FLock.Free;
  inherited;
end;

procedure TPublicKeyCache.Trim(AMaxCount: Integer);
var
  LPair: TPair<TBytes, TKeyCacheEntry>;
  LOldest: TBytes;
  LOldestUse: UInt64;
begin
  // Linear scan: the cache is small and eviction rare
  while FEntries.Count > AMaxCount do
  begin
    LOldest := nil;
    LOldestUse := High(UInt64);
    for LPair in FEntries do
      if LPair.Value.LastUse < LOldestUse then
      begin
        LOldest := LPair.Key;
        LOldestUse := LPair.Value.LastUse;
      end;
    EVP_PKEY_free(FEntries[LOldest].Key);
    FEntries.Remove(LOldest);
    Inc(FEvictions);
  end;
end;

function TPublicKeyCache.Acquire(const ASubjectPublicKeyInfo: TBytes): PEVP_PKEY;
var
  LEntry: TKeyCacheEntry;
begin
  FLock.Enter;
  try
    if FEntries.TryGetValue(ASubjectPublicKeyInfo, LEntry) then
    begin
      Inc(FHits);
      Inc(FTick);
      LEntry.LastUse := FTick;
      FEntries[ASubjectPublicKeyInfo] := LEntry;
      if EVP_PKEY_up_ref(LEntry.Key) <> 1 then
        Exit(nil);
      Exit(LEntry.Key);
    end;
    Inc(FMisses);
  finally
    FLock.Leave;
  end;

  // Decoded outside the lock: d2i_PUBKEY is the slow part
  Result := DecodePublicKey(ASubjectPublicKeyInfo);
  if Result = nil then
    Exit;

  FLock.Enter;
  try
    // Disabled, cached by another thread meanwhile or not referenceable: the caller's key only
    if (FCapacity = 0) or FEntries.ContainsKey(ASubjectPublicKeyInfo) or
       (EVP_PKEY_up_ref(Result) <> 1) then
      Exit;

    Trim(FCapacity - 1);
    Inc(FTick);
    LEntry.Key := Result;
    LEntry.LastUse := FTick;
    FEntries.Add(ASubjectPublicKeyInfo, LEntry);
  finally
    FLock.Leave;
  end;
end;

procedure TPublicKeyCache.Clear;
var
  LEntry: TKeyCacheEntry;
begin
  FLock.Enter;
  try
    for LEntry in FEntries.Values do
      EVP_PKEY_free(LEntry.Key);
    FEntries.Clear;
  finally
    FLock.Leave;
  end;
end;

function TPublicKeyCache.Stats: TIAM4DKeyCacheStats;
begin
  FLock.Enter;
  try
    Result.Count := FEntries.Count;
    Result.Capacity := FCapacity;
    Result.Hits := FHits;
    Result.Misses := FMisses;
    Result.Evictions := FEvictions;
  finally
    FLock.Leave;
  end;
end;

procedure TPublicKeyCache.SetCapacity(AValue: Integer);
begin
  FLock.Enter;
  try
    FCapacity := AValue;
    Trim(AValue);
  finally
    FLock.Leave;
  end;
end;

// Referenced key for the caller; decoded each time once the cache is gone (finalization)
function AcquirePublicKey(const ASubjectPublicKeyInfo: TBytes): PEVP_PKEY;
begin
  if GKeyCache <> nil then
    Result := GKeyCache.Acquire(ASubjectPublicKeyInfo)
  else
    Result := DecodePublicKey(ASubjectPublicKeyInfo);
end;

// Registered with TaurusTLS: runs on OpenSSL unload while its functions are still bound
procedure ReleaseCachedKeys;
begin
  if GKeyCache <> nil then
    GKeyCache.Clear;
end;

function DigestOf(AHashAlg: TIAM4DHashAlgorithm): PEVP_MD;
begin
  case AHashAlg of
    haSHA256: Result := EVP_sha256();
    haSHA384: Result := EVP_sha384();
    haSHA512: Result := EVP_sha512();
  else
    Result := nil;
  end;
end;

function DigestName(AHashAlg: TIAM4DHashAlgorithm): PAnsiChar;
begin
  case AHashAlg of
    haSHA256: Result := 'SHA256';
    haSHA384: Result := 'SHA384';
    haSHA512: Result := 'SHA512';
  else
    Result := nil;
  end;
end;

function BytesPtr(const AValue: TBytes): PByte;
begin
  if Length(AValue) > 0 then
    Result := @AValue[0]
  else
    Result := nil;
end;

{ TIAM4DTaurusTLSCryptoProvider }

constructor TIAM4DTaurusTLSCryptoProvider.Create;
begin
  inherited Create;
  TIAM4DOpenSSL.EnsureLoaded;
end;

// GKeyCache is nil only after finalization
class function TIAM4DTaurusTLSCryptoProvider.KeyCacheStats: TIAM4DKeyCacheStats;
begin
  if GKeyCache <> nil then
    Result := GKeyCache.Stats
  else
    Result := Default(TIAM4DKeyCacheStats);
end;

class procedure TIAM4DTaurusTLSCryptoProvider.ClearKeyCache;
begin
  if GKeyCache <> nil then
    GKeyCache.Clear;
end;

class function TIAM4DTaurusTLSCryptoProvider.GetKeyCacheCapacity: Integer;
begin
  Result := KeyCacheStats.Capacity;
end;

class procedure TIAM4DTaurusTLSCryptoProvider.SetKeyCacheCapacity(AValue: Integer);
begin
  if (AValue < 0) or (AValue > MAX_KEY_CACHE_CAPACITY) then
    raise EArgumentOutOfRangeException.CreateFmt(
      'KeyCacheCapacity must be between 0 and %d (got %d)', [MAX_KEY_CACHE_CAPACITY, AValue]);
  if GKeyCache <> nil then
    GKeyCache.SetCapacity(AValue);
end;

function TIAM4DTaurusTLSCryptoProvider.GetProviderName: string;
begin
  Result := 'TaurusTLS (OpenSSL)';
end;

function TIAM4DTaurusTLSCryptoProvider.GetSupportedAlgorithms: TArray<string>;
begin
  Result := TArray<string>.Create(
    'RS256', 'RS384', 'RS512',  // RSA PKCS#1 v1.5
    'PS256', 'PS384', 'PS512',  // RSA-PSS
    'ES256', 'ES384', 'ES512'   // ECDSA
  );
end;

function TIAM4DTaurusTLSCryptoProvider.SupportsAlgorithm(const AAlg: string): Boolean;
var
  LAlg: string;
begin
  // Case-sensitive (RFC 7515 4.1.1)
  for LAlg in GetSupportedAlgorithms do
    if LAlg = AAlg then
      Exit(True);
  Result := False;
end;

function TIAM4DTaurusTLSCryptoProvider.RSAVerifyPKCS1(const AExpectedEM, ASignature,
  AModulus, AExponent: TBytes): Boolean;
var
  LCtx: PBN_CTX;
  LN, LE, LS, LM: PBIGNUM;
  LActualEM: TBytes;
  LLen: Integer;
begin
  Result := False;
  LLen := Length(AExpectedEM);
  // BN_mod_exp applies no key checks: e = 1 would accept the EM itself, a huge n or e burns CPU
  if (LLen = 0) or (Length(ASignature) <> LLen) or
     not TIAM4DRSAPublicKey.IsValid(AModulus, AExponent) then
    Exit;

  LCtx := nil;
  LN := nil;
  LE := nil;
  LS := nil;
  LM := nil;
  try
    LCtx := BN_CTX_new();
    LN := BN_bin2bn(@AModulus[0], Length(AModulus), nil);
    LE := BN_bin2bn(@AExponent[0], Length(AExponent), nil);
    LS := BN_bin2bn(@ASignature[0], LLen, nil);
    LM := BN_new();
    if (LCtx = nil) or (LN = nil) or (LE = nil) or (LS = nil) or (LM = nil) then
      Exit;

    // k = |n| must match EM length; s must be in [0, n) (RFC 8017 5.2.2)
    if (BN_num_bits(LN) + 7) div 8 <> LLen then
      Exit;
    if BN_cmp(LS, LN) >= 0 then
      Exit;

    // m = s^e mod n: public values only, constant time not required
    if BN_mod_exp(LM, LS, LE, LN, LCtx) <> 1 then
      Exit;

    SetLength(LActualEM, LLen);
    if BN_bn2binpad(LM, @LActualEM[0], LLen) <> LLen then
      Exit;

    Result := SecureEquals(AExpectedEM, LActualEM);
  finally
    BN_free(LM);
    BN_free(LS);
    BN_free(LE);
    BN_free(LN);
    BN_CTX_free(LCtx);
    ERR_clear_error();
  end;
end;

function TIAM4DTaurusTLSCryptoProvider.RSAVerifyPSS(const AMessage, ASignature,
  AModulus, AExponent: TBytes; AHashAlg: TIAM4DHashAlgorithm; ASaltLen: Integer): Boolean;
var
  LKey: PEVP_PKEY;
  LMDCtx: PEVP_MD_CTX;
  LPKeyCtx: PEVP_PKEY_CTX;
  LSaltLen: AnsiString;
begin
  Result := False;
  // OpenSSL also accepts signatures shorter than k (leading zero bytes stripped)
  if (ASaltLen < 0) or (DigestOf(AHashAlg) = nil) or
     not TIAM4DRSAPublicKey.IsValid(AModulus, AExponent) or
     (Length(ASignature) <> TIAM4DRSAPublicKey.ModulusSize(AModulus)) then
    Exit;

  // Allocated inside the try: a missing OpenSSL symbol raises
  LKey := nil;
  LMDCtx := nil;
  try
    LKey := AcquirePublicKey(BuildRSASubjectPublicKeyInfo(AModulus, AExponent));
    if LKey = nil then
      Exit;

    LMDCtx := EVP_MD_CTX_new();
    if LMDCtx = nil then
      Exit;

    // LPKeyCtx is owned by LMDCtx
    LPKeyCtx := nil;
    if EVP_DigestVerifyInit(LMDCtx, @LPKeyCtx, DigestOf(AHashAlg), nil, LKey) <> 1 then
      Exit;

    LSaltLen := AnsiString(IntToStr(ASaltLen));
    if (EVP_PKEY_CTX_ctrl_str(LPKeyCtx, 'rsa_padding_mode', 'pss') <= 0) or
       (EVP_PKEY_CTX_ctrl_str(LPKeyCtx, 'rsa_pss_saltlen', PAnsiChar(LSaltLen)) <= 0) or
       (EVP_PKEY_CTX_ctrl_str(LPKeyCtx, 'rsa_mgf1_md', DigestName(AHashAlg)) <= 0) then
      Exit;

    Result := EVP_DigestVerify(LMDCtx, @ASignature[0], Length(ASignature),
      BytesPtr(AMessage), Length(AMessage)) = 1;
  finally
    if LMDCtx <> nil then
      EVP_MD_CTX_free(LMDCtx);
    if LKey <> nil then
      EVP_PKEY_free(LKey);
    ERR_clear_error();
  end;
end;

// DER ECDSA-Sig-Value; False unless R, S, x, y have the coordinate size
function TIAM4DTaurusTLSCryptoProvider.ECDSASignature(ACurve: TIAM4DECCurve;
  const AR, AS_, AX, AY: TBytes; out ASignature: TBytes): Boolean;
var
  LSize: Integer;
begin
  LSize := CurveCoordinateSize(ACurve);
  if LSize = 0 then
    raise EIAM4DCryptoNotSupportedException.Create(
      Format('Curve %d not supported', [Ord(ACurve)]), GetProviderName);

  // Exact sizes, as TMS: OpenSSL would accept padded or stripped values
  Result := (Length(AR) = LSize) and (Length(AS_) = LSize) and
    (Length(AX) = LSize) and (Length(AY) = LSize);
  if Result then
    // ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
    ASignature := DerTLV($30, DerUnsignedInteger(AR) + DerUnsignedInteger(AS_));
end;

function TIAM4DTaurusTLSCryptoProvider.ECDSAVerify(const AHash, AR, AS_, AX, AY: TBytes;
  ACurve: TIAM4DECCurve): Boolean;
var
  LKey: PEVP_PKEY;
  LPKeyCtx: PEVP_PKEY_CTX;
  LSignature: TBytes;
begin
  Result := False;
  // OpenSSL would truncate a longer digest
  if not ECDSASignature(ACurve, AR, AS_, AX, AY, LSignature) or
     (Length(AHash) <> CurveHashSize(ACurve)) then
    Exit;

  // Allocated inside the try: a missing OpenSSL symbol raises
  LKey := nil;
  LPKeyCtx := nil;
  try
    LKey := AcquirePublicKey(BuildECSubjectPublicKeyInfo(ACurve, AX, AY));
    if LKey = nil then
      Exit;

    LPKeyCtx := EVP_PKEY_CTX_new(LKey, nil);
    if (LPKeyCtx = nil) or (EVP_PKEY_verify_init(LPKeyCtx) <> 1) then
      Exit;

    Result := EVP_PKEY_verify(LPKeyCtx, @LSignature[0], Length(LSignature),
      @AHash[0], Length(AHash)) = 1;
  finally
    if LPKeyCtx <> nil then
      EVP_PKEY_CTX_free(LPKeyCtx);
    if LKey <> nil then
      EVP_PKEY_free(LKey);
    ERR_clear_error();
  end;
end;

function TIAM4DTaurusTLSCryptoProvider.ECDSAVerifyMessage(const AMessage, AR, AS_, AX, AY: TBytes;
  ACurve: TIAM4DECCurve): Boolean;
var
  LKey: PEVP_PKEY;
  LMDCtx: PEVP_MD_CTX;
  LSignature: TBytes;
begin
  Result := False;
  if not ECDSASignature(ACurve, AR, AS_, AX, AY, LSignature) then
    Exit;

  // Allocated inside the try: a missing OpenSSL symbol raises
  LKey := nil;
  LMDCtx := nil;
  try
    LKey := AcquirePublicKey(BuildECSubjectPublicKeyInfo(ACurve, AX, AY));
    if LKey = nil then
      Exit;

    LMDCtx := EVP_MD_CTX_new();
    if (LMDCtx = nil) or
       (EVP_DigestVerifyInit(LMDCtx, nil, DigestOf(CurveHash(ACurve)), nil, LKey) <> 1) then
      Exit;

    // OpenSSL hashes the message with the curve hash
    Result := EVP_DigestVerify(LMDCtx, @LSignature[0], Length(LSignature),
      BytesPtr(AMessage), Length(AMessage)) = 1;
  finally
    if LMDCtx <> nil then
      EVP_MD_CTX_free(LMDCtx);
    if LKey <> nil then
      EVP_PKEY_free(LKey);
    ERR_clear_error();
  end;
end;

initialization
  GKeyCache := TPublicKeyCache.Create;
  Register_SSLUnloader(ReleaseCachedKeys);

finalization
  // Before TaurusTLSLoader (used by this unit): OpenSSL still bound
  FreeAndNil(GKeyCache);

{$ELSE}
// Unit is empty when TaurusTLS is not the active provider (mutual exclusivity)
interface
implementation
{$ENDIF}

end.
