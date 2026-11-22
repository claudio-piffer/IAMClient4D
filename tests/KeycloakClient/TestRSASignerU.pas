unit TestRSASignerU;

{ RSA signing key of the fake identity provider of IAM4DKeycloakClientTest: generated at startup,
  RSASSA-PKCS1-v1_5 with SHA-256 (RS256).

  The operating system does the RSA work: CNG (bcrypt.dll) on Windows, OpenSSL libcrypto
  (libcrypto.so.3, loaded at runtime) on Linux. LockBox3, the pure Pascal provider of the library,
  only verifies: generating a 2048-bit key with it takes minutes, and every id_token of the tests
  would need a private key operation. }

interface

uses
  System.SysUtils;

type
  ETestRSASigner = class(Exception);

  TTestRSASigner = class
  private
    FKey: Pointer;
    {$IFDEF MSWINDOWS}
    FAlgorithm: Pointer;
    {$ENDIF}
    FModulus: TBytes;
    FExponent: TBytes;
  public
    /// <summary>Generates an RSA key of ABits bits (public exponent 65537)</summary>
    constructor Create(const ABits: Integer);
    destructor Destroy; override;
    /// <summary>RSASSA-PKCS1-v1_5 signature of ASHA256 (the SHA-256 hash of the signing input)</summary>
    function SignSHA256(const ASHA256: TBytes): TBytes;
    /// <summary>Modulus n, big-endian, without leading zero bytes</summary>
    property Modulus: TBytes read FModulus;
    /// <summary>Public exponent e, big-endian</summary>
    property Exponent: TBytes read FExponent;
  end;

implementation

{$IFDEF MSWINDOWS}

type
  NTSTATUS = Integer;

  BCRYPT_PKCS1_PADDING_INFO = record
    pszAlgId: PWideChar;
  end;

  BCRYPT_RSAKEY_BLOB = record
    Magic: Cardinal;
    BitLength: Cardinal;
    cbPublicExp: Cardinal;
    cbModulus: Cardinal;
    cbPrime1: Cardinal;
    cbPrime2: Cardinal;
  end;
  PBCRYPT_RSAKEY_BLOB = ^BCRYPT_RSAKEY_BLOB;

const
  BCRYPT_DLL = 'bcrypt.dll';
  BCRYPT_PAD_PKCS1 = $00000002;

function BCryptOpenAlgorithmProvider(out phAlgorithm: Pointer; pszAlgId, pszImplementation: PWideChar;
  dwFlags: Cardinal): NTSTATUS; stdcall; external BCRYPT_DLL;
function BCryptCloseAlgorithmProvider(hAlgorithm: Pointer; dwFlags: Cardinal): NTSTATUS; stdcall; external BCRYPT_DLL;
function BCryptGenerateKeyPair(hAlgorithm: Pointer; out phKey: Pointer; dwLength, dwFlags: Cardinal): NTSTATUS;
  stdcall; external BCRYPT_DLL;
function BCryptFinalizeKeyPair(hKey: Pointer; dwFlags: Cardinal): NTSTATUS; stdcall; external BCRYPT_DLL;
function BCryptDestroyKey(hKey: Pointer): NTSTATUS; stdcall; external BCRYPT_DLL;
function BCryptExportKey(hKey, hExportKey: Pointer; pszBlobType: PWideChar; pbOutput: PByte; cbOutput: Cardinal;
  out pcbResult: Cardinal; dwFlags: Cardinal): NTSTATUS; stdcall; external BCRYPT_DLL;
function BCryptSignHash(hKey: Pointer; pPaddingInfo: Pointer; pbInput: PByte; cbInput: Cardinal; pbOutput: PByte;
  cbOutput: Cardinal; out pcbResult: Cardinal; dwFlags: Cardinal): NTSTATUS; stdcall; external BCRYPT_DLL;

procedure CheckStatus(const AStatus: NTSTATUS; const AWhat: string);
begin
  if AStatus <> 0 then
    raise ETestRSASigner.CreateFmt('%s failed: NTSTATUS $%.8x', [AWhat, Cardinal(AStatus)]);
end;

constructor TTestRSASigner.Create(const ABits: Integer);
var
  LBlob: TBytes;
  LSize: Cardinal;
  LHeader: PBCRYPT_RSAKEY_BLOB;
begin
  inherited Create;
  CheckStatus(BCryptOpenAlgorithmProvider(FAlgorithm, 'RSA', nil, 0), 'BCryptOpenAlgorithmProvider');
  CheckStatus(BCryptGenerateKeyPair(FAlgorithm, FKey, ABits, 0), 'BCryptGenerateKeyPair');
  CheckStatus(BCryptFinalizeKeyPair(FKey, 0), 'BCryptFinalizeKeyPair');

  // RSAPUBLICBLOB: BCRYPT_RSAKEY_BLOB, then exponent and modulus, both big-endian
  CheckStatus(BCryptExportKey(FKey, nil, 'RSAPUBLICBLOB', nil, 0, LSize, 0), 'BCryptExportKey (size)');
  SetLength(LBlob, LSize);
  CheckStatus(BCryptExportKey(FKey, nil, 'RSAPUBLICBLOB', @LBlob[0], LSize, LSize, 0), 'BCryptExportKey');
  LHeader := PBCRYPT_RSAKEY_BLOB(@LBlob[0]);
  FExponent := Copy(LBlob, SizeOf(BCRYPT_RSAKEY_BLOB), LHeader.cbPublicExp);
  FModulus := Copy(LBlob, SizeOf(BCRYPT_RSAKEY_BLOB) + Integer(LHeader.cbPublicExp), LHeader.cbModulus);
end;

destructor TTestRSASigner.Destroy;
begin
  if Assigned(FKey) then
    BCryptDestroyKey(FKey);
  if Assigned(FAlgorithm) then
    BCryptCloseAlgorithmProvider(FAlgorithm, 0);
  inherited;
end;

function TTestRSASigner.SignSHA256(const ASHA256: TBytes): TBytes;
var
  LPadding: BCRYPT_PKCS1_PADDING_INFO;
  LSize: Cardinal;
begin
  LPadding.pszAlgId := 'SHA256';
  SetLength(Result, Length(FModulus));
  CheckStatus(BCryptSignHash(FKey, @LPadding, @ASHA256[0], Length(ASHA256), @Result[0], Length(Result), LSize,
    BCRYPT_PAD_PKCS1), 'BCryptSignHash');
  SetLength(Result, LSize);
end;

{$ELSE}

const
  LIBCRYPTO = 'libcrypto.so.3';
  NID_SHA256 = 672;
  RSA_F4 = 65537;

type
  TRSA_new = function: Pointer; cdecl;
  TRSA_free = procedure(ARSA: Pointer); cdecl;
  TRSA_generate_key_ex = function(ARSA: Pointer; ABits: Integer; AE: Pointer; ACallback: Pointer): Integer; cdecl;
  TRSA_sign = function(AType: Integer; AM: PByte; AMLength: Cardinal; ASigRet: PByte; var ASigLen: Cardinal;
    ARSA: Pointer): Integer; cdecl;
  TRSA_get0_key = procedure(ARSA: Pointer; out AN, AE, AD: Pointer); cdecl;
  TBN_new = function: Pointer; cdecl;
  TBN_free = procedure(ABN: Pointer); cdecl;
  TBN_set_word = function(ABN: Pointer; AW: NativeUInt): Integer; cdecl;
  TBN_num_bits = function(ABN: Pointer): Integer; cdecl;
  TBN_bn2bin = function(ABN: Pointer; ATo: PByte): Integer; cdecl;

var
  GLibrary: HMODULE;
  RSA_new: TRSA_new;
  RSA_free: TRSA_free;
  RSA_generate_key_ex: TRSA_generate_key_ex;
  RSA_sign: TRSA_sign;
  RSA_get0_key: TRSA_get0_key;
  BN_new: TBN_new;
  BN_free: TBN_free;
  BN_set_word: TBN_set_word;
  BN_num_bits: TBN_num_bits;
  BN_bn2bin: TBN_bn2bin;

function Bind(const AName: string): Pointer;
begin
  Result := GetProcAddress(GLibrary, PChar(AName));
  if not Assigned(Result) then
    raise ETestRSASigner.CreateFmt('%s not found in %s', [AName, LIBCRYPTO]);
end;

procedure LoadLibCrypto;
begin
  if GLibrary <> 0 then
    Exit;
  GLibrary := LoadLibrary(PChar(LIBCRYPTO));
  if GLibrary = 0 then
    raise ETestRSASigner.CreateFmt('Cannot load %s', [LIBCRYPTO]);
  RSA_new := Bind('RSA_new');
  RSA_free := Bind('RSA_free');
  RSA_generate_key_ex := Bind('RSA_generate_key_ex');
  RSA_sign := Bind('RSA_sign');
  RSA_get0_key := Bind('RSA_get0_key');
  BN_new := Bind('BN_new');
  BN_free := Bind('BN_free');
  BN_set_word := Bind('BN_set_word');
  BN_num_bits := Bind('BN_num_bits');
  BN_bn2bin := Bind('BN_bn2bin');
end;

function BigNumBytes(const ABN: Pointer): TBytes;
begin
  SetLength(Result, (BN_num_bits(ABN) + 7) div 8);
  if Length(Result) > 0 then
    BN_bn2bin(ABN, @Result[0]);
end;

constructor TTestRSASigner.Create(const ABits: Integer);
var
  LE, LN, LPublicE, LD: Pointer;
begin
  inherited Create;
  LoadLibCrypto;
  FKey := RSA_new();
  LE := BN_new();
  try
    if (BN_set_word(LE, RSA_F4) <> 1) or (RSA_generate_key_ex(FKey, ABits, LE, nil) <> 1) then
      raise ETestRSASigner.Create('RSA_generate_key_ex failed');
  finally
    BN_free(LE);
  end;
  // Owned by the key
  RSA_get0_key(FKey, LN, LPublicE, LD);
  FModulus := BigNumBytes(LN);
  FExponent := BigNumBytes(LPublicE);
end;

destructor TTestRSASigner.Destroy;
begin
  if Assigned(FKey) then
    RSA_free(FKey);
  inherited;
end;

function TTestRSASigner.SignSHA256(const ASHA256: TBytes): TBytes;
var
  LSize: Cardinal;
begin
  SetLength(Result, Length(FModulus));
  LSize := Length(Result);
  if RSA_sign(NID_SHA256, @ASHA256[0], Length(ASHA256), @Result[0], LSize, FKey) <> 1 then
    raise ETestRSASigner.Create('RSA_sign failed');
  SetLength(Result, LSize);
end;

{$ENDIF}

end.
