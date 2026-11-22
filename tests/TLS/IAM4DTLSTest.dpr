program IAM4DTLSTest;

{ Certificate validation and public key pinning over real TLS handshakes.

  Three local HTTPS servers (Indy + TaurusTLS) present the certificates of certs\: a valid
  self-signed RSA certificate, an expired one and an ECDSA P-256 one. The client is the
  THTTPClient of TIAM4DHTTPClientFactory with the SSL helper and validator of the library, as a
  TIAM4DKeycloakClient builds it: what the platform (WinHTTP, libcurl) reports is what is checked.

  The expected pins are computed without IAMClient4D, from the certificate:
    openssl x509 -in rsa.pem -noout -modulus | cut -d= -f2 | tr -d '\r\n' | openssl dgst -sha256
  (SHA-256 of the RSA modulus in uppercase hex, as TCertificate.PublicKey reports it).

  Usage : IAM4DTLSTest [OpenSSL folder]   (Windows: folder of libcrypto/libssl; Linux: system OpenSSL)
  Exit  : number of failed checks; 2 when OpenSSL cannot be loaded and nothing was checked
          (unless IAM4D_ALLOW_SKIP=1: then 0). }

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Classes,
  System.SyncObjs,
  System.Net.URLClient,
  System.Net.HttpClient,
  IdGlobal,
  IdContext,
  IdCustomHTTPServer,
  IdHTTPServer,
  TaurusTLS,
  TaurusTLSLoader,
  IAMClient4D.Core,
  IAMClient4D.Common.Security,
  IAMClient4D.Exceptions;

const
  // certs\rsa.pem and certs\expired.pem, see the header for the command
  PIN_RSA = '39ec664322c7ffedbc17ddcd2484994d38f3ef882be8947edfc4a5e73713656a';
  PIN_EXPIRED = 'd522b47ad5d128c0ab15dfeafa5dda6bd1772520934ea00b57429b597220faa8';
  PIN_OTHER = '0000000000000000000000000000000000000000000000000000000000000000';
  PORT_RSA = 18943;
  PORT_EXPIRED = 18944;
  PORT_EC = 18945;

type
  TOutcome = (
    ocAccepted,
    // EIAM4DSSLCertificateException: the certificate was refused
    ocRejected,
    // Any other error: the check fails
    ocError);

  TTLSServer = class
  private
    FHTTP: TIdHTTPServer;
    FIO: TTaurusTLSServerIOHandler;
    procedure QuerySSLPort(APort: TIdPort; var VUseSSL: Boolean);
    procedure CommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo;
      AResponseInfo: TIdHTTPResponseInfo);
  public
    constructor Create(APort: Integer; const ACertDir, AName: string);
    destructor Destroy; override;
  end;

  /// <summary>Messages of TIAM4DSSLCertificateValidator.OnCertificateValidation</summary>
  TValidationLog = class
  private
    FLock: TCriticalSection;
    FText: string;
  public
    constructor Create;
    destructor Destroy; override;
    procedure CertificateValidation(Sender: TObject; const Certificate: TCertificate; Accepted: Boolean;
      Reason: TIAM4DCertificateRejectionReason; const Message: string);
    function Text: string;
  end;

var
  GPassed: Integer = 0;
  GFailed: Integer = 0;

{ TTLSServer }

constructor TTLSServer.Create(APort: Integer; const ACertDir, AName: string);
begin
  inherited Create;
  FIO := TTaurusTLSServerIOHandler.Create(nil);
  FIO.DefaultCert.PublicKey := ACertDir + AName + '.pem';
  FIO.DefaultCert.PrivateKey := ACertDir + AName + '.key';
  FHTTP := TIdHTTPServer.Create(nil);
  FHTTP.IOHandler := FIO;
  FHTTP.OnQuerySSLPort := QuerySSLPort;
  FHTTP.OnCommandGet := CommandGet;
  FHTTP.Bindings.Clear;
  with FHTTP.Bindings.Add do
  begin
    IP := '127.0.0.1';
    Port := APort;
  end;
  FHTTP.Active := True;
end;

destructor TTLSServer.Destroy;
begin
  FHTTP.Active := False;
  FHTTP.Free;
  FIO.Free;
  inherited;
end;

procedure TTLSServer.QuerySSLPort(APort: TIdPort; var VUseSSL: Boolean);
begin
  VUseSSL := True;
end;

procedure TTLSServer.CommandGet(AContext: TIdContext; ARequestInfo: TIdHTTPRequestInfo;
  AResponseInfo: TIdHTTPResponseInfo);
begin
  AResponseInfo.ResponseNo := 200;
  AResponseInfo.ContentType := 'text/plain';
  AResponseInfo.ContentText := 'tls ok';
end;

{ TValidationLog }

constructor TValidationLog.Create;
begin
  inherited Create;
  FLock := TCriticalSection.Create;
end;

destructor TValidationLog.Destroy;
begin
  FLock.Free;
  inherited;
end;

procedure TValidationLog.CertificateValidation(Sender: TObject; const Certificate: TCertificate; Accepted: Boolean;
  Reason: TIAM4DCertificateRejectionReason; const Message: string);
begin
  FLock.Enter;
  try
    FText := FText + Message + ' | ';
  finally
    FLock.Leave;
  end;
end;

function TValidationLog.Text: string;
begin
  FLock.Enter;
  try
    Result := FText;
  finally
    FLock.Leave;
  end;
end;

{ Checks }

procedure Check(const AName: string; ACondition: Boolean; const ADetail: string = '');
begin
  if ACondition then
  begin
    Inc(GPassed);
    Writeln('  PASS  ', AName);
  end
  else
  begin
    Inc(GFailed);
    Writeln('  FAIL  ', AName);
    if ADetail <> '' then
      Writeln('        ', ADetail);
  end;
end;

/// <summary>
/// GET https://127.0.0.1:APort/ with a client built as TIAM4DKeycloakClient builds it: mode
/// AMode, pins APins. ADetail: exception and messages of the validator.
/// </summary>
function Probe(AMode: TIAM4DSSLValidationMode; const APins: TArray<string>; APort: Integer;
  out ADetail: string): TOutcome;
var
  LValidatorObj: TIAM4DSSLCertificateValidator;
  LValidator: IIAM4DSSLCertificateValidator;
  LLog: TValidationLog;
  LHelper: TIAM4DHTTPClientSSLHelper;
  LConfig: TIAM4DClientConfig;
  LClient: THTTPClient;
  LResponse: IHTTPResponse;
  LURL: string;
begin
  LURL := Format('https://127.0.0.1:%d', [APort]);
  LLog := TValidationLog.Create;
  try
    LValidatorObj := TIAM4DSSLCertificateValidator.Create;
    LValidator := LValidatorObj;
    LValidator.SetValidationMode(AMode);
    LValidator.AddPinnedPublicKeys(APins);
    LValidatorObj.OnCertificateValidation := LLog.CertificateValidation;
    LHelper := TIAM4DHTTPClientSSLHelper.Create(LValidator);
    try
      LConfig := TIAM4DClientConfig.Create(LURL, 'test', 'tls-test', gtAuthorizationCode, nil, '', AMode, 5000, 10000);
      LClient := TIAM4DHTTPClientFactory.CreateHTTPClient(LConfig, LHelper);
      try
        try
          LResponse := TIAM4DHTTPClientFactory.Execute(LClient, 'GET', LURL + '/');
          if (LResponse.StatusCode = 200) and (LResponse.ContentAsString = 'tls ok') then
            Result := ocAccepted
          else
            Result := ocError;
          ADetail := Format('HTTP %d', [LResponse.StatusCode]);
        except
          on E: EIAM4DSSLCertificateException do
          begin
            Result := ocRejected;
            ADetail := E.ClassName + ': ' + E.Message;
          end;
          on E: Exception do
          begin
            Result := ocError;
            ADetail := E.ClassName + ': ' + E.Message;
          end;
        end;
      finally
        LClient.Free;
      end;
    finally
      LHelper.Free;
    end;
    ADetail := ADetail + ' [validator: ' + LLog.Text + ']';
  finally
    LLog.Free;
  end;
end;

procedure CheckProbe(const AName: string; AMode: TIAM4DSSLValidationMode; const APins: TArray<string>;
  APort: Integer; AExpected: TOutcome; const AMustContain: string = '');
const
  CNames: array[TOutcome] of string = ('accepted', 'rejected', 'error');
var
  LDetail: string;
  LOutcome: TOutcome;
begin
  LOutcome := Probe(AMode, APins, APort, LDetail);
  Check(AName, (LOutcome = AExpected) and ((AMustContain = '') or LDetail.Contains(AMustContain)),
    CNames[LOutcome] + ': ' + LDetail);
end;

function LoadOpenSSL: Boolean;
var
  LLoader: IOpenSSLLoader;
begin
  LLoader := GetOpenSSLLoader;
  if not Assigned(LLoader) then
    Exit(True);
  if ParamCount > 0 then
    LLoader.OpenSSLPath := ParamStr(1);
  try
    Result := LLoader.Load;
  except
    on E: Exception do
    begin
      Writeln('OpenSSL: ', E.Message);
      Result := False;
    end;
  end;
end;

function CertDir: string;
begin
  // tests\bin\TLS\<platform>\<config>\ -> tests\TLS\certs\
  // ExpandFileName drops the trailing delimiter on Linux
  Result := IncludeTrailingPathDelimiter(ExpandFileName(ExtractFilePath(ParamStr(0)) + '..' + PathDelim + '..' + PathDelim + '..' + PathDelim +
    '..' + PathDelim + 'TLS' + PathDelim + 'certs'));
end;

procedure RunChecks;
{$IFDEF LINUX}
var
  LRaised: Boolean;
  LValidator: IIAM4DSSLCertificateValidator;
{$ENDIF}
begin
  Writeln('Validation modes');
  CheckProbe('strict: self-signed certificate refused (untrusted root)', svmStrict, nil, PORT_RSA, ocRejected);
  CheckProbe('self-signed mode: self-signed certificate accepted', svmAllowSelfSigned, nil, PORT_RSA, ocAccepted);
  CheckProbe('self-signed mode: expired certificate refused', svmAllowSelfSigned, nil, PORT_EXPIRED, ocRejected,
    'expired');
  CheckProbe('self-signed mode: ECDSA certificate accepted', svmAllowSelfSigned, nil, PORT_EC, ocAccepted);

  Writeln('Public key pinning');
  {$IFDEF LINUX}
  // libcurl calls the validator only for a certificate the system refused: pins are refused
  LValidator := TIAM4DSSLCertificateValidator.Create;
  LRaised := False;
  try
    LValidator.AddPinnedPublicKeys([PIN_RSA]);
  except
    on ENotSupportedException do
      LRaised := True;
  end;
  Check('Linux: AddPinnedPublicKeys refused (ENotSupportedException)', LRaised);
  {$ELSE}
  CheckProbe('pin computed with openssl x509 -modulus accepted', svmAllowSelfSigned, [PIN_RSA], PORT_RSA, ocAccepted);
  CheckProbe('pin given in uppercase accepted', svmAllowSelfSigned, [UpperCase(PIN_RSA)], PORT_RSA, ocAccepted);
  CheckProbe('one of several pins accepted (rotation)', svmAllowSelfSigned, [PIN_OTHER, PIN_RSA], PORT_RSA, ocAccepted);
  CheckProbe('other pin: refused, the hash reported is the openssl one', svmAllowSelfSigned, [PIN_OTHER], PORT_RSA,
    ocRejected, 'hash: ' + PIN_RSA);
  CheckProbe('pin of another certificate refused', svmAllowSelfSigned, [PIN_EXPIRED], PORT_RSA, ocRejected,
    'Public key pinning failed');
  CheckProbe('strict with the right pin: still refused (a pin does not replace the chain)', svmStrict, [PIN_RSA],
    PORT_RSA, ocRejected);
  CheckProbe('expired certificate with its pin refused', svmAllowSelfSigned, [PIN_EXPIRED], PORT_EXPIRED, ocRejected,
    'expired');
  CheckProbe('ECDSA certificate with pins refused (no RSA key reported)', svmAllowSelfSigned, [PIN_RSA], PORT_EC,
    ocRejected, 'no public key reported');
  // A second client of the same process: the pin is checked again (no TLS session reuse that skips it)
  CheckProbe('pin checked again by a later client: other pin refused', svmAllowSelfSigned, [PIN_OTHER], PORT_RSA,
    ocRejected, 'Public key pinning failed');
  {$ENDIF}
end;

var
  LServers: array of TTLSServer;
  LDir: string;
begin
  ReportMemoryLeaksOnShutdown := True;
  try
    if not LoadOpenSSL then
    begin
      Writeln('OpenSSL not available: TLS test not run (pass the OpenSSL folder as the first parameter)');
      if GetEnvironmentVariable('IAM4D_ALLOW_SKIP') = '1' then
        ExitCode := 0
      else
        ExitCode := 2;
      Exit;
    end;
    LDir := CertDir;
    Writeln('IAMClient4D TLS test - certificates in ', LDir);
    LServers := [TTLSServer.Create(PORT_RSA, LDir, 'rsa'), TTLSServer.Create(PORT_EXPIRED, LDir, 'expired'),
      TTLSServer.Create(PORT_EC, LDir, 'ec')];
    try
      RunChecks;
    finally
      for var LServer in LServers do
        LServer.Free;
    end;
    Writeln;
    Writeln(Format('Passed: %d  Failed: %d', [GPassed, GFailed]));
    ExitCode := GFailed;
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
      ExitCode := 99;
    end;
  end;
end.
