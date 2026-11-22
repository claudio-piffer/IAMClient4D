unit WebModuleU;

interface

uses
  System.SysUtils,
  System.Classes,
  Web.HTTPApp,
  MVCFramework,
  MVCFramework.Swagger.Commons;

type
  TMyWebModule = class(TWebModule)
    procedure WebModuleCreate(Sender: TObject);
    procedure WebModuleDestroy(Sender: TObject);
  private
    FMVC: TMVCEngine;
    function GetSwagInfoV1: TMVCSwaggerInfo;
    function GetSwagInfoV2: TMVCSwaggerInfo;
  public
    { Public declarations }
  end;

var
  WebModuleClass: TComponentClass = TMyWebModule;

implementation

{$R *.dfm}

uses
  MyControllerU,
  System.IOUtils,
  MVCFramework.Commons,
  MVCFramework.Filters,
  MVCFramework.Filters.Swagger,
  IAMClient4D.DMVC.Filters,
  IAMClient4D.Common.Security;

function TMyWebModule.GetSwagInfoV1: TMVCSwaggerInfo;
begin
  Result.Title := 'DMVCFramework IAMClient4D integration (Version 1)';
  Result.Version := 'V1';
  Result.Description := 'SwaggerAPI Versioning V1' + DMVCFRAMEWORK_VERSION;
  Result.ContactName := 'Claudio Piffer';
  Result.ContactEmail := 'claudio.piffer@gmail.com';
  Result.LicenseName := 'Apache v2';
  Result.LicenseUrl := 'https://www.apache.org/licenses/LICENSE-2.0';
end;

function TMyWebModule.GetSwagInfoV2: TMVCSwaggerInfo;
begin
  Result.Title := 'DMVCFramework IAMClient4D integration (Version 2)';
  Result.Version := 'V2';
  Result.Description := 'SwaggerAPI Versioning V2' + DMVCFRAMEWORK_VERSION;
  Result.ContactName := 'Claudio Piffer';
  Result.ContactEmail := 'claudio.piffer@gmail.com';
  Result.LicenseName := 'Apache v2';
  Result.LicenseUrl := 'https://www.apache.org/licenses/LICENSE-2.0';
end;

procedure TMyWebModule.WebModuleCreate(Sender: TObject);
var
  LSSLMode: TIAM4DSSLValidationMode;
begin
  FMVC := TMVCEngine.Create(Self,
    procedure(Config: TMVCConfig)
    begin
      // session timeout (0 means session cookie)

      // default content-type
      Config[TMVCConfigKey.DefaultContentType] := TMVCConstants.DEFAULT_CONTENT_TYPE;
      // default content charset
      Config[TMVCConfigKey.DefaultContentCharset] := TMVCConstants.DEFAULT_CONTENT_CHARSET;
      // unhandled actions are permitted?
      Config[TMVCConfigKey.AllowUnhandledAction] := 'false';
      // default view file extension
      Config[TMVCConfigKey.DefaultViewFileExtension] := 'html';
      // view path
      Config[TMVCConfigKey.ViewPath] := 'templates';
      // Max Record Count for automatic Entities CRUD
      Config[TMVCConfigKey.MaxEntitiesRecordCount] := '20';
      // No Server header: it would tell the framework and its version
      Config[TMVCConfigKey.ExposeServerSignature] := 'false';
      // Max request size in bytes
      Config[TMVCConfigKey.MaxRequestSize] := IntToStr(TMVCConstants.DEFAULT_MAX_REQUEST_SIZE);
    end);

  //  FMVC.AddController(TMyControllerV1);
  //  FMVC.AddController(TMyControllerV2);

  // CORS first: it answers the preflight before any token is asked; WWW-Authenticate (401/403)
  // and Retry-After (503) readable by a browser client
  FMVC.Use(CORSHTTPFilter('*', False, 'WWW-Authenticate,Retry-After'));

  // Bearer token checked on every controller action; before SwaggerHTTPFilter,
  // so the bearer scheme is added to the Swagger documents on the way out.
  // Issuer from IAM4D_ISSUER (environment or .env next to the exe); the default is the Keycloak of
  // Docker/ (start.cmd)
  if dotEnv.Env('IAM4D_ALLOW_SELF_SIGNED', False) then
    LSSLMode := TIAM4DSSLValidationMode.svmAllowSelfSigned
  else
    LSSLMode := TIAM4DSSLValidationMode.svmStrict;
  FMVC.Use(IAM4DJWTBundle(
    dotEnv.Env('IAM4D_ISSUER', 'http://localhost:18180/auth/realms/iamclient4d').TrimRight(['/']),
    dotEnv.Env('IAM4D_AUDIENCE', 'api-server'),
    LSSLMode));

  FMVC.Use(StaticFilesHTTPFilter('/swagger', '.\www'));

  FMVC.Use(SwaggerHTTPFilter(FMVC, GetSwagInfoV1, '/api/swagger-v1.json',
    'Method for authentication using JSON Web Token (JWT)', [], '', '', '/api/v1'));
  FMVC.Use(SwaggerHTTPFilter(FMVC, GetSwagInfoV2, '/api/swagger-v2.json',
    'Method for authentication using JSON Web Token (JWT)', [], '', '', '/api/v2', [psHTTP, psHTTPS]));

  FMVC.AddController(TMyControllerV1);
  FMVC.AddController(TMyControllerV2);
end;

procedure TMyWebModule.WebModuleDestroy(Sender: TObject);
begin
  FMVC.Free;
end;

end.

