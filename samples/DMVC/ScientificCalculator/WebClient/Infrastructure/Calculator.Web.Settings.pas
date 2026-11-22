unit Calculator.Web.Settings;

{ Configuration of the web client, read through DMVC dotEnv (environment
  variables, or a .env file next to the executable; the file wins). }

interface

type
  /// <summary>The two REST servers of the sample, same API.</summary>
  TCalculatorBackend = (cbControllers, cbMinimalAPI);

  TWebClientSettings = record
    /// <summary>Keycloak realm URL (IAM4D_ISSUER), the same key the servers read.</summary>
    Issuer: string;
    /// <summary>Keycloak base URL and realm, taken from Issuer.</summary>
    KeycloakBaseURL: string;
    Realm: string;
    /// <summary>Client whose roles the API checks (IAM4D_AUDIENCE).</summary>
    Audience: string;
    /// <summary>Accept a self-signed Keycloak certificate (IAM4D_ALLOW_SELF_SIGNED).</summary>
    AllowSelfSigned: Boolean;
    /// <summary>Confidential client of this web app (CALC_WEB_CLIENT_ID, CALC_WEB_CLIENT_SECRET).</summary>
    ClientId: string;
    ClientSecret: string;
    Port: Integer;
    /// <summary>URL the browser uses to reach this app, without the final slash (CALC_WEB_PUBLIC_URL).</summary>
    PublicURL: string;
    BackendURLs: array [TCalculatorBackend] of string;
    SessionIdleMinutes: Integer;
    /// <summary>Folder with templates\ and www\ (CALC_WEB_ROOT).</summary>
    WebRoot: string;
    /// <summary>Random at every start: the sessions live in memory too.</summary>
    CsrfSecret: string;
    class function Load: TWebClientSettings; static;
    function RedirectURI: string;
    /// <summary>Secure cookies when the public URL is https.</summary>
    function CookieSecure: Boolean;
  end;

const
  APP_NAME = 'Scientific Calculator';
  BACKEND_IDS: array [TCalculatorBackend] of string = ('controllers', 'minimal-api');
  BACKEND_LABELS: array [TCalculatorBackend] of string = ('Controllers', 'Minimal API');
  CALLBACK_PATH = '/auth/callback';

procedure LoadSettings;
function Settings: TWebClientSettings;

function TryBackendFromId(const AId: string; out ABackend: TCalculatorBackend): Boolean;

implementation

uses
  System.SysUtils,
  System.IOUtils,
  MVCFramework.Commons,
  IAMClient4D.Common.CryptoUtils;

const
  // The Keycloak of Docker/ (start.cmd): override it with IAM4D_ISSUER
  DEFAULT_ISSUER = 'http://localhost:18180/auth/realms/iamclient4d';
  REALMS_SEGMENT = '/realms/';

var
  GSettings: TWebClientSettings;
  GSettingsLoaded: Boolean;

class function TWebClientSettings.Load: TWebClientSettings;
var
  LPos: Integer;
begin
  Result.Issuer := dotEnv.Env('IAM4D_ISSUER', DEFAULT_ISSUER).TrimRight(['/']);
  LPos := Result.Issuer.IndexOf(REALMS_SEGMENT);
  if LPos < 0 then
    raise EArgumentException.CreateFmt('IAM4D_ISSUER "%s" is not a realm URL (.../realms/<realm>)', [Result.Issuer]);
  Result.KeycloakBaseURL := Result.Issuer.Substring(0, LPos);
  Result.Realm := Result.Issuer.Substring(LPos + REALMS_SEGMENT.Length);
  Result.Audience := dotEnv.Env('IAM4D_AUDIENCE', 'api-server');
  Result.AllowSelfSigned := dotEnv.Env('IAM4D_ALLOW_SELF_SIGNED', True);

  Result.ClientId := dotEnv.Env('CALC_WEB_CLIENT_ID', 'calculator-web');
  Result.ClientSecret := dotEnv.Env('CALC_WEB_CLIENT_SECRET', '');
  if Result.ClientSecret.Trim.IsEmpty then
    raise EArgumentException.Create('CALC_WEB_CLIENT_SECRET is empty: copy the secret of the "' +
      Result.ClientId + '" client (Keycloak admin console, Clients > Credentials) into .env');

  Result.Port := dotEnv.Env('CALC_WEB_PORT', 8092);
  Result.PublicURL := dotEnv.Env('CALC_WEB_PUBLIC_URL', 'http://localhost:' + Result.Port.ToString).TrimRight(['/']);
  Result.BackendURLs[cbControllers] := dotEnv.Env('CALC_CONTROLLERS_URL', 'http://localhost:8090').TrimRight(['/']);
  Result.BackendURLs[cbMinimalAPI] := dotEnv.Env('CALC_MINIMAL_URL', 'http://localhost:8091').TrimRight(['/']);
  Result.SessionIdleMinutes := dotEnv.Env('CALC_WEB_SESSION_IDLE_MINUTES', 30);
  Result.WebRoot := dotEnv.Env('CALC_WEB_ROOT', TPath.Combine(AppPath, 'CalculatorWeb'));
  Result.CsrfSecret := BytesToHex(TIAM4DCryptoUtils.GenerateSecureRandomBytes(32));
end;

function TWebClientSettings.RedirectURI: string;
begin
  Result := PublicURL + CALLBACK_PATH;
end;

function TWebClientSettings.CookieSecure: Boolean;
begin
  Result := PublicURL.StartsWith('https://', True);
end;

procedure LoadSettings;
begin
  GSettings := TWebClientSettings.Load;
  GSettingsLoaded := True;
end;

function Settings: TWebClientSettings;
begin
  if not GSettingsLoaded then
    raise EInvalidOpException.Create('LoadSettings has not been called');
  Result := GSettings;
end;

function TryBackendFromId(const AId: string; out ABackend: TCalculatorBackend): Boolean;
var
  LBackend: TCalculatorBackend;
begin
  for LBackend := Low(TCalculatorBackend) to High(TCalculatorBackend) do
    if SameText(AId, BACKEND_IDS[LBackend]) then
    begin
      ABackend := LBackend;
      Exit(True);
    end;
  Result := False;
end;

end.
