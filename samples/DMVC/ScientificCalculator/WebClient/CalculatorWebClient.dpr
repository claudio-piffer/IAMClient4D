program CalculatorWebClient;

{ Web client of the scientific calculator (DMVCFramework + TemplatePro + HTMX,
  Bootstrap 5.3). Backend For Frontend: the user signs in through Keycloak
  (Authorization Code + PKCE, confidential client, done by IAMClient4D on the
  server); the browser only gets an HttpOnly session cookie and the server
  calls the REST servers with the access token.

  Layers (see ..\README.md):
    Infrastructure   settings, sessions and login (IAMClient4D), REST client of the API
    Presentation     engine, controllers, number formatting, texts (English, Italian)
    templates, www,  views, static files and the texts of the pages (i18n\en.json,
    i18n             i18n\it.json), copied next to the executable by the build

  Configuration (environment or .env next to the executable):
    IAM4D_ISSUER, IAM4D_AUDIENCE, IAM4D_ALLOW_SELF_SIGNED, CALC_WEB_CLIENT_ID,
    CALC_WEB_CLIENT_SECRET, CALC_WEB_PORT (8092), CALC_WEB_PUBLIC_URL,
    CALC_CONTROLLERS_URL, CALC_MINIMAL_URL, CALC_WEB_SESSION_IDLE_MINUTES, CALC_WEB_ROOT. }

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.IOUtils,
  MVCFramework,
  MVCFramework.Commons,
  MVCFramework.Server.Intf,
  MVCFramework.Server.Factory,
  Calculator.Web.Settings in 'Infrastructure\Calculator.Web.Settings.pas',
  Calculator.Web.Sessions in 'Infrastructure\Calculator.Web.Sessions.pas',
  Calculator.Web.ApiClient in 'Infrastructure\Calculator.Web.ApiClient.pas',
  Calculator.Web.Formatting in 'Presentation\Calculator.Web.Formatting.pas',
  Calculator.Web.Texts in 'Presentation\Calculator.Web.Texts.pas',
  Calculator.Web.Controllers.Base in 'Presentation\Calculator.Web.Controllers.Base.pas',
  Calculator.Web.Controllers.Public in 'Presentation\Calculator.Web.Controllers.Public.pas',
  Calculator.Web.Controllers.Auth in 'Presentation\Calculator.Web.Controllers.Auth.pas',
  Calculator.Web.Controllers.Calculator in 'Presentation\Calculator.Web.Controllers.Calculator.pas',
  Calculator.Web.Controllers.Keypad in 'Presentation\Calculator.Web.Controllers.Keypad.pas',
  Calculator.Web.Controllers.Advanced in 'Presentation\Calculator.Web.Controllers.Advanced.pas',
  Calculator.Web.Controllers.Account in 'Presentation\Calculator.Web.Controllers.Account.pas',
  Calculator.Web.Engine in 'Presentation\Calculator.Web.Engine.pas';

procedure RunServer;
var
  LEngine: TMVCEngine;
begin
  LEngine := TMVCEngine.Create(
    procedure(AConfig: TMVCConfig)
    begin
      AConfig[TMVCConfigKey.DefaultContentType] := TMVCMediaType.TEXT_HTML;
      AConfig[TMVCConfigKey.ViewPath] := TPath.Combine(Settings.WebRoot, 'templates');
      AConfig[TMVCConfigKey.DefaultViewFileExtension] := 'html';
{$IFDEF DEBUG}
      AConfig[TMVCConfigKey.ViewCache] := 'false';
{$ELSE}
      AConfig[TMVCConfigKey.ViewCache] := 'true';
{$ENDIF}
    end);
  try
    ConfigureWebEngine(LEngine);

    WriteLn(APP_NAME, ' - web client (DMVC + HTMX)');
    WriteLn('  Open        : ', Settings.PublicURL);
    WriteLn('  Keycloak    : ', Settings.Issuer, ' (client ', Settings.ClientId, ')');
    WriteLn('  Controllers : ', Settings.BackendURLs[cbControllers]);
    WriteLn('  Minimal API : ', Settings.BackendURLs[cbMinimalAPI]);
    WriteLn('Press Ctrl+C to stop.');
    TMVCServerFactory.CreateIndyDirect(LEngine).RunAndWait(Settings.Port);
  finally
    LEngine.Free;
  end;
end;

begin
  ReportMemoryLeaksOnShutdown := True;
  IsMultiThread := True;
  try
    LoadSettings;
    RunServer;
  except
    on E: Exception do
    begin
      WriteLn(E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
