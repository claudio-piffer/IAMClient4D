program CalculatorMinimalAPIServer;

{ Scientific calculator REST API, Minimal API version (DMVCFramework + IAMClient4D).

  Layers (see ..\README.md):
    Core\Domain          math rules and domain errors, no dependency
    Core\Application     use cases, DTOs, ports
    Core\Infrastructure  in-memory history, clock
    Shared               composition root and presentation helpers of both servers
    Presentation         the route groups of this server

  Security: the IAM4DJWTEndpointFilter endpoint filter validates the bearer
  token on the protected groups, a second filter checks the role; the public
  group has none. IAM4DSwaggerSecurityHTTPFilter adds the bearer scheme to the
  OpenAPI document. (With no public route, AEngine.Use(IAM4DJWTBundle(...))
  would protect every route, as in the controller server.)

  Configuration (environment or .env next to the executable):
    IAM4D_ISSUER, IAM4D_AUDIENCE, IAM4D_ALLOW_SELF_SIGNED, CALC_CORS_ORIGINS,
    CALC_MINIMAL_PORT (default 8091). }

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  MVCFramework,
  MVCFramework.Commons,
  MVCFramework.Server.Intf,
  MVCFramework.Server.Factory,
  IAMClient4D.DMVC.Authenticator,
  Calculator.Domain.Errors in '..\Core\Domain\Calculator.Domain.Errors.pas',
  Calculator.Domain.Elementary in '..\Core\Domain\Calculator.Domain.Elementary.pas',
  Calculator.Domain.Expressions in '..\Core\Domain\Calculator.Domain.Expressions.pas',
  Calculator.Domain.NumberTheory in '..\Core\Domain\Calculator.Domain.NumberTheory.pas',
  Calculator.Domain.Statistics in '..\Core\Domain\Calculator.Domain.Statistics.pas',
  Calculator.Domain.Equations in '..\Core\Domain\Calculator.Domain.Equations.pas',
  Calculator.Domain.Constants in '..\Core\Domain\Calculator.Domain.Constants.pas',
  Calculator.Domain.Calculation in '..\Core\Domain\Calculator.Domain.Calculation.pas',
  Calculator.Application.Caller in '..\Core\Application\Calculator.Application.Caller.pas',
  Calculator.Application.Ports in '..\Core\Application\Calculator.Application.Ports.pas',
  Calculator.Application.DTO in '..\Core\Application\Calculator.Application.DTO.pas',
  Calculator.Application.UseCases in '..\Core\Application\Calculator.Application.UseCases.pas',
  Calculator.Infrastructure.History in '..\Core\Infrastructure\Calculator.Infrastructure.History.pas',
  Calculator.Presentation.Settings in '..\Shared\Calculator.Presentation.Settings.pas',
  Calculator.Presentation.Security in '..\Shared\Calculator.Presentation.Security.pas',
  Calculator.Presentation.Errors in '..\Shared\Calculator.Presentation.Errors.pas',
  Calculator.Presentation.Requests in '..\Shared\Calculator.Presentation.Requests.pas',
  Calculator.Presentation.SwaggerUI in '..\Shared\Calculator.Presentation.SwaggerUI.pas',
  Calculator.Presentation.Composition in '..\Shared\Calculator.Presentation.Composition.pas',
  Calculator.Routes in 'Presentation\Calculator.Routes.pas';

const
  TITLE = 'Scientific Calculator API (Minimal API)';

procedure RunServer;
var
  LEngine: TMVCEngine;
  LAuthenticator: IIAM4DJWTAuthenticator;
begin
  LEngine := TMVCEngine.Create(
    procedure(AConfig: TMVCConfig)
    begin
      AConfig[TMVCConfigKey.DefaultContentType] := TMVCMediaType.APPLICATION_JSON;
    end);
  try
    // Engine filters first (ConfigureEngine), then the routes (ConfigureRoutes)
    LAuthenticator := ConfigureCalculatorEngine(LEngine, TITLE, cpRouteGroups);
    ConfigureRoutes(LEngine, LAuthenticator);

    WriteLn(TITLE);
    WriteLn('  Issuer    : ', Settings.Issuer);
    WriteLn('  Audience  : ', Settings.Audience);
    WriteLn('  Swagger UI: http://localhost:', Settings.Port, SWAGGER_UI_PATH);
    WriteLn('  OpenAPI   : http://localhost:', Settings.Port, OPENAPI_URL);
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
    LoadSettings('CALC_MINIMAL_PORT', 8091);
    RegisterCalculatorServices;
    RunServer;
  except
    on E: Exception do
    begin
      WriteLn(E.ClassName, ': ', E.Message);
      ExitCode := 1;
    end;
  end;
end.
