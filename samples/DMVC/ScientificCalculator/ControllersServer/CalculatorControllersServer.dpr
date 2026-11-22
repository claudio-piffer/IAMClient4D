program CalculatorControllersServer;

{ Scientific calculator REST API, controller version (DMVCFramework + IAMClient4D).

  Layers (see ..\README.md):
    Core\Domain          math rules and domain errors, no dependency
    Core\Application     use cases, DTOs, ports
    Core\Infrastructure  in-memory history, clock
    Shared               composition root and presentation helpers of both servers
    Presentation         the controllers of this server

  Security: the IAM4DJWTBundle filter bundle validates the bearer token on
  every action but the [IAM4DPublic] ones; the controllers check the roles.

  Configuration (environment or .env next to the executable):
    IAM4D_ISSUER, IAM4D_AUDIENCE, IAM4D_ALLOW_SELF_SIGNED, CALC_CORS_ORIGINS,
    CALC_CONTROLLERS_PORT (default 8090). }

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  MVCFramework,
  MVCFramework.Commons,
  MVCFramework.Server.Intf,
  MVCFramework.Server.Factory,
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
  Calculator.Controllers.Public in 'Presentation\Calculator.Controllers.Public.pas',
  Calculator.Controllers.Math in 'Presentation\Calculator.Controllers.Math.pas',
  Calculator.Controllers.Advanced in 'Presentation\Calculator.Controllers.Advanced.pas',
  Calculator.Controllers.Account in 'Presentation\Calculator.Controllers.Account.pas';

const
  TITLE = 'Scientific Calculator API (controllers)';

procedure RunServer;
var
  LEngine: TMVCEngine;
begin
  LEngine := TMVCEngine.Create(
    procedure(AConfig: TMVCConfig)
    begin
      AConfig[TMVCConfigKey.DefaultContentType] := TMVCMediaType.APPLICATION_JSON;
    end);
  try
    ConfigureCalculatorEngine(LEngine, TITLE, cpEngine);

    LEngine.AddController(TPublicController);
    LEngine.AddController(TMathController);
    LEngine.AddController(TAdvancedController);
    LEngine.AddController(TAccountController);

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
    LoadSettings('CALC_CONTROLLERS_PORT', 8090);
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
