program IdentityBrokeringMobile;

uses
  System.StartUpCopy,
  FMX.Forms,
  FMX.Skia,
  IdentityBrokeringMobile.MainForm in 'IdentityBrokeringMobile.MainForm.pas' {MainForm},
  IdentityBrokering.SpidRegistry in '..\..\Common\IdentityBrokering.SpidRegistry.pas',
  IdentityBrokering.Common in '..\..\Common\IdentityBrokering.Common.pas',
  Samples.PendingOperations.FMX in '..\Common\Samples.PendingOperations.FMX.pas',
  IdentityBrokeringMobile.Animations in 'IdentityBrokeringMobile.Animations.pas';

{$R *.res}

begin
  GlobalUseSkia := True;
  Application.FormFactor.Orientations := [TFormOrientation.Portrait];
  Application.Initialize;
  ReportMemoryLeaksOnShutdown := True;
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;
end.
