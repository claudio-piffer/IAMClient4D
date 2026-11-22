program IdentityBrokering;

uses
  Vcl.Forms,
  Vcl.Themes,
  Vcl.Styles,
  IdentityBrokering.MainForm in 'IdentityBrokering.MainForm.pas' {MainForm},
  IdentityBrokering.SpidRegistry in '..\..\Common\IdentityBrokering.SpidRegistry.pas',
  IdentityBrokering.Common in '..\..\Common\IdentityBrokering.Common.pas',
  Samples.PendingOperations in '..\Common\Samples.PendingOperations.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  ReportMemoryLeaksOnShutdown := True;
  TStyleManager.TrySetStyle('Iceberg Classico');
  Application.CreateForm(TMainForm, MainForm);
  Application.Run;

end.
