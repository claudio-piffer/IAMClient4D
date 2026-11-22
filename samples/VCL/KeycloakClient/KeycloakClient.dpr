program KeycloakClient;

uses
  Vcl.Forms,
  Vcl.Themes,
  Vcl.Styles,
  IAMClient.MainForm in 'IAMClient.MainForm.pas' {MainForm},
  UserManagement in 'UserManagement.pas',
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
