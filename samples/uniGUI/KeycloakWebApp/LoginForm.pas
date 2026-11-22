unit LoginForm;

interface

uses
  Windows,
  Messages,
  SysUtils,
  Variants,
  Classes,
  Graphics,
  Controls,
  Forms,
  uniGUITypes,
  uniGUIAbstractClasses,
  uniGUIClasses,
  uniGUIRegClasses,
  uniGUIForm,
  uniGUIBaseClasses,
  uniPanel,
  uniImage,
  uniURLFrame,
  Vcl.Imaging.pngimage,
  uniTimer;

type
  TUniLoginForm1 = class(TUniLoginForm)
    UniContainerPanel1: TUniContainerPanel;
    htmlFrame: TUniURLFrame;
    UniImage1: TUniImage;
    UniTimer1: TUniTimer;
    procedure UniLoginFormCreate(Sender: TObject);
    procedure UniTimer1Timer(Sender: TObject);
  private
    procedure ShowLoginError(const AMessage: string);
  public
    { Public declarations }
  end;

function UniLoginForm1: TUniLoginForm1;

implementation

{$R *.dfm}

uses
  System.NetEncoding,
  uniGUIVars,
  MainModule,
  uniGUIApplication;

function UniLoginForm1: TUniLoginForm1;
begin
  Result := TUniLoginForm1(UniMainModule.GetFormInstance(TUniLoginForm1));
end;

procedure TUniLoginForm1.UniLoginFormCreate(Sender: TObject);
begin
  UniTimer1.Enabled := True;
end;

procedure TUniLoginForm1.ShowLoginError(const AMessage: string);
begin
  htmlFrame.HTML.Text :=
    '<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding-top:40px">' +
    '<p>' + TNetEncoding.HTML.Encode(AMessage) + '</p>' +
    '<p><a href="/" target="_top">Sign in again</a></p></body></html>';
end;

procedure TUniLoginForm1.UniTimer1Timer(Sender: TObject);
begin
  UniTimer1.Enabled := False;
  // The login was started by TUniMainModule.StartLogin (BeforeLogin), or failed
  if UniMainModule.AuthURL <> '' then
    UniSession.UrlRedirect(UniMainModule.AuthURL)
  else
    ShowLoginError(UniMainModule.LoginError);
end;

initialization
  RegisterAppFormClass(TUniLoginForm1);

end.

