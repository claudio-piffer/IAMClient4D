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
    procedure OpenIAMLogin;
    function ExtractStateFromURL(const AURL: string): string;
  public
    { Public declarations }
  end;

function UniLoginForm1: TUniLoginForm1;

implementation

{$R *.dfm}

uses
  uniGUIVars,
  MainModule,
  uniGUIApplication,
  IAMClient4D.Core,
  IAMClient4D.Config.Builder;

function UniLoginForm1: TUniLoginForm1;
begin
  Result := TUniLoginForm1(UniMainModule.GetFormInstance(TUniLoginForm1));
end;

procedure TUniLoginForm1.UniLoginFormCreate(Sender: TObject);
begin
  UniTimer1.Enabled := True;
end;

function TUniLoginForm1.ExtractStateFromURL(const AURL: string): string;
var
  LStatePos, LAmpPos: Integer;
begin
  Result := '';

  LStatePos := Pos('state=', AURL);
  if LStatePos > 0 then
  begin
    Result := Copy(AURL, LStatePos + 6, Length(AURL));

    LAmpPos := Pos('&', Result);
    if LAmpPos > 0 then
      Result := Copy(Result, 1, LAmpPos - 1)
    else
    begin
      LAmpPos := Pos('#', Result);
      if LAmpPos > 0 then
        Result := Copy(Result, 1, LAmpPos - 1);
    end;
  end;
end;

procedure TUniLoginForm1.OpenIAMLogin;
var
  LAuthURL: string;
  LClient: IIAM4DClient;
begin
  LClient := TIAM4DClientConfigBuilder.New
    .ForAuthorizationCode(
    'https://192.168.0.24:28443/auth',
    'iamclient4d',
    'demo_public')
    .WithExternalCallback('http://localhost:8077/?oauthcallback=keycloak')
    .WithAllowSelfSignedSSL
    .Build;

  LClient.InitializeAuthorizationFlow;

  LAuthURL := LClient.GenerateAuthURL;

  UniMainModule.IAMClientManager.SetClient(ExtractStateFromURL(LAuthURL), LClient);

  UniSession.UrlRedirect(LAuthURL);
end;

procedure TUniLoginForm1.UniTimer1Timer(Sender: TObject);
begin
  UniTimer1.Enabled := False;
  OpenIAMLogin;
end;

initialization
  RegisterAppFormClass(TUniLoginForm1);

end.

