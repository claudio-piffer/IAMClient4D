unit Main;

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
  uniButton,
  uniGUIBaseClasses,
  uniPanel,
  uniMemo,
  uniLabel,
  uniStatusBar,
  uniSweetAlert,
  Vcl.Imaging.pngimage,
  uniImage;

type
  TMainForm = class(TUniForm)
    UniContainerPanel1: TUniContainerPanel;
    UniContainerPanel2: TUniContainerPanel;
    AccessTokeniButton: TUniButton;
    ValidateTokenButton: TUniButton;
    UserInfoButton: TUniButton;
    UniMemo1: TUniMemo;
    UniStatusBar1: TUniStatusBar;
    LogoutButton: TUniButton;
    UniSweetAlert: TUniSweetAlert;
    UniImage1: TUniImage;
    procedure UniFormCreate(Sender: TObject);
    procedure AccessTokeniButtonClick(Sender: TObject);
    procedure ValidateTokenButtonClick(Sender: TObject);
    procedure UserInfoButtonClick(Sender: TObject);
    procedure LogoutButtonClick(Sender: TObject);
    procedure UniFormActivate(Sender: TObject);
    procedure UniFormShow(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

function MainForm: TMainForm;

implementation

{$R *.dfm}

uses
  System.JSON,
  uniGUIVars,
  MainModule,
  uniGUIApplication,
  IAMClient4D.Security.Core,
  IAMClient4D.Security.JWT,
  IAMClient4D.Common.Security,
  IAMClient4D.Core;

function MainForm: TMainForm;
begin
  Result := TMainForm(UniMainModule.GetFormInstance(TMainForm));
end;

procedure TMainForm.UniFormCreate(Sender: TObject);
begin
  AccessTokeniButton.JSInterface.JSCall('addCls', ['mybtn-primary']);
  ValidateTokenButton.JSInterface.JSCall('addCls', ['mybtn-warning']);
  UserInfoButton.JSInterface.JSCall('addCls', ['mybtn-success']);
  LogoutButton.JSInterface.JSCall('addCls', ['mybtn-danger']);
  UniStatusBar1.Height := 30;
  UniStatusBar1.JSInterface.JSCall('addCls', ['mystatus']);
end;

procedure TMainForm.AccessTokeniButtonClick(Sender: TObject);
begin
  UniMemo1.Lines.Clear;
  UniMemo1.Lines.Add(UniMainModule.IAMClient.GetAccessToken);
end;

procedure TMainForm.ValidateTokenButtonClick(Sender: TObject);
var
  LJWTValidator: IIAM4DJWTValidator;
  LClaims: TJSONObject;
begin
  UniMemo1.Lines.Clear;
  UniMemo1.Lines.Add(UniMainModule.IAMClient.GetAccessToken);
  LJWTValidator := TIAM4DJWTValidator.Create(UniMainModule.IAMClient.Issuer, 'api-server', svmAllowSelfSigned);
  try
    if LJWTValidator.ValidateToken(UniMemo1.Lines.Text, LClaims) then
    begin
      try
        UniMemo1.Lines.Clear;
        UniMemo1.Lines.Add(LClaims.Format(4));
      finally
        LClaims.Free;
      end;
    end;
  except on E: Exception do
    begin
      with UniSweetAlert do
      begin
        Title := 'JWT Validation error';
        Text := E.Message;
        AlertType := TAlertType.atError;

        ShowConfirmButton := True;
        ConfirmButtonText := 'Ok';
        ConfirmButtonColor := $0003131;
        ShowCancelButton := False;

        AllowOutsideClick := False;
        AllowEscapeKey := False;
        Show;
      end;
    end;
  end;
end;

procedure TMainForm.UserInfoButtonClick(Sender: TObject);
var
  LUserInfo: TIAM4DUserInfo;
begin
  UniMemo1.Lines.Clear;
  LUserInfo := UniMainModule.IAMClient.GetUserInfo;
  UniMemo1.Lines.Add('=== User Info ===');
  UniMemo1.Lines.Add('Sub: ' + LUserInfo.Sub);
  UniMemo1.Lines.Add('Preferred Username: ' + LUserInfo.PreferredUsername);
  UniMemo1.Lines.Add('Name: ' + LUserInfo.Name);
  UniMemo1.Lines.Add('Email: ' + LUserInfo.Email);
  UniMemo1.Lines.Add('Email Verified: ' + BoolToStr(LUserInfo.EmailVerified, True));
end;

procedure TMainForm.LogoutButtonClick(Sender: TObject);
begin
  UniMemo1.Lines.Clear;

  UniMainModule.IAMClient.Logout;
  UniSession.TerminateAfterSecs(0);
  TUniGUIApplication(UniApplication).Terminate;
end;

procedure TMainForm.UniFormActivate(Sender: TObject);
begin
  UniSession.AddJS(Format('history.replaceState({}, "", "%s");', ['/']));
end;

procedure TMainForm.UniFormShow(Sender: TObject);
begin
  UniMemo1.Lines.Clear;
  if Assigned(UniMainModule.IAMClient) then
  begin
    UniMemo1.Lines.Add(UniMainModule.IAMClient.GetAccessToken);
    UniStatusBar1.Panels.Items[0].Text := Format('Welcome %s', [UniMainModule.IAMClient.GetUserInfo.PreferredUsername]);
  end;
end;

initialization
  RegisterAppFormClass(TMainForm);

end.

