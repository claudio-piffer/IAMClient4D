unit Calculator.Application.Caller;

{ Application layer: who is asking. The presentation layer builds it from the
  validated token (IAMClient4D); the use cases never see a token or a framework. }

interface

type
  TCaller = record
    /// <summary>Stable user identifier (the "sub" claim).</summary>
    Subject: string;
    /// <summary>Name to show (preferred_username, email or sub).</summary>
    UserName: string;
    class function Create(const ASubject, AUserName: string): TCaller; static;
  end;

implementation

uses
  System.SysUtils;

class function TCaller.Create(const ASubject, AUserName: string): TCaller;
begin
  if ASubject.Trim.IsEmpty then
    raise EArgumentException.Create('TCaller: the subject is required');
  Result.Subject := ASubject;
  Result.UserName := AUserName;
end;

end.
