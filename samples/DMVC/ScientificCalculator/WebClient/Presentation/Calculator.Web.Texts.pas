unit Calculator.Web.Texts;

(* Texts of the pages, in English and Italian: i18n\en.json and i18n\it.json
  under the web root, one object per section ("home.welcome").

  The language of a request: a GET with ?lang=it|en (saved in a cookie, then
  a redirect without it), else the cookie, else Accept-Language, else English.
  LanguageHTTPFilter puts the texts into the view data of the request:
    t         the catalog (templates: {{:t.home.welcome}})
    lang      'en' or 'it' (<html lang>)
    js_texts  the "js" section as JSON, for app.js

  Template conventions: keys ending in _html hold markup and are written raw
  ({{:t.x_html$}}); {name} placeholders are filled with the replace filter,
  and in a raw key only with values chosen by this server, never user data. *)

interface

uses
  MVCFramework;

type
  TLanguage = (lgEnglish, lgItalian);

const
  LANGUAGE_CODES: array [TLanguage] of string = ('en', 'it');
  LANGUAGE_COOKIE = 'calcweb_lang';

/// <summary>Loads the catalogs of AFolder; raises when they do not have the same keys.</summary>
procedure LoadTexts(const AFolder: string);
/// <summary>Chooses the language of the request and puts its texts into the view data.</summary>
function LanguageHTTPFilter: TMVCHTTPFilter;
/// <summary>
/// The text of AKey in the language of the request, with the {name}
/// placeholders replaced by AArgs (name, value pairs). The key itself when missing.
/// </summary>
function Text(const AContext: TWebContext; const AKey: string; const AArgs: array of string): string;

implementation

uses
  System.SysUtils,
  System.Classes,
  System.IOUtils,
  System.DateUtils,
  System.Rtti,
  Web.HTTPApp,
  JsonDataObjects,
  MVCFramework.Commons,
  Calculator.Web.Settings;

var
  // Read-only after LoadTexts. JsonDataObjects caches the last lookup inside the
  // object, so requests read a clone, never these
  GCatalogs: array [TLanguage] of TJsonObject;

procedure CollectKeys(const AObject: TJsonObject; const APrefix: string; const AKeys: TStrings);
var
  I: Integer;
begin
  for I := 0 to AObject.Count - 1 do
    if AObject.Types[AObject.Names[I]] = jdtObject then
      CollectKeys(AObject.O[AObject.Names[I]], APrefix + AObject.Names[I] + '.', AKeys)
    else
      AKeys.Add(APrefix + AObject.Names[I]);
end;

procedure LoadTexts(const AFolder: string);
var
  LLanguage: TLanguage;
  LKeys: array [TLanguage] of TStringList;
  LKey: string;
begin
  for LLanguage := Low(TLanguage) to High(TLanguage) do
  begin
    FreeAndNil(GCatalogs[LLanguage]);
    GCatalogs[LLanguage] := TJsonObject.ParseFromFile(
      TPath.Combine(AFolder, LANGUAGE_CODES[LLanguage] + '.json')) as TJsonObject;
  end;
  // A key missing in one catalog would show up as an empty text: refuse to start
  for LLanguage := Low(TLanguage) to High(TLanguage) do
  begin
    LKeys[LLanguage] := TStringList.Create;
    LKeys[LLanguage].Sorted := True;
    CollectKeys(GCatalogs[LLanguage], '', LKeys[LLanguage]);
  end;
  try
    for LLanguage := Succ(Low(TLanguage)) to High(TLanguage) do
    begin
      for LKey in LKeys[lgEnglish] do
        if LKeys[LLanguage].IndexOf(LKey) < 0 then
          raise EFileNotFoundException.CreateFmt('i18n: "%s" missing in %s.json', [LKey, LANGUAGE_CODES[LLanguage]]);
      for LKey in LKeys[LLanguage] do
        if LKeys[lgEnglish].IndexOf(LKey) < 0 then
          raise EFileNotFoundException.CreateFmt('i18n: "%s" missing in en.json', [LKey]);
    end;
  finally
    for LLanguage := Low(TLanguage) to High(TLanguage) do
      LKeys[LLanguage].Free;
  end;
end;

function TryLanguageOfCode(const ACode: string; out ALanguage: TLanguage): Boolean;
var
  LLanguage: TLanguage;
begin
  for LLanguage := Low(TLanguage) to High(TLanguage) do
    if SameText(ACode, LANGUAGE_CODES[LLanguage]) then
    begin
      ALanguage := LLanguage;
      Exit(True);
    end;
  Result := False;
end;

// The first known language of "it-IT,it;q=0.9,en;q=0.8" (browsers send them by preference)
function LanguageOfAcceptLanguage(const AHeader: string): TLanguage;
var
  LItem, LCode: string;
begin
  for LItem in AHeader.Split([',']) do
  begin
    LCode := LItem.Split([';'])[0].Split(['-'])[0].Trim;
    if TryLanguageOfCode(LCode, Result) then
      Exit;
  end;
  Result := lgEnglish;
end;

function RequestLanguage(const AContext: TWebContext): TLanguage;
begin
  if not TryLanguageOfCode(AContext.Request.Cookie(LANGUAGE_COOKIE), Result) then
    Result := LanguageOfAcceptLanguage(AContext.Request.Headers['Accept-Language']);
end;

procedure SaveLanguage(const AContext: TWebContext; const ALanguage: TLanguage);
var
  LCookie: TCookie;
begin
  LCookie := AContext.Response.Cookies.Add;
  LCookie.Name := LANGUAGE_COOKIE;
  LCookie.Value := LANGUAGE_CODES[ALanguage];
  LCookie.Path := '/';
  LCookie.HttpOnly := True;
  LCookie.Secure := Settings.CookieSecure;
  LCookie.SameSite := 'Lax';
  LCookie.Expires := IncYear(Now, 1);
end;

function LanguageHTTPFilter: TMVCHTTPFilter;
begin
  Result :=
    procedure(const AContext: TWebContext; const ANext: TMVCHTTPFilterNext)
    var
      LLanguage: TLanguage;
      LTexts: TJsonObject;
    begin
      // A preference, not data: a link (GET) may change it
      if (AContext.Request.HTTPMethod = httpGET) and
        TryLanguageOfCode(AContext.Request.QueryStringParam('lang'), LLanguage) then
      begin
        SaveLanguage(AContext, LLanguage);
        AContext.Response.CustomHeaders.Values['Location'] := AContext.Request.PathInfo;
        AContext.Response.StatusCode := HTTP_STATUS.SeeOther;
        Exit;
      end;

      LLanguage := RequestLanguage(AContext);
      LTexts := GCatalogs[LLanguage].Clone as TJsonObject;
      try
        // Context view data: also seen by the error page of UseExceptionHandler
        AContext.ViewData['t'] := LTexts;
        AContext.ViewData['lang'] := LANGUAGE_CODES[LLanguage];
        AContext.ViewData['js_texts'] := LTexts.O['js'].ToJSON(True);
        ANext();
      finally
        AContext.ViewData.Remove('t');
        LTexts.Free;
      end;
    end;
end;

function Text(const AContext: TWebContext; const AKey: string; const AArgs: array of string): string;
var
  LValue: TValue;
  I: Integer;
begin
  if not (AContext.ViewData.TryGetValue('t', LValue) and LValue.IsObject and (LValue.AsObject is TJsonObject)) then
    Exit(AKey);
  Result := TJsonObject(LValue.AsObject).Path[AKey].Value;
  if Result.IsEmpty then
    Exit(AKey);
  I := 0;
  while I < High(AArgs) do
  begin
    Result := Result.Replace('{' + AArgs[I] + '}', AArgs[I + 1]);
    Inc(I, 2);
  end;
end;

procedure FreeCatalogs;
var
  LLanguage: TLanguage;
begin
  for LLanguage := Low(TLanguage) to High(TLanguage) do
    FreeAndNil(GCatalogs[LLanguage]);
end;

initialization

finalization
  FreeCatalogs;

end.
