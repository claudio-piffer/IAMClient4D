{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Common.PlatformUtils.pas
  Project    : IAMClient4D
  Author     : Claudio Piffer
  Copyright  : Copyright (c) 2018-2025 Claudio Piffer
  License    : Apache License, Version 2.0, January 2004
  Source URL : https://github.com/claudio-piffer/IAMClient4D

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  ---------------------------------------------------------------------------
}

unit IAMClient4D.Common.PlatformUtils;

interface

type
  /// <summary>
  /// Cross-platform utility class for platform-specific operations.
  /// </summary>
  /// <remarks>
  /// Provides platform-abstracted methods for common OS operations.
  /// Supported platforms: Windows, macOS, iOS, Linux, Android.
  /// All methods are static and handle platform-specific implementations internally.
  /// Returns false on errors without raising exceptions.
  /// </remarks>
  TIAM4DPlatformUtils = class
  public
    /// <summary>
    /// Extracts URI scheme if present and syntactically valid
    /// </summary>
    class function TryGetURIScheme(const AURL: string; out AScheme: string): Boolean;

    /// <summary>
    /// Opens URI using the default system handler
    /// </summary>
    class function OpenURL(const AURL: string): Boolean;
  end;

implementation

uses
  System.SysUtils

  {$IFDEF MSWINDOWS}
  , Winapi.Windows
  , Winapi.ShellAPI
  {$ENDIF}

  {$IFDEF MACOS}
  {$IFNDEF IOS}
  , Posix.Stdlib
  {$ELSE}
  , Macapi.Helpers
  , iOSapi.Foundation
  , FMX.Platform
  {$ENDIF}
  {$ENDIF}

  {$IFDEF LINUX}
  , Posix.Stdlib  
  {$ENDIF}

  {$IFDEF ANDROID}
  , Androidapi.JNI.GraphicsContentViewText
  , Androidapi.JNI.Net
  , Androidapi.JNI.App
  , Androidapi.Helpers
  , FMX.Platform.Android
  {$ENDIF}
  ;

{$IFDEF POSIX}
function QuoteShellArgPosix(const AValue: string): string;
begin
  Result := '''' + StringReplace(AValue, '''', '''"''"''', [rfReplaceAll]) + '''';
end;
{$ENDIF}

class function TIAM4DPlatformUtils.TryGetURIScheme(const AURL: string; out AScheme: string): Boolean;
var
  LColonPos: Integer;
  I: Integer;
begin
  Result := False;
  AScheme := '';

  LColonPos := Pos(':', AURL);
  if LColonPos <= 1 then
    Exit;

  AScheme := AURL.Substring(0, LColonPos - 1).ToLower;
  if not CharInSet(AScheme[1], ['a'..'z']) then
  begin
    AScheme := '';
    Exit;
  end;

  for I := 1 to Length(AScheme) do
    if not CharInSet(AScheme[I], ['a'..'z', '0'..'9', '+', '-', '.']) then
    begin
      AScheme := '';
      Exit;
    end;

  Result := True;
end;

class function TIAM4DPlatformUtils.OpenURL(const AURL: string): Boolean;
{$IFDEF MSWINDOWS}
var
  LResult: HINST;
{$ENDIF}
{$IFDEF MACOS}
{$IFNDEF IOS}
var
  LCommand: string;
{$ELSE}
var
  LNSUrl: NSUrl;
{$ENDIF}
{$ENDIF}
{$IFDEF LINUX}
var
  LCommand: string;
{$ENDIF}
{$IFDEF ANDROID}
var
  LIntent: JIntent;
{$ENDIF}
var
  LScheme: string;
begin
  Result := False;

  if AURL.Trim.IsEmpty then
    Exit;

  if not TIAM4DPlatformUtils.TryGetURIScheme(AURL, LScheme) then
    Exit;

  if (LScheme = 'file') or
     (LScheme = 'javascript') or
     (LScheme = 'data') then
    Exit;

  try
    {$IFDEF MSWINDOWS}
    LResult := ShellExecute(0, 'open', PChar(AURL), nil, nil, SW_SHOWNORMAL);
    Result := LResult > 32; 
    {$ENDIF}

    {$IFDEF MACOS}
    {$IFNDEF IOS}
    LCommand := 'open ' + QuoteShellArgPosix(AURL);
    Result := system(PAnsiChar(AnsiString(LCommand))) = 0;
    {$ELSE}
    LNSUrl := TNSUrl.Wrap(TNSUrl.OCClass.URLWithString(StrToNSStr(AURL)));
    if Assigned(LNSUrl) then
    begin
      if TOSVersion.Check(10) then
        TiOSHelper.SharedApplication.openURL(LNSUrl)
      else
        TiOSHelper.SharedApplication.openURL(LNSUrl);
      Result := True;
    end;
    {$ENDIF}
    {$ENDIF}

    {$IFDEF LINUX}
    LCommand := 'xdg-open ' + QuoteShellArgPosix(AURL);
    Result := system(PAnsiChar(AnsiString(LCommand))) = 0;
    {$ENDIF}

    {$IFDEF ANDROID}
    LIntent := TJIntent.JavaClass.init(TJIntent.JavaClass.ACTION_VIEW);
    LIntent.setData(StrToJURI(AURL));
    LIntent.setFlags(TJIntent.JavaClass.FLAG_ACTIVITY_NEW_TASK);
    TAndroidHelper.Activity.startActivity(LIntent);
    Result := True;
    {$ENDIF}

  except
    Result := False;
  end;
end;

end.
