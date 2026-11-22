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

uses
  IAMClient4D.Core;

type
  /// <summary>
  /// Opens a URL in place of the default system handler; returns False if it cannot.
  /// </summary>
  TIAM4DOpenURLHandler = reference to function(const AURL: string): Boolean;

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
  private
    class var FOpenURLHandler: TIAM4DOpenURLHandler;
    class function GetOpenURLHandler: TIAM4DOpenURLHandler; static;
    class procedure SetOpenURLHandler(const AValue: TIAM4DOpenURLHandler); static;
  public
    /// <summary>
    /// Extracts URI scheme if present and syntactically valid
    /// </summary>
    class function TryGetURIScheme(const AURL: string; out AScheme: string): Boolean;

    /// <summary>
    /// Opens an http(s) URL with the default system handler, or OpenURLHandler when assigned
    /// </summary>
    /// <remarks>
    /// Other schemes return False: the system handler of an arbitrary scheme (file:, ms-*, custom
    /// protocol handlers) may run a program.
    /// </remarks>
    class function OpenURL(const AURL: string): Boolean;

    /// <summary>
    /// Replaces the default system handler in OpenURL (e.g. the browser of the login flow);
    /// nil (default) restores it.
    /// </summary>
    /// <remarks>
    /// For tests without a browser, embedded browsers or showing the URL on a headless machine.
    /// Process-wide: assign it before the first flow starts. The scheme check of OpenURL runs first
    /// (only http and https reach it); it runs on the thread calling OpenURL, and an
    /// exception raised by it makes OpenURL return False. Reading and assigning it is thread-safe.
    /// </remarks>
    class property OpenURLHandler: TIAM4DOpenURLHandler read GetOpenURLHandler write SetOpenURLHandler;

    /// <summary>
    /// Brings the app back to the user after the browser: flashes its taskbar button or takes the foreground
    /// </summary>
    /// <remarks>
    /// Windows only (other platforms and aaNone do nothing). The window is the first visible, unowned,
    /// non-tool top-level window of the process. aaForeground attaches the thread input to the foreground
    /// window to get around the focus-stealing prevention; if Windows refuses anyway the taskbar button
    /// flashes. Never raises: it must not break the login.
    /// </remarks>
    class procedure ActivateApplication(const AMode: TIAM4DAppActivation);
  end;

implementation

uses
  System.SysUtils
  , System.SyncObjs

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
  , iOSapi.UIKit
  , iOSapi.Helpers
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
  {$ENDIF}
  ;

var
  GOpenURLHandlerLock: TCriticalSection;

{$IFDEF MSWINDOWS}
type
  TAppWindowSearch = record
    ProcessId: DWORD;
    Window: HWND;
  end;
  PAppWindowSearch = ^TAppWindowSearch;

function FindAppWindowProc(AWindow: HWND; AParam: LPARAM): BOOL; stdcall;
var
  LSearch: PAppWindowSearch;
  LProcessId: DWORD;
begin
  Result := True;
  LSearch := PAppWindowSearch(AParam);
  GetWindowThreadProcessId(AWindow, @LProcessId);
  if (LProcessId = LSearch.ProcessId) and
     IsWindowVisible(AWindow) and
     (GetWindow(AWindow, GW_OWNER) = 0) and
     ((GetWindowLong(AWindow, GWL_EXSTYLE) and WS_EX_TOOLWINDOW) = 0) then
  begin
    LSearch.Window := AWindow;
    Result := False;
  end;
end;

function FindAppWindow: HWND;
var
  LSearch: TAppWindowSearch;
begin
  LSearch.ProcessId := GetCurrentProcessId;
  LSearch.Window := 0;
  EnumWindows(@FindAppWindowProc, LPARAM(@LSearch));
  Result := LSearch.Window;
end;

procedure FlashAppWindow(AWindow: HWND);
var
  LInfo: TFlashWInfo;
begin
  LInfo.cbSize := SizeOf(LInfo);
  LInfo.hwnd := AWindow;
  LInfo.dwFlags := FLASHW_TRAY or FLASHW_TIMERNOFG;
  LInfo.uCount := 0;
  LInfo.dwTimeout := 0;
  FlashWindowEx(LInfo);
end;

procedure ForegroundAppWindow(AWindow: HWND);
var
  LForegroundThread: DWORD;
  LThisThread: DWORD;
  LAttached: Boolean;
begin
  if IsIconic(AWindow) then
    ShowWindowAsync(AWindow, SW_RESTORE);

  LThisThread := GetCurrentThreadId;
  LForegroundThread := GetWindowThreadProcessId(GetForegroundWindow, nil);
  LAttached := (LForegroundThread <> 0) and (LForegroundThread <> LThisThread) and
    AttachThreadInput(LThisThread, LForegroundThread, True);
  try
    SetForegroundWindow(AWindow);
  finally
    if LAttached then
      AttachThreadInput(LThisThread, LForegroundThread, False);
  end;

  if GetForegroundWindow <> AWindow then
    FlashAppWindow(AWindow);
end;
{$ENDIF}

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

class function TIAM4DPlatformUtils.GetOpenURLHandler: TIAM4DOpenURLHandler;
begin
  GOpenURLHandlerLock.Acquire;
  try
    Result := FOpenURLHandler;
  finally
    GOpenURLHandlerLock.Release;
  end;
end;

class procedure TIAM4DPlatformUtils.SetOpenURLHandler(const AValue: TIAM4DOpenURLHandler);
begin
  GOpenURLHandlerLock.Acquire;
  try
    FOpenURLHandler := AValue;
  finally
    GOpenURLHandlerLock.Release;
  end;
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
  LHandler: TIAM4DOpenURLHandler;
begin
  Result := False;

  if AURL.Trim.IsEmpty then
    Exit;

  if not TIAM4DPlatformUtils.TryGetURIScheme(AURL, LScheme) then
    Exit;

  // Allow-list: the login opens the authorization endpoint only
  if not SameText(LScheme, 'https') and not SameText(LScheme, 'http') then
    Exit;

  // Own reference: another thread may replace the handler while it runs
  LHandler := GetOpenURLHandler();
  if Assigned(LHandler) then
  begin
    try
      Result := LHandler(AURL);
    except
      Result := False;
    end;
    Exit;
  end;

  try
    {$IFDEF MSWINDOWS}
    LResult := ShellExecute(0, 'open', PChar(AURL), nil, nil, SW_SHOWNORMAL);
    Result := LResult > 32; 
    {$ENDIF}

    {$IFDEF MACOS}
    {$IFNDEF IOS}
    LCommand := 'open ' + QuoteShellArgPosix(AURL);
    Result := _system(PAnsiChar(AnsiString(LCommand))) = 0;
    {$ELSE}
    LNSUrl := TNSUrl.Wrap(TNSUrl.OCClass.URLWithString(StrToNSStr(AURL)));
    if Assigned(LNSUrl) then
    begin
      // openURL: is deprecated (iOS 10) and ignored by recent versions: only the options variant opens the URL
      TiOSHelper.SharedApplication.openURL(LNSUrl, nil, nil);
      Result := True;
    end;
    {$ENDIF}
    {$ENDIF}

    {$IFDEF LINUX}
    LCommand := 'xdg-open ' + QuoteShellArgPosix(AURL);
    Result := _system(PAnsiChar(AnsiString(LCommand))) = 0;
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

class procedure TIAM4DPlatformUtils.ActivateApplication(const AMode: TIAM4DAppActivation);
{$IFDEF MSWINDOWS}
var
  LWindow: HWND;
{$ENDIF}
begin
  {$IFDEF MSWINDOWS}
  if AMode = aaNone then
    Exit;

  try
    LWindow := FindAppWindow;
    if LWindow = 0 then
      Exit;

    case AMode of
      aaFlash: FlashAppWindow(LWindow);
      aaForeground: ForegroundAppWindow(LWindow);
    end;
  except
    // best effort: the login goes on without it
  end;
  {$ENDIF}
end;

initialization
  GOpenURLHandlerLock := TCriticalSection.Create;

finalization
  FreeAndNil(GOpenURLHandlerLock);

end.
