{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.FMX.AppRedirect.pas
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

unit IAMClient4D.FMX.AppRedirect;

interface

uses
  System.SysUtils;

type
  /// <summary>
  /// Called with every URL the app receives on its scheme: ATaken is False if the login did not take it
  /// (no login waiting, other state): it was ignored.
  /// </summary>
  /// <remarks>The URL holds the authorization code and state: do not log it as it is.</remarks>
  TIAM4DAppRedirectNotify = reference to procedure(const AURL: string; const ATaken: Boolean);

  /// <summary>
  /// How the login page opens on iOS.
  /// </summary>
  /// <remarks>
  /// ilbSafari: in Safari, the redirect comes back through the URL scheme of the app (default).
  /// ilbAuthenticationSession: in an ASWebAuthenticationSession (RFC 8252 B.1): the redirect goes to
  /// the session of this app only, not to any app that registers the same scheme, and the user does
  /// not leave the app. Shares the Safari cookies (single sign-on). Falls back to Safari when the
  /// session cannot start.
  /// </remarks>
  TIAM4DIOSLoginBrowser = (
    ilbSafari,

    ilbAuthenticationSession);

  /// <summary>
  /// Passes the URLs that the operating system hands to the app to TIAM4DAppRedirect.HandleURL, and opens
  /// the login page of the mobile app in the browser.
  /// </summary>
  /// <remarks>
  /// Android: the intent filter of the manifest (ACTION_VIEW on the scheme of the redirect URI) starts or
  /// resumes the main activity; the page opens in a Custom Tab (androidx.browser, falls back to the
  /// browser), without a new task, so that the redirect closes the tab when the activity is singleTask.
  /// iOS: TApplicationEvent.OpenURL (CFBundleURLTypes of the info.plist); the page opens in Safari
  /// (TIAM4DPlatformUtils.OpenURL), or in an ASWebAuthenticationSession (AIOSLoginBrowser), which hands
  /// the redirect straight to the app. Windows, macOS and other platforms: Install does nothing.
  ///
  /// The open URL handler of TIAM4DPlatformUtils is process-wide: Install replaces it, Uninstall restores
  /// the previous one. All methods run on the main thread.
  /// </remarks>
  TIAM4DAppRedirectListener = class
  public
    /// <summary>
    /// Starts to listen. Call it once at startup (e.g. in FormCreate).
    /// </summary>
    /// <param name="AOnURL">Optional: called (main thread) with every URL received and whether it was taken</param>
    /// <param name="AUseCustomTabs">Android: opens the pages in a Custom Tab instead of the default way</param>
    /// <param name="AIOSLoginBrowser">iOS: Safari (default) or ASWebAuthenticationSession</param>
    class procedure Install(const AOnURL: TIAM4DAppRedirectNotify = nil;
      const AUseCustomTabs: Boolean = True;
      const AIOSLoginBrowser: TIAM4DIOSLoginBrowser = ilbSafari); static;

    /// <summary>
    /// Stops listening and restores the previous open URL handler
    /// </summary>
    class procedure Uninstall; static;

    /// <summary>
    /// Opens a URL in a Custom Tab (Android). Falls back to the browser if Custom Tabs are not available.
    /// False on the other platforms.
    /// </summary>
    class function OpenInCustomTab(const AURL: string): Boolean; static;
  end;

implementation

uses
  System.Classes,
  System.Messaging,
  {$IFDEF ANDROID}
  Androidapi.Helpers,
  Androidapi.JNIBridge,
  Androidapi.JNI.JavaTypes,
  Androidapi.JNI.GraphicsContentViewText,
  Androidapi.JNI.Net,
  Androidapi.JNI.App,
  FMX.Platform.Android,
  IAMClient4D.Androidapi.CustomTabs,
  {$ENDIF}
  {$IFDEF IOS}
  Posix.Dlfcn,
  System.Net.URLClient,
  Macapi.ObjectiveC,
  Macapi.Helpers,
  iOSapi.Foundation,
  iOSapi.UIKit,
  iOSapi.Helpers,
  FMX.Platform,
  FMX.Platform.iOS,
  {$ENDIF}
  IAMClient4D.Common.PlatformUtils,
  IAMClient4D.Callback.Handler.AppRedirect;

{$IFDEF IOS}
// AuthenticationServices is not in the iOS SDK that RAD Studio imports by default: the framework is
// loaded with dlopen and its classes are found by name, no link-time dependency
const
  LIB_AUTHENTICATION_SERVICES = '/System/Library/Frameworks/AuthenticationServices.framework/AuthenticationServices';

type
  ASWebAuthenticationSession = interface;

  TASWebAuthenticationSessionCompletionHandler = procedure(callbackURL: NSURL; error: NSError) of object;

  ASWebAuthenticationPresentationContextProviding = interface(IObjectiveC)
    ['{6ACB2D76-6CEA-45AC-A202-2E7E73904D00}']
    function presentationAnchorForWebAuthenticationSession(session: ASWebAuthenticationSession): UIWindow; cdecl;
  end;

  ASWebAuthenticationSessionClass = interface(NSObjectClass)
    ['{B8E0298F-5C11-43CA-AAB5-99644BAA0907}']
  end;

  ASWebAuthenticationSession = interface(NSObject)
    ['{9770E638-E724-457D-9A1C-D4B0DBA0E7D0}']
    function initWithURL(URL: NSURL; callbackURLScheme: NSString;
      completionHandler: TASWebAuthenticationSessionCompletionHandler): Pointer; cdecl;
    procedure setPresentationContextProvider(presentationContextProvider: Pointer); cdecl;
    procedure setPrefersEphemeralWebBrowserSession(prefersEphemeralWebBrowserSession: Boolean); cdecl;
    function start: Boolean; cdecl;
    procedure cancel; cdecl;
  end;

  TASWebAuthenticationSession = class(TOCGenericImport<ASWebAuthenticationSessionClass, ASWebAuthenticationSession>)
  end;

  /// <summary>Window the session is presented on: the key window of the app</summary>
  TPresentationProvider = class(TOCLocal, ASWebAuthenticationPresentationContextProviding)
  public
    function presentationAnchorForWebAuthenticationSession(session: ASWebAuthenticationSession): UIWindow; cdecl;
  end;
{$ENDIF}

type
  TListener = class
  private
    FOnURL: TIAM4DAppRedirectNotify;
    FPreviousHandler: TIAM4DOpenURLHandler;
    FHandlerReplaced: Boolean;
    {$IF Defined(ANDROID) or Defined(IOS)}
    FSubscriptionId: TMessageSubscriptionId;
    FSubscribed: Boolean;
    {$ENDIF}
    FStopped: Boolean;
    {$IFDEF IOS}
    FSession: ASWebAuthenticationSession;
    // Incremented by each session: a queued release does not touch a newer one
    FSessionSerial: Integer;
    FProvider: TPresentationProvider;
    {$ENDIF}
    {$IF Defined(ANDROID) or Defined(IOS)}
    procedure Deliver(const AURL: string);
    {$ENDIF}
    {$IFDEF ANDROID}
    procedure HandleIntentMessage(const Sender: TObject; const M: TMessage);
    procedure ProcessIntent(const AIntent: JIntent);
    procedure CheckLaunchIntent;
    {$ENDIF}
    {$IFDEF IOS}
    procedure HandleApplicationEvent(const Sender: TObject; const M: TMessage);
    function StartAuthenticationSession(const AURL: string): Boolean;
    procedure SessionCompleted(callbackURL: NSURL; error: NSError);
    procedure ReleaseSession;
    {$ENDIF}
  public
    constructor Create(const AOnURL: TIAM4DAppRedirectNotify; const AUseCustomTabs: Boolean;
      const AIOSLoginBrowser: TIAM4DIOSLoginBrowser);
    destructor Destroy; override;
  end;

var
  GListener: TListener;

{$IFDEF ANDROID}
/// <summary>ACTION_VIEW from the activity: no new task, so that the redirect closes the page</summary>
function OpenWithView(const AURL: string): Boolean;
var
  LIntent: JIntent;
begin
  LIntent := TJIntent.JavaClass.init(TJIntent.JavaClass.ACTION_VIEW);
  LIntent.setData(StrToJURI(AURL));
  TAndroidHelper.Activity.startActivity(LIntent);
  Result := True;
end;

function LaunchCustomTab(const AURL: string): Boolean;
var
  LBuilder: JCustomTabsIntent_Builder;
  LTabs: JCustomTabsIntent;
begin
  try
    LBuilder := TJCustomTabsIntent_Builder.JavaClass.init;
    LBuilder.setShowTitle(True);
    LTabs := LBuilder.build;
    // The activity as the context: the tab joins the task of the app and the redirect closes it
    LTabs.launchUrl(TAndroidHelper.Activity, StrToJURI(AURL));
    Result := True;
  except
    on EJNIException do
      // androidx.browser is not in the package, or the call failed
      Result := OpenWithView(AURL);
  end;
end;

function IsWebURL(const AURL: string): Boolean;
begin
  Result := AURL.StartsWith('http://', True) or AURL.StartsWith('https://', True);
end;

function OpenOnMainThread(const AURL: string; const AWebAsCustomTab: Boolean): Boolean;
var
  LResult: Boolean;
begin
  LResult := False;
  try
    if TThread.CurrentThread.ThreadID = MainThreadID then
    begin
      if AWebAsCustomTab and IsWebURL(AURL) then
        LResult := LaunchCustomTab(AURL)
      else
        LResult := OpenWithView(AURL);
    end
    else
      TThread.Synchronize(nil,
        procedure
        begin
          if AWebAsCustomTab and IsWebURL(AURL) then
            LResult := LaunchCustomTab(AURL)
          else
            LResult := OpenWithView(AURL);
        end);
  except
    LResult := False;
  end;
  Result := LResult;
end;
{$ENDIF}

{$IFDEF IOS}
{ TPresentationProvider }

function TPresentationProvider.presentationAnchorForWebAuthenticationSession(
  session: ASWebAuthenticationSession): UIWindow;
begin
  Result := TiOSHelper.SharedApplication.keyWindow;
end;

/// <summary>Scheme of the redirect_uri of an authorization URL ('' if none)</summary>
function RedirectSchemeOf(const AURL: string): string;
var
  LRedirect: string;
  LColon: Integer;
begin
  Result := '';
  try
    LRedirect := TURI.Create(AURL).ParameterByName['redirect_uri'];
  except
    Exit;
  end;
  LColon := Pos(':', LRedirect);
  if LColon > 1 then
    Result := Copy(LRedirect, 1, LColon - 1);
  // A web redirect is not for the session: it waits for a custom scheme
  if SameText(Result, 'http') or SameText(Result, 'https') then
    Result := '';
end;

/// <summary>What TIAM4DPlatformUtils.OpenURL does on iOS without a handler</summary>
function OpenInSafari(const AURL: string): Boolean;
var
  LURL: NSURL;
begin
  LURL := TNSURL.Wrap(TNSURL.OCClass.URLWithString(StrToNSStr(AURL)));
  Result := Assigned(LURL);
  if Result then
    TiOSHelper.SharedApplication.openURL(LURL, nil, nil);
end;

var
  GAuthServicesLoaded: Integer; // 0: not tried, 1: loaded, -1: not available

function AuthenticationServicesAvailable: Boolean;
begin
  if GAuthServicesLoaded = 0 then
  begin
    if dlopen(MarshaledAString(LIB_AUTHENTICATION_SERVICES), RTLD_LAZY) <> 0 then
      GAuthServicesLoaded := 1
    else
      GAuthServicesLoaded := -1;
  end;
  Result := GAuthServicesLoaded = 1;
end;
{$ENDIF}

{ TListener }

constructor TListener.Create(const AOnURL: TIAM4DAppRedirectNotify; const AUseCustomTabs: Boolean;
  const AIOSLoginBrowser: TIAM4DIOSLoginBrowser);
{$IF Defined(ANDROID) or Defined(IOS)}
var
  LSelf: TListener;
{$ENDIF}
begin
  inherited Create;
  FOnURL := AOnURL;

  {$IFDEF ANDROID}
  if AUseCustomTabs then
  begin
    FPreviousHandler := TIAM4DPlatformUtils.OpenURLHandler;
    FHandlerReplaced := True;
    TIAM4DPlatformUtils.OpenURLHandler :=
      function(const AURL: string): Boolean
      begin
        Result := OpenOnMainThread(AURL, True);
      end;
  end;

  FSubscriptionId := TMessageManager.DefaultManager.SubscribeToMessage(TMessageReceivedNotification,
    HandleIntentMessage);
  FSubscribed := True;
  MainActivity.registerIntentAction(TJIntent.JavaClass.ACTION_VIEW);

  // The intent that started the app (cold start from the redirect): the form must exist first
  LSelf := Self;
  TThread.ForceQueue(nil,
    procedure
    begin
      // Uninstall may have run meanwhile
      if GListener = LSelf then
        LSelf.CheckLaunchIntent;
    end);
  {$ENDIF}

  {$IFDEF IOS}
  if AIOSLoginBrowser = ilbAuthenticationSession then
  begin
    FPreviousHandler := TIAM4DPlatformUtils.OpenURLHandler;
    FHandlerReplaced := True;
    LSelf := Self;
    TIAM4DPlatformUtils.OpenURLHandler :=
      function(const AURL: string): Boolean
      var
        LResult: Boolean;
      begin
        LResult := False;
        // UIKit: main thread only
        System.Classes.TThread.Synchronize(nil,
          procedure
          begin
            if GListener = LSelf then
              LResult := LSelf.StartAuthenticationSession(AURL);
          end);
        if not LResult then
          // Not an authorization URL with a custom scheme, or no session: Safari as before
          if Assigned(LSelf.FPreviousHandler) then
            LResult := LSelf.FPreviousHandler(AURL)
          else
            System.Classes.TThread.Synchronize(nil,
              procedure
              begin
                LResult := OpenInSafari(AURL);
              end);
        Result := LResult;
      end;
  end;

  FSubscriptionId := TMessageManager.DefaultManager.SubscribeToMessage(TApplicationEventMessage,
    HandleApplicationEvent);
  FSubscribed := True;
  {$ENDIF}
end;

destructor TListener.Destroy;
begin
  FStopped := True;
  {$IFDEF ANDROID}
  if FSubscribed then
    TMessageManager.DefaultManager.Unsubscribe(TMessageReceivedNotification, FSubscriptionId);
  {$ENDIF}
  {$IFDEF IOS}
  if FSubscribed then
    TMessageManager.DefaultManager.Unsubscribe(TApplicationEventMessage, FSubscriptionId);
  if Assigned(FSession) then
    FSession.cancel;
  ReleaseSession;
  FProvider.Free;
  {$ENDIF}
  if FHandlerReplaced then
    TIAM4DPlatformUtils.OpenURLHandler := FPreviousHandler;
  inherited;
end;

{$IF Defined(ANDROID) or Defined(IOS)}
procedure TListener.Deliver(const AURL: string);
var
  LTaken: Boolean;
begin
  if FStopped or AURL.IsEmpty then
    Exit;
  LTaken := TIAM4DAppRedirect.HandleURL(AURL);
  if Assigned(FOnURL) then
    FOnURL(AURL, LTaken);
end;
{$ENDIF}

{$IFDEF ANDROID}
procedure TListener.ProcessIntent(const AIntent: JIntent);
begin
  if (AIntent <> nil) and (AIntent.getAction <> nil) and
    (JStringToString(AIntent.getAction) = JStringToString(TJIntent.JavaClass.ACTION_VIEW)) and
    (AIntent.getDataString <> nil) then
    Deliver(JStringToString(AIntent.getDataString));
end;

procedure TListener.HandleIntentMessage(const Sender: TObject; const M: TMessage);
begin
  if M is TMessageReceivedNotification then
    ProcessIntent(TMessageReceivedNotification(M).Value);
end;

procedure TListener.CheckLaunchIntent;
begin
  if not FStopped then
    ProcessIntent(TAndroidHelper.Activity.getIntent);
end;
{$ENDIF}

{$IFDEF IOS}
procedure TListener.HandleApplicationEvent(const Sender: TObject; const M: TMessage);
var
  LData: TApplicationEventData;
begin
  if M is TApplicationEventMessage then
  begin
    LData := TApplicationEventMessage(M).Value;
    if (LData.Event = TApplicationEvent.OpenURL) and (LData.Context is TiOSOpenApplicationContext) then
      Deliver(TiOSOpenApplicationContext(LData.Context).URL);
  end;
end;

function TListener.StartAuthenticationSession(const AURL: string): Boolean;
var
  LScheme: string;
  LURL: NSURL;
begin
  Result := False;
  LScheme := RedirectSchemeOf(AURL);
  if LScheme.IsEmpty or not AuthenticationServicesAvailable then
    Exit;

  // One login at a time: a new one replaces the session still open
  if Assigned(FSession) then
    FSession.cancel;
  ReleaseSession;

  LURL := TNSURL.Wrap(TNSURL.OCClass.URLWithString(StrToNSStr(AURL)));
  if LURL = nil then
    Exit;
  // alloc + init: this object owns the session (released in ReleaseSession)
  Inc(FSessionSerial);
  FSession := TASWebAuthenticationSession.Wrap(
    TASWebAuthenticationSession.Alloc.initWithURL(LURL, StrToNSStr(LScheme), SessionCompleted));
  if FSession = nil then
    Exit;
  if FProvider = nil then
    FProvider := TPresentationProvider.Create;
  FSession.setPresentationContextProvider(FProvider.GetObjectID);
  // Shares the Safari cookies: single sign-on with the browser
  FSession.setPrefersEphemeralWebBrowserSession(False);
  Result := FSession.start;
  if not Result then
    ReleaseSession;
end;

procedure TListener.SessionCompleted(callbackURL: NSURL; error: NSError);
var
  LURL: string;
  LSelf: TListener;
  LSerial: Integer;
begin
  // Main thread. No callback URL: the user closed the page, or the session failed; the login stays
  // pending as with Safari, the app cancels it
  if callbackURL <> nil then
    LURL := NSStrToStr(callbackURL.absoluteString)
  else
    LURL := '';
  // The session is released after its completion handler returns
  LSelf := Self;
  LSerial := FSessionSerial;
  System.Classes.TThread.ForceQueue(nil,
    procedure
    begin
      if (GListener = LSelf) and (LSelf.FSessionSerial = LSerial) then
        LSelf.ReleaseSession;
    end);
  if not LURL.IsEmpty then
    Deliver(LURL);
end;

procedure TListener.ReleaseSession;
begin
  if Assigned(FSession) then
  begin
    FSession.release;
    FSession := nil;
  end;
end;
{$ENDIF}

{ TIAM4DAppRedirectListener }

class procedure TIAM4DAppRedirectListener.Install(const AOnURL: TIAM4DAppRedirectNotify;
  const AUseCustomTabs: Boolean; const AIOSLoginBrowser: TIAM4DIOSLoginBrowser);
begin
  Uninstall;
  GListener := TListener.Create(AOnURL, AUseCustomTabs, AIOSLoginBrowser);
end;

class procedure TIAM4DAppRedirectListener.Uninstall;
begin
  FreeAndNil(GListener);
end;

class function TIAM4DAppRedirectListener.OpenInCustomTab(const AURL: string): Boolean;
begin
  {$IFDEF ANDROID}
  Result := OpenOnMainThread(AURL, True);
  {$ELSE}
  Result := False;
  {$ENDIF}
end;

initialization

finalization
  FreeAndNil(GListener);

end.
