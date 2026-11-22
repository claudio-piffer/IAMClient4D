unit Calculator.Web.Engine;

{ Engine of the web client: TemplatePro views, static files, the CSRF check
  of the unsafe requests (token = HMAC of the session id, sent by HTMX in
  X-CSRF-Token), browser security headers and the HTML error page. }

interface

uses
  MVCFramework;

procedure ConfigureWebEngine(const AEngine: TMVCEngine);

implementation

uses
  System.SysUtils,
  System.IOUtils,
  MVCFramework.Commons,
  MVCFramework.Filters,
  MVCFramework.View.Renderers.TemplatePro,
  Calculator.Web.Settings,
  Calculator.Web.Formatting,
  Calculator.Web.Texts,
  Calculator.Web.Controllers.Base,
  Calculator.Web.Controllers.Public,
  Calculator.Web.Controllers.Auth,
  Calculator.Web.Controllers.Calculator,
  Calculator.Web.Controllers.Keypad,
  Calculator.Web.Controllers.Advanced,
  Calculator.Web.Controllers.Account;

const
  CDN = 'https://cdn.jsdelivr.net';
  STATIC_PREFIX = '/static';

// Only the CDN pinned (with SRI) in baselayout.html; no inline script or style,
// no eval (htmx: allowEval false, no hx-on)
function ContentSecurityPolicy: string;
begin
  Result := 'default-src ''self''; ' +
    'script-src ''self'' ' + CDN + '; ' +
    'style-src ''self'' ' + CDN + '; ' +
    'font-src ''self'' ' + CDN + '; ' +
    'img-src ''self'' data:; ' +
    'connect-src ''self''; ' +
    'form-action ''self''; ' +
    'frame-ancestors ''none''; ' +
    'base-uri ''none''; ' +
    'object-src ''none''';
end;

function BrowserSecurityHTTPFilter: TMVCHTTPFilter;
var
  LCSP: string;
  LSecure: Boolean;
begin
  LCSP := ContentSecurityPolicy;
  LSecure := Settings.CookieSecure;
  Result :=
    procedure(const AContext: TWebContext; const ANext: TMVCHTTPFilterNext)
    begin
      AContext.Response.SetCustomHeader('Content-Security-Policy', LCSP);
      AContext.Response.SetCustomHeader('X-Frame-Options', 'DENY');
      // not no-referrer: the browser would send "Origin: null" and the CSRF check refuses it
      AContext.Response.SetCustomHeader('Referrer-Policy', 'same-origin');
      AContext.Response.SetCustomHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
      if LSecure then
        AContext.Response.SetCustomHeader('Strict-Transport-Security', 'max-age=31536000');
      // Pages carry personal data: not in the browser cache (Back after the logout)
      if not AContext.Request.PathInfo.StartsWith(STATIC_PREFIX + '/') then
        AContext.Response.SetCustomHeader('Cache-Control', 'no-store');
      ANext();
    end;
end;

procedure ConfigureWebEngine(const AEngine: TMVCEngine);
var
  LViewPath: string;
  LOptions: TMVCExceptionHandlerOptions;
begin
  LViewPath := TPath.GetFullPath(TPath.Combine(Settings.WebRoot, 'templates'));
  if not TDirectory.Exists(LViewPath) then
    raise EDirectoryNotFoundException.CreateFmt('Templates not found in %s (CALC_WEB_ROOT)', [LViewPath]);
  ConfigureTemplatePro(LViewPath);
  LoadTexts(TPath.Combine(Settings.WebRoot, 'i18n'));
  AEngine.SetViewEngine(TMVCTemplateProViewEngine);

  // First: also the unsafe requests answered by the filters after it. GET /login and the
  // callback are safe requests, so no path is exempt
  AEngine.Use(CSRFHTTPFilter(Settings.CsrfSecret,
    function(AContext: TWebContext): string
    begin
      Result := AContext.Request.Cookie(SESSION_COOKIE);
    end));
  AEngine.Use(SecurityHeadersHTTPFilter());
  AEngine.Use(BrowserSecurityHTTPFilter());
  AEngine.Use(FileServerBundle(STATIC_PREFIX, TPath.Combine(Settings.WebRoot, 'www')));
  AEngine.Use(CompressionHTTPFilter(1024));
  AEngine.Use(LanguageHTTPFilter());

  AEngine.AddController(TPublicController);
  AEngine.AddController(TAuthController);
  AEngine.AddController(TCalculatorController);
  AEngine.AddController(TKeypadController);
  AEngine.AddController(TAdvancedController);
  AEngine.AddController(TAccountController);

  LOptions := [];
{$IFDEF DEBUG}
  LOptions := [ehShowDetails];
{$ENDIF}
  // templates/error.html for the browser; problem+json for the others
  AEngine.UseExceptionHandler('error', APP_NAME, LOptions);
end;

end.
