unit Calculator.Presentation.SwaggerUI;

{ Presentation layer, shared by both servers: Swagger UI page for the
  OpenAPI document. The assets come from a CDN, pinned and checked with
  Subresource Integrity. The token is pasted in the "Authorize" dialog: the
  bearer scheme is added to the document by the IAMClient4D filters
  (IAM4DJWTBundle or IAM4DSwaggerSecurityHTTPFilter). }

interface

uses
  MVCFramework;

/// <summary>
/// Serves the Swagger UI page on GET APath and redirects GET / there.
/// </summary>
function SwaggerUIHTTPFilter(const ATitle, ADocumentURL: string;
  const APath: string = '/swagger'): TMVCHTTPFilter;

implementation

uses
  System.SysUtils,
  System.Classes,
  System.NetEncoding,
  MVCFramework.Commons;

const
  SWAGGER_UI_CDN = 'https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/';
  SWAGGER_UI_CSS_SRI = 'sha384-wxLW6kwyHktdDGr6Pv1zgm/VGJh99lfUbzSn6HNHBENZlCN7W602k9VkGdxuFvPn';
  SWAGGER_UI_JS_SRI = 'sha384-wmyclcVGX/WhUkdkATwhaK1X1JtiNrr2EoYJ+diV3vj4v6OC5yCeSu+yW13SYJep';

  PAGE =
    '<!doctype html>' + sLineBreak +
    '<html lang="en">' + sLineBreak +
    '<head>' + sLineBreak +
    '  <meta charset="utf-8">' + sLineBreak +
    '  <meta name="viewport" content="width=device-width, initial-scale=1">' + sLineBreak +
    '  <title>{title}</title>' + sLineBreak +
    '  <link rel="stylesheet" href="' + SWAGGER_UI_CDN + 'swagger-ui.css"' + sLineBreak +
    '        integrity="' + SWAGGER_UI_CSS_SRI + '" crossorigin="anonymous">' + sLineBreak +
    '</head>' + sLineBreak +
    '<body>' + sLineBreak +
    '  <div id="swagger-ui"></div>' + sLineBreak +
    '  <script src="' + SWAGGER_UI_CDN + 'swagger-ui-bundle.js"' + sLineBreak +
    '          integrity="' + SWAGGER_UI_JS_SRI + '" crossorigin="anonymous"></script>' + sLineBreak +
    '  <script>' + sLineBreak +
    '    window.onload = function () {' + sLineBreak +
    '      SwaggerUIBundle({ url: "{document}", dom_id: "#swagger-ui", deepLinking: true });' + sLineBreak +
    '    };' + sLineBreak +
    '  </script>' + sLineBreak +
    '</body>' + sLineBreak +
    '</html>' + sLineBreak;

function SwaggerUIHTTPFilter(const ATitle, ADocumentURL, APath: string): TMVCHTTPFilter;
var
  LPage: string;
begin
  // Built once: title and URL come from the code, escaped anyway
  // (the URL is a JavaScript string: no HTML entities inside <script>)
  LPage := PAGE
    .Replace('{title}', TNetEncoding.HTML.Encode(ATitle))
    .Replace('{document}', ADocumentURL.Replace('\', '\\').Replace('"', '\"').Replace('<', '<'));
  Result :=
    procedure(const AContext: TWebContext; const ANext: TMVCHTTPFilterNext)
    var
      LPathInfo: string;
    begin
      LPathInfo := AContext.Request.PathInfo;
      if AContext.Request.HTTPMethod <> httpGET then
      begin
        ANext();
        Exit;
      end;
      if (LPathInfo = '') or (LPathInfo = '/') then
      begin
        AContext.Response.StatusCode := HTTP_STATUS.Found;
        AContext.Response.Location := APath;
        Exit;
      end;
      if SameText(LPathInfo, APath) or SameText(LPathInfo, APath + '/') then
      begin
        AContext.Response.SetContentStream(TStringStream.Create(LPage, TEncoding.UTF8),
          BuildContentType(TMVCMediaType.TEXT_HTML, TMVCCharSet.UTF_8));
        Exit;
      end;
      ANext();
    end;
end;

end.
