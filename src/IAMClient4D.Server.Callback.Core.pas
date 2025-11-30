{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Server.Callback.Core.pas
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

unit IAMClient4D.Server.Callback.Core;

interface

uses
  System.SysUtils,
  IAMClient4D.Exceptions;

type
  /// <summary>
  /// Callback response type enumeration.
  /// </summary>
  TIAM4DCallbackResponseType = (crtCheckResponseIAM, crtOther);

  /// <summary>
  /// Customizable text content for OAuth2 callback HTML pages.
  /// </summary>
  TIAM4DCallbackPageTexts = record
    PageTitleIamCallback: string;
    PageTitleAuthError: string;
    PageTitleError: string;
    PageTitleAuthEndpoint: string;
    PageTitleAppListening: string;
    PageTitleNotFound: string;

    AuthSuccessHeading: string;
    AuthSuccessBody: string;

    AuthErrorHeading: string;
    AuthErrorBodyPrefix: string;
    CallbackHandlerNotSet: string;

    NotIamCallbackHeading: string;
    NotIamCallbackBody: string;
    AppListeningHeading: string;
    AppListeningBody: string;
    NotFoundBody: string;

    /// <summary>
    /// Creates default English text content for callback pages.
    /// </summary>
    class function CreateDefault: TIAM4DCallbackPageTexts; static;
  end;

  /// <summary>
  /// HTTP callback server interface for OAuth2 redirect handling.
  /// </summary>
  /// <remarks>
  /// Runs local HTTP server to receive OAuth2 authorization callbacks.
  /// Usage: Call Start before authorization flow, Stop when done.
  /// Handler: Set callback handler to process authorization codes.
  /// HTML pages: Customizable success/error pages shown to user after redirect.
  /// Thread-safety: Implementation should handle concurrent requests.
  /// </remarks>
  IIAM4DHttpCallbackServer = interface
    ['{0399FD00-0C1E-45DD-B470-302827620453}']
    /// <summary>
    /// Starts HTTP server on configured port.
    /// </summary>
    procedure Start;
    /// <summary>
    /// Stops HTTP server and releases port.
    /// </summary>
    procedure Stop;
    /// <summary>
    /// Returns true if server is running.
    /// </summary>
    function IsRunning: Boolean;
    /// <summary>
    /// Sets callback handler invoked when OAuth2 redirect is received.
    /// </summary>
    procedure SetCallbackHandler(const Handler: TProc<TIAM4DCallbackResponseType, string>);
    /// <summary>
    /// Returns HTML base page with title, heading, and body.
    /// </summary>
    function GetHtmlBasePage(const ATitle, AHeading, ABody: string; const AHeadingStyle: string = ''): string;
    /// <summary>
    /// Returns HTML page shown on successful authorization.
    /// </summary>
    function GetHtmlAuthSuccessPage: string;
    /// <summary>
    /// Returns HTML page shown on authorization error.
    /// </summary>
    function GetHtmlAuthErrorPage(const AErrorMessage: string): string;
    /// <summary>
    /// Returns HTML page shown when callback handler not configured.
    /// </summary>
    function GetHtmlCallbackHandlerNotSet: string;
    /// <summary>
    /// Returns HTML page shown for non-IAM callback requests.
    /// </summary>
    function GetHtmlNotIAMCallbackPage: string;
    /// <summary>
    /// Returns HTML page shown when server is listening.
    /// </summary>
    function GetHtmlAppListeningPage: string;
    /// <summary>
    /// Returns HTML page shown for 404 not found.
    /// </summary>
    function GetHtmlNotFoundPage: string;
    /// <summary>
    /// Returns current page text configuration.
    /// </summary>
    function GetPageTexts: TIAM4DCallbackPageTexts;
    /// <summary>
    /// Returns the actual port the server is listening on.
    /// </summary>
    function GetListeningPort: Word;

    property PageTexts: TIAM4DCallbackPageTexts read GetPageTexts;
  end;

implementation

{TCallbackPageTexts}

class function TIAM4DCallbackPageTexts.CreateDefault: TIAM4DCallbackPageTexts;
begin
  Result.PageTitleIamCallback := 'IAM Server callback';
  Result.PageTitleAuthError := 'Authentication Error';
  Result.PageTitleError := 'Error';
  Result.PageTitleAuthEndpoint := 'Authentication Endpoint';
  Result.PageTitleAppListening := 'Application Listening';
  Result.PageTitleNotFound := 'Page Not Found';

  Result.AuthSuccessHeading := 'Authorization Successful';
  Result.AuthSuccessBody := 'You can now close this browser window and return to the application.';

  Result.AuthErrorHeading := 'Authentication Error';
  Result.AuthErrorBodyPrefix := 'An issue occurred: ';
  Result.CallbackHandlerNotSet := 'Callback handler not set for IAM redirect.';

  Result.NotIamCallbackHeading := 'Authentication Endpoint';
  Result.NotIamCallbackBody := 'This URL is intended for IAM callbacks after an authentication flow. Please start the login process from the main application.';
  Result.AppListeningHeading := 'Your Application is Listening!';
  Result.AppListeningBody := 'Start the authentication flow.';
  Result.NotFoundBody := 'Page not found.';
end;

end.