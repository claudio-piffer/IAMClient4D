{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Admin.Keycloak.Constants.pas
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

  Constants shared by the Keycloak Admin REST API clients (users, identity
  providers). IAMClient4D.UserManagement.Constants re-declares them.

  ---------------------------------------------------------------------------
}

unit IAMClient4D.Admin.Keycloak.Constants;

interface

const
  /// <summary>HTTP status code: OK (successful GET, PUT).</summary>
  IAM4D_HTTP_STATUS_OK = 200;
  /// <summary>HTTP status code: Created (successful POST with resource creation).</summary>
  IAM4D_HTTP_STATUS_CREATED = 201;
  /// <summary>HTTP status code: No Content (successful DELETE or PUT without response body).</summary>
  IAM4D_HTTP_STATUS_NO_CONTENT = 204;
  /// <summary>HTTP status code: Bad Request.</summary>
  IAM4D_HTTP_STATUS_BAD_REQUEST = 400;
  /// <summary>HTTP status code: Not Found (resource doesn't exist).</summary>
  IAM4D_HTTP_STATUS_NOT_FOUND = 404;

  /// <summary>HTTP method: GET</summary>
  IAM4D_HTTP_METHOD_GET = 'GET';
  /// <summary>HTTP method: POST</summary>
  IAM4D_HTTP_METHOD_POST = 'POST';
  /// <summary>HTTP method: PUT</summary>
  IAM4D_HTTP_METHOD_PUT = 'PUT';
  /// <summary>HTTP method: DELETE</summary>
  IAM4D_HTTP_METHOD_DELETE = 'DELETE';

  /// <summary>JSON content type for HTTP requests.</summary>
  IAM4D_CONTENT_TYPE_JSON = 'application/json';

  /// <summary>Maximum length for error message preview in exceptions.</summary>
  IAM4D_MAX_ERROR_PREVIEW_LENGTH = 500;

  /// <summary>Default pagination page size for search and list operations (Keycloak default max).</summary>
  IAM4D_DEFAULT_PAGE_SIZE = 100;
  /// <summary>Default first result index for pagination (zero-based).</summary>
  IAM4D_DEFAULT_FIRST_RESULT = 0;

implementation

end.
