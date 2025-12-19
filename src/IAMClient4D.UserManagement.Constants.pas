{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.UserManagement.Constants.pas
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

unit IAMClient4D.UserManagement.Constants;

interface

const
  /// <summary>
  /// Empty user ID constant to indicate missing or invalid user.
  /// </summary>
  IAM4D_EMPTY_USER_ID = '';

  /// <summary>
  /// Default pagination page size for search and list operations.
  /// </summary>
  IAM4D_DEFAULT_PAGE_SIZE = 100;

  /// <summary>
  /// Default first result index for pagination (zero-based).
  /// </summary>
  IAM4D_DEFAULT_FIRST_RESULT = 0;

  /// <summary>
  /// Minimum password length required by the library.
  /// Note: Keycloak may have additional password policies configured.
  /// </summary>
  IAM4D_MIN_PASSWORD_LENGTH = 8;

  /// <summary>
  /// Maximum password length to prevent DoS attacks.
  /// </summary>
  IAM4D_MAX_PASSWORD_LENGTH = 4096;

  /// <summary>
  /// Minimum username length.
  /// </summary>
  IAM4D_MIN_USERNAME_LENGTH = 3;

  /// <summary>
  /// Maximum username length.
  /// </summary>
  IAM4D_MAX_USERNAME_LENGTH = 255;

  /// <summary>
  /// Maximum email length (RFC 5321).
  /// </summary>
  IAM4D_MAX_EMAIL_LENGTH = 320;

  /// <summary>
  /// HTTP status code: OK (successful GET, PUT).
  /// </summary>
  IAM4D_HTTP_STATUS_OK = 200;

  /// <summary>
  /// HTTP status code: Created (successful POST with resource creation).
  /// </summary>
  IAM4D_HTTP_STATUS_CREATED = 201;

  /// <summary>
  /// HTTP status code: No Content (successful DELETE or PUT without response body).
  /// </summary>
  IAM4D_HTTP_STATUS_NO_CONTENT = 204;

  /// <summary>
  /// HTTP status code: Not Found (resource doesn't exist).
  /// </summary>
  IAM4D_HTTP_STATUS_NOT_FOUND = 404;

  /// <summary>
  /// Maximum length for error message preview in exceptions.
  /// </summary>
  IAM4D_MAX_ERROR_PREVIEW_LENGTH = 500;

  /// <summary>
  /// Email validation regex pattern (RFC 5322 simplified).
  /// Validates: user@domain.tld format with common characters.
  /// </summary>
  IAM4D_EMAIL_REGEX_PATTERN = '^[a-zA-Z0-9.!#$%&''*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$';

  /// <summary>
  /// Username validation regex pattern.
  /// Allows: letters, numbers, underscore, hyphen, dot.
  /// </summary>
  IAM4D_USERNAME_REGEX_PATTERN = '^[a-zA-Z0-9._-]+$';

  /// <summary>
  /// JSON content type for HTTP requests.
  /// </summary>
  IAM4D_CONTENT_TYPE_JSON = 'application/json';

  /// <summary>
  /// HTTP method: GET
  /// </summary>
  IAM4D_HTTP_METHOD_GET = 'GET';

  /// <summary>
  /// HTTP method: POST
  /// </summary>
  IAM4D_HTTP_METHOD_POST = 'POST';

  /// <summary>
  /// HTTP method: PUT
  /// </summary>
  IAM4D_HTTP_METHOD_PUT = 'PUT';

  /// <summary>
  /// HTTP method: DELETE
  /// </summary>
  IAM4D_HTTP_METHOD_DELETE = 'DELETE';

  /// <summary>
  /// Minimum batch size for bulk operations (must have at least 1 item).
  /// </summary>
  IAM4D_MIN_BATCH_SIZE = 1;

  /// <summary>
  /// Maximum batch size for bulk operations to prevent memory issues.
  /// Recommended to keep batches under 1000 items for optimal performance.
  /// </summary>
  IAM4D_MAX_BATCH_SIZE = 1000;

  /// <summary>
  /// Error message used when a batch operation is cancelled.
  /// </summary>
  IAM4D_OPERATION_CANCELLED = 'Operation cancelled';

implementation

end.