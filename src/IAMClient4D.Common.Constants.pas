{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.Common.Constants.pas
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

unit IAMClient4D.Common.Constants;

interface

const
  // === Version (Semantic Versioning): IAM4D_VERSION_MAJOR >= 3 for code that needs this release ===
  IAM4D_VERSION_MAJOR = 3;
  IAM4D_VERSION_MINOR = 0;
  IAM4D_VERSION_PATCH = 0;
  IAM4D_VERSION = '3.0.0';

  // === General ===
  IAM4D_SECOND_PER_DAY = 86400;

  // === OAuth2 Parameters ===
  IAM4D_OAUTH2_PARAM_CLIENT_ID = 'client_id';
  IAM4D_OAUTH2_PARAM_CLIENT_SECRET = 'client_secret';
  IAM4D_OAUTH2_PARAM_REDIRECT_URI = 'redirect_uri';
  IAM4D_OAUTH2_PARAM_RESPONSE_TYPE = 'response_type';
  IAM4D_OAUTH2_PARAM_SCOPE = 'scope';
  IAM4D_OAUTH2_PARAM_STATE = 'state';
  // RFC 9207: issuer of the authorization response
  IAM4D_OAUTH2_PARAM_ISS = 'iss';
  IAM4D_OAUTH2_PARAM_NONCE = 'nonce';
  IAM4D_OAUTH2_PARAM_CODE = 'code';
  IAM4D_OAUTH2_PARAM_GRANT_TYPE = 'grant_type';
  IAM4D_OAUTH2_PARAM_REFRESH_TOKEN = 'refresh_token';
  IAM4D_OAUTH2_PARAM_CODE_VERIFIER = 'code_verifier';
  IAM4D_OAUTH2_PARAM_CODE_CHALLENGE = 'code_challenge';
  IAM4D_OAUTH2_PARAM_CODE_CHALLENGE_METHOD = 'code_challenge_method';
  IAM4D_OAUTH2_PARAM_LOGIN_HINT = 'login_hint';
  IAM4D_OAUTH2_PARAM_ID_TOKEN_HINT = 'id_token_hint';
  IAM4D_OAUTH2_PARAM_POST_LOGOUT_REDIRECT_URI = 'post_logout_redirect_uri';
  IAM4D_OAUTH2_PARAM_AUDIENCE = 'audience';
  IAM4D_OAUTH2_PARAM_USERNAME = 'username';
  IAM4D_OAUTH2_PARAM_PASSWORD = 'password';
  IAM4D_OAUTH2_PARAM_PROMPT = 'prompt';
  IAM4D_OAUTH2_PARAM_MAX_AGE = 'max_age';
  IAM4D_OAUTH2_PARAM_UI_LOCALES = 'ui_locales';
  // RFC 7009 token revocation
  IAM4D_OAUTH2_PARAM_TOKEN = 'token';
  IAM4D_OAUTH2_PARAM_TOKEN_TYPE_HINT = 'token_type_hint';
  IAM4D_OAUTH2_TOKEN_TYPE_HINT_ACCESS_TOKEN = 'access_token';
  IAM4D_OAUTH2_TOKEN_TYPE_HINT_REFRESH_TOKEN = 'refresh_token';
  IAM4D_OAUTH2_ERROR_UNSUPPORTED_TOKEN_TYPE = 'unsupported_token_type';

  // === OAuth2 error response keys (RFC 6749 section 5.2) ===
  IAM4D_OAUTH2_ERROR = 'error';
  IAM4D_OAUTH2_ERROR_DESCRIPTION = 'error_description';
  IAM4D_OAUTH2_ERROR_INVALID_GRANT = 'invalid_grant';

  // === OAuth2 Values ===
  IAM4D_OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE = 'authorization_code';
  IAM4D_OAUTH2_GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials';
  IAM4D_OAUTH2_GRANT_TYPE_REFRESH_TOKEN = 'refresh_token';
  IAM4D_OAUTH2_GRANT_TYPE_PASSWORD = 'password';
  IAM4D_OAUTH2_RESPONSE_TYPE_CODE = 'code';
  IAM4D_OAUTH2_SCOPE_OPENID = 'openid';
  IAM4D_OAUTH2_CODE_CHALLENGE_METHOD_S256 = 'S256';

  // === OAuth2 Callback Server Configuration ===
  IAM4D_OAUTH2_CALLBACK_DEFAULT_PATH = '/oauth2callback';

  // === OAuth2 Token JSON keys ===
  IAM4D_OAUTH2_TOKEN_ACCESS_TOKEN = 'access_token';
  IAM4D_OAUTH2_TOKEN_REFRESH_TOKEN = 'refresh_token';
  IAM4D_OAUTH2_TOKEN_ID_TOKEN = 'id_token';
  IAM4D_OAUTH2_TOKEN_EXPIRES_IN = 'expires_in';
  IAM4D_OAUTH2_TOKEN_REFRESH_EXPIRES_IN = 'refresh_expires_in';

  // === HTTP Headers ===
  IAM4D_HTTP_HEADER_AUTHORIZATION = 'Authorization';
  IAM4D_HTTP_HEADER_AUTHORIZATION_BEARER = 'Bearer ';

  // === HTTP Content Types ===
  IAM4D_CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded';

  // === OIDC Discovery Metadata Keys ===
  IAM4D_OIDC_METADATA_AUTHORIZATION_ENDPOINT = 'authorization_endpoint';
  IAM4D_OIDC_METADATA_TOKEN_ENDPOINT = 'token_endpoint';
  IAM4D_OIDC_METADATA_USERINFO_ENDPOINT = 'userinfo_endpoint';
  IAM4D_OIDC_METADATA_END_SESSION_ENDPOINT = 'end_session_endpoint';
  IAM4D_OIDC_METADATA_REVOCATION_ENDPOINT = 'revocation_endpoint';
  IAM4D_OIDC_METADATA_JWKS_URI = 'jwks_uri';
  IAM4D_OIDC_METADATA_ISSUER = 'issuer';
  // RFC 9207: the authorization response carries iss
  IAM4D_OIDC_METADATA_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED = 'authorization_response_iss_parameter_supported';

  IAM4D_TOKEN_ACCESS_TOKEN_EXPIRY = 'access_token_expiry';
  IAM4D_TOKEN_REFRESH_TOKEN_EXPIRY = 'refresh_token_expiry';
  IAM4D_TOKEN_GRANT_TYPE = 'grant_type';

  // === OAuth2 ACR Values Parameter ===
  IAM4D_OAUTH2_PARAM_ACR_VALUES = 'acr_values';

  // === RFC 8176 - Authentication Method Reference (AMR) Values ===
  IAM4D_AMR_PASSWORD = 'pwd';       // Password authentication
  IAM4D_AMR_USER_PRESENCE = 'user'; // User presence test (WebAuthn/Passkey)
  IAM4D_AMR_PIN = 'pin';            // Personal Identification Number
  IAM4D_AMR_FINGERPRINT = 'fpt';    // Fingerprint biometric
  IAM4D_AMR_HARDWARE_KEY = 'hwk';   // Hardware-secured key (e.g., YubiKey)
  IAM4D_AMR_SOFTWARE_KEY = 'swk';   // Software-secured key
  IAM4D_AMR_OTP = 'otp';            // One-time password
  IAM4D_AMR_MFA = 'mfa';            // Multi-factor authentication
  IAM4D_AMR_SMS = 'sms';            // SMS confirmation
  IAM4D_AMR_FACE = 'face';          // Facial recognition biometric
  IAM4D_AMR_RETINA = 'retina';      // Retina scan biometric
  IAM4D_AMR_VOICE = 'vbm';          // Voice biometric
  IAM4D_AMR_GEO = 'geo';            // Geolocation
  IAM4D_AMR_KBA = 'kba';            // Knowledge-based authentication

  // === Keycloak-specific ACR (Authentication Context Class Reference) Values ===
  IAM4D_ACR_PASSKEY = 'urn:keycloak:acr:passkey';
  IAM4D_ACR_2FA = 'urn:keycloak:acr:2fa';
  IAM4D_ACR_1FA = 'urn:keycloak:acr:1fa';

  // === Keycloak identity brokering ===
  // Alias of the identity provider Keycloak redirects to, skipping its login page
  IAM4D_KEYCLOAK_PARAM_IDP_HINT = 'kc_idp_hint';

  // === Keycloak application initiated actions ===
  // Required action to run after the login (e.g. UPDATE_PASSWORD) and its outcome in the callback
  IAM4D_KEYCLOAK_PARAM_KC_ACTION = 'kc_action';
  IAM4D_KEYCLOAK_PARAM_KC_ACTION_STATUS = 'kc_action_status';

  // === typ claim of Keycloak tokens (explicit typing, RFC 8725 3.11) ===
  IAM4D_KEYCLOAK_TOKEN_TYPE_BEARER = 'Bearer';
  IAM4D_KEYCLOAK_TOKEN_TYPE_ID = 'ID';

  // === Keycloak error_description of invalid_grant (Resource Owner Password Credentials) ===
  IAM4D_KEYCLOAK_ERROR_INVALID_USER_CREDENTIALS = 'Invalid user credentials';
  // A required action is pending (e.g. UPDATE_PASSWORD): the password was right
  IAM4D_KEYCLOAK_ERROR_ACCOUNT_NOT_FULLY_SET_UP = 'Account is not fully set up';
  IAM4D_KEYCLOAK_ERROR_ACCOUNT_DISABLED = 'Account disabled';
  // Not answered by Keycloak 26 to the direct grant: a brute force lock gives 'Invalid user
  // credentials' even for the right password. Kept for the versions that answer it
  IAM4D_KEYCLOAK_ERROR_ACCOUNT_TEMPORARILY_DISABLED = 'Account temporarily disabled';

implementation

end.