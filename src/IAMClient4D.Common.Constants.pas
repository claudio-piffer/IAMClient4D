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
  // === General ===
  IAM4D_SECOND_PER_DAY = 86400;

  // === OAuth2 Parameters ===
  IAM4D_OAUTH2_PARAM_CLIENT_ID = 'client_id';
  IAM4D_OAUTH2_PARAM_CLIENT_SECRET = 'client_secret';
  IAM4D_OAUTH2_PARAM_REDIRECT_URI = 'redirect_uri';
  IAM4D_OAUTH2_PARAM_RESPONSE_TYPE = 'response_type';
  IAM4D_OAUTH2_PARAM_SCOPE = 'scope';
  IAM4D_OAUTH2_PARAM_STATE = 'state';
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

  // === OAuth2 Values ===
  IAM4D_OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE = 'authorization_code';
  IAM4D_OAUTH2_GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials';
  IAM4D_OAUTH2_GRANT_TYPE_REFRESH_TOKEN = 'refresh_token';
  IAM4D_OAUTH2_RESPONSE_TYPE_CODE = 'code';
  IAM4D_OAUTH2_SCOPE_OPENID = 'openid';
  IAM4D_OAUTH2_CODE_CHALLENGE_METHOD_S256 = 'S256';

  // === OAuth2 Callback Server Configuration ===
  IAM4D_OAUTH2_CALLBACK_PORT_MIN = 8000;
  IAM4D_OAUTH2_CALLBACK_PORT_MAX = 8020;
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
  IAM4D_OIDC_METADATA_JWKS_URI = 'jwks_uri';
  IAM4D_OIDC_METADATA_ISSUER = 'issuer';

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

implementation

end.