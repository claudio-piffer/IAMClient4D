{
  ---------------------------------------------------------------------------
  Unit Name  : IAMClient4D.IdentityProvider.Builders.pas
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

  Fluent builders that fill a TIAM4DIdentityProvider for a specific broker:
  - Any OpenID Connect provider: Keycloak provider 'oidc' (Okta, Auth0, ADFS, Ping, another Keycloak...).
  - Any SAML 2.0 provider: Keycloak provider 'saml' (ADFS, Okta, Google Workspace, Shibboleth...).
  - Any OAuth 2.0 provider that is not OpenID Connect: Keycloak provider 'oauth2'.
  - Microsoft Entra ID: Keycloak OpenID Connect provider ('oidc').
  - Google, Facebook, Microsoft (personal accounts), LinkedIn, GitHub and GitLab: Keycloak social providers
    'google', 'facebook', 'microsoft', 'linkedin-openid-connect', 'github' and 'gitlab' (endpoints built in).
  - SPID: provider 'spid-saml' of the Keycloak extension italia/spid-keycloak-provider.
  - CIE ID: provider 'cieid-saml' of the Keycloak extension lscorcia/keycloak-cieid-provider.
  SPID and CIE need their extension installed in Keycloak (same version line as Keycloak).

  ---------------------------------------------------------------------------
}

unit IAMClient4D.IdentityProvider.Builders;

interface

uses
  System.SysUtils,
  IAMClient4D.IdentityProvider.Core;

const
  /// <summary>Default alias of the Microsoft Entra ID provider.</summary>
  IAM4D_IDP_ALIAS_ENTRA = 'entra';
  /// <summary>Default alias of the CIE ID provider.</summary>
  IAM4D_IDP_ALIAS_CIE = 'cie';
  /// <summary>Default alias of the Google provider.</summary>
  IAM4D_IDP_ALIAS_GOOGLE = 'google';
  /// <summary>Default alias of the Facebook provider.</summary>
  IAM4D_IDP_ALIAS_FACEBOOK = 'facebook';
  /// <summary>Default alias of the Microsoft (personal accounts) provider.</summary>
  IAM4D_IDP_ALIAS_MICROSOFT = 'microsoft';
  /// <summary>Default alias of the LinkedIn provider.</summary>
  IAM4D_IDP_ALIAS_LINKEDIN = 'linkedin';
  /// <summary>Default alias of the GitHub provider.</summary>
  IAM4D_IDP_ALIAS_GITHUB = 'github';
  /// <summary>Default alias of the GitLab provider.</summary>
  IAM4D_IDP_ALIAS_GITLAB = 'gitlab';

  /// <summary>Provider type of the Keycloak Google social provider.</summary>
  IAM4D_IDP_PROVIDER_GOOGLE = 'google';
  /// <summary>Provider type of the Keycloak Facebook social provider.</summary>
  IAM4D_IDP_PROVIDER_FACEBOOK = 'facebook';
  /// <summary>Provider type of the Keycloak Microsoft social provider (Microsoft Graph, not OpenID Connect).</summary>
  IAM4D_IDP_PROVIDER_MICROSOFT = 'microsoft';
  /// <summary>Provider type of the Keycloak LinkedIn social provider (OpenID Connect).</summary>
  IAM4D_IDP_PROVIDER_LINKEDIN = 'linkedin-openid-connect';
  /// <summary>Provider type of the Keycloak GitHub social provider.</summary>
  IAM4D_IDP_PROVIDER_GITHUB = 'github';
  /// <summary>Provider type of the Keycloak GitLab social provider (gitlab.com only).</summary>
  IAM4D_IDP_PROVIDER_GITLAB = 'gitlab';

  /// <summary>Provider type of italia/spid-keycloak-provider (24.0.1 and later).</summary>
  IAM4D_IDP_PROVIDER_SPID = 'spid-saml';
  /// <summary>Provider type of lscorcia/keycloak-cieid-provider (24.0.1 and later).</summary>
  IAM4D_IDP_PROVIDER_CIE = 'cieid-saml';

  /// <summary>Mapper type of the SPID extension: imports a SPID attribute into a user attribute.</summary>
  IAM4D_IDP_MAPPER_SPID_ATTRIBUTE = 'spid-user-attribute-idp-mapper';
  /// <summary>Mapper type of the CIE extension: imports a CIE ID attribute into a user attribute.</summary>
  IAM4D_IDP_MAPPER_CIE_ATTRIBUTE = 'cieid-user-attribute-idp-mapper';
  /// <summary>Mapper type of the Google provider: imports a user info field into a user attribute.</summary>
  IAM4D_IDP_MAPPER_GOOGLE_ATTRIBUTE = 'google-user-attribute-mapper';
  /// <summary>Mapper type of the Facebook provider: imports a profile field into a user attribute.</summary>
  IAM4D_IDP_MAPPER_FACEBOOK_ATTRIBUTE = 'facebook-user-attribute-mapper';
  /// <summary>Mapper type of the Microsoft provider: imports a Microsoft Graph user field into a user attribute.</summary>
  IAM4D_IDP_MAPPER_MICROSOFT_ATTRIBUTE = 'microsoft-user-attribute-mapper';
  /// <summary>Mapper type of the LinkedIn provider: imports a user info field into a user attribute.</summary>
  IAM4D_IDP_MAPPER_LINKEDIN_ATTRIBUTE = 'linkedin-user-attribute-mapper';
  /// <summary>Mapper type of the GitHub provider: imports a GitHub user field into a user attribute.</summary>
  IAM4D_IDP_MAPPER_GITHUB_ATTRIBUTE = 'github-user-attribute-mapper';
  /// <summary>Mapper type of the SAML provider: imports an assertion attribute into a user attribute.</summary>
  IAM4D_IDP_MAPPER_SAML_ATTRIBUTE = 'saml-user-attribute-idp-mapper';

  /// <summary>SAML NameID formats for TIAM4DSamlIdPBuilder.WithNameIDFormat.</summary>
  IAM4D_SAML_NAMEID_PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
  IAM4D_SAML_NAMEID_TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
  IAM4D_SAML_NAMEID_EMAIL = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
  IAM4D_SAML_NAMEID_UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

  /// <summary>AgID registry of the SPID identity providers (JSON: entity IDs and metadata links).</summary>
  IAM4D_SPID_REGISTRY_URL = 'https://registry.spid.gov.it/entities-idp?output=json';

type
  /// <summary>SPID/CIE authentication level (AuthnContextClassRef https://www.spid.gov.it/SpidLn).</summary>
  TIAM4DSpidLevel = (slL1, slL2, slL3);

  TIAM4DSpidLevelHelper = record helper for TIAM4DSpidLevel
    function ToURI: string;
  end;

  /// <summary>CIE ID identity server.</summary>
  TIAM4DCieEnvironment = (ceProduction, cePreProduction);

  // ==========================================================================
  // OpenID Connect: any provider and Microsoft Entra ID
  // ==========================================================================

  /// <summary>How Keycloak authenticates to the token endpoint of the provider (config clientAuthMethod).</summary>
  /// <remarks>
  /// ocaClientSecretPost: secret in the request body (client_secret_post); ocaClientSecretBasic: HTTP Basic
  /// (client_secret_basic); ocaPrivateKeyJwt: JWT signed with a realm key, no secret (private_key_jwt: register
  /// {realm URL}/protocol/openid-connect/certs at the provider); ocaClientSecretJwt: JWT signed with the
  /// secret (client_secret_jwt).
  /// </remarks>
  TIAM4DOidcClientAuthMethod = (ocaClientSecretPost, ocaClientSecretBasic, ocaPrivateKeyJwt, ocaClientSecretJwt);

  /// <summary>
  /// Settings shared by the OpenID Connect, OAuth 2.0 and social builders: client, scopes, PKCE S256 and,
  /// for OpenID Connect, the security checks (issuer, signature through the JWKS), written by Build.
  /// </summary>
  TIAM4DOidcIdPBuilderBase = class(TInterfacedObject)
  protected
    FIdentityProvider: TIAM4DIdentityProvider;
    FProduct: string;
    FScopes: TArray<string>;
    FClientAuthMethod: TIAM4DOidcClientAuthMethod;
    FClientAssertionSigningAlg: string;
    /// <summary>False for OAuth 2.0 (provider 'oauth2'): no id_token, so no issuer nor signature to check.</summary>
    FIdToken: Boolean;
    FIssuerCheck: Boolean;
    FSignatureValidation: Boolean;
    FPkce: Boolean;
    procedure Initialize(const AAlias, AProviderID, AProduct, ADisplayName: string);
    /// <summary>Social provider (endpoints built into Keycloak): display name AProduct, PKCE S256 if APkce.</summary>
    procedure InitializeSocial(const AAlias, AProviderID, AProduct: string; const AScopes: TArray<string>;
      const APkce: Boolean);
    procedure SetClient(const AClientID, AClientSecret: string);
    procedure SetClientAuthMethod(const AMethod: TIAM4DOidcClientAuthMethod; const ASigningAlgorithm: string);
    /// <summary>Client ID, and the secret unless the method is private_key_jwt.</summary>
    procedure CheckClient;
    /// <summary>
    /// Checks alias, client, endpoints, issuer, JWKS (user info URL for OAuth 2.0) and trust email, then
    /// writes client authentication, scopes, signature validation and PKCE (WithConfig cannot turn them off).
    /// </summary>
    function BuildIdentityProvider: TIAM4DIdentityProvider;
    /// <summary>Checks alias and client, then writes the scopes (none: the Keycloak default) and PKCE.</summary>
    function BuildSocialIdentityProvider: TIAM4DIdentityProvider;
  end;

  /// <summary>
  /// With* methods shared by the OpenID Connect, OAuth 2.0 and social builders; I is the builder interface
  /// they return.
  /// </summary>
  TIAM4DOidcIdPBuilderCommon<I: IInterface> = class(TIAM4DOidcIdPBuilderBase)
  protected
    /// <summary>Self as the builder interface (result of the fluent methods).</summary>
    function Builder: I; virtual; abstract;
  public
    function WithClient(const AClientID, AClientSecret: string): I;
    function WithDisplayName(const ADisplayName: string): I;
    function WithScopes(const AScopes: TArray<string>): I;
    function WithPrompt(const APrompt: string): I;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): I;
    function WithTrustEmail(const AValue: Boolean = True): I;
    function WithHideOnLogin(const AValue: Boolean = True): I;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): I;
    function WithConfig(const AKey, AValue: string): I;
  end;

  /// <summary>
  /// Any OpenID Connect provider (Okta, Auth0, ADFS, Ping, another Keycloak...) through the Keycloak
  /// provider 'oidc'.
  /// </summary>
  /// <remarks>
  /// Register a confidential client at the provider with redirect URI {Keycloak}/realms/{realm}/broker/{alias}/endpoint.
  /// Endpoints: WithImportedConfig with the result of IIAM4DIdentityProviderManager.ImportConfig(IAM4D_IDP_PROVIDER_OIDC,
  /// discovery URL), or WithEndpoints, WithJwksURL and WithIssuer. The later call wins: override imported
  /// values after WithImportedConfig.
  /// Defaults: PKCE S256, signature validated with the JWKS of the provider, issuer checked, client_secret_post.
  /// Build requires issuer and JWKS URL; turning a check off takes DisableIssuerCheck, DisableSignatureValidation
  /// or DisablePkce. WithTrustEmail requires both checks (see there).
  /// </remarks>
  IIAM4DOidcIdPBuilder = interface
    ['{5B0E7C4A-93D1-4F2B-A6E8-0C71D2F49B35}']
    /// <summary>
    /// Config returned by ImportConfig from the discovery document (endpoints, JWKS URL, issuer); replaces
    /// all of them, also those the document lacks.
    /// </summary>
    function WithImportedConfig(const AConfig: TIAM4DConfigMap): IIAM4DOidcIdPBuilder;
    /// <summary>Endpoints set by hand; empty user info or logout URL: not used.</summary>
    function WithEndpoints(const AAuthorizationURL, ATokenURL: string; const AUserInfoURL: string = '';
      const ALogoutURL: string = ''): IIAM4DOidcIdPBuilder;
    /// <summary>Keys of the provider, to validate the signature of its tokens.</summary>
    function WithJwksURL(const AURL: string): IIAM4DOidcIdPBuilder;
    /// <summary>Expected iss claim; several accepted issuers comma-separated.</summary>
    function WithIssuer(const AIssuer: string): IIAM4DOidcIdPBuilder;
    /// <summary>Client registered at the provider; empty secret with ocaPrivateKeyJwt.</summary>
    function WithClient(const AClientID, AClientSecret: string): IIAM4DOidcIdPBuilder;
    /// <summary>
    /// Default ocaClientSecretPost. ASigningAlgorithm: JWS algorithm of the client assertion; private_key_jwt
    /// RS256 (default), RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512 or EdDSA; client_secret_jwt
    /// HS256 (default), HS384 or HS512.
    /// </summary>
    function WithClientAuthMethod(const AMethod: TIAM4DOidcClientAuthMethod;
      const ASigningAlgorithm: string = ''): IIAM4DOidcIdPBuilder;
    /// <summary>Default: the alias (Keycloak shows it when the display name is empty).</summary>
    function WithDisplayName(const ADisplayName: string): IIAM4DOidcIdPBuilder;
    /// <summary>Default openid, profile, email.</summary>
    function WithScopes(const AScopes: TArray<string>): IIAM4DOidcIdPBuilder;
    /// <summary>OIDC prompt sent to the provider, e.g. 'select_account' or 'login'.</summary>
    function WithPrompt(const APrompt: string): IIAM4DOidcIdPBuilder;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): IIAM4DOidcIdPBuilder;
    /// <summary>
    /// Emails from the provider are considered verified. Requires the issuer check and signature validation:
    /// without them a token of another issuer, or a forged one, could claim the email of an existing user (nOAuth).
    /// </summary>
    function WithTrustEmail(const AValue: Boolean = True): IIAM4DOidcIdPBuilder;
    /// <summary>Hides the provider on the Keycloak login page (reachable with kc_idp_hint only).</summary>
    function WithHideOnLogin(const AValue: Boolean = True): IIAM4DOidcIdPBuilder;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): IIAM4DOidcIdPBuilder;
    /// <summary>
    /// Any other config key of the Keycloak OIDC provider. Client authentication, scopes, signature
    /// validation and PKCE are written by Build: use the dedicated methods.
    /// </summary>
    function WithConfig(const AKey, AValue: string): IIAM4DOidcIdPBuilder;
    /// <summary>Accepts tokens of any issuer (e.g. multi-tenant providers): no WithTrustEmail.</summary>
    function DisableIssuerCheck: IIAM4DOidcIdPBuilder;
    /// <summary>Token signatures not validated, no JWKS needed: tokens are trusted on TLS alone; no WithTrustEmail.</summary>
    function DisableSignatureValidation: IIAM4DOidcIdPBuilder;
    /// <summary>No PKCE, for providers that reject code_challenge.</summary>
    function DisablePkce: IIAM4DOidcIdPBuilder;
    /// <exception cref="EIAM4DInvalidConfigurationException">Raised when endpoints, client, issuer or JWKS URL
    /// are missing, with a signing algorithm that does not fit the client authentication, or with
    /// WithTrustEmail and DisableIssuerCheck or DisableSignatureValidation</exception>
    function Build: TIAM4DIdentityProvider;
  end;

  TIAM4DOidcIdPBuilder = class(TIAM4DOidcIdPBuilderCommon<IIAM4DOidcIdPBuilder>, IIAM4DOidcIdPBuilder)
  protected
    function Builder: IIAM4DOidcIdPBuilder; override;
  public
    /// <param name="AAlias">Alias of the provider in the realm, e.g. 'okta'.</param>
    class function New(const AAlias: string): IIAM4DOidcIdPBuilder;

    function WithImportedConfig(const AConfig: TIAM4DConfigMap): IIAM4DOidcIdPBuilder;
    function WithEndpoints(const AAuthorizationURL, ATokenURL: string; const AUserInfoURL: string = '';
      const ALogoutURL: string = ''): IIAM4DOidcIdPBuilder;
    function WithJwksURL(const AURL: string): IIAM4DOidcIdPBuilder;
    function WithIssuer(const AIssuer: string): IIAM4DOidcIdPBuilder;
    function WithClientAuthMethod(const AMethod: TIAM4DOidcClientAuthMethod;
      const ASigningAlgorithm: string = ''): IIAM4DOidcIdPBuilder;
    function DisableIssuerCheck: IIAM4DOidcIdPBuilder;
    function DisableSignatureValidation: IIAM4DOidcIdPBuilder;
    function DisablePkce: IIAM4DOidcIdPBuilder;
    function Build: TIAM4DIdentityProvider;
  end;

  /// <summary>
  /// Microsoft Entra ID (Azure AD) through the Keycloak OpenID Connect provider.
  /// </summary>
  /// <remarks>
  /// Register an application in Entra ID with redirect URI {Keycloak}/realms/{realm}/broker/{alias}/endpoint
  /// and a client secret, then pass tenant, application (client) ID and secret.
  /// Tenant: directory ID (GUID) for a single organization; 'organizations', 'common' or 'consumers'
  /// for multi-tenant apps. The issuer is checked only with a directory ID: with a domain name or a
  /// multi-tenant value the tokens carry an issuer Keycloak cannot know in advance.
  /// WithTrustEmail requires the directory ID (see there).
  /// </remarks>
  IIAM4DEntraIdPBuilder = interface
    ['{2C9E5B71-4A0D-4F36-8E12-B7D3A61F0C94}']
    function WithTenant(const ATenant: string): IIAM4DEntraIdPBuilder;
    function WithClient(const AClientID, AClientSecret: string): IIAM4DEntraIdPBuilder;
    /// <summary>Default 'Microsoft'.</summary>
    function WithDisplayName(const ADisplayName: string): IIAM4DEntraIdPBuilder;
    /// <summary>Default openid, profile, email.</summary>
    function WithScopes(const AScopes: TArray<string>): IIAM4DEntraIdPBuilder;
    /// <summary>OIDC prompt sent to Entra, e.g. 'select_account' or 'login'.</summary>
    function WithPrompt(const APrompt: string): IIAM4DEntraIdPBuilder;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): IIAM4DEntraIdPBuilder;
    /// <summary>
    /// Emails from Entra ID are considered verified. Only with a directory ID (GUID) as tenant: with a
    /// multi-tenant or domain tenant the issuer is not checked and the email claim is not verified by
    /// Microsoft, so any tenant could claim the email of an existing user (nOAuth). Build raises otherwise.
    /// </summary>
    function WithTrustEmail(const AValue: Boolean = True): IIAM4DEntraIdPBuilder;
    /// <summary>Hides the provider on the Keycloak login page (reachable with kc_idp_hint only).</summary>
    function WithHideOnLogin(const AValue: Boolean = True): IIAM4DEntraIdPBuilder;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): IIAM4DEntraIdPBuilder;
    /// <summary>Any other config key of the Keycloak OIDC provider.</summary>
    function WithConfig(const AKey, AValue: string): IIAM4DEntraIdPBuilder;
    /// <exception cref="EIAM4DInvalidConfigurationException">Raised when tenant or client are missing, or
    /// with WithTrustEmail and a tenant that is not a directory ID</exception>
    function Build: TIAM4DIdentityProvider;
  end;

  TIAM4DEntraIdPBuilder = class(TIAM4DOidcIdPBuilderCommon<IIAM4DEntraIdPBuilder>, IIAM4DEntraIdPBuilder)
  private
    FTenant: string;
  protected
    function Builder: IIAM4DEntraIdPBuilder; override;
  public
    class function New(const AAlias: string = IAM4D_IDP_ALIAS_ENTRA): IIAM4DEntraIdPBuilder;

    function WithTenant(const ATenant: string): IIAM4DEntraIdPBuilder;
    function Build: TIAM4DIdentityProvider;
  end;

  // ==========================================================================
  // OAuth 2.0: any provider that is not OpenID Connect
  // ==========================================================================

  /// <summary>
  /// Any OAuth 2.0 provider without OpenID Connect (no id_token) through the Keycloak provider 'oauth2':
  /// Keycloak reads the user profile from the user info endpoint with the access token.
  /// </summary>
  /// <remarks>
  /// Register a confidential client at the provider with redirect URI {Keycloak}/realms/{realm}/broker/{alias}/endpoint.
  /// Prefer TIAM4DOidcIdPBuilder when the provider supports OpenID Connect: the id_token is signed and its issuer
  /// checked, here nothing is (the profile is trusted on TLS and on the access token alone).
  /// Endpoints: WithEndpoints (authorization, token and user info, all required), or WithImportedConfig with the
  /// result of IIAM4DIdentityProviderManager.ImportConfig(IAM4D_IDP_PROVIDER_OAUTH2, metadata URL); the later call wins.
  /// The user info response must be JSON; WithUserProfileClaims and WithNameClaims name its fields (dot notation
  /// for nested ones, e.g. 'data.id'), when they differ from sub, preferred_username, email, name, given_name
  /// and family_name.
  /// Defaults: PKCE S256 (DisablePkce for providers that reject it), client_secret_post, no scope.
  /// WithTrustEmail only for providers that verify the email: Keycloak has no email_verified to check here.
  /// </remarks>
  IIAM4DOAuth2IdPBuilder = interface
    ['{8E2D4B6A-1C3F-4A57-9B0E-6D5F7A2C1E48}']
    /// <summary>
    /// Config returned by ImportConfig from the metadata (authorization, token, user info and introspection
    /// URLs); replaces all of them, also those the metadata lacks.
    /// </summary>
    function WithImportedConfig(const AConfig: TIAM4DConfigMap): IIAM4DOAuth2IdPBuilder;
    function WithEndpoints(const AAuthorizationURL, ATokenURL, AUserInfoURL: string): IIAM4DOAuth2IdPBuilder;
    /// <summary>
    /// Fields of the user info response with user ID (stable and unique: it links the account), username and
    /// email; empty: the Keycloak default (sub, preferred_username, email). Without a username Keycloak uses
    /// the email, then the user ID.
    /// </summary>
    function WithUserProfileClaims(const AUserID, AUserName, AEmail: string): IIAM4DOAuth2IdPBuilder;
    /// <summary>Fields with full name, given name and family name; empty: name, given_name, family_name.</summary>
    function WithNameClaims(const AFullName, AGivenName, AFamilyName: string): IIAM4DOAuth2IdPBuilder;
    /// <summary>Client registered at the provider; empty secret with ocaPrivateKeyJwt.</summary>
    function WithClient(const AClientID, AClientSecret: string): IIAM4DOAuth2IdPBuilder;
    /// <summary>Default ocaClientSecretPost; ASigningAlgorithm as in IIAM4DOidcIdPBuilder.WithClientAuthMethod.</summary>
    function WithClientAuthMethod(const AMethod: TIAM4DOidcClientAuthMethod;
      const ASigningAlgorithm: string = ''): IIAM4DOAuth2IdPBuilder;
    /// <summary>Default: the alias (Keycloak shows it when the display name is empty).</summary>
    function WithDisplayName(const ADisplayName: string): IIAM4DOAuth2IdPBuilder;
    /// <summary>Scopes of the provider, e.g. 'read:user'; default none.</summary>
    function WithScopes(const AScopes: TArray<string>): IIAM4DOAuth2IdPBuilder;
    /// <summary>Prompt sent to the provider, if it supports one.</summary>
    function WithPrompt(const APrompt: string): IIAM4DOAuth2IdPBuilder;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): IIAM4DOAuth2IdPBuilder;
    /// <summary>
    /// Emails from the provider are considered verified. Only if the provider verifies them: Keycloak takes
    /// the email field as is, so an unverified one could take over the local account with that email.
    /// </summary>
    function WithTrustEmail(const AValue: Boolean = True): IIAM4DOAuth2IdPBuilder;
    /// <summary>Hides the provider on the Keycloak login page (reachable with kc_idp_hint only).</summary>
    function WithHideOnLogin(const AValue: Boolean = True): IIAM4DOAuth2IdPBuilder;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): IIAM4DOAuth2IdPBuilder;
    /// <summary>
    /// Any other config key of the Keycloak OAuth 2.0 provider. Client authentication, scopes and PKCE are
    /// written by Build: use the dedicated methods.
    /// </summary>
    function WithConfig(const AKey, AValue: string): IIAM4DOAuth2IdPBuilder;
    /// <summary>No PKCE, for providers that reject code_challenge.</summary>
    function DisablePkce: IIAM4DOAuth2IdPBuilder;
    /// <exception cref="EIAM4DInvalidConfigurationException">Raised when endpoints or client are missing</exception>
    function Build: TIAM4DIdentityProvider;
  end;

  TIAM4DOAuth2IdPBuilder = class(TIAM4DOidcIdPBuilderCommon<IIAM4DOAuth2IdPBuilder>, IIAM4DOAuth2IdPBuilder)
  private
    procedure SetClaim(const AKey, AValue: string);
  protected
    function Builder: IIAM4DOAuth2IdPBuilder; override;
  public
    /// <param name="AAlias">Alias of the provider in the realm, e.g. 'strava'.</param>
    class function New(const AAlias: string): IIAM4DOAuth2IdPBuilder;

    function WithImportedConfig(const AConfig: TIAM4DConfigMap): IIAM4DOAuth2IdPBuilder;
    function WithEndpoints(const AAuthorizationURL, ATokenURL, AUserInfoURL: string): IIAM4DOAuth2IdPBuilder;
    function WithUserProfileClaims(const AUserID, AUserName, AEmail: string): IIAM4DOAuth2IdPBuilder;
    function WithNameClaims(const AFullName, AGivenName, AFamilyName: string): IIAM4DOAuth2IdPBuilder;
    function WithClientAuthMethod(const AMethod: TIAM4DOidcClientAuthMethod;
      const ASigningAlgorithm: string = ''): IIAM4DOAuth2IdPBuilder;
    function DisablePkce: IIAM4DOAuth2IdPBuilder;
    function Build: TIAM4DIdentityProvider;
  end;

  // ==========================================================================
  // Social providers built into Keycloak
  // ==========================================================================

  /// <summary>
  /// Google accounts (personal and Google Workspace) through the Keycloak Google provider.
  /// </summary>
  /// <remarks>
  /// Create an OAuth client ID of type "Web application" in the Google Cloud console with authorized
  /// redirect URI {Keycloak}/realms/{realm}/broker/{alias}/endpoint, then pass client ID and secret.
  /// Keycloak knows the Google endpoints and checks the issuer; the builder adds PKCE (S256).
  /// WithHostedDomains limits the login to Google Workspace domains: Keycloak rejects tokens whose
  /// hd claim is missing or not in the list (Google pre-selects the accounts only for a single domain).
  /// Google sets email_verified on its accounts: WithTrustEmail is reasonable.
  /// </remarks>
  IIAM4DGoogleIdPBuilder = interface
    ['{CB8FF213-CD27-42D3-9ECB-5D2F59E59F45}']
    function WithClient(const AClientID, AClientSecret: string): IIAM4DGoogleIdPBuilder;
    /// <summary>Default 'Google'.</summary>
    function WithDisplayName(const ADisplayName: string): IIAM4DGoogleIdPBuilder;
    /// <summary>Default openid, profile, email.</summary>
    function WithScopes(const AScopes: TArray<string>): IIAM4DGoogleIdPBuilder;
    /// <summary>
    /// Google Workspace domains allowed to log in (e.g. 'example.com'); ['*']: any Google Workspace account
    /// (no personal account); empty: any account.
    /// </summary>
    function WithHostedDomains(const ADomains: TArray<string>): IIAM4DGoogleIdPBuilder;
    /// <summary>Prompt sent to Google, e.g. 'select_account' or 'consent'.</summary>
    function WithPrompt(const APrompt: string): IIAM4DGoogleIdPBuilder;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): IIAM4DGoogleIdPBuilder;
    function WithTrustEmail(const AValue: Boolean = True): IIAM4DGoogleIdPBuilder;
    /// <summary>Hides the provider on the Keycloak login page (reachable with kc_idp_hint only).</summary>
    function WithHideOnLogin(const AValue: Boolean = True): IIAM4DGoogleIdPBuilder;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): IIAM4DGoogleIdPBuilder;
    /// <summary>
    /// Any other config key of the Google provider (e.g. 'offlineAccess'). Hosted domains and PKCE are
    /// written by Build: use the dedicated methods.
    /// </summary>
    function WithConfig(const AKey, AValue: string): IIAM4DGoogleIdPBuilder;
    /// <exception cref="EIAM4DInvalidConfigurationException">Raised when the client is missing or a
    /// hosted domain is not a domain name ('*' only alone)</exception>
    function Build: TIAM4DIdentityProvider;
  end;

  TIAM4DGoogleIdPBuilder = class(TIAM4DOidcIdPBuilderCommon<IIAM4DGoogleIdPBuilder>, IIAM4DGoogleIdPBuilder)
  private
    FHostedDomains: TArray<string>;
  protected
    function Builder: IIAM4DGoogleIdPBuilder; override;
  public
    class function New(const AAlias: string = IAM4D_IDP_ALIAS_GOOGLE): IIAM4DGoogleIdPBuilder;
    /// <summary>Mapper importing a Google user info field (e.g. 'picture', 'hd') into a user attribute.</summary>
    class function AttributeMapper(const AIdentityProviderAlias, AJsonField,
      AUserAttribute: string): TIAM4DIdentityProviderMapper;

    function WithHostedDomains(const ADomains: TArray<string>): IIAM4DGoogleIdPBuilder;
    function Build: TIAM4DIdentityProvider;
  end;

  /// <summary>
  /// Facebook Login through the Keycloak Facebook provider (OAuth 2.0 and Graph API, not OpenID Connect).
  /// </summary>
  /// <remarks>
  /// Create a Meta app with the Facebook Login product, add {Keycloak}/realms/{realm}/broker/{alias}/endpoint
  /// to the valid OAuth redirect URIs and pass app ID and app secret. Outside development mode the app
  /// must be Live (privacy policy and data deletion URLs).
  /// Keycloak reads id, name, email, first_name and last_name from the Graph API; WithFetchedFields adds
  /// others (each may need its permission in WithScopes and Meta app review).
  /// Accounts registered with a phone number have no email: Keycloak asks for it at the first login.
  /// Meta does not state that the email is verified: WithTrustEmail lets a Facebook account take over
  /// a local account with the same email, keep it off unless the realm accepts that.
  /// </remarks>
  IIAM4DFacebookIdPBuilder = interface
    ['{4313913C-C72A-4550-B1AB-C09AF39FCB38}']
    function WithClient(const AClientID, AClientSecret: string): IIAM4DFacebookIdPBuilder;
    /// <summary>Default 'Facebook'.</summary>
    function WithDisplayName(const ADisplayName: string): IIAM4DFacebookIdPBuilder;
    /// <summary>Default email, public_profile.</summary>
    function WithScopes(const AScopes: TArray<string>): IIAM4DFacebookIdPBuilder;
    /// <summary>Additional Graph API profile fields (e.g. 'birthday'), for the attribute mappers.</summary>
    function WithFetchedFields(const AFields: TArray<string>): IIAM4DFacebookIdPBuilder;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): IIAM4DFacebookIdPBuilder;
    function WithTrustEmail(const AValue: Boolean = True): IIAM4DFacebookIdPBuilder;
    /// <summary>Hides the provider on the Keycloak login page (reachable with kc_idp_hint only).</summary>
    function WithHideOnLogin(const AValue: Boolean = True): IIAM4DFacebookIdPBuilder;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): IIAM4DFacebookIdPBuilder;
    /// <summary>Any other config key of the Facebook provider.</summary>
    function WithConfig(const AKey, AValue: string): IIAM4DFacebookIdPBuilder;
    /// <exception cref="EIAM4DInvalidConfigurationException">Raised when the client is missing or a
    /// fetched field is not a field name</exception>
    function Build: TIAM4DIdentityProvider;
  end;

  TIAM4DFacebookIdPBuilder = class(TIAM4DOidcIdPBuilderCommon<IIAM4DFacebookIdPBuilder>, IIAM4DFacebookIdPBuilder)
  private
    FFetchedFields: TArray<string>;
  protected
    function Builder: IIAM4DFacebookIdPBuilder; override;
  public
    class function New(const AAlias: string = IAM4D_IDP_ALIAS_FACEBOOK): IIAM4DFacebookIdPBuilder;
    /// <summary>Mapper importing a Facebook profile field (e.g. 'birthday') into a user attribute; fields
    /// other than id, name, email, first_name and last_name need WithFetchedFields.</summary>
    class function AttributeMapper(const AIdentityProviderAlias, AJsonField,
      AUserAttribute: string): TIAM4DIdentityProviderMapper;

    function WithFetchedFields(const AFields: TArray<string>): IIAM4DFacebookIdPBuilder;
    function Build: TIAM4DIdentityProvider;
  end;

  /// <summary>
  /// Microsoft accounts through the Keycloak Microsoft provider: OAuth 2.0 with the Microsoft Graph profile
  /// (/v1.0/me), no id_token.
  /// </summary>
  /// <remarks>
  /// Register an application in the Microsoft Entra admin center (App registrations) with redirect URI (platform
  /// Web) {Keycloak}/realms/{realm}/broker/{alias}/endpoint and a client secret; supported account types must
  /// match the tenant.
  /// Tenant: default 'consumers' (personal accounts: Outlook.com, Hotmail, Xbox); 'common' personal and work
  /// accounts, 'organizations' work accounts, or a directory ID. For work accounts prefer TIAM4DEntraIdPBuilder:
  /// OpenID Connect, with the id_token signature and issuer checked.
  /// Keycloak reads id, mail (or userPrincipalName when it is an email), givenName and surname from Graph;
  /// nothing says whether the email is verified.
  /// Defaults: scope User.Read, PKCE (S256). WithTrustEmail requires a directory ID (see there).
  /// </remarks>
  IIAM4DMicrosoftIdPBuilder = interface
    ['{3F6A1D92-7B4E-4C08-A5D3-9E21C8B07F64}']
    /// <summary>
    /// 'consumers' (default, also for an empty value), 'common', 'organizations', a directory ID (GUID) or a domain.
    /// </summary>
    function WithTenant(const ATenant: string): IIAM4DMicrosoftIdPBuilder;
    function WithClient(const AClientID, AClientSecret: string): IIAM4DMicrosoftIdPBuilder;
    /// <summary>Default 'Microsoft'.</summary>
    function WithDisplayName(const ADisplayName: string): IIAM4DMicrosoftIdPBuilder;
    /// <summary>Microsoft Graph scopes; default User.Read (needed to read the profile).</summary>
    function WithScopes(const AScopes: TArray<string>): IIAM4DMicrosoftIdPBuilder;
    /// <summary>Prompt sent to Microsoft, e.g. 'select_account' or 'login'.</summary>
    function WithPrompt(const APrompt: string): IIAM4DMicrosoftIdPBuilder;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): IIAM4DMicrosoftIdPBuilder;
    /// <summary>
    /// Emails from Microsoft are considered verified. Only with a directory ID (GUID) as tenant: Keycloak
    /// takes mail or userPrincipalName from Graph without any check, and with a multi-tenant value any tenant
    /// can set them to the email of an existing user (nOAuth). Build raises otherwise.
    /// </summary>
    function WithTrustEmail(const AValue: Boolean = True): IIAM4DMicrosoftIdPBuilder;
    /// <summary>Hides the provider on the Keycloak login page (reachable with kc_idp_hint only).</summary>
    function WithHideOnLogin(const AValue: Boolean = True): IIAM4DMicrosoftIdPBuilder;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): IIAM4DMicrosoftIdPBuilder;
    /// <summary>Any other config key of the Microsoft provider.</summary>
    function WithConfig(const AKey, AValue: string): IIAM4DMicrosoftIdPBuilder;
    /// <exception cref="EIAM4DInvalidConfigurationException">Raised when the client is missing, the tenant is
    /// not valid, or with WithTrustEmail and a tenant that is not a directory ID</exception>
    function Build: TIAM4DIdentityProvider;
  end;

  TIAM4DMicrosoftIdPBuilder = class(TIAM4DOidcIdPBuilderCommon<IIAM4DMicrosoftIdPBuilder>, IIAM4DMicrosoftIdPBuilder)
  private
    FTenant: string;
  protected
    function Builder: IIAM4DMicrosoftIdPBuilder; override;
  public
    class function New(const AAlias: string = IAM4D_IDP_ALIAS_MICROSOFT): IIAM4DMicrosoftIdPBuilder;
    /// <summary>Mapper importing a Microsoft Graph user field (e.g. 'jobTitle', 'preferredLanguage') into a user attribute.</summary>
    class function AttributeMapper(const AIdentityProviderAlias, AJsonField,
      AUserAttribute: string): TIAM4DIdentityProviderMapper;

    function WithTenant(const ATenant: string): IIAM4DMicrosoftIdPBuilder;
    function Build: TIAM4DIdentityProvider;
  end;

  /// <summary>
  /// LinkedIn members through the Keycloak provider 'linkedin-openid-connect' (Sign In with LinkedIn using
  /// OpenID Connect).
  /// </summary>
  /// <remarks>
  /// Create an app in the LinkedIn Developer Portal, add the product "Sign In with LinkedIn using OpenID Connect"
  /// and the authorized redirect URL {Keycloak}/realms/{realm}/broker/{alias}/endpoint, then pass client ID and
  /// primary client secret.
  /// Keycloak reads the LinkedIn discovery document and validates the id_token (signature, issuer, audience);
  /// no nonce, which LinkedIn does not return. No PKCE: LinkedIn documents it for native apps only.
  /// Default scopes openid, profile, email. With WithTrustEmail Keycloak takes email_verified from the id_token,
  /// so only emails LinkedIn verified are trusted.
  /// </remarks>
  IIAM4DLinkedInIdPBuilder = interface
    ['{C5B19E73-0F2A-4D86-B3E7-41A9D6C28F05}']
    function WithClient(const AClientID, AClientSecret: string): IIAM4DLinkedInIdPBuilder;
    /// <summary>Default 'LinkedIn'.</summary>
    function WithDisplayName(const ADisplayName: string): IIAM4DLinkedInIdPBuilder;
    /// <summary>Default openid, profile, email.</summary>
    function WithScopes(const AScopes: TArray<string>): IIAM4DLinkedInIdPBuilder;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): IIAM4DLinkedInIdPBuilder;
    function WithTrustEmail(const AValue: Boolean = True): IIAM4DLinkedInIdPBuilder;
    /// <summary>Hides the provider on the Keycloak login page (reachable with kc_idp_hint only).</summary>
    function WithHideOnLogin(const AValue: Boolean = True): IIAM4DLinkedInIdPBuilder;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): IIAM4DLinkedInIdPBuilder;
    /// <summary>Any other config key of the LinkedIn provider.</summary>
    function WithConfig(const AKey, AValue: string): IIAM4DLinkedInIdPBuilder;
    /// <exception cref="EIAM4DInvalidConfigurationException">Raised when the client is missing</exception>
    function Build: TIAM4DIdentityProvider;
  end;

  TIAM4DLinkedInIdPBuilder = class(TIAM4DOidcIdPBuilderCommon<IIAM4DLinkedInIdPBuilder>, IIAM4DLinkedInIdPBuilder)
  protected
    function Builder: IIAM4DLinkedInIdPBuilder; override;
  public
    class function New(const AAlias: string = IAM4D_IDP_ALIAS_LINKEDIN): IIAM4DLinkedInIdPBuilder;
    /// <summary>Mapper importing a LinkedIn user info field (e.g. 'picture', 'locale') into a user attribute.</summary>
    class function AttributeMapper(const AIdentityProviderAlias, AJsonField,
      AUserAttribute: string): TIAM4DIdentityProviderMapper;

    function Build: TIAM4DIdentityProvider;
  end;

  /// <summary>
  /// GitHub accounts (github.com or GitHub Enterprise Server) through the Keycloak GitHub provider: OAuth 2.0
  /// with the GitHub REST API, not OpenID Connect.
  /// </summary>
  /// <remarks>
  /// Create an OAuth app (or a GitHub App) in the GitHub developer settings with authorization callback URL
  /// {Keycloak}/realms/{realm}/broker/{alias}/endpoint, then pass client ID and client secret.
  /// Keycloak reads id, login (username), name and the public email of /user; without a public email, the
  /// primary one of /user/emails, whether verified or not: there is no WithTrustEmail.
  /// WithEnterprise points to a GitHub Enterprise Server (web and API URLs).
  /// Defaults: scope user:email, PKCE (S256).
  /// </remarks>
  IIAM4DGitHubIdPBuilder = interface
    ['{6A0E8C37-D15B-4F92-8E4C-B2F73A190D6E}']
    function WithClient(const AClientID, AClientSecret: string): IIAM4DGitHubIdPBuilder;
    /// <summary>
    /// GitHub Enterprise Server: web URL (e.g. https://github.example.com) and API URL
    /// (e.g. https://github.example.com/api/v3); both required, https.
    /// </summary>
    function WithEnterprise(const ABaseURL, AApiURL: string): IIAM4DGitHubIdPBuilder;
    /// <summary>Default 'GitHub'.</summary>
    function WithDisplayName(const ADisplayName: string): IIAM4DGitHubIdPBuilder;
    /// <summary>Default user:email (needed for a private email).</summary>
    function WithScopes(const AScopes: TArray<string>): IIAM4DGitHubIdPBuilder;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): IIAM4DGitHubIdPBuilder;
    /// <summary>Hides the provider on the Keycloak login page (reachable with kc_idp_hint only).</summary>
    function WithHideOnLogin(const AValue: Boolean = True): IIAM4DGitHubIdPBuilder;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): IIAM4DGitHubIdPBuilder;
    /// <summary>Any other config key of the GitHub provider (e.g. 'githubJsonFormat').</summary>
    function WithConfig(const AKey, AValue: string): IIAM4DGitHubIdPBuilder;
    /// <exception cref="EIAM4DInvalidConfigurationException">Raised when the client is missing or an
    /// Enterprise URL is not valid</exception>
    function Build: TIAM4DIdentityProvider;
  end;

  TIAM4DGitHubIdPBuilder = class(TIAM4DOidcIdPBuilderCommon<IIAM4DGitHubIdPBuilder>, IIAM4DGitHubIdPBuilder)
  private
    FBaseURL: string;
    FApiURL: string;
  protected
    function Builder: IIAM4DGitHubIdPBuilder; override;
  public
    class function New(const AAlias: string = IAM4D_IDP_ALIAS_GITHUB): IIAM4DGitHubIdPBuilder;
    /// <summary>Mapper importing a GitHub /user field (e.g. 'company', 'html_url') into a user attribute.</summary>
    class function AttributeMapper(const AIdentityProviderAlias, AJsonField,
      AUserAttribute: string): TIAM4DIdentityProviderMapper;

    function WithEnterprise(const ABaseURL, AApiURL: string): IIAM4DGitHubIdPBuilder;
    function Build: TIAM4DIdentityProvider;
  end;

  /// <summary>
  /// gitlab.com accounts through the Keycloak GitLab provider (OpenID Connect plus the GitLab REST API).
  /// </summary>
  /// <remarks>
  /// Create an application in GitLab (User settings > Applications, or a group) with redirect URI
  /// {Keycloak}/realms/{realm}/broker/{alias}/endpoint, confidential, scopes openid, read_user and email; pass
  /// application ID and secret.
  /// Keycloak 26 has the gitlab.com endpoints hard-coded: for a self-managed GitLab use TIAM4DOidcIdPBuilder
  /// with its discovery document ({GitLab}/.well-known/openid-configuration).
  /// Keycloak does not check the id_token signature nor its issuer by default: the builder turns both on
  /// (JWKS and issuer of gitlab.com). Defaults: scopes openid, read_user, email, PKCE (S256).
  /// WithTrustEmail needs the email scope: GitLab sends email_verified only with it, and Keycloak then
  /// trusts only verified emails.
  /// </remarks>
  IIAM4DGitLabIdPBuilder = interface
    ['{E19B7D24-5A3C-4F60-9D8B-07C4E2A6F153}']
    function WithClient(const AClientID, AClientSecret: string): IIAM4DGitLabIdPBuilder;
    /// <summary>Default 'GitLab'.</summary>
    function WithDisplayName(const ADisplayName: string): IIAM4DGitLabIdPBuilder;
    /// <summary>Default openid, read_user, email.</summary>
    function WithScopes(const AScopes: TArray<string>): IIAM4DGitLabIdPBuilder;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): IIAM4DGitLabIdPBuilder;
    function WithTrustEmail(const AValue: Boolean = True): IIAM4DGitLabIdPBuilder;
    /// <summary>Hides the provider on the Keycloak login page (reachable with kc_idp_hint only).</summary>
    function WithHideOnLogin(const AValue: Boolean = True): IIAM4DGitLabIdPBuilder;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): IIAM4DGitLabIdPBuilder;
    /// <summary>
    /// Any other config key of the GitLab provider. Scopes, signature validation, issuer and PKCE are
    /// written by Build: use the dedicated methods.
    /// </summary>
    function WithConfig(const AKey, AValue: string): IIAM4DGitLabIdPBuilder;
    /// <exception cref="EIAM4DInvalidConfigurationException">Raised when the client is missing, the openid
    /// scope is missing, or with WithTrustEmail without the email scope</exception>
    function Build: TIAM4DIdentityProvider;
  end;

  TIAM4DGitLabIdPBuilder = class(TIAM4DOidcIdPBuilderCommon<IIAM4DGitLabIdPBuilder>, IIAM4DGitLabIdPBuilder)
  protected
    function Builder: IIAM4DGitLabIdPBuilder; override;
  public
    class function New(const AAlias: string = IAM4D_IDP_ALIAS_GITLAB): IIAM4DGitLabIdPBuilder;

    function Build: TIAM4DIdentityProvider;
  end;

  // ==========================================================================
  // SAML 2.0: any provider
  // ==========================================================================

  /// <summary>Where Keycloak reads the brokered user ID (config principalType).</summary>
  /// <remarks>
  /// sptSubject: NameID of the subject; sptAttribute: attribute by name; sptFriendlyAttribute: attribute by
  /// friendly name.
  /// </remarks>
  TIAM4DSamlPrincipalType = (sptSubject, sptAttribute, sptFriendlyAttribute);

  /// <summary>
  /// Identity provider data shared by the SAML builders (generic, SPID, CIE): imported metadata, metadata
  /// URL, endpoints set by hand and their checks.
  /// </summary>
  TIAM4DSamlIdPBuilderBase = class(TInterfacedObject)
  protected
    FIdentityProvider: TIAM4DIdentityProvider;
    FProduct: string;
    /// <summary>
    /// Entity ID, endpoints, certificates and metadata URL of the imported metadata; the provider data it lacks
    /// is removed (the metadata URL is kept).
    /// </summary>
    procedure SetImportedConfig(const AConfig: TIAM4DConfigMap);
    procedure SetMetadataURL(const AURL: string);
    /// <summary>POST binding endpoints; imported data of another provider is removed.</summary>
    procedure SetIdentityProviderEndpoints(const AEntityID, ASingleSignOnURL, ASigningCertificate,
      ASingleLogoutURL: string);
    /// <summary>
    /// Alias, entity ID, single sign-on URL and, with ASignatureValidation, the signing certificate unless Keycloak
    /// reads it from the metadata URL. ACertificateHint: where the certificate comes from (error message).
    /// </summary>
    procedure CheckIdentityProvider(const ASignatureValidation: Boolean; const ACertificateHint: string);
  end;

  /// <summary>
  /// Any SAML 2.0 identity provider (ADFS, Okta, Google Workspace, Shibboleth, another Keycloak...) through
  /// the Keycloak provider 'saml'.
  /// </summary>
  /// <remarks>
  /// Register Keycloak at the provider with the SP metadata of IIAM4DIdentityProviderManager.ExportServiceProviderMetadata
  /// (entity ID: the realm URL, or WithServiceProviderEntityID; ACS {Keycloak}/realms/{realm}/broker/{alias}/endpoint).
  /// Identity provider data: WithImportedConfig with the result of ImportConfig(IAM4D_IDP_PROVIDER_SAML,
  /// metadata URL), or WithIdentityProviderEndpoints; the later call wins. WithMetadataURL makes Keycloak read
  /// (and refresh) the signing keys from the metadata: entity ID and single sign-on URL still come from one of
  /// the two.
  /// Defaults: signed requests, signed assertions, signature validation, POST bindings (imported metadata
  /// decides the binding of its endpoints), NameID persistent (or the first format of the imported metadata),
  /// principal = subject NameID.
  /// Build requires the signing certificate of the provider, unless WithMetadataURL; turning a check off takes
  /// DisableRequestSigning, AllowUnsignedAssertions or DisableSignatureValidation.
  /// </remarks>
  IIAM4DSamlIdPBuilder = interface
    ['{A3C61F08-7E25-4B9D-8D40-2F95B6E1C7A2}']
    /// <summary>
    /// Config returned by ImportConfig from the provider metadata (entity ID, endpoints, certificates, NameID
    /// format); replaces the provider data set before, also what the metadata lacks.
    /// </summary>
    function WithImportedConfig(const AConfig: TIAM4DConfigMap): IIAM4DSamlIdPBuilder;
    /// <summary>Metadata URL Keycloak reads and refreshes the signing keys from (useMetadataDescriptorUrl).</summary>
    function WithMetadataURL(const AURL: string): IIAM4DSamlIdPBuilder;
    /// <summary>
    /// Provider data set by hand, POST binding endpoints; replaces the imported one (encryption key and NameID
    /// format included). ASigningCertificate: base64 DER, comma-separated if more than one; empty only with
    /// WithMetadataURL.
    /// </summary>
    function WithIdentityProviderEndpoints(const AEntityID, ASingleSignOnURL, ASigningCertificate: string;
      const ASingleLogoutURL: string = ''): IIAM4DSamlIdPBuilder;
    /// <summary>Service provider entity ID (default: the realm URL).</summary>
    function WithServiceProviderEntityID(const AEntityID: string): IIAM4DSamlIdPBuilder;
    /// <summary>NameID format requested, e.g. IAM4D_SAML_NAMEID_EMAIL; wins over the imported one.</summary>
    function WithNameIDFormat(const AFormat: string): IIAM4DSamlIdPBuilder;
    /// <summary>Brokered user ID: the subject NameID (default) or an attribute (AAttribute required).</summary>
    function WithPrincipal(const AType: TIAM4DSamlPrincipalType; const AAttribute: string = ''): IIAM4DSamlIdPBuilder;
    /// <summary>Default: the alias (Keycloak shows it when the display name is empty).</summary>
    function WithDisplayName(const ADisplayName: string): IIAM4DSamlIdPBuilder;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): IIAM4DSamlIdPBuilder;
    /// <summary>Emails from the provider are considered verified; requires signature validation.</summary>
    function WithTrustEmail(const AValue: Boolean = True): IIAM4DSamlIdPBuilder;
    /// <summary>Hides the provider on the Keycloak login page (reachable with kc_idp_hint only).</summary>
    function WithHideOnLogin(const AValue: Boolean = True): IIAM4DSamlIdPBuilder;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): IIAM4DSamlIdPBuilder;
    /// <summary>
    /// Any other config key of the Keycloak SAML provider (e.g. 'forceAuthn'). Signatures, NameID format and
    /// principal are written by Build: use the dedicated methods.
    /// </summary>
    function WithConfig(const AKey, AValue: string): IIAM4DSamlIdPBuilder;
    /// <summary>AuthnRequests not signed, for providers that do not check them.</summary>
    function DisableRequestSigning: IIAM4DSamlIdPBuilder;
    /// <summary>Accepts assertions without their own signature (the response signature is still validated).</summary>
    function AllowUnsignedAssertions: IIAM4DSamlIdPBuilder;
    /// <summary>No signature validated: anyone can forge a response. Tests only; no WithTrustEmail.</summary>
    function DisableSignatureValidation: IIAM4DSamlIdPBuilder;
    /// <exception cref="EIAM4DInvalidConfigurationException">Raised when entity ID, single sign-on URL or
    /// signing certificate are missing, with a principal attribute missing or a transient NameID for the
    /// subject principal, or with WithTrustEmail and DisableSignatureValidation</exception>
    function Build: TIAM4DIdentityProvider;
  end;

  TIAM4DSamlIdPBuilder = class(TIAM4DSamlIdPBuilderBase, IIAM4DSamlIdPBuilder)
  private
    FNameIDFormat: string;
    FPrincipalType: TIAM4DSamlPrincipalType;
    FPrincipalAttribute: string;
    FRequestSigning: Boolean;
    FAssertionSignature: Boolean;
    FSignatureValidation: Boolean;
  public
    /// <param name="AAlias">Alias of the provider in the realm, e.g. 'adfs'.</param>
    class function New(const AAlias: string): IIAM4DSamlIdPBuilder;
    /// <summary>
    /// Mapper importing an assertion attribute (by name, e.g.
    /// 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress') into a user attribute.
    /// </summary>
    class function AttributeMapper(const AIdentityProviderAlias, AAttributeName,
      AUserAttribute: string): TIAM4DIdentityProviderMapper;

    function WithImportedConfig(const AConfig: TIAM4DConfigMap): IIAM4DSamlIdPBuilder;
    function WithMetadataURL(const AURL: string): IIAM4DSamlIdPBuilder;
    function WithIdentityProviderEndpoints(const AEntityID, ASingleSignOnURL, ASigningCertificate: string;
      const ASingleLogoutURL: string = ''): IIAM4DSamlIdPBuilder;
    function WithServiceProviderEntityID(const AEntityID: string): IIAM4DSamlIdPBuilder;
    function WithNameIDFormat(const AFormat: string): IIAM4DSamlIdPBuilder;
    function WithPrincipal(const AType: TIAM4DSamlPrincipalType; const AAttribute: string = ''): IIAM4DSamlIdPBuilder;
    function WithDisplayName(const ADisplayName: string): IIAM4DSamlIdPBuilder;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): IIAM4DSamlIdPBuilder;
    function WithTrustEmail(const AValue: Boolean = True): IIAM4DSamlIdPBuilder;
    function WithHideOnLogin(const AValue: Boolean = True): IIAM4DSamlIdPBuilder;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): IIAM4DSamlIdPBuilder;
    function WithConfig(const AKey, AValue: string): IIAM4DSamlIdPBuilder;
    function DisableRequestSigning: IIAM4DSamlIdPBuilder;
    function AllowUnsignedAssertions: IIAM4DSamlIdPBuilder;
    function DisableSignatureValidation: IIAM4DSamlIdPBuilder;
    function Build: TIAM4DIdentityProvider;
  end;

  // ==========================================================================
  // SPID and CIE ID (SAML 2.0)
  // ==========================================================================

  /// <summary>
  /// Settings shared by the SPID and CIE builders: SAML defaults required by AgID
  /// (signed requests and assertions, POST bindings, transient NameID, principal = fiscalNumber)
  /// and service provider data published in the metadata.
  /// </summary>
  TIAM4DItalianSamlIdPBuilderBase = class(TIAM4DSamlIdPBuilderBase)
  protected
    /// <summary>Service name stored as '{locale}|{name}' (SPID extension) or as is (CIE extension).</summary>
    FLocalizedServiceName: Boolean;
    procedure Initialize(const AAlias, AProviderID, AProduct: string);
    /// <summary>WithImportedConfig: SetImportedConfig, plus what a builder records about it.</summary>
    procedure ApplyImportedConfig(const AConfig: TIAM4DConfigMap); virtual;
    procedure SetLevel(const ALevel: TIAM4DSpidLevel);
    /// <summary>ALocalized: '{locale}|{name}' (SPID extension); otherwise the name as is (CIE extension).</summary>
    procedure SetAttributeConsumingService(const AIndex: Integer; const AName: string; const ALocalized: Boolean);
    procedure SetOrganization(const AName, ADisplayName, AURL, ALocale: string);
    /// <summary>ACertificateHint: where the signing certificate comes from (error message).</summary>
    function BuildIdentityProvider(const ACertificateHint: string): TIAM4DIdentityProvider;
    /// <summary>'{locale}|{value}': the extensions read comma-separated lists of such pairs.</summary>
    function LocalizedValue(const ALocale, AValue, AWhat: string): string;
  end;

  /// <summary>
  /// With* methods shared by the SPID and CIE builders; I is the builder interface they return.
  /// </summary>
  TIAM4DItalianSamlIdPBuilder<I: IInterface> = class(TIAM4DItalianSamlIdPBuilderBase)
  protected
    /// <summary>Self as the builder interface (result of the fluent methods).</summary>
    function Builder: I; virtual; abstract;
  public
    function WithImportedConfig(const AConfig: TIAM4DConfigMap): I;
    function WithServiceProviderEntityID(const AEntityID: string): I;
    function WithLevel(const ALevel: TIAM4DSpidLevel): I;
    function WithAttributeConsumingService(const AIndex: Integer; const AName: string): I;
    function WithOrganization(const AName, ADisplayName, AURL: string; const ALocale: string = 'it'): I;
    function WithDisplayName(const ADisplayName: string): I;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): I;
    function WithTrustEmail(const AValue: Boolean = True): I;
    function WithHideOnLogin(const AValue: Boolean = True): I;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): I;
    function WithConfig(const AKey, AValue: string): I;
  end;

  /// <summary>
  /// One SPID identity provider (Poste, Aruba, InfoCert, ...): Keycloak needs one instance per
  /// provider, each with its own alias (e.g. 'spid-poste'), all with provider type 'spid-saml'.
  /// </summary>
  /// <remarks>
  /// Requires italia/spid-keycloak-provider. Identity provider data: WithImportedConfig with the result
  /// of IIAM4DIdentityProviderManager.ImportConfig(IAM4D_IDP_PROVIDER_SPID, metadata URL of the AgID
  /// registry), or WithIdentityProviderEndpoints. The service provider metadata to register with AgID
  /// is aggregated for all SPID providers at ServiceProviderMetadataURL; the extension takes
  /// organization and contacts from the first enabled SPID provider in alias order, so set them on each.
  /// Required: WithAttributeConsumingService (the name is the ServiceName of the SP metadata) and the
  /// signing certificate of the identity provider (imported, set by hand, or read by Keycloak from
  /// WithMetadataURL): without it Keycloak rejects every signed response.
  /// Defaults: level SpidL2 (minimum), sync mode FORCE, trust email.
  /// Private service providers: WithPrivateServiceProvider and WithBillingContact (AgID requires the
  /// billing contact in their metadata; the extension writes it only for private service providers).
  /// The identity provider sends only the attributes requested in the SP metadata, which the extension
  /// derives from the mappers: create at least AttributeMapper(Alias, 'fiscalNumber', ...), the principal.
  /// A "SPID only" login: hide the providers (WithHideOnLogin), show the SPID button in the application
  /// and pass the chosen alias as kc_idp_hint.
  /// </remarks>
  IIAM4DSpidIdPBuilder = interface
    ['{7D3A9F16-2B84-4E5C-A0D1-C96E8B274F53}']
    /// <summary>Config returned by ImportConfig from the provider metadata (entity ID, endpoints, certificates).</summary>
    function WithImportedConfig(const AConfig: TIAM4DConfigMap): IIAM4DSpidIdPBuilder;
    /// <summary>Metadata URL Keycloak refreshes the provider data from (e.g. its AgID registry entry).</summary>
    function WithMetadataURL(const AURL: string): IIAM4DSpidIdPBuilder;
    /// <summary>Provider data set by hand. ASigningCertificate: base64 DER, comma-separated if more than one.</summary>
    function WithIdentityProviderEndpoints(const AEntityID, ASingleSignOnURL, ASigningCertificate: string;
      const ASingleLogoutURL: string = ''): IIAM4DSpidIdPBuilder;
    /// <summary>Service provider entity ID (default: the realm URL).</summary>
    function WithServiceProviderEntityID(const AEntityID: string): IIAM4DSpidIdPBuilder;
    function WithLevel(const ALevel: TIAM4DSpidLevel): IIAM4DSpidIdPBuilder;
    /// <summary>Index and name (ServiceName, Italian) of the AttributeConsumingService registered with AgID.</summary>
    function WithAttributeConsumingService(const AIndex: Integer; const AName: string): IIAM4DSpidIdPBuilder;
    function WithOrganization(const AName, ADisplayName, AURL: string; const ALocale: string = 'it'): IIAM4DSpidIdPBuilder;
    /// <summary>Public administration service provider: IPA code and contact.</summary>
    function WithPublicServiceProvider(const AIpaCode, AEmail: string; const APhone: string = ''): IIAM4DSpidIdPBuilder;
    /// <summary>Private service provider: VAT number (e.g. IT12345678901), fiscal code, company and contact.</summary>
    function WithPrivateServiceProvider(const AVatNumber, AFiscalCode, ACompany, AEmail: string;
      const APhone: string = ''): IIAM4DSpidIdPBuilder;
    /// <summary>
    /// Billing contact of a private service provider (AgID invoicing data, fpa:CessionarioCommittente):
    /// company, email and phone of the contact, registered name (Denominazione) and head office.
    /// The fiscal ID is the VAT number of WithPrivateServiceProvider, with the country code (IT12345678901).
    /// </summary>
    function WithBillingContact(const ACompany, AEmail, APhone, ARegisteredName, AAddress, AStreetNumber,
      APostalCode, ACity, AProvince: string; const ACountry: string = 'IT'): IIAM4DSpidIdPBuilder;
    function WithDisplayName(const ADisplayName: string): IIAM4DSpidIdPBuilder;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): IIAM4DSpidIdPBuilder;
    function WithTrustEmail(const AValue: Boolean = True): IIAM4DSpidIdPBuilder;
    function WithHideOnLogin(const AValue: Boolean = True): IIAM4DSpidIdPBuilder;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): IIAM4DSpidIdPBuilder;
    /// <summary>Any other config key of the SPID provider. Build sets wantAuthnRequestsSigned,
    /// wantAssertionsSigned, validateSignature and signSpMetadata back to true: WithConfig cannot turn them off.</summary>
    function WithConfig(const AKey, AValue: string): IIAM4DSpidIdPBuilder;
    /// <exception cref="EIAM4DInvalidConfigurationException">Raised when the identity provider data
    /// (entity ID, single sign-on URL, signing certificate) or the service name is missing, or when a
    /// billing contact is set without a private service provider with a VAT number</exception>
    function Build: TIAM4DIdentityProvider;
  end;

  TIAM4DSpidIdPBuilder = class(TIAM4DItalianSamlIdPBuilder<IIAM4DSpidIdPBuilder>, IIAM4DSpidIdPBuilder)
  protected
    function Builder: IIAM4DSpidIdPBuilder; override;
  public
    /// <param name="AAlias">Alias of this SPID provider, e.g. 'spid-poste'.</param>
    class function New(const AAlias: string): IIAM4DSpidIdPBuilder;
    /// <summary>{KeycloakURL}/realms/{realm}/spid-sp-metadata: service provider metadata for AgID.</summary>
    class function ServiceProviderMetadataURL(const AKeycloakURL, ARealm: string): string;
    /// <summary>Mapper importing a SPID attribute (e.g. 'fiscalNumber', 'email') into a user attribute.</summary>
    class function AttributeMapper(const AIdentityProviderAlias, ASpidAttribute,
      AUserAttribute: string): TIAM4DIdentityProviderMapper;

    function WithMetadataURL(const AURL: string): IIAM4DSpidIdPBuilder;
    function WithIdentityProviderEndpoints(const AEntityID, ASingleSignOnURL, ASigningCertificate: string;
      const ASingleLogoutURL: string = ''): IIAM4DSpidIdPBuilder;
    function WithPublicServiceProvider(const AIpaCode, AEmail: string; const APhone: string = ''): IIAM4DSpidIdPBuilder;
    function WithPrivateServiceProvider(const AVatNumber, AFiscalCode, ACompany, AEmail: string;
      const APhone: string = ''): IIAM4DSpidIdPBuilder;
    function WithBillingContact(const ACompany, AEmail, APhone, ARegisteredName, AAddress, AStreetNumber,
      APostalCode, ACity, AProvince: string; const ACountry: string = 'IT'): IIAM4DSpidIdPBuilder;
    function Build: TIAM4DIdentityProvider;
  end;

  /// <summary>
  /// CIE ID (Carta d'Identita Elettronica) over SAML 2.0: a single identity provider.
  /// </summary>
  /// <remarks>
  /// Requires lscorcia/keycloak-cieid-provider. WithEnvironment sets entity ID, endpoints and metadata
  /// URL of the production (default) or pre-production identity server; the signing certificate comes
  /// from WithImportedConfig (ImportConfig(IAM4D_IDP_PROVIDER_CIE, MetadataURL(...))).
  /// WithEnvironment and WithImportedConfig can come in any order, but the imported metadata must be of
  /// the chosen identity server (MetadataURL(cePreProduction) for pre-production): Build raises otherwise.
  /// Without WithEnvironment the imported metadata decides the identity server (e.g. a local test one).
  /// The service provider metadata to register is at ServiceProviderMetadataURL.
  /// Required: WithAttributeConsumingService (the name is the ServiceName of the SP metadata) and the
  /// signing certificate (WithImportedConfig), unless config useMetadataDescriptorUrl is true.
  /// Defaults: level SpidL2 (minimum), sync mode FORCE, trust email.
  /// The SP metadata requests the attributes of the mappers: create at least
  /// AttributeMapper(Alias, 'fiscalNumber', ...), the principal.
  /// </remarks>
  IIAM4DCieIdPBuilder = interface
    ['{E4B80C27-9D51-4A6F-8B3E-15F7A2C9D064}']
    function WithEnvironment(const AEnvironment: TIAM4DCieEnvironment): IIAM4DCieIdPBuilder;
    function WithImportedConfig(const AConfig: TIAM4DConfigMap): IIAM4DCieIdPBuilder;
    function WithServiceProviderEntityID(const AEntityID: string): IIAM4DCieIdPBuilder;
    function WithLevel(const ALevel: TIAM4DSpidLevel): IIAM4DCieIdPBuilder;
    /// <summary>Index and name (ServiceName, stored as is: the CIE extension has no locale) of the
    /// AttributeConsumingService.</summary>
    function WithAttributeConsumingService(const AIndex: Integer; const AName: string): IIAM4DCieIdPBuilder;
    function WithOrganization(const AName, ADisplayName, AURL: string; const ALocale: string = 'it'): IIAM4DCieIdPBuilder;
    /// <summary>Public administration: administrative contact with IPA code and category.</summary>
    function WithPublicServiceProvider(const ACompany, AIpaCode, AIpaCategory, AEmail: string;
      const APhone: string = ''): IIAM4DCieIdPBuilder;
    /// <summary>Private service provider: administrative contact with VAT number and fiscal code.</summary>
    function WithPrivateServiceProvider(const ACompany, AVatNumber, AFiscalCode, AEmail: string;
      const APhone: string = ''): IIAM4DCieIdPBuilder;
    function WithTechnicalContact(const ACompany, AVatNumber, AFiscalCode, AEmail: string;
      const APhone: string = ''): IIAM4DCieIdPBuilder;
    function WithDisplayName(const ADisplayName: string): IIAM4DCieIdPBuilder;
    function WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): IIAM4DCieIdPBuilder;
    function WithTrustEmail(const AValue: Boolean = True): IIAM4DCieIdPBuilder;
    function WithHideOnLogin(const AValue: Boolean = True): IIAM4DCieIdPBuilder;
    function WithFirstBrokerLoginFlow(const AFlowAlias: string): IIAM4DCieIdPBuilder;
    /// <summary>Any other config key of the CIE provider. Build sets wantAuthnRequestsSigned,
    /// wantAssertionsSigned, validateSignature and signSpMetadata back to true: WithConfig cannot turn them off.</summary>
    function WithConfig(const AKey, AValue: string): IIAM4DCieIdPBuilder;
    /// <exception cref="EIAM4DInvalidConfigurationException">Raised when the signing certificate or the
    /// service name is missing, or when the imported metadata is of another identity server</exception>
    function Build: TIAM4DIdentityProvider;
  end;

  TIAM4DCieIdPBuilder = class(TIAM4DItalianSamlIdPBuilder<IIAM4DCieIdPBuilder>, IIAM4DCieIdPBuilder)
  private
    FEnvironment: TIAM4DCieEnvironment;
    FEnvironmentSet: Boolean;
    FImported: Boolean;
    FImportedConfig: TIAM4DConfigMap;
    procedure ApplyEnvironment(const AEnvironment: TIAM4DCieEnvironment);
  protected
    function Builder: IIAM4DCieIdPBuilder; override;
    procedure ApplyImportedConfig(const AConfig: TIAM4DConfigMap); override;
  public
    class function New(const AAlias: string = IAM4D_IDP_ALIAS_CIE): IIAM4DCieIdPBuilder;
    /// <summary>Identity server metadata, for ImportConfig.</summary>
    class function MetadataURL(const AEnvironment: TIAM4DCieEnvironment = ceProduction): string;
    /// <summary>{KeycloakURL}/realms/{realm}/cieid-sp-metadata: service provider metadata to register.</summary>
    class function ServiceProviderMetadataURL(const AKeycloakURL, ARealm: string): string;
    /// <summary>Mapper importing a CIE ID attribute (e.g. 'fiscalNumber', 'familyName') into a user attribute.</summary>
    class function AttributeMapper(const AIdentityProviderAlias, ACieAttribute,
      AUserAttribute: string): TIAM4DIdentityProviderMapper;

    function WithEnvironment(const AEnvironment: TIAM4DCieEnvironment): IIAM4DCieIdPBuilder;
    function WithPublicServiceProvider(const ACompany, AIpaCode, AIpaCategory, AEmail: string;
      const APhone: string = ''): IIAM4DCieIdPBuilder;
    function WithPrivateServiceProvider(const ACompany, AVatNumber, AFiscalCode, AEmail: string;
      const APhone: string = ''): IIAM4DCieIdPBuilder;
    function WithTechnicalContact(const ACompany, AVatNumber, AFiscalCode, AEmail: string;
      const APhone: string = ''): IIAM4DCieIdPBuilder;
    function Build: TIAM4DIdentityProvider;
  end;

implementation

uses
  System.StrUtils,
  System.RegularExpressions,
  IAMClient4D.Exceptions;

const
  CEntraLoginHost = 'https://login.microsoftonline.com/';
  CEntraUserInfoURL = 'https://graph.microsoft.com/oidc/userinfo';
  CGitLabIssuer = 'https://gitlab.com';

  COidcClientAuthMethods: array[TIAM4DOidcClientAuthMethod] of string = (
    'client_secret_post', 'client_secret_basic', 'private_key_jwt', 'client_secret_jwt');
  CSamlPrincipalTypes: array[TIAM4DSamlPrincipalType] of string = ('SUBJECT', 'ATTRIBUTE', 'FRIENDLY_ATTRIBUTE');

  // JWS algorithms of the client assertion: realm key (private_key_jwt) or client secret (client_secret_jwt)
  CPrivateKeyJwtAlgorithms: array[0..9] of string = (
    'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA');
  CClientSecretJwtAlgorithms: array[0..2] of string = ('HS256', 'HS384', 'HS512');

  // Provider side of the imported config: replaced as a whole (see ImportKeys)
  COidcImportedKeys: array[0..7] of string = ('authorizationUrl', 'tokenUrl', 'userInfoUrl', 'jwksUrl', 'logoutUrl',
    'issuer', 'tokenIntrospectionUrl', 'metadataDescriptorUrl');
  COAuth2ImportedKeys: array[0..3] of string = ('authorizationUrl', 'tokenUrl', 'userInfoUrl', 'tokenIntrospectionUrl');
  CSamlImportedKeys: array[0..4] of string = ('idpEntityId', 'singleSignOnServiceUrl', 'singleLogoutServiceUrl',
    'signingCertificate', 'encryptionPublicKey');

  CCieHost: array[TIAM4DCieEnvironment] of string = (
    'https://idserver.servizicie.interno.gov.it',
    'https://preproduzione.idserver.servizicie.interno.gov.it');

procedure CheckAlias(const AAlias: string);
begin
  if AAlias.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Identity provider alias cannot be empty');
  if not TRegEx.IsMatch(AAlias, '^[A-Za-z0-9._\-]+$') then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      'Identity provider alias "%s": use letters, digits, ".", "_" and "-" only', [AAlias]));
end;

function IsGUID(const AValue: string): Boolean;
begin
  Result := TRegEx.IsMatch(AValue, '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$');
end;

function RealmURL(const AKeycloakURL, ARealm: string): string;
begin
  Result := AKeycloakURL.Trim.TrimRight(['/']) + '/realms/' + ARealm.Trim;
end;

function CieEntityID(const AEnvironment: TIAM4DCieEnvironment): string;
begin
  // The identity server entity ID is its POST single sign-on URL
  Result := CCieHost[AEnvironment] + '/idp/profile/SAML2/POST/SSO';
end;

// ATarget with the AKeys of AConfig: the keys AConfig lacks are removed, so nothing of a previous provider remains
function ImportKeys(const ATarget, AConfig: TIAM4DConfigMap; const AKeys: array of string): TIAM4DConfigMap;
var
  LKey: string;
  LEntry: TIAM4DConfigEntry;
begin
  Result := ATarget;
  for LKey in AKeys do
    if not AConfig.Contains(LKey) then
      Result.Remove(LKey);
  for LEntry in AConfig.Entries do
    if MatchStr(LEntry.Key, AKeys) then
      Result.Values[LEntry.Key] := LEntry.Value;
end;

// Mapper of the social providers: a field of the user profile JSON into a user attribute
function JsonAttributeMapper(const AMapperType, AIdentityProviderAlias, AJsonField,
  AUserAttribute: string): TIAM4DIdentityProviderMapper;
begin
  Result := TIAM4DIdentityProviderMapper.Create(AIdentityProviderAlias, AJsonField, AMapperType);
  Result.Config.Values['syncMode'] := 'INHERIT';
  Result.Config.Values['jsonField'] := AJsonField;
  Result.Config.Values['userAttribute'] := AUserAttribute;
end;

// Mapper of the SAML providers: an assertion attribute into a user attribute
function SamlAttributeMapper(const AMapperType, AIdentityProviderAlias, AAttributeName,
  AUserAttribute: string): TIAM4DIdentityProviderMapper;
begin
  Result := TIAM4DIdentityProviderMapper.Create(AIdentityProviderAlias, AAttributeName, AMapperType);
  Result.Config.Values['syncMode'] := 'INHERIT';
  Result.Config.Values['attribute.name'] := AAttributeName;
  Result.Config.Values['user.attribute'] := AUserAttribute;
end;

{ TIAM4DSpidLevelHelper }

function TIAM4DSpidLevelHelper.ToURI: string;
const
  CLevels: array[TIAM4DSpidLevel] of string = ('SpidL1', 'SpidL2', 'SpidL3');
begin
  Result := 'https://www.spid.gov.it/' + CLevels[Self];
end;

{ TIAM4DOidcIdPBuilderBase }

procedure TIAM4DOidcIdPBuilderBase.Initialize(const AAlias, AProviderID, AProduct, ADisplayName: string);
begin
  FProduct := AProduct;
  FIdentityProvider := TIAM4DIdentityProvider.Create(AAlias, AProviderID);
  FIdentityProvider.DisplayName := ADisplayName;
  FIdToken := AProviderID <> IAM4D_IDP_PROVIDER_OAUTH2;
  if FIdToken then
    FScopes := ['openid', 'profile', 'email']
  else
    FScopes := [];
  FClientAuthMethod := ocaClientSecretPost;
  FIssuerCheck := FIdToken;
  FSignatureValidation := FIdToken;
  FPkce := True;
end;

procedure TIAM4DOidcIdPBuilderBase.InitializeSocial(const AAlias, AProviderID, AProduct: string;
  const AScopes: TArray<string>; const APkce: Boolean);
begin
  FProduct := AProduct;
  FIdentityProvider := TIAM4DIdentityProvider.Create(AAlias, AProviderID);
  FIdentityProvider.DisplayName := AProduct;
  FScopes := AScopes;
  FClientAuthMethod := ocaClientSecretPost;
  FPkce := APkce;
end;

procedure TIAM4DOidcIdPBuilderBase.SetClient(const AClientID, AClientSecret: string);
begin
  FIdentityProvider.Config.Values['clientId'] := AClientID.Trim;
  FIdentityProvider.Config.Values['clientSecret'] := AClientSecret;
end;

procedure TIAM4DOidcIdPBuilderBase.SetClientAuthMethod(const AMethod: TIAM4DOidcClientAuthMethod;
  const ASigningAlgorithm: string);
begin
  FClientAuthMethod := AMethod;
  FClientAssertionSigningAlg := ASigningAlgorithm.Trim;
end;

procedure TIAM4DOidcIdPBuilderBase.CheckClient;
begin
  if FIdentityProvider.Config.Values['clientId'].IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(Format('%s: client ID is required', [FProduct]));
  // private_key_jwt signs with a realm key: no secret
  if (FClientAuthMethod <> ocaPrivateKeyJwt) and FIdentityProvider.Config.Values['clientSecret'].IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(Format('%s: client secret is required', [FProduct]));
end;

function TIAM4DOidcIdPBuilderBase.BuildIdentityProvider: TIAM4DIdentityProvider;
var
  LConfig: TIAM4DConfigMap;
begin
  // A signing algorithm without a JWT method would be ignored by Keycloak: say so
  if not FClientAssertionSigningAlg.IsEmpty and not (FClientAuthMethod in [ocaPrivateKeyJwt, ocaClientSecretJwt]) then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      '%s "%s": a client assertion signing algorithm needs private_key_jwt or client_secret_jwt',
      [FProduct, FIdentityProvider.Alias]));
  // Keycloak signs with a realm key (private_key_jwt) or with the secret (client_secret_jwt): the other
  // family fails at every login
  if (FClientAuthMethod = ocaPrivateKeyJwt) and not FClientAssertionSigningAlg.IsEmpty and
     not MatchStr(FClientAssertionSigningAlg, CPrivateKeyJwtAlgorithms) then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      '%s "%s": private_key_jwt signs with a realm key, not with "%s" (%s)',
      [FProduct, FIdentityProvider.Alias, FClientAssertionSigningAlg, string.Join(', ', CPrivateKeyJwtAlgorithms)]));
  if (FClientAuthMethod = ocaClientSecretJwt) and not FClientAssertionSigningAlg.IsEmpty and
     not MatchStr(FClientAssertionSigningAlg, CClientSecretJwtAlgorithms) then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      '%s "%s": client_secret_jwt signs with the client secret, not with "%s" (%s)',
      [FProduct, FIdentityProvider.Alias, FClientAssertionSigningAlg, string.Join(', ', CClientSecretJwtAlgorithms)]));
  CheckAlias(FIdentityProvider.Alias);
  CheckClient;
  LConfig := FIdentityProvider.Config;
  if LConfig.Values['authorizationUrl'].Trim.IsEmpty or LConfig.Values['tokenUrl'].Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      '%s "%s": authorization and token URLs are required (WithImportedConfig or WithEndpoints)',
      [FProduct, FIdentityProvider.Alias]));
  // OAuth 2.0: the profile comes only from the user info endpoint (Keycloak rejects the provider without it)
  if not FIdToken and LConfig.Values['userInfoUrl'].Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      '%s "%s": user info URL is required, the user profile comes from it (WithImportedConfig or WithEndpoints)',
      [FProduct, FIdentityProvider.Alias]));
  // Without it Keycloak accepts tokens of any issuer the keys validate
  if FIssuerCheck and LConfig.Values['issuer'].Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      '%s "%s": issuer is required (WithImportedConfig or WithIssuer; DisableIssuerCheck to accept any)',
      [FProduct, FIdentityProvider.Alias]));
  if FSignatureValidation and LConfig.Values['jwksUrl'].Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      '%s "%s": JWKS URL is required to validate the token signatures (WithImportedConfig or WithJwksURL; ' +
      'DisableSignatureValidation to skip it)', [FProduct, FIdentityProvider.Alias]));
  // nOAuth: without the issuer check another issuer could send an unverified email of an existing user
  if FIdToken and FIdentityProvider.TrustEmail and not FIssuerCheck then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      '%s "%s": WithTrustEmail requires the issuer check', [FProduct, FIdentityProvider.Alias]));
  // Same with an unsigned token (e.g. through token exchange): any email could be claimed
  if FIdToken and FIdentityProvider.TrustEmail and not FSignatureValidation then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      '%s "%s": WithTrustEmail requires signature validation', [FProduct, FIdentityProvider.Alias]));

  Result := FIdentityProvider;
  if not FIssuerCheck then
    Result.Config.Remove('issuer');
  Result.Config.Values['clientAuthMethod'] := COidcClientAuthMethods[FClientAuthMethod];
  if not FClientAssertionSigningAlg.IsEmpty then
    Result.Config.Values['clientAssertionSigningAlg'] := FClientAssertionSigningAlg;
  if FIdToken then
  begin
    Result.Config.Values['defaultScope'] := string.Join(' ', FScopes);
    Result.Config.SetBool('validateSignature', FSignatureValidation);
    Result.Config.SetBool('useJwksUrl', True);
  end
  else if Length(FScopes) = 0 then
    Result.Config.Remove('defaultScope')
  else
    Result.Config.Values['defaultScope'] := string.Join(' ', FScopes);
  Result.Config.SetBool('pkceEnabled', FPkce);
  if FPkce then
    Result.Config.Values['pkceMethod'] := 'S256'
  else
    Result.Config.Remove('pkceMethod');
end;

function TIAM4DOidcIdPBuilderBase.BuildSocialIdentityProvider: TIAM4DIdentityProvider;
var
  LScopes: string;
begin
  CheckAlias(FIdentityProvider.Alias);
  CheckClient;

  Result := FIdentityProvider;
  // Single spaces: an element may hold several scopes
  LScopes := string.Join(' ', string.Join(' ', FScopes).Split([' '], TStringSplitOptions.ExcludeEmpty));
  if LScopes.IsEmpty then
    Result.Config.Remove('defaultScope')
  else
    Result.Config.Values['defaultScope'] := LScopes;
  // Providers without PKCE: config left as is
  if FPkce then
  begin
    Result.Config.SetBool('pkceEnabled', True);
    Result.Config.Values['pkceMethod'] := 'S256';
  end;
end;

{ TIAM4DOidcIdPBuilderCommon<I> }

function TIAM4DOidcIdPBuilderCommon<I>.WithClient(const AClientID, AClientSecret: string): I;
begin
  SetClient(AClientID, AClientSecret);
  Result := Builder;
end;

function TIAM4DOidcIdPBuilderCommon<I>.WithDisplayName(const ADisplayName: string): I;
begin
  FIdentityProvider.DisplayName := ADisplayName;
  Result := Builder;
end;

function TIAM4DOidcIdPBuilderCommon<I>.WithScopes(const AScopes: TArray<string>): I;
begin
  FScopes := Copy(AScopes);
  Result := Builder;
end;

function TIAM4DOidcIdPBuilderCommon<I>.WithPrompt(const APrompt: string): I;
begin
  FIdentityProvider.Config.Values['prompt'] := APrompt.Trim;
  Result := Builder;
end;

function TIAM4DOidcIdPBuilderCommon<I>.WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): I;
begin
  FIdentityProvider.SyncMode := ASyncMode;
  Result := Builder;
end;

function TIAM4DOidcIdPBuilderCommon<I>.WithTrustEmail(const AValue: Boolean): I;
begin
  FIdentityProvider.TrustEmail := AValue;
  Result := Builder;
end;

function TIAM4DOidcIdPBuilderCommon<I>.WithHideOnLogin(const AValue: Boolean): I;
begin
  FIdentityProvider.HideOnLogin := AValue;
  Result := Builder;
end;

function TIAM4DOidcIdPBuilderCommon<I>.WithFirstBrokerLoginFlow(const AFlowAlias: string): I;
begin
  FIdentityProvider.FirstBrokerLoginFlowAlias := AFlowAlias;
  Result := Builder;
end;

function TIAM4DOidcIdPBuilderCommon<I>.WithConfig(const AKey, AValue: string): I;
begin
  FIdentityProvider.Config.Values[AKey] := AValue;
  Result := Builder;
end;

{ TIAM4DOidcIdPBuilder }

class function TIAM4DOidcIdPBuilder.New(const AAlias: string): IIAM4DOidcIdPBuilder;
var
  LBuilder: TIAM4DOidcIdPBuilder;
begin
  LBuilder := TIAM4DOidcIdPBuilder.Create;
  LBuilder.Initialize(AAlias, IAM4D_IDP_PROVIDER_OIDC, 'OpenID Connect', '');
  Result := LBuilder;
end;

function TIAM4DOidcIdPBuilder.Builder: IIAM4DOidcIdPBuilder;
begin
  Result := Self;
end;

function TIAM4DOidcIdPBuilder.WithImportedConfig(const AConfig: TIAM4DConfigMap): IIAM4DOidcIdPBuilder;
begin
  // Only the provider side: client and security settings stay the builder's
  FIdentityProvider.Config := ImportKeys(FIdentityProvider.Config, AConfig, COidcImportedKeys);
  Result := Self;
end;

function TIAM4DOidcIdPBuilder.WithEndpoints(const AAuthorizationURL, ATokenURL, AUserInfoURL,
  ALogoutURL: string): IIAM4DOidcIdPBuilder;
begin
  FIdentityProvider.Config.Values['authorizationUrl'] := AAuthorizationURL.Trim;
  FIdentityProvider.Config.Values['tokenUrl'] := ATokenURL.Trim;
  if AUserInfoURL.Trim.IsEmpty then
    FIdentityProvider.Config.Remove('userInfoUrl')
  else
    FIdentityProvider.Config.Values['userInfoUrl'] := AUserInfoURL.Trim;
  if ALogoutURL.Trim.IsEmpty then
    FIdentityProvider.Config.Remove('logoutUrl')
  else
    FIdentityProvider.Config.Values['logoutUrl'] := ALogoutURL.Trim;
  Result := Self;
end;

function TIAM4DOidcIdPBuilder.WithJwksURL(const AURL: string): IIAM4DOidcIdPBuilder;
begin
  FIdentityProvider.Config.Values['jwksUrl'] := AURL.Trim;
  Result := Self;
end;

function TIAM4DOidcIdPBuilder.WithIssuer(const AIssuer: string): IIAM4DOidcIdPBuilder;
begin
  FIdentityProvider.Config.Values['issuer'] := AIssuer.Trim;
  Result := Self;
end;

function TIAM4DOidcIdPBuilder.WithClientAuthMethod(const AMethod: TIAM4DOidcClientAuthMethod;
  const ASigningAlgorithm: string): IIAM4DOidcIdPBuilder;
begin
  SetClientAuthMethod(AMethod, ASigningAlgorithm);
  Result := Self;
end;

function TIAM4DOidcIdPBuilder.DisableIssuerCheck: IIAM4DOidcIdPBuilder;
begin
  FIssuerCheck := False;
  Result := Self;
end;

function TIAM4DOidcIdPBuilder.DisableSignatureValidation: IIAM4DOidcIdPBuilder;
begin
  FSignatureValidation := False;
  Result := Self;
end;

function TIAM4DOidcIdPBuilder.DisablePkce: IIAM4DOidcIdPBuilder;
begin
  FPkce := False;
  Result := Self;
end;

function TIAM4DOidcIdPBuilder.Build: TIAM4DIdentityProvider;
begin
  Result := BuildIdentityProvider;
end;

{ TIAM4DEntraIdPBuilder }

class function TIAM4DEntraIdPBuilder.New(const AAlias: string): IIAM4DEntraIdPBuilder;
var
  LBuilder: TIAM4DEntraIdPBuilder;
begin
  LBuilder := TIAM4DEntraIdPBuilder.Create;
  LBuilder.Initialize(AAlias, IAM4D_IDP_PROVIDER_OIDC, 'Entra ID', 'Microsoft');
  Result := LBuilder;
end;

function TIAM4DEntraIdPBuilder.Builder: IIAM4DEntraIdPBuilder;
begin
  Result := Self;
end;

function TIAM4DEntraIdPBuilder.WithTenant(const ATenant: string): IIAM4DEntraIdPBuilder;
begin
  FTenant := ATenant.Trim;
  Result := Self;
end;

function TIAM4DEntraIdPBuilder.Build: TIAM4DIdentityProvider;
var
  LBase: string;
begin
  CheckAlias(FIdentityProvider.Alias);
  if FTenant.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('Entra ID: tenant is required (directory ID, domain or "organizations")');
  if not TRegEx.IsMatch(FTenant, '^[A-Za-z0-9.\-]+$') then
    raise EIAM4DInvalidConfigurationException.Create(Format('Entra ID: invalid tenant "%s"', [FTenant]));
  CheckClient;
  // nOAuth: without the issuer check any tenant can send an unverified email of an existing user
  if FIdentityProvider.TrustEmail and not IsGUID(FTenant) then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      'Entra ID: WithTrustEmail requires the directory ID (GUID) as tenant, not "%s": with a multi-tenant or ' +
      'domain tenant the issuer is not checked and Microsoft does not verify the email claim', [FTenant]));

  LBase := CEntraLoginHost + FTenant;
  FIdentityProvider.Config.Values['authorizationUrl'] := LBase + '/oauth2/v2.0/authorize';
  FIdentityProvider.Config.Values['tokenUrl'] := LBase + '/oauth2/v2.0/token';
  FIdentityProvider.Config.Values['logoutUrl'] := LBase + '/oauth2/v2.0/logout';
  FIdentityProvider.Config.Values['jwksUrl'] := LBase + '/discovery/v2.0/keys';
  FIdentityProvider.Config.Values['userInfoUrl'] := CEntraUserInfoURL;
  // Tokens carry the directory ID: the issuer is known only when the tenant is that ID
  FIssuerCheck := IsGUID(FTenant);
  if FIssuerCheck then
    FIdentityProvider.Config.Values['issuer'] := LBase + '/v2.0'
  else
    FIdentityProvider.Config.Remove('issuer');
  Result := BuildIdentityProvider;
end;

{ TIAM4DOAuth2IdPBuilder }

class function TIAM4DOAuth2IdPBuilder.New(const AAlias: string): IIAM4DOAuth2IdPBuilder;
var
  LBuilder: TIAM4DOAuth2IdPBuilder;
begin
  LBuilder := TIAM4DOAuth2IdPBuilder.Create;
  LBuilder.Initialize(AAlias, IAM4D_IDP_PROVIDER_OAUTH2, 'OAuth 2.0', '');
  Result := LBuilder;
end;

function TIAM4DOAuth2IdPBuilder.Builder: IIAM4DOAuth2IdPBuilder;
begin
  Result := Self;
end;

procedure TIAM4DOAuth2IdPBuilder.SetClaim(const AKey, AValue: string);
begin
  // Empty: Keycloak default claim name
  if AValue.Trim.IsEmpty then
    FIdentityProvider.Config.Remove(AKey)
  else
    FIdentityProvider.Config.Values[AKey] := AValue.Trim;
end;

function TIAM4DOAuth2IdPBuilder.WithImportedConfig(const AConfig: TIAM4DConfigMap): IIAM4DOAuth2IdPBuilder;
begin
  // Endpoints only: no id_token, so no issuer nor JWKS
  FIdentityProvider.Config := ImportKeys(FIdentityProvider.Config, AConfig, COAuth2ImportedKeys);
  Result := Self;
end;

function TIAM4DOAuth2IdPBuilder.WithEndpoints(const AAuthorizationURL, ATokenURL,
  AUserInfoURL: string): IIAM4DOAuth2IdPBuilder;
begin
  FIdentityProvider.Config.Values['authorizationUrl'] := AAuthorizationURL.Trim;
  FIdentityProvider.Config.Values['tokenUrl'] := ATokenURL.Trim;
  FIdentityProvider.Config.Values['userInfoUrl'] := AUserInfoURL.Trim;
  Result := Self;
end;

function TIAM4DOAuth2IdPBuilder.WithUserProfileClaims(const AUserID, AUserName,
  AEmail: string): IIAM4DOAuth2IdPBuilder;
begin
  SetClaim('userIDClaim', AUserID);
  SetClaim('userNameClaim', AUserName);
  SetClaim('emailClaim', AEmail);
  Result := Self;
end;

function TIAM4DOAuth2IdPBuilder.WithNameClaims(const AFullName, AGivenName,
  AFamilyName: string): IIAM4DOAuth2IdPBuilder;
begin
  SetClaim('fullNameClaim', AFullName);
  SetClaim('givenNameClaim', AGivenName);
  SetClaim('familyNameClaim', AFamilyName);
  Result := Self;
end;

function TIAM4DOAuth2IdPBuilder.WithClientAuthMethod(const AMethod: TIAM4DOidcClientAuthMethod;
  const ASigningAlgorithm: string): IIAM4DOAuth2IdPBuilder;
begin
  SetClientAuthMethod(AMethod, ASigningAlgorithm);
  Result := Self;
end;

function TIAM4DOAuth2IdPBuilder.DisablePkce: IIAM4DOAuth2IdPBuilder;
begin
  FPkce := False;
  Result := Self;
end;

function TIAM4DOAuth2IdPBuilder.Build: TIAM4DIdentityProvider;
begin
  Result := BuildIdentityProvider;
end;

{ TIAM4DGoogleIdPBuilder }

class function TIAM4DGoogleIdPBuilder.New(const AAlias: string): IIAM4DGoogleIdPBuilder;
var
  LBuilder: TIAM4DGoogleIdPBuilder;
begin
  LBuilder := TIAM4DGoogleIdPBuilder.Create;
  LBuilder.InitializeSocial(AAlias, IAM4D_IDP_PROVIDER_GOOGLE, 'Google', ['openid', 'profile', 'email'], True);
  Result := LBuilder;
end;

class function TIAM4DGoogleIdPBuilder.AttributeMapper(const AIdentityProviderAlias, AJsonField,
  AUserAttribute: string): TIAM4DIdentityProviderMapper;
begin
  Result := JsonAttributeMapper(IAM4D_IDP_MAPPER_GOOGLE_ATTRIBUTE, AIdentityProviderAlias, AJsonField, AUserAttribute);
end;

function TIAM4DGoogleIdPBuilder.Builder: IIAM4DGoogleIdPBuilder;
begin
  Result := Self;
end;

function TIAM4DGoogleIdPBuilder.WithHostedDomains(const ADomains: TArray<string>): IIAM4DGoogleIdPBuilder;
begin
  FHostedDomains := Copy(ADomains);
  Result := Self;
end;

function TIAM4DGoogleIdPBuilder.Build: TIAM4DIdentityProvider;
var
  LDomains: TArray<string>;
  LDomain: string;
begin
  LDomains := [];
  // '*': any Google Workspace domain; Keycloak takes it only as the whole value
  if (Length(FHostedDomains) = 1) and (FHostedDomains[0].Trim = '*') then
    LDomains := ['*']
  else
    for LDomain in FHostedDomains do
    begin
      // Keycloak compares each entry as is with the hd claim, which Google sends in lower case
      if not TRegEx.IsMatch(LDomain.Trim, '^[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$') then
        raise EIAM4DInvalidConfigurationException.Create(Format('Google: invalid hosted domain "%s"', [LDomain]));
      LDomains := LDomains + [LDomain.Trim.ToLower];
    end;

  Result := BuildSocialIdentityProvider;
  // Comma-separated, no spaces: Keycloak splits on the comma only
  if Length(LDomains) = 0 then
    Result.Config.Remove('hostedDomain')
  else
    Result.Config.Values['hostedDomain'] := string.Join(',', LDomains);
end;

{ TIAM4DFacebookIdPBuilder }

class function TIAM4DFacebookIdPBuilder.New(const AAlias: string): IIAM4DFacebookIdPBuilder;
var
  LBuilder: TIAM4DFacebookIdPBuilder;
begin
  LBuilder := TIAM4DFacebookIdPBuilder.Create;
  LBuilder.InitializeSocial(AAlias, IAM4D_IDP_PROVIDER_FACEBOOK, 'Facebook', ['email', 'public_profile'], False);
  Result := LBuilder;
end;

class function TIAM4DFacebookIdPBuilder.AttributeMapper(const AIdentityProviderAlias, AJsonField,
  AUserAttribute: string): TIAM4DIdentityProviderMapper;
begin
  Result := JsonAttributeMapper(IAM4D_IDP_MAPPER_FACEBOOK_ATTRIBUTE, AIdentityProviderAlias, AJsonField, AUserAttribute);
end;

function TIAM4DFacebookIdPBuilder.Builder: IIAM4DFacebookIdPBuilder;
begin
  Result := Self;
end;

function TIAM4DFacebookIdPBuilder.WithFetchedFields(const AFields: TArray<string>): IIAM4DFacebookIdPBuilder;
begin
  FFetchedFields := Copy(AFields);
  Result := Self;
end;

function TIAM4DFacebookIdPBuilder.Build: TIAM4DIdentityProvider;
var
  LFields: TArray<string>;
  LField: string;
begin
  LFields := [];
  for LField in FFetchedFields do
  begin
    // Keycloak appends the list to the fields parameter of the Graph API URL as is
    if not TRegEx.IsMatch(LField.Trim, '^[A-Za-z0-9_.(){},]+$') then
      raise EIAM4DInvalidConfigurationException.Create(Format('Facebook: invalid fetched field "%s"', [LField]));
    LFields := LFields + [LField.Trim];
  end;

  Result := BuildSocialIdentityProvider;
  if Length(LFields) = 0 then
    Result.Config.Remove('fetchedFields')
  else
    Result.Config.Values['fetchedFields'] := string.Join(',', LFields);
end;

{ TIAM4DMicrosoftIdPBuilder }

class function TIAM4DMicrosoftIdPBuilder.New(const AAlias: string): IIAM4DMicrosoftIdPBuilder;
var
  LBuilder: TIAM4DMicrosoftIdPBuilder;
begin
  LBuilder := TIAM4DMicrosoftIdPBuilder.Create;
  LBuilder.InitializeSocial(AAlias, IAM4D_IDP_PROVIDER_MICROSOFT, 'Microsoft', ['User.Read'], True);
  LBuilder.FTenant := 'consumers';
  Result := LBuilder;
end;

class function TIAM4DMicrosoftIdPBuilder.AttributeMapper(const AIdentityProviderAlias, AJsonField,
  AUserAttribute: string): TIAM4DIdentityProviderMapper;
begin
  Result := JsonAttributeMapper(IAM4D_IDP_MAPPER_MICROSOFT_ATTRIBUTE, AIdentityProviderAlias, AJsonField, AUserAttribute);
end;

function TIAM4DMicrosoftIdPBuilder.Builder: IIAM4DMicrosoftIdPBuilder;
begin
  Result := Self;
end;

function TIAM4DMicrosoftIdPBuilder.WithTenant(const ATenant: string): IIAM4DMicrosoftIdPBuilder;
begin
  FTenant := ATenant.Trim;
  if FTenant.IsEmpty then
    FTenant := 'consumers';
  Result := Self;
end;

function TIAM4DMicrosoftIdPBuilder.Build: TIAM4DIdentityProvider;
begin
  // Keycloak puts the tenant in the endpoint URLs as is
  if not TRegEx.IsMatch(FTenant, '^[A-Za-z0-9.\-]+$') then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      'Microsoft: invalid tenant "%s" (consumers, common, organizations or a directory ID)', [FTenant]));
  // nOAuth: Keycloak trusts mail/userPrincipalName from Graph; only one tenant controls them with a directory ID
  if FIdentityProvider.TrustEmail and not IsGUID(FTenant) then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      'Microsoft: WithTrustEmail requires the directory ID (GUID) as tenant, not "%s": Keycloak takes the email ' +
      'from Microsoft Graph without any check', [FTenant]));

  Result := BuildSocialIdentityProvider;
  Result.Config.Values['tenantId'] := FTenant;
end;

{ TIAM4DLinkedInIdPBuilder }

class function TIAM4DLinkedInIdPBuilder.New(const AAlias: string): IIAM4DLinkedInIdPBuilder;
var
  LBuilder: TIAM4DLinkedInIdPBuilder;
begin
  LBuilder := TIAM4DLinkedInIdPBuilder.Create;
  LBuilder.InitializeSocial(AAlias, IAM4D_IDP_PROVIDER_LINKEDIN, 'LinkedIn', ['openid', 'profile', 'email'], False);
  Result := LBuilder;
end;

class function TIAM4DLinkedInIdPBuilder.AttributeMapper(const AIdentityProviderAlias, AJsonField,
  AUserAttribute: string): TIAM4DIdentityProviderMapper;
begin
  Result := JsonAttributeMapper(IAM4D_IDP_MAPPER_LINKEDIN_ATTRIBUTE, AIdentityProviderAlias, AJsonField, AUserAttribute);
end;

function TIAM4DLinkedInIdPBuilder.Builder: IIAM4DLinkedInIdPBuilder;
begin
  Result := Self;
end;

function TIAM4DLinkedInIdPBuilder.Build: TIAM4DIdentityProvider;
begin
  // Endpoints, issuer and signature validation: Keycloak forces them from the LinkedIn discovery document
  Result := BuildSocialIdentityProvider;
end;

{ TIAM4DGitHubIdPBuilder }

class function TIAM4DGitHubIdPBuilder.New(const AAlias: string): IIAM4DGitHubIdPBuilder;
var
  LBuilder: TIAM4DGitHubIdPBuilder;
begin
  LBuilder := TIAM4DGitHubIdPBuilder.Create;
  LBuilder.InitializeSocial(AAlias, IAM4D_IDP_PROVIDER_GITHUB, 'GitHub', ['user:email'], True);
  Result := LBuilder;
end;

class function TIAM4DGitHubIdPBuilder.AttributeMapper(const AIdentityProviderAlias, AJsonField,
  AUserAttribute: string): TIAM4DIdentityProviderMapper;
begin
  Result := JsonAttributeMapper(IAM4D_IDP_MAPPER_GITHUB_ATTRIBUTE, AIdentityProviderAlias, AJsonField, AUserAttribute);
end;

function TIAM4DGitHubIdPBuilder.Builder: IIAM4DGitHubIdPBuilder;
begin
  Result := Self;
end;

function TIAM4DGitHubIdPBuilder.WithEnterprise(const ABaseURL, AApiURL: string): IIAM4DGitHubIdPBuilder;
begin
  FBaseURL := ABaseURL.Trim.TrimRight(['/']);
  FApiURL := AApiURL.Trim.TrimRight(['/']);
  Result := Self;
end;

function TIAM4DGitHubIdPBuilder.Build: TIAM4DIdentityProvider;
const
  CHttpsURL = '^https://[^/?#\s]+(/[^?#\s]*)?$';
begin
  // Not in the interface: Keycloak takes the GitHub email whether verified or not
  if FIdentityProvider.TrustEmail then
    raise EIAM4DInvalidConfigurationException.Create(
      'GitHub: trust email is not supported, Keycloak does not check that the GitHub email is verified');
  // Both or none: with the web URL only, Keycloak would still call api.github.com
  if FBaseURL.IsEmpty <> FApiURL.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('GitHub Enterprise: both web URL and API URL are required');
  if not FBaseURL.IsEmpty and not (TRegEx.IsMatch(FBaseURL, CHttpsURL) and TRegEx.IsMatch(FApiURL, CHttpsURL)) then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      'GitHub Enterprise: web URL "%s" and API URL "%s" must be https URLs', [FBaseURL, FApiURL]));

  Result := BuildSocialIdentityProvider;
  if FBaseURL.IsEmpty then
  begin
    Result.Config.Remove('baseUrl');
    Result.Config.Remove('apiUrl');
  end
  else
  begin
    Result.Config.Values['baseUrl'] := FBaseURL;
    Result.Config.Values['apiUrl'] := FApiURL;
  end;
end;

{ TIAM4DGitLabIdPBuilder }

class function TIAM4DGitLabIdPBuilder.New(const AAlias: string): IIAM4DGitLabIdPBuilder;
var
  LBuilder: TIAM4DGitLabIdPBuilder;
begin
  LBuilder := TIAM4DGitLabIdPBuilder.Create;
  LBuilder.InitializeSocial(AAlias, IAM4D_IDP_PROVIDER_GITLAB, 'GitLab', ['openid', 'read_user', 'email'], True);
  Result := LBuilder;
end;

function TIAM4DGitLabIdPBuilder.Builder: IIAM4DGitLabIdPBuilder;
begin
  Result := Self;
end;

function TIAM4DGitLabIdPBuilder.Build: TIAM4DIdentityProvider;
var
  LScopes: TArray<string>;
begin
  // Scopes as Keycloak sends them: an element may hold several, space-separated
  LScopes := string.Join(' ', FScopes).Split([' '], TStringSplitOptions.ExcludeEmpty);
  // The id_token is validated below: without openid there is none
  if not MatchStr('openid', LScopes) then
    raise EIAM4DInvalidConfigurationException.Create('GitLab: the openid scope is required');
  // GitLab sends email_verified only with the email scope; without it Keycloak would trust any email
  if FIdentityProvider.TrustEmail and not MatchStr('email', LScopes) then
    raise EIAM4DInvalidConfigurationException.Create(
      'GitLab: WithTrustEmail requires the email scope (GitLab sends email_verified only with it)');

  Result := BuildSocialIdentityProvider;
  // Keycloak checks neither signature nor issuer of the GitLab id_token unless told
  Result.Config.Values['issuer'] := CGitLabIssuer;
  Result.Config.Values['jwksUrl'] := CGitLabIssuer + '/oauth/discovery/keys';
  Result.Config.SetBool('useJwksUrl', True);
  Result.Config.SetBool('validateSignature', True);
end;

{ TIAM4DSamlIdPBuilderBase }

procedure TIAM4DSamlIdPBuilderBase.SetImportedConfig(const AConfig: TIAM4DConfigMap);
var
  LURL: string;
begin
  FIdentityProvider.Config := ImportKeys(FIdentityProvider.Config, AConfig, CSamlImportedKeys);
  // Kept when missing: it may come from WithMetadataURL or from the defaults of a builder
  if AConfig.TryGetValue('metadataDescriptorUrl', LURL) then
    FIdentityProvider.Config.Values['metadataDescriptorUrl'] := LURL;
end;

procedure TIAM4DSamlIdPBuilderBase.SetMetadataURL(const AURL: string);
begin
  FIdentityProvider.Config.Values['metadataDescriptorUrl'] := AURL.Trim;
  FIdentityProvider.Config.SetBool('useMetadataDescriptorUrl', not AURL.Trim.IsEmpty);
end;

procedure TIAM4DSamlIdPBuilderBase.SetIdentityProviderEndpoints(const AEntityID, ASingleSignOnURL,
  ASigningCertificate, ASingleLogoutURL: string);
begin
  FIdentityProvider.Config.Values['idpEntityId'] := AEntityID.Trim;
  FIdentityProvider.Config.Values['singleSignOnServiceUrl'] := ASingleSignOnURL.Trim;
  FIdentityProvider.Config.SetBool('postBindingAuthnRequest', True);
  // Empty: Build accepts it only with the metadata URL (Keycloak reads the certificate from it)
  if ASigningCertificate.Trim.IsEmpty then
    FIdentityProvider.Config.Remove('signingCertificate')
  else
    FIdentityProvider.Config.Values['signingCertificate'] := ASigningCertificate.Trim;
  if ASingleLogoutURL.Trim.IsEmpty then
    FIdentityProvider.Config.Remove('singleLogoutServiceUrl')
  else
    FIdentityProvider.Config.Values['singleLogoutServiceUrl'] := ASingleLogoutURL.Trim;
  FIdentityProvider.Config.SetBool('postBindingLogout', True);
  // Imported data of another provider: the encryption key, and the metadata URL unless Keycloak reads it
  FIdentityProvider.Config.Remove('encryptionPublicKey');
  if not FIdentityProvider.Config.GetBool('useMetadataDescriptorUrl') then
    FIdentityProvider.Config.Remove('metadataDescriptorUrl');
end;

procedure TIAM4DSamlIdPBuilderBase.CheckIdentityProvider(const ASignatureValidation: Boolean;
  const ACertificateHint: string);
var
  LConfig: TIAM4DConfigMap;
begin
  CheckAlias(FIdentityProvider.Alias);
  LConfig := FIdentityProvider.Config;
  if LConfig.Values['idpEntityId'].Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      '%s "%s": identity provider entity ID is required (WithImportedConfig or WithIdentityProviderEndpoints)',
      [FProduct, FIdentityProvider.Alias]));
  if LConfig.Values['singleSignOnServiceUrl'].Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(Format('%s "%s": single sign-on URL is required',
      [FProduct, FIdentityProvider.Alias]));
  // Without it Keycloak rejects every signed response
  if ASignatureValidation and not LConfig.GetBool('useMetadataDescriptorUrl') and
     LConfig.Values['signingCertificate'].Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      '%s "%s": signing certificate of the identity provider is required (%s)',
      [FProduct, FIdentityProvider.Alias, ACertificateHint]));
end;

{ TIAM4DSamlIdPBuilder }

class function TIAM4DSamlIdPBuilder.New(const AAlias: string): IIAM4DSamlIdPBuilder;
var
  LBuilder: TIAM4DSamlIdPBuilder;
begin
  LBuilder := TIAM4DSamlIdPBuilder.Create;
  LBuilder.FProduct := 'SAML';
  LBuilder.FIdentityProvider := TIAM4DIdentityProvider.Create(AAlias, IAM4D_IDP_PROVIDER_SAML);
  LBuilder.FIdentityProvider.Config.SetBool('postBindingAuthnRequest', True);
  LBuilder.FIdentityProvider.Config.SetBool('postBindingResponse', True);
  LBuilder.FIdentityProvider.Config.SetBool('postBindingLogout', True);
  LBuilder.FIdentityProvider.Config.Values['signatureAlgorithm'] := 'RSA_SHA256';
  LBuilder.FPrincipalType := sptSubject;
  LBuilder.FRequestSigning := True;
  LBuilder.FAssertionSignature := True;
  LBuilder.FSignatureValidation := True;
  Result := LBuilder;
end;

class function TIAM4DSamlIdPBuilder.AttributeMapper(const AIdentityProviderAlias, AAttributeName,
  AUserAttribute: string): TIAM4DIdentityProviderMapper;
begin
  Result := SamlAttributeMapper(IAM4D_IDP_MAPPER_SAML_ATTRIBUTE, AIdentityProviderAlias, AAttributeName, AUserAttribute);
end;

function TIAM4DSamlIdPBuilder.WithImportedConfig(const AConfig: TIAM4DConfigMap): IIAM4DSamlIdPBuilder;
const
  CBindings: array[0..1] of string = ('postBindingAuthnRequest', 'postBindingLogout');
var
  LKey: string;
begin
  // Only the provider side. The bindings go with the imported endpoints (Keycloak picks the
  // Redirect endpoint when the metadata has no POST one); signatures stay the builder's
  SetImportedConfig(AConfig);
  for LKey in CBindings do
    if AConfig.Contains(LKey) then
      FIdentityProvider.Config.Values[LKey] := AConfig.Values[LKey]
    else
      FIdentityProvider.Config.SetBool(LKey, True);
  FIdentityProvider.Config := ImportKeys(FIdentityProvider.Config, AConfig, ['nameIDPolicyFormat']);
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.WithMetadataURL(const AURL: string): IIAM4DSamlIdPBuilder;
begin
  SetMetadataURL(AURL);
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.WithIdentityProviderEndpoints(const AEntityID, ASingleSignOnURL,
  ASigningCertificate, ASingleLogoutURL: string): IIAM4DSamlIdPBuilder;
begin
  SetIdentityProviderEndpoints(AEntityID, ASingleSignOnURL, ASigningCertificate, ASingleLogoutURL);
  // NameID format of the imported metadata: Build falls back to WithNameIDFormat or persistent
  FIdentityProvider.Config.Remove('nameIDPolicyFormat');
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.WithServiceProviderEntityID(const AEntityID: string): IIAM4DSamlIdPBuilder;
begin
  FIdentityProvider.Config.Values['entityId'] := AEntityID.Trim;
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.WithNameIDFormat(const AFormat: string): IIAM4DSamlIdPBuilder;
begin
  FNameIDFormat := AFormat.Trim;
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.WithPrincipal(const AType: TIAM4DSamlPrincipalType;
  const AAttribute: string): IIAM4DSamlIdPBuilder;
begin
  FPrincipalType := AType;
  FPrincipalAttribute := AAttribute.Trim;
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.WithDisplayName(const ADisplayName: string): IIAM4DSamlIdPBuilder;
begin
  FIdentityProvider.DisplayName := ADisplayName;
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): IIAM4DSamlIdPBuilder;
begin
  FIdentityProvider.SyncMode := ASyncMode;
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.WithTrustEmail(const AValue: Boolean): IIAM4DSamlIdPBuilder;
begin
  FIdentityProvider.TrustEmail := AValue;
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.WithHideOnLogin(const AValue: Boolean): IIAM4DSamlIdPBuilder;
begin
  FIdentityProvider.HideOnLogin := AValue;
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.WithFirstBrokerLoginFlow(const AFlowAlias: string): IIAM4DSamlIdPBuilder;
begin
  FIdentityProvider.FirstBrokerLoginFlowAlias := AFlowAlias;
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.WithConfig(const AKey, AValue: string): IIAM4DSamlIdPBuilder;
begin
  FIdentityProvider.Config.Values[AKey] := AValue;
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.DisableRequestSigning: IIAM4DSamlIdPBuilder;
begin
  FRequestSigning := False;
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.AllowUnsignedAssertions: IIAM4DSamlIdPBuilder;
begin
  FAssertionSignature := False;
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.DisableSignatureValidation: IIAM4DSamlIdPBuilder;
begin
  FSignatureValidation := False;
  Result := Self;
end;

function TIAM4DSamlIdPBuilder.Build: TIAM4DIdentityProvider;
var
  LNameIDFormat: string;
begin
  CheckIdentityProvider(FSignatureValidation, 'WithImportedConfig, WithIdentityProviderEndpoints or WithMetadataURL');
  if (FPrincipalType <> sptSubject) and FPrincipalAttribute.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(Format('SAML "%s": the principal attribute is required',
      [FIdentityProvider.Alias]));

  // Explicit format, else the imported one, else persistent (Keycloak default)
  LNameIDFormat := FNameIDFormat;
  if LNameIDFormat.IsEmpty then
    LNameIDFormat := FIdentityProvider.Config.Values['nameIDPolicyFormat'].Trim;
  if LNameIDFormat.IsEmpty then
    LNameIDFormat := IAM4D_SAML_NAMEID_PERSISTENT;
  // Keycloak rejects it: a transient NameID changes at every login
  if (FPrincipalType = sptSubject) and (LNameIDFormat = IAM4D_SAML_NAMEID_TRANSIENT) then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      'SAML "%s": a transient NameID cannot be the principal: use WithPrincipal with an attribute or ' +
      'WithNameIDFormat with another format', [FIdentityProvider.Alias]));
  // An unsigned response can carry any email
  if FIdentityProvider.TrustEmail and not FSignatureValidation then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      'SAML "%s": WithTrustEmail requires signature validation', [FIdentityProvider.Alias]));

  Result := FIdentityProvider;
  Result.Config.Values['nameIDPolicyFormat'] := LNameIDFormat;
  Result.Config.Values['principalType'] := CSamlPrincipalTypes[FPrincipalType];
  if FPrincipalType = sptSubject then
    Result.Config.Remove('principalAttribute')
  else
    Result.Config.Values['principalAttribute'] := FPrincipalAttribute;
  Result.Config.SetBool('wantAuthnRequestsSigned', FRequestSigning);
  Result.Config.SetBool('wantAssertionsSigned', FAssertionSignature and FSignatureValidation);
  Result.Config.SetBool('validateSignature', FSignatureValidation);
end;

{ TIAM4DItalianSamlIdPBuilderBase }

procedure TIAM4DItalianSamlIdPBuilderBase.Initialize(const AAlias, AProviderID, AProduct: string);
var
  LConfig: TIAM4DConfigMap;
begin
  FProduct := AProduct;
  FIdentityProvider := TIAM4DIdentityProvider.Create(AAlias, AProviderID);
  FIdentityProvider.TrustEmail := True;
  FIdentityProvider.SyncMode := ismForce;

  // SAML profile required by AgID technical rules
  LConfig := FIdentityProvider.Config;
  LConfig.Values['principalType'] := 'ATTRIBUTE';
  LConfig.Values['principalAttribute'] := 'fiscalNumber';
  LConfig.Values['nameIDPolicyFormat'] := 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
  LConfig.SetBool('wantAuthnRequestsSigned', True);
  LConfig.SetBool('wantAssertionsSigned', True);
  LConfig.SetBool('validateSignature', True);
  LConfig.SetBool('signSpMetadata', True);
  LConfig.SetBool('forceAuthn', True);
  LConfig.SetBool('postBindingAuthnRequest', True);
  LConfig.SetBool('postBindingResponse', True);
  LConfig.SetBool('postBindingLogout', True);
  LConfig.Values['signatureAlgorithm'] := 'RSA_SHA256';
  LConfig.Values['xmlSigKeyInfoKeyNameTransformer'] := 'NONE';
  LConfig.Values['attributeConsumingServiceIndex'] := '1';
  FIdentityProvider.Config := LConfig;
  SetLevel(slL2);
end;

procedure TIAM4DItalianSamlIdPBuilderBase.ApplyImportedConfig(const AConfig: TIAM4DConfigMap);
begin
  // Only the identity provider side: the SAML profile above stays as AgID requires
  SetImportedConfig(AConfig);
end;

procedure TIAM4DItalianSamlIdPBuilderBase.SetLevel(const ALevel: TIAM4DSpidLevel);
begin
  // JSON array string, as Keycloak reads it
  FIdentityProvider.Config.Values['authnContextClassRefs'] := '["' + ALevel.ToURI + '"]';
  FIdentityProvider.Config.Values['authnContextComparisonType'] := 'minimum';
end;

procedure TIAM4DItalianSamlIdPBuilderBase.SetAttributeConsumingService(const AIndex: Integer; const AName: string;
  const ALocalized: Boolean);
begin
  if AIndex < 0 then
    raise EIAM4DInvalidConfigurationException.Create(FProduct + ': attribute consuming service index cannot be negative');
  if AName.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(FProduct + ': attribute consuming service name is required');
  FIdentityProvider.Config.Values['attributeConsumingServiceIndex'] := AIndex.ToString;
  if ALocalized then
    FIdentityProvider.Config.Values['attributeConsumingServiceName'] := LocalizedValue('it', AName, 'attribute consuming service name')
  else
    FIdentityProvider.Config.Values['attributeConsumingServiceName'] := AName.Trim;
end;

function TIAM4DItalianSamlIdPBuilderBase.LocalizedValue(const ALocale, AValue, AWhat: string): string;
begin
  if AValue.Contains(',') or AValue.Contains('|') then
    raise EIAM4DInvalidConfigurationException.Create(Format('%s: %s cannot contain "," or "|"', [FProduct, AWhat]));
  Result := ALocale.Trim + '|' + AValue.Trim;
end;

procedure TIAM4DItalianSamlIdPBuilderBase.SetOrganization(const AName, ADisplayName, AURL, ALocale: string);
begin
  FIdentityProvider.Config.Values['organizationNames'] := LocalizedValue(ALocale, AName, 'organization name');
  FIdentityProvider.Config.Values['organizationDisplayNames'] := LocalizedValue(ALocale, ADisplayName, 'organization display name');
  FIdentityProvider.Config.Values['organizationUrls'] := LocalizedValue(ALocale, AURL, 'organization URL');
end;

function TIAM4DItalianSamlIdPBuilderBase.BuildIdentityProvider(const ACertificateHint: string): TIAM4DIdentityProvider;
begin
  // As the generic SAML builder rewrites them at Build: the AgID and CIE rules require signed
  // requests, signed assertions, validated signatures and signed SP metadata, and no method of these
  // builders turns them off, so WithConfig cannot either
  FIdentityProvider.Config.SetBool('wantAuthnRequestsSigned', True);
  FIdentityProvider.Config.SetBool('wantAssertionsSigned', True);
  FIdentityProvider.Config.SetBool('validateSignature', True);
  FIdentityProvider.Config.SetBool('signSpMetadata', True);
  CheckIdentityProvider(True, ACertificateHint);
  // Without it the SP metadata has no ServiceName and fails the SAML schema (identity providers reject it)
  if FIdentityProvider.Config.Values['attributeConsumingServiceName'].IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      '%s "%s": attribute consuming service name is required (WithAttributeConsumingService)',
      [FProduct, FIdentityProvider.Alias]));
  Result := FIdentityProvider;
end;

{ TIAM4DItalianSamlIdPBuilder<I> }

function TIAM4DItalianSamlIdPBuilder<I>.WithImportedConfig(const AConfig: TIAM4DConfigMap): I;
begin
  ApplyImportedConfig(AConfig);
  Result := Builder;
end;

function TIAM4DItalianSamlIdPBuilder<I>.WithServiceProviderEntityID(const AEntityID: string): I;
begin
  FIdentityProvider.Config.Values['entityId'] := AEntityID.Trim;
  Result := Builder;
end;

function TIAM4DItalianSamlIdPBuilder<I>.WithLevel(const ALevel: TIAM4DSpidLevel): I;
begin
  SetLevel(ALevel);
  Result := Builder;
end;

function TIAM4DItalianSamlIdPBuilder<I>.WithAttributeConsumingService(const AIndex: Integer; const AName: string): I;
begin
  SetAttributeConsumingService(AIndex, AName, FLocalizedServiceName);
  Result := Builder;
end;

function TIAM4DItalianSamlIdPBuilder<I>.WithOrganization(const AName, ADisplayName, AURL, ALocale: string): I;
begin
  SetOrganization(AName, ADisplayName, AURL, ALocale);
  Result := Builder;
end;

function TIAM4DItalianSamlIdPBuilder<I>.WithDisplayName(const ADisplayName: string): I;
begin
  FIdentityProvider.DisplayName := ADisplayName;
  Result := Builder;
end;

function TIAM4DItalianSamlIdPBuilder<I>.WithSyncMode(const ASyncMode: TIAM4DIdentityProviderSyncMode): I;
begin
  FIdentityProvider.SyncMode := ASyncMode;
  Result := Builder;
end;

function TIAM4DItalianSamlIdPBuilder<I>.WithTrustEmail(const AValue: Boolean): I;
begin
  FIdentityProvider.TrustEmail := AValue;
  Result := Builder;
end;

function TIAM4DItalianSamlIdPBuilder<I>.WithHideOnLogin(const AValue: Boolean): I;
begin
  FIdentityProvider.HideOnLogin := AValue;
  Result := Builder;
end;

function TIAM4DItalianSamlIdPBuilder<I>.WithFirstBrokerLoginFlow(const AFlowAlias: string): I;
begin
  FIdentityProvider.FirstBrokerLoginFlowAlias := AFlowAlias;
  Result := Builder;
end;

function TIAM4DItalianSamlIdPBuilder<I>.WithConfig(const AKey, AValue: string): I;
begin
  FIdentityProvider.Config.Values[AKey] := AValue;
  Result := Builder;
end;

{ TIAM4DSpidIdPBuilder }

class function TIAM4DSpidIdPBuilder.New(const AAlias: string): IIAM4DSpidIdPBuilder;
var
  LBuilder: TIAM4DSpidIdPBuilder;
begin
  LBuilder := TIAM4DSpidIdPBuilder.Create;
  LBuilder.Initialize(AAlias, IAM4D_IDP_PROVIDER_SPID, 'SPID');
  // The SPID extension reads '{locale}|{name}'
  LBuilder.FLocalizedServiceName := True;
  Result := LBuilder;
end;

function TIAM4DSpidIdPBuilder.Builder: IIAM4DSpidIdPBuilder;
begin
  Result := Self;
end;

class function TIAM4DSpidIdPBuilder.ServiceProviderMetadataURL(const AKeycloakURL, ARealm: string): string;
begin
  Result := RealmURL(AKeycloakURL, ARealm) + '/spid-sp-metadata';
end;

class function TIAM4DSpidIdPBuilder.AttributeMapper(const AIdentityProviderAlias, ASpidAttribute,
  AUserAttribute: string): TIAM4DIdentityProviderMapper;
begin
  Result := SamlAttributeMapper(IAM4D_IDP_MAPPER_SPID_ATTRIBUTE, AIdentityProviderAlias, ASpidAttribute, AUserAttribute);
end;

function TIAM4DSpidIdPBuilder.WithMetadataURL(const AURL: string): IIAM4DSpidIdPBuilder;
begin
  SetMetadataURL(AURL);
  Result := Self;
end;

function TIAM4DSpidIdPBuilder.WithIdentityProviderEndpoints(const AEntityID, ASingleSignOnURL,
  ASigningCertificate: string; const ASingleLogoutURL: string): IIAM4DSpidIdPBuilder;
begin
  SetIdentityProviderEndpoints(AEntityID, ASingleSignOnURL, ASigningCertificate, ASingleLogoutURL);
  Result := Self;
end;

function TIAM4DSpidIdPBuilder.WithPublicServiceProvider(const AIpaCode, AEmail: string;
  const APhone: string): IIAM4DSpidIdPBuilder;
begin
  if AIpaCode.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('SPID: IPA code is required for a public service provider');
  FIdentityProvider.Config.SetBool('otherContactIsSpPrivate', False);
  FIdentityProvider.Config.Values['otherContactIpaCode'] := AIpaCode.Trim;
  FIdentityProvider.Config.Values['otherContactEmail'] := AEmail.Trim;
  FIdentityProvider.Config.Values['otherContactPhone'] := APhone.Trim;
  Result := Self;
end;

function TIAM4DSpidIdPBuilder.WithPrivateServiceProvider(const AVatNumber, AFiscalCode, ACompany, AEmail: string;
  const APhone: string): IIAM4DSpidIdPBuilder;
begin
  if AVatNumber.Trim.IsEmpty and AFiscalCode.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('SPID: VAT number or fiscal code is required for a private service provider');
  FIdentityProvider.Config.SetBool('otherContactIsSpPrivate', True);
  FIdentityProvider.Config.Values['otherContactVatNumber'] := AVatNumber.Trim;
  FIdentityProvider.Config.Values['otherContactFiscalCode'] := AFiscalCode.Trim;
  FIdentityProvider.Config.Values['otherContactCompany'] := ACompany.Trim;
  FIdentityProvider.Config.Values['otherContactEmail'] := AEmail.Trim;
  FIdentityProvider.Config.Values['otherContactPhone'] := APhone.Trim;
  Result := Self;
end;

function TIAM4DSpidIdPBuilder.WithBillingContact(const ACompany, AEmail, APhone, ARegisteredName, AAddress,
  AStreetNumber, APostalCode, ACity, AProvince, ACountry: string): IIAM4DSpidIdPBuilder;
const
  CRequired: array[0..6] of string = ('company', 'email', 'registered name', 'address', 'postal code', 'city',
    'country');
var
  LValues: array[0..6] of string;
  LIndex: Integer;
begin
  LValues[0] := ACompany;
  LValues[1] := AEmail;
  LValues[2] := ARegisteredName;
  LValues[3] := AAddress;
  LValues[4] := APostalCode;
  LValues[5] := ACity;
  LValues[6] := ACountry;
  for LIndex := Low(LValues) to High(LValues) do
    if LValues[LIndex].Trim.IsEmpty then
      raise EIAM4DInvalidConfigurationException.Create(Format('SPID: billing contact %s is required', [CRequired[LIndex]]));

  // Keys of italia/spid-keycloak-provider (fpa:CessionarioCommittente of the billing ContactPerson)
  FIdentityProvider.Config.Values['billingContactCompany'] := ACompany.Trim;
  FIdentityProvider.Config.Values['billingContactEmail'] := AEmail.Trim;
  FIdentityProvider.Config.Values['billingContactPhone'] := APhone.Trim;
  FIdentityProvider.Config.Values['billingContactRegistryName'] := ARegisteredName.Trim;
  FIdentityProvider.Config.Values['billingContactSiteAddress'] := AAddress.Trim;
  FIdentityProvider.Config.Values['billingContactSiteNumber'] := AStreetNumber.Trim;
  FIdentityProvider.Config.Values['billingContactSiteZipCode'] := APostalCode.Trim;
  FIdentityProvider.Config.Values['billingContactSiteCity'] := ACity.Trim;
  FIdentityProvider.Config.Values['billingContactSiteProvince'] := AProvince.Trim;
  FIdentityProvider.Config.Values['billingContactSiteCountry'] := ACountry.Trim;
  Result := Self;
end;

function TIAM4DSpidIdPBuilder.Build: TIAM4DIdentityProvider;
var
  LConfig: TIAM4DConfigMap;
begin
  LConfig := FIdentityProvider.Config;
  if not (LConfig.Values['billingContactCompany'] + LConfig.Values['billingContactEmail'] +
    LConfig.Values['billingContactPhone']).IsEmpty then
  begin
    // The extension writes the billing contact only for a private service provider
    if not LConfig.GetBool('otherContactIsSpPrivate') then
      raise EIAM4DInvalidConfigurationException.Create(Format(
        'SPID "%s": the billing contact is for private service providers (WithPrivateServiceProvider)',
        [FIdentityProvider.Alias]));
    // IdPaese and IdCodice: the first 2 and the next 11 characters of the VAT number
    if not TRegEx.IsMatch(LConfig.Values['otherContactVatNumber'], '^[A-Za-z]{2}[0-9A-Za-z]{11}$') then
      raise EIAM4DInvalidConfigurationException.Create(Format(
        'SPID "%s": the billing contact needs the VAT number with the country code (e.g. IT12345678901) in ' +
        'WithPrivateServiceProvider, not "%s"', [FIdentityProvider.Alias, LConfig.Values['otherContactVatNumber']]));
  end;
  Result := BuildIdentityProvider('WithImportedConfig, WithIdentityProviderEndpoints or WithMetadataURL');
end;

{ TIAM4DCieIdPBuilder }

class function TIAM4DCieIdPBuilder.New(const AAlias: string): IIAM4DCieIdPBuilder;
var
  LBuilder: TIAM4DCieIdPBuilder;
begin
  LBuilder := TIAM4DCieIdPBuilder.Create;
  LBuilder.Initialize(AAlias, IAM4D_IDP_PROVIDER_CIE, 'CIE ID');
  LBuilder.FIdentityProvider.DisplayName := 'CIE ID';
  // Default endpoints, not a choice: without WithEnvironment the imported metadata decides
  LBuilder.ApplyEnvironment(ceProduction);
  // The CIE extension writes the service name as is
  LBuilder.FLocalizedServiceName := False;
  Result := LBuilder;
end;

function TIAM4DCieIdPBuilder.Builder: IIAM4DCieIdPBuilder;
begin
  Result := Self;
end;

class function TIAM4DCieIdPBuilder.MetadataURL(const AEnvironment: TIAM4DCieEnvironment): string;
begin
  Result := CCieHost[AEnvironment] + '/idp/shibboleth?Metadata';
end;

class function TIAM4DCieIdPBuilder.ServiceProviderMetadataURL(const AKeycloakURL, ARealm: string): string;
begin
  Result := RealmURL(AKeycloakURL, ARealm) + '/cieid-sp-metadata';
end;

class function TIAM4DCieIdPBuilder.AttributeMapper(const AIdentityProviderAlias, ACieAttribute,
  AUserAttribute: string): TIAM4DIdentityProviderMapper;
begin
  Result := SamlAttributeMapper(IAM4D_IDP_MAPPER_CIE_ATTRIBUTE, AIdentityProviderAlias, ACieAttribute, AUserAttribute);
end;

procedure TIAM4DCieIdPBuilder.ApplyEnvironment(const AEnvironment: TIAM4DCieEnvironment);
begin
  FEnvironment := AEnvironment;
  FIdentityProvider.Config.Values['idpEntityId'] := CieEntityID(AEnvironment);
  FIdentityProvider.Config.Values['singleSignOnServiceUrl'] := CCieHost[AEnvironment] + '/idp/profile/SAML2/POST/SSO';
  FIdentityProvider.Config.Values['singleLogoutServiceUrl'] := CCieHost[AEnvironment] + '/idp/profile/SAML2/POST/SLO';
  FIdentityProvider.Config.Values['metadataDescriptorUrl'] := MetadataURL(AEnvironment);
end;

function TIAM4DCieIdPBuilder.WithEnvironment(const AEnvironment: TIAM4DCieEnvironment): IIAM4DCieIdPBuilder;
begin
  ApplyEnvironment(AEnvironment);
  FEnvironmentSet := True;
  // Order irrelevant: metadata imported before still wins over the defaults (Build checks the identity server)
  if FImported then
    SetImportedConfig(FImportedConfig);
  Result := Self;
end;

procedure TIAM4DCieIdPBuilder.ApplyImportedConfig(const AConfig: TIAM4DConfigMap);
begin
  // Kept for WithEnvironment (applied again) and Build (identity server check)
  FImported := True;
  FImportedConfig := AConfig;
  inherited;
end;

function TIAM4DCieIdPBuilder.WithPublicServiceProvider(const ACompany, AIpaCode, AIpaCategory, AEmail: string;
  const APhone: string): IIAM4DCieIdPBuilder;
begin
  if AIpaCode.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('CIE ID: IPA code is required for a public service provider');
  FIdentityProvider.Config.SetBool('administrativeContactIsSpPrivate', False);
  FIdentityProvider.Config.Values['administrativeContactCompany'] := ACompany.Trim;
  FIdentityProvider.Config.Values['administrativeContactIpaCode'] := AIpaCode.Trim;
  FIdentityProvider.Config.Values['administrativeContactIpaCategory'] := AIpaCategory.Trim;
  FIdentityProvider.Config.Values['administrativeContactEmail'] := AEmail.Trim;
  FIdentityProvider.Config.Values['administrativeContactPhone'] := APhone.Trim;
  Result := Self;
end;

function TIAM4DCieIdPBuilder.WithPrivateServiceProvider(const ACompany, AVatNumber, AFiscalCode, AEmail: string;
  const APhone: string): IIAM4DCieIdPBuilder;
begin
  if AVatNumber.Trim.IsEmpty and AFiscalCode.Trim.IsEmpty then
    raise EIAM4DInvalidConfigurationException.Create('CIE ID: VAT number or fiscal code is required for a private service provider');
  FIdentityProvider.Config.SetBool('administrativeContactIsSpPrivate', True);
  FIdentityProvider.Config.Values['administrativeContactCompany'] := ACompany.Trim;
  FIdentityProvider.Config.Values['administrativeContactVatNumber'] := AVatNumber.Trim;
  FIdentityProvider.Config.Values['administrativeContactFiscalCode'] := AFiscalCode.Trim;
  FIdentityProvider.Config.Values['administrativeContactEmail'] := AEmail.Trim;
  FIdentityProvider.Config.Values['administrativeContactPhone'] := APhone.Trim;
  Result := Self;
end;

function TIAM4DCieIdPBuilder.WithTechnicalContact(const ACompany, AVatNumber, AFiscalCode, AEmail: string;
  const APhone: string): IIAM4DCieIdPBuilder;
begin
  FIdentityProvider.Config.Values['technicalContactCompany'] := ACompany.Trim;
  FIdentityProvider.Config.Values['technicalContactVatNumber'] := AVatNumber.Trim;
  FIdentityProvider.Config.Values['technicalContactFiscalCode'] := AFiscalCode.Trim;
  FIdentityProvider.Config.Values['technicalContactEmail'] := AEmail.Trim;
  FIdentityProvider.Config.Values['technicalContactPhone'] := APhone.Trim;
  Result := Self;
end;

function TIAM4DCieIdPBuilder.Build: TIAM4DIdentityProvider;
const
  CEnvironmentNames: array[TIAM4DCieEnvironment] of string = ('production', 'pre-production');
  CEnvironmentConstants: array[TIAM4DCieEnvironment] of string = ('ceProduction', 'cePreProduction');
var
  LImportedEntityID: string;
begin
  // Endpoints and certificate of the other identity server: every login would fail
  LImportedEntityID := FImportedConfig.Values['idpEntityId'].Trim;
  if FEnvironmentSet and not LImportedEntityID.IsEmpty and
     not SameText(LImportedEntityID.TrimRight(['/']), CieEntityID(FEnvironment)) then
    raise EIAM4DInvalidConfigurationException.Create(Format(
      'CIE ID "%s": the imported metadata is of "%s", not of the %s identity server (import MetadataURL(%s))',
      [FIdentityProvider.Alias, LImportedEntityID, CEnvironmentNames[FEnvironment],
       CEnvironmentConstants[FEnvironment]]));
  Result := BuildIdentityProvider('WithImportedConfig with ImportConfig(IAM4D_IDP_PROVIDER_CIE, MetadataURL(...))');
end;

end.
