# Identity brokering

Reference of identity brokering in IAMClient4D 3.0: Keycloak delegates the login to an external identity provider (Microsoft Entra ID, Google, Facebook, Microsoft accounts, LinkedIn, GitHub, GitLab, SPID, CIE ID, any OpenID Connect, OAuth 2.0 or SAML 2.0 provider) and the application keeps receiving Keycloak tokens. The library adds the direct login to one provider (`kc_idp_hint`) and the management of providers and mappers through the Keycloak Admin REST API, with builders that apply secure defaults. Login flows are in [Core.md](Core.md), token validation in [Security.md](Security.md), users and their federated identities in [AdminAPI.md](AdminAPI.md).

## Contents

- [Units](#units)
- [Direct login (kc_idp_hint)](#direct-login-kc_idp_hint)
- [Identity provider manager](#identity-provider-manager)
- [Records](#records)
- [Copies, secrets and aliases](#copies-secrets-and-aliases)
- [Errors](#errors)
- [Builders](#builders)
- [OpenID Connect](#openid-connect)
- [Microsoft Entra ID](#microsoft-entra-id)
- [OAuth 2.0](#oauth-20)
- [Social providers](#social-providers)
- [SAML 2.0](#saml-20)
- [SPID and CIE ID](#spid-and-cie-id)
- [Provider types without a builder](#provider-types-without-a-builder)
- [Tests and samples](#tests-and-samples)

## Units

| Unit | Content |
|------|---------|
| `IAMClient4D.IdentityProvider.Core` | Records, `IIAM4DIdentityProviderManager`, `IIAM4DIdentityProviderManagerAsync`, `IAM4D_IDP_PROVIDER_OIDC` / `_SAML` / `_OAUTH2`, `IAM4D_IDP_SECRET_MASK` |
| `IAMClient4D.IdentityProvider.Keycloak` | `TIAM4DKeycloakIdentityProviderManager` (sync), JSON mapping |
| `IAMClient4D.IdentityProvider.Keycloak.Async` | `TIAM4DKeycloakIdentityProviderManagerAsync` |
| `IAMClient4D.IdentityProvider.Builders` | Builders, aliases (`IAM4D_IDP_ALIAS_*`), provider types (`IAM4D_IDP_PROVIDER_*`), mapper types (`IAM4D_IDP_MAPPER_*`), NameID formats (`IAM4D_SAML_NAMEID_*`), `IAM4D_SPID_REGISTRY_URL` |
| `IAMClient4D.Core`, `IAMClient4D.Config.Builder` | `IAM4D_IDP_HINT_NONE`, `StartAuthorizationFlowAsync(AIdpHint)`, `GenerateAuthURL(..., AIdpHint)`, `TIAM4DAuthRequestOptions.WithIdpHint`, `WithIdentityProvider` |

## Direct login (kc_idp_hint)

The value is the **alias** of the identity provider in the realm. Keycloak skips its login page and redirects to that provider.

| Where | Effect |
|-------|--------|
| `TIAM4DClientConfigBuilder.WithIdentityProvider(AAlias)` | Every login of the client (`Config.IdpHint`). Kept by the other `With*` methods. Authorization Code only: with Client Credentials (or another grant) it raises `EInvalidOpException` |
| `StartAuthorizationFlowAsync(AIdpHint = '')`, `StartAuthorizationFlowAsync(AIdpHint, ALoginHint)` | One login |
| `GenerateAuthURL(ALoginHint = '', AIdpHint = '')` | Authorization URL for an external callback (after `InitializeAuthorizationFlow`) |
| `TIAM4DAuthRequestOptions.WithIdpHint` | Same, with the other options of one login |

The argument wins over the configuration. An empty argument uses `Config.IdpHint`; both empty show the Keycloak login page. `IAM4D_IDP_HINT_NONE` (`'/none'`, unit `IAMClient4D.Core`, never a valid alias) sends no hint even when one is configured.

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
// Every login of this client goes to Entra ID
LClient := TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('http://localhost:18180/auth', 'iamclient4d', 'iam4d-sample-app')
  .WithIdentityProvider('entra')
  .Build;

// One login: the application shows its own buttons and passes the alias
LClient.StartAuthorizationFlowAsync('cie')
  .OnSuccess(
    procedure(const AAccessToken: string)
    begin
      ShowMessage('Logged in');
    end)
  .Run;

// Keycloak login page for this login, despite WithIdentityProvider
LClient.StartAuthorizationFlowAsync(IAM4D_IDP_HINT_NONE).Run;
```

- `kc_idp_hint` is a hint, not a constraint: without it in the URL the Keycloak page is shown again. To hide a provider from that page use `HideOnLogin`; to enforce one server side, override the browser flow of the Keycloak client with the *Identity Provider Redirector* authenticator.
- SPID is one provider per SPID identity provider (Poste, Aruba, InfoCert...), each with its alias (e.g. `spid-poste`): the application shows the list and passes the alias the user picks. Entra ID and CIE are single providers.

## Identity provider manager

Units `IAMClient4D.IdentityProvider.Keycloak` and `.Keycloak.Async`. `TIAM4DKeycloakIdentityProviderManager` inherits from `TIAM4DKeycloakAdminBase`: same constructors, token handling, HTTP pool, redirects, timeouts and URL encoding as the user manager ([AdminAPI.md, Construction](AdminAPI.md#construction)). `TIAM4DKeycloakIdentityProviderManagerAsync` has `Create(ASyncManager)`, `Create(AClient, ABaseURL = '', ARealm = '')` and `Create(AAccessToken, ABaseURL, ARealm)`; each method runs the sync one in a task, callbacks on the main thread by default ([AsyncCore.md](AsyncCore.md)), and the wrapper can be released while operations run.

**Token.** The `realm-management` roles `view-identity-providers` (read) and `manage-identity-providers` (write), or `realm-admin`. Keycloak 26.8.2 and later also require the audience of the `kc-admin-api` client scope (see [AdminAPI.md, Admin token](AdminAPI.md#admin-token) and [KeycloakSetup.md](KeycloakSetup.md#admin-rest-api-client)); without it every call answers 401. In the [sample environment](../../Docker/README.md) a client of `iam4d-sample-app` logged in as `demo` has both.

Paths relative to `{BaseURL}/admin/realms/{realm}/identity-provider`; every method has an `...Async` twin.

| Method | Request | Notes |
|--------|---------|-------|
| `GetIdentityProviders` | `GET instances?first=&max=100`, page by page | Every provider (Keycloak 24+ returns 100 per request). Stops at a short page or when the server ignores paging |
| `GetIdentityProviders(ASearch, AFirst, AMax)` | `GET instances?search=&first=&max=` | One page. `ASearch`: alias, prefix by default (`name*`), `*name*` contains, `"name"` exact, empty for all. `AFirst` < 0 or `AMax` < 1 raise before the request |
| `GetIdentityProvider(AAlias)`, `TryGetIdentityProvider` | `GET instances/{alias}` | Missing: `EIAM4DHTTPNotFoundException` / `Found` False |
| `CreateIdentityProvider(AIdP)` | `POST instances` | `InternalID` not sent |
| `UpdateIdentityProvider(AIdP)` | `PUT instances/{alias}` | |
| `SaveIdentityProvider(AIdP)` | `GET`, then `PUT` or `POST` | Create or update by alias |
| `DeleteIdentityProvider(AAlias)` | `DELETE instances/{alias}` | Missing: `EIAM4DHTTPNotFoundException` |
| `IsProviderInstalled(AProviderID)` | `GET providers/{id}` | True if Keycloak has that provider type (e.g. `IAM4D_IDP_PROVIDER_SPID`: SPID extension installed). 400 and 404 give False |
| `ImportConfig(AProviderID, AFromURL): TIAM4DConfigMap` | `POST import-config` | Keycloak downloads the OIDC discovery document or the SAML metadata (the URL must be reachable from Keycloak) and returns the config it derives. Empty arguments raise |
| `ExportServiceProviderMetadata(AAlias): string` | `GET instances/{alias}/export` | Keycloak's SAML SP descriptor of one SAML provider. Not for SPID and CIE: see [SPID and CIE ID](#spid-and-cie-id) |
| `GetMappers(AAlias)` | `GET instances/{alias}/mappers` | |
| `GetMapper(AAlias, AMapperID)` | `GET instances/{alias}/mappers/{id}` | A mapper of another provider is not found (`EIAM4DHTTPNotFoundException`) |
| `GetMapperTypes(AAlias)` | `GET instances/{alias}/mapper-types` | Types the provider supports, with their properties, sorted by ID |
| `CreateMapper(AMapper): string` | `POST instances/{alias}/mappers` | Returns the new ID; `ID` not sent. Alias, name and mapper type required |
| `UpdateMapper(AMapper)` | `PUT .../mappers/{id}` | `ID` required |
| `DeleteMapper(AAlias, AMapperID)` | `DELETE .../mappers/{id}` | |

The manager rejects an empty alias and one with `/`, `\`, `?`, `#`, `%`, `&` or a space (`EIAM4DInvalidConfigurationException`); create and update also require `ProviderID`.

**Keycloak versions.** Tested with 26.8, 26.7 and 25.0. `HideOnLogin` is sent as the field `hideOnLogin` (Keycloak 26) and as the config key `hideOnLoginPage` (earlier versions); when Keycloak answers 400 *Unrecognized field "hideOnLogin"* the request is sent again without the field. On read the field wins, else the config key, which is then removed from `Config`.

## Records

Unit `IAMClient4D.IdentityProvider.Core`. Keycloak describes every provider the same way (`IdentityProviderRepresentation`): only `ProviderID` and the config change. `TIAM4DIdentityProvider` mirrors it, so providers configured in the admin console are read and updated too.

### TIAM4DIdentityProvider

| Property | Keycloak field | Notes |
|----------|----------------|-------|
| `Alias` | `alias` | Key of the provider, part of the broker URLs (`{realm URL}/broker/{alias}/endpoint`) |
| `DisplayName` | `displayName` | Button text on the login page |
| `ProviderID` | `providerId` | `oidc`, `saml`, `oauth2`, `google`, `spid-saml`, ... |
| `InternalID` | `internalId` | Read only in practice: never sent on create |
| `Enabled` | `enabled` | True after `Create` |
| `TrustEmail` | `trustEmail` | Emails from the provider are marked verified: see the builders for when it is safe |
| `StoreToken`, `AddReadTokenRoleOnCreate` | `storeToken`, `addReadTokenRoleOnCreate` | Keep the provider tokens |
| `LinkOnly` | `linkOnly` | Only to link existing accounts, no login |
| `HideOnLogin` | `hideOnLogin` / `hideOnLoginPage` | Not shown on the login page; still usable with `kc_idp_hint` |
| `FirstBrokerLoginFlowAlias`, `PostBrokerLoginFlowAlias` | same names | Authentication flows |
| `Config` | `config` | `TIAM4DConfigMap` |
| `SyncMode` | config `syncMode` | `ismDefault` (key removed: Keycloak default), `ismImport`, `ismLegacy`, `ismForce`, `ismInherit` |

`TIAM4DIdentityProvider.Create(AAlias, AProviderID)` trims both and sets `Enabled`. `TIAM4DIdentityProviderTryResult`: `Found`, `IdentityProvider`.

### TIAM4DConfigMap

String key-value list, case-sensitive keys, in insertion order. A value copy: assigning a map, or a record that holds one, gives an independent copy.

| Member | Notes |
|--------|-------|
| `Values[AKey]` | Read (empty if missing) and write (adds or replaces). An empty key raises `EArgumentException` |
| `Contains`, `TryGetValue`, `Remove`, `Clear`, `Count`, `Entries` | |
| `GetBool(AKey, ADefault = False)`, `SetBool` | `'true'`/`'false'`, read case-insensitively |
| `Merge(ASource)` | Adds or replaces the keys of `ASource` |

Config values Keycloak returns as JSON numbers or booleans are kept as their JSON text.

### Mappers

`TIAM4DIdentityProviderMapper`: `ID` (not sent on create), `Name`, `IdentityProviderAlias`, `MapperType` (e.g. `hardcoded-role-idp-mapper`, `IAM4D_IDP_MAPPER_*`), `Config`; `Create(AIdentityProviderAlias, AName, AMapperType)`. `TIAM4DIdentityProviderMapperType` (from `GetMapperTypes`): `ID`, `Name`, `Category`, `HelpText`, `Properties` (`TIAM4DConfigProperty`: `Name`, `DisplayLabel`, `HelpText`, `PropertyType`, `DefaultValue`, `Options`, `Secret`, `Required`, `ReadOnly`).

## Copies, secrets and aliases

- **Copies.** Create does not send `InternalID` nor the mapper `ID`: a provider or mapper read from Keycloak can be created again under another alias or in another realm.
- **Secret mask.** Keycloak returns the client secret as `**********` (`IAM4D_IDP_SECRET_MASK`). On update the mask in `clientSecret` keeps the stored secret; Keycloak 26.8.1+ answers 400 to it when the update changes the client ID, token URL, client authentication or other destination settings: send the real secret then. The mask in any other config key, or in any key on create, raises `EIAM4DInvalidConfigurationException` before the request (Keycloak would store the mask as the secret): set the real secret on a copy.
- **Alias.** Cannot be renamed: Keycloak 26 answers 400. Create the provider with the new alias and delete the old one; mappers and user links (federated identities) are not moved.

## Errors

| Case | Exception |
|------|-----------|
| Invalid argument, builder validation (`Build`), secret mask, 3xx response | `EIAM4DInvalidConfigurationException` |
| 403 (missing `manage-identity-providers` / `view-identity-providers`) | `EIAM4DInsufficientPermissionsException` |
| 404, missing alias or mapper | `EIAM4DHTTPNotFoundException` |
| 409 (alias that exists) | `EIAM4DHTTPConflictException` |
| other 4xx (400: config Keycloak rejects; 401: missing `kc-admin-api` audience) | `EIAM4DHTTPClientErrorException` (`StatusCode`, `ResponseBody`) |
| 5xx | `EIAM4DHTTPServerErrorException` |

The table of status codes is shared with the user manager: [AdminAPI.md, Errors](AdminAPI.md#errors).

## Builders

Unit `IAMClient4D.IdentityProvider.Builders`. A builder is an interface (`TIAM4DxxxIdPBuilder.New` returns `IIAM4DxxxIdPBuilder`) whose `Build` returns a `TIAM4DIdentityProvider` for `CreateIdentityProvider`, `UpdateIdentityProvider` or `SaveIdentityProvider`. `Build` validates and raises `EIAM4DInvalidConfigurationException`; it writes the security settings last, so `WithConfig` cannot turn them off: each off switch is a method that says so.

| Builder | `New` | Provider type |
|---------|-------|---------------|
| `TIAM4DOidcIdPBuilder` | `New(AAlias)` | `oidc` |
| `TIAM4DEntraIdPBuilder` | `New(AAlias = 'entra')` | `oidc` |
| `TIAM4DOAuth2IdPBuilder` | `New(AAlias)` | `oauth2` |
| `TIAM4DGoogleIdPBuilder` | `New(AAlias = 'google')` | `google` |
| `TIAM4DFacebookIdPBuilder` | `New(AAlias = 'facebook')` | `facebook` |
| `TIAM4DMicrosoftIdPBuilder` | `New(AAlias = 'microsoft')` | `microsoft` |
| `TIAM4DLinkedInIdPBuilder` | `New(AAlias = 'linkedin')` | `linkedin-openid-connect` |
| `TIAM4DGitHubIdPBuilder` | `New(AAlias = 'github')` | `github` |
| `TIAM4DGitLabIdPBuilder` | `New(AAlias = 'gitlab')` | `gitlab` |
| `TIAM4DSamlIdPBuilder` | `New(AAlias)` | `saml` |
| `TIAM4DSpidIdPBuilder` | `New(AAlias)` | `spid-saml` (extension) |
| `TIAM4DCieIdPBuilder` | `New(AAlias = 'cie')` | `cieid-saml` (extension) |

Builder aliases must match `^[A-Za-z0-9._-]+$`. The redirect URI (OIDC, OAuth 2.0) or assertion consumer service (SAML) to register at the provider is `{Keycloak}/realms/{realm}/broker/{alias}/endpoint`.

**Common methods** (each builder has those that apply):

| Method | Effect | Not on |
|--------|--------|--------|
| `WithClient(AClientID, AClientSecret)` | `clientId` (trimmed), `clientSecret`. Client ID required at `Build`; secret too, except with `private_key_jwt` | SAML, SPID, CIE |
| `WithDisplayName` | `DisplayName` | |
| `WithScopes(AScopes)` | `defaultScope`, space-separated; replaces the default scopes | SAML, SPID, CIE |
| `WithPrompt(APrompt)` | config `prompt` | Facebook, LinkedIn, GitHub, GitLab, SAML, SPID, CIE |
| `WithSyncMode` | `SyncMode` | |
| `WithTrustEmail(AValue = True)` | `TrustEmail`, with the checks of each builder | GitHub |
| `WithHideOnLogin(AValue = True)` | `HideOnLogin` | |
| `WithFirstBrokerLoginFlow(AFlowAlias)` | `FirstBrokerLoginFlowAlias` | |
| `WithConfig(AKey, AValue)` | Any other config key | |

PKCE, where a builder sets it, is `pkceEnabled` with `pkceMethod` `S256`.

## OpenID Connect

`TIAM4DOidcIdPBuilder`, for Okta, Auth0, ADFS, Ping, another Keycloak, a self-managed GitLab...

| Method | Effect |
|--------|--------|
| `WithImportedConfig(AConfig)` | Provider endpoints from `ImportConfig(IAM4D_IDP_PROVIDER_OIDC, discovery URL)`: replaces `authorizationUrl`, `tokenUrl`, `userInfoUrl`, `jwksUrl`, `logoutUrl`, `issuer`, `tokenIntrospectionUrl`, `metadataDescriptorUrl` as a whole (a key the document lacks is removed) |
| `WithEndpoints(AAuthorizationURL, ATokenURL, AUserInfoURL = '', ALogoutURL = '')` | By hand; an empty value removes the key. Of this and `WithImportedConfig` the later wins |
| `WithJwksURL`, `WithIssuer` | `jwksUrl`; `issuer` (several issuers comma-separated) |
| `WithClientAuthMethod(AMethod, ASigningAlgorithm = '')` | `ocaClientSecretPost` (default), `ocaClientSecretBasic`, `ocaPrivateKeyJwt` (no secret: Keycloak signs with a realm key, register `{realm URL}/protocol/openid-connect/certs` at the provider), `ocaClientSecretJwt` |
| `DisableIssuerCheck`, `DisableSignatureValidation`, `DisablePkce` | Off switches |

Defaults: scopes `openid profile email`, `client_secret_post`, issuer checked, signatures validated with the JWKS (`useJwksUrl`), PKCE S256.

`Build` raises when:

- alias, client, authorization URL or token URL is missing;
- the issuer is missing while the issuer check is on, or the JWKS URL while signature validation is on;
- a signing algorithm is given without a JWT method, or of the wrong family (`private_key_jwt`: `RS256`..`RS512`, `PS256`..`PS512`, `ES256`..`ES512`, `EdDSA`; `client_secret_jwt`: `HS256`, `HS384`, `HS512`);
- `TrustEmail` is set without the issuer check or without signature validation (a token of another issuer, or a forged one, could claim the email of an existing user: nOAuth).

<!-- snippet ver=3.0 kind=body ctx=client uses=IAMClient4D.IdentityProvider.Core,IAMClient4D.IdentityProvider.Keycloak,IAMClient4D.IdentityProvider.Builders -->
```delphi
var LManager: IIAM4DIdentityProviderManager := TIAM4DKeycloakIdentityProviderManager.Create(LClient);
LManager.SaveIdentityProvider(
  TIAM4DOidcIdPBuilder.New('okta')
    .WithImportedConfig(LManager.ImportConfig(IAM4D_IDP_PROVIDER_OIDC,
      'https://example.okta.com/.well-known/openid-configuration'))
    .WithClient('okta-client-id', 'okta-client-secret')
    .WithClientAuthMethod(ocaClientSecretBasic)
    .WithDisplayName('Okta')
    .Build);
```

## Microsoft Entra ID

`TIAM4DEntraIdPBuilder`: OpenID Connect against `login.microsoftonline.com`. Register an application in Entra ID with the redirect URI and a client secret.

- `WithTenant(ATenant)` is required: a directory ID (GUID), `organizations`, `common`, `consumers` or a domain name (letters, digits, `.`, `-`).
- The builder sets the authorize, token and logout endpoints of `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/`, the JWKS `.../discovery/v2.0/keys`, user info `https://graph.microsoft.com/oidc/userinfo`, PKCE S256 and `client_secret_post`, display name `Microsoft`.
- The issuer `https://login.microsoftonline.com/{tenant}/v2.0` is checked only with a directory ID: multi-tenant tokens carry the tenant of the user.
- `WithTrustEmail` requires a directory ID; otherwise `Build` raises: tokens of any tenant are accepted and Microsoft does not verify the `email` claim (nOAuth).

<!-- snippet ver=3.0 kind=body ctx=client uses=IAMClient4D.IdentityProvider.Core,IAMClient4D.IdentityProvider.Keycloak,IAMClient4D.IdentityProvider.Builders -->
```delphi
var LManager: IIAM4DIdentityProviderManager := TIAM4DKeycloakIdentityProviderManager.Create(LClient);
LManager.SaveIdentityProvider(
  TIAM4DEntraIdPBuilder.New
    .WithTenant('6f1c3a52-0b7e-4d2a-9c8f-2e5d7b4a1c90')  // directory ID, or 'organizations'
    .WithClient('entra-application-id', 'entra-client-secret')
    .WithSyncMode(ismImport)
    .Build);
```

## OAuth 2.0

`TIAM4DOAuth2IdPBuilder`: providers with OAuth 2.0 but no OpenID Connect (Strava, Discord, Dropbox, an internal API). Keycloak reads the profile from the user info endpoint with the access token; no token signature or issuer can be checked. Prefer `TIAM4DOidcIdPBuilder` when the provider supports OpenID Connect.

| Method | Effect |
|--------|--------|
| `WithImportedConfig(AConfig)` | `authorizationUrl`, `tokenUrl`, `userInfoUrl`, `tokenIntrospectionUrl` from `ImportConfig(IAM4D_IDP_PROVIDER_OAUTH2, metadata URL)` |
| `WithEndpoints(AAuthorizationURL, ATokenURL, AUserInfoURL)` | All three required at `Build`; the later of this and `WithImportedConfig` wins |
| `WithUserProfileClaims(AUserID, AUserName, AEmail)` | `userIDClaim`, `userNameClaim`, `emailClaim`: JSON fields of the user info response (dot notation for nested ones); empty keeps the Keycloak default (`sub`, `preferred_username`, `email`) |
| `WithNameClaims(AFullName, AGivenName, AFamilyName)` | `fullNameClaim`, `givenNameClaim`, `familyNameClaim` (defaults `name`, `given_name`, `family_name`) |
| `WithClientAuthMethod`, `DisablePkce` | As for OpenID Connect |

Defaults: no scope, PKCE S256, `client_secret_post`. The user ID must be stable and unique: Keycloak links the account with it. `WithTrustEmail` only for providers that verify the email: Keycloak has no `email_verified` here.

<!-- snippet ver=3.0 kind=body ctx=client uses=IAMClient4D.IdentityProvider.Core,IAMClient4D.IdentityProvider.Keycloak,IAMClient4D.IdentityProvider.Builders -->
```delphi
var LManager: IIAM4DIdentityProviderManager := TIAM4DKeycloakIdentityProviderManager.Create(LClient);
LManager.SaveIdentityProvider(
  TIAM4DOAuth2IdPBuilder.New('strava')
    .WithEndpoints('https://www.strava.com/oauth/authorize', 'https://www.strava.com/oauth/token',
      'https://www.strava.com/api/v3/athlete')
    .WithClient('strava-client-id', 'strava-client-secret')
    .WithScopes(['read'])
    .WithUserProfileClaims('id', 'username', '')
    .WithNameClaims('', 'firstname', 'lastname')
    .WithDisplayName('Strava')
    .Build);
```

## Social providers

Built-in Keycloak providers: Keycloak knows their endpoints, the builders set client, scopes, PKCE where the provider accepts it and the checks Keycloak leaves off.

| Builder | Defaults | Specific methods | Trust email |
|---------|----------|------------------|-------------|
| `TIAM4DGoogleIdPBuilder` | scopes `openid profile email`, PKCE | `WithHostedDomains(ADomains)`: `hostedDomain`, Google Workspace accounts of these domains only (lowercased; `['*']` alone: any Workspace account, no personal one). An invalid domain raises | Google sets `email_verified` |
| `TIAM4DFacebookIdPBuilder` | scopes `email public_profile`, no PKCE | `WithFetchedFields(AFields)`: `fetchedFields`, Graph API fields beyond `id`, `name`, `email`, `first_name`, `last_name` (each may need its permission in the scopes) | Off by default; turning it on lets a Facebook account take over a local account with the same email |
| `TIAM4DMicrosoftIdPBuilder` | tenant `consumers`, scope `User.Read`, PKCE | `WithTenant`: `consumers` (personal accounts; also when empty), `common`, `organizations` or a directory ID. OAuth 2.0 with the Microsoft Graph profile, no id_token: for work accounts prefer `TIAM4DEntraIdPBuilder` | Only with a directory ID (else `Build` raises: nOAuth) |
| `TIAM4DLinkedInIdPBuilder` | scopes `openid profile email`, no PKCE | | Keycloak takes `email_verified` from the id_token |
| `TIAM4DGitHubIdPBuilder` | scope `user:email`, PKCE | `WithEnterprise(ABaseURL, AApiURL)`: GitHub Enterprise Server, both or none, `https` | Not offered: Keycloak does not check that the address is verified. `TrustEmail` set by hand makes `Build` raise |
| `TIAM4DGitLabIdPBuilder` | scopes `openid read_user email` (`openid` required), PKCE; id_token signature and issuer (`https://gitlab.com`) checked | gitlab.com only (Keycloak 26 hard-codes its URLs): for a self-managed GitLab use `TIAM4DOidcIdPBuilder` with its discovery document | Requires the `email` scope |

Facebook accounts registered with a phone number have no email: Keycloak asks for it at the first login. For GitHub Apps add `WithConfig('githubJsonFormat', 'true')`.

`AttributeMapper(AIdentityProviderAlias, AJsonField, AUserAttribute)` (Google, Facebook, Microsoft, LinkedIn, GitHub) returns a mapper of type `<provider>-user-attribute-mapper` that imports a field of the profile into a user attribute (declare it in the realm user profile), sync mode `INHERIT`. GitLab has no attribute importer in Keycloak.

<!-- snippet ver=3.0 kind=body ctx=client uses=IAMClient4D.IdentityProvider.Core,IAMClient4D.IdentityProvider.Keycloak,IAMClient4D.IdentityProvider.Builders -->
```delphi
var LManager: IIAM4DIdentityProviderManager := TIAM4DKeycloakIdentityProviderManager.Create(LClient);
LManager.SaveIdentityProvider(
  TIAM4DGoogleIdPBuilder.New
    .WithClient('google-client-id', 'google-client-secret')
    .WithHostedDomains(['example.com'])
    .WithTrustEmail
    .Build);
LManager.CreateMapper(TIAM4DGoogleIdPBuilder.AttributeMapper('google', 'picture', 'picture'));

LManager.SaveIdentityProvider(
  TIAM4DGitHubIdPBuilder.New
    .WithClient('github-client-id', 'github-client-secret')
    // .WithEnterprise('https://github.example.com', 'https://github.example.com/api/v3')
    .Build);
```

**iOS apps.** App Store guideline 4.8 (Login Services) asks an app offering a third-party or social login for the primary account to offer also an equivalent privacy-preserving login service, such as Sign in with Apple; government electronic IDs (SPID, CIE ID) and enterprise-only accounts are among its exceptions. Keycloak needs an extension for Sign in with Apple; there is no builder for it (see [Provider types without a builder](#provider-types-without-a-builder)).

## SAML 2.0

`TIAM4DSamlIdPBuilder`, for ADFS, Shibboleth, Google Workspace (SAML) and other SAML identity providers.

| Method | Effect |
|--------|--------|
| `WithImportedConfig(AConfig)` | Provider side from `ImportConfig(IAM4D_IDP_PROVIDER_SAML, metadata URL)`: `idpEntityId`, `singleSignOnServiceUrl`, `singleLogoutServiceUrl`, `signingCertificate`, `encryptionPublicKey`, the bindings and the NameID format. The signature settings stay those of the builder |
| `WithIdentityProviderEndpoints(AEntityID, ASingleSignOnURL, ASigningCertificate, ASingleLogoutURL = '')` | By hand, POST bindings. The later of this and `WithImportedConfig` replaces the provider data of the other |
| `WithMetadataURL(AURL)` | Keycloak reads and refreshes the signing keys from the metadata (`useMetadataDescriptorUrl`) |
| `WithServiceProviderEntityID(AEntityID)` | `entityId` (default: the realm URL) |
| `WithNameIDFormat(AFormat)` | `IAM4D_SAML_NAMEID_PERSISTENT`, `_TRANSIENT`, `_EMAIL`, `_UNSPECIFIED`; wins over the imported one |
| `WithPrincipal(AType, AAttribute = '')` | `sptSubject` (NameID), `sptAttribute`, `sptFriendlyAttribute` with the attribute name |
| `DisableRequestSigning` | AuthnRequests not signed |
| `AllowUnsignedAssertions` | Assertions need not be signed (the response signature is still validated) |
| `DisableSignatureValidation` | No validation at all (tests only) |

Defaults: signed AuthnRequests, signed assertions, signature validation, POST bindings, `RSA_SHA256`, NameID persistent (unless imported or set), principal = subject NameID.

`Build` raises when the entity ID or the single sign-on URL is missing; when the signing certificate is missing while signatures are validated and `WithMetadataURL` is not used; when a non-subject principal has no attribute; when the principal is a transient NameID; when `TrustEmail` is set without signature validation.

`AttributeMapper(AIdentityProviderAlias, AAttributeName, AUserAttribute)` returns a `saml-user-attribute-idp-mapper` (attribute by name to user attribute).

`ExportServiceProviderMetadata(AAlias)` returns the SP descriptor to register at the identity provider.

<!-- snippet ver=3.0 kind=body ctx=client uses=IAMClient4D.IdentityProvider.Core,IAMClient4D.IdentityProvider.Keycloak,IAMClient4D.IdentityProvider.Builders -->
```delphi
var LManager: IIAM4DIdentityProviderManager := TIAM4DKeycloakIdentityProviderManager.Create(LClient);
LManager.SaveIdentityProvider(
  TIAM4DSamlIdPBuilder.New('adfs')
    .WithImportedConfig(LManager.ImportConfig(IAM4D_IDP_PROVIDER_SAML,
      'https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml'))
    .WithNameIDFormat(IAM4D_SAML_NAMEID_EMAIL)
    .WithDisplayName('Corporate account')
    .Build);
LManager.CreateMapper(TIAM4DSamlIdPBuilder.AttributeMapper('adfs',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname', 'firstName'));
var LMetadata := LManager.ExportServiceProviderMetadata('adfs');
```

## SPID and CIE ID

`TIAM4DSpidIdPBuilder` needs the Keycloak extension `italia/spid-keycloak-provider` (provider `spid-saml`), `TIAM4DCieIdPBuilder` the extension `lscorcia/keycloak-cieid-provider` (provider `cieid-saml`). Their version must match the Keycloak version; `IsProviderInstalled` tells whether they are installed.

**Common profile** (AgID rules), set by `New` and kept when importing metadata:

- signed AuthnRequests and assertions, signature validation, signed SP metadata: `Build` sets them back on even if changed with `WithConfig`;
- `forceAuthn`, POST bindings, `RSA_SHA256`, transient NameID, principal attribute `fiscalNumber`;
- level SpidL2 (`WithLevel(slL1 | slL2 | slL3)`, comparison `minimum`), attribute consuming service index 1;
- `TrustEmail` on and sync mode `FORCE` by default (`WithTrustEmail(False)`, `WithSyncMode` change them).

| Method | Effect |
|--------|--------|
| `WithImportedConfig(AConfig)` | Identity provider side of the metadata |
| `WithServiceProviderEntityID`, `WithLevel` | |
| `WithAttributeConsumingService(AIndex, AName)` | Index (0 or more) and service name, required at `Build` |
| `WithOrganization(AName, ADisplayName, AURL, ALocale = 'it')` | Organization of the SP metadata |

`Build` also requires the signing certificate of the identity provider (imported, or by hand), unless Keycloak reads the metadata (`WithMetadataURL`, SPID only).

The identity provider sends only the attributes requested in the SP metadata, which Keycloak derives from the mappers: add one for `fiscalNumber` (the principal) and one for every other attribute (`email`, `name`, `familyName`, ...) with `AttributeMapper(AIdentityProviderAlias, AAttribute, AUserAttribute)`.

**SP metadata.** `ExportServiceProviderMetadata` lacks the contacts AgID requires. Register the metadata the extensions publish: `TIAM4DSpidIdPBuilder.ServiceProviderMetadataURL(AKeycloakURL, ARealm)` (`{Keycloak}/realms/{realm}/spid-sp-metadata`, all SPID providers of the realm) and `TIAM4DCieIdPBuilder.ServiceProviderMetadataURL` (`.../cieid-sp-metadata`).

### SPID

One provider per SPID identity provider; their metadata links are in the AgID registry (`IAM4D_SPID_REGISTRY_URL`).

| Method | Effect |
|--------|--------|
| `WithMetadataURL`, `WithIdentityProviderEndpoints` | As for SAML |
| `WithPublicServiceProvider(AIpaCode, AEmail, APhone = '')` | Public administration: IPA code required |
| `WithPrivateServiceProvider(AVatNumber, AFiscalCode, ACompany, AEmail, APhone = '')` | VAT number (with country code, e.g. `IT12345678901`) or fiscal code required |
| `WithBillingContact(ACompany, AEmail, APhone, ARegisteredName, AAddress, AStreetNumber, APostalCode, ACity, AProvince, ACountry = 'IT')` | Private service providers only (`Build` raises otherwise) |

The extension reads organization and contacts from the first enabled SPID provider in alias order: set them on each one.

<!-- snippet ver=3.0 kind=body ctx=client uses=IAMClient4D.IdentityProvider.Core,IAMClient4D.IdentityProvider.Keycloak,IAMClient4D.IdentityProvider.Builders -->
```delphi
var LManager: IIAM4DIdentityProviderManager := TIAM4DKeycloakIdentityProviderManager.Create(LClient);
LManager.SaveIdentityProvider(
  TIAM4DSpidIdPBuilder.New('spid-poste')
    .WithDisplayName('Poste ID')
    .WithImportedConfig(LManager.ImportConfig(IAM4D_IDP_PROVIDER_SPID,
      'https://registry.spid.gov.it/entities-idp/https%3A%2F%2Fposteid.poste.it'))
    .WithLevel(slL2)
    .WithAttributeConsumingService(1, 'Servizi online')
    .WithOrganization('Comune di Esempio', 'Comune di Esempio', 'https://www.comune.esempio.it')
    .WithPublicServiceProvider('c_x000', 'protocollo@comune.esempio.it')
    .WithHideOnLogin
    .Build);
LManager.CreateMapper(TIAM4DSpidIdPBuilder.AttributeMapper('spid-poste', 'fiscalNumber', 'fiscalNumber'));
var LMetadataURL := TIAM4DSpidIdPBuilder.ServiceProviderMetadataURL('http://localhost:18180/auth', 'iamclient4d');
```

### CIE ID

| Method | Effect |
|--------|--------|
| `WithEnvironment(ceProduction | cePreProduction)` | Endpoints of that identity server (production by default); any order with `WithImportedConfig` |
| `MetadataURL(AEnvironment = ceProduction)` (class) | Metadata of the identity server, for `ImportConfig` |
| `WithPublicServiceProvider(ACompany, AIpaCode, AIpaCategory, AEmail, APhone = '')` | Public administration |
| `WithPrivateServiceProvider(ACompany, AVatNumber, AFiscalCode, AEmail, APhone = '')` | Private service provider |
| `WithTechnicalContact(ACompany, AVatNumber, AFiscalCode, AEmail, APhone = '')` | Technical contact |

Display name `CIE ID`. `Build` rejects imported metadata of the other identity server than `WithEnvironment`; without `WithEnvironment` the imported metadata decides.

<!-- snippet ver=3.0 kind=body ctx=client uses=IAMClient4D.IdentityProvider.Core,IAMClient4D.IdentityProvider.Keycloak,IAMClient4D.IdentityProvider.Builders -->
```delphi
var LManager: IIAM4DIdentityProviderManager := TIAM4DKeycloakIdentityProviderManager.Create(LClient);
LManager.SaveIdentityProvider(
  TIAM4DCieIdPBuilder.New
    .WithEnvironment(cePreProduction)
    .WithImportedConfig(LManager.ImportConfig(IAM4D_IDP_PROVIDER_CIE,
      TIAM4DCieIdPBuilder.MetadataURL(cePreProduction)))
    .WithAttributeConsumingService(1, 'Servizi online')
    .WithPublicServiceProvider('Comune di Esempio', 'c_x000', 'L6', 'protocollo@comune.esempio.it')
    .WithOrganization('Comune di Esempio', 'Comune di Esempio', 'https://www.comune.esempio.it')
    .Build);
```

## Provider types without a builder

Other provider types (the built-in `bitbucket` or `paypal`, an extension such as Sign in with Apple) are filled by hand, with the config keys of the Keycloak admin console.

<!-- snippet ver=3.0 kind=body ctx=client uses=IAMClient4D.IdentityProvider.Core,IAMClient4D.IdentityProvider.Keycloak -->
```delphi
var LManager: IIAM4DIdentityProviderManager := TIAM4DKeycloakIdentityProviderManager.Create(LClient);
var LIdP := TIAM4DIdentityProvider.Create('bitbucket', 'bitbucket');
LIdP.Config.Values['clientId'] := 'bitbucket-client-id';
LIdP.Config.Values['clientSecret'] := 'bitbucket-client-secret';
LManager.CreateIdentityProvider(LIdP);
```

From a form, the async manager:

<!-- snippet ver=3.0 kind=body ctx=client,ui uses=IAMClient4D.IdentityProvider.Core,IAMClient4D.IdentityProvider.Keycloak.Async -->
```delphi
var LAsync: IIAM4DIdentityProviderManagerAsync := TIAM4DKeycloakIdentityProviderManagerAsync.Create(LClient);
LAsync.GetIdentityProvidersAsync
  .OnSuccess(
    procedure(const AProviders: TArray<TIAM4DIdentityProvider>)
    begin
      for var LIdP in AProviders do
        ShowMessage(LIdP.Alias + ' (' + LIdP.ProviderID + ')');
    end)
  .OnError(
    procedure(const AException: Exception)
    begin
      ShowMessage(AException.Message);
    end)
  .Run;
```

## Tests and samples

- `tests/IdentityProvider`: builders, JSON mapping and, against a real Keycloak, management and the login redirect of every provider type (see its README). `tests/IdentityProvider/docker` starts a throwaway Keycloak with the SPID and CIE extensions and the AgID test identity provider (`up.cmd` / `down.cmd`).
- `Docker/identity-providers/*.ps1`: scripts that add providers to the [sample environment](../../Docker/README.md).
- `samples/VCL/KeycloakClient`: identity provider field for the login; list, save (Entra ID) and delete providers.
- `samples/VCL/IdentityBrokering`: login buttons for Entra ID, Google, Facebook, Microsoft accounts, SPID and CIE, and an administration tab for every builder. `samples/FMX/IdentityBrokering`: the same for Android and iOS.
