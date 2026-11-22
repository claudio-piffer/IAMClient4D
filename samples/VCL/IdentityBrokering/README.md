# Identity Brokering (VCL sample)

VCL demo of IAMClient4D identity brokering: login straight to Microsoft Entra ID, a personal Microsoft account, Google, Facebook, SPID or CIE ID through Keycloak (`kc_idp_hint`), and the identity providers configured from the application through the Keycloak Admin REST API. Win32 and Win64, RAD Studio 13.

## Keycloak

```bat
Docker\start.cmd brokering   & rem Keycloak 26.8.2 + SPID/CIE extensions, http://localhost:18180/auth
Docker\stop.cmd              & rem stop; the providers created from the sample stay until delete-volumes.cmd
```

The sample environment of [`Docker/`](../../../Docker/README.md) (Linux/macOS: `start.sh`, `stop.sh`), with the SPID demo identity provider and the CIE simulator (profile `brokering`). The sample defaults match its realm: base URL `http://localhost:18180/auth`, realm `iamclient4d`, client `iam4d-sample-app` (public, PKCE, local callback on any loopback port: redirect URIs `http://localhost/oauth2callback` and `http://127.0.0.1/oauth2callback`, port ignored as in RFC 8252, and `it.iam4d.identitybrokering:/oauth2callback` for the [mobile version](../../FMX/IdentityBrokering/README.md)), user `demo` / `demo` with `realm-admin`.

## "Login" tab

| Button | `kc_idp_hint` |
|--------|---------------|
| Sign in with Entra ID | `entra` (work and school accounts) |
| Microsoft account | `microsoft` (personal Microsoft accounts) |
| Sign in with Google | `google` |
| Sign in with Facebook | `facebook` |
| Sign in with SPID | `spid-<name>` of the SPID identity provider picked in the menu (AgID registry and SPID providers of the realm; checked: found in the realm); *Other alias...*, always present (also when the AgID registry cannot be read), proposes `spid-test` |
| Sign in with CIE | `cie` |
| Keycloak login page | none: Keycloak login page |

`StartAuthorizationFlowAsync(Alias)` opens the browser and waits for the callback. After the login the sample shows user info and access token (claims decoded for display, not verified); **Sign out** logs out. **Cancel login** ends a login still waiting for the browser; closing the form cancels it and closes when every pending operation has finished.

## "IdP administration" tab

It uses the session of the "Login" tab: sign in first on the Keycloak page as `demo` / `demo` (the realm-management roles `view-identity-providers` and `manage-identity-providers` are needed). The tab appears after the login only when the access token has `view-identity-providers` or `manage-identity-providers` in `resource_access.realm-management` (`realm-admin` puts them there too); the token is read, not verified, to show the tab: the Admin REST API checks the permission at every call. All calls are asynchronous (`IIAM4DIdentityProviderManagerAsync`).

- **Realm identity providers**: list and delete.
- **Microsoft Entra ID**: tenant, application (client) ID and secret (`TIAM4DEntraIdPBuilder`); an empty secret on an existing provider keeps the stored one, as long as tenant and client ID do not change (Keycloak 26.8.1+ asks for the secret again when the token URL or the client ID changes). *Prompt* (`WithPrompt`) is sent to Entra ID at every login: not set, an Entra ID session still open in the browser signs in again with no question, also after **Sign out** (back-channel, it ends only the Keycloak session); `select_account` shows the account picker, `login` asks for the credentials. The form is not loaded from Keycloak: saving with *Not set* removes the stored prompt.
- **Google**: client ID and secret of an OAuth client of type *Web application* (`TIAM4DGoogleIdPBuilder`: PKCE), optional hosted domains (Google Workspace, comma-separated; `*` any Workspace account, no personal one) and *Trust email*.
- **Facebook**: app ID and secret of a Meta app with Facebook Login (`TIAM4DFacebookIdPBuilder`); trust email stays off, Meta does not state that the email is verified.
- **Generic OIDC**: discovery URL (Keycloak imports it: it must be reachable from Keycloak), alias (default `oidc`), client ID and secret of a confidential client at the provider (`TIAM4DOidcIdPBuilder`: PKCE, signature and issuer checked). No login button: sign in from the Keycloak login page (button of the provider), or with the alias in the *Identity provider* field of `samples/VCL/KeycloakClient`.
- **Other providers**: provider type *Microsoft account* (`TIAM4DMicrosoftIdPBuilder`, tenant default `consumers`; trust email only with a directory ID), *LinkedIn* (`TIAM4DLinkedInIdPBuilder`), *GitHub* (`TIAM4DGitHubIdPBuilder`, optional GitHub Enterprise web and API URLs; trust email disabled), *GitLab.com* (`TIAM4DGitLabIdPBuilder`) or *Any OAuth 2.0 provider* (`TIAM4DOAuth2IdPBuilder`: authorization, token and user info URLs, scopes, profile fields `id,login,email`); alias (default per type, it follows the type until edited), client ID and secret, hide on login, trust email. No login button except *Microsoft account*: sign in from the Keycloak login page or with the alias as `kc_idp_hint`.
- **SPID**: **Load AgID registry** reads `IAM4D_SPID_REGISTRY_URL`; pick the identity provider, Keycloak imports its metadata (`ImportConfig` from the registry entry) and the sample saves it as `spid-<second-level domain of the entity ID>`, e.g. `https://posteid.poste.it` gives `spid-poste` (`TIAM4DSpidIdPBuilder`). Then it adds the missing attribute mappers `fiscalNumber`, `email`, `name` and `familyName`: SPID identity providers send only the attributes requested in the SP metadata, which Keycloak derives from the mappers, and `fiscalNumber` is the principal. The first item, *SPID test (spid-saml-check)*, is there also without the registry: it saves `spid-test` from the demo identity provider of the sample environment (metadata URL editable for another `SPID_CHECK_PORT`), so that `spid-test` can be deleted and created again.
- **CIE ID**: production or pre-production identity server, metadata imported from `TIAM4DCieIdPBuilder.MetadataURL`; *Local test (CIE simulator)*, the default: the CIE simulator of the sample environment, metadata imported from the editable URL (default `http://cie-simulator:18444/demo/metadata.xml`, the name Keycloak reaches in Docker) without `WithEnvironment`. Then the missing attribute mappers `fiscalNumber`, `name` and `familyName` (`TIAM4DCieIdPBuilder.AttributeMapper`).
- **Service provider (SPID and CIE)**: organization, contacts (public administration: IPA code; private: VAT number or fiscal code) and service name (`WithAttributeConsumingService`, required `ServiceName` of the SP metadata).
- **URLs to register with the provider**: broker redirect URI `{issuer}/broker/{alias}/endpoint` (Entra ID: redirect URI of type Web; Google: authorized redirect URI; Facebook: valid OAuth redirect URI; generic OIDC: redirect URI of the client; Microsoft account: redirect URI of type Web; GitHub: authorization callback URL) and SP metadata `.../spid-sp-metadata` (AgID) and `.../cieid-sp-metadata` (CIE).

## Walkthrough

1. `Docker\start.cmd brokering`, then start the sample.
2. **Keycloak login page**: sign in as `demo` / `demo`.
3. **IdP administration**: save Entra ID (app registration with redirect URI `http://localhost:18180/auth/realms/iamclient4d/broker/entra/endpoint`, or with `Docker\identity-providers\entra.ps1`), Google and Facebook (redirect URIs `.../broker/google/endpoint` and `.../broker/facebook/endpoint`; Google and Facebook accept `http` for `localhost`, Facebook while the app is in development mode), one or more SPID identity providers, CIE ID.
4. **Sign out**, then **Sign in with Entra ID**, **Microsoft account**, **Google**, **Facebook**, **SPID** or **CIE**: the browser opens the provider page directly.

SPID and CIE identity servers accept only service providers whose metadata is registered with AgID or the Ministry of the Interior: with the local Keycloak the browser reaches their page with a signed request, but the login cannot be completed. The sample environment has local stand-ins for both, below.

### Complete SPID login on this machine

The realm includes the SPID provider `spid-test`, bound to the demo identity provider of spid-saml-check (see [Docker/](../../../Docker/README.md#spid-and-cie-profile-brokering)):

1. **Sign in with SPID**, *Other alias...*, `spid-test`: the item is in the menu also without the AgID registry (offline).
2. The browser opens `http://localhost:18443/demo`: sign in as `ada` / `password123` and confirm the attributes.
3. The sample shows user info and token of the brokered user (username: the fiscal number, also in the user attribute `fiscalNumber`).

### Complete CIE login on this machine (CIE simulator)

The sample environment includes a CIE simulator, a second spid-saml-check relabelled *Simulatore CIE*; the CIE provider is created from the sample (see [Docker/](../../../Docker/README.md#spid-and-cie-profile-brokering)):

1. **Keycloak login page** as `demo` / `demo`; **IdP administration**, *CIE ID*: environment *Local test (CIE simulator)* (the default), alias `cie`, **Import metadata and save**.
2. After a few seconds (the simulator registers the new CIE SP metadata): **Sign out**, then **Sign in with CIE**.
3. The browser opens `http://localhost:18444/demo`: sign in as `marcopolo` / `password123` (level 3, as CIE ID) within 60 seconds and confirm the attributes.
4. At the first login Keycloak asks for the email (CIE ID does not return it); the sample shows user info and token of the brokered user (username: the fiscal number).
