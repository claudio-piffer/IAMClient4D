# Keycloak setup

How to configure a Keycloak of your own for IAMClient4D: realm, clients for each scenario, users and roles. To try the library first, use the sample environment of [`Docker/`](../../Docker/README.md): its realm `iamclient4d` already has every client and user described here, and the export (`Docker/config/keycloak/realm/realm.json`) is a working reference.

Tested with Keycloak 25.0, 26.7 and 26.8. The labels are those of the Keycloak 26 admin console.

## Contents

- [Administrator](#administrator)
- [Realm](#realm)
- [Clients](#clients)
- [API audience and roles](#api-audience-and-roles)
- [Users and roles](#users-and-roles)
- [Check the configuration](#check-the-configuration)

## Administrator

Keycloak 26 creates a temporary administrator at the first start (`KC_BOOTSTRAP_ADMIN_USERNAME` / `KC_BOOTSTRAP_ADMIN_PASSWORD`) and shows a warning until a permanent one exists.

1. Realm `master`, *Users* > *Add user*: username, email, *Email verified* on. *Create*.
2. *Credentials* > *Set password*, *Temporary* off.
3. *Role mapping* > *Assign role* > *Realm roles*: `admin`.
4. Sign out, sign in with the new administrator, then delete or disable the temporary one.

## Realm

*Create realm*, e.g. `myrealm`. The issuer is `<base URL>/realms/myrealm`; the base URL includes the relative path when Keycloak has one (the sample environment uses `/auth`: `http://localhost:18180/auth`). Pass the base URL and the realm name to the builder, not the issuer.

Over the network Keycloak must be reachable through `https`: the library refuses `http://` to a host other than the loopback (`WithAllowInsecureHTTP` for test environments only) and refuses an `http` endpoint in the discovery document of an `https` realm.

## Clients

*Clients* > *Create client*, type *OpenID Connect*. One client per kind of application:

| Application | Client authentication | Authentication flow | Redirect URIs | Builder |
|---|---|---|---|---|
| Desktop app (local callback server) | off (public) | Standard flow | `http://localhost/oauth2callback`, `http://127.0.0.1/oauth2callback` | `ForAuthorizationCode` |
| Mobile app (private-use scheme) | off (public) | Standard flow | `com.example.app:/oauth2callback` | `ForAuthorizationCode` + `WithAppRedirect` |
| Web app (server side) | on (confidential) | Standard flow | `https://app.example.com/auth/callback` | `ForAuthorizationCode` with secret + `WithExternalCallback` |
| Service to service | on (confidential) | Service accounts roles | none | `ForClientCredentials` |
| Username and password | off or on | Direct access grants | none | `ForPassword` |

For every Standard flow client, in *Advanced* > *Advanced settings*: *Proof Key for Code Exchange Code Challenge Method* `S256`. The library always sends PKCE S256; requiring it on the server refuses a client that does not.

Notes:

- **Loopback redirect URIs.** The local callback server listens on `/oauth2callback` of a port chosen by the system. Keycloak ignores the port of a loopback redirect URI (RFC 8252 7.3), so register it without a port. `WithLoopbackRedirectHost(lrhLoopbackIP)` uses `127.0.0.1` instead of `localhost`; `WithCallbackPort` fixes the port when a server compares the port too.
- **Post logout redirect URIs.** A web app that sends the browser to `GenerateLogoutURL(APostLogoutRedirectURI)` must register that URI in *Valid post logout redirect URIs* (`+` repeats the redirect URIs).
- **Direct access grants.** Keep them on a client of their own: the password grant cannot go through a brokered identity provider nor complete MFA or required actions.
- **`at+jwt` access tokens.** *Advanced* > *Use "at+jwt" as access token header type* (attribute `access.token.header.type.rfc9068`) makes the access tokens RFC 9068 tokens. The DMVC filters accept them by default; a `TIAM4DJWTValidator` needs `SetAllowedHeaderTypes(['JWT', 'at+jwt'])` ([Security.md](Security.md)).
- **Offline tokens.** Request the `offline_access` scope (`WithScopes`); the user needs the realm role `offline_access` (default role of new realms). `RevokeTokens` and `Logout` end the offline session.

### Admin REST API client

An application that manages users, roles or identity providers ([AdminAPI.md](AdminAPI.md), [IdentityBrokering.md](IdentityBrokering.md)) calls the Admin REST API with the token of a client:

- a service account (*Service accounts roles* on), with the client roles of `realm-management` it needs: `view-users` / `query-users` to read, `manage-users` to change users, `manage-identity-providers` for identity providers, or `realm-admin` for everything;
- or a user signed in through a client, with the same roles assigned to the user.

With Keycloak 26.8.2 or later the token must also carry the audience of the `kc-admin-api` client scope, which is a default scope only of `admin-cli` and `security-admin-console`: *Clients* > the client > *Client scopes* > *Add client scope* > `kc-admin-api`, type *Default*. Without it every Admin API call answers 401.

## API audience and roles

A REST API validated by the DMVC filters ([DMVC.md](DMVC.md)) or by `TIAM4DJWTValidator` checks the audience of the token. Model the API as a client of its own (e.g. `api-server`, no flow enabled) with its client roles (e.g. `calculator-user`, `calculator-advanced`).

The clients that call the API add its audience: *Clients* > the calling client > *Client scopes* > the dedicated scope > *Configure a new mapper* > *Audience*, *Included Client Audience* `api-server`, *Add to access token* on. The access token then has `aud` `api-server` and the client roles of `api-server` in `resource_access`.

## Users and roles

*Users* > *Add user*, then *Credentials* > *Set password* (*Temporary* off for a test user; on, the first login asks for a new password, which the password grant reports as `EIAM4DAccountNotFullySetUpException`). Assign the client roles of the API in *Role mapping* > *Assign role* > *Client roles*.

The sample realm has `demo` (`realm-admin`), `student` (`calculator-user`) and `scientist` (`calculator-user`, `calculator-advanced`); the passwords are in [`Docker/README.md`](../../Docker/README.md).

## Check the configuration

A desktop login against the realm, with the public client of the first row of the table:

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
LClient := TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('https://keycloak.example.com', 'myrealm', 'my-desktop-app')
  .Build;
LClient.StartAuthorizationFlowAsync
  .OnSuccess(
    procedure(const AAccessToken: string)
    begin
      ShowMessage('Signed in as ' + LClient.GetIDTokenClaims.PreferredUsername);
    end)
  .OnError(
    procedure(const E: Exception)
    begin
      ShowMessage(E.ClassName + ': ' + E.Message);
    end)
  .Run;
```

The browser opens the Keycloak login page; after the login the library validates the id_token and the callback, and the promise completes. Errors: [Core.md](Core.md) and the troubleshooting of [`Docker/README.md`](../../Docker/README.md).
