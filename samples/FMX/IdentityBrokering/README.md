# Identity Brokering (FMX sample, Android and iOS)

FMX demo of IAMClient4D identity brokering for the phone: login straight to Microsoft Entra ID, a personal Microsoft account, Google, Facebook, SPID or CIE ID through Keycloak (`kc_idp_hint`), and the identity providers configured from the application through the Keycloak Admin REST API. It is the mobile version of [samples/VCL/IdentityBrokering](../../VCL/IdentityBrokering/README.md): same functions, same defaults, same test Keycloak. Android and Android64 are built, iOS device and simulator are compiled (no Mac here), Win32 and Win64 run it with the loopback server, handy while developing. RAD Studio 13.

The login does not use a loopback server on the phone: Keycloak redirects the browser to `it.iam4d.identitybrokering:/oauth2callback`, a URI on a private-use scheme (RFC 8252 7.1) that the operating system hands back to the app.

## Screens

- **Sign in**: Keycloak, Entra ID (work or school account), Microsoft (personal account), Google, Facebook, SPID and CIE tiles; the *Connection* card (tap to edit base URL, realm, client; it shows the redirect URI of the platform); session buttons (user info, token, sign out); an output window. While a login waits for the browser a **Cancel** button appears.
- **Providers** (IdP administration, needs the session of the first page; the dock and the page appear only when the access token has the realm-management role `view-identity-providers` or `manage-identity-providers`): *Providers* (list, refresh, delete, URLs to register), *Entra ID* (with the *Prompt* sent to Entra ID: `select_account` or `login` so that an Entra ID session still open in the browser does not sign in again with no question after Sign out), *Google*, *Facebook*, *Generic OIDC* (discovery URL, alias, client and secret; no login tile: sign in from the Keycloak page), *Other providers* (provider type: Microsoft account, LinkedIn, GitHub, GitLab.com or any OAuth 2.0 provider; alias, client, secret and the fields of the type: tenant for Microsoft, Enterprise URLs for GitHub, endpoints, scopes and profile fields for OAuth 2.0; hide on login, trust email, not for GitHub; only the Microsoft account has a login tile, the others sign in from the Keycloak page or with the alias as `kc_idp_hint`), *SPID* (AgID registry; the first item, *SPID test (spid-saml-check)*, saves `spid-test` from the demo identity provider of the test stack, also without the registry), *CIE ID* (the *Local test (CIE simulator)* environment is the default), *Service provider* and *Log*.
- The SPID tile opens a bottom sheet with the identity providers of the AgID registry and of the realm (checked: found in the realm); *Other alias...* proposes `spid-test` and is there also without the registry.
- On the *Providers* page the choice fields (Entra ID prompt, SPID identity provider and level, CIE environment and level, service provider type, type of the other providers) open the same kind of bottom sheet instead of the platform list: one row per choice with a short description, the current one checked.

## Keycloak and device

```bat
Docker\start.cmd brokering     & rem Keycloak 26.8.2 + SPID/CIE extensions, http://localhost:18180/auth
```

The sample environment of [`Docker/`](../../../Docker/README.md), with the SPID demo identity provider and the CIE simulator (profile `brokering`). The sample defaults match its realm `iamclient4d` (client `iam4d-sample-app`, user `demo` / `demo` with `realm-admin`), whose client accepts `it.iam4d.identitybrokering:/oauth2callback`. On a phone `localhost` is the phone: forward the ports of the environment through USB (USB debugging on, `adb devices` lists the phone):

```bat
adb reverse tcp:18180 tcp:18180     & rem Keycloak
adb reverse tcp:18443 tcp:18443     & rem SPID demo identity provider (spid-test)
adb reverse tcp:18444 tcp:18444     & rem CIE simulator
```

Keycloak publishes `http://localhost:18180/auth` (`KC_HOSTNAME`), so every redirect of the brokered logins (SPID, CIE) goes to `localhost` on the phone, through the forwarded ports.

`keycloak.cmd` (Windows) and `keycloak.sh` in this folder do both steps:

```bat
keycloak.cmd           & rem Docker\start.cmd brokering, then adb reverse of 18180, 18443 and 18444
keycloak.cmd reverse   & rem forward the ports again, after reconnecting the phone
keycloak.cmd logs      & rem follow the Keycloak log
keycloak.cmd stop      & rem remove the forwards, Docker\stop.cmd (data kept)
```

The ports follow `Docker/.env` (`KC_PORT`, `SPID_CHECK_PORT`, `CIE_CHECK_PORT`). With Docker inside WSL, `start` also opens a minimized *IAMClient4D WSL keep-alive* window (through `Docker\start.cmd`), because WSL stops when idle and the containers with it; `stop` closes it. The providers saved from the app stay in the database of the environment until `Docker\delete-volumes.cmd`. `ADB` selects the adb to use (default: the one of the RAD Studio Android SDK, as `build.bat`; `adb` from the PATH for `keycloak.sh`), `ANDROID_SERIAL` the device when more than one is connected.

## Build

```bat
samples\FMX\IdentityBrokering\build.bat                 & rem Android64 (default): build and package the APK
samples\FMX\IdentityBrokering\build.bat Android64 install   & rem and install it with adb (the phone must be connected)
samples\FMX\IdentityBrokering\build.bat Android         & rem 32 bit
samples\FMX\IdentityBrokering\build.bat Win64           & rem desktop, loopback redirect
```

`RSVARS` selects another RAD Studio installation; `ADB` the `adb.exe` (default: the one of the RAD Studio Android SDK). Output: `samples\bin\FMX\<platform>\Debug`, units in `samples\dcu\FMX`. iOS needs a Mac (PAServer): the project is set up for `iOSDevice64` and `iOSSimARM64`, here only compiled.

The `.dproj` is modelled on a RAD Studio 13 sample and the `.deployproj` is written by hand: if the deployment of a platform fails, open the project once in the IDE (pick the platform, *Project > Deployment*, save).

## How the login works

```pascal
TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode(BaseURL, Realm, ClientID)
  .WithAppRedirect('it.iam4d.identitybrokering:/oauth2callback')   // Android and iOS only
  .BuildAsync ...
// FormCreate
TIAM4DAppRedirectListener.Install(AppRedirectReceived);
```

1. `StartAuthorizationFlowAsync(Alias)` opens the Keycloak page in a **Custom Tab** (Android) or in Safari (iOS) and returns a promise.
2. After the login Keycloak redirects to `it.iam4d.identitybrokering:/oauth2callback?code=...&state=...`. The manifest intent filter (Android, `singleTask`: the activity is resumed and the Custom Tab, which is in the same task, closes by itself) or `CFBundleURLTypes` (iOS) hands the URL to the app.
3. `TIAM4DAppRedirectListener` passes it to `TIAM4DAppRedirect.HandleURL`: if it is the redirect of the login that waits (URI and state), the code is exchanged (PKCE) and the promise completes; otherwise it is ignored. The sample logs the scheme and path of every URL it receives (never the code).
4. **Cancel**, or coming back from the browser without the redirect (the browser tab closed: the sample cancels after one second; it also cancels if the user switches back to the app by hand), ends the login as cancelled. The Back button closes the SPID sheet, then returns to the first page; from there, it leaves the app and cancels a pending login.

If Android kills the app while the browser is open, the redirect finds no login waiting: the sample writes *Redirect received ... no login is waiting ... the login is interrupted* and the user signs in again. The pending login is not persisted (the README of the library lists it as a follow-up).

## Walkthrough on the phone

1. `keycloak.cmd` (or `Docker\start.cmd brokering` and `adb reverse`, above), `build.bat Android64 install`, start **IdentityBrokering**.
2. **Keycloak**: the Custom Tab shows the Keycloak page, sign in as `demo` / `demo`: the tab closes by itself and the output shows user info and token.
3. **Providers**: the list loads (`spid-test`); *CIE ID* > **Import metadata and save** creates the provider `cie` with the simulator; wait a few seconds (the simulator registers the new SP metadata).
4. **Sign out**, then **SPID** > *Other alias...* > `spid-test` (sign in as `ada` / `password123` at the demo identity provider and confirm), and **CIE** (`marcopolo` / `password123`, within 60 seconds).
5. Google and Facebook: save them in *Google* and *Facebook* (or with `Docker\identity-providers\google.ps1` and `facebook.ps1`), redirect URIs `http://localhost:18180/auth/realms/iamclient4d/broker/google/endpoint` and `.../broker/facebook/endpoint`: the phone reaches Keycloak through `adb reverse`, so the same URIs work. Both refuse embedded web views; the Custom Tab is a real browser.
6. Microsoft account, LinkedIn, GitHub, GitLab.com, any OAuth 2.0 provider: save them in *Other providers* (or with `microsoft.ps1`, `linkedin.ps1`, `github.ps1`, `gitlab.ps1`, `oauth2.ps1` in `Docker\identity-providers`), redirect URI `http://localhost:18180/auth/realms/iamclient4d/broker/<alias>/endpoint`; the **Microsoft** tile signs in with the alias `microsoft`.
7. Cancel paths: close the Custom Tab (login cancelled after a second), **Cancel**, a refusal at the identity provider (`access_denied`, shown as *Login failed*).
8. `adb shell am start -a android.intent.action.VIEW -d "it.iam4d.identitybrokering:/oauth2callback?code=x&state=y"`: the app comes to the front and logs *Redirect ignored* (a login waiting) or *no login is waiting*.

## Notes and limits

- `android:usesCleartextTraffic="true"` in `AndroidManifest.template.xml` is only for the local sample Keycloak over `http`; use `https` in a real app. On iOS, App Transport Security blocks cleartext `http` too (this sample's `info.plist.TemplateiOS.xml` does not change it): use an `https` Keycloak, or add the exception for your test host.
- A private-use scheme can be claimed by another app; PKCE keeps it from using the code (RFC 8252 8.1). Safari asks the user to confirm opening the app (a follow-up could use `ASWebAuthenticationSession`).
- `TIAM4DAppRedirectListener.Install` replaces the process-wide `TIAM4DPlatformUtils.OpenURLHandler` (to open Custom Tabs); `Uninstall` restores it.
- The auto-cancel when the user comes back from the browser is a heuristic (`BecameActive` and no redirect within a second).
- iOS is compiled only here: the Safari prompt, `CFBundleURLTypes` and the `OpenURL` event are not exercised.
