# Guida di migrazione a IAMClient4D 3.0 (dalla 2.x)

<!-- Traduzione italiana di docs/MIGRATION_3.0.md, da cui si genera docs/IAMClient4D_3.0_Guida_Migrazione_IT.docx. La fonte è il testo inglese: ogni modifica va fatta prima lì. -->

Questa guida elenca cosa cambiare, o verificare, quando si porta un'applicazione da IAMClient4D 2.x alla 3.0. Quasi tutto il codice 2.x compila sulla 3.0 senza modifiche. Il lavoro sta soprattutto nei comportamenti che la 3.0 rende più severi: il codice compila ancora, ma a runtime il risultato cambia.

Come leggerla:

- ogni voce ha uno snippet **prima** (2.1) e uno **dopo** (3.0) quando il codice cambia, e una riga **cosa fare**;
- gli snippet "dopo" compilano sulla 3.0. Gli snippet "prima" compilano sulla 2.1, tranne quelli DMVC: il middleware 2.1 richiede una DMVCFramework precedente alla 3.5, che la 3.0 non supporta, quindi sono controllati solo sulle dichiarazioni della 2.1;
- l'elenco completo delle differenze, unit per unit, con i riferimenti al codice, è in [`docs/release-3.0/API_DIFF_2.1_3.0.md`](API_DIFF_2.1_3.0.md).

Indice:

1. [Requisiti](#1-requisiti)
2. [Sicurezza: comportamenti più severi](#2-sicurezza-comportamenti-più-severi)
3. [Interfacce](#3-interfacce)
4. [Rimossi e deprecati](#4-rimossi-e-deprecati)
5. [Errori ed eccezioni](#5-errori-ed-eccezioni)
6. [Admin API](#6-admin-api)
7. [Async.Core](#7-asynccore)
8. [Dati: date, scope, logout](#8-dati-date-scope-logout)
9. [DMVCFramework](#9-dmvcframework)
10. [Cosa si guadagna](#10-cosa-si-guadagna)
11. [Checklist](#11-checklist)

---

## 1. Requisiti

| | 2.x | 3.0 |
|---|---|---|
| Delphi | 12.3 o successiva (non controllato) | Delphi 12 o successiva, provata con Delphi 13. `IAMClient4D.Config.inc` ferma i compilatori più vecchi con un errore fatale |
| DMVCFramework | 3.4 o successiva | **3.5.0-silicon-rc10 o successiva**: il middleware usa `TMVCUser` e i filter bundle |
| Keycloak | 22 o successiva | 25 o successiva, provata con 25.0, 26.7 e 26.8 |
| Provider crittografico | LockBox3 (default) o TMS | LockBox3 (default), TMS, oppure TaurusTLS/OpenSSL 3.x-4.x. TMS e TaurusTLS non si possono attivare insieme |
| Piattaforme | Win32, Win64 | Win32, Win64, Linux64, Android, iOS, macOS |

**Cosa fare:**

- aggiornare DMVCFramework alla 3.5.0-silicon-rc10 o successiva prima di aggiornare il middleware. Il middleware 2.x non compila sulla DMVC 3.5, e quello 3.0 non compila sulla 3.4;
- con Keycloak 26.8.2 o successiva, i token dell'Admin REST API devono avere l'audience del client scope `kc-admin-api`: aggiungere quello scope ai default client scope del client che chiama l'Admin API, altrimenti ogni chiamata risponde 401;
- su Linux il pinning delle chiavi pubbliche non è supportato: `AddPinnedPublicKeys` e `WithPinnedPublicKeys` sollevano `ENotSupportedException`.

---

## 2. Sicurezza: comportamenti più severi

Questi cambi non richiedono modifiche al codice se la configurazione è già corretta. Rompono invece gli ambienti di test e i server configurati male: vanno verificati uno per uno.

### 2.1 `http://` in chiaro rifiutato fuori dal loopback

`BaseURL`, l'URL di una callback esterna e ogni endpoint del documento di discovery devono usare `https`, a meno che l'host sia `localhost`, `127.0.0.0/8` o `::1`. In un realm `https`, anche un endpoint `http` nel documento di discovery viene rifiutato. L'errore è `EIAM4DInvalidConfigurationException`.

Prima (2.1), accettato:

<!-- snippet ver=2.1 kind=body ctx=client -->
```delphi
LClient := TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('http://keycloak.test.lan:8080', 'demo', 'demo_public')
  .Build;
```

Dopo (3.0), solo per un server di test:

<!-- snippet ver=3.0 kind=body ctx=client -->
```delphi
LClient := TIAM4DClientConfigBuilder.New
  .ForAuthorizationCode('http://keycloak.test.lan:8080', 'demo', 'demo_public')
  .WithAllowInsecureHTTP // solo ambienti di test: i token viaggiano in chiaro
  .Build;
```

**Cosa fare:** in produzione usare `https`. `WithAllowInsecureHTTP` va usato solo nei test, e mai rilasciato.

### 2.2 I redirect HTTP non vengono seguiti

I client della libreria non seguono più le risposte 3xx. Nella 2.x un 307 mandava il form, con il client secret, a qualunque `Location` indicata. Ora un 3xx è un errore che riporta il `Location`.

**Cosa fare:** far puntare `BaseURL` all'indirizzo finale di Keycloak. Se un proxy fa redirect (per esempio da `http` a `https`, o un percorso senza la `/` finale), correggere l'URL o il proxy.

### 2.3 Viene controllato l'`iss` della risposta di autorizzazione (RFC 9207)

Quando il documento di discovery annuncia `authorization_response_iss_parameter_supported`, come fa Keycloak 26, la callback deve portare un `iss` uguale all'issuer del client. Con il server di callback locale e con l'app redirect la libreria lo controlla da sola: un `iss` sbagliato o assente fa fallire il login con `EIAM4DCallbackHandlerException`.

Nel modo di callback esterno (applicazioni web) i parametri della callback li legge il vostro codice, che quindi deve passare anche `iss`.

Prima (2.1):

<!-- snippet ver=2.1 kind=decl ctx=client -->
```delphi
procedure HandleCallback(const ACode, AState: string);
begin
  LClient.CompleteAuthorizationFlow(ACode, AState);
end;
```

Dopo (3.0):

<!-- snippet ver=3.0 kind=decl ctx=client -->
```delphi
procedure HandleCallback(const ACode, AState, AIss: string);
begin
  // AIss: il parametro iss della query dell'URL di callback ('' se assente)
  LClient.CompleteAuthorizationFlow(ACode, AState, AIss);
end;
```

**Cosa fare:** inoltrare il parametro `iss` della query della callback. Se `AIss` è vuoto, il modo esterno non lo controlla e il login funziona senza la protezione RFC 9207.

Sempre nel modo esterno, il contesto del flusso viene preso prima dello scambio del code: dopo un `CompleteAuthorizationFlow` fallito non si può riprovare con lo stesso `state`. Bisogna iniziare un nuovo login.

### 2.4 L'id_token viene validato del tutto

Nella 2.x dell'id_token si controllava solo il `nonce`. La 3.0 lo valida come JWT allo scambio del code, a ogni refresh e in Client Credentials quando c'è un id_token:

- la firma, verificata con la JWKS del realm;
- `iss` uguale all'issuer, `aud` uguale al client ID, `azp` uguale al client ID se presente;
- `typ` uguale a `ID`;
- `exp` e `iat`, con 300 secondi di tolleranza sull'orologio.

Dopo un refresh, anche `sub`, `aud` e `nonce` devono essere uguali a quelli del login.

Gli errori sollevano `EIAM4DSecurityValidationException` (prima era `EIAM4DException`).

**Cosa fare:**

- il client deve raggiungere l'endpoint JWKS del realm: ora un login fa una GET in più, e se la JWKS non si scarica il login fallisce con `EIAM4DJWKSUnavailableException`;
- tenere sincronizzati gli orologi del client e di Keycloak: con uno scarto oltre i 5 minuti il login fallisce.

### 2.5 JWT: `alg` esatto, chiavi RSA da 2048 bit in su

- L'header `alg` viene confrontato in modo esatto (RFC 7515): `rs256` non vale più come RS256. I nomi passati a `SetAllowedAlgs` devono essere quelli registrati.
- Quando una JWK dichiara `alg`, deve essere uguale all'`alg` del token. Le chiavi con `use: enc` non si usano più per verificare le firme.
- Le chiavi RSA devono avere un modulo da 2048 a 16384 bit e un esponente valido. Una chiave più piccola fallisce con `EIAM4DJWTSignatureInvalidException`.
- I token con un header `crit`, con un base64url non canonico o con `exp`/`nbf`/`iat` non numerici vengono rifiutati.
- Un refresh della JWKS sostituisce tutto il set di chiavi dell'issuer: una chiave che Keycloak non pubblica più smette di validare al refresh successivo.
- L'`issuer` del documento di discovery deve essere quello richiesto: un frontend URL di Keycloak o un proxy che cambia l'issuer rompe la validazione.

Per ammettere chiavi da 1024 bit, solo con un identity provider legacy che non si può correggere:

<!-- snippet ver=3.0 kind=body ctx=jwt uses=IAMClient4D.Security.Crypto.Interfaces -->
```delphi
// Vale per tutto il processo: impostarlo all'avvio, prima di validare qualsiasi token
TIAM4DRSAPublicKey.MinModulusBits := TIAM4DRSAPublicKey.LOWEST_MIN_MODULUS_BITS; // 1024
```

**Cosa fare:** verificare che `SetAllowedAlgs` elenchi `RS256`, `PS256`, `ES256`... in maiuscolo. Le chiavi di Keycloak sono di default da 2048 bit o più.

### 2.6 TLS: i pin vengono applicati in modo strict

- Nella 2.x `svmStrict` non installava alcuna callback sul certificato, quindi le chiavi pubbliche con pin non venivano mai controllate. Nella 3.0 i pin si controllano dopo la validazione di sistema, anche quando si scarica la JWKS.
- Su Android, in `svmStrict`, ora vale il verdetto della piattaforma: una CA non fidata o un certificato scaduto vengono rifiutati.
- In `svmAllowSelfSigned`, un bug della 2.x rifiutava ogni certificato appena si impostava un pin. Ora i pin si confrontano senza distinzione di maiuscole, e il pinning funziona.

**Cosa fare:** se usate i pin, verificate che siano gli hash SHA-256 delle chiavi dei certificati attuali, e aggiungete l'hash della chiave successiva prima di ruotarla.

### 2.7 Altri controlli più severi

- `TIAM4DPlatformUtils.OpenURL` apre solo URL `http` e `https` e restituisce False per ogni altro schema (`mailto:`, protocolli personalizzati).
- `GetUserInfo` solleva `EIAM4DSecurityValidationException` quando il `sub` della risposta non è quello dell'id_token.
- Il server di callback locale risponde 400 a un header `Host` diverso da `localhost`, `127.0.0.1` o `[::1]`, a una callback con uno `state` sbagliato (il login resta in attesa) e a una seconda callback con lo stesso `state`.
- `state` e `nonce` vengono da un CSPRNG.

### 2.8 Login annullato: niente più `OnError`

`CancelAuthorizationFlow`, la distruzione del client durante un login e un nuovo login che sostituisce quello in attesa ora terminano la promise in attesa come **Cancelled**. `OnError` non viene chiamato; `OnFinally` sì.

Prima (2.1), un login annullato arrivava a `OnError`:

<!-- snippet ver=2.1 kind=body ctx=client,ui -->
```delphi
LClient.StartAuthorizationFlowAsync
  .OnSuccess(
    procedure(const AAccessToken: string)
    begin
      ShowMessage('Logged in');
    end)
  .OnError(
    procedure(const AException: Exception)
    begin
      ShowMessage('Login failed or cancelled: ' + AException.Message);
    end)
  .Run;
```

Dopo (3.0), la fine del flusso si gestisce in `OnFinally`:

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
LClient.StartAuthorizationFlowAsync
  .OnSuccess(
    procedure(const AAccessToken: string)
    begin
      ShowMessage('Logged in');
    end)
  .OnError(
    procedure(const AException: Exception)
    begin
      // Non viene chiamato quando il login è annullato
      ShowMessage('Login failed: ' + AException.Message);
    end)
  .OnFinally(
    procedure
    begin
      // Successo, errore o annullamento: qui si ripristina la UI
    end)
  .Run;
```

È cambiato anche il caso opposto: una risposta d'errore OAuth2 con lo `state` del flusso (`error=access_denied`, `login_required`) ora termina il login con `EIAM4DOAuth2CallbackException`, il cui `Context` contiene `error` ed `error_description`. Nella 2.x la promise non terminava mai.

---

## 3. Interfacce

### 3.1 Nuovi metodi: solo per chi implementa

Se chiamate queste interfacce, il codice compila senza modifiche: i metodi esistenti hanno solo parametri opzionali in coda o nuovi overload. Se invece le **implementate** (test double, decorator), dovete aggiungere i nuovi metodi:

| Interfaccia | Membri nuovi o cambiati |
|---|---|
| `IIAM4DClient` | `AuthenticatePassword(Async)`, `CompleteAuthorizationFlow(Async)` con `AIss`, overload di `GenerateAuthURL` e `StartAuthorizationFlowAsync`, `InitializeAuthorizationFlow(AOptions)`, `GenerateLogoutURL`, `RevokeTokens(Async)`, `InvalidateAccessToken`, `GetIDTokenClaims`, `GetGrantedScopes`, `HasGrantedScope`, `GetKeycloakActionStatus`, `GetRedirectURI`, `CancelAuthorizationFlow` |
| `IIAM4DClientConfigBuilder` | `ForPassword`, `ForAuthorizationCode` con `AClientSecret`, `WithAllowInsecureHTTP`, `WithAppRedirect`, `WithAppActivation`, `WithCallbackPort`, `WithLoopbackRedirectHost`, `WithIdentityProvider`, `WithKeycloakAction`, `WithPrompt`, `WithMaxAge` |
| `IIAM4DUserManager` | `LinkFederatedIdentity`, `UnlinkFederatedIdentity` |
| `IIAM4DUserManagerAsync` | `LinkFederatedIdentityAsync`, `UnlinkFederatedIdentityAsync` |
| `IIAM4DSSLCertificateValidator` | `HasPinnedPublicKeys`; `ValidateCertificate` ha un parametro in più (3.3) |

I GUID di `IIAM4DUserManager` e `IIAM4DStorageCryptoProvider` sono cambiati. Conta solo se il vostro codice li scrive come stringhe.

`IIAM4DUserManager` non è pensata come punto di estensione. Per cambiarne il comportamento conviene incapsulare `TIAM4DKeycloakUserManager` invece di implementare l'interfaccia da zero.

### 3.2 Opzioni della richiesta di autorizzazione

Ora le opzioni del login si possono passare per singola richiesta con `TIAM4DAuthRequestOptions`. Le chiamate 2.x compilano ancora; il record serve per passare più di un hint.

Prima (2.1):

<!-- snippet ver=2.1 kind=body ctx=client -->
```delphi
LClient.StartAuthorizationFlowAsync.Run;
```

Dopo (3.0):

<!-- snippet ver=3.0 kind=body ctx=client -->
```delphi
LClient.StartAuthorizationFlowAsync(
  TIAM4DAuthRequestOptions.Create
    .WithLoginHint('john.doe@example.com')
    .WithIdpHint('google')
    .WithPrompt('login'))
  .Run;
```

### 3.3 Validatori di certificato personalizzati

`ValidateCertificate` riceve il verdetto della piattaforma, e l'interfaccia ha `HasPinnedPublicKeys`. Il valore `crrStrictModeBypass` di `TIAM4DCertificateRejectionReason` è diventato `crrSystemValidationFailed`.

Prima (2.1):

<!-- snippet ver=2.1 kind=decl ctx=security -->
```delphi
type
  TMyValidator = class(TInterfacedObject, IIAM4DSSLCertificateValidator)
  private
    FMode: TIAM4DSSLValidationMode;
  public
    procedure SetValidationMode(AMode: TIAM4DSSLValidationMode);
    function GetValidationMode: TIAM4DSSLValidationMode;
    procedure AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);
    procedure ClearPinnedPublicKeys;
    function ValidateCertificate(const Certificate: TCertificate): Boolean;
  end;

procedure TMyValidator.SetValidationMode(AMode: TIAM4DSSLValidationMode);
begin
  FMode := AMode;
end;

function TMyValidator.GetValidationMode: TIAM4DSSLValidationMode;
begin
  Result := FMode;
end;

procedure TMyValidator.AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);
begin
end;

procedure TMyValidator.ClearPinnedPublicKeys;
begin
end;

function TMyValidator.ValidateCertificate(const Certificate: TCertificate): Boolean;
begin
  Result := Certificate.Expiry > Now;
end;
```

Dopo (3.0):

<!-- snippet ver=3.0 kind=decl ctx=security -->
```delphi
type
  TMyValidator = class(TInterfacedObject, IIAM4DSSLCertificateValidator)
  private
    FMode: TIAM4DSSLValidationMode;
  public
    procedure SetValidationMode(AMode: TIAM4DSSLValidationMode);
    function GetValidationMode: TIAM4DSSLValidationMode;
    procedure AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);
    procedure ClearPinnedPublicKeys;
    function HasPinnedPublicKeys: Boolean;
    function ValidateCertificate(const Certificate: TCertificate; ASystemAccepted: Boolean): Boolean;
  end;

procedure TMyValidator.SetValidationMode(AMode: TIAM4DSSLValidationMode);
begin
  FMode := AMode;
end;

function TMyValidator.GetValidationMode: TIAM4DSSLValidationMode;
begin
  Result := FMode;
end;

procedure TMyValidator.AddPinnedPublicKeys(const APublicKeyHashes: TArray<string>);
begin
end;

procedure TMyValidator.ClearPinnedPublicKeys;
begin
end;

function TMyValidator.HasPinnedPublicKeys: Boolean;
begin
  Result := False;
end;

function TMyValidator.ValidateCertificate(const Certificate: TCertificate; ASystemAccepted: Boolean): Boolean;
begin
  // In svmStrict il verdetto della piattaforma va rispettato
  Result := ((FMode <> svmStrict) or ASystemAccepted) and (Certificate.Expiry > Now);
end;
```

### 3.4 `SetOnCodeReceived` dei callback handler

La callback riceve un terzo argomento, il `kc_action_status` della risposta (le application-initiated action di Keycloak). Il metodo è stato spostato in `TIAM4DRedirectCallbackHandlerBase`.

Prima (2.1):

<!-- snippet ver=2.1 kind=decl uses=IAMClient4D.Callback.Handler.Local -->
```delphi
procedure HookCallback(AHandler: TIAM4DLocalCallbackHandler);
begin
  AHandler.SetOnCodeReceived(
    procedure(ACode, AState: string)
    begin
      // scambio del code
    end);
end;
```

Dopo (3.0):

<!-- snippet ver=3.0 kind=decl uses=IAMClient4D.Callback.Handler.Local -->
```delphi
procedure HookCallback(AHandler: TIAM4DLocalCallbackHandler);
begin
  AHandler.SetOnCodeReceived(
    procedure(ACode, AState, AKeycloakActionStatus: string)
    begin
      // scambio del code; AKeycloakActionStatus è '' fuori dalle action di Keycloak
    end);
end;
```

---

## 4. Rimossi e deprecati

### 4.1 Rimossi

| Rimosso | Sostituto |
|---|---|
| Unit `IAMClient4D.Common.TokenValidator` (`TIAM4DTokenValidator`, `IAM4D_DEFAULT_TOKEN_EXPIRATION_BUFFER_SECONDS`) | `IIAM4DTokenStorage.IsAccessTokenValid` / `IsRefreshTokenValid`, oppure i campi di scadenza di `TIAM4DTokens` (UTC) |
| `IAM4D_OAUTH2_CALLBACK_PORT_MIN` / `IAM4D_OAUTH2_CALLBACK_PORT_MAX` | nessuno: non erano usate. `WithCallbackPort` imposta una porta fissa |
| `TValidatedTokenCacheEntry` | nessuno: tipo interno, pubblico per errore |
| `IEventWrapper` / `TEventWrapper` (Async.Core) | nessuno: spostati nella sezione implementation |
| `TAsyncOperationController<T>.SetResult` (protected) | `TrySetResult`, per le sottoclassi |
| `TIAM4DCertificateRejectionReason.crrStrictModeBypass` | `crrSystemValidationFailed` (stesso ordinale) |

Nella 2.x, per `TIAM4DTokenValidator`, una scadenza 0 voleva dire "non scade mai". Nella 3.0 i controlli dello storage trattano 0 come scaduto.

Prima (2.1):

<!-- snippet ver=2.1 kind=decl uses=IAMClient4D.Core,IAMClient4D.Common.TokenValidator -->
```delphi
function NeedsRefresh(const ATokens: TIAM4DTokens): Boolean;
begin
  Result := not TIAM4DTokenValidator.IsAccessTokenValid(ATokens, 30);
end;
```

Dopo (3.0):

<!-- snippet ver=3.0 kind=decl uses=IAMClient4D.Core,System.DateUtils -->
```delphi
function NeedsRefresh(const ATokens: TIAM4DTokens): Boolean;
begin
  // AccessTokenExpiry è UTC; 0 significa nessun token
  Result := (ATokens.AccessToken = '') or
    (ATokens.AccessTokenExpiry <= TDateTime.NowUTC + 30 / SecsPerDay);
end;
```

Di solito non serve né l'uno né l'altro: `GetAccessToken` rinnova il token quando sta per scadere (`WithTokenExpiryBuffer`).

### 4.2 Deprecati (warning W1000)

| Deprecato | Da usare al suo posto |
|---|---|
| `TIAM4DJWTMiddleware` | `IAM4DJWTBundle` (sezione 9.1). Il middleware non protegge le route Minimal API |
| `CONTEXT_KEY_STD_JSON`, `CONTEXT_KEY_KC_JSON` | `Context.JWT`, `Context.Keycloak`: le chiavi non vengono più popolate |
| `CACHE_KEY`, `KC_CACHE_KEY` | niente: non sono più usate |
| `EIAM4DAccessTokenExpiredException`, `EIAM4DInvalidAuthCodeException`, `EIAM4DPKCEValidationException`, `EIAM4DAuthorizationTimeoutException`, `EIAM4DEndpointsNotConfiguredException`, `EIAM4DUnknownRequiredActionException` | non vengono mai sollevate: togliere i rami `except` |

---

## 5. Errori ed eccezioni

### 5.1 Refresh: `EIAM4DRefreshTokenExpiredException`

Nella 2.x qualsiasi errore di refresh azzerava i token, e `invalid_grant` arrivava come una generica `EIAM4DException` ("Token endpoint failed: 400"). Nella 3.0:

- `invalid_grant` (sessione chiusa, refresh token scaduto o revocato) solleva `EIAM4DRefreshTokenExpiredException` e azzera i token;
- errori di rete, timeout e 5xx conservano i token: `IsAuthenticated` resta True e una chiamata successiva può rinnovarli.

Prima (2.1):

<!-- snippet ver=2.1 kind=body ctx=client,ui -->
```delphi
try
  LClient.GetAccessToken;
except
  on E: EIAM4DException do
    ShowMessage('Please log in again'); // qualsiasi errore chiudeva la sessione
end;
```

Dopo (3.0):

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
try
  LClient.GetAccessToken;
except
  on E: EIAM4DRefreshTokenExpiredException do
    ShowMessage('Please log in again'); // sessione chiusa, token azzerati
  on E: EIAM4DNetworkUnreachableException do
    ShowMessage('Identity provider unreachable, retry later'); // token conservati
end;
```

### 5.2 Gli errori di rete sono eccezioni della libreria

Le eccezioni RTL `ENetHTTPClientException` ed `ENetHTTPRequestException` non escono più dalla libreria. Diventano:

- `EIAM4DNetworkTimeoutException`, dove `ResponseTimeout` ora limita l'intera richiesta;
- `EIAM4DNetworkUnreachableException`;
- `EIAM4DSSLCertificateException`.

Gli helper con retry (`GetWithRetry`, `PostFormUrlEncodedWithRetry`) non ritentano più i timeout e gli errori di certificato. Dopo l'ultimo tentativo restituiscono la risposta 429/5xx invece di sollevare un'eccezione.

Prima (2.1):

<!-- snippet ver=2.1 kind=body ctx=client,ui -->
```delphi
try
  LClient.GetUserInfo;
except
  on E: ENetHTTPClientException do
    ShowMessage('Network error: ' + E.Message);
end;
```

Dopo (3.0):

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
try
  LClient.GetUserInfo;
except
  on E: EIAM4DNetworkTimeoutException do
    ShowMessage('Timeout: ' + E.Message);
  on E: EIAM4DNetworkUnreachableException do
    ShowMessage('Network error: ' + E.Message);
end;
```

### 5.3 Gerarchie cambiate

L'ordine dei rami `except` conta, perché alcune classi hanno un nuovo antenato:

| Classe | Antenato 2.x | Antenato 3.0 |
|---|---|---|
| `EIAM4DUserNotFoundException`, `EIAM4DRoleNotFoundException`, `EIAM4DGroupNotFoundException` | `EIAM4DException` | `EIAM4DHTTPNotFoundException` |
| `EIAM4DUserAlreadyExistsException` | `EIAM4DException` | `EIAM4DHTTPConflictException` |
| `EIAM4DInsufficientPermissionsException` | `EIAM4DException` | `EIAM4DHTTPClientErrorException` |
| `EIAM4DStorageCryptoException` | `Exception` | `EIAM4DException` |

Quindi un ramo `on E: EIAM4DHTTPClientErrorException` messo per primo intercetta anche "not found", "already exists" e 403. Un `on E: EIAM4DException` messo prima del ramo dello storage intercetta anche gli errori crittografici dello storage.

Altri cambi alle eccezioni:

- gli errori della callback OAuth2 sono `EIAM4DOAuth2CallbackException`, sorella di `EIAM4DCallbackHandlerException`;
- gli errori JWT sono sottoclassi tipizzate di `EIAM4DSecurityValidationException`: `EIAM4DJWTIssuerMismatchException`, `EIAM4DJWTSignatureInvalidException`, `EIAM4DJWKSKeyNotFoundException`, `EIAM4DJWKSUnavailableException`;
- le eccezioni che `WaitForResult` rilancia conservano `ErrorCode`, `Context` e `StatusCode`.

---

## 6. Admin API

### 6.1 Errori HTTP tipizzati, "not found" è 404

Nella 2.x ogni status HTTP diverso da 200/201/204 sollevava `EIAM4DInvalidConfigurationException`. Nella 3.0 ogni status ha la sua eccezione:

| Status | Eccezione |
|---|---|
| 403 | `EIAM4DInsufficientPermissionsException` |
| 404 | `EIAM4DHTTPNotFoundException`, o le sue sottoclassi `EIAM4DUserNotFoundException`, `EIAM4DRoleNotFoundException`, `EIAM4DGroupNotFoundException` |
| 409 | `EIAM4DHTTPConflictException`, oppure `EIAM4DUserAlreadyExistsException` da `CreateUser` |
| altri 4xx | `EIAM4DHTTPClientErrorException` |
| 5xx | `EIAM4DHTTPServerErrorException` |

Prima (2.1):

<!-- snippet ver=2.1 kind=body ctx=umgr,ui -->
```delphi
try
  LUserManager.GetUserByUsername('john.doe');
except
  on E: EIAM4DUserNotFoundException do
    ShowMessage('No such user');
  on E: EIAM4DInvalidConfigurationException do
    ShowMessage('Keycloak error: ' + E.Message); // 403, 409, 500...
end;
```

Dopo (3.0):

<!-- snippet ver=3.0 kind=body ctx=umgr,ui -->
```delphi
try
  LUserManager.GetUserByUsername('john.doe');
except
  on E: EIAM4DUserNotFoundException do
    ShowMessage('No such user');
  on E: EIAM4DInsufficientPermissionsException do
    ShowMessage('Missing realm-management roles');
  on E: EIAM4DHTTPServerErrorException do
    ShowMessage('Keycloak unavailable: ' + E.Message);
end;
```

I messaggi d'errore riportano al massimo 500 caratteri del corpo della risposta: il corpo intero è in `ResponseBody`. L'URL nel messaggio è senza query string.

### 6.2 `UpdateUser` sostituisce il profilo

Nella 2.x `Email`, `FirstName` e `LastName` vuoti non venivano inviati, quindi non si potevano cancellare, e neppure un `RequiredActions` vuoto veniva inviato. Nella 3.0 il record sostituisce il profilo: i campi vuoti azzerano i valori su Keycloak e `RequiredActions` viene sempre inviato. L'unica eccezione è uno `Username` vuoto, che non viene inviato.

Prima (2.1), un record parziale:

<!-- snippet ver=2.1 kind=body ctx=umgr -->
```delphi
var LUser: TIAM4DUser;
LUser.ID := '5f2c0a5e-0000-0000-0000-000000000000';
LUser.Email := 'john.doe@example.com';
LUser.Enabled := True;
LUserManager.UpdateUser(LUser); // nomi e required action restavano com'erano
```

Dopo (3.0), leggere, modificare, aggiornare:

<!-- snippet ver=3.0 kind=body ctx=umgr -->
```delphi
var LUser := LUserManager.GetUser('5f2c0a5e-0000-0000-0000-000000000000');
LUser.Email := 'john.doe@example.com';
LUserManager.UpdateUser(LUser); // viene inviato ogni campo di LUser
```

### 6.3 Altri cambi dell'Admin API

- **I nomi sono case-sensitive.** I nomi di ruoli, ruoli client e gruppi si confrontano in modo esatto, come fa Keycloak: `HasRole`, `HasClientRole`, `Assign*ByName`, la ricerca dei gruppi per percorso e `TIAM4DRoleLookupCache`. Gli ID restano case-insensitive. Un ruolo per nome si legge con `GET roles/{name}`.
- **`GetGroups` restituisce tutto l'albero, appiattito.** La 2.x restituiva solo il primo livello. Per tenere solo il primo livello, tenere i gruppi il cui `Path` contiene una sola `/`.
- **Validazione prima della richiesta:**
  - una paginazione con `FirstResult` < 0 o `MaxResults` < 1 solleva `EIAM4DInvalidConfigurationException`;
  - la `TemporaryPassword` di `CreateUser(s)` deve avere da 8 a 4096 caratteri, altrimenti `EIAM4DInvalidUserDataException`;
  - un segmento di percorso vuoto, oppure `.` o `..` (per esempio `UnlockUser('')`), solleva `EIAM4DInvalidConfigurationException`.
- **Email duplicate:** `GetUserByEmail` e `TryGetUserByEmail` sollevano `EIAM4DInvalidUserDataException` quando due utenti hanno la stessa email. La 2.x restituiva il primo. Nella 2.x questi due metodi e `IsUserLocked` non arrivavano proprio a Keycloak (una variabile locale nascondeva l'URL).
- **Ricerca per username:** si accetta qualsiasi nome non vuoto fino a 255 caratteri, `@` e `+` compresi. Anche `ValidateUsername` accetta `@` e `+`.
- **Altri metodi:**
  - `IsUserLocked` restituisce False solo per un 404 e solleva gli altri errori;
  - `RevokeUserSession(UserID, SessionID)` solleva `EIAM4DHTTPNotFoundException` quando la sessione non è di quell'utente;
  - `AssignClientRolesToUser` controlla ogni ruolo e invia una richiesta per client.
- **Redirect e codifica dei percorsi:** i redirect non vengono seguiti, quindi un 3xx solleva `EIAM4DInvalidConfigurationException`. I segmenti di percorso sono codificati con `%20`, mentre la 2.x usava `+` e un ruolo con uno spazio non si trovava.
- **Client HTTP:** ogni manager tiene un pool di al massimo 4 client HTTP.

---

## 7. Async.Core

### 7.1 `RunWithTimeout` termina con `EAsyncTimeoutException`

Nella 2.x un timeout terminava l'operazione come Cancelled (`EAsyncCancelException`). Nella 3.0 la termina come Faulted con `EAsyncTimeoutException`, e il task riceve una richiesta di annullamento.

Prima (2.1):

<!-- snippet ver=2.1 kind=body ctx=async,ui -->
```delphi
try
  TAsyncCore.RunWithTimeout<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := 'done';
    end, 5000).WaitForResult;
except
  on E: EAsyncCancelException do
    ShowMessage('Timed out or cancelled');
end;
```

Dopo (3.0):

<!-- snippet ver=3.0 kind=body ctx=async,ui -->
```delphi
try
  TAsyncCore.RunWithTimeout<string>(
    function(const AOperation: IAsyncOperation): string
    begin
      Result := 'done';
    end, 5000).WaitForResult;
except
  on E: EAsyncTimeoutException do
    ShowMessage('Timed out');
  on E: EAsyncCancelException do
    ShowMessage('Cancelled');
end;
```

### 7.2 `dmQueue` accoda sempre

`dmQueue` ora usa `TThread.ForceQueue`: chiamata dal main thread, la callback gira al giro successivo del message loop, non dentro la chiamata. `TAsyncTaskCompletionSource` usa `dmQueue` di default.

**Cosa fare:** in un'applicazione console o in un servizio senza message loop, chiamare `CheckSynchronize`, oppure usare il nuovo modo `dmInline`, che esegue le callback sul thread che completa l'operazione:

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
LClient.GetUserInfoAsync
  .DispatchMode(TAsyncCallbackDispatchMode.dmInline) // non serve il main thread
  .OnSuccess(
    procedure(const AUserInfo: TIAM4DUserInfo)
    begin
      ShowMessage(AUserInfo.PreferredUsername);
    end)
  .Run;
```

### 7.3 Altri cambi di Async.Core

- **Eccezioni nelle callback:** un'eccezione sollevata dentro `OnSuccess`, `OnFinally` o `OnCancelled` non cambia più lo stato dell'operazione. Nella 2.x un'eccezione in `OnSuccess` trasformava Completed in Faulted ed eseguiva `OnError`. Ora va a `TAsyncCore.OnUnhandledError` se è assegnato, altrimenti ad `ApplicationHandleException` sul main thread; senza nessuno dei due viene scartata.
- **L'eccezione passata a `OnError`** è l'oggetto originale, con tutti i suoi campi. Non va liberata né conservata.
- **I combinatori** (`ContinueWith`, `WhenAll`, `WhenAny`, `RunWithTimeout`) non hanno più bisogno del main thread. `Cancel` sul loro risultato lo termina subito.
- **`Delay` e `RunWithRetry`** aspettano su un timer condiviso, non su un thread del pool bloccato, quindi un `Cancel` durante l'attesa li termina subito.
- **Argomenti di `RunWithRetry`:** con `AMaxRetries` < 0 la chiamata solleva `EArgumentOutOfRangeException`. Il nuovo parametro facoltativo `AShouldRetry` filtra gli errori da ritentare.
- **`OnCancelled`** accetta più di un gestore.

---

## 8. Dati: date, scope, logout

### 8.1 DMVC: date in ISO 8601 UTC

`LoggedUser.CustomData['exp']`, `['iat']` e `['auth_time']` venivano scritti con `DateTimeToStr`, nelle impostazioni locali del server. Ora sono in ISO 8601 UTC. Anche `LoggedSince` è UTC.

Prima (2.1):

<!-- snippet ver=2.1 kind=body ctx=dmvc_ctx -->
```delphi
var LExpiry := StrToDateTime(Context.LoggedUser.CustomData['exp']); // impostazioni locali del server
```

Dopo (3.0):

<!-- snippet ver=3.0 kind=body ctx=dmvc_ctx uses=System.DateUtils -->
```delphi
var LExpiry := ISO8601ToDate(Context.LoggedUser.CustomData['exp'], True); // UTC
```

Tutti gli orologi della libreria usano `TDateTime.NowUTC`. Il calcolo della 2.x sbagliava di un'ora durante l'ora ripetuta alla fine dell'ora legale.

### 8.2 Scope concessi

Lo scope della risposta del token viene conservato: `TIAM4DTokens.Scope`, `GetGrantedScopes`, `HasGrantedScope`. Il JSON del serializer dei token ha un campo `scope`. Un JSON 2.x si carica ancora, con `Scope` vuoto.

<!-- snippet ver=3.0 kind=body ctx=client,ui -->
```delphi
if not LClient.HasGrantedScope('offline_access') then
  ShowMessage('Keycloak did not grant offline_access');
```

### 8.3 Logout con una POST back-channel

- **La richiesta:** con un refresh token, `Logout` manda una POST all'`end_session_endpoint` con `client_id`, il secret e `refresh_token`. La 2.x mandava una GET lato server con `id_token_hint`, e solo in Authorization Code. Un 200 o un 204 vuol dire sessione chiusa, `invalid_grant` vuol dire che era già chiusa. La GET con `id_token_hint` si usa solo quando non c'è un refresh token.
- **Token e scope:** `Logout` azzera sempre i token, anche quando la richiesta fallisce, e solleva comunque l'errore. Nella 2.x venivano svuotati anche gli scope configurati, quindi il login successivo chiedeva solo `openid`. Ora vengono ripristinati.
- **Logout nel browser:** `GenerateLogoutURL` è pubblica, quindi si può chiudere la sessione SSO anche nel browser.

### 8.4 Cache della discovery

Il documento di discovery resta in cache per processo per un'ora, per URL del realm e modo SSL. Una modifica lato server si vede dopo un'ora, oppure dopo `TIAM4DDiscoveryCache.Clear`.

---

## 9. DMVCFramework

### 9.1 Dal middleware al filter bundle

`TIAM4DJWTMiddleware` funziona ancora, ma è deprecato. Il filter bundle protegge anche le route Minimal API.

Prima (2.1):

<!-- snippet ver=2.1 kind=body ctx=dmvc_engine -->
```delphi
FEngine.AddMiddleware(TIAM4DJWTMiddleware.Create(
  'https://keycloak.example.com/realms/demo', // Issuer
  'demo_api'));                               // Audience
```

Dopo (3.0):

<!-- snippet ver=3.0 kind=body ctx=dmvc_engine -->
```delphi
// Prima dei controller e prima del filtro Swagger
FEngine.Use(IAM4DJWTBundle(
  'https://keycloak.example.com/realms/demo', // Issuer
  'demo_api'));                               // Audience
```

### 9.2 Errori di configurazione all'avvio

- Un `Issuer` o un `TokenHeaderName` vuoti sollevano `EIAM4DInvalidConfigurationException` quando si crea l'authenticator.
- Lo stesso vale per un'`Audience` vuota con `AudienceValidationEnabled` attivo. Nella 2.x il server partiva e rispondeva 401 a ogni token.
- Un `TIAM4DJWTMiddlewareConfig` compilato campo per campo, senza `Create`, ora riceve i default di `Create` grazie all'`Initialize` del managed record. Nella 2.x i campi valevano zero: controllo dell'audience spento, skew 0, header vuoto.
- I timeout HTTP di default sono 10000 ms per la connessione e 15000 ms per la ricezione (2.x: 30000/60000).
- `JWKS_URL`, `RolesClaimName` e `SubjectClaimName` ora vengono usati. La 2.x li ignorava.

### 9.3 Richieste che non passano più

- **Le richieste OPTIONS** vengono autenticate come gli altri verbi. Il preflight CORS va gestito prima del filtro di IAMClient4D.
- **Percorsi Swagger:** le GET il cui percorso contiene `swagger`, `openapi` o `api-docs` e termina con `.json` non sono più esenti. Un controller che serve il proprio documento va marcato con `[IAM4DPublic]`.
- **Token non validi con `AllowAnonymous`:** ora un token non valido riceve un 401 `invalid_token`. Passa come anonima solo una richiesta senza token.
- **ID token:** il `typ` del payload deve essere `Bearer` (`ExpectedTokenType`). Un id_token di Keycloak con la `aud` giusta prima passava. Un token senza `typ` passa ancora.

### 9.4 Ruoli, scope e claim

- **Ruoli client:** `LoggedUser.Roles` contiene solo i ruoli client di `Audience` ed `ExpectedAzp`. La 2.x aggiungeva quelli di tutti i client in `resource_access`.
- **Confronti case-sensitive:** la deduplicazione dei ruoli, `HasRole`, `HasScope`, `HasGroup` e `amr` dei DTO ora sono case-sensitive.
- **`RequireAnyRole` / `RequireAllRoles`** controllano `LoggedUser.Roles`. La 2.x leggeva il claim `roles`, che Keycloak non emette, quindi queste chiamate rispondevano sempre 403.
- **`GetCustomClaim`** legge una chiave di primo livello: `'address.country'` è il nome di un claim, non un percorso. Il valore annidato va letto da `Context.JWT`.
- **Le risposte 403** dicono solo "Insufficient permissions" e mandano un `WWW-Authenticate` con `insufficient_scope`. I ruoli richiesti finiscono nel log (`LogW`).
- **Un identity provider irraggiungibile** dà 503 `temporarily_unavailable` con `Retry-After`. La 2.x rispondeva 401.
- **Il messaggio del 401** per un token inviato e rifiutato è "Invalid or expired JWT token".

Prima (2.1), un claim annidato letto come percorso:

<!-- snippet ver=2.1 kind=body ctx=dmvc_ctx -->
```delphi
var LCountry := Context.GetCustomClaim('address.country', '');
```

Dopo (3.0):

<!-- snippet ver=3.0 kind=body ctx=dmvc_ctx -->
```delphi
// 'address' è il nome del claim; il valore annidato si legge dall'oggetto JSON
var LCountry := '';
var LAddress := Context.GetCustomClaim('address', '');
if LAddress <> '' then
begin
  var LJSON := TJSONObject.ParseJSONValue(LAddress);
  try
    if LJSON is TJSONObject then
      LCountry := TJSONObject(LJSON).GetValue<string>('country', '');
  finally
    LJSON.Free;
  end;
end;
```

### 9.5 Token `at+jwt`

Il `typ` dell'header degli access token può essere `JWT` o `at+jwt` (RFC 9068, opzione del client Keycloak "Use 'at+jwt' as access token header type"). Per accettare solo `JWT`, come la 2.x:

<!-- snippet ver=3.0 kind=body ctx=dmvc_engine -->
```delphi
var LConfig := TIAM4DJWTMiddlewareConfig.Create(
  'https://keycloak.example.com/realms/demo', 'demo_api', '');
LConfig.AllowedHeaderTypes := ['JWT']; // comportamento della 2.x
FEngine.Use(IAM4DJWTBundle(LConfig));
```

### 9.6 Chiavi del contesto

`CONTEXT_KEY_STD_JSON` e `CONTEXT_KEY_KC_JSON` non vengono più popolate: usare `Context.JWT` e `Context.Keycloak`. `JWT_Auth_Status` ora è sempre impostato. Oltre ad `authenticated` e `not_authenticated`, può valere `invalid_token` o `unavailable`.

---

## 10. Cosa si guadagna

- **Sicurezza più severa:** validazione completa dell'id_token, `iss` RFC 9207, ES256/384/512 con TMS e TaurusTLS, pin applicati davvero, niente HTTP in chiaro, niente redirect, e una rotazione della JWKS più sicura.
- **Nuove opzioni di login:** il provider TaurusTLS/OpenSSL; Android, iOS e macOS con l'app redirect e `ASWebAuthenticationSession`; il redirect sul loopback `127.0.0.1` (RFC 8252); le opzioni per richiesta, le application-initiated action di Keycloak, e revoca dei token e URL di logout.
- **Admin API:** identity provider (Entra ID, Google, Facebook, SPID, CIE), identità federate, errori tipizzati e un pool di client HTTP.
- **DMVCFramework 3.5:** filter bundle, Minimal API, OpenAPI 3, trasformazione dei claim, e 503 quando l'identity provider non risponde.
- **Async.Core:** funziona senza main thread, ha `dmInline`, non blocca mai un thread del pool nelle attese, e conserva le eccezioni intatte.

I dettagli sono nel [README](../../README.md).

---

## 11. Checklist

1. DMVCFramework 3.5.0-silicon-rc10 o successiva; Delphi 12 o successiva; Keycloak 25 o successiva (dalla 26.8.2, aggiungere `kc-admin-api` al client dell'Admin API).
2. Ogni URL è `https` e definitivo (nessun redirect), con l'issuer uguale all'`issuer` della discovery; `WithAllowInsecureHTTP` solo nei test.
3. Orologi del client e di Keycloak sincronizzati (id_token controllato con 5 minuti di tolleranza); endpoint JWKS raggiungibile dal client.
4. Modo di callback esterno: passare `iss` a `CompleteAuthorizationFlow`.
5. Annullamento del login gestito in `OnFinally`, non in `OnError`.
6. Blocchi `except`: `EIAM4DRefreshTokenExpiredException`, `EIAM4DNetwork*`, eccezioni tipizzate dell'Admin API, nuovi antenati.
7. `UpdateUser` con un record completo (leggere, modificare, aggiornare); nomi di ruoli e gruppi con le maiuscole esatte; `GetGroups` restituisce tutto l'albero.
8. `TIAM4DTokenValidator` sostituito; eccezioni e chiavi di contesto deprecate tolte.
9. Async.Core: `EAsyncTimeoutException` gestita; `dmInline` o `CheckSynchronize` senza message loop.
10. DMVC: `IAM4DJWTBundle` con un'`Audience`; preflight CORS prima del filtro; `[IAM4DPublic]` sui documenti pubblici; date di `CustomData` lette come ISO 8601 UTC.
