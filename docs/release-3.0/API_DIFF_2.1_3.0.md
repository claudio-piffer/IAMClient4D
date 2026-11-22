# Inventario API 2.1 → 3.0

Confronto ricavato dal codice, non dal CHANGELOG né dal README.

- **2.1:** `d:\D13\IAMClient4D\src`, clone del repo pubblico a `a7d84fb` (tag `v2.1.0` = `515b7f9`; il suo `src` coincide con `210f97c` del repo di sviluppo).
- **3.0:** `src` del repo di sviluppo a `834ca7a`, escluso `src/Lib`.
- I numeri di riga citati (`Unit.pas:123`) si riferiscono a `834ca7a` e cambieranno con le fasi successive. Per brevità si omette il prefisso `IAMClient4D.` dei nomi delle unit.

## Metodo

1. **Interfacce.** `tools/pasiface.py` toglie i commenti, estrae la sezione `interface` di ogni unit e ne fa l'analisi sintattica: tipi, membri pubblici, published e protected, costanti, variabili e routine. `tools/mdtables.py` confronta le due versioni e produce le tabelle della sezione 5, con una prima classificazione. Questa è stata poi controllata a mano: tipi spostati con alias, metodi passati nella classe base, overload aggiunti.
2. **Comportamenti.** Le implementazioni delle due versioni sono state lette unit per unit (client, sicurezza e storage, Admin API e Async.Core, DMVC). Ogni voce delle sezioni 3 e 4 riporta il riferimento nel codice 3.0. Le voci più delicate sono state ricontrollate sul codice 2.1.
3. **Sample 2.1.** I tre sample della 2.1 sono stati compilati contro il `src` 3.0 (`tools/build_samples_21.bat`): sezione 6.
4. **Riscontro incrociato** con `CHANGELOG.md` `[Unreleased]` e con la memoria `release-3-0-pending`: sezione 7.

Rigenerare le tabelle:

```
python docs/release-3.0/tools/pasiface.py <2.1>/src src parsed.json
python docs/release-3.0/tools/mdtables.py parsed.json tables.md
python docs/release-3.0/tools/diffiface.py parsed.json raw.tsv   (diff grezzo, una riga per differenza)
```

## Legenda della colonna Tipo

| Tipo | Significato |
|---|---|
| **breaking** | Il codice 2.1 non compila più, oppure compila ma fa altro e va cambiato. |
| **breaking (impl.)** | Rompe solo chi implementa l'interfaccia o deriva dalla classe; chi la usa compila. |
| **comportamento** | Compila uguale, ma il risultato a runtime cambia (eccezioni, default, richieste HTTP, controlli). |
| **sicurezza** | Cambio di comportamento dovuto a un controllo di sicurezza più severo. |
| **fix** | Correzione di un difetto della 2.1 che cambia un risultato. |
| **nuovo** | Aggiunta che non tocca il codice esistente. |
| **deprecato** | Esiste ancora, ma il compilatore emette W1000. |
| **compatibile** | Il cambio di firma o di posizione non richiede modifiche (alias, parametri opzionali in coda, metodo spostato nella classe base). |

---

## 1. Sintesi

Numeri del diff d'interfaccia, dalla sezione 5: 50 unit nella 2.1 e 68 nella 3.0. Ci sono 19 unit nuove e una rimossa (`Common.TokenValidator`). Le righe si dividono così: 11 breaking, 33 breaking (impl.), 7 di comportamento (gerarchie delle eccezioni), 4 deprecate, 38 compatibili e 331 nuove. A queste si aggiungono i comportamenti cambiati delle sezioni 3 e 4.

### Cosa rompe la compilazione

- Unit `Common.TokenValidator` rimossa (`TIAM4DTokenValidator`, `IAM4D_DEFAULT_TOKEN_EXPIRATION_BUFFER_SECONDS`).
- `IAM4D_OAUTH2_CALLBACK_PORT_MIN` / `MAX` rimosse.
- `TValidatedTokenCacheEntry` rimosso: era interno, pubblico per errore.
- `IEventWrapper` / `TEventWrapper` spostati nella sezione `implementation` di `Async.Core`.
- `TAsyncOperationController<T>.SetResult` (protected) sostituito da `TrySetResult`: tocca solo le sottoclassi.
- `IIAM4DSSLCertificateValidator.ValidateCertificate(Certificate, ASystemAccepted)` ha un parametro in più, e c'è il nuovo `HasPinnedPublicKeys`. Il valore `crrStrictModeBypass` diventa `crrSystemValidationFailed`.
- `TIAM4DLocalCallbackHandler.SetOnCodeReceived` riceve `TProc<string, string, string>` (code, state, `kc_action_status`).
- Il middleware DMVC richiede DMVCFramework 3.5.0-silicon-rc10 o successiva (`TMVCUser`): la 2.1 non compila sulla 3.5, la 3.0 non compila sulle DMVC precedenti.
- `IAMClient4D.Config.inc`: `{$MESSAGE FATAL}` sotto Delphi 12 e con `IAM4D_TMS` insieme a `IAM4D_TAURUSTLS`.

### Cosa rompe chi implementa le interfacce

Ci sono metodi nuovi o firme cambiate in `IIAM4DClient` (16 voci), `IIAM4DClientConfigBuilder` (11), `IIAM4DUserManager` e `IIAM4DUserManagerAsync` (2 + 2), oltre a `IIAM4DSSLCertificateValidator`. Cambiano i GUID di `IIAM4DUserManager` e `IIAM4DStorageCryptoProvider`, che contano solo per chi scrive il GUID come stringa. Per chi chiama, i metodi esistenti hanno solo parametri opzionali in coda o overload nuovi, e le chiamate compilano.

### Cosa compila uguale ma cambia a runtime (il grosso della migrazione)

1. **Sicurezza del client:**
   - `http://` verso host diversi dal loopback rifiutato;
   - redirect non seguiti;
   - `iss` (RFC 9207) obbligatorio quando Keycloak lo annuncia;
   - id_token validato del tutto (firma, `iss`, `aud`, `exp`, `typ`), non solo il nonce;
   - endpoint `http` di un realm `https` rifiutati;
   - `OpenURL` solo per http(s).
2. **JWT:**
   - `alg` confrontato in modo esatto;
   - RSA sotto 2048 bit rifiutate;
   - `alg` della JWK vincolante e chiavi `enc` escluse;
   - `crit` rifiutato, base64url canonico, claim temporali solo numerici;
   - issuer della discovery verificato;
   - rotazione della JWKS: una chiave non più pubblicata smette di validare.
3. **Errori:**
   - Admin API con eccezioni HTTP tipizzate (non più `EIAM4DInvalidConfigurationException`);
   - "not found" come 404;
   - errori di rete come eccezioni della libreria (non più `ENetHTTP*`);
   - `EIAM4DRefreshTokenExpiredException` su `invalid_grant`, mentre gli altri errori di refresh conservano i token;
   - eccezioni copiate da Async.Core con tutti i campi.
4. **Admin API:**
   - `UpdateUser` sostituisce il profilo (i campi vuoti si azzerano);
   - nomi di ruoli e gruppi case-sensitive;
   - `GetGroups` restituisce tutto l'albero;
   - email duplicate, paginazione e password temporanea validate;
   - `RevokeUserSession` controlla l'utente.
5. **Async.Core:**
   - `RunWithTimeout` termina in `EAsyncTimeoutException`;
   - `dmQueue` sempre accodato (`ForceQueue`);
   - un'eccezione in una callback non cambia lo stato;
   - Cancel immediato sui combinatori;
   - nessun thread del pool bloccato da `Delay` e dai retry.
6. **Flusso di login:**
   - annullamento come Cancelled (niente più `OnError`);
   - `error=access_denied` termina il login;
   - le callback con uno state diverso vengono ignorate;
   - `Logout` con POST back-channel che azzera sempre i token;
   - discovery in cache per un'ora.
7. **DMVC:**
   - `Audience`, `Issuer` e `TokenHeaderName` vuoti sono errori di configurazione;
   - bypass di OPTIONS e dei percorsi Swagger chiuso;
   - `AllowAnonymous` non accetta più token non validi;
   - ruoli client solo di `Audience`/`ExpectedAzp`;
   - ruoli, scope e gruppi case-sensitive;
   - `typ` del payload uguale a `Bearer`;
   - `at+jwt` accettato;
   - 503 con IdP non raggiungibile;
   - date di `LoggedUser.CustomData` in ISO 8601 UTC;
   - `CONTEXT_KEY_*_JSON` non più popolate.

---

## 2. Requisiti e build

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| Delphi | README: "Tested with 12.3 or later"; nessun controllo | `{$MESSAGE FATAL}` sotto `CompilerVersion` 36 (Delphi 12) | breaking (build) | `Config.inc:56-58`. **Provato solo con Delphi 13** (Studio 37.0, l'unico installato): il requisito "Delphi 12" del CHANGELOG non è verificato. Il piano dice "RAD Studio 13". Decidere alla fase 1. |
| DMVCFramework | README: "3.4+"; usa `TUser` | 3.5.0-silicon-rc10 o successiva: `TMVCUser`, filtri (`IMVCFilterBundle`, `TMVCEndpointFilter`) | breaking | `DMVC.Authenticator.pas:572`, `DMVC.Filters.pas:28-30` |
| Keycloak | README: 22+ (provato fino alla 24) | provato con 25.0, 26.7 e 26.8; Admin API di 26.8.2+ con lo scope `kc-admin-api` | comportamento | `hideOnLogin` rimandato senza il campo a Keycloak < 26 |
| Crypto provider | LockBox3 o TMS (TMS non compilava, sezione 4.5) | in più TaurusTLS/OpenSSL 3.x-4.x (`IAM4D_TAURUSTLS`), che esclude TMS | nuovo | `Config.inc:28-62` |
| Piattaforme | Win32/Win64; Linux64 non compilava (`system()`), iOS/macOS non compilavano | Win32, Win64, Linux64, Android, Android64, iOSDevice64, iOSSimARM64, OSXARM64 (compilazione) | fix | `Common.PlatformUtils.pas:315`, `Common.CryptoUtils.pas:63-112` |
| Pinning su Linux | accettato senza effetto | `ENotSupportedException` da `AddPinnedPublicKeys` e da `Build` con `WithPinnedPublicKeys` | breaking (Linux) | `Common.Security.pas:270-275` |

---

## 3. Comportamenti cambiati: client OAuth2/OIDC

### 3.1 Configurazione, discovery e HTTP

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `BaseURL`, URL di callback esterna | qualsiasi `http://` | `http://` verso host diversi da `localhost`, `127.0.0.0/8` e `::1` → `EIAM4DInvalidConfigurationException` | breaking/sicurezza | `Keycloak.pas:722-732`; eccezione per i test: `WithAllowInsecureHTTP` |
| Endpoint della discovery | usati come arrivano | in un realm `https`, un endpoint `http` (authorization, token, userinfo, end_session, revocation, jwks) → `EIAM4DInvalidConfigurationException` | breaking/sicurezza | `Keycloak.pas:1274-1282` |
| Discovery | scaricata a ogni `ConfigureAsync` | in cache per processo, 3600 s, per URL del realm e modo SSL (solo i successi; i client con pin non la usano) | comportamento | `Discovery.Cache.pas:73,105`. Una modifica lato server si vede dopo un'ora o dopo `TIAM4DDiscoveryCache.Clear` |
| Redirect HTTP | `HandleRedirects` = True (default RTL): un 307 rimandava form e secret al `Location` | `HandleRedirects` = False su tutti i client della libreria; un 3xx è un errore che nomina il `Location` | breaking/sicurezza | `Core.pas:1802`, `Keycloak.pas:1195-1215`. Si rompe un Keycloak dietro un proxy che redirige |
| Timeout | timeout di WinHTTP per singola operazione (una risposta lenta a gocce non scadeva mai); `SendTimeout` 60 s | `ResponseTimeout` limita l'intera richiesta (timer su Windows, libcurl su Linux); `SendTimeout` = `ResponseTimeout` | comportamento | `Core.pas:1798,1898-1965` |
| Errori di rete | `ENetHTTPClientException` / `ENetHTTPRequestException` dell'RTL | `EIAM4DNetworkTimeoutException`, `EIAM4DSSLCertificateException`, `EIAM4DNetworkUnreachableException` | breaking | `Core.pas:1898-1965`. Chi intercettava le eccezioni `ENetHTTP*` deve cambiare il blocco `except` |
| `GetWithRetry` / `PostFormUrlEncodedWithRetry` | 429/5xx all'ultimo tentativo → `ENetHTTPClientException('HTTP n')`; timeout ritentati | ultimo tentativo: risposta restituita al chiamante; timeout e errori di certificato non ritentati; errori di connessione ritentati, poi `EIAM4DNetworkUnreachableException` | breaking | `Core.pas:2015-2045,2068-2104` |
| Concorrenza HTTP del client | un `THTTPClient`, richieste serializzate da un lock | pool di `THTTPClient` (4 inattivi): le richieste di un client vanno in parallelo | comportamento | `Keycloak.pas:815-877` |
| Nuova `Configure` o pin cambiati | restava il `THTTPClient` della prima richiesta, con i vecchi timeout e la vecchia callback del certificato | pool scartato a ogni `Configure`, `AddPinnedPublicKeys`, `ClearPinnedPublicKeys` | fix | `Keycloak.pas:739,2510-2530` |
| Form (token, logout, revoca) | `TStringStream` | stesso formato in rete; parametri, corpo codificato e buffer azzerati dopo l'invio (`SecureZeroStrings`) | comportamento | `Keycloak.pas:1170-1193` |
| Messaggi d'errore del token endpoint | corpo della risposta intero | corpo tagliato a 512 caratteri | comportamento | `Keycloak.pas:1195-1215` |
| `Build` / `BuildAsync` del builder | `ConfigureAsync` + `WaitForCompletion(30000)`: dopo 30 s `EAsyncTimeoutException` con il task ancora in corso; errore ricopiato con classe e messaggio soltanto | `Configure` sul thread chiamante, senza limite fisso (valgono i timeout); l'eccezione originale arriva intatta | comportamento | `Config.Builder.pas:824-831` |
| Builder Client Credentials: `WithScopes`, `WithTimeouts`, `WithStrictSSL`, `WithAllowSelfSignedSSL` | riportavano `TokenExpiryBufferSeconds` a 120 | il valore viene conservato | fix | `Config.Builder.pas:426-485` |
| Builder: un secondo `For*` | ereditava ACR values e IdP della configurazione precedente; `ForClientCredentials` teneva `cbmExternal` | li azzera; `ForPassword`/`ForClientCredentials` tornano a `cbmLocalServer` | fix | `Config.Builder.pas:376-409` |

### 3.2 TLS e pinning

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| Pin in `svmStrict` | nessuna callback: i pin non venivano mai controllati | callback installata quando ci sono pin; pin controllati dopo la validazione di sistema, anche sul download della JWKS | sicurezza/breaking | `Core.pas:1736-1743,1785-1788` |
| Pin in `svmAllowSelfSigned` | hash maiuscolo confrontato con pin salvati in minuscolo: con un pin qualsiasi, ogni certificato veniva rifiutato | confronto senza distinzione di maiuscole; certificato senza chiave pubblica riportata → `crrPublicKeyPinningFailed` | fix | `Common.Security.pas:385-404` |
| Android, `svmStrict` | senza callback l'RTL Android accetta CA non fidate e certificati scaduti | `KeepPlatformVerdict`: il rifiuto della piattaforma vale | sicurezza | `Core.pas:1767-1772`; anche per la JWKS |
| Validatore condiviso della factory | ogni `CreateHTTPClient` ne cambiava il modo (gara tra client strict e self-signed) | fisso su `svmAllowSelfSigned`, usato solo da quei client | fix | `Core.pas:1753` |
| `ValidateCertificate` | un argomento; in `svmStrict` restituiva sempre False | riceve il verdetto della piattaforma: `svmStrict` lo richiede, `svmAllowSelfSigned` lo ignora | breaking (impl.) | `Common.Security.pas:341,377-382` |
| Android: errore di rete su https | connessione rifiutata o host sconosciuto → `EIAM4DSSLCertificateException` | errore di certificato solo se la piattaforma registra un errore TLS | fix | CHANGELOG, `Core.pas` (`SecureFailureReasons`) |

### 3.3 Login (Authorization Code)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| id_token allo scambio del code | solo il nonce, decodificando il payload; nessun controllo di firma, `iss`, `aud`, `exp` | validazione JWT completa tramite JWKS: firma, `iss` = issuer della discovery, `aud` = ClientID, `azp` = ClientID se c'è, `typ` = `ID`, `exp`/`iat` con 300 s di tolleranza, poi nonce | sicurezza/breaking | `Keycloak.pas:770-808,2361-2400,2450-2472`; verificato sul 2.1 (`Keycloak.pas:1131-1158`). Novità: una GET alla JWKS al login; un orologio sfasato di oltre 5 minuti o una JWKS irraggiungibile (`EIAM4DJWKSUnavailableException`) fanno fallire il login |
| Errori di nonce/id_token | `EIAM4DException` | `EIAM4DSecurityValidationException` (`ecTokenInvalid`), sottoclasse di `EIAM4DException` | comportamento | `Keycloak.pas:2460-2471` |
| `iss` della risposta (RFC 9207) | ignorato | callback locale e app redirect: un `iss` diverso, o assente quando la discovery annuncia `authorization_response_iss_parameter_supported` (Keycloak 26 lo fa), fa fallire il login con `EIAM4DCallbackHandlerException`. Modo esterno: controllato se l'app passa `AIss` | sicurezza/breaking | `Callback.Handler.pas:284-297,539`, `Core.pas:1266`. Il punto più delicato per i sample web e mobile (fase 3) |
| `max_age` | `max_age` inviato ma `auth_time` mai letto | id_token senza `auth_time`, o più vecchio di `max_age` rispetto all'inizio del flusso (+300 s), rifiutato con `EIAM4DSecurityValidationException` | sicurezza | CHANGELOG, `IAM4D_AUTH_TIME_CLOCK_SKEW_SECONDS` |
| state / nonce | `CreateGUID`, 32 cifre esadecimali maiuscole | CSPRNG a 128 bit, 32 cifre minuscole | sicurezza | `Keycloak.pas:1027-1044` |
| Callback con uno state diverso | lo state veniva controllato dopo che il browser aveva già ricevuto la pagina di successo; il login falliva (qualunque pagina poteva interromperlo) | controllo sincrono: il browser riceve un 400 e il login resta in attesa | sicurezza/comportamento | `Callback.Handler.Local.pas:186-187`, `Callback.Handler.pas:495-506` |
| Risposta d'errore OAuth2 (`error=access_denied`, `login_required`) | ignorata: la promise non terminava mai | con lo state del flusso: `EIAM4DOAuth2CallbackException` (`error`, `error_description` nel `Context`) e pagina 400; senza state, o con uno state diverso, ignorata | fix/comportamento | `Server.Callback.IndyHttpServer.pas:487-510` |
| Callback ripetuta (reload) | code scambiato due volte | una sola volta per state; la seconda riceve un 400 | fix | `Callback.Handler.Local.pas:191-199` |
| Classe degli errori della callback | sempre `EIAM4DCallbackHandlerException` | errori OAuth2: `EIAM4DOAuth2CallbackException`; altri: `EIAM4DCallbackHandlerException` | breaking (minore) | `Callback.Handler.pas:528-553` |
| Header `Host` del server di callback | non controllato | diverso da `localhost`, `127.0.0.1`, `[::1]` → 400 (DNS rebinding) | sicurezza | `Server.Callback.IndyHttpServer.pas:418-430` |
| Pagine del server di callback | header di default; pagina inviata dopo l'evento (uno `Stop` veloce la troncava) | `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `nosniff`, UTF-8; pagina scritta dentro l'evento | comportamento/fix | `Server.Callback.IndyHttpServer.pas:388-417` |
| `Stop` del server di callback | poteva bloccarsi per sempre (gara di Indy); 500 ms con una connessione aperta | scheduler proprio (polling ogni 5 ms); aspetta al massimo 2 s le richieste e 5 s i thread | fix | `Server.Callback.IndyHttpServer.pas:149-151,232-315` |
| `CancelAuthorizationFlow`, distruttore del client | promise in errore (`EIAM4DException`: `OnError`) | promise Cancelled (`OnFinally`, niente `OnError`); il distruttore ferma prima il server e aspetta lo scambio in corso | breaking | `Keycloak.pas:933-951,1545-1561`. Chi mostrava un messaggio in `OnError` all'annullamento non lo vede più |
| `Cancel` sull'operazione di `StartAuthorizationFlowAsync(...).Run` | ignorato: il server restava attivo e un thread del pool restava bloccato | termina il flusso e ferma il server; nessun thread aspetta il browser | fix | `Keycloak.pas:1462` |
| Secondo login, o `ConfigureAsync`, con un login in attesa | la prima promise non terminava mai | il flusso precedente termina come Cancelled; una callback tardiva non completa il nuovo | fix | `Keycloak.pas:750-758,1464-1473` |
| `CompleteAuthorizationFlow` (modo esterno) | contesto letto e cancellato solo dopo il successo: dopo un errore si poteva riprovare con lo stesso state | contesto preso in modo atomico prima dello scambio (`TakeContext`): un secondo tentativo dà `EIAM4DException` "No authorization flow is waiting" | comportamento/sicurezza | `Callback.Handler.External.pas:235`, `Keycloak.pas:1106-1114` |
| `TIAM4DOAuth2URLParser` | URL `schema:/percorso` rifiutate (`TURI`); messaggio "error - " anche senza descrizione | analizzate (schema privato), con `KeycloakActionStatus` e `Iss`; " - descrizione" solo se c'è | comportamento | `Common.OAuth2URLParser.pas:124-154,256-279` |
| `TIAM4DPlatformUtils.OpenURL` | tutto tranne `file:`, `javascript:`, `data:` (anche `mailto:`, `ms-*`, protocolli personalizzati) | solo http e https, altrimenti False | breaking/sicurezza | `Common.PlatformUtils.pas:290-292` |

### 3.4 Token, refresh e logout

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| Refresh fallito in `GetAccessToken` | qualsiasi errore azzerava i token; `invalid_grant` arrivava come `EIAM4DException` "Token endpoint failed: 400" | `invalid_grant` → `EIAM4DRefreshTokenExpiredException` (`Context['error_description']`) e token azzerati; errori di rete, timeout e 5xx conservano i token (`IsAuthenticated` resta True) | breaking/comportamento | `Keycloak.pas:1689-1708` |
| Risposta di refresh senza `refresh_token` o `scope` | refresh token salvato vuoto: la sessione si perdeva | refresh token precedente, scadenza e scope conservati | fix | `Keycloak.pas:2265-2284` |
| id_token del refresh | salvato com'era, anche vuoto | validato, con `sub`/`aud`/nonce uguali a quelli del login; se non è valido `EIAM4DSecurityValidationException` e token azzerati; con la JWKS irraggiungibile il nuovo viene scartato e resta il vecchio; se manca resta il precedente | sicurezza/fix | `Keycloak.pas:2272-2281,2409-2448` |
| id_token in Client Credentials | ignorato | validato come sopra se presente (scope `openid`) | comportamento | `Keycloak.pas:2317-2319` |
| Rinnovo fallito in Client Credentials | token azzerati; errore sostituito da `EIAM4DException('Failed to re-authenticate client...')` | token azzerati; le eccezioni della libreria (per esempio il timeout) arrivano così come sono | comportamento | `Keycloak.pas:1714-1731` |
| Refresh in gara con login o logout | un refresh tardivo poteva sovrascrivere la sessione di un nuovo utente o ripristinarne una appena chiusa | token salvati solo se la generazione non è cambiata; `Logout` e `RevokeTokens` sotto il lock del refresh | fix | `Keycloak.pas:617-630,1676-1688,1877` |
| `Logout`: richiesta | GET lato server di `end_session?client_id&id_token_hint`, solo Authorization Code | con un refresh token: POST back-channel a `end_session` (`client_id`, secret, `refresh_token`); 200/204 e `invalid_grant` = già chiusa; nessuna richiesta con il refresh token scaduto; GET con `id_token_hint` solo senza refresh token | comportamento | `Keycloak.pas:1871-1900,2201-2231` |
| `Logout`: errori e scope | in caso di errore i token restavano; `FScopes.Clear` svuotava gli scope configurati (il login successivo chiedeva solo `openid`) | token sempre azzerati, anche quando la richiesta fallisce (l'errore viene comunque sollevato); scope ripristinati | fix/comportamento | `Keycloak.pas:1901-1904,2194-2199` |
| `GenerateLogoutURL` | privata, nessun controllo | pubblica; senza `end_session_endpoint` → `EIAM4DException`; `post_logout_redirect_uri` solo http(s), `http` verso host esterni solo con `AllowInsecureHTTP` | nuovo/comportamento | `Keycloak.pas:1598-1621` |
| `GetUserInfo` | risposta restituita com'era | `sub` diverso da quello dell'id_token → `EIAM4DSecurityValidationException` | sicurezza | `Keycloak.pas:1852-1864` |
| `TIAM4DUserInfo.GetCustomClaims` | nomi dei claim standard confrontati senza distinzione di maiuscole | case-sensitive: `Email` finisce tra i claim personalizzati | comportamento | `Core.pas:1647` |
| Ora UTC | `TTimeZone.Local.ToUniversalTime(Now)`: un'ora avanti nella prima ora ripetuta di fine ora legale | `TDateTime.NowUTC` (serializer, storage, validatore, JWKS, `auth_time`, DTO, sessioni) | fix | `Common.TokenSerializer.pas:110-119`, `Storage.AESMemoryTokenStorage.pas:385,398` |
| JSON dei token (`TokenSerializer`) | niente `scope` | legge e scrive `scope` (un JSON 2.1 si carica, con `Scope` = '') | comportamento | `Common.TokenSerializer.pas:104,132` |
| Metodi `*Async` del client | catturavano `Self`: rilasciare il client durante un task portava a un use-after-free | catturano un riferimento `IIAM4DClient`: il client vive fino alla fine del task e può essere liberato sul thread di lavoro | fix/comportamento | `Keycloak.pas:548-573` |

---

## 4. Comportamenti cambiati: sicurezza, Admin API, Async.Core, DMVC

### 4.1 Validazione JWT (`Security.JWT`)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `alg` (allow-list, verifier, provider) | `SameText`: `rs256` passava come RS256 | confronto esatto (RFC 7515) | sicurezza/breaking | `Security.JWT.pas:595`, `Verifiers.Universal.pas:145-165`. Le liste passate a `SetAllowedAlgs` devono usare i nomi registrati |
| `alg` della JWK | ignorato | se la chiave dichiara `alg`, deve coincidere con quello del token | sicurezza | `Security.JWT.pas:892` |
| `crit` nell'header | ignorato | token rifiutato | sicurezza | `Security.JWT.pas:859` |
| Base64url | caratteri non validi saltati | padding, caratteri estranei, lunghezza 4n+1 o bit inutilizzati non nulli → rifiuto | sicurezza | `Security.JWT.pas:808` |
| `typ` dell'header | solo `JWT` (senza distinzione di maiuscole) | `AllowedHeaderTypes` (default `['JWT']`); `application/` facoltativo, quindi `application/jwt` ora passa | comportamento | `Security.JWT.pas:850,945`. Il middleware DMVC usa `['JWT','at+jwt']` (sezione 4.6) |
| `typ` del payload | non controllato | `SetExpectedTokenType`: un `typ` diverso viene rifiutato, un token senza `typ` passa | sicurezza | `Security.JWT.pas:863-870`. Client: `ID`; DMVC: `Bearer` |
| Issuer atteso vuoto | discovery e JWKS scaricate dall'`iss` del token (richiesta verso un host scelto da chi manda il token), poi rifiuto | rifiuto immediato, senza richieste | sicurezza | `Security.JWT.pas:793-797` |
| `exp`/`nbf`/`iat` | `GetValue<Int64>`: una stringa numerica passava, una frazione valeva 0 | solo numeri JSON (frazioni ammesse, `nbf` arrotondato per eccesso); negativi, oltre l'anno 9999 o non numerici → rifiuto | sicurezza/fix | `Security.JWT.pas:391-421` |
| Tolleranza su `nbf` | rifiuto se now - skew < nbf (più severo) | rifiuto se now + skew < nbf (RFC 7519) | fix | `Security.JWT.pas:750` |
| `iat` nel futuro (con `SetIatMaxAge`) | rifiutato senza tolleranza | ammesso entro now + skew | fix | `Security.JWT.pas:719` |
| `aud` array di un elemento | contava come audience multipla: senza `azp` il token veniva rifiutato | audience singola | fix | `Security.JWT.pas:664` |
| Controllo dell'audience senza audience attesa | `aud` "x" rifiutato; un array con "" accettato | eccezione: "Audience validation is enabled but no expected audience" | comportamento | `Security.JWT.pas:644-646` |
| Replay del `jti` | controllo e registrazione separati (due richieste parallele passavano); ricordato solo per la TTL | un solo passo atomico; ricordato fino a max(exp + skew, now + TTL); cache dei token disattivata con il controllo del jti | sicurezza | `Security.JWT.pas:757,1104-1137` |
| Cache dei token validati | valida fino a exp - buffer, anche oltre `SetIatMaxAge` e dopo la rimozione della chiave; i setter non la svuotavano | min(exp - buffer, iat + IatMaxAge, now + 300 s); svuotata da ogni setter di policy; chiave SHA-256; quando è piena se ne toglie un ottavo | sicurezza/comportamento | `Security.JWT.pas:1164-1258,1300-1308` |
| Classi delle eccezioni | `EIAM4DSecurityValidationException` generica, `ecUnknown` | `EIAM4DJWTIssuerMismatchException`, `EIAM4DJWKSKeyNotFoundException`, `EIAM4DJWTSignatureInvalidException` (sottoclassi, stessi messaggi, codici dedicati) | comportamento | `Security.JWT.pas:639,878,889,899` |
| ES256/384/512 | in lista con TMS, ma il verifier universale le rifiutava | verificate con TMS e TaurusTLS; LockBox3 continua a rifiutarle | nuovo | `Verifiers.Universal.pas:194`, `Verifiers.ECDSA.pas` |
| Algoritmo che il provider non supporta | RS*/PS* inviati comunque ai verifier | "Unsupported JWT algorithm", con l'elenco degli algoritmi del provider | comportamento | `Verifiers.Universal.pas:175-179` |

### 4.2 JWKS (`Security.JWT.JWKS`)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| Discovery | `issuer` del documento non controllato; qualsiasi `jwks_uri` | `issuer` uguale a quello richiesto (la `/` finale si ignora); `jwks_uri` http(s), https se l'issuer è https | sicurezza/breaking | `Security.JWT.JWKS.pas:512-521,858-868`. Si rompe con un frontend URL o un proxy che cambia l'issuer |
| Scelta della chiave | prima chiave RSA/EC con quel `kid` (o la prima in assoluto, senza `kid`), anche `use: enc` | solo chiavi di firma (`use` assente o `sig`, `key_ops` assente o con `verify`), per `kid` e famiglia (RSA, EC P-256/384/521) | sicurezza | `Security.JWT.JWKS.pas:913-997` |
| Rotazione | ogni chiave scaricata si aggiungeva; una chiave ritirata validava fino alla TTL (1 h) | ogni refresh sostituisce tutto il set dell'issuer | sicurezza | `Security.JWT.JWKS.pas:745-790` |
| `kid` sconosciuto | discovery più due fetch della JWKS a ogni miss | un refresh per issuer ogni 30 s al massimo (`SetMinRefreshIntervalSeconds`), un solo refresh in corso, cache negativa limitata (1000) | comportamento | `Security.JWT.JWKS.pas:999-1083` |
| Chiave scaduta o IdP irraggiungibile | refetch sincrono; se fallisce, errore | chiave servita subito e refresh in background; con l'IdP giù le chiavi restano valide fino a TTL + 24 h | comportamento | `Security.JWT.JWKS.pas:1157-1276` |
| Errori | `EIAM4DSecurityValidationException` generica | `EIAM4DJWKSUnavailableException` (`ecDiscoveryFailed`, `RetryAfterSeconds`) e `EIAM4DJWKSKeyNotFoundException`; `on E: EIAM4DSecurityValidationException` le intercetta ancora | comportamento | `Security.JWT.JWKS.pas:49,374,1058` |
| `ClearCache` | chiavi e cache negativa | anche gli stati degli issuer (jwks_uri, intervallo); le `SetJWKSUri` restano | comportamento | `Security.JWT.JWKS.pas:1380-1415` |
| Provider per client | ogni `TIAM4DKeycloakClient` aveva il suo | i client senza pin condividono un provider per processo, per modo SSL e timeout (`TIAM4DSharedJWKSProviders`) | comportamento | `Security.JWT.JWKS.pas:1480-1560` |

### 4.3 Crittografia, storage ed eccezioni

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| Chiavi RSA | qualsiasi `n`/`e` (anche `e = 1`: il messaggio verificava se stesso) | `TIAM4DRSAPublicKey.IsValid`: da 2048 a 16384 bit (`MinModulusBits`, abbassabile a 1024), `e` dispari, 3 ≤ e < n | breaking/sicurezza | `Security.Crypto.Interfaces.pas:180-300`. Una chiave a 1024 bit dà `EIAM4DJWTSignatureInvalidException` |
| `n` con uno zero iniziale | RS*: ogni firma rifiutata | zeri ignorati; firma lunga esattamente k byte (anche PS*) | fix | `Verifiers.RSA.pas:322`, `Verifiers.RSAPSS.pas:214` |
| LockBox3 in parallelo | un pool di memoria condiviso, non thread-safe: token validi rifiutati, leak | un pool per chiamata | fix | `Security.Crypto.LockBox3.pas:164,387` |
| TMS RSA | modulo oltre 8192 bit → eccezione; nessun controllo s < n | False; s < n (RFC 8017) | fix/sicurezza | `Security.Crypto.TMS.pas:496-622` |
| TMS `ECDSAVerify(digest)` | non funzionava (doppio hash, manca il prefisso `04`) | `EIAM4DCryptoNotSupportedException`; ES* passano da `IIAM4DECDSAMessageVerifier` | breaking (chiamate dirette)/fix | `Security.Crypto.TMS.pas:690-735` |
| Storage dei token | sempre LockBox3 CBC + HMAC | il provider compilato: LockBox3 (formato identico alla 2.1) oppure AES-256-GCM con TMS/TaurusTLS | comportamento | `Storage.AESMemoryTokenStorage.pas:144`. Incompatibilità solo teorica: lo storage è in memoria |
| IV di LockBox3 | seed dal generatore globale di LockBox3, non crittografico | seed dal CSPRNG; formato invariato | sicurezza | `Crypto.AES256_CBC_HMAC_LB.pas:137-141` |
| Storage TMS | buffer di output vuoti: non funzionava mai | funziona; plaintext azzerato quando il tag è sbagliato | fix | `Storage.Crypto.TMS.pas:165-238` |
| Errore di caricamento dello storage | "Authentication failed (HMAC)." | "Failed to load tokens (RawKey32): ..." (stessa classe) | comportamento | `Storage.AESMemoryTokenStorage.pas:348` |
| `EIAM4DStorageCryptoException` | deriva da `Exception` | deriva da `EIAM4DException` (codici `ecStorage*`) | breaking (ordine degli `except`) | `Storage.Crypto.Interfaces.pas:131,197` |
| Gerarchia delle eccezioni Admin | `EIAM4DInsufficientPermissions`, `UserNotFound`, `UserAlreadyExists`, `RoleNotFound`, `GroupNotFound` da `EIAM4DException` | 403 → `EIAM4DHTTPClientErrorException`; not found → `EIAM4DHTTPNotFoundException`; already exists → `EIAM4DHTTPConflictException` | breaking (ordine degli `except`) | `Exceptions.pas:444-559`. Un `on EIAM4DHTTPClientErrorException` messo prima li intercetta |
| Eccezioni rilanciate da `WaitForResult` | copiate con `ExceptClass.Create(Message)`: `ErrorCode`, `Context`, `StatusCode` persi | clonate con tutti i campi | fix | `Exceptions.pas:1261-1265` |
| `EIAM4DNetworkTimeoutException` | URL completo nel messaggio e nell'endpoint | senza query e fragment (niente `id_token_hint` nei log) | comportamento | `Exceptions.pas:908-920` |
| Eccezioni deprecate | — | `EIAM4DAccessTokenExpired`, `InvalidAuthCode`, `PKCEValidation`, `AuthorizationTimeout`, `EndpointsNotConfigured`, `UnknownRequiredAction`: mai sollevate, W1000 | deprecato | `Exceptions.pas:250-646` |

### 4.4 Admin API (`UserManagement.Keycloak`, `Admin.Keycloak.Base`)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| Errori HTTP | ogni status diverso da 200/201/204 → `EIAM4DInvalidConfigurationException` | 403 `EIAM4DInsufficientPermissionsException`, 404 `EIAM4DHTTPNotFoundException`, 409 `EIAM4DHTTPConflictException`, altri 4xx `EIAM4DHTTPClientErrorException`, 5xx `EIAM4DHTTPServerErrorException` (`RetryAfter`); 3xx ancora `EIAM4DInvalidConfigurationException` | breaking | `Admin.Keycloak.Base.pas:437-467` |
| Messaggi | corpo intero; URL con la query (username ed email nei log) | corpo tagliato a 500 caratteri (intero in `ResponseBody`); niente query | comportamento | `Admin.Keycloak.Base.pas:478-522` |
| Errori di rete | `ENetHTTP*` dell'RTL | eccezioni della libreria (come al punto 3.1) | breaking | `Admin.Keycloak.Base.pas:133-137` |
| Client HTTP | un `THTTPClient` per operazione | pool per manager (4 inattivi); una modifica SSL vale per i manager creati dopo | comportamento | `Admin.Keycloak.Base.pas:621-700` |
| Redirect | seguiti, con il bearer, anche verso altri host o `http`; `DELETE` diventava `GET` su 303 | non seguiti; 3xx → `EIAM4DInvalidConfigurationException` | sicurezza | `Admin.Keycloak.Base.pas:649-651` |
| Segmenti di percorso | `TNetEncoding.URL`: lo spazio diventava `+` (un ruolo con uno spazio non si trovava); realm non codificato; ID vuoto ammesso (`UnlockUser('')` sbloccava tutto il realm) | `%20`; realm codificato; segmento vuoto, `.` o `..` → `EIAM4DInvalidConfigurationException` prima della richiesta | sicurezza/fix | `Admin.Keycloak.Base.pas:411-435` |
| `Create(AClient, ABaseURL, ARealm)` | con uno dei due vuoto prendeva entrambi dall'issuer | prende dall'issuer solo il valore mancante; realm decodificato | fix | `Admin.Keycloak.Base.pas:364-381` |
| Token nei batch | un token per tutto il batch (scadeva dopo 5 minuti) | rilettura prima di ogni elemento | fix | `UserManagement.Keycloak.pas:799,881,940,...` |
| `CreateUser` su 409 | `EIAM4DInvalidConfigurationException` | `EIAM4DUserAlreadyExistsException` (`ConflictingField`) | breaking | `UserManagement.Keycloak.pas:634-656` |
| `TemporaryPassword` di `CreateUser(s)` | non controllata | `ValidatePassword` (8..4096) → `EIAM4DInvalidUserDataException` (in `CreateUsers`, nell'`ErrorMessage` dell'elemento) | comportamento | `UserManagement.Keycloak.pas:638-640,878-880` |
| `UpdateUser` / `UpdateUsers` | email e nomi vuoti omessi (non si potevano cancellare); `requiredActions` vuoto omesso; `Enabled`/`EmailVerified` sempre inviati | il record sostituisce il profilo: i campi vuoti lo azzerano, `requiredActions` è sempre inviato, lo username vuoto no | breaking | `UserManagement.Keycloak.pas:299-357`. Leggere l'utente, modificarlo, aggiornarlo |
| Azioni richieste fuori da `TIAM4DRequiredAction` | lettura dell'utente in errore (`EIAM4DUnknownRequiredActionException`, `EArgumentException`) | in `OtherRequiredActions`, rimandate a Keycloak su create e update | fix | `UserManagement.Keycloak.pas:380-404` |
| `Set/RemoveUserRequiredActions` | doppia liberazione dell'array JSON (`EInvalidPointer`) | funzionano | fix | `UserManagement.Keycloak.pas:1646-1720` |
| `GetUserByUsername` / `TryGetUserByUsername` | `ValidateUsername`: rifiutava `@`, `+` e nomi sotto i 3 caratteri | solo non vuoto e al massimo 255 caratteri | fix | `UserManagement.Validation.pas:184-191` |
| `ValidateUsername` | `^[a-zA-Z0-9._-]+$` | accetta anche `@` e `+` | comportamento | `UserManagement.Constants.pas:110` |
| Paginazione | qualsiasi valore (max negativo = tutti gli utenti) | `First` < 0 o `Max` < 1 → `EIAM4DInvalidConfigurationException` | breaking | `UserManagement.Validation.pas:258-263` |
| `GetUserByEmail` / `TryGetUserByEmail` con email duplicate | il primo trovato | `EIAM4DInvalidUserDataException` | breaking | `UserManagement.Keycloak.pas:1748-1785` |
| `GetUserByEmail`, `TryGetUserByEmail`, `IsUserLocked` | non arrivavano a Keycloak (variabili locali nascondevano quelle catturate) | funzionano | fix | CHANGELOG |
| Ruoli, client e gruppi non trovati | `EIAM4DException` o `EIAM4DInvalidConfigurationException` | `EIAM4DRoleNotFoundException`, `EIAM4DHTTPNotFoundException`, `EIAM4DGroupNotFoundException` | breaking | `UserManagement.Keycloak.pas:1342-1409,2544-2845` |
| Ruolo per nome (`Assign/Remove*ByName`) | lista completa e `SameText` | `GET roles/{name}` e nome uguale (case-sensitive) | breaking | `UserManagement.Keycloak.pas:1342-1409` |
| Confronti di nomi (`HasRole`, `HasClientRole`, gruppi per percorso, helper, `TIAM4DRoleLookupCache`) | senza distinzione di maiuscole | case-sensitive (gli ID restano case-insensitive) | breaking | `UserManagement.Helpers.pas:1121-1828` |
| Gruppi per percorso | cercati in `GET /groups` (i sottogruppi mancavano dalla 23 in poi) | `GET group-by-path/{path}`, percorso esatto | fix/comportamento | `UserManagement.Keycloak.pas:524-556` |
| `GetGroups` | solo il primo livello | tutto l'albero, appiattito (richieste in più) | breaking | `UserManagement.Keycloak.pas:1412-1437,558-601` |
| `AssignClientRolesToUser(s)` | controllava solo il primo ruolo; tutti i ruoli inviati al client del primo | ogni ruolo controllato, una POST per client | fix | `UserManagement.Keycloak.pas:2402-2437` |
| `IsUserLocked` | qualsiasi errore → False | False solo per 404; gli altri errori vengono sollevati | comportamento | `UserManagement.Keycloak.pas:1875-1898` |
| `RevokeUserSession(UserID, SessionID)` | cancellava qualsiasi sessione del realm | sessione non dell'utente → `EIAM4DHTTPNotFoundException` (una richiesta in più) | sicurezza | `UserManagement.Keycloak.pas:2002-2030` |
| Manager async | catturavano `Self`; array condivisi con il chiamante | un riferimento al manager per operazione; array copiati | fix | `UserManagement.Keycloak.Async.pas:223-235` |
| `TIAM4DUser.CreatedTimestamp`, `IdleTimeInSeconds` | ora locale presa come UTC / ora legale | `NowUTC` | fix | `UserManagement.Core.pas:1672`, `UserManagement.Helpers.pas:1618` |
| `TClientBasedAuthProvider.GetAccessToken` | `GetAccessTokenAsync.Run.WaitForResult` (copia dell'eccezione) | `GetAccessToken` sincrono, eccezione originale | comportamento | `Admin.Keycloak.Base.pas:286-290` |
| Gestione degli IdP (nuova) | — | segreto mascherato rifiutato; `hideOnLogin` rimandato senza il campo a Keycloak < 26; elenco paginato completo | nuovo | `IdentityProvider.Keycloak.pas` |

### 4.5 Async.Core

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `RunWithTimeout` alla scadenza | Cancelled (`EAsyncCancelException`) | Faulted con `EAsyncTimeoutException`; il task riceve la richiesta di annullamento | breaking | `Async.Core.pas:2580-2585` |
| `dmQueue` chiamato dal main thread | `TThread.Queue` eseguiva subito, dentro la chiamata | `TThread.ForceQueue`: sempre al giro successivo del message loop | breaking | `Async.Core.pas:1679-1681`. `TAsyncTaskCompletionSource` usa `dmQueue` di default; una console che non pompa non vede le callback |
| Eccezione in `OnSuccess` (dmSynchronize) | l'operazione da Completed diventava Faulted e partiva `OnError` | lo stato non cambia: `OnUnhandledError`, altrimenti `ApplicationHandleException` sul main thread, altrimenti l'eccezione viene scartata | breaking | `Async.Core.pas:1664-1676,1850-1856` |
| Eccezioni in `OnFinally`/`OnCompletion`/`OnCancelled` | perse o inghiottite | come sopra | comportamento | `Async.Core.pas:1657-1687` |
| Eccezione passata a `OnError` | copia con classe e messaggio soltanto | l'oggetto originale con tutti i campi (da non liberare né conservare) | comportamento | `Async.Core.pas:1576-1586` |
| `WaitForResult`, `GetException` | copia con classe e messaggio | clone tramite i cloner registrati (`EIAM4DException`: tutti i campi) | comportamento | `Async.Core.pas:1745-1777` |
| Combinatori senza main thread (`ContinueWith`, `WhenAll`, `WhenAny`, `RunWithTimeout`, `LinkCancellationToken`) | concatenati con `Synchronize`: bloccati in console, servizi e server DMVC | continuazioni inline e un thread timer condiviso | fix | `Async.Core.pas:2186-2377,910-1179` |
| `Cancel` sul risultato dei combinatori | impostava solo il flag; il risultato restava in attesa | Cancelled subito, inoltrato alle operazioni sorgente | comportamento | `Async.Core.pas:2194-2593` |
| `ContinueWith` con `EAsyncCancelException` nella continuazione | Faulted | Cancelled | comportamento | `Async.Core.pas:2221-2222` |
| `WhenAll` con un'operazione completata senza risultato | non terminava mai | Faulted (`EAsyncException`) | fix | `Async.Core.pas:2300-2304` |
| `Delay`, `CreateCancellationTokenWithTimeout` | un thread del pool bloccato per tutta l'attesa | thread timer condiviso; `Cancel` termina subito come Cancelled, callback su un thread del pool | comportamento | `Async.Core.pas:2620-2678` |
| Attesa di `RunWithRetry` | `Sleep` su un thread del pool (Cancel efficace solo alla fine) | timer; `Cancel` durante l'attesa termina subito | comportamento | `Async.Core.pas:2501-2536` |
| `RunWithRetry`: errori ritentati | tutti tranne `EAsyncCancelException` | uguale di default; filtro facoltativo `AShouldRetry` | nuovo | `Async.Core.pas:2456-2468` |
| `RunWithRetry` con `AMaxRetries` < 0 / `Linear` con delay 0 | errore a runtime / `EDivByZero` | `EArgumentOutOfRangeException` subito / nessuna divisione | fix | `Async.Core.pas:2557-2558` |
| `OnCancelled` | un solo gestore: il secondo sostituiva il primo (anche quello interno di `Delay`) | più gestori | comportamento | `Async.Core.pas:1339-1379` |
| `TryWaitForResult` | sollevava e intercettava `EAsyncTimeoutException` | nessuna eccezione | fix | `Async.Core.pas:1633-1641` |
| `TAsyncTaskCompletionSource` | riferimento a oggetto: leak, oppure use-after-free | riferimento a interfaccia | fix | `Async.Core.pas:1991-1996` |
| Chiusura dell'applicazione | i `Delay` in attesa bloccavano l'uscita | timer in attesa rilasciati alla finalizzazione | fix | `Async.Core.pas:1026-1051` |
| Ordine delle callback | `OnSuccess`/`OnError`, `OnCompletion`, attese, `OnFinally` | invariato; nuovo `dmInline` | nuovo | `Async.Core.pas:1825-1861` |

### 4.6 DMVC (`DMVC.*`)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DJWTMiddleware` | middleware classico | deprecato (W1000): usare `IAM4DJWTBundle`. Il middleware non protegge le route Minimal API | deprecato | `DMVC.Middleware.pas:139` |
| `Issuer` vuoto | accettato (discovery verso l'`iss` del token, poi 401) | `EIAM4DInvalidConfigurationException` nel costruttore | breaking/sicurezza | `DMVC.Authenticator.pas:275-277` |
| `Audience` vuota con `AudienceValidationEnabled` | si avviava, ogni token 401 | eccezione nel costruttore (anche da `SetAudienceValidationEnabled(True)`) | breaking | `DMVC.Authenticator.pas:284-285,473-479` |
| `TokenHeaderName` vuoto | ogni richiesta 401 | eccezione nel costruttore | breaking | `DMVC.Authenticator.pas:279-281` |
| Config compilata campo per campo senza `Create` | zeri: `AudienceValidationEnabled` False, skew 0, timeout 0, header '' | operatore `Initialize` con i default di `Create`: controllo dell'audience attivo, skew 60, `Authorization` | breaking | `DMVC.Authenticator.pas:225-249` |
| Timeout HTTP di default | 30000 / 60000 ms | 10000 / 15000 ms | comportamento | `DMVC.Authenticator.pas:243-244` |
| `JWKS_URL`, `RolesClaimName`, `SubjectClaimName` | ignorati (`SubjectClaimName` solo nel log) | usati (`JWKS_URL` salta la discovery) | fix/comportamento | `DMVC.Authenticator.pas:321-322,595-672` |
| `SetExpectedAzp('')` | non azzerava | azzera | fix | `DMVC.Authenticator.pas:453-458` |
| `typ` dell'header | solo `JWT` | `JWT` e `at+jwt` (`AllowedHeaderTypes`; `['JWT']` ripristina la 2.x) | comportamento | `DMVC.Authenticator.pas:246,332` |
| `typ` del payload | non controllato: un id_token Keycloak con la `aud` giusta passava | deve essere `Bearer` (`ExpectedTokenType`); senza `typ` passa | sicurezza/breaking | `DMVC.Authenticator.pas:245,330` |
| OPTIONS | autenticazione saltata (un'azione senza `[MVCHTTPMethod]` girava anonima) | autenticata come gli altri verbi; il preflight CORS va gestito prima | breaking/sicurezza | `DMVC.Authenticator.pas:807-808` |
| Percorsi "Swagger" (GET con `swagger`/`openapi`/`api-docs` e `.json`) | autenticazione saltata, anche per azioni dei controller | nessuna esenzione; un controller che serve il proprio documento va marcato `[IAM4DPublic]` | breaking/sicurezza | `DMVC.Middleware.pas:214-222` |
| `AllowAnonymous` con un token non valido | passava come anonimo | 401 `invalid_token` | sicurezza | `DMVC.Authenticator.pas:816-818` |
| Validatore personalizzato che dà True con claims nil | richiesta autenticata senza identità | 401 | fix | `DMVC.Authenticator.pas:747-751` |
| IdP irraggiungibile | 401 e `LogE` con stack trace | 503 `temporarily_unavailable` con `Retry-After` | comportamento | `DMVC.Authenticator.pas:543-565,783-789` |
| Messaggio del 401 | sempre "Missing or invalid Authorization header" | token mancante: invariato; token non valido: "Invalid or expired JWT token" | comportamento | `DMVC.Authenticator.pas:529-537` |
| `WWW-Authenticate` | WebBroker: sempre `error="invalid_token"`; altri host: solo `realm` | RFC 6750 su tutti gli host: `error` solo per un token rifiutato | comportamento | `DMVC.Common.pas:164-198` |
| Ruoli client in `LoggedUser.Roles` | tutti i client di `resource_access` | solo `Audience` ed `ExpectedAzp` (nessuno se sono entrambi vuoti) | sicurezza/breaking | `DMVC.Authenticator.pas:648-658` |
| Deduplicazione dei ruoli | senza distinzione di maiuscole | case-sensitive | breaking | `DMVC.Authenticator.pas:628-629` |
| `RequireAnyRole` / `RequireAllRoles` | solo il claim `roles` (Keycloak non lo emette: 403) | `LoggedUser.Roles` | breaking/fix | `DMVC.Helpers.pas:178-186,364-388` |
| `HasRole`, `HasScope`, `HasGroup`, ruoli realm, `amr` del DTO | `CompareText` | case-sensitive | breaking | `DMVC.DTO.pas:412-808` |
| Risposte 403 | messaggio con i ruoli/scope richiesti | "Insufficient permissions", `WWW-Authenticate` con `insufficient_scope`; dettagli in `LogW` | comportamento/sicurezza | `DMVC.Helpers.pas:161,190-198` |
| `RequireAuthentication` | 401 senza header | 401 con challenge, oppure 503 con `Retry-After` | comportamento | `DMVC.Helpers.pas:339-362` |
| `GetCustomClaim*` | nome letto come percorso JSON (`address.country` trovava il valore annidato; i nomi con `.` fallivano) | nome letto come chiave di primo livello | breaking/fix | `DMVC.Helpers.pas:261-320` |
| Scope del DTO | solo `scope` | `scp` se `scope` manca | comportamento | `DMVC.DTO.pas:659-667` |
| Claim stringa del DTO | `null` diventava 'null', i numeri diventavano testo | solo stringhe JSON | fix | `DMVC.DTO.pas:302-318` |
| `CONTEXT_KEY_STD_JSON` / `KC_JSON` | popolate | non più popolate (deprecate) | breaking | `DMVC.Common.pas:35-36` |
| `JWT_Auth_Status` | `authenticated` / `not_authenticated` (non impostato per OPTIONS e Swagger) | sempre impostato; in più `invalid_token` e `unavailable` | comportamento | `DMVC.Authenticator.pas:724-733` |
| `LoggedUser` | non svuotato prima (con una sessione attiva: 401, perché `LoggedSince` si assegna una volta sola) | `Clear` prima di popolarlo | fix | `DMVC.Authenticator.pas:606-608` |
| `LoggedUser.CustomData` `exp`, `iat`, `auth_time` | `DateTimeToStr` (locale del server) | ISO 8601 UTC | breaking | `DMVC.Authenticator.pas:691-697` |
| `LoggedSince` senza `iat` | `Now` locale | `NowUTC` | comportamento | `DMVC.Authenticator.pas:622-626` |
| Log dei token rifiutati | `LogW` a ogni 401, `LogE` con stack trace, testo non filtrato | 401 a livello debug; un `LogW` ogni `RejectedTokenWarningIntervalSec` (10 s); testo filtrato e limitato a 512 caratteri | comportamento/sicurezza | `DMVC.Authenticator.pas:397-423,777-795` |
| Iniezione dello schema bearer | solo Swagger 2.0; qualsiasi percorso con le parole chiave; `Content-Type` forzato | anche OpenAPI 3; conta solo il nome del file; `Content-Type` lasciato com'è | comportamento | `DMVC.Internal.pas:175-346` |
| `[IAM4DPublic]` su un controller dichiarato nella sezione implementation | protetto senza avvisi | protetto, con un `LogW` | comportamento | `DMVC.Internal.pas:133-135` |
| Invariato (verificato) | `[MVCRequiresAuthentication]`/`[MVCRequiresRole]` di DMVC non letti; skew 60, cache JWKS 60 min, `RequireAzpWhenMultipleAud` True, prefisso `Bearer ` senza distinzione di maiuscole | uguale | — | |

---

## 5. Diff dell'interfaccia per unit

Generato da `tools/mdtables.py`, poi controllato a mano. Per le unit e i tipi nuovi c'è una riga per tipo, con l'elenco dei membri nella nota. Per i tipi esistenti c'è una riga per ogni membro cambiato. Le colonne 2.1 e 3.0 riportano la dichiarazione così come la normalizza lo script.

### `Async.Core.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IEventWrapper` | `interface` |  | breaking | spostato nella sezione implementation |
| `TAsyncCallbackDispatchMode` | `enum (dmSynchronize, dmQueue)` | `enum (dmSynchronize, dmQueue, dmInline)` | nuovo | valori aggiunti in coda: ordinali invariati |
| `TAsyncCore.ContinueWith` | `function ContinueWith<T, TResult>(const AOperation: IAsyncOperation<T>; const AContinuation: TAsyncCoreContinuationFunc<T, TResult>): IAsyncOperation<TResult>; static` | `function ContinueWith<T, TResult>(const AOperation: IAsyncOperation<T>; const AContinuation: TAsyncCoreContinuationFunc<T, TResult>; ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation<TResult>; static` | compatibile | parametri opzionali in coda: le chiamate compilano |
| `TAsyncCore.CreateCancellationTokenWithTimeout` | `function CreateCancellationTokenWithTimeout(ATimeoutMs: Cardinal): IAsyncOperation; static` | `function CreateCancellationTokenWithTimeout(ATimeoutMs: Cardinal; ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation; static` | compatibile | parametri opzionali in coda: le chiamate compilano |
| `TAsyncCore.Delay` | `function Delay(AMilliseconds: Cardinal): IAsyncOperation; static` | `function Delay(AMilliseconds: Cardinal; ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation; static` | compatibile | parametri opzionali in coda: le chiamate compilano |
| `TAsyncCore.FromOperation` |  | `function FromOperation<T>(const AOperation: IAsyncOperation<T>): IAsyncPromise<T>; static` | nuovo |  |
| `TAsyncCore.PendingTimerCount` |  | `function PendingTimerCount: Integer; static` | nuovo |  |
| `TAsyncCore.RegisterExceptionCloner` |  | `procedure RegisterExceptionCloner(AClass: ExceptClass; const ACloner: TAsyncExceptionCloner); static` | nuovo |  |
| `TAsyncCore.RunWithRetry` | `function RunWithRetry<T>(ATask: TAsyncCoreFunctionTask<T>; AMaxRetries: Integer = 3; AInitialDelay: Cardinal = 1000; ABackoffStrategy: TBackoffStrategy = TBackoffStrategy.Exponential; AMaxDelay: Cardinal = 30000): IAsyncOperation<T>; static` | `function RunWithRetry<T>(ATask: TAsyncCoreFunctionTask<T>; AMaxRetries: Integer = 3; AInitialDelay: Cardinal = 1000; ABackoffStrategy: TBackoffStrategy = TBackoffStrategy.Exponential; AMaxDelay: Cardinal = 30000; AShouldRetry: TAsyncCoreRetryPredicate = nil; A …` | compatibile | parametri opzionali in coda: le chiamate compilano |
| `TAsyncCore.RunWithTimeout` | `function RunWithTimeout<T>(ATask: TAsyncCoreFunctionTask<T>; ATimeoutMs: Cardinal): IAsyncOperation<T>; static` | `function RunWithTimeout<T>(ATask: TAsyncCoreFunctionTask<T>; ATimeoutMs: Cardinal; ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation<T>; static` | compatibile | parametri opzionali in coda: le chiamate compilano |
| `TAsyncCore.WhenAll` | `function WhenAll<T>(const AOperations: array of IAsyncOperation<T>): IAsyncOperation<TArray<T>>; static` | `function WhenAll<T>(const AOperations: array of IAsyncOperation<T>; ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation<TArray<T>>; static` | compatibile | parametri opzionali in coda: le chiamate compilano |
| `TAsyncCore.WhenAny` | `function WhenAny<T>(const AOperations: array of IAsyncOperation<T>): IAsyncOperation<T>; static` | `function WhenAny<T>(const AOperations: array of IAsyncOperation<T>; ADispatchMode: TAsyncCallbackDispatchMode = TAsyncCallbackDispatchMode.dmSynchronize): IAsyncOperation<T>; static` | compatibile | parametri opzionali in coda: le chiamate compilano |
| `TAsyncCorePromise<T>.CreateFromOperation` |  | `constructor CreateFromOperation(const ASource: IAsyncOperation<T>)` | nuovo |  |
| `TAsyncCoreRetryPredicate` |  | `proctype reference to function(const AException: Exception): Boolean` | nuovo |  |
| `TAsyncExceptionCloner` |  | `proctype reference to function(const ASource: Exception): Exception` | nuovo |  |
| `TAsyncOperationController<T>.SetResult` | `procedure SetResult(const AValue: T)` |  | breaking (impl.) | sostituito da `TrySetResult`: tocca solo le sottoclassi |
| `TAsyncOperationController<T>.TrySetResult` |  | `function TrySetResult(const AValue: T): Boolean` | nuovo |  |
| `TAsyncRetryOperation<T>` |  | `class(TAsyncOperationController<T >)` | nuovo | 1 membri: Create |
| `TAsyncTaskCompletionSource.Destroy` | `destructor Destroy; override` |  | compatibile | resta il distruttore ereditato |
| `TBackoffStrategy` | `enum (Fixed, Linear, Exponential)` | `enum (Fixed, Linear, Exponential, ExponentialJitter)` | nuovo | valori aggiunti in coda: ordinali invariati |
| `TEventWrapper` | `class(TInterfacedObject, IEventWrapper)` |  | breaking | spostato nella sezione implementation |

### `DMVCMiddleware/IAMClient4D.DMVC.Authenticator.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IIAM4DJWTAuthenticator` |  | `interface` | nuovo | 8 membri: AuthenticateRequest, AuthorizeRequest, Config, GetConfig, SetAudienceValidationEnabled, SetClaimsTransformer, SetExpectedAzp, SetRequireAzpWhenMultipleAud |
| `TIAM4DJWTAuthenticator` |  | `class(TInterfacedObject, IIAM4DJWTAuthenticator)` | nuovo | 9 membri: AuthenticateRequest, AuthorizeRequest, Create, Destroy, GetConfig, SetAudienceValidationEnabled, SetClaimsTransformer, SetExpectedAzp, SetRequireAzpWhenMultipleAud |
| `TIAM4DJWTMiddlewareConfig` |  | `record` | nuovo | 24 membri: AllowAnonymous, AllowedHeaderTypes, Audience, AudienceValidationEnabled, ClaimsTransformer, ClockSkewSeconds, Create, ExpectedAzp, ExpectedTokenType, HTTPConnectTimeoutMs, HTTPReceiveTimeoutMs, Issuer, JWKSCacheDurationMinutes, JWKS_URL, PinnedPublicKeys, RejectedTokenWarningIntervalSec, RequireAzpWhenMultipleAud, RolesClaimName, SSLValidationMode, SSLValidator, SubjectClaimName, TokenHeaderName, TokenPrefix, operator Initialize |

### `DMVCMiddleware/IAMClient4D.DMVC.ClaimsTransformation.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IIAM4DClaimsTransformer` |  | `interface` | nuovo | 1 membri: Transform |
| `TIAM4DRolesClaimsTransformer` |  | `class(TInterfacedObject, IIAM4DClaimsTransformer)` | nuovo | 7 membri: CacheCount, Clear, Create, Destroy, Invalidate, Mode, Transform |
| `TIAM4DRolesLoader` |  | `proctype reference to function(const ASubject: string; const AClaims: TJSONObject): TArray<string>` | nuovo |  |
| `TIAM4DRolesMode` |  | `enum (rmMerge, rmReplace)` | nuovo |  |

### `DMVCMiddleware/IAMClient4D.DMVC.Common.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `AUTH_STATUS_INVALID_TOKEN` |  | `'invalid_token'` | nuovo | const |
| `AUTH_STATUS_UNAVAILABLE` |  | `'unavailable'` | nuovo | const |
| `CACHE_KEY` | `'__IAM4D_JWT_CLAIMS_CACHE__'` | `'__IAM4D_JWT_CLAIMS_CACHE__' deprecated 'No longer used'` | deprecato | const |
| `CONTEXT_KEY_AUTHENTICATED_BY` |  | `'__IAM4D_AUTHENTICATED_BY__'` | nuovo | const |
| `CONTEXT_KEY_KC_JSON` | `'JWT_KC_JSON'` | `'JWT_KC_JSON' deprecated 'No longer populated: use Context.Keycloak'` | deprecato | const |
| `CONTEXT_KEY_REALM` |  | `'JWT_Realm'` | nuovo | const |
| `CONTEXT_KEY_RETRY_AFTER` |  | `'JWT_Retry_After'` | nuovo | const |
| `CONTEXT_KEY_STD_JSON` | `'JWT_STD_JSON'` | `'JWT_STD_JSON' deprecated 'No longer populated: use Context.JWT'` | deprecato | const |
| `IAM4D_LOG_TEXT_MAX_LENGTH` |  | `512` | nuovo | const |
| `KC_CACHE_KEY` | `'__IAM4D_KC_CLAIMS_CACHE__'` | `'__IAM4D_KC_CLAIMS_CACHE__' deprecated 'No longer used'` | deprecato | const |
| `bearerchallenge` |  | `function BearerChallenge(const ARealm, AError, ADescription: string; const AScope: string = ''): string` | nuovo | routine |
| `sanitizelogtext` |  | `function SanitizeLogText(const AText: string; AMaxLength: Integer = IAM4D_LOG_TEXT_MAX_LENGTH): string` | nuovo | routine |

### `DMVCMiddleware/IAMClient4D.DMVC.Filters.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `iam4djwtbundle` |  | `function IAM4DJWTBundle(const AConfig: TIAM4DJWTMiddlewareConfig): IMVCFilterBundle; overload`<br>`function IAM4DJWTBundle(const AIssuer, AAudience: string; const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict; const AExpectedAzp: string = ''): IMVCFilterBundle; overload`<br>`function IAM4DJWTBundle(const AAuthenticator: IIAM4DJWTAuthenticator): IMVCFilterBundle; overload` | nuovo | routine |
| `iam4djwtendpointfilter` |  | `function IAM4DJWTEndpointFilter(const AConfig: TIAM4DJWTMiddlewareConfig): TMVCEndpointFilter; overload`<br>`function IAM4DJWTEndpointFilter(const AIssuer, AAudience: string; const ASSLValidationMode: TIAM4DSSLValidationMode = svmStrict; const AExpectedAzp: string = ''): TMVCEndpointFilter; overload`<br>`function IAM4DJWTEndpointFilter(const AAuthenticator: IIAM4DJWTAuthenticator): TMVCEndpointFilter; overload` | nuovo | routine |
| `iam4dswaggersecurityhttpfilter` |  | `function IAM4DSwaggerSecurityHTTPFilter: TMVCHTTPFilter` | nuovo | routine |

### `DMVCMiddleware/IAMClient4D.DMVC.Internal.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IIAM4DPublicActionCache` |  | `interface` | nuovo | 1 membri: IsPublic |
| `iam4dinjectswaggersecurityinresponse` |  | `procedure IAM4DInjectSwaggerSecurityInResponse(AContext: TWebContext)` | nuovo | routine |
| `newiam4dpublicactioncache` |  | `function NewIAM4DPublicActionCache: IIAM4DPublicActionCache` | nuovo | routine |

### `DMVCMiddleware/IAMClient4D.DMVC.Middleware.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IIAM4DJWTAuthenticator` |  | `alias IAMClient4D.DMVC.Authenticator.IIAM4DJWTAuthenticator` | nuovo |  |
| `TIAM4DJWTAuthenticator` |  | `alias IAMClient4D.DMVC.Authenticator.TIAM4DJWTAuthenticator` | nuovo |  |
| `TIAM4DJWTMiddleware.Authenticator` |  | `property Authenticator: IIAM4DJWTAuthenticator read FAuthenticator` | nuovo |  |
| `TIAM4DJWTMiddleware.SetClaimsTransformer` |  | `procedure SetClaimsTransformer(const AValue: IIAM4DClaimsTransformer)` | nuovo |  |
| `TIAM4DJWTMiddlewareConfig` |  | `IAMClient4D.DMVC.Authenticator.TIAM4DJWTMiddlewareConfig` | compatibile | spostato in `DMVCMiddleware/IAMClient4D.DMVC.Authenticator.pas`, alias nella unit |
| `TIAM4DJWTMiddlewareConfig.AllowedHeaderTypes` |  | `TArray<string>` | nuovo |  |
| `TIAM4DJWTMiddlewareConfig.ClaimsTransformer` |  | `IIAM4DClaimsTransformer` | nuovo |  |
| `TIAM4DJWTMiddlewareConfig.ExpectedTokenType` |  | `string` | nuovo |  |
| `TIAM4DJWTMiddlewareConfig.operator Initialize` |  | `operator Initialize(out Dest: TIAM4DJWTMiddlewareConfig)` | nuovo |  |
| `TIAM4DJWTMiddlewareConfig.PinnedPublicKeys` |  | `TArray<string>` | nuovo |  |
| `TIAM4DJWTMiddlewareConfig.RejectedTokenWarningIntervalSec` |  | `Integer` | nuovo |  |
| `TIAM4DJWTMiddlewareConfig.SSLValidator` |  | `IIAM4DSSLCertificateValidator` | nuovo |  |

### `FMX/IAMClient4D.Androidapi.CustomTabs.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `JCustomTabsIntent` |  | `interface(JObject)` | nuovo | 1 membri: launchUrl |
| `JCustomTabsIntent_Builder` |  | `interface(JObject)` | nuovo | 2 membri: build, setShowTitle |
| `JCustomTabsIntent_BuilderClass` |  | `interface(JObjectClass)` | nuovo | 1 membri: init |
| `JCustomTabsIntentClass` |  | `interface(JObjectClass)` | nuovo | 0 membri:  |
| `TJCustomTabsIntent` |  | `class(TJavaGenericImport<JCustomTabsIntentClass, JCustomTabsIntent >)` | nuovo | 0 membri:  |
| `TJCustomTabsIntent_Builder` |  | `class(TJavaGenericImport<JCustomTabsIntent_BuilderClass, JCustomTabsIntent_Builder >)` | nuovo | 0 membri:  |

### `FMX/IAMClient4D.FMX.AppRedirect.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DAppRedirectListener` |  | `class` | nuovo | 3 membri: Install, OpenInCustomTab, Uninstall |
| `TIAM4DAppRedirectNotify` |  | `proctype reference to procedure(const AURL: string; const ATaken: Boolean)` | nuovo |  |
| `TIAM4DIOSLoginBrowser` |  | `enum (ilbSafari, ilbAuthenticationSession)` | nuovo |  |

### `IAMClient4D.Admin.Keycloak.Base.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IKeycloakAuthProvider` |  | `interface` | nuovo | 2 membri: CreateHTTPClient, GetAccessToken |
| `TClientBasedAuthProvider` |  | `class(TInterfacedObject, IKeycloakAuthProvider)` | nuovo | 3 membri: Create, CreateHTTPClient, GetAccessToken |
| `TIAM4DJSONObjectReader<T>` |  | `proctype reference to function(const AJSON: TJSONObject): T` | nuovo |  |
| `TIAM4DKeycloakAdminBase` |  | `class(TInterfacedObject)` | nuovo | 19 membri: AuthProvider, BaseURL, Create, Destroy, EncodePathSegment, EnsureResponseSuccess, ExecuteJSONArrayRequest, ExecuteJSONRequest, ExecuteJSONRequestWithLocation, ExecuteWithAuth, ExecuteWithAuthVoid, ExtractLocationID, GetAccessToken, GetAdminURL, ParseJSONArray, RaiseResponseError, Realm, RenewAuthorization, SendJSONRequest |
| `TTokenBasedAuthProvider` |  | `class(TInterfacedObject, IKeycloakAuthProvider)` | nuovo | 3 membri: Create, CreateHTTPClient, GetAccessToken |

### `IAMClient4D.Admin.Keycloak.Constants.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IAM4D_CONTENT_TYPE_JSON` |  | `'application/json'` | nuovo | const |
| `IAM4D_DEFAULT_FIRST_RESULT` |  | `0` | nuovo | const |
| `IAM4D_DEFAULT_PAGE_SIZE` |  | `100` | nuovo | const |
| `IAM4D_HTTP_METHOD_DELETE` |  | `'DELETE'` | nuovo | const |
| `IAM4D_HTTP_METHOD_GET` |  | `'GET'` | nuovo | const |
| `IAM4D_HTTP_METHOD_POST` |  | `'POST'` | nuovo | const |
| `IAM4D_HTTP_METHOD_PUT` |  | `'PUT'` | nuovo | const |
| `IAM4D_HTTP_STATUS_BAD_REQUEST` |  | `400` | nuovo | const |
| `IAM4D_HTTP_STATUS_CREATED` |  | `201` | nuovo | const |
| `IAM4D_HTTP_STATUS_NO_CONTENT` |  | `204` | nuovo | const |
| `IAM4D_HTTP_STATUS_NOT_FOUND` |  | `404` | nuovo | const |
| `IAM4D_HTTP_STATUS_OK` |  | `200` | nuovo | const |
| `IAM4D_MAX_ERROR_PREVIEW_LENGTH` |  | `500` | nuovo | const |

### `IAMClient4D.AuthorizedHTTP.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DAuthorizedHTTPClient` |  | `class` | nuovo | 12 membri: AllowInsecureHTTP, Client, Create, Delete, Destroy, Execute, Get, HTTPClient, Patch, Post, Put, RetryOnUnauthorized |

### `IAMClient4D.Callback.Handler.AppRedirect.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DAppRedirect` |  | `class` | nuovo | 2 membri: HandleURL, IsWaiting |
| `TIAM4DAppRedirectCallbackHandler` |  | `class(TIAM4DRedirectCallbackHandlerBase)` | nuovo | 6 membri: Create, DoGetRedirectURI, DoIsListening, DoStart, DoStop, IsValidRedirectURI |

### `IAMClient4D.Callback.Handler.External.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DExternalCallbackHandler.TakeContext` |  | `function TakeContext(const AState: string): TIAM4DOAuthContext` | nuovo |  |

### `IAMClient4D.Callback.Handler.Local.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DLocalCallbackHandler` | `class(TIAM4DCallbackHandlerBase)` | `class(TIAM4DRedirectCallbackHandlerBase)` | compatibile | la nuova base deriva da `TIAM4DCallbackHandlerBase` |
| `TIAM4DLocalCallbackHandler.Create` | `constructor Create(const APort: Word; const ACallbackPath: string = '/callback'); reintroduce` | `constructor Create(const APort: Word; const ACallbackPath: string = '/callback'; const AAppActivation: TIAM4DAppActivation = aaNone; const ALoopbackRedirectHost: TIAM4DLoopbackRedirectHost = lrhLocalhost); reintroduce` | compatibile | parametri opzionali in coda: le chiamate compilano |
| `TIAM4DLocalCallbackHandler.SetOnCodeReceived` | `procedure SetOnCodeReceived(const ACallback: TProc<string, string>)` | `procedure SetOnCodeReceived(const ACallback: TProc<string, string, string>)` | breaking | spostato in `TIAM4DRedirectCallbackHandlerBase`; il terzo argomento è `kc_action_status` |
| `TIAM4DLocalCallbackHandler.SetOnError` | `procedure SetOnError(const ACallback: TProc<Exception>)` |  | compatibile | spostato nella classe base |

### `IAMClient4D.Callback.Handler.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DCallbackHandlerBase.Destroy` |  | `destructor Destroy; override` | nuovo |  |
| `TIAM4DOAuthContext.AuthRequestTime` |  | `property AuthRequestTime: Int64 read FAuthRequestTime write FAuthRequestTime` | nuovo |  |
| `TIAM4DOAuthContext.CheckResponseIssuer` |  | `procedure CheckResponseIssuer(const AIss: string)` | nuovo |  |
| `TIAM4DOAuthContext.IssRequired` |  | `property IssRequired: Boolean read FIssRequired write FIssRequired` | nuovo |  |
| `TIAM4DOAuthContext.Issuer` |  | `property Issuer: string read FIssuer write FIssuer` | nuovo |  |
| `TIAM4DOAuthContext.MaxAge` |  | `property MaxAge: Integer read FMaxAge write FMaxAge` | nuovo |  |
| `TIAM4DRedirectCallbackHandlerBase` |  | `class abstract(TIAM4DCallbackHandlerBase)` | nuovo | 4 membri: CheckCallbackCanEndFlow, DispatchCallback, SetOnCodeReceived, SetOnError |

### `IAMClient4D.Common.Constants.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IAM4D_KEYCLOAK_ERROR_ACCOUNT_DISABLED` |  | `'Account disabled'` | nuovo | const |
| `IAM4D_KEYCLOAK_ERROR_ACCOUNT_NOT_FULLY_SET_UP` |  | `'Account is not fully set up'` | nuovo | const |
| `IAM4D_KEYCLOAK_ERROR_ACCOUNT_TEMPORARILY_DISABLED` |  | `'Account temporarily disabled'` | nuovo | const |
| `IAM4D_KEYCLOAK_ERROR_INVALID_USER_CREDENTIALS` |  | `'Invalid user credentials'` | nuovo | const |
| `IAM4D_KEYCLOAK_PARAM_IDP_HINT` |  | `'kc_idp_hint'` | nuovo | const |
| `IAM4D_KEYCLOAK_PARAM_KC_ACTION` |  | `'kc_action'` | nuovo | const |
| `IAM4D_KEYCLOAK_PARAM_KC_ACTION_STATUS` |  | `'kc_action_status'` | nuovo | const |
| `IAM4D_KEYCLOAK_TOKEN_TYPE_BEARER` |  | `'Bearer'` | nuovo | const |
| `IAM4D_KEYCLOAK_TOKEN_TYPE_ID` |  | `'ID'` | nuovo | const |
| `IAM4D_OAUTH2_CALLBACK_PORT_MAX` | `8020` |  | breaking | const rimossa: non era usata |
| `IAM4D_OAUTH2_CALLBACK_PORT_MIN` | `8000` |  | breaking | const rimossa: non era usata |
| `IAM4D_OAUTH2_ERROR` |  | `'error'` | nuovo | const |
| `IAM4D_OAUTH2_ERROR_DESCRIPTION` |  | `'error_description'` | nuovo | const |
| `IAM4D_OAUTH2_ERROR_INVALID_GRANT` |  | `'invalid_grant'` | nuovo | const |
| `IAM4D_OAUTH2_ERROR_UNSUPPORTED_TOKEN_TYPE` |  | `'unsupported_token_type'` | nuovo | const |
| `IAM4D_OAUTH2_GRANT_TYPE_PASSWORD` |  | `'password'` | nuovo | const |
| `IAM4D_OAUTH2_PARAM_ISS` |  | `'iss'` | nuovo | const |
| `IAM4D_OAUTH2_PARAM_MAX_AGE` |  | `'max_age'` | nuovo | const |
| `IAM4D_OAUTH2_PARAM_PASSWORD` |  | `'password'` | nuovo | const |
| `IAM4D_OAUTH2_PARAM_PROMPT` |  | `'prompt'` | nuovo | const |
| `IAM4D_OAUTH2_PARAM_TOKEN` |  | `'token'` | nuovo | const |
| `IAM4D_OAUTH2_PARAM_TOKEN_TYPE_HINT` |  | `'token_type_hint'` | nuovo | const |
| `IAM4D_OAUTH2_PARAM_UI_LOCALES` |  | `'ui_locales'` | nuovo | const |
| `IAM4D_OAUTH2_PARAM_USERNAME` |  | `'username'` | nuovo | const |
| `IAM4D_OAUTH2_TOKEN_TYPE_HINT_ACCESS_TOKEN` |  | `'access_token'` | nuovo | const |
| `IAM4D_OAUTH2_TOKEN_TYPE_HINT_REFRESH_TOKEN` |  | `'refresh_token'` | nuovo | const |
| `IAM4D_OIDC_METADATA_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED` |  | `'authorization_response_iss_parameter_supported'` | nuovo | const |
| `IAM4D_OIDC_METADATA_REVOCATION_ENDPOINT` |  | `'revocation_endpoint'` | nuovo | const |
| `IAM4D_VERSION` |  | `'3.0.0'` | nuovo | const |
| `IAM4D_VERSION_MAJOR` |  | `3` | nuovo | const |
| `IAM4D_VERSION_MINOR` |  | `0` | nuovo | const |
| `IAM4D_VERSION_PATCH` |  | `0` | nuovo | const |

### `IAMClient4D.Common.OAuth2URLParser.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DOAuth2CallbackResult.Iss` |  | `string` | nuovo |  |
| `TIAM4DOAuth2CallbackResult.KeycloakActionStatus` |  | `string` | nuovo |  |
| `TIAM4DOAuth2URLParser.CreateErrorException` |  | `function CreateErrorException(const AResult: TIAM4DOAuth2CallbackResult): EIAM4DOAuth2CallbackException; static` | nuovo |  |

### `IAMClient4D.Common.PlatformUtils.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DOpenURLHandler` |  | `proctype reference to function(const AURL: string): Boolean` | nuovo |  |
| `TIAM4DPlatformUtils.ActivateApplication` |  | `procedure ActivateApplication(const AMode: TIAM4DAppActivation)` | nuovo |  |
| `TIAM4DPlatformUtils.OpenURLHandler` |  | `property OpenURLHandler: TIAM4DOpenURLHandler read GetOpenURLHandler write SetOpenURLHandler` | nuovo |  |

### `IAMClient4D.Common.SecureMemory.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `securezerostrings` |  | `procedure SecureZeroStrings(const AStrings: TStrings)` | nuovo | routine |

### `IAMClient4D.Common.Security.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IIAM4DSSLCertificateValidator.HasPinnedPublicKeys` |  | `function HasPinnedPublicKeys: Boolean` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DSSLCertificateValidator.ValidateCertificate` | `function ValidateCertificate(const Certificate: TCertificate): Boolean` | `function ValidateCertificate(const Certificate: TCertificate; ASystemAccepted: Boolean): Boolean` | breaking | parametro nuovo `ASystemAccepted`: chi implementa e chi chiama |
| `TIAM4DCertificateRejectionReason` | `enum (crrNone, crrEmptySubject, crrNotYetValid, crrExpired, crrPublicKeyPinningFailed, crrStrictModeBypass, crrUnknown)` | `enum (crrNone, crrEmptySubject, crrNotYetValid, crrExpired, crrPublicKeyPinningFailed, crrSystemValidationFailed, crrUnknown)` | breaking | `crrStrictModeBypass` → `crrSystemValidationFailed`, stesso ordinale |
| `TIAM4DSSLCertificateValidator.HasPinnedPublicKeys` |  | `function HasPinnedPublicKeys: Boolean` | nuovo |  |
| `TIAM4DSSLCertificateValidator.ValidateCertificate` | `function ValidateCertificate(const Certificate: TCertificate): Boolean` | `function ValidateCertificate(const Certificate: TCertificate; ASystemAccepted: Boolean): Boolean` | breaking | parametro nuovo `ASystemAccepted` |

### `IAMClient4D.Common.TokenValidator.pas` (rimossa)

Unit rimossa nella 3.0.

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DTokenValidator` | `class` |  | breaking | unit rimossa: controlli di scadenza in `IIAM4DTokenStorage` (sezione 7.1) |
| `IAM4D_DEFAULT_TOKEN_EXPIRATION_BUFFER_SECONDS` | `10` |  | breaking | unit rimossa |

### `IAMClient4D.Config.Builder.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IIAM4DClientConfigBuilder.ForAuthorizationCode` | `function ForAuthorizationCode(const ABaseURL, ARealm, AClientID: string): IIAM4DClientConfigBuilder` | `function ForAuthorizationCode(const ABaseURL, ARealm, AClientID: string; const AClientSecret: string = ''): IIAM4DClientConfigBuilder` | breaking (impl.) | parametri opzionali in coda: le chiamate compilano |
| `IIAM4DClientConfigBuilder.ForPassword` |  | `function ForPassword(const ABaseURL, ARealm, AClientID: string; const AClientSecret: string = ''): IIAM4DClientConfigBuilder` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClientConfigBuilder.WithAllowInsecureHTTP` |  | `function WithAllowInsecureHTTP(const AValue: Boolean = True): IIAM4DClientConfigBuilder` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClientConfigBuilder.WithAppActivation` |  | `function WithAppActivation(const AValue: TIAM4DAppActivation): IIAM4DClientConfigBuilder` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClientConfigBuilder.WithAppRedirect` |  | `function WithAppRedirect(const ARedirectURI: string): IIAM4DClientConfigBuilder` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClientConfigBuilder.WithCallbackPort` |  | `function WithCallbackPort(const APort: Integer): IIAM4DClientConfigBuilder` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClientConfigBuilder.WithIdentityProvider` |  | `function WithIdentityProvider(const AAlias: string): IIAM4DClientConfigBuilder` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClientConfigBuilder.WithKeycloakAction` |  | `function WithKeycloakAction(const AAction: string): IIAM4DClientConfigBuilder` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClientConfigBuilder.WithLoopbackRedirectHost` |  | `function WithLoopbackRedirectHost(const AValue: TIAM4DLoopbackRedirectHost): IIAM4DClientConfigBuilder` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClientConfigBuilder.WithMaxAge` |  | `function WithMaxAge(const ASeconds: Integer): IIAM4DClientConfigBuilder` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClientConfigBuilder.WithPrompt` |  | `function WithPrompt(const APrompt: string): IIAM4DClientConfigBuilder` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `TIAM4DClientConfigBuilder.ForAuthorizationCode` | `function ForAuthorizationCode(const ABaseURL, ARealm, AClientID: string): IIAM4DClientConfigBuilder` | `function ForAuthorizationCode(const ABaseURL, ARealm, AClientID: string; const AClientSecret: string = ''): IIAM4DClientConfigBuilder` | compatibile | parametri opzionali in coda: le chiamate compilano |
| `TIAM4DClientConfigBuilder.ForPassword` |  | `function ForPassword(const ABaseURL, ARealm, AClientID: string; const AClientSecret: string = ''): IIAM4DClientConfigBuilder` | nuovo |  |
| `TIAM4DClientConfigBuilder.WithAllowInsecureHTTP` |  | `function WithAllowInsecureHTTP(const AValue: Boolean = True): IIAM4DClientConfigBuilder` | nuovo |  |
| `TIAM4DClientConfigBuilder.WithAppActivation` |  | `function WithAppActivation(const AValue: TIAM4DAppActivation): IIAM4DClientConfigBuilder` | nuovo |  |
| `TIAM4DClientConfigBuilder.WithAppRedirect` |  | `function WithAppRedirect(const ARedirectURI: string): IIAM4DClientConfigBuilder` | nuovo |  |
| `TIAM4DClientConfigBuilder.WithCallbackPort` |  | `function WithCallbackPort(const APort: Integer): IIAM4DClientConfigBuilder` | nuovo |  |
| `TIAM4DClientConfigBuilder.WithIdentityProvider` |  | `function WithIdentityProvider(const AAlias: string): IIAM4DClientConfigBuilder` | nuovo |  |
| `TIAM4DClientConfigBuilder.WithKeycloakAction` |  | `function WithKeycloakAction(const AAction: string): IIAM4DClientConfigBuilder` | nuovo |  |
| `TIAM4DClientConfigBuilder.WithLoopbackRedirectHost` |  | `function WithLoopbackRedirectHost(const AValue: TIAM4DLoopbackRedirectHost): IIAM4DClientConfigBuilder` | nuovo |  |
| `TIAM4DClientConfigBuilder.WithMaxAge` |  | `function WithMaxAge(const ASeconds: Integer): IIAM4DClientConfigBuilder` | nuovo |  |
| `TIAM4DClientConfigBuilder.WithPrompt` |  | `function WithPrompt(const APrompt: string): IIAM4DClientConfigBuilder` | nuovo |  |

### `IAMClient4D.Core.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IIAM4DClient.AuthenticatePassword` |  | `function AuthenticatePassword(const AUserName, APassword: string): string` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClient.AuthenticatePasswordAsync` |  | `function AuthenticatePasswordAsync(const AUserName, APassword: string): IAsyncPromise<string>` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClient.CompleteAuthorizationFlow` | `function CompleteAuthorizationFlow(const ACode, AState: string): string` | `function CompleteAuthorizationFlow(const ACode, AState: string; const AIss: string = ''): string` | breaking (impl.) | parametri opzionali in coda: le chiamate compilano |
| `IIAM4DClient.CompleteAuthorizationFlowAsync` | `function CompleteAuthorizationFlowAsync(const ACode, AState: string): IAsyncPromise<string>` | `function CompleteAuthorizationFlowAsync(const ACode, AState: string; const AIss: string = ''): IAsyncPromise<string>` | breaking (impl.) | parametri opzionali in coda: le chiamate compilano |
| `IIAM4DClient.GenerateAuthURL` | `function GenerateAuthURL(const ALoginHint: string = ''): string` | `function GenerateAuthURL(const ALoginHint: string = ''; const AIdpHint: string = ''): string; overload`<br>`function GenerateAuthURL(const AOptions: TIAM4DAuthRequestOptions): string; overload` | breaking (impl.) | parametri opzionali in coda e overload nuovi: le chiamate compilano |
| `IIAM4DClient.GenerateLogoutURL` |  | `function GenerateLogoutURL(const APostLogoutRedirectURI: string = ''; const AState: string = ''): string` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClient.GetGrantedScopes` |  | `function GetGrantedScopes: TArray<string>` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClient.GetIDTokenClaims` |  | `function GetIDTokenClaims: TIAM4DIDTokenClaims` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClient.GetKeycloakActionStatus` |  | `function GetKeycloakActionStatus: string` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClient.HasGrantedScope` |  | `function HasGrantedScope(const AScope: string): Boolean` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClient.InitializeAuthorizationFlow` |  | `procedure InitializeAuthorizationFlow(const AOptions: TIAM4DAuthRequestOptions); overload` | breaking (impl.) | overload nuovo |
| `IIAM4DClient.InvalidateAccessToken` |  | `procedure InvalidateAccessToken(const AAccessToken: string)` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClient.KeycloakActionStatus` |  | `property KeycloakActionStatus: string read GetKeycloakActionStatus` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClient.RevokeTokens` |  | `procedure RevokeTokens` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClient.RevokeTokensAsync` |  | `function RevokeTokensAsync: IAsyncVoidPromise` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DClient.StartAuthorizationFlowAsync` | `function StartAuthorizationFlowAsync: IAsyncPromise<string>` | `function StartAuthorizationFlowAsync(const AIdpHint: string = ''): IAsyncPromise<string>; overload`<br>`function StartAuthorizationFlowAsync(const AIdpHint, ALoginHint: string): IAsyncPromise<string>; overload`<br>`function StartAuthorizationFlowAsync(const AOptions: TIAM4DAuthRequestOptions): IAsyncPromise<string>; overload` | breaking (impl.) | parametro opzionale e overload nuovi: le chiamate compilano |
| `TIAM4DAppActivation` |  | `enum (aaNone, aaFlash, aaForeground)` | nuovo |  |
| `TIAM4DAuthRequestOptions` |  | `record` | nuovo | 18 membri: AcrValues, Create, IdpHint, IsReservedParameter, LoginHint, MaxAge, ParameterNames, ParameterValues, Prompt, UILocales, WithAcrValues, WithIdpHint, WithLoginHint, WithMaxAge, WithParameter, WithPrompt, WithUILocales, operator Initialize |
| `TIAM4DCallbackMode` | `enum (cbmLocalServer, cbmExternal)` | `enum (cbmLocalServer, cbmExternal, cbmAppRedirect)` | nuovo | valori aggiunti in coda: ordinali invariati |
| `TIAM4DClientConfig.AllowInsecureHTTP` |  | `property AllowInsecureHTTP: Boolean read FAllowInsecureHTTP` | nuovo |  |
| `TIAM4DClientConfig.AppActivation` |  | `property AppActivation: TIAM4DAppActivation read FAppActivation` | nuovo |  |
| `TIAM4DClientConfig.CallbackPort` |  | `property CallbackPort: Integer read FCallbackPort` | nuovo |  |
| `TIAM4DClientConfig.Create` | `function Create(const ABaseURL, ARealm, AClientID: string; const AGrantType: TIAM4DGrantType = TIAM4DGrantType.gtAuthorizationCode; const AScopes: TArray<string> = nil; const AClientSecret: string = ''; const ASSLValidationMode: TIAM4DSSLValidationMode = TIAM4 …` | `function Create(const ABaseURL, ARealm, AClientID: string; const AGrantType: TIAM4DGrantType = TIAM4DGrantType.gtAuthorizationCode; const AScopes: TArray<string> = nil; const AClientSecret: string = ''; const ASSLValidationMode: TIAM4DSSLValidationMode = TIAM4 …` | compatibile | parametri opzionali in coda: le chiamate compilano |
| `TIAM4DClientConfig.CreateForAuthorizationCode` | `function CreateForAuthorizationCode(const ABaseURL, ARealm, AClientID: string; const AScopes: TArray<string> = nil; const ASSLValidationMode: TIAM4DSSLValidationMode = TIAM4DSSLValidationMode.svmStrict; const AConnectionTimeout: Integer = 30000; const ARespons …` | `function CreateForAuthorizationCode(const ABaseURL, ARealm, AClientID: string; const AScopes: TArray<string> = nil; const ASSLValidationMode: TIAM4DSSLValidationMode = TIAM4DSSLValidationMode.svmStrict; const AConnectionTimeout: Integer = 30000; const ARespons …` | compatibile | parametri opzionali in coda: le chiamate compilano |
| `TIAM4DClientConfig.CreateForPassword` |  | `function CreateForPassword(const ABaseURL, ARealm, AClientID: string; const AClientSecret: string = ''; const AScopes: TArray<string> = nil; const ASSLValidationMode: TIAM4DSSLValidationMode = TIAM4DSSLValidationMode.svmStrict; const AConnectionTimeout: Intege …` | nuovo |  |
| `TIAM4DClientConfig.IdpHint` |  | `property IdpHint: string read FIdpHint` | nuovo |  |
| `TIAM4DClientConfig.IsInsecureHTTPURL` |  | `function IsInsecureHTTPURL(const AURL: string): Boolean; static` | nuovo |  |
| `TIAM4DClientConfig.KeycloakAction` |  | `property KeycloakAction: string read FKeycloakAction` | nuovo |  |
| `TIAM4DClientConfig.LoopbackRedirectHost` |  | `property LoopbackRedirectHost: TIAM4DLoopbackRedirectHost read FLoopbackRedirectHost` | nuovo |  |
| `TIAM4DClientConfig.MaxAge` |  | `property MaxAge: Integer read FMaxAge` | nuovo |  |
| `TIAM4DClientConfig.Prompt` |  | `property Prompt: string read FPrompt` | nuovo |  |
| `TIAM4DClientConfig.WithAllowInsecureHTTP` |  | `function WithAllowInsecureHTTP(const AValue: Boolean): TIAM4DClientConfig` | nuovo |  |
| `TIAM4DClientConfig.WithAppActivation` |  | `function WithAppActivation(const AValue: TIAM4DAppActivation): TIAM4DClientConfig` | nuovo |  |
| `TIAM4DClientConfig.WithAuthRequestOptions` |  | `function WithAuthRequestOptions(const APrompt: string; const AMaxAge: Integer): TIAM4DClientConfig` | nuovo |  |
| `TIAM4DClientConfig.WithCallbackPort` |  | `function WithCallbackPort(const APort: Integer): TIAM4DClientConfig` | nuovo |  |
| `TIAM4DClientConfig.WithKeycloakAction` |  | `function WithKeycloakAction(const AAction: string): TIAM4DClientConfig` | nuovo |  |
| `TIAM4DClientConfig.WithLoopbackRedirectHost` |  | `function WithLoopbackRedirectHost(const AValue: TIAM4DLoopbackRedirectHost): TIAM4DClientConfig` | nuovo |  |
| `TIAM4DGrantType` | `enum (gtUnknown, gtAuthorizationCode, gtClientCredentials)` | `enum (gtUnknown, gtAuthorizationCode, gtClientCredentials, gtPassword)` | nuovo | valori aggiunti in coda: ordinali invariati |
| `TIAM4DHTTPClientFactory.Execute` |  | `function Execute(const AClient: THTTPClient; const AMethod, AURL: string; const ASource: TStream = nil; const AHeaders: TNetHeaders = nil): IHTTPResponse; static` | nuovo |  |
| `TIAM4DHTTPClientSSLHelper.IsCallbackNeeded` |  | `function IsCallbackNeeded(AMode: TIAM4DSSLValidationMode; const AValidator: IIAM4DSSLCertificateValidator): Boolean; static` | nuovo |  |
| `TIAM4DHTTPClientSSLHelper.KeepPlatformVerdict` |  | `procedure KeepPlatformVerdict(const Sender: TObject; const ARequest: TURLRequest; const Certificate: TCertificate; var Accepted: Boolean)` | nuovo |  |
| `TIAM4DHTTPClientSSLHelper.SSLValidator` |  | `property SSLValidator: IIAM4DSSLCertificateValidator read FSSLValidator` | nuovo |  |
| `TIAM4DIDTokenClaims` |  | `record` | nuovo | 18 membri: Acr, Amr, Audience, AuthTime, AuthorizedParty, Email, ExpiresAt, FromIDToken, GetClaim, HasClaim, IsEmpty, IssuedAt, Issuer, JSON, Name, PreferredUsername, SessionID, Subject |
| `TIAM4DLoopbackRedirectHost` |  | `enum (lrhLocalhost, lrhLoopbackIP)` | nuovo |  |
| `TIAM4DTokens.Scope` |  | `property Scope: string read FScope write FScope` | nuovo |  |
| `TIAM4DWellKnownEndpoints.AuthorizationResponseIssParameterSupported` |  | `Boolean` | nuovo |  |
| `TIAM4DWellKnownEndpoints.RevocationEndpoint` |  | `string` | nuovo |  |
| `IAM4D_AUTH_TIME_CLOCK_SKEW_SECONDS` |  | `300` | nuovo | const |
| `IAM4D_IDP_HINT_NONE` |  | `'/none'` | nuovo | const |
| `IAM4D_KC_ACTION_STATUS_CANCELLED` |  | `'cancelled'` | nuovo | const |
| `IAM4D_KC_ACTION_STATUS_ERROR` |  | `'error'` | nuovo | const |
| `IAM4D_KC_ACTION_STATUS_SUCCESS` |  | `'success'` | nuovo | const |
| `IAM4D_KC_ACTION_UPDATE_PASSWORD` |  | `'UPDATE_PASSWORD'` | nuovo | const |
| `IAM4D_MAX_AGE_CONFIGURED` |  | `- 2` | nuovo | const |
| `IAM4D_MAX_AGE_NONE` |  | `- 1` | nuovo | const |
| `IAM4D_PROMPT_CONSENT` |  | `'consent'` | nuovo | const |
| `IAM4D_PROMPT_LOGIN` |  | `'login'` | nuovo | const |
| `IAM4D_PROMPT_NONE` |  | `'none'` | nuovo | const |
| `IAM4D_PROMPT_SELECT_ACCOUNT` |  | `'select_account'` | nuovo | const |

### `IAMClient4D.Crypto.TaurusTLS.Common.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `EIAM4DOpenSSLException` |  | `class(EIAM4DException)` | nuovo | 1 membri: Create |
| `TIAM4DOpenSSL` |  | `class sealed` | nuovo | 5 membri: EnsureLoaded, LastErrorMessage, LibraryPath, VersionNumber, VersionText |
| `IAM4D_OPENSSL_MIN_VERSION` |  | `$30000000` | nuovo | const |

### `IAMClient4D.Discovery.Cache.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DDiscoveryCache` |  | `class sealed` | nuovo | 8 membri: Clear, Count, DEFAULT_TIME_TO_LIVE_SECONDS, Enabled, KeyOf, Put, TimeToLiveSeconds, TryGet |

### `IAMClient4D.Exceptions.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `EIAM4DAccountDisabledException` |  | `class(EIAM4DException)` | nuovo | 1 membri: Create |
| `EIAM4DAccountNotFullySetUpException` |  | `class(EIAM4DException)` | nuovo | 1 membri: Create |
| `EIAM4DException.Clone` |  | `function Clone: EIAM4DException` | nuovo |  |
| `EIAM4DException.CreateCopy` |  | `constructor CreateCopy(ASource: EIAM4DException); virtual` | nuovo |  |
| `EIAM4DExceptionClass` |  | `alias class of EIAM4DException` | nuovo |  |
| `EIAM4DGroupNotFoundException` | `class(EIAM4DException)` | `class(EIAM4DHTTPNotFoundException)` | comportamento | antenato cambiato: conta l'ordine dei blocchi `except` |
| `EIAM4DHTTPClientErrorException.CreateCopy` |  | `constructor CreateCopy(ASource: EIAM4DException); override` | nuovo |  |
| `EIAM4DHTTPClientErrorException.CreateFromResponse` |  | `constructor CreateFromResponse(AStatusCode: Integer; const AResponseBody, AMessage: string); virtual` | nuovo |  |
| `EIAM4DHTTPClientErrorExceptionClass` |  | `alias class of EIAM4DHTTPClientErrorException` | nuovo |  |
| `EIAM4DHTTPConflictException` |  | `class(EIAM4DHTTPClientErrorException)` | nuovo | 0 membri:  |
| `EIAM4DHTTPNotFoundException` |  | `class(EIAM4DHTTPClientErrorException)` | nuovo | 0 membri:  |
| `EIAM4DHTTPServerErrorException.CreateCopy` |  | `constructor CreateCopy(ASource: EIAM4DException); override` | nuovo |  |
| `EIAM4DHTTPServerErrorException.CreateFromResponse` |  | `constructor CreateFromResponse(AStatusCode: Integer; const AResponseBody, AMessage: string; ARetryAfterSeconds: Integer = 0)` | nuovo |  |
| `EIAM4DHTTPServerErrorException.ResponseBody` |  | `property ResponseBody: string read FResponseBody` | nuovo |  |
| `EIAM4DInsufficientPermissionsException` | `class(EIAM4DException)` | `class(EIAM4DHTTPClientErrorException)` | comportamento | antenato cambiato: conta l'ordine dei blocchi `except` |
| `EIAM4DInsufficientPermissionsException.CreateCopy` |  | `constructor CreateCopy(ASource: EIAM4DException); override` | nuovo |  |
| `EIAM4DInsufficientPermissionsException.CreateFromResponse` |  | `constructor CreateFromResponse(AStatusCode: Integer; const AResponseBody, AMessage: string); override` | nuovo |  |
| `EIAM4DJWTSignatureInvalidException.Create` |  | `constructor Create(const AKeyID, AAlgorithm: string); overload` | nuovo | overload nuovo |
| `EIAM4DNetworkTimeoutException.CreateCopy` |  | `constructor CreateCopy(ASource: EIAM4DException); override` | nuovo |  |
| `EIAM4DNetworkUnreachableException.Create` |  | `constructor Create(const AHost, ADetail: string); overload` | nuovo | overload nuovo |
| `EIAM4DRoleNotFoundException` | `class(EIAM4DException)` | `class(EIAM4DHTTPNotFoundException)` | comportamento | antenato cambiato: conta l'ordine dei blocchi `except` |
| `EIAM4DRoleNotFoundException.Create` |  | `constructor Create(const ARoleName, AClientID: string); overload` | nuovo | overload nuovo |
| `EIAM4DSSLCertificateException.CreateCopy` |  | `constructor CreateCopy(ASource: EIAM4DException); override` | nuovo |  |
| `EIAM4DUnknownRequiredActionException.CreateCopy` |  | `constructor CreateCopy(ASource: EIAM4DException); override` | nuovo |  |
| `EIAM4DUserAlreadyExistsException` | `class(EIAM4DException)` | `class(EIAM4DHTTPConflictException)` | comportamento | antenato cambiato: conta l'ordine dei blocchi `except` |
| `EIAM4DUserAlreadyExistsException.CreateCopy` |  | `constructor CreateCopy(ASource: EIAM4DException); override` | nuovo |  |
| `EIAM4DUserAlreadyExistsException.CreateFromConflict` |  | `constructor CreateFromConflict(AConflict: EIAM4DHTTPClientErrorException; const AUsername, AEmail: string)` | nuovo |  |
| `EIAM4DUserNotFoundException` | `class(EIAM4DException)` | `class(EIAM4DHTTPNotFoundException)` | comportamento | antenato cambiato: conta l'ordine dei blocchi `except` |
| `EIAM4DUserNotFoundException.CreateCopy` |  | `constructor CreateCopy(ASource: EIAM4DException); override` | nuovo |  |
| `TIAM4DErrorCode` | `enum (ecUnknown = 0, ecAccessTokenExpired = 1001, ecRefreshTokenExpired = 1002, ecTokenInvalid = 1003, ecInvalidCredentials = 1010, ecInvalidAuthorizationCode = 1020, ecPKCEValidationFailed = 1021, ecStateMismatch = 1022, ecAuthorizationCancelled = 1030, ecAut …` | `enum (ecUnknown = 0, ecAccessTokenExpired = 1001, ecRefreshTokenExpired = 1002, ecTokenInvalid = 1003, ecInvalidCredentials = 1010, ecAccountNotFullySetUp = 1011, ecAccountDisabled = 1012, ecInvalidAuthorizationCode = 1020, ecPKCEValidationFailed = 1021, ecSta …` | nuovo | valori aggiunti (ordinali spostati) |

### `IAMClient4D.IdentityProvider.Builders.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IIAM4DCieIdPBuilder` |  | `interface` | nuovo | 16 membri: Build, WithAttributeConsumingService, WithConfig, WithDisplayName, WithEnvironment, WithFirstBrokerLoginFlow, WithHideOnLogin, WithImportedConfig, WithLevel, WithOrganization, WithPrivateServiceProvider, WithPublicServiceProvider, WithServiceProviderEntityID, WithSyncMode, WithTechnicalContact, WithTrustEmail |
| `IIAM4DEntraIdPBuilder` |  | `interface` | nuovo | 11 membri: Build, WithClient, WithConfig, WithDisplayName, WithFirstBrokerLoginFlow, WithHideOnLogin, WithPrompt, WithScopes, WithSyncMode, WithTenant, WithTrustEmail |
| `IIAM4DFacebookIdPBuilder` |  | `interface` | nuovo | 10 membri: Build, WithClient, WithConfig, WithDisplayName, WithFetchedFields, WithFirstBrokerLoginFlow, WithHideOnLogin, WithScopes, WithSyncMode, WithTrustEmail |
| `IIAM4DGitHubIdPBuilder` |  | `interface` | nuovo | 9 membri: Build, WithClient, WithConfig, WithDisplayName, WithEnterprise, WithFirstBrokerLoginFlow, WithHideOnLogin, WithScopes, WithSyncMode |
| `IIAM4DGitLabIdPBuilder` |  | `interface` | nuovo | 9 membri: Build, WithClient, WithConfig, WithDisplayName, WithFirstBrokerLoginFlow, WithHideOnLogin, WithScopes, WithSyncMode, WithTrustEmail |
| `IIAM4DGoogleIdPBuilder` |  | `interface` | nuovo | 11 membri: Build, WithClient, WithConfig, WithDisplayName, WithFirstBrokerLoginFlow, WithHideOnLogin, WithHostedDomains, WithPrompt, WithScopes, WithSyncMode, WithTrustEmail |
| `IIAM4DLinkedInIdPBuilder` |  | `interface` | nuovo | 9 membri: Build, WithClient, WithConfig, WithDisplayName, WithFirstBrokerLoginFlow, WithHideOnLogin, WithScopes, WithSyncMode, WithTrustEmail |
| `IIAM4DMicrosoftIdPBuilder` |  | `interface` | nuovo | 11 membri: Build, WithClient, WithConfig, WithDisplayName, WithFirstBrokerLoginFlow, WithHideOnLogin, WithPrompt, WithScopes, WithSyncMode, WithTenant, WithTrustEmail |
| `IIAM4DOAuth2IdPBuilder` |  | `interface` | nuovo | 16 membri: Build, DisablePkce, WithClient, WithClientAuthMethod, WithConfig, WithDisplayName, WithEndpoints, WithFirstBrokerLoginFlow, WithHideOnLogin, WithImportedConfig, WithNameClaims, WithPrompt, WithScopes, WithSyncMode, WithTrustEmail, WithUserProfileClaims |
| `IIAM4DOidcIdPBuilder` |  | `interface` | nuovo | 18 membri: Build, DisableIssuerCheck, DisablePkce, DisableSignatureValidation, WithClient, WithClientAuthMethod, WithConfig, WithDisplayName, WithEndpoints, WithFirstBrokerLoginFlow, WithHideOnLogin, WithImportedConfig, WithIssuer, WithJwksURL, WithPrompt, WithScopes, WithSyncMode, WithTrustEmail |
| `IIAM4DSamlIdPBuilder` |  | `interface` | nuovo | 16 membri: AllowUnsignedAssertions, Build, DisableRequestSigning, DisableSignatureValidation, WithConfig, WithDisplayName, WithFirstBrokerLoginFlow, WithHideOnLogin, WithIdentityProviderEndpoints, WithImportedConfig, WithMetadataURL, WithNameIDFormat, WithPrincipal, WithServiceProviderEntityID, WithSyncMode, WithTrustEmail |
| `IIAM4DSpidIdPBuilder` |  | `interface` | nuovo | 17 membri: Build, WithAttributeConsumingService, WithBillingContact, WithConfig, WithDisplayName, WithFirstBrokerLoginFlow, WithHideOnLogin, WithIdentityProviderEndpoints, WithImportedConfig, WithLevel, WithMetadataURL, WithOrganization, WithPrivateServiceProvider, WithPublicServiceProvider, WithServiceProviderEntityID, WithSyncMode, WithTrustEmail |
| `TIAM4DCieEnvironment` |  | `enum (ceProduction, cePreProduction)` | nuovo |  |
| `TIAM4DCieIdPBuilder` |  | `class(TIAM4DItalianSamlIdPBuilder<IIAM4DCieIdPBuilder >, IIAM4DCieIdPBuilder)` | nuovo | 11 membri: ApplyImportedConfig, AttributeMapper, Build, Builder, MetadataURL, New, ServiceProviderMetadataURL, WithEnvironment, WithPrivateServiceProvider, WithPublicServiceProvider, WithTechnicalContact |
| `TIAM4DEntraIdPBuilder` |  | `class(TIAM4DOidcIdPBuilderCommon<IIAM4DEntraIdPBuilder >, IIAM4DEntraIdPBuilder)` | nuovo | 4 membri: Build, Builder, New, WithTenant |
| `TIAM4DFacebookIdPBuilder` |  | `class(TIAM4DOidcIdPBuilderCommon<IIAM4DFacebookIdPBuilder >, IIAM4DFacebookIdPBuilder)` | nuovo | 5 membri: AttributeMapper, Build, Builder, New, WithFetchedFields |
| `TIAM4DGitHubIdPBuilder` |  | `class(TIAM4DOidcIdPBuilderCommon<IIAM4DGitHubIdPBuilder >, IIAM4DGitHubIdPBuilder)` | nuovo | 5 membri: AttributeMapper, Build, Builder, New, WithEnterprise |
| `TIAM4DGitLabIdPBuilder` |  | `class(TIAM4DOidcIdPBuilderCommon<IIAM4DGitLabIdPBuilder >, IIAM4DGitLabIdPBuilder)` | nuovo | 3 membri: Build, Builder, New |
| `TIAM4DGoogleIdPBuilder` |  | `class(TIAM4DOidcIdPBuilderCommon<IIAM4DGoogleIdPBuilder >, IIAM4DGoogleIdPBuilder)` | nuovo | 5 membri: AttributeMapper, Build, Builder, New, WithHostedDomains |
| `TIAM4DItalianSamlIdPBuilder<I:IInterface>` |  | `class(TIAM4DItalianSamlIdPBuilderBase)` | nuovo | 12 membri: Builder, WithAttributeConsumingService, WithConfig, WithDisplayName, WithFirstBrokerLoginFlow, WithHideOnLogin, WithImportedConfig, WithLevel, WithOrganization, WithServiceProviderEntityID, WithSyncMode, WithTrustEmail |
| `TIAM4DItalianSamlIdPBuilderBase` |  | `class(TIAM4DSamlIdPBuilderBase)` | nuovo | 7 membri: ApplyImportedConfig, BuildIdentityProvider, Initialize, LocalizedValue, SetAttributeConsumingService, SetLevel, SetOrganization |
| `TIAM4DLinkedInIdPBuilder` |  | `class(TIAM4DOidcIdPBuilderCommon<IIAM4DLinkedInIdPBuilder >, IIAM4DLinkedInIdPBuilder)` | nuovo | 4 membri: AttributeMapper, Build, Builder, New |
| `TIAM4DMicrosoftIdPBuilder` |  | `class(TIAM4DOidcIdPBuilderCommon<IIAM4DMicrosoftIdPBuilder >, IIAM4DMicrosoftIdPBuilder)` | nuovo | 5 membri: AttributeMapper, Build, Builder, New, WithTenant |
| `TIAM4DOAuth2IdPBuilder` |  | `class(TIAM4DOidcIdPBuilderCommon<IIAM4DOAuth2IdPBuilder >, IIAM4DOAuth2IdPBuilder)` | nuovo | 9 membri: Build, Builder, DisablePkce, New, WithClientAuthMethod, WithEndpoints, WithImportedConfig, WithNameClaims, WithUserProfileClaims |
| `TIAM4DOidcClientAuthMethod` |  | `enum (ocaClientSecretPost, ocaClientSecretBasic, ocaPrivateKeyJwt, ocaClientSecretJwt)` | nuovo |  |
| `TIAM4DOidcIdPBuilder` |  | `class(TIAM4DOidcIdPBuilderCommon<IIAM4DOidcIdPBuilder >, IIAM4DOidcIdPBuilder)` | nuovo | 11 membri: Build, Builder, DisableIssuerCheck, DisablePkce, DisableSignatureValidation, New, WithClientAuthMethod, WithEndpoints, WithImportedConfig, WithIssuer, WithJwksURL |
| `TIAM4DOidcIdPBuilderBase` |  | `class(TInterfacedObject)` | nuovo | 7 membri: BuildIdentityProvider, BuildSocialIdentityProvider, CheckClient, Initialize, InitializeSocial, SetClient, SetClientAuthMethod |
| `TIAM4DOidcIdPBuilderCommon<I:IInterface>` |  | `class(TIAM4DOidcIdPBuilderBase)` | nuovo | 10 membri: Builder, WithClient, WithConfig, WithDisplayName, WithFirstBrokerLoginFlow, WithHideOnLogin, WithPrompt, WithScopes, WithSyncMode, WithTrustEmail |
| `TIAM4DSamlIdPBuilder` |  | `class(TIAM4DSamlIdPBuilderBase, IIAM4DSamlIdPBuilder)` | nuovo | 18 membri: AllowUnsignedAssertions, AttributeMapper, Build, DisableRequestSigning, DisableSignatureValidation, New, WithConfig, WithDisplayName, WithFirstBrokerLoginFlow, WithHideOnLogin, WithIdentityProviderEndpoints, WithImportedConfig, WithMetadataURL, WithNameIDFormat, WithPrincipal, WithServiceProviderEntityID, WithSyncMode, WithTrustEmail |
| `TIAM4DSamlIdPBuilderBase` |  | `class(TInterfacedObject)` | nuovo | 4 membri: CheckIdentityProvider, SetIdentityProviderEndpoints, SetImportedConfig, SetMetadataURL |
| `TIAM4DSamlPrincipalType` |  | `enum (sptSubject, sptAttribute, sptFriendlyAttribute)` | nuovo |  |
| `TIAM4DSpidIdPBuilder` |  | `class(TIAM4DItalianSamlIdPBuilder<IIAM4DSpidIdPBuilder >, IIAM4DSpidIdPBuilder)` | nuovo | 10 membri: AttributeMapper, Build, Builder, New, ServiceProviderMetadataURL, WithBillingContact, WithIdentityProviderEndpoints, WithMetadataURL, WithPrivateServiceProvider, WithPublicServiceProvider |
| `TIAM4DSpidLevel` |  | `enum (slL1, slL2, slL3)` | nuovo |  |
| `TIAM4DSpidLevelHelper` |  | `record helper for TIAM4DSpidLevel` | nuovo | 1 membri: ToURI |
| `IAM4D_IDP_ALIAS_CIE` |  | `'cie'` | nuovo | const |
| `IAM4D_IDP_ALIAS_ENTRA` |  | `'entra'` | nuovo | const |
| `IAM4D_IDP_ALIAS_FACEBOOK` |  | `'facebook'` | nuovo | const |
| `IAM4D_IDP_ALIAS_GITHUB` |  | `'github'` | nuovo | const |
| `IAM4D_IDP_ALIAS_GITLAB` |  | `'gitlab'` | nuovo | const |
| `IAM4D_IDP_ALIAS_GOOGLE` |  | `'google'` | nuovo | const |
| `IAM4D_IDP_ALIAS_LINKEDIN` |  | `'linkedin'` | nuovo | const |
| `IAM4D_IDP_ALIAS_MICROSOFT` |  | `'microsoft'` | nuovo | const |
| `IAM4D_IDP_MAPPER_CIE_ATTRIBUTE` |  | `'cieid-user-attribute-idp-mapper'` | nuovo | const |
| `IAM4D_IDP_MAPPER_FACEBOOK_ATTRIBUTE` |  | `'facebook-user-attribute-mapper'` | nuovo | const |
| `IAM4D_IDP_MAPPER_GITHUB_ATTRIBUTE` |  | `'github-user-attribute-mapper'` | nuovo | const |
| `IAM4D_IDP_MAPPER_GOOGLE_ATTRIBUTE` |  | `'google-user-attribute-mapper'` | nuovo | const |
| `IAM4D_IDP_MAPPER_LINKEDIN_ATTRIBUTE` |  | `'linkedin-user-attribute-mapper'` | nuovo | const |
| `IAM4D_IDP_MAPPER_MICROSOFT_ATTRIBUTE` |  | `'microsoft-user-attribute-mapper'` | nuovo | const |
| `IAM4D_IDP_MAPPER_SAML_ATTRIBUTE` |  | `'saml-user-attribute-idp-mapper'` | nuovo | const |
| `IAM4D_IDP_MAPPER_SPID_ATTRIBUTE` |  | `'spid-user-attribute-idp-mapper'` | nuovo | const |
| `IAM4D_IDP_PROVIDER_CIE` |  | `'cieid-saml'` | nuovo | const |
| `IAM4D_IDP_PROVIDER_FACEBOOK` |  | `'facebook'` | nuovo | const |
| `IAM4D_IDP_PROVIDER_GITHUB` |  | `'github'` | nuovo | const |
| `IAM4D_IDP_PROVIDER_GITLAB` |  | `'gitlab'` | nuovo | const |
| `IAM4D_IDP_PROVIDER_GOOGLE` |  | `'google'` | nuovo | const |
| `IAM4D_IDP_PROVIDER_LINKEDIN` |  | `'linkedin-openid-connect'` | nuovo | const |
| `IAM4D_IDP_PROVIDER_MICROSOFT` |  | `'microsoft'` | nuovo | const |
| `IAM4D_IDP_PROVIDER_SPID` |  | `'spid-saml'` | nuovo | const |
| `IAM4D_SAML_NAMEID_EMAIL` |  | `'urn: oasis: names: tc: SAML: 1.1: nameid-format: emailAddress'` | nuovo | const |
| `IAM4D_SAML_NAMEID_PERSISTENT` |  | `'urn: oasis: names: tc: SAML: 2.0: nameid-format: persistent'` | nuovo | const |
| `IAM4D_SAML_NAMEID_TRANSIENT` |  | `'urn: oasis: names: tc: SAML: 2.0: nameid-format: transient'` | nuovo | const |
| `IAM4D_SAML_NAMEID_UNSPECIFIED` |  | `'urn: oasis: names: tc: SAML: 1.1: nameid-format: unspecified'` | nuovo | const |
| `IAM4D_SPID_REGISTRY_URL` |  | `'https: //registry.spid.gov.it/entities-idp?output=json'` | nuovo | const |

### `IAMClient4D.IdentityProvider.Core.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IIAM4DIdentityProviderManager` |  | `interface` | nuovo | 16 membri: CreateIdentityProvider, CreateMapper, DeleteIdentityProvider, DeleteMapper, ExportServiceProviderMetadata, GetIdentityProvider, GetIdentityProviders, GetMapper, GetMapperTypes, GetMappers, ImportConfig, IsProviderInstalled, SaveIdentityProvider, TryGetIdentityProvider, UpdateIdentityProvider, UpdateMapper |
| `IIAM4DIdentityProviderManagerAsync` |  | `interface` | nuovo | 16 membri: CreateIdentityProviderAsync, CreateMapperAsync, DeleteIdentityProviderAsync, DeleteMapperAsync, ExportServiceProviderMetadataAsync, GetIdentityProviderAsync, GetIdentityProvidersAsync, GetMapperAsync, GetMapperTypesAsync, GetMappersAsync, ImportConfigAsync, IsProviderInstalledAsync, SaveIdentityProviderAsync, TryGetIdentityProviderAsync, UpdateIdentityProviderAsync, UpdateMapperAsync |
| `TIAM4DConfigEntry` |  | `record` | nuovo | 2 membri: Key, Value |
| `TIAM4DConfigMap` |  | `record` | nuovo | 10 membri: Clear, Contains, Count, Entries, GetBool, Merge, Remove, SetBool, TryGetValue, Values |
| `TIAM4DConfigProperty` |  | `record` | nuovo | 9 membri: DefaultValue, DisplayLabel, HelpText, Name, Options, PropertyType, ReadOnly, Required, Secret |
| `TIAM4DIdentityProvider` |  | `record` | nuovo | 15 membri: AddReadTokenRoleOnCreate, Alias, Config, Create, DisplayName, Enabled, FirstBrokerLoginFlowAlias, HideOnLogin, InternalID, LinkOnly, PostBrokerLoginFlowAlias, ProviderID, StoreToken, SyncMode, TrustEmail |
| `TIAM4DIdentityProviderMapper` |  | `record` | nuovo | 6 membri: Config, Create, ID, IdentityProviderAlias, MapperType, Name |
| `TIAM4DIdentityProviderMapperType` |  | `record` | nuovo | 5 membri: Category, HelpText, ID, Name, Properties |
| `TIAM4DIdentityProviderSyncMode` |  | `enum (ismDefault, ismImport, ismLegacy, ismForce, ismInherit)` | nuovo |  |
| `TIAM4DIdentityProviderSyncModeHelper` |  | `record helper for TIAM4DIdentityProviderSyncMode` | nuovo | 2 membri: FromString, ToString |
| `TIAM4DIdentityProviderTryResult` |  | `record` | nuovo | 2 membri: Found, IdentityProvider |
| `IAM4D_IDP_CONFIG_CLIENT_SECRET` |  | `'clientSecret'` | nuovo | const |
| `IAM4D_IDP_PROVIDER_OAUTH2` |  | `'oauth2'` | nuovo | const |
| `IAM4D_IDP_PROVIDER_OIDC` |  | `'oidc'` | nuovo | const |
| `IAM4D_IDP_PROVIDER_SAML` |  | `'saml'` | nuovo | const |
| `IAM4D_IDP_SECRET_MASK` |  | `'**********'` | nuovo | const |

### `IAMClient4D.IdentityProvider.Keycloak.Async.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DKeycloakIdentityProviderManagerAsync` |  | `class(TInterfacedObject, IIAM4DIdentityProviderManagerAsync)` | nuovo | 17 membri: Create, CreateIdentityProviderAsync, CreateMapperAsync, DeleteIdentityProviderAsync, DeleteMapperAsync, ExportServiceProviderMetadataAsync, GetIdentityProviderAsync, GetIdentityProvidersAsync, GetMapperAsync, GetMapperTypesAsync, GetMappersAsync, ImportConfigAsync, IsProviderInstalledAsync, SaveIdentityProviderAsync, TryGetIdentityProviderAsync, UpdateIdentityProviderAsync, UpdateMapperAsync |

### `IAMClient4D.IdentityProvider.Keycloak.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DIdentityProviderJSON` |  | `class` | nuovo | 7 membri: ConfigFromJSON, ConfigToJSON, IdentityProviderFromJSON, IdentityProviderToJSON, MapperFromJSON, MapperToJSON, MapperTypeFromJSON |
| `TIAM4DKeycloakIdentityProviderManager` |  | `class(TIAM4DKeycloakAdminBase, IIAM4DIdentityProviderManager)` | nuovo | 16 membri: CreateIdentityProvider, CreateMapper, DeleteIdentityProvider, DeleteMapper, ExportServiceProviderMetadata, GetIdentityProvider, GetIdentityProviders, GetMapper, GetMapperTypes, GetMappers, ImportConfig, IsProviderInstalled, SaveIdentityProvider, TryGetIdentityProvider, UpdateIdentityProvider, UpdateMapper |

### `IAMClient4D.Keycloak.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IIAM4DPendingWork` |  | `interface` | nuovo | 3 membri: CloseAndWait, Leave, TryEnter |
| `TIAM4DKeycloakClient.AuthenticatePassword` |  | `function AuthenticatePassword(const AUserName, APassword: string): string` | nuovo |  |
| `TIAM4DKeycloakClient.AuthenticatePasswordAsync` |  | `function AuthenticatePasswordAsync(const AUserName, APassword: string): IAsyncPromise<string>` | nuovo |  |
| `TIAM4DKeycloakClient.CompleteAuthorizationFlow` | `function CompleteAuthorizationFlow(const ACode, AState: string): string` | `function CompleteAuthorizationFlow(const ACode, AState: string; const AIss: string = ''): string` | compatibile | parametri opzionali in coda: le chiamate compilano |
| `TIAM4DKeycloakClient.CompleteAuthorizationFlowAsync` | `function CompleteAuthorizationFlowAsync(const ACode, AState: string): IAsyncPromise<string>` | `function CompleteAuthorizationFlowAsync(const ACode, AState: string; const AIss: string = ''): IAsyncPromise<string>` | compatibile | parametri opzionali in coda: le chiamate compilano |
| `TIAM4DKeycloakClient.Configure` |  | `procedure Configure(const AConfig: TIAM4DClientConfig)` | nuovo |  |
| `TIAM4DKeycloakClient.GenerateLogoutURL` |  | `function GenerateLogoutURL(const APostLogoutRedirectURI: string = ''; const AState: string = ''): string` | nuovo |  |
| `TIAM4DKeycloakClient.GetGrantedScopes` |  | `function GetGrantedScopes: TArray<string>` | nuovo |  |
| `TIAM4DKeycloakClient.GetIDTokenClaims` |  | `function GetIDTokenClaims: TIAM4DIDTokenClaims` | nuovo |  |
| `TIAM4DKeycloakClient.GetKeycloakActionStatus` |  | `function GetKeycloakActionStatus: string` | nuovo |  |
| `TIAM4DKeycloakClient.HasGrantedScope` |  | `function HasGrantedScope(const AScope: string): Boolean` | nuovo |  |
| `TIAM4DKeycloakClient.InitializeAuthorizationFlow` |  | `procedure InitializeAuthorizationFlow(const AOptions: TIAM4DAuthRequestOptions); overload` | nuovo | overload nuovo |
| `TIAM4DKeycloakClient.InvalidateAccessToken` |  | `procedure InvalidateAccessToken(const AAccessToken: string)` | nuovo |  |
| `TIAM4DKeycloakClient.RevokeTokens` |  | `procedure RevokeTokens` | nuovo |  |
| `TIAM4DKeycloakClient.RevokeTokensAsync` |  | `function RevokeTokensAsync: IAsyncVoidPromise` | nuovo |  |
| `TIAM4DKeycloakClient.StartAuthorizationFlowAsync` | `function StartAuthorizationFlowAsync: IAsyncPromise<string>` | `function StartAuthorizationFlowAsync(const AIdpHint: string = ''): IAsyncPromise<string>; overload`<br>`function StartAuthorizationFlowAsync(const AIdpHint, ALoginHint: string): IAsyncPromise<string>; overload`<br>`function StartAuthorizationFlowAsync(const AOptions: TIAM4DAuthRequestOptions): IAsyncPromise<string>; overload` | compatibile | parametro opzionale e overload nuovi (protected: si usa tramite `IIAM4DClient`) |

### `IAMClient4D.Security.Core.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IIAM4DJWKSKeySelector` |  | `interface` | nuovo | 1 membri: GetPublicKeyForAlg |

### `IAMClient4D.Security.Crypto.Interfaces.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IIAM4DECDSAMessageVerifier` |  | `interface` | nuovo | 1 membri: ECDSAVerifyMessage |
| `TIAM4DRSAPublicKey` |  | `class sealed` | nuovo | 9 membri: DEFAULT_MIN_MODULUS_BITS, IsValid, LOWEST_MIN_MODULUS_BITS, MAX_EXPONENT_BITS, MAX_MODULUS_BITS, MinModulusBits, ModulusSize, SMALL_MODULUS_BITS, Stripped |

### `IAMClient4D.Security.Crypto.LockBox3.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DLockBox3CryptoProvider.Destroy` | `destructor Destroy; override` |  | compatibile | resta il distruttore ereditato |

### `IAMClient4D.Security.Crypto.TMS.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DTMSCryptoProvider` | `class(TInterfacedObject, IIAM4DCryptoProvider)` | `class(TInterfacedObject, IIAM4DCryptoProvider, IIAM4DECDSAMessageVerifier)` | nuovo | interfacce implementate in più |
| `TIAM4DTMSCryptoProvider.ECDSAVerifyMessage` |  | `function ECDSAVerifyMessage(const AMessage, AR, AS_, AX, AY: TBytes; ACurve: TIAM4DECCurve): Boolean` | nuovo |  |

### `IAMClient4D.Security.Crypto.TaurusTLS.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DKeyCacheStats` |  | `record` | nuovo | 5 membri: Capacity, Count, Evictions, Hits, Misses |
| `TIAM4DTaurusTLSCryptoProvider` |  | `class(TInterfacedObject, IIAM4DCryptoProvider, IIAM4DECDSAMessageVerifier)` | nuovo | 13 membri: ClearKeyCache, Create, DEFAULT_KEY_CACHE_CAPACITY, ECDSAVerify, ECDSAVerifyMessage, GetProviderName, GetSupportedAlgorithms, KeyCacheCapacity, KeyCacheStats, MAX_KEY_CACHE_CAPACITY, RSAVerifyPKCS1, RSAVerifyPSS, SupportsAlgorithm |

### `IAMClient4D.Security.JWT.JWKS.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `EIAM4DJWKSUnavailableException` |  | `class(EIAM4DSecurityValidationException)` | nuovo | 3 membri: Create, CreateCopy, RetryAfterSeconds |
| `TIAM4DJWKSProvider` | `class(TInterfacedObject, IIAM4DJWKSProvider)` | `class(TInterfacedObject, IIAM4DJWKSProvider, IIAM4DJWKSKeySelector)` | nuovo | interfacce implementate in più |
| `TIAM4DJWKSProvider.Create` |  | `constructor Create(const AHTTPConfig: TIAM4DHTTPClientConfig; const ASSLValidator: IIAM4DSSLCertificateValidator); overload` | nuovo | overload nuovo |
| `TIAM4DJWKSProvider.GetPublicKeyForAlg` |  | `function GetPublicKeyForAlg(const AIssuer, AKeyId, AAlg: string): TJSONObject` | nuovo |  |
| `TIAM4DJWKSProvider.NegativeKidCacheCount` |  | `function NegativeKidCacheCount: Integer` | nuovo |  |
| `TIAM4DJWKSProvider.SetJWKSUri` |  | `procedure SetJWKSUri(const AIssuer, AJWKSUri: string)` | nuovo |  |
| `TIAM4DJWKSProvider.SetMaxNegativeKidEntries` |  | `procedure SetMaxNegativeKidEntries(ACount: Integer)` | nuovo |  |
| `TIAM4DJWKSProvider.SetMinRefreshIntervalSeconds` |  | `procedure SetMinRefreshIntervalSeconds(ASeconds: Integer)` | nuovo |  |
| `TIAM4DSharedJWKSProviders` |  | `class sealed` | nuovo | 5 membri: Acquire, Clear, Count, Enabled, KeyOf |

### `IAMClient4D.Security.JWT.Verifiers.ECDSA.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TECDSAJWTSignatureVerifier` |  | `class(TInterfacedObject, IIAM4DJWTSignatureVerifier)` | nuovo | 4 membri: Create, Destroy, GetSupportedAlgorithms, Verify |

### `IAMClient4D.Security.JWT.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DJWTValidator.SetAllowedHeaderTypes` |  | `procedure SetAllowedHeaderTypes(const ATypes: TArray<string>)` | nuovo |  |
| `TIAM4DJWTValidator.SetExpectedTokenType` |  | `procedure SetExpectedTokenType(const AValue: string)` | nuovo |  |
| `TValidatedTokenCacheEntry` | `record` |  | breaking | interno, pubblico per errore |
| `trygetnumericdateclaim` |  | `function TryGetNumericDateClaim(const AClaims: TJSONObject; const AName: string; out AValue: Int64; ARoundUp: Boolean = False): Boolean` | nuovo | routine |

### `IAMClient4D.Storage.AESMemoryTokenStorage.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DAESMemoryTokenStorageRawKey32.Create` |  | `constructor Create(const ACryptoProvider: IIAM4DStorageCryptoProvider; const AAAD: TBytes; const ATokenExpiryBufferSeconds: Integer = IAM4D_TOKEN_EXPIRATION_BUFFER_SECONDS); overload` | nuovo | overload nuovo |

### `IAMClient4D.Storage.Crypto.Interfaces.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `EIAM4DStorageCryptoException` | `class(Exception)` | `class(EIAM4DException)` | comportamento | antenato cambiato: conta l'ordine dei blocchi `except` |
| `EIAM4DStorageCryptoException.Clone` |  | `function Clone: EIAM4DStorageCryptoException` | nuovo |  |
| `EIAM4DStorageCryptoException.CreateCopy` |  | `constructor CreateCopy(ASource: EIAM4DException); override` | nuovo |  |
| `EIAM4DStorageCryptoException.DefaultErrorCode` |  | `function DefaultErrorCode: TIAM4DErrorCode; virtual` | nuovo |  |
| `EIAM4DStorageCryptoExceptionClass` |  | `alias class of EIAM4DStorageCryptoException` | nuovo |  |
| `EIAM4DStorageDecryptionException.DefaultErrorCode` |  | `function DefaultErrorCode: TIAM4DErrorCode; override` | nuovo |  |
| `EIAM4DStorageEncryptionException.DefaultErrorCode` |  | `function DefaultErrorCode: TIAM4DErrorCode; override` | nuovo |  |
| `IIAM4DStorageCryptoProvider (GUID)` | `['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']` | `['{87717FEE-6EC6-46CB-A01D-F506BD9603C5}']` | compatibile | GUID nuovo |

### `IAMClient4D.Storage.Crypto.TaurusTLS.pas` (nuova)

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DTaurusTLSStorageCryptoProvider` |  | `class(TInterfacedObject, IIAM4DStorageCryptoProvider)` | nuovo | 6 membri: Create, Decrypt, Destroy, Encrypt, GetAlgorithm, GetProviderName |

### `IAMClient4D.UserManagement.Constants.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IAM4D_CONTENT_TYPE_JSON` | `'application/json'` | `IAMClient4D.Admin.Keycloak.Constants.IAM4D_CONTENT_TYPE_JSON` | compatibile | const |
| `IAM4D_DEFAULT_FIRST_RESULT` | `0` | `IAMClient4D.Admin.Keycloak.Constants.IAM4D_DEFAULT_FIRST_RESULT` | compatibile | const |
| `IAM4D_DEFAULT_PAGE_SIZE` | `100` | `IAMClient4D.Admin.Keycloak.Constants.IAM4D_DEFAULT_PAGE_SIZE` | compatibile | const |
| `IAM4D_HTTP_METHOD_DELETE` | `'DELETE'` | `IAMClient4D.Admin.Keycloak.Constants.IAM4D_HTTP_METHOD_DELETE` | compatibile | const |
| `IAM4D_HTTP_METHOD_GET` | `'GET'` | `IAMClient4D.Admin.Keycloak.Constants.IAM4D_HTTP_METHOD_GET` | compatibile | const |
| `IAM4D_HTTP_METHOD_POST` | `'POST'` | `IAMClient4D.Admin.Keycloak.Constants.IAM4D_HTTP_METHOD_POST` | compatibile | const |
| `IAM4D_HTTP_METHOD_PUT` | `'PUT'` | `IAMClient4D.Admin.Keycloak.Constants.IAM4D_HTTP_METHOD_PUT` | compatibile | const |
| `IAM4D_HTTP_STATUS_CREATED` | `201` | `IAMClient4D.Admin.Keycloak.Constants.IAM4D_HTTP_STATUS_CREATED` | compatibile | const |
| `IAM4D_HTTP_STATUS_NO_CONTENT` | `204` | `IAMClient4D.Admin.Keycloak.Constants.IAM4D_HTTP_STATUS_NO_CONTENT` | compatibile | const |
| `IAM4D_HTTP_STATUS_NOT_FOUND` | `404` | `IAMClient4D.Admin.Keycloak.Constants.IAM4D_HTTP_STATUS_NOT_FOUND` | compatibile | const |
| `IAM4D_HTTP_STATUS_OK` | `200` | `IAMClient4D.Admin.Keycloak.Constants.IAM4D_HTTP_STATUS_OK` | compatibile | const |
| `IAM4D_MAX_ERROR_PREVIEW_LENGTH` | `500` | `IAMClient4D.Admin.Keycloak.Constants.IAM4D_MAX_ERROR_PREVIEW_LENGTH` | compatibile | const |
| `IAM4D_USERNAME_REGEX_PATTERN` | `'^[a-zA-Z0-9._-]+$'` | `'^[a-zA-Z0-9._@+-]+$'` | comportamento | const |

### `IAMClient4D.UserManagement.Core.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IIAM4DUserManager (GUID)` | `['{A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D}']` | `['{94441FA3-FF65-438D-B2B2-5D4B6DE92490}']` | compatibile | GUID nuovo |
| `IIAM4DUserManager.LinkFederatedIdentity` |  | `procedure LinkFederatedIdentity(const AUserID: string; const AFederatedIdentity: TIAM4DFederatedIdentity)` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DUserManager.UnlinkFederatedIdentity` |  | `procedure UnlinkFederatedIdentity(const AUserID: string; const AIdentityProvider: string)` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DUserManagerAsync.LinkFederatedIdentityAsync` |  | `function LinkFederatedIdentityAsync(const AUserID: string; const AFederatedIdentity: TIAM4DFederatedIdentity): IAsyncVoidPromise` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `IIAM4DUserManagerAsync.UnlinkFederatedIdentityAsync` |  | `function UnlinkFederatedIdentityAsync(const AUserID: string; const AIdentityProvider: string): IAsyncVoidPromise` | breaking (impl.) | nuovo metodo dell'interfaccia |
| `TIAM4DRequiredActionHelper.TryFromString` |  | `function TryFromString(const AValue: string; out AAction: TIAM4DRequiredAction): Boolean; static` | nuovo |  |
| `TIAM4DUser.FederationLink` |  | `property FederationLink: string read FFederationLink write FFederationLink` | nuovo |  |
| `TIAM4DUser.OtherRequiredActions` |  | `property OtherRequiredActions: TArray<string> read FOtherRequiredActions write FOtherRequiredActions` | nuovo |  |
| `TIAM4DUserSearchCriteria.FilterByEnabled` |  | `property FilterByEnabled: Boolean read FFilterByEnabled write FFilterByEnabled` | nuovo |  |

### `IAMClient4D.UserManagement.Keycloak.Async.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DKeycloakUserManagerAsync.LinkFederatedIdentityAsync` |  | `function LinkFederatedIdentityAsync(const AUserID: string; const AFederatedIdentity: TIAM4DFederatedIdentity): IAsyncVoidPromise` | nuovo |  |
| `TIAM4DKeycloakUserManagerAsync.UnlinkFederatedIdentityAsync` |  | `function UnlinkFederatedIdentityAsync(const AUserID: string; const AIdentityProvider: string): IAsyncVoidPromise` | nuovo |  |

### `IAMClient4D.UserManagement.Keycloak.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `IKeycloakAuthProvider` |  | `IAMClient4D.Admin.Keycloak.Base.IKeycloakAuthProvider` | compatibile | spostato in `IAMClient4D.Admin.Keycloak.Base.pas`, alias nella unit |
| `TClientBasedAuthProvider` |  | `IAMClient4D.Admin.Keycloak.Base.TClientBasedAuthProvider` | compatibile | spostato in `IAMClient4D.Admin.Keycloak.Base.pas`, alias nella unit |
| `TIAM4DKeycloakUserManager` | `class(TInterfacedObject, IIAM4DUserManager)` | `class(TIAM4DKeycloakAdminBase, IIAM4DUserManager)` | compatibile | la nuova base `TIAM4DKeycloakAdminBase` contiene i costruttori di prima |
| `TIAM4DKeycloakUserManager.Create` | `constructor Create(const AAuthProvider: IKeycloakAuthProvider; const ABaseURL: string; const ARealm: string); overload` |  | compatibile | spostato nella classe base |
| `TIAM4DKeycloakUserManager.LinkFederatedIdentity` |  | `procedure LinkFederatedIdentity(const AUserID: string; const AFederatedIdentity: TIAM4DFederatedIdentity)` | nuovo |  |
| `TIAM4DKeycloakUserManager.UnlinkFederatedIdentity` |  | `procedure UnlinkFederatedIdentity(const AUserID: string; const AIdentityProvider: string)` | nuovo |  |
| `TTokenBasedAuthProvider` |  | `IAMClient4D.Admin.Keycloak.Base.TTokenBasedAuthProvider` | compatibile | spostato in `IAMClient4D.Admin.Keycloak.Base.pas`, alias nella unit |

### `IAMClient4D.UserManagement.Validation.pas`

| Elemento | 2.1 | 3.0 | Tipo | Nota |
|---|---|---|---|---|
| `TIAM4DUserManagementValidator.ValidatePaging` |  | `procedure ValidatePaging(AFirst, AMax: Integer); static` | nuovo |  |
| `TIAM4DUserManagementValidator.ValidateUsernameLookup` |  | `procedure ValidateUsernameLookup(const AUsername: string); static` | nuovo |  |

---

## 6. Sample della 2.1 compilati sulla 3.0

I sample del clone 2.1 sono stati compilati senza modifiche contro il `src` 3.0 (Win64 Debug, Delphi 13). Il comando è `tools/build_samples_21.bat <clone 2.1> src <cartella di lavoro>`, e il sample DMVC usa la DMVC rc10 di `src/Lib`.

| Sample 2.1 | Risultato | Warning della libreria |
|---|---|---|
| `VCL/KeycloakClient` | compila | nessuno |
| `DMVC/SwaggerAPIVersioning` | compila | W1000 `TIAM4DJWTMiddleware` deprecato; gli altri W1000 vengono dai middleware DMVC deprecati nella rc10 (CORS, StaticFiles, Swagger) |
| `uniGUI/KeycloakWebApp` | compila | nessuno; solo i warning dei sorgenti uniGUI |

Nessun sample 2.1 dimostra quindi un'incompatibilità di sorgente. I cambi che rompono la compilazione (sezione 1) toccano API che i sample non usano. Per i cambi di comportamento la compilazione non dice niente. Sui sample 2.1 contano soprattutto:

- `iss` nel modo esterno di uniGUI: il sample chiama `CompleteAuthorizationFlow` senza `AIss`, quindi il login funziona ma senza il controllo RFC 9207 (nel modo esterno l'`iss` viene controllato solo se l'applicazione lo passa);
- `Audience` obbligatoria nel middleware DMVC;
- `http://` non loopback rifiutato.

I sample attuali sono già allineati (fasi 4 e 5).

---

## 7. Riscontro incrociato

### 7.1 Voci di `CHANGELOG.md` `[Unreleased]` smentite o imprecise

| Voce del CHANGELOG | Cosa dice il codice | Da fare in fase 7 |
|---|---|---|
| Changed, "This review": "`TIAM4DTokenValidator`: an expiry of 0 is expired (fail-closed)" | La classe non esiste più: la unit `Common.TokenValidator` è stata rimossa in `549ec5a`. Nella 2.1 una scadenza 0 voleva dire "non scade mai". Lo stesso controllo, con 0 = scaduto, vive in `IIAM4DTokenStorage.IsAccessTokenValid`/`IsRefreshTokenValid` (`Storage.AESMemoryTokenStorage.pas:378-400`). | togliere la voce; mettere la rimozione della unit in Removed (breaking) |
| Fixed, "UTC clock": cita `TIAM4DTokenValidator` tra i punti corretti | come sopra | togliere il nome |
| Removed | Mancano la unit `Common.TokenValidator` (`TIAM4DTokenValidator`, `IAM4D_DEFAULT_TOKEN_EXPIRATION_BUFFER_SECONDS`) e `TAsyncOperationController<T>.SetResult` (protected, ora `TrySetResult`). `IEventWrapper`/`TEventWrapper` sono citati in Changed come "moved to the implementation section": per chi li usava sono una rimozione. | completare Removed |
| Changed, "Requirements": "Delphi 12 or later" | Il controllo di `Config.inc` ammette Delphi 12, ma è installato e provato solo Delphi 13. Il piano dice "RAD Studio 13". | decidere: "Delphi 12 o successiva (provato con 13)" oppure alzare il controllo |
| Fixed: "`UpdateUser` reset fields" (con la nota "Breaking") e "`GetGroups` returned the top level only" | Sono cambi incompatibili: `UpdateUser` ora azzera i campi vuoti, `GetGroups` restituisce tutto l'albero. | spostarli in Breaking |
| Fixed: "Namespaced claim names" | Vero, ma il rovescio non è scritto: `GetCustomClaim('address.country')` trovava un valore annidato e ora restituisce il default. | aggiungerlo come breaking |
| Changed, "Requirements": "Keycloak 25 or later (tested with 25.0, 26.7 and 26.8)" | coerente con i test; il piano cita 25.0 e 26.8 | nessuna, salvo allineare il piano |

Nessun'altra voce è risultata in contrasto con il codice. Le voci di Security e Fixed controllate a campione sono tutte confermate: `alg` case-sensitive, pin mai applicati, OPTIONS e Swagger, `AllowAnonymous`, ruoli client, `nbf`, `GetUserByEmail` con la variabile nascosta, doppia liberazione delle required actions, segmenti `%20`, `max_age` e `auth_time`.

### 7.2 Modifiche del codice che il CHANGELOG non riporta

| Modifica | Dove | Peso |
|---|---|---|
| **id_token validato del tutto** allo scambio del code, al refresh e in Client Credentials (firma via JWKS, `iss`, `aud`, `azp`, `typ` = `ID`, `exp`/`iat` con 300 s). Nella 2.1 si controllava solo il nonce. Errori come `EIAM4DSecurityValidationException`. Il refresh richiede `sub`/`aud`/nonce uguali al login. | `Keycloak.pas:770-808,2361-2472` | breaking/sicurezza: la voce più importante che manca |
| `WithLoopbackRedirectHost(lrhLoopbackIP)` / `TIAM4DLoopbackRedirectHost`: redirect su `http://127.0.0.1:porta` (RFC 8252 8.3) | `Core.pas`, `Config.Builder.pas`, `549ec5a` | nuovo |
| iOS: `TIAM4DIOSLoginBrowser` (`ilbSafari`, `ilbAuthenticationSession`), login in una `ASWebAuthenticationSession` | `FMX/IAMClient4D.FMX.AppRedirect.pas`, `549ec5a` | nuovo (compilato, non provato su dispositivo) |
| Android in `svmStrict`: senza una callback l'RTL accettava CA non fidate e certificati scaduti; ora vale il verdetto della piattaforma (`KeepPlatformVerdict`) | `Core.pas:1767-1772` | sicurezza |
| Pool di `THTTPClient` nel client Keycloak: le richieste di un client non sono più serializzate | `Keycloak.pas:815-877` | comportamento |
| `EIAM4DStorageCryptoException` ed `EIAM4DOpenSSLException` derivano da `EIAM4DException`; nuovo `ecCryptoProviderUnavailable` | `Storage.Crypto.Interfaces.pas:131`, `Crypto.TaurusTLS.Common.pas` | breaking (ordine degli `except`) |
| `TIAM4DJWTMiddlewareConfig`, `IIAM4DJWTAuthenticator` e `TIAM4DJWTAuthenticator` spostati in `DMVC.Authenticator` (alias in `DMVC.Middleware`) | `549ec5a` | compatibile |
| DMVC: ruoli, scope, gruppi e `amr` del DTO case-sensitive; deduplicazione dei ruoli case-sensitive | `DMVC.DTO.pas:412-808`, `DMVC.Authenticator.pas:628` | breaking |
| DMVC: i 403 dicono solo "Insufficient permissions"; i ruoli richiesti vanno nel log | `DMVC.Helpers.pas:161,190-198` | comportamento |
| `TIAM4DUserInfo.GetCustomClaims` case-sensitive | `Core.pas:1647` | comportamento |
| Modo esterno: dopo uno scambio fallito non si può riprovare con lo stesso state (`TakeContext` prima dello scambio) | `Callback.Handler.External.pas:235` | comportamento |
| Validatore JWT: l'header `typ` `application/jwt` ora è accettato | `Security.JWT.pas:850` | comportamento |
| Errori di callback OAuth2 come `EIAM4DOAuth2CallbackException` invece di `EIAM4DCallbackHandlerException` | `Callback.Handler.pas:528-553` | breaking (minore) |
| `IIAM4DUserManager` documentato come "non è un punto di estensione" | `UserManagement.Core.pas`, `549ec5a` | documentazione |
| Costanti `IAM4D_VERSION`, `IAM4D_VERSION_MAJOR`/`MINOR`/`PATCH` | `Common.Constants.pas` | nuovo |
| `TIAM4DOAuth2URLParser`: messaggio senza " - " finale quando manca la descrizione | `Common.OAuth2URLParser.pas:256` | minore |
| `TAsyncCore.RunWithRetry` con `AMaxRetries` < 0: `EArgumentOutOfRangeException` sincrona (era un errore dell'operazione) | `Async.Core.pas:2557` | citato in Fixed; da tenere tra i cambi di comportamento |

### 7.3 Memoria `release-3-0-pending`

Tutte le voci della memoria sono confermate dal codice:

- DMVC 3.5 (`TMVCUser`);
- metodi nuovi in `IIAM4DClient`, `IIAM4DClientConfigBuilder` e `IIAM4DUserManager(Async)`;
- `SetOnCodeReceived` con `TProc<string,string,string>`;
- rimozione di `IAM4D_OAUTH2_CALLBACK_PORT_MIN/MAX`, `TValidatedTokenCacheEntry` e `IEventWrapper`/`TEventWrapper`;
- `CONTEXT_KEY_*`/`CACHE_KEY` deprecati;
- RSA sotto 2048 bit rifiutate e `alg` esatto;
- bypass di OPTIONS e openapi chiuso;
- eccezioni HTTP tipizzate e "not found" = 404;
- `EIAM4DRefreshTokenExpiredException`;
- date ISO 8601 UTC;
- `EAsyncTimeoutException`, `ForceQueue` e timeout non ritentati;
- `Logout` con POST;
- blocchi 1-3: `iss`, redirect, HTTP in chiaro, `at+jwt`.

Da aggiungere alla guida rispetto alla memoria:

- rimozione di `Common.TokenValidator`;
- validazione completa dell'id_token;
- `IIAM4DSSLCertificateValidator.ValidateCertificate` e `crrSystemValidationFailed`;
- `OpenURL` solo http(s);
- annullamento del login come Cancelled;
- `UpdateUser` che sostituisce il profilo, `GetGroups` con l'albero intero, nomi case-sensitive nell'Admin API e nel DMVC;
- `GetCustomClaim` con chiavi di primo livello;
- `typ` del payload `Bearer` nel DMVC;
- `Issuer` e `TokenHeaderName` obbligatori;
- gerarchie di `EIAM4DStorageCryptoException` e delle eccezioni dell'Admin API;
- callback di Async.Core che non cambiano lo stato;
- pinning su Linux rifiutato.

La memoria dice anche "README Requirements still says Keycloak 22+". Valeva per il README 2.1: quello attuale dice "Keycloak 25+ (tested with 25.0, 26.7 and 26.8)". Resta però "Delphi: Tested with 12.3 or later" (`README.md:250`), che come in 7.1 non è verificato.
