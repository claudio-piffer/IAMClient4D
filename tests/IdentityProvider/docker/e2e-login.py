#  ---------------------------------------------------------------------------
#  End-to-end brokered login against the test stack, as a browser would do it:
#  public client iam4d-sample-app (authorization code + PKCE S256) -> Keycloak ->
#  kc_idp_hint -> demo identity provider (spid-saml-check or the CIE simulator) ->
#  signed SAML response -> Keycloak first broker login -> code -> tokens.
#  Prints every step and the claims of the id_token; exit code 0 when the login works.
#  Usage: python e2e-login.py <alias> <user> <password>
#    python e2e-login.py spid-test ada password123
#    python e2e-login.py cie marcopolo password123      (after: python cie-provider.py create)
#  Variables: KC_URL (default http://localhost:KC_PORT, KC_PORT default 18080; with the relative path,
#  e.g. http://localhost:18180/auth for Docker/), KC_REALM (default iam4d-sample). The brokered
#  user is created at the first login: CIE ID returns no email, the script fills <user>@example.com.
#  Standard library only.
#  ---------------------------------------------------------------------------
import base64, hashlib, html, http.cookiejar, json, os, re, secrets, sys, urllib.error, urllib.parse, urllib.request

if len(sys.argv) != 4:
    sys.exit('Usage: python e2e-login.py <alias> <user> <password>')
ALIAS, USER, PASSWORD = sys.argv[1:4]
KC = (os.environ.get('KC_URL', f"http://localhost:{os.environ.get('KC_PORT', '18080')}").rstrip('/')
      + '/realms/' + os.environ.get('KC_REALM', 'iam4d-sample'))
CLIENT_ID = 'iam4d-sample-app'
# Never contacted: the script stops at the redirect and reads the code from it
REDIRECT_URI = 'http://127.0.0.1:53682/oauth2callback'
MAX_STEPS = 25


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class LocalhostPolicy(http.cookiejar.DefaultCookiePolicy):
    # Like browsers, localhost is a secure context: Keycloak's Secure cookies also go over http
    def return_ok_secure(self, cookie, request):
        return True


opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar(LocalhostPolicy())), NoRedirect)
step = 0


def request(url, form=None):
    global step
    step += 1
    body = urllib.parse.urlencode(form).encode() if form is not None else None
    try:
        response = opener.open(urllib.request.Request(url, data=body))
        status, location, text = response.status, response.headers.get('Location'), response.read()
    except urllib.error.HTTPError as e:
        status, location, text = e.code, e.headers.get('Location'), e.read()
    print(f"[{step:02d}] {'POST' if form is not None else 'GET '} {url[:100]} -> {status}"
          + (f' Location: {location[:100]}' if location else ''))
    return status, location, text.decode('utf-8', 'replace')


def forms(text, base_url):
    result = []
    for match in re.finditer(r'<form\b([^>]*)>(.*?)</form>', text, re.S | re.I):
        action = re.search(r'action\s*=\s*["\']([^"\']*)', match.group(1), re.I)
        fields = {}
        for field in re.finditer(r'<input\b[^>]*>', match.group(2), re.I):
            name = re.search(r'name\s*=\s*["\']([^"\']*)', field.group(0), re.I)
            value = re.search(r'value\s*=\s*["\']([^"\']*)', field.group(0), re.I)
            if name:
                fields[html.unescape(name.group(1))] = html.unescape(value.group(1)) if value else ''
        result.append((urllib.parse.urljoin(base_url, html.unescape(action.group(1)) if action else base_url), fields))
    return result


def fail(message):
    print('[FAILED]', message)
    sys.exit(1)


verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
url = KC + '/protocol/openid-connect/auth?' + urllib.parse.urlencode(dict(
    client_id=CLIENT_ID, redirect_uri=REDIRECT_URI, response_type='code', scope='openid',
    kc_idp_hint=ALIAS, state='e2e', code_challenge=challenge, code_challenge_method='S256'))
form, logged_in = None, False

for _ in range(MAX_STEPS):
    status, location, text = request(url, form)
    form = None
    if location:
        url = urllib.parse.urljoin(url, location)
        if url.startswith(REDIRECT_URI):
            break
        continue
    page_forms = forms(text, url)
    if not page_forms:
        page_text = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', re.sub(r'<script.*?</script>', '', text, flags=re.S)))
        fail(f'HTTP {status}, page without a form: {page_text.strip()[:400]}')
    # Login page of the demo identity provider
    login_form = next((f for f in page_forms if any('password' in k.lower() for k in f[1])), None)
    if login_form and not logged_in:
        url, form = login_form
        form['username'], form['password'] = USER, PASSWORD
        logged_in = True
        print(f'     sign in as {USER}')
        continue
    if login_form:
        fail('the demo identity provider rejected the credentials')
    # Otherwise the first form: SAML POST binding, consent, Keycloak first broker login
    url, form = page_forms[0]
    if 'email' in form and not form['email']:
        form['email'] = USER + '@example.com'
        print(f"     first broker login: email requested by Keycloak, {form['email']}")
    print('     submit form', sorted(form))
else:
    fail(f'no redirect to the client after {MAX_STEPS} steps')

query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
if 'code' not in query:
    fail(f'redirect to the client without a code: {query}')
status, _, text = request(KC + '/protocol/openid-connect/token', dict(
    grant_type='authorization_code', client_id=CLIENT_ID, code=query['code'][0],
    redirect_uri=REDIRECT_URI, code_verifier=verifier))
tokens = json.loads(text)
if 'id_token' not in tokens:
    fail(f'no tokens: {text[:400]}')
payload = tokens['id_token'].split('.')[1]
claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
print('[OK] id_token:', {k: claims.get(k) for k in ('preferred_username', 'name', 'email', 'iss')})
