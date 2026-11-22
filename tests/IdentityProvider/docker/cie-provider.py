#  ---------------------------------------------------------------------------
#  CIE provider "cie" of the realm iam4d-sample bound to the CIE simulator, for e2e-login.py
#  without the VCL sample. Same configuration the sample saves with the environment
#  "Local test (CIE simulator)" (TIAM4DCieIdPBuilder): AgID SAML profile, metadata imported
#  from the simulator as Keycloak reaches it, mappers fiscalNumber, name and familyName.
#  register.sh of cie-simulator registers the CIE SP metadata a few seconds after create.
#  Usage: python cie-provider.py create|delete
#    delete  removes the provider and the users created by brokered logins (username tinit-...),
#            so that the realm is back as imported
#  Variables: KC_URL (default http://localhost:KC_PORT, KC_PORT default 18080; with the relative path,
#  e.g. http://localhost:18180/auth for Docker/), KC_REALM (default iam4d-sample), CIE_CHECK_PORT
#  (default 8444), KC_ADMIN_PASSWORD (password of the master admin admin, default admin).
#  Standard library only.
#  ---------------------------------------------------------------------------
import json, os, sys, time, urllib.error, urllib.parse, urllib.request

if sys.argv[1:] not in (['create'], ['delete']):
    sys.exit('Usage: python cie-provider.py create|delete')
KC = os.environ.get('KC_URL', f"http://localhost:{os.environ.get('KC_PORT', '18080')}").rstrip('/')
ADMIN = KC + '/admin/realms/' + os.environ.get('KC_REALM', 'iam4d-sample')
ALIAS = 'cie'
METADATA_URL = f"http://cie-simulator:{os.environ.get('CIE_CHECK_PORT', '8444')}/demo/metadata.xml"


def call(method, url, body=None, token=None, form=False):
    data, headers = None, {}
    if body is not None:
        data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
    if token:
        headers['Authorization'] = 'Bearer ' + token
    try:
        response = urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers, method=method))
        return response.status, response.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def check(what, status, body, expected):
    print(f'{what} -> {status}')
    if status not in expected:
        sys.exit(f'[FAILED] {what}: {status} {body[:300]}')


status, body = call('POST', KC + '/realms/master/protocol/openid-connect/token',
                    dict(grant_type='password', client_id='admin-cli', username='admin',
                         password=os.environ.get('KC_ADMIN_PASSWORD', 'admin')), form=True)
check('admin token', status, body, (200,))
token = json.loads(body)['access_token']

if sys.argv[1] == 'delete':
    status, body = call('DELETE', f'{ADMIN}/identity-provider/instances/{ALIAS}', token=token)
    check(f'delete provider {ALIAS}', status, body, (204, 404))
    status, body = call('GET', ADMIN + '/users?' + urllib.parse.urlencode(dict(search='tinit-', max=1000)), token=token)
    for user in json.loads(body):
        if user['username'].startswith('tinit-'):
            status, body = call('DELETE', f"{ADMIN}/users/{user['id']}", token=token)
            check(f"delete user {user['username']}", status, body, (204,))
    sys.exit(0)

# Identity provider side from the simulator metadata: entity ID, endpoints, signing certificate
status, body = call('POST', ADMIN + '/identity-provider/import-config',
                    dict(providerId='cieid-saml', fromUrl=METADATA_URL), token)
check(f'import-config {METADATA_URL}', status, body, (200,))
imported = json.loads(body)
config = {k: v for k, v in imported.items() if k in (
    'idpEntityId', 'singleSignOnServiceUrl', 'singleLogoutServiceUrl', 'signingCertificate', 'metadataDescriptorUrl')}
config.update({
    # AgID SAML profile (TIAM4DItalianSamlIdPBuilderBase.Initialize)
    'principalType': 'ATTRIBUTE', 'principalAttribute': 'fiscalNumber',
    'nameIDPolicyFormat': 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
    'wantAuthnRequestsSigned': 'true', 'wantAssertionsSigned': 'true', 'validateSignature': 'true',
    'signSpMetadata': 'true', 'forceAuthn': 'true', 'postBindingAuthnRequest': 'true',
    'postBindingResponse': 'true', 'postBindingLogout': 'true', 'signatureAlgorithm': 'RSA_SHA256',
    'xmlSigKeyInfoKeyNameTransformer': 'NONE',
    'authnContextClassRefs': '["https://www.spid.gov.it/SpidL2"]', 'authnContextComparisonType': 'minimum',
    # Service provider data of the SP metadata (ServiceName is required by the SAML schema)
    'attributeConsumingServiceIndex': '1', 'attributeConsumingServiceName': 'IAMClient4D sample',
    'organizationNames': 'it|IAMClient4D', 'organizationDisplayNames': 'it|IAMClient4D',
    'organizationUrls': 'it|https://github.com/claudio-piffer/IAMClient4D',
    'administrativeContactIsSpPrivate': 'true', 'administrativeContactCompany': 'IAMClient4D',
    'administrativeContactVatNumber': 'IT12345678901', 'administrativeContactEmail': 'test@example.com',
    'syncMode': 'FORCE', 'hideOnLoginPage': 'false'})
# storeToken and the other flags explicit: without them the CIE extension fails on the login (NPE)
status, body = call('POST', ADMIN + '/identity-provider/instances', dict(
    alias=ALIAS, displayName='CIE ID', providerId='cieid-saml', enabled=True, trustEmail=True, storeToken=False,
    addReadTokenRoleOnCreate=False, linkOnly=False, hideOnLogin=False,
    firstBrokerLoginFlowAlias='first broker login', config=config), token)
check(f'create provider {ALIAS} ({imported.get("idpEntityId")})', status, body, (201,))
for attribute, user_attribute in (('fiscalNumber', 'fiscalNumber'), ('name', 'firstName'), ('familyName', 'lastName')):
    status, body = call('POST', f'{ADMIN}/identity-provider/instances/{ALIAS}/mappers', dict(
        name=attribute, identityProviderAlias=ALIAS, identityProviderMapper='cieid-user-attribute-idp-mapper',
        config={'syncMode': 'INHERIT', 'attribute.name': attribute, 'user.attribute': user_attribute}), token)
    check(f'mapper {attribute}', status, body, (201,))
# register.sh polls every 5 seconds: leave it the time to register the new SP metadata
print('Waiting 10 seconds for the CIE simulator to register the SP metadata')
time.sleep(10)
