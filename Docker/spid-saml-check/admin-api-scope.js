// Keycloak 26.8.2+: Admin REST API tokens need the audience of the kc-admin-api client scope, default
// only on admin-cli and security-admin-console. Adds it to the default scopes of the sample client,
// for the Admin API calls of the samples (user demo). Older Keycloak has no such scope: nothing to do.
// Not in the realm file, which would log a warning on older Keycloak. Usage (from register.sh): node admin-api-scope.js
const keycloak = process.env.KEYCLOAK_URL || 'http://keycloak:8080';
const realm = process.env.IAM4D_REALM || 'iam4d-sample';
const clientId = process.env.ADMIN_API_CLIENT || 'iam4d-sample-app';
const scopeName = 'kc-admin-api';

async function call(url, options) {
  const response = await fetch(url, options);
  if (!response.ok)
    throw new Error(`${options?.method || 'GET'} ${url}: HTTP ${response.status}`);
  return response;
}

(async () => {
  const token = (await (await call(`${keycloak}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'password', client_id: 'admin-cli',
      username: process.env.KC_ADMIN || 'admin', password: process.env.KC_ADMIN_PASSWORD || 'admin'
    })
  })).json()).access_token;
  const headers = { Authorization: `Bearer ${token}` };
  const base = `${keycloak}/admin/realms/${realm}`;
  const scope = (await (await call(`${base}/client-scopes`, { headers })).json()).find(s => s.name === scopeName);
  if (!scope) {
    console.log(`No ${scopeName} client scope in ${realm}: nothing to add`);
    return;
  }
  const client = (await (await call(`${base}/clients?clientId=${encodeURIComponent(clientId)}`, { headers })).json())[0];
  if (!client)
    throw new Error(`Client ${clientId} not found in ${realm}`);
  const defaults = await (await call(`${base}/clients/${client.id}/default-client-scopes`, { headers })).json();
  if (!defaults.some(s => s.id === scope.id))
    await call(`${base}/clients/${client.id}/default-client-scopes/${scope.id}`, { method: 'PUT', headers });
  console.log(`${scopeName} is a default client scope of ${realm}/${clientId}`);
})().catch(e => {
  console.error(e.message);
  process.exit(1);
});
