// Stores SP metadata in the spid-saml-check store of the user "validator", where the demo IdP
// looks it up. The download API cannot be used: it accepts only https URLs with a domain name.
// Usage (from register.sh): node register.js <metadata file> <metadata URL>
const fs = require('fs');

process.chdir('/spid-saml-check/src');
const Database = require('/spid-saml-check/src/server/lib/database');
const { MetadataParser } = require('/spid-saml-check/src/server/lib/saml-utils');

const [file, url] = process.argv.slice(2);
const xml = fs.readFileSync(file, 'utf8');
const entityId = new MetadataParser(xml).getServiceProviderEntityId();
if (!entityId) {
  console.error('entityID not found in ' + url);
  process.exit(1);
}

new Database().connect().setup().setMetadata('validator', 'iam4d', entityId, null, 'main', url, xml);
console.log('SP metadata registered with the demo IdP: ' + entityId);
