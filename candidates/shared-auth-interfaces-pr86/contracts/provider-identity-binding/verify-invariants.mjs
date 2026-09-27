import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(fs.readFileSync(path.join(root, "authored.schema.json"), "utf8"));
const migrated = JSON.parse(fs.readFileSync(
  path.join(root, "instances/ProviderIdentityBinding/valid/supabase-migrated.json"),
  "utf8",
));
const nonMerge = JSON.parse(fs.readFileSync(
  path.join(root, "instances/IdentityNonMergeScenario/valid/matching-email-distinct-providers.json"),
  "utf8",
));

const keyProperties = Object.keys(schema.$defs.ProviderIdentityKey.properties);
assert.deepEqual(keyProperties, ["provider", "issuer", "subject", "realm"]);
assert.deepEqual(schema.$defs.ProviderIdentityKey.required, keyProperties);
assert.equal("email" in schema.$defs.ProviderIdentityKey.properties, false);
assert.equal("provider_tenant" in schema.$defs.ProviderIdentityKey.properties, false);
assert.equal("principal_id" in schema.$defs.ProviderIdentityKey.properties, false);

function canonicalKey(binding) {
  const { provider, issuer, subject, realm } = binding.key;
  return JSON.stringify([provider, issuer, subject, realm]);
}

assert.notEqual(canonicalKey(nonMerge.left), canonicalKey(nonMerge.right));
assert.notEqual(nonMerge.left.shared_user_id, nonMerge.right.shared_user_id);
assert.equal(nonMerge.email_is_identity_evidence, false);
assert.equal(nonMerge.expected_same_identity, false);
assert.equal(typeof nonMerge.matching_profile_email, "string");
assert.ok(nonMerge.matching_profile_email.length > 0);

assert.equal(migrated.legacy.migration_state, "mapped");
assert.equal(migrated.legacy.migration_basis, "reviewed_provider_mapping");
assert.equal(migrated.key.subject, migrated.legacy.provider_subject);
assert.notEqual(migrated.key.issuer, migrated.legacy.provider_tenant);

const quarantined = {
  migration_state: "quarantined",
  migration_basis: "insufficient_evidence",
};
assert.equal(quarantined.migration_state, "quarantined");
assert.equal(quarantined.migration_basis, "insufficient_evidence");

console.log("provider identity binding invariants: ok");
