import assert from "node:assert/strict";
import test from "node:test";
import { applyEvidence, createArbitration, proofRequirementSatisfied,
  recordReconciliation } from "../index.mjs";

// Synthetic contract canary, not product E2E or authorization implementation.
const lanes = ["supabase", "neon"].map((provider) => ({ id: provider, provider,
  issuer: `https://${provider}.example.test`, audience: "quaestor-api",
  proofClass: "provider" }));
const policy = { version: 1, mode: "strict-provider-pair", realm: "customer",
  operation: "sensitive", minimumAssurance: 2, lanes };
const context = { sessionId: "synthetic-okla-session", transactionId: "ledger-command-1",
  sessionEpoch: 4, policyEpoch: 2, now: 1000, deadline: 1030 };

function proof(lane, overrides = {}) {
  return { ...context, laneId: lane.id, kind: "valid", proof: { ...lane,
    realm: "customer", subject: `${lane.provider}-synthetic-subject`,
    sharedUserId: "synthetic-shared-user", ceremonyId: `${lane.provider}-ceremony`,
    assurance: 2, issuedAt: 990, expiresAt: 1100, ...overrides } };
}

test("Okla-to-Quaestor sensitive proof cannot use an optimistic read decision", () => {
  const readPolicy = { ...policy, mode: "customer-optimistic", operation: "authentication_read" };
  let read = applyEvidence(createArbitration(readPolicy, context), proof(lanes[0]), 1000);
  read = recordReconciliation(read, { ...context, eventId: "durable-read-intent" });
  assert.equal(proofRequirementSatisfied(read, 1000), true);

  const sensitive = applyEvidence(createArbitration(policy, context), proof(lanes[0]), 1000);
  assert.equal(proofRequirementSatisfied(sensitive, 1000), false);
  // Receipt is not a second independent provider proof.
  assert.equal(proofRequirementSatisfied(recordReconciliation(sensitive,
    { ...context, eventId: "durable-read-intent" }), 1000), false);
});

test("Quaestor rejects Okla-audience, stale-command, low-assurance and conflicting-principal proof", () => {
  for (const invalid of [{ audience: "okla-api" }, { assurance: 1 },
    { sharedUserId: "different-user" }]) {
    let state = applyEvidence(createArbitration(policy, context), proof(lanes[0]), 1000);
    state = applyEvidence(state, proof(lanes[1], invalid), 1000);
    assert.equal(proofRequirementSatisfied(state, 1000), false);
  }
  const state = applyEvidence(createArbitration(policy, context),
    { ...proof(lanes[0]), transactionId: "ledger-command-other" }, 1000);
  assert.equal(state.status, "denied");
});

test("reconciled ledger proof returns no membership, tenant, role or financial grant", () => {
  const state = lanes.reduce((current, lane) => applyEvidence(current, proof(lane,
    { roles: ["ledger-admin"], tenant_id: "injected-tenant", tenant_membership_id: "injected-membership" }), 1000),
  createArbitration(policy, context));
  assert.equal(proofRequirementSatisfied(state, 1000), true);
  const encoded = JSON.stringify(state);
  for (const forbidden of ["ledger-admin", "injected-tenant", "injected-membership"]) {
    assert.equal(encoded.includes(forbidden), false);
  }
});
