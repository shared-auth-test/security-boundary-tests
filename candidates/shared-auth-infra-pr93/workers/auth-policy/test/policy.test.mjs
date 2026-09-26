import assert from "node:assert/strict";
import test from "node:test";
import { applyEvidence, compilePolicy, createArbitration, createReadOnlyAdapter,
  proofRequirementSatisfied, recordReconciliation } from "../index.mjs";

const providers = ["shared-auth", "supabase", "neon"];
const lanes = providers.map((provider) => ({ id: provider, provider,
  issuer: `https://${provider}.example.test`, audience: "customer", proofClass: "provider" }));
const context = { sessionId: "session-1", transactionId: "transaction-1",
  sessionEpoch: 7, policyEpoch: 3, now: 100, deadline: 130 };
const optimistic = { version: 1, mode: "customer-optimistic", realm: "customer",
  operation: "authentication_read", minimumAssurance: 1, lanes };
const strict = { ...optimistic, mode: "strict-provider-pair", operation: "sensitive", lanes: lanes.slice(1) };

function evidence(lane, kind = "valid", override = {}) {
  return { ...context, laneId: lane.id, kind, proof: { ...lane, realm: "customer",
    subject: `${lane.provider}-subject`, sharedUserId: "canonical-1", ceremonyId: lane.id,
    assurance: 1, issuedAt: 90, expiresAt: 140, ...override } };
}

function receipt() {
  return { ...context, eventId: "reconciliation-1" };
}

function permutations(items) {
  if (items.length === 0) {
    return [[]];
  }
  return items.flatMap((item, index) => permutations(items.filter((_, i) => i !== index))
    .map((tail) => [item, ...tail]));
}

test("all 384 three-provider outcome orderings have deterministic final admission", () => {
  const kinds = ["valid", "hard_deny", "degraded", "not_applicable"];
  for (const a of kinds) {
    for (const b of kinds) {
      for (const c of kinds) {
        const outcomes = [a, b, c];
        for (const order of permutations([0, 1, 2])) {
          let state = recordReconciliation(createArbitration(optimistic, context), receipt());
          for (const index of order) {
            state = applyEvidence(state, evidence(lanes[index], outcomes[index]), 100);
          }
          const expected = !outcomes.includes("hard_deny") && outcomes.includes("valid");
          assert.equal(proofRequirementSatisfied(state, 100), expected, JSON.stringify({ outcomes, order }));
          assert.equal(state.status === "reconciled", outcomes.every((kind) => kind === "valid"));
        }
      }
    }
  }
});

test("all strict-pair outcomes and both arrival orders require two valid proofs", () => {
  const kinds = ["valid", "hard_deny", "degraded", "not_applicable"];
  for (const a of kinds) {
    for (const b of kinds) {
      for (const order of [[0, 1], [1, 0]]) {
        let state = createArbitration(strict, context);
        state = applyEvidence(state, evidence(strict.lanes[order[0]], [a, b][order[0]]), 100);
        assert.equal(proofRequirementSatisfied(state, 100), false);
        state = applyEvidence(state, evidence(strict.lanes[order[1]], [a, b][order[1]]), 100);
        assert.equal(proofRequirementSatisfied(state, 100), a === "valid" && b === "valid");
      }
    }
  }
});

test("first success cannot admit until exact durable receipt exists", () => {
  const state = applyEvidence(createArbitration(optimistic, context), evidence(lanes[1]), 100);
  assert.equal(state.status, "awaiting_durable_reconciliation");
  assert.equal(proofRequirementSatisfied(state, 100), false);
  const admitted = recordReconciliation(state, receipt());
  assert.equal(admitted.status, "optimistic");
  assert.equal(proofRequirementSatisfied(admitted, 100), true);
  assert.equal(recordReconciliation(state, { ...receipt(), transactionId: "other" }).status, "denied");
  assert.equal(recordReconciliation(admitted, { ...receipt(), eventId: "other" }).status, "denied");
});

test("denial and identity conflicts are terminal in every provider order", () => {
  for (const order of permutations([0, 1, 2])) {
    let state = createArbitration(optimistic, context);
    for (const index of order) {
      state = applyEvidence(state, evidence(lanes[index], "valid", {
        sharedUserId: index === 1 ? "different-principal" : "canonical-1",
      }), 100);
    }
    assert.equal(state.status, "denied");
    assert.equal(applyEvidence(state, evidence(lanes[0]), 100), state);
    assert.equal(recordReconciliation(state, receipt()), state);
  }
});

test("realm, issuer, audience, assurance, expiry, context, and lane substitution reject", () => {
  const invalidProofs = [{ realm: "admin" }, { issuer: "https://attacker.test" },
    { audience: "other" }, { provider: "neon" }, { proofClass: "native" },
    { assurance: 0 }, { assurance: 3 }, { expiresAt: 100 }, { issuedAt: 101 },
    { expiresAt: Infinity }, { subject: "" }, { sharedUserId: "" }];
  for (const proof of invalidProofs) {
    assert.equal(applyEvidence(createArbitration(optimistic, context), evidence(lanes[0], "valid", proof), 100).status, "denied");
  }
  for (const bad of [{ sessionId: "other" }, { transactionId: "other" },
    { policyEpoch: 4 }, { sessionEpoch: 8 }, { laneId: "unregistered" }, { kind: "reconciled" }]) {
    assert.equal(applyEvidence(createArbitration(optimistic, context), { ...evidence(lanes[0]), ...bad }, 100).status, "denied");
  }
});

test("deadlines and proof expiry are checked again at admission", () => {
  let state = recordReconciliation(createArbitration(optimistic, context), receipt());
  state = applyEvidence(state, evidence(lanes[0], "valid", { expiresAt: 110 }), 100);
  assert.equal(proofRequirementSatisfied(state, 109), true);
  assert.equal(proofRequirementSatisfied(state, 110), false);
  assert.equal(proofRequirementSatisfied(state, 130), false);
  assert.equal(applyEvidence(state, evidence(lanes[1]), 110).status, "denied");
  assert.equal(applyEvidence(state, evidence(lanes[1]), 130).status, "denied");
  assert.throws(() => applyEvidence(state, evidence(lanes[1]), 99));
});

test("policy compilation blocks downgrade and duplicate-provider substitutions", () => {
  for (const bad of [{ realm: "admin" }, { operation: "sensitive" },
    { mode: "unknown" }, { version: 2 }, { minimumAssurance: 0 },
    { lanes: [lanes[0]] }, { lanes: [lanes[0], { ...lanes[0], id: "copy" }] }]) {
    assert.throws(() => compilePolicy({ ...optimistic, ...bad }));
  }
  assert.throws(() => compilePolicy({ ...strict, operation: "subsystem_grant" }));
  assert.throws(() => compilePolicy({ ...strict, lanes: lanes.slice(0, 2) }));
});

test("subsystem proof requirement cannot be met by an exchanged copy or Neon replacement", () => {
  const subsystem = { ...optimistic, mode: "subsystem-grant", operation: "subsystem_grant",
    lanes: [{ ...lanes[0], proofClass: "native" }, { ...lanes[1], proofClass: "federation-root" }] };
  let state = createArbitration(subsystem, context);
  state = applyEvidence(state, evidence(subsystem.lanes[0], "valid", { ceremonyId: "same-root" }), 100);
  state = applyEvidence(state, evidence(subsystem.lanes[1], "valid", { ceremonyId: "same-root" }), 100);
  assert.equal(state.reason, "dependent_proofs");
  assert.throws(() => compilePolicy({ ...subsystem, lanes: [subsystem.lanes[0], lanes[2]] }));
  const accepted = subsystem.lanes.reduce((current, lane) => applyEvidence(current, evidence(lane), 100), createArbitration(subsystem, context));
  assert.equal(accepted.status, "reconciled");
  assert.equal("roles" in accepted, false);
  assert.equal("grant" in accepted, false);
});

test("duplicate results are idempotent, conflicting duplicates deny, inputs stay immutable", () => {
  const event = evidence(lanes[0]);
  event.proof.roles = ["admin"];
  const state = applyEvidence(createArbitration(optimistic, context), event, 100);
  event.proof.sharedUserId = "changed-after-return";
  assert.equal(state.sharedUserId, "canonical-1");
  assert.equal("roles" in state.evidence[lanes[0].id].proof, false);
  assert.deepEqual(applyEvidence(state, evidence(lanes[0]), 100), state);
  assert.equal(applyEvidence(state, evidence(lanes[0], "degraded"), 100).status, "denied");
  assert.throws(() => { state.policy.lanes[0].issuer = "changed"; });
});

test("all three adapters bind immutable tuples and strip provider-supplied canonical identity", async () => {
  for (const lane of lanes) {
    let tuple;
    const adapter = createReadOnlyAdapter(lane, {
      verify: async () => ({ kind: "valid", proof: evidence(lane).proof }),
      bind: async (input) => {
        tuple = input;
        return { sharedUserId: "bound-by-authority", sessionEpoch: 7, policyEpoch: 3 };
      },
    });
    const event = await adapter.verify("synthetic-credential", { ...context, realm: "customer" });
    assert.deepEqual(tuple, { provider: lane.provider, issuer: lane.issuer,
      subject: `${lane.provider}-subject`, realm: "customer" });
    assert.equal(event.proof.sharedUserId, "bound-by-authority");
    assert.equal(applyEvidence(createArbitration(optimistic, context), event, 100).status, "awaiting_durable_reconciliation");
  }
});

test("adapter distinguishes invalid and unavailable and never binds invalid evidence", async () => {
  const bind = async () => { throw new Error("must not bind invalid evidence"); };
  for (const kind of ["hard_deny", "degraded", "not_applicable"]) {
    const adapter = createReadOnlyAdapter(lanes[0], { verify: async () => ({ kind }), bind });
    assert.equal((await adapter.verify("fixture", { ...context, realm: "customer" })).kind, kind);
  }
  const adapter = createReadOnlyAdapter(lanes[0], {
    verify: async () => { throw new Error("sensitive provider response"); }, bind,
  });
  const event = await adapter.verify("fixture", { ...context, realm: "customer" });
  assert.equal(event.kind, "degraded");
  assert.equal(JSON.stringify(event).includes("sensitive"), false);
  const aborted = new AbortController();
  aborted.abort();
  assert.equal((await adapter.verify("fixture", context, aborted.signal)).kind, "degraded");
});
