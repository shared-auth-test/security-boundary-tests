/** Internal verified-evidence boundary. Never deserialize this API from HTTP.
 * Crypto verification, canonical binding, and durable storage are injected by
 * trusted server code. This module grants no roles, scopes, or product access.
 */
const PROVIDERS = ["shared-auth", "supabase", "neon"];
const MODES = ["customer-optimistic", "strict-provider-pair", "subsystem-grant"];
const RESULTS = ["valid", "hard_deny", "degraded", "not_applicable"];

function requireValue(condition, message) {
  if (!condition) {
    throw new TypeError(message);
  }
}

function text(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 512
    && value.trim() === value && !/[\u0000-\u001f\u007f]/u.test(value);
}

function integer(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function https(value) {
  try {
    const url = new URL(value);
    return text(value) && url.protocol === "https:" && !url.username
      && !url.password && !url.hash && !url.search;
  } catch {
    return false;
  }
}

function freeze(value) {
  if (value && typeof value === "object") {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}

function validateLane(lane) {
  requireValue(lane && text(lane.id) && PROVIDERS.includes(lane.provider), "invalid lane");
  requireValue(https(lane.issuer) && text(lane.audience), "invalid lane trust anchor");
  requireValue(["provider", "native", "federation-root"].includes(lane.proofClass), "invalid proof class");
  requireValue(lane.proofClass !== "native" || lane.provider === "shared-auth", "native proof provider");
  requireValue(lane.proofClass !== "federation-root" || lane.provider === "supabase", "root proof provider");
  return { id: lane.id, provider: lane.provider, issuer: lane.issuer,
    audience: lane.audience, proofClass: lane.proofClass };
}

export function compilePolicy(input) {
  requireValue(input && input.version === 1 && MODES.includes(input.mode), "unsupported proof policy");
  requireValue(["customer", "admin"].includes(input.realm), "invalid realm");
  requireValue(["authentication_read", "sensitive", "subsystem_grant"].includes(input.operation), "invalid operation");
  requireValue(Array.isArray(input.lanes) && input.lanes.length >= 2 && input.lanes.length <= 3, "invalid lane count");
  const lanes = input.lanes.map(validateLane);
  requireValue(new Set(lanes.map((lane) => lane.id)).size === lanes.length, "duplicate lane");
  requireValue(new Set(lanes.map((lane) => lane.provider)).size === lanes.length, "duplicate provider");
  requireValue(integer(input.minimumAssurance) && input.minimumAssurance >= 1
    && input.minimumAssurance <= 2, "invalid assurance");
  if (input.mode === "customer-optimistic") {
    requireValue(input.realm === "customer" && input.operation === "authentication_read", "optimistic policy restricted to customer reads");
  } else if (input.mode === "strict-provider-pair") {
    requireValue(input.operation !== "subsystem_grant" && lanes.length === 2
      && lanes.some((lane) => lane.provider === "supabase")
      && lanes.some((lane) => lane.provider === "neon"), "strict pair requires Supabase and Neon");
  } else {
    requireValue(input.realm === "customer" && input.operation === "subsystem_grant"
      && lanes.length === 2 && lanes.some((lane) => lane.proofClass === "native")
      && lanes.some((lane) => lane.proofClass === "federation-root"), "subsystem requires independent native and root proofs");
  }
  return freeze({ version: 1, mode: input.mode, realm: input.realm,
    operation: input.operation, minimumAssurance: input.minimumAssurance, lanes });
}

export function createArbitration(input, context) {
  const policy = compilePolicy(input);
  requireValue(context && text(context.sessionId) && text(context.transactionId)
    && integer(context.sessionEpoch) && integer(context.policyEpoch), "invalid arbitration context");
  requireValue(integer(context.now) && integer(context.deadline) && context.deadline > context.now
    && context.deadline - context.now <= 300, "invalid bounded deadline");
  return freeze({ policy, context: { sessionId: context.sessionId,
    transactionId: context.transactionId, sessionEpoch: context.sessionEpoch,
    policyEpoch: context.policyEpoch, now: context.now, deadline: context.deadline },
  status: "pending", evidence: {}, winner: null, sharedUserId: null,
  reconciliationId: null, reason: null });
}

function deny(state, reason) {
  return freeze({ ...state, status: "denied", reason });
}

function sameContext(state, event) {
  return event.sessionId === state.context.sessionId
    && event.transactionId === state.context.transactionId
    && event.sessionEpoch === state.context.sessionEpoch
    && event.policyEpoch === state.context.policyEpoch;
}

function validProof(state, lane, proof, now) {
  return proof && proof.provider === lane.provider && proof.issuer === lane.issuer
    && proof.audience === lane.audience && proof.realm === state.policy.realm
    && proof.proofClass === lane.proofClass && text(proof.subject)
    && text(proof.sharedUserId) && text(proof.ceremonyId)
    && integer(proof.assurance) && proof.assurance >= state.policy.minimumAssurance
    && proof.assurance <= 2 && integer(proof.issuedAt) && proof.issuedAt <= now
    && integer(proof.expiresAt) && proof.expiresAt > now
    && proof.expiresAt > proof.issuedAt;
}

/** Pure reducer: final decisions are independent of provider completion order.
 * The first winner is provenance only. A denial is terminal for this context.
 */
export function applyEvidence(state, event, now) {
  if (state.status === "denied") {
    return state;
  }
  requireValue(integer(now) && now >= state.context.now, "non-monotonic clock");
  if (!event || !sameContext(state, event)) {
    return deny(state, "context_mismatch");
  }
  const lane = state.policy.lanes.find((item) => item.id === event.laneId);
  if (!lane || !RESULTS.includes(event.kind)) {
    return deny(state, "invalid_evidence");
  }
  if (now >= state.context.deadline) {
    return deny(state, "deadline_elapsed");
  }
  if (event.kind === "hard_deny") {
    return deny(state, "authority_denied");
  }
  if (event.kind === "valid" && !validProof(state, lane, event.proof, now)) {
    return deny(state, "invalid_proof_binding");
  }
  // Copy only the reviewed projection: provider roles/contact data never escape.
  const proof = event.kind === "valid" ? Object.fromEntries([
    "provider", "issuer", "audience", "realm", "proofClass", "subject",
    "sharedUserId", "ceremonyId", "assurance", "issuedAt", "expiresAt",
  ].map((key) => [key, event.proof[key]])) : undefined;
  const normalized = proof ? { kind: event.kind, proof } : { kind: event.kind };
  const previous = Object.hasOwn(state.evidence, lane.id) ? state.evidence[lane.id] : undefined;
  if (previous && JSON.stringify(previous) !== JSON.stringify(normalized)) {
    return deny(state, "conflicting_lane_result");
  }
  const evidence = { ...state.evidence, [lane.id]: normalized };
  const valid = Object.values(evidence).filter((item) => item.kind === "valid");
  if (valid.some((item) => item.proof.expiresAt <= now)) {
    return deny(state, "expired_evidence");
  }
  if (new Set(valid.map((item) => item.proof.sharedUserId)).size > 1) {
    return deny(state, "identity_conflict");
  }
  if (state.policy.mode === "subsystem-grant" && valid.length === 2
      && new Set(valid.map((item) => item.proof.ceremonyId)).size !== 2) {
    return deny(state, "dependent_proofs");
  }
  const complete = valid.length === state.policy.lanes.length;
  const optimistic = state.policy.mode === "customer-optimistic" && valid.length > 0;
  const status = complete ? "reconciled"
    : optimistic ? (state.reconciliationId ? "optimistic" : "awaiting_durable_reconciliation")
      : Object.keys(evidence).length === state.policy.lanes.length ? "degraded" : "pending";
  return freeze({ ...state, context: { ...state.context, now }, evidence, status,
    winner: state.winner ?? (proof ? lane.id : null),
    sharedUserId: valid[0]?.proof.sharedUserId ?? null });
}

/** Call only after the durable outbox/queue acknowledges this exact transaction.
 * A receipt is trusted backend input, never a caller-supplied boolean/header.
 */
export function recordReconciliation(state, receipt) {
  if (state.status === "denied") {
    return state;
  }
  if (!receipt || !sameContext(state, receipt) || !text(receipt.eventId)) {
    return deny(state, "invalid_reconciliation_receipt");
  }
  if (state.reconciliationId && state.reconciliationId !== receipt.eventId) {
    return deny(state, "conflicting_reconciliation_receipt");
  }
  return freeze({ ...state, reconciliationId: receipt.eventId,
    status: state.status === "awaiting_durable_reconciliation" ? "optimistic" : state.status });
}

/** Even reconciled evidence is not authorization: enrollment, exact OAuth
 * transaction bindings, fresh revocation checks and product permissions remain
 * mandatory at their owning commit boundary.
 */
export function proofRequirementSatisfied(state, now) {
  requireValue(integer(now) && now >= state.context.now, "non-monotonic clock");
  if (now >= state.context.deadline || Object.values(state.evidence).some(
    (item) => item.kind === "valid" && item.proof.expiresAt <= now,
  )) {
    return false;
  }
  return state.status === "reconciled" || (state.status === "optimistic"
    && state.policy.mode === "customer-optimistic" && Boolean(state.reconciliationId));
}

/** Provider-specific crypto/transport stays behind verify. It must classify
 * invalid credentials as hard_deny, outages as degraded, and verify signatures
 * before returning valid. bind resolves the immutable tuple without email.
 * No login, refresh, code redemption, exchange or revocation callback belongs here.
 */
export function createReadOnlyAdapter(laneInput, { verify, bind }) {
  const lane = freeze(validateLane(laneInput));
  requireValue(typeof verify === "function" && typeof bind === "function", "adapter dependencies required");
  return freeze({ lane, async verify(credential, context, signal) {
    const envelope = { laneId: lane.id, sessionId: context.sessionId,
      transactionId: context.transactionId, sessionEpoch: context.sessionEpoch,
      policyEpoch: context.policyEpoch };
    try {
      if (signal?.aborted) {
        return { ...envelope, kind: "degraded" };
      }
      const result = await verify(credential, signal);
      if (!result || !RESULTS.includes(result.kind)) {
        return { ...envelope, kind: "hard_deny" };
      }
      if (result.kind !== "valid") {
        return { ...envelope, kind: result.kind };
      }
      const evidence = result.proof;
      if (!evidence || evidence.provider !== lane.provider || evidence.issuer !== lane.issuer
          || evidence.audience !== lane.audience || evidence.realm !== context.realm
          || evidence.proofClass !== lane.proofClass || !text(evidence.subject)) {
        return { ...envelope, kind: "hard_deny" };
      }
      const identity = await bind({ provider: lane.provider, issuer: lane.issuer,
        subject: evidence.subject, realm: context.realm }, context, signal);
      if (!identity || !text(identity.sharedUserId)
          || identity.sessionEpoch !== context.sessionEpoch
          || identity.policyEpoch !== context.policyEpoch) {
        return { ...envelope, kind: "hard_deny" };
      }
      if (signal?.aborted) {
        return { ...envelope, kind: "degraded" };
      }
      const proof = Object.fromEntries(["provider", "issuer", "audience", "realm", "proofClass",
        "subject", "ceremonyId", "assurance", "issuedAt", "expiresAt"].map((key) => [key, evidence[key]]));
      return { ...envelope, kind: "valid", proof: { ...proof, sharedUserId: identity.sharedUserId } };
    } catch {
      // Exceptions are indeterminate; never expose provider errors or tokens.
      return { ...envelope, kind: "degraded" };
    }
  } });
}
