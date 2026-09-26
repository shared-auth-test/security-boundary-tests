export type Provider = "shared-auth" | "supabase" | "neon";
export type Realm = "customer" | "admin";
export type ProofClass = "provider" | "native" | "federation-root";
export interface Lane {
  readonly id: string;
  readonly provider: Provider;
  readonly issuer: string;
  readonly audience: string;
  readonly proofClass: ProofClass;
}
interface PolicyBase {
  readonly version: 1;
  readonly minimumAssurance: 1 | 2;
  readonly lanes: readonly Lane[];
}
export type Policy = PolicyBase & (
  | { readonly mode: "customer-optimistic"; readonly realm: "customer"; readonly operation: "authentication_read" }
  | { readonly mode: "strict-provider-pair"; readonly realm: Realm; readonly operation: "authentication_read" | "sensitive" }
  | { readonly mode: "subsystem-grant"; readonly realm: "customer"; readonly operation: "subsystem_grant" }
);
export interface ContextBinding {
  readonly sessionId: string;
  readonly transactionId: string;
  readonly sessionEpoch: number;
  readonly policyEpoch: number;
}
export interface Context extends ContextBinding {
  /** Integer Unix seconds; deadline is exclusive and at most 300 seconds away. */
  readonly now: number;
  readonly deadline: number;
}
export interface VerifiedProof {
  readonly provider: Provider;
  readonly issuer: string;
  readonly audience: string;
  readonly realm: Realm;
  readonly proofClass: ProofClass;
  readonly subject: string;
  readonly sharedUserId: string;
  /** Trusted ceremony lineage; reissuing a proof preserves its origin. */
  readonly ceremonyId: string;
  readonly assurance: 1 | 2;
  readonly issuedAt: number;
  readonly expiresAt: number;
}
export type Outcome =
  | { readonly kind: "valid"; readonly proof: VerifiedProof }
  | { readonly kind: "hard_deny" | "degraded" | "not_applicable" };
export type Evidence = ContextBinding & { readonly laneId: string } & Outcome;
export interface ReconciliationReceipt extends ContextBinding {
  readonly eventId: string;
}
export interface Arbitration {
  readonly policy: Policy;
  readonly context: Context;
  readonly status: "pending" | "awaiting_durable_reconciliation" | "optimistic" | "reconciled" | "degraded" | "denied";
  readonly evidence: Readonly<Record<string, Outcome>>;
  readonly winner: string | null;
  readonly sharedUserId: string | null;
  readonly reconciliationId: string | null;
  readonly reason: string | null;
}
export function compilePolicy(input: Policy): Policy;
export function createArbitration(policy: Policy, context: Context): Arbitration;
export function applyEvidence(state: Arbitration, event: Evidence, now: number): Arbitration;
export function recordReconciliation(state: Arbitration, receipt: ReconciliationReceipt): Arbitration;
/** Satisfies only this proof requirement, never product authorization. */
export function proofRequirementSatisfied(state: Arbitration, now: number): boolean;
export type ProviderOutcome =
  | { readonly kind: "valid"; readonly proof: Omit<VerifiedProof, "sharedUserId"> }
  | { readonly kind: "hard_deny" | "degraded" | "not_applicable" };
export interface AdapterContext extends ContextBinding { readonly realm: Realm }
export interface AdapterDependencies<Credential> {
  readonly verify: (credential: Credential, signal?: AbortSignal) => Promise<ProviderOutcome>;
  readonly bind: (
    identity: Pick<VerifiedProof, "provider" | "issuer" | "subject" | "realm">,
    context: AdapterContext,
    signal?: AbortSignal,
  ) => Promise<{ readonly sharedUserId: string; readonly sessionEpoch: number; readonly policyEpoch: number } | null>;
}
export interface ReadOnlyAdapter<Credential> {
  readonly lane: Lane;
  readonly verify: (credential: Credential, context: AdapterContext, signal?: AbortSignal) => Promise<Evidence>;
}
export function createReadOnlyAdapter<Credential>(lane: Lane, dependencies: AdapterDependencies<Credential>): ReadOnlyAdapter<Credential>;
