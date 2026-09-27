import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const nix = await readFile("deploy/baremetal/nixos/bmscl-lifecycle-agent.nix", "utf8");
const docs = await readFile("deploy/baremetal/process-lifecycle.md", "utf8");
const readme = await readFile("deploy/baremetal/README.md", "utf8");

for (const required of [
  'stateRoot = "/var/lib/beamscale/lifecycle"',
  'managedCgroupRoot = "/sys/fs/cgroup/beamscale-workloads.slice"',
  'lifecycleKeyPrefix = "beamscale/runtime-lifecycle"',
  'type = lib.types.enum [ "cloudflare_durable_object" "fiducia" ]',
  '"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[^[:space:]]*)?$"',
  'builtins.hasAttr cfg.credentialName cfg.credentialFiles',
  'ORES_PROCESS_LIFECYCLE_LEASE_KEY_PREFIX = lifecycleKeyPrefix',
  'ORES_PROCESS_LIFECYCLE_CREDENTIAL_NAME = cfg.credentialName',
  'ORES_PROCESS_LIFECYCLE_EFFECTS = "freeze_thaw"',
  'CapabilityBoundingSet = [ ]',
  'AmbientCapabilities = [ ]',
  'ReadOnlyPaths = [ "/sys/fs/cgroup" ]',
  'managedCgroupRoot',
  'RestrictNamespaces = true',
]) {
  assert.ok(nix.includes(required), `missing hardened lifecycle invariant: ${required}`);
}

for (const forbidden of [
  "stateRoot = lib.mkOption",
  "checkpointRoot = lib.mkOption",
  "managedCgroupRoot = lib.mkOption",
  "ORES_PROCESS_LIFECYCLE_CHECKPOINT_ROOT",
  "ORES_PROCESS_LIFECYCLE_EFFECTS = \"checkpoint",
  'ReadWritePaths = [ "/sys/fs/cgroup" ]',
]) {
  assert.ok(!nix.includes(forbidden), `forbidden lifecycle authority: ${forbidden}`);
}

assert.ok(
  /ReadWritePaths = \[[\s\S]*stateRoot[\s\S]*managedCgroupRoot[\s\S]*\];/.test(nix),
  "write authority must be limited to lifecycle state + fixed workload cgroup subtree",
);

for (const required of [
  "ORESoftware/ores-locks-and-leases",
  "merged PR #127",
  "beamscale/runtime-lifecycle/<environment>/<region>/<runtime-id>",
  "fresh logical request",
  "fencing token is newer",
  "separately reviewed checkpoint helper",
]) {
  assert.ok(docs.includes(required), `lifecycle docs missing: ${required}`);
}

assert.ok(!docs.includes("process-lifecycle/beamscale/"));
assert.ok(!docs.includes("ores-otel/ores-otel-sidecar.rs"));
assert.ok(readme.includes("freeze agent receives no checkpoint/ptrace/mount/kernel"));
assert.match(
  readme,
  /fixed `beamscale-workloads\.slice` cgroup\s+subtree/,
);

console.log("BeamScale lifecycle agent contract: hardened freeze/thaw boundary ok");
