# BeamScale bare-process fleet

This backend runs BeamScale on a small NixOS fleet without Kubernetes, containers, or mandatory microVMs.

## Responsibilities

- Cloud IaC owns machines, networking, disks, IAM/service identities, DNS and load balancers.
- NixOS owns the complete host configuration.
- Colmena owns stateless multi-host rollout/activation.
- `ores-proc-isolation-cli` owns the mandatory OS process sandbox for tenant-influenced workloads.
- `bmscl-supervisor` owns trusted BEAM supervision, generation selection, hot rollout/drain and capability mediation.
- `bmscl-lifecycle-agent` is the external host authority for fenced freeze/thaw; it is never placed in the suspendable workload cgroup subtree. RAM-reclaiming checkpoint/restore requires a separately reviewed typed adapter and is not granted to the freeze agent.

The intended production fleet is 3-9 hosts distributed across at least two regions/failure domains. Region-local quorum/state services must not depend on WAN-synchronous consensus unless explicitly designed for it.

## Idle process lifecycle

See `process-lifecycle.md` for the runtime-state, fencing, placement-epoch, wake-on-demand, and shard-reassignment contract.

`nixos/bmscl-lifecycle-agent.nix` defines the host service and a dedicated
`beamscale-workloads.slice`. The module is intentionally standalone until the
fleet's Colmena wrapper imports an exact shared lifecycle-agent package. The first
lease backend is Cloudflare Durable Objects through
`ORESoftware/ores-locks-and-leases`; BeamScale-native locking is a future backend
swap, not a dependency of the lifecycle policy.

Start with cgroup freeze/thaw for warm-idle runtimes. That reclaims scheduling
CPU but keeps RSS. The freeze agent receives no checkpoint/ptrace/mount/kernel
capabilities and can write only the fixed `beamscale-workloads.slice` cgroup
subtree. True hibernation (checkpoint + terminate) must use a separately reviewed
typed helper/adapter only for explicitly compatible execution classes.

## Isolation policy

`.ores-proc-isolation.yaml` is checked in beside this document. Validate it with the matching pinned `ores-proc-isolation-cli` before deployment. Production automation must record the policy file digest and isolation-tool version/commit used for admission.

The current policy uses only capabilities supported by the isolation CLI v1 schema. Independent host-level cgroup/systemd/NixOS controls should add memory/PID/CPU ceilings; do not invent unsupported YAML fields and assume they are enforced.

Tenant-worker launches must enable the isolation CLI's reviewed BeamScale tripwire mode. The policy exposes only the exact inert-wrapper directory and Unix socket, and replaces tenant `PATH` with the wrapper directory:

```bash
ores-proc-isolation doctor \
  --beamscale-honeypot \
  --config deploy/baremetal/.ores-proc-isolation.yaml

ores-proc-isolation run bmscl-worker \
  --beamscale-honeypot \
  --config deploy/baremetal/.ores-proc-isolation.yaml
```

Do not broaden these mounts to `/opt`, `/run`, `/bin`, `/sbin`, `/usr/bin`, or `/usr/sbin`. The isolation CLI independently rejects those broad paths in BeamScale honeypot mode.

A customer worker must never be launched if:

- the isolation policy cannot be parsed or validated;
- the requested process/profile is missing or ambiguous;
- the expected policy/tool digest differs from the installed copy;
- the host cannot enforce the required sandbox backend;
- `--beamscale-honeypot` is absent for a tenant-worker launch or the exact tripwire directory/socket fails the isolation CLI doctor checks;
- the executable/artifact digest is not admitted;
- a requested capability is broader than the release policy.

## Density rule

Prefer one trusted BEAM runtime to multiplex many lightweight admitted actors/processes where policy permits. Do not create one operating-system process per request merely for symmetry with other lambda platforms; the BeamScale advantage is amortizing the BEAM runtime while preserving per-invocation actor supervision and metering.

OS process boundaries are used where they materially improve tenant/runtime containment. Erlang actor isolation provides additional fault/resource structure inside that boundary, not a substitute for it.
