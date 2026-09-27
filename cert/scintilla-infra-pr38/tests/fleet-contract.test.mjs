import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const nix = fs.readFileSync("fleet/nixos/scintilla-runtime.nix", "utf8");
const hive = fs.readFileSync("fleet/colmena-hive.nix", "utf8");
const aws = fs.readFileSync("infra/fleet/aws/main.tf", "utf8");
const gcp = fs.readFileSync("infra/fleet/gcp/main.tf", "utf8");

test("bare-process host keeps security boundaries explicit", () => {
  for (const required of [
    'SCINTILLA_EXECUTOR = "process"',
    "SCINTILLA_ISOLATION_BINARY",
    "NoNewPrivileges = true",
    'ProtectSystem = "strict"',
    'ProtectProc = "invisible"',
    "PrivateDevices = true",
    "MemoryMax = cfg.memoryMax",
    "CPUQuota = cfg.cpuQuota",
    "TasksMax = cfg.tasksMax",
    "LoadCredential",
  ]) {
    assert.ok(nix.includes(required), "missing " + required);
  }
  assert.ok(!/Docker|containerd|firecracker/i.test(nix));
});

test("runtime host paths are evaluated Nix values, never literal interpolation text", () => {
  assert.ok(!nix.includes("\\${"), "escaped Nix interpolation would emit literal runtime paths");
  for (const required of [
    'users.users.${cfg.runtimeUser}',
    '"d ${cfg.stateRoot} 0750 ${cfg.runtimeUser} scintilla -"',
    'SCINTILLA_ISOLATION_BINARY = "${cfg.isolationPackage}/bin/${cfg.isolationBinary}"',
    'ExecStart = "${cfg.runnerPackage}/bin/${cfg.runnerBinary}"',
    'LoadCredential = lib.mapAttrsToList (name: path: "${name}:${path}") cfg.credentialFiles',
  ]) {
    assert.ok(nix.includes(required), "missing evaluated interpolation: " + required);
  }
});

test("fenced lifecycle control is opt-in, scoped, and fail-closed", () => {
  for (const required of [
    'enable = lib.mkEnableOption "fenced Scintilla runtime hibernation/resume control"',
    'default = "cloudflare_durable_object"',
    'lifecycleKeyPrefix = "scintilla/runtime-lifecycle"',
    'lifecycleCheckpointRoot = "${cfg.stateRoot}/hibernation"',
    '"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[^[:space:]]*)?$"',
    'builtins.hasAttr cfg.lifecycle.credentialName cfg.credentialFiles',
    'builtins.hasAttr "SCINTILLA_REGION" cfg.environment',
    'cfg.environment.SCINTILLA_REGION or ""',
    'cfg.lifecycle.environmentName != null',
    'cfg.lifecycle.credentialName != null',
    'cfg.lifecycle.hibernateAfterMs > cfg.lifecycle.warmIdleMs',
    '(cfg.lifecycle.renewEveryMs * 2) <= cfg.lifecycle.leaseTtlMs',
    'SCINTILLA_LIFECYCLE_ENABLED = "1"',
    'SCINTILLA_LIFECYCLE_PROVIDER = cfg.lifecycle.provider',
    'SCINTILLA_LIFECYCLE_KEY_PREFIX = lifecycleKeyPrefix',
    'SCINTILLA_LIFECYCLE_CREDENTIAL_NAME = cfg.lifecycle.credentialName',
    'SCINTILLA_LIFECYCLE_CHECKPOINT_ROOT = lifecycleCheckpointRoot',
    '"d ${lifecycleCheckpointRoot} 0700 ${cfg.runtimeUser} scintilla -"',
  ]) {
    assert.ok(nix.includes(required), "missing lifecycle boundary: " + required);
  }

  assert.ok(nix.includes("ProtectControlGroups = true"));
  assert.ok(!nix.includes("ProtectControlGroups = false"));
  assert.ok(!nix.includes("Delegate = true"));
  assert.ok(!nix.includes("SCINTILLA_LIFECYCLE_TOKEN"));
  assert.ok(!nix.includes("ORES_LOCKS_API_TOKEN ="));
  assert.ok(!nix.includes("checkpointRoot = lib.mkOption"));
  assert.ok(!nix.includes("leaseKeyPrefix = lib.mkOption"));
});

test("colmena carries region and cloud identity", () => {
  assert.ok(hive.includes("SCINTILLA_REGION"));
  assert.ok(hive.includes("SCINTILLA_CLOUD"));
  assert.ok(hive.includes("credentialFiles"));
});

test("cloud modules default to private hardened runtime nodes", () => {
  assert.ok(aws.includes("map_public_ip_on_launch = false"));
  assert.ok(aws.includes('http_tokens                 = "required"'));
  assert.ok(aws.includes("encrypted = true"));
  assert.ok(gcp.includes("enable_secure_boot          = true"));
  assert.ok(gcp.includes("enable_vtpm                 = true"));
  assert.ok(gcp.includes("block-project-ssh-keys"));
});

test("fleet variables contain no secret-shaped inputs", () => {
  const all = [
    fs.readFileSync("infra/fleet/aws/variables.tf", "utf8"),
    fs.readFileSync("infra/fleet/gcp/variables.tf", "utf8"),
  ].join("\\n");
  assert.ok(!/variable\\s+"[^"]*(secret|token|password|credential|private_key)[^"]*"/i.test(all));
});
