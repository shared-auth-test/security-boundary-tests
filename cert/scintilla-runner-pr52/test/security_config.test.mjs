import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const flags = readFileSync(new URL('../.cli-flags.toml', import.meta.url), 'utf8');
const ci = readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8');
const deployment = readFileSync(new URL('../k8s/ec2/dd-gleam-lambda-runner.deployment.yaml', import.meta.url), 'utf8');
const childRunner = readFileSync(new URL('../src/lambda_child_runner.erl', import.meta.url), 'utf8');

function flagSection(name) {
  const marker = `[flags.${name}]`;
  const start = flags.indexOf(marker);
  assert.notEqual(start, -1, `missing ${marker}`);
  const next = flags.indexOf('\n[flags.', start + marker.length);
  return flags.slice(start, next === -1 ? flags.length : next);
}

test('host runtime execution stays opt-in', () => {
  const section = flagSection('lambda_allow_host_runtimes');
  assert.match(section, /env\s*=\s*"LAMBDA_ALLOW_HOST_RUNTIMES"/);
  assert.doesNotMatch(section, /^default\s*=\s*"?nodejs"?\s*$/m);
});


test('hostile native execution is argv-only and clears ambient env', () => {
  assert.match(childRunner, /native_host_spawn_spec\(Runtime\)/);
  assert.match(childRunner, /\{ok, \{exec, Launcher, \[Policy, Runtime\], \[\]\}\}/);
  assert.match(childRunner, /open_port\(\{spawn_executable, binary_to_list\(Executable\)\}/);
  assert.match(childRunner, /clean_port_environment\(Env\)/);
  assert.match(childRunner, /\{Name, false\}/);
  assert.doesNotMatch(childRunner, /isolated_host_command\(/);
  assert.doesNotMatch(childRunner, /<runtime-command>/);
});

test('native startup no longer exposes host-command override flags', () => {
  for (const name of [
    'lambda_nodejs_host_command',
    'lambda_python3_host_command',
    'lambda_ruby_host_command',
    'lambda_bash_host_command',
    'lambda_browser_host_command',
  ]) {
    assert.equal(flags.includes(`[flags.${name}]`), false, name);
  }
});

test('nested container execution stays opt-in', () => {
  const section = flagSection('lambda_container_execution_enabled');
  assert.match(section, /type\s*=\s*"boolean"/);
  assert.match(section, /^default\s*=\s*false\s*$/m);
  assert.match(childRunner, /LAMBDA_CONTAINER_EXECUTION_ENABLED/);
});

test('legacy EC2 runner has no node containerd authority', () => {
  assert.match(deployment, /name:\s+LAMBDA_CONTAINER_EXECUTION_ENABLED[\s\S]*?value:\s+'false'/);
  assert.doesNotMatch(deployment, /LAMBDA_CONTAINER_NETWORK[\s\S]*?value:\s+host/);
  assert.doesNotMatch(deployment, /LAMBDA_ALLOW_CONTAINER_HOST_NETWORK[\s\S]*?value:\s+'true'/);
  assert.doesNotMatch(deployment, /hostPath:\s*\n\s+path:\s+\/run\/containerd/);
  assert.doesNotMatch(deployment, /hostPath:\s*\n\s+path:\s+\/var\/lib\/containerd/);
});

test('host-networked containers require an explicit acknowledgement', () => {
  const section = flagSection('lambda_allow_container_host_network');
  assert.match(section, /type\s*=\s*"boolean"/);
  assert.match(section, /^default\s*=\s*false\s*$/m);
});

test('per-function JavaScript sandboxes remain bounded', () => {
  const section = flagSection('lambda_sandbox_cache_max');
  assert.match(section, /type\s*=\s*"integer"/);
  assert.match(section, /^default\s*=\s*64\s*$/m);
});

test('source formatting is a required CI gate', () => {
  const formatJob = ci.match(/\n  fmt:[\s\S]*?(?=\n  [a-zA-Z0-9_-]+:|$)/)?.[0];
  assert.ok(formatJob, 'fmt job must exist');
  assert.doesNotMatch(formatJob, /continue-on-error:\s*true/);
  assert.match(formatJob, /gleam format --check src test/);
});
