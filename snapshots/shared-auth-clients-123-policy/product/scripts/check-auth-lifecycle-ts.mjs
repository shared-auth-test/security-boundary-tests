#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const model = JSON.parse(
  readFileSync(join(root, "formal", "auth-lifecycle.json"), "utf8"),
);
const source = readFileSync(
  join(root, "clients", "ts", "src", "auth_lifecycle.ts"),
  "utf8",
);

const fail = (message) => {
  console.error(`auth-lifecycle TypeScript projection: FAILED: ${message}`);
  process.exit(1);
};

const block = (start, end) => {
  const from = source.indexOf(start);
  if (from === -1) fail(`missing ${start}`);
  const to = source.indexOf(end, from + start.length);
  if (to === -1) fail(`missing ${end}`);
  return source.slice(from + start.length, to);
};

const events = [...block(
  "export const AUTH_LIFECYCLE_EVENTS = [",
  "] as const satisfies readonly AuthLifecycleEvent[];",
).matchAll(/"([A-Za-z][A-Za-z0-9]*)"/g)].map((match) => match[1]);

const states = [...block(
  "const STATE_INFO: Readonly<Record<AuthLifecycleState, AuthLifecycleStateInfo>> = {",
  "\n};\n\ntype TransitionTarget",
).matchAll(
  /^\s*([A-Za-z][A-Za-z0-9]*): \{ hasCredential: (true|false), operationInFlight: (true|false), allowsAuthenticatedApi: (true|false), allowsPrivilegedApi: (true|false) \},$/gm,
)].map((match) => ({
  name: match[1],
  hasCredential: match[2] === "true",
  operationInFlight: match[3] === "true",
  allowsAuthenticatedApi: match[4] === "true",
  allowsPrivilegedApi: match[5] === "true",
}));

const transitions = [...block(
  "const ACCEPTED: Readonly<Record<string, TransitionTarget>> = {",
  "\n};\n\nexport function authLifecycleStateInfo",
).matchAll(
  /^\s*"([A-Za-z][A-Za-z0-9]*)\|([A-Za-z][A-Za-z0-9]*)": \["([A-Za-z][A-Za-z0-9]*)", "([A-Za-z][A-Za-z0-9]*)"\],$/gm,
)].map((match) => ({
  from: match[1],
  event: match[2],
  to: match[3],
  effect: match[4],
}));

const projected = {
  schemaVersion: model.schemaVersion,
  initialState: model.initialState,
  states,
  events,
  effects: model.effects,
  transitions,
};

const stable = (value) => {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stable(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
};

if (stable(projected) !== stable(model)) {
  fail(
    `source projection differs from formal/auth-lifecycle.json ` +
      `(states=${states.length}, events=${events.length}, transitions=${transitions.length})`,
  );
}

const fingerprint = createHash("sha256").update(stable(model)).digest("hex");
if (!source.includes(`"${fingerprint}" as const`)) {
  fail(`fingerprint constant is stale; expected ${fingerprint}`);
}

console.log(
  `auth-lifecycle TypeScript projection: OK ` +
    `(${states.length} states, ${events.length} events, ${transitions.length} accepted transitions, ${fingerprint})`,
);
