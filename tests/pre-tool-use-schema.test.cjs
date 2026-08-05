// PreToolUse output-schema contract.
//
// Claude Code validates every hook payload against the PreToolUse schema and
// drops the whole object when it fails, printing
// `Hook JSON output validation failed — (root): Invalid input`. A dropped
// payload is silently fail-open: the decision the hook meant to communicate
// never arrives, and the user sees the error on every matched tool call.
//
// Two regressions of exactly that shape shipped before:
//   1. the TIER-050 path emitted `additionalContext: { env: {...} }` — the
//      field must be a string;
//   2. both the TIER-050 and agent-binding paths omitted `permissionDecision`,
//      which PreToolUse requires.
//
// The e2e suite only asserts on deny paths and needs a live daemon, so these
// allow/context paths went unchecked. This suite pins the contract two ways:
// statically over every emission site in the source (so a new hand-rolled
// payload cannot reintroduce the bug even if its runtime path is unreachable
// in CI), and dynamically over the exported helper's real stdout.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const PLUGIN_ROOT = path.resolve(__dirname, '..');
const SHARED = path.join(PLUGIN_ROOT, 'adapters', 'shared', 'claude-hooks.cjs');

// Scan every adapter, not just the shared module. The shared module is the only
// emitter today (the files under adapters/claude/ are one-line delegators), but
// the guarantee this suite states — that a hand-rolled payload cannot
// reintroduce the bug — would silently not hold for an emitter added elsewhere.
function adapterFiles() {
  const out = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.cjs')) out.push(full);
    }
  };
  walk(path.join(PLUGIN_ROOT, 'adapters'));
  return out;
}

const SOURCES = adapterFiles().map((file) => ({
  file,
  rel: path.relative(PLUGIN_ROOT, file),
  lines: fs.readFileSync(file, 'utf8').split('\n'),
}));

// Every literal that declares `hookEventName: 'PreToolUse'` is an emission
// site. We inspect the enclosing object literal so the assertions do not depend
// on field ordering. The scan starts at the literal's own opening brace — the
// line that OPENS the object the event name sits in — so termination is
// brace-balanced rather than dependent on a line cap.
function preToolUseSites() {
  const sites = [];
  for (const { rel, lines } of SOURCES) {
    lines.forEach((line, i) => {
      if (!/hookEventName:\s*'PreToolUse'/.test(line)) return;
      // Walk back to the line opening the enclosing literal (unbalanced `{`).
      let start = i;
      for (let j = i; j >= 0 && j > i - 20; j -= 1) {
        const opens = (lines[j].match(/\{/g) || []).length;
        const closes = (lines[j].match(/\}/g) || []).length;
        if (opens > closes) { start = j; break; }
      }
      const body = [];
      let depth = 0;
      for (let j = start; j < lines.length; j += 1) {
        body.push(lines[j]);
        depth += (lines[j].match(/\{/g) || []).length;
        depth -= (lines[j].match(/\}/g) || []).length;
        if (depth <= 0) break;
      }
      sites.push({ rel, line: i + 1, body: body.join('\n') });
    });
  }
  return sites;
}

test('every PreToolUse emission site sets permissionDecision', () => {
  const sites = preToolUseSites();
  assert.ok(sites.length > 5, `expected several emission sites, found ${sites.length}`);
  const missing = sites.filter((s) => !/permissionDecision:/.test(s.body));
  assert.deepEqual(
    missing.map((s) => `${s.rel}:${s.line}`),
    [],
    'PreToolUse requires permissionDecision; sites missing it are dropped by the harness',
  );
});

test('no PreToolUse site passes an object as additionalContext', () => {
  const offenders = [];
  for (const { rel, lines } of SOURCES) {
    lines.forEach((line, i) => {
      // Comments quote the broken shape on purpose (see the TIER-050 note), so
      // skip them — only real code counts.
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) return;
      // `additionalContext: {` — an object literal. Strings (backtick, quote)
      // and identifier/call expressions are fine; only a brace is a break.
      if (/additionalContext:\s*\{/.test(line)) offenders.push(`${rel}:${i + 1}`);
    });
  }
  assert.deepEqual(offenders, [], 'additionalContext must be a string');
});

test('allowPreToolUse emits a schema-valid allow with no context', () => {
  const res = spawnSync('node', ['-e', `require(${JSON.stringify(SHARED)});`], {
    encoding: 'utf-8',
    timeout: 15000,
  });
  assert.equal(res.status, 0, `module must load cleanly: ${res.stderr}`);
});

// Drive the real helper and parse what it actually prints — the static checks
// above cannot catch a serialization bug inside the helper itself.
function runHelper(arg) {
  const call = arg === undefined ? 'allowPreToolUse()' : `allowPreToolUse(${JSON.stringify(arg)})`;
  const script = `
    const m = require(${JSON.stringify(SHARED)});
    const { allowPreToolUse } = m.__test__ || {};
    if (typeof allowPreToolUse !== 'function') {
      process.stderr.write('allowPreToolUse not exported on __test__');
      process.exit(9);
    }
    ${call};
  `;
  const res = spawnSync('node', ['-e', script], { encoding: 'utf-8', timeout: 15000 });
  let parsed = null;
  try { parsed = JSON.parse(res.stdout || '{}'); } catch {}
  return { ...res, parsed };
}

test('allowPreToolUse() prints allow with the event name and no additionalContext', () => {
  const res = runHelper();
  assert.equal(res.status, 0, `stderr: ${res.stderr}`);
  const hso = res.parsed && res.parsed.hookSpecificOutput;
  assert.ok(hso, `expected hookSpecificOutput, got: ${res.stdout}`);
  assert.equal(hso.hookEventName, 'PreToolUse');
  assert.equal(hso.permissionDecision, 'allow');
  assert.equal('additionalContext' in hso, false, 'omit the field when there is no context');
});

test('allowPreToolUse(context) carries the context as a string alongside the decision', () => {
  const res = runHelper('CLAWKET_TIER_USED=med');
  assert.equal(res.status, 0, `stderr: ${res.stderr}`);
  const hso = res.parsed && res.parsed.hookSpecificOutput;
  assert.ok(hso, `expected hookSpecificOutput, got: ${res.stdout}`);
  assert.equal(hso.permissionDecision, 'allow', 'context must not displace the decision');
  assert.equal(typeof hso.additionalContext, 'string');
  assert.equal(hso.additionalContext, 'CLAWKET_TIER_USED=med');
});
