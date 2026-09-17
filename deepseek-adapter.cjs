#!/usr/bin/env node
'use strict';
// Adapter for the DeepSeek Harness (`dsh`) over its own web automation
// protocol — the same one the dsh desktop/browser UI speaks: unary JSON-RPC
// over HTTP (POST /api/<method>) plus a downlink WebSocket (/api/events.mux)
// carrying the full internal session event stream (token-level text deltas,
// reasoning deltas, tool calls/results, approvals).
//
// Why this transport and not the ACP stdio bridge: the bridge deliberately
// keeps reasoning and raw chunks off the wire ("committed-message output"),
// while the web protocol is the full-fidelity surface dsh's own UI runs on.
// Nothing in the dsh checkout is patched.
//
// Installation: the plugin ships its own dsh runtime (a deploy closure of the
// pinned release) next to this adapter; the manifest names its entry point.
//
// Process model: this adapter spawns one dedicated `dsh web` server per bus
// session, under an ISOLATED DSH_HOME (<PRTS_AGENT_DATA_DIR>/dsh-home). The
// home is bootstrapped idempotently on every boot:
//   - profiles/web/*       minimal profile mounting the dsh-base + web-app
//                          bundles (no plugins are authored here);
//   - settings.yaml        private scope: migrated from the user's own
//                          ~/.dsh/settings.yaml (settings only carry
//                          apiKeyEnv REFS, never secret values) with
//                          permission.defaultPreset FORCED to workspace-write.
//                          system scope: the REAL ~/.dsh is used as-is; the
//                          adapter only adds a missing profiles/web and never
//                          rewrites the user's settings. Approvals protection
//                          is then enforced by refusing session/start when the
//                          user's own preset disables it (never by silently
//                          editing the shared global config).
//
// Configuration face (PROTOCOL §6): connections/auth/models/credentials methods
// are bridged to dsh's native settings.*, credentials.*, llm.* RPCs. Secrets
// NEVER ride this path to disk: apiKeyEnv references are what get persisted;
// values live in the shell keychain and cross into dsh's process env via
// credentials/grant (re-granted every spawn). connections/validate uses
// llm.discoverModels whose apiKey is write-only at the host ("never stored and
// never returned").
//
// Bus contract (same as every adapter):
//   - session/start → boots the server, creates (or resumes) a session,
//     reports the dsh session id as result.ref. Resume is REAL here: dsh
//     persists sessions under DSH_HOME and a known id reattaches to its
//     history. An unknown ref fails loudly — never a silent fresh session.
//   - session/prompt → one turn: turn_started, text_delta / reasoning_delta
//     streams, tool_started / tool_end, then message_end (aggregated text)
//     and turn_end {status: completed|aborted|failed}.
//   - session/abort → session.cancel.
//   - approval_need {approval_id, respond_rpc_id} ← dsh's approval/requested
//     frame; the core answers {approved}; the adapter maps that to the
//     allowed-once / rejected outcome via POST /api/respond.
//   - stdin closed → kill the server, exit(0)   (contract: die with the core)

const { spawn, spawnSync } = require('child_process');
const http = require('http');
const https = require('https');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PLUGIN_DIR = __dirname;
const DATA_DIR = process.env.PRTS_AGENT_DATA_DIR;
const CWD = process.env.PRTS_CWD;
// Extra roots the caller asked for (ACP calls these additionalDirectories).
// The core passes them through; whether this harness can use them is decided
// here, not by the core. We forward them and REPORT what happened rather than
// dropping them silently.
const ADDITIONAL_DIRS = JSON.parse(process.env.PRTS_ADDITIONAL_DIRS || '[]');
if (!DATA_DIR) {
  die('PRTS_AGENT_DATA_DIR not set: the core must provide a data dir; refusing to write runtime data next to plugin code');
}
if (!CWD) {
  die('PRTS_CWD not set: the core must provide the user project cwd');
}
fs.mkdirSync(DATA_DIR, { recursive: true });

function die(msg) {
  process.stderr.write(`deepseek-adapter: ${msg}\n`);
  process.exit(1);
}

function send(o) { process.stdout.write(JSON.stringify(o) + '\n'); }

// --- the runtime this plugin drives -----------------------------------------
// The manifest declares it; the host hands the declaration over as argv. This
// plugin owns its runtime (a deploy closure of the pinned dsh release next to
// this adapter), so nothing is found on the machine and no checkout path is
// read: whatever the manifest names is what runs.
const rawRuntime = process.env.PRTS_RUNTIME_COMMAND;
if (!rawRuntime) die('the host did not declare a runtime for this plugin (PRTS_RUNTIME_COMMAND missing)');
let DSH_RUNTIME;
try { DSH_RUNTIME = JSON.parse(rawRuntime); } catch { die('PRTS_RUNTIME_COMMAND is not valid JSON'); }
if (!Array.isArray(DSH_RUNTIME) || !DSH_RUNTIME.length) die('PRTS_RUNTIME_COMMAND must be a non-empty argv array');
const DSH_BIN = DSH_RUNTIME[DSH_RUNTIME.length - 1];
if (!fs.existsSync(DSH_BIN)) die(`dsh runtime not found: ${DSH_BIN} (the plugin's runtime is missing)`);

// --- DSH_HOME --------------------------------------------------------------
// ONE home, inside the hub's own data dir. There is no "system scope": it pointed
// DSH_HOME at the user's ~/.dsh, attached to a dsh daemon the user happened to
// have running on the default port, refused to stop a server it had not started,
// and — worst — let the USER'S OWN settings decide the permission policy, so a
// session could run with approvals suppressed while the hub believed it was
// answering them. A managed spawn owns its harness home, full stop. The user's
// own configuration is still BORROWED read-only once (settings.yaml, minus the
// permission section) so their known connections keep working; nothing is
// written back to their home.
const DSH_HOME = path.join(DATA_DIR, 'dsh-home');
const USER_DSH_HOME = path.join(os.homedir(), '.dsh');   // read-only: settings migration

// hub-managed secrets live HERE ONLY (in-memory; PROTOCOL §6.2 zero-plaintext):
// ENV-REF → value. They reach dsh exclusively through the child env.
const grants = new Map();

// adapter-owned bookkeeping (never secrets): ids this adapter added to a
// provider's model list (so saves replace only hub-added ids, shared per
// harness), and the last applied {connectionId, model}. The binding is
// PER-SESSION (FD-5: model switches within a session, connection changes do
// not) — one adapter process serves one session, so keying by sid in a shared
// file keeps a second session from reading the first's binding and falsely
// reporting `requires-new-session`.
const CFG_STATE = path.join(DATA_DIR, 'config-state.json');
const SID = process.env.PRTS_SESSION_ID || 'default';
const cfgStateFile = (() => {
  try { return JSON.parse(fs.readFileSync(CFG_STATE, 'utf8')); } catch { return { addedModels: {} }; }
})();
const cfgState = {
  get addedModels() { return (cfgStateFile.addedModels ||= {}); },
  get applied() { return ((cfgStateFile.bindings ||= {})[SID] ?? null); },
  set applied(v) { (cfgStateFile.bindings ||= {})[SID] = v; saveCfgState(); },
};
function saveCfgState() { fs.writeFileSync(CFG_STATE, JSON.stringify(cfgStateFile)); }

// Place the extensions the hub installed for this harness into dsh's home: its
// user preset root ($DSH_HOME/.agent-presets) and the node_modules walk that the
// preset's composition resolves its plugin through. The hub chose the set and
// wrote it into this harness's data dir; what a preset must look like inside a
// dsh home is dsh's own rule, so the placing lives here.
function installDshPresets() {
  const installed = process.env.PRTS_INSTALLED_EXTENSIONS_DIR || null;
  const srcRoot = installed ? path.join(installed, 'dsh-presets') : null;
  const pluginSrc = installed ? path.join(installed, 'prts-command-approval') : null;
  if (!srcRoot || !fs.existsSync(srcRoot)) return;
  // The composition names the plugin by package specifier; it must be resolvable
  // from the preset, so place it where the profile's node_modules walk finds it.
  if (pluginSrc && fs.existsSync(pluginSrc)) {
    const dst = path.join(DSH_HOME, 'profiles', 'node_modules', 'prts-command-approval');
    fs.mkdirSync(dst, { recursive: true });
    for (const f of ['index.js', 'package.json']) {
      if (fs.existsSync(path.join(pluginSrc, f))) fs.copyFileSync(path.join(pluginSrc, f), path.join(dst, f));
    }
    // Also beside the user preset root, for resolution from that location.
    const dst2 = path.join(DSH_HOME, '.agent-presets', 'node_modules', 'prts-command-approval');
    fs.mkdirSync(dst2, { recursive: true });
    for (const f of ['index.js', 'package.json']) {
      if (fs.existsSync(path.join(pluginSrc, f))) fs.copyFileSync(path.join(pluginSrc, f), path.join(dst2, f));
    }
  }
  fs.mkdirSync(path.join(DSH_HOME, '.agent-presets'), { recursive: true });
  // A row's bare package name resolves from the HOST composition's base, which
  // is inside the installed harness — a preset travels with the hub, so its plugin
  // must be named by an ABSOLUTE FILESYSTEM PATH. dsh turns an absolute name
  // into a file URL itself (mount.ts: `isAbsolute(name) ? pathToFileURL(...)`),
  // so a `file://` URL is wrong: `isAbsolute('file:///…')` is false, so it is
  // treated as a bare specifier, fails, and the row is silently dropped.
  // Forward slashes: `isAbsolute` accepts them on Windows, and a backslash path
  // written into YAML would be read as an escape by the loader, not a path.
  const pluginEntry = pluginSrc && fs.existsSync(path.join(pluginSrc, 'index.js'))
    ? path.resolve(pluginSrc, 'index.js').replace(/\\/g, '/') : null;
  for (const preset of fs.readdirSync(srcRoot)) {
    const from = path.join(srcRoot, preset);
    if (!fs.statSync(from).isDirectory()) continue;
    const to = path.join(DSH_HOME, '.agent-presets', preset);
    fs.mkdirSync(to, { recursive: true });
    for (const f of fs.readdirSync(from)) {
      let body = fs.readFileSync(path.join(from, f), 'utf8');
      if (pluginEntry && f.endsWith('.yml')) body = body.replace(/name:\s*'prts-command-approval'/g, `name: '${pluginEntry}'`);
      fs.writeFileSync(path.join(to, f), body);
    }
  }
}

function bootstrapHome() {
  const prof = path.join(DSH_HOME, 'profiles', 'web');
  const pkgFile = path.join(prof, 'package.json');
  if (!fs.existsSync(pkgFile)) {
    fs.mkdirSync(prof, { recursive: true });
    fs.writeFileSync(pkgFile, JSON.stringify({
      name: 'dsh-profile-web',
      private: true,
      dependencies: {},
      dsh: { profile: { bundles: ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app'] } },
    }, null, 2));
    fs.writeFileSync(path.join(prof, 'cordis.yml'), '[]\n');
    fs.writeFileSync(path.join(prof, 'cordis.patch.yml'), '[]\n');
  }
  // PRESET
  installDshPresets();
  const settingsFile = path.join(DSH_HOME, 'settings.yaml');
  {
    // CREATE ONLY once — dsh itself owns the file afterwards (settings.*
    // writes live there; rewriting it on every boot would clobber the
    // user's saved connections). Migration reads ~/.dsh/settings.yaml
    // (settings carry apiKeyEnv REFS, never secret values) and drops the
    // permission section; approvals-forcing happens over the settings RPC
    // after boot. Credentials are NOT imported — plaintext stays in the
    // user's own home; terminal env keys are inherited by the child,
    // hub-managed keys arrive via credentials/grant (PROTOCOL §6.2).
    if (!fs.existsSync(settingsFile)) {
      let migrated = '';
      const userSettings = path.join(USER_DSH_HOME, 'settings.yaml');
      if (fs.existsSync(userSettings)) {
        let skipping = false;
        for (const l of fs.readFileSync(userSettings, 'utf8').split('\n')) {
          const top = /^[A-Za-z][A-Za-z0-9_-]*:/.test(l);
          if (top) skipping = l.startsWith('permission:');
          if (!skipping) migrated += l + '\n';
        }
      }
      fs.writeFileSync(settingsFile, migrated + 'permission:\n  defaultPreset: workspace-write\n');
    }
  }
}

// --- dsh web server ----------------------------------------------------------
let dsh = null;       // the spawned server process
let port = null;      // HTTP/WS port once announced
let ws = null;        // the mux WebSocket
let rpcId = 0;
let dshEndpoint = null; // the shared endpoint path (one dsh per home)
let dshOwned = true;    // true = this adapter spawned the dsh (may kill it)

// dsh is ONE server serving MANY sessions — its own UI runs that way — and the hub
// runs one ADAPTER per session. So every adapter of one DSH_HOME must talk to the
// SAME server: two servers over one home collide on their settings writes
// (SETTINGS_CONFLICT / EPERM on the settings.yaml rename -> session/start 502) and
// each session pays for a whole server of its own.
//
// Which home is the scope's business (`~/.dsh` for system, `<data>/agents/<id>/
// dsh-home` for private). How many servers there are is not: one, in both scopes.
// The private home is per HARNESS, not per session, so "each session owns its own
// dsh" was never what the code did — it spawned one server per adapter over that
// shared home, which is the worst of both.
//
// Discovery, in order:
//   1. system scope: the dsh DEFAULT PORT, so a server the USER started is
//      attached to rather than duplicated.
//   2. the port this home last published (`.prts-dsh-port`), if it still answers.
//   3. otherwise exactly one adapter (the lock holder) starts the server — on the
//      default port in system scope, on any free port in private — and publishes it.
const DSH_DEFAULT_PORT = Number(process.env.PRTS_DSH_PORT || 3080);   // kept for the published-port fallback
function dshLockFile() { return path.join(DSH_HOME, '.prts-dsh-boot.lock'); }
function dshPortFile() { return path.join(DSH_HOME, '.prts-dsh-port'); }
function publishedPort() {
  try { const n = Number(fs.readFileSync(dshPortFile(), 'utf8').trim()); return Number.isInteger(n) && n > 0 ? n : null; } catch { return null; }
}
function publishPort(p) { try { fs.mkdirSync(DSH_HOME, { recursive: true }); fs.writeFileSync(dshPortFile(), String(p)); } catch {} }
function releaseLock() { try { fs.unlinkSync(dshLockFile()); } catch {} }

function probePort(p) {
  if (!p) return Promise.resolve(false);
  return new Promise((resolve) => {
    const req = http.request({ method: 'GET', hostname: '127.0.0.1', port: p, path: '/api/session.list', timeout: 1500 }, (res) => { res.resume(); resolve(true); });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}

function waitPortUp(p, ms) {
  const t0 = Date.now();
  return new Promise((resolve) => {
    const tick = async () => {
      if (await probePort(p)) return resolve(true);
      if (Date.now() - t0 > ms) return resolve(false);
      setTimeout(tick, 250);
    };
    tick();
  });
}

// The owner waits for the port its own child announces (reallySpawn publishes it),
// not for a probe of a port nobody knows yet.
function waitOwnPort(ms) {
  const t0 = Date.now();
  return new Promise((resolve) => {
    const tick = () => {
      if (port) return resolve(true);
      if (!dsh) return resolve(false);            // the child died before announcing
      if (Date.now() - t0 > ms) return resolve(false);
      setTimeout(tick, 100);
    };
    tick();
  });
}

function attach(p) {
  port = p;
  dshOwned = false;
  process.stderr.write(`[adapter] attached to running dsh on 127.0.0.1:${p} (home=${DSH_HOME})\n`);
  openMux();
}

// Every adapter looks for the shared server; exactly one of them becomes its owner.
function startServerAsync() {
  bootstrapHome();
  return (async () => {
    const known = publishedPort();
    if (await probePort(known)) { attach(known); return; }

    let gotLock = false;
    try { fs.mkdirSync(DSH_HOME, { recursive: true }); fs.closeSync(fs.openSync(dshLockFile(), 'wx')); gotLock = true; } catch {}
    if (!gotLock) {
      // Someone else is starting it: wait for the port it publishes, then attach.
      const up = await waitPortUp(publishedPort(), 45000);
      if (up) { attach(publishedPort()); return; }
      // The holder died before publishing — stake it ourselves.
      releaseLock();
      const stale = publishedPort();
      if (stale && await probePort(stale)) { attach(stale); return; }
      process.stderr.write('[adapter] a previous dsh boot left no reachable server; taking over\n');
      throw new Error('dsh server did not come up: its owner published no reachable port');
    }
    dsh = reallySpawn(null);
    dshOwned = true;
    const up = await waitOwnPort(45000);
    if (!up) { releaseLock(); throw new Error('dsh server did not announce a port within 45s'); }
  })();
}

function dshLogFile() { return path.join(DSH_HOME, '.prts-dsh-server.log'); }

function reallySpawn(fixedPort) {
  // Skills the hub installed. The hub hands over the directory that HOLDS the skill
  // directories; dsh's `agentsHome` is the directory whose `skills/` child it reads,
  // so the translation is the parent — that is the adapter's job, not the hub's.
  // Pointing it there means the harness sees what the hub installed and NOT the
  // user's own ~/.agents/skills (the default keeps that isolation even when no
  // directory was handed over, e.g. a standalone adapter for debugging).
  const skillsDir = process.env.PRTS_INSTALLED_SKILLS_DIR || null;
  const childEnv = {
    ...process.env, DSH_HOME,
    DSH_AGENTS_HOME: skillsDir ? path.dirname(skillsDir) : path.join(DATA_DIR, 'agents-home'),
  };
  // granted values ride the child env ONLY (names are apiKeyEnv refs; values
  // never touch disk, never echo to logs — count only, never contents).
  for (const [ref, value] of grants) childEnv[ref] = value;
  // The server OUTLIVES this adapter (every session of this DSH_HOME shares it):
  // detach it with file stdio so a pipe back to a dying adapter can never kill
  // it, and read its port from its log.
  const shared = true;
  let outFd = 'pipe';
  if (shared) {
    try { fs.mkdirSync(DSH_HOME, { recursive: true }); outFd = fs.openSync(dshLogFile(), 'a'); } catch { outFd = 'pipe'; }
  }
  const portArgs = fixedPort ? ['--port', String(fixedPort)] : ['--port', '0'];
  // --no-open, always: `dsh web` opens the Web UI in the user's browser unless it
  // is told not to, and the hub runs the harness headless — a session must never
  // pop a browser window on the user's desktop. (It did: every managed spawn of
  // dsh opened one.)
  const child = spawn(DSH_RUNTIME[0], [...DSH_RUNTIME.slice(1), 'web', '--no-open', ...portArgs], {
    windowsHide: true,
    cwd: DATA_DIR,
    stdio: shared ? ['ignore', outFd, outFd] : ['pipe', 'pipe', 'pipe'],
    env: childEnv,
    detached: shared,
  });
  if (shared) { try { child.unref(); } catch {} }
  process.stderr.write(`[adapter] dsh spawned pid=${child.pid} cwd=${DATA_DIR} home=${DSH_HOME} grantedRefs=${grants.size} detached=${shared}\n`);
  // A failed spawn used to be SILENT (no 'error' listener): the caller just
  // spun until the port timeout. Surface it immediately.
  child.on('error', (e) => process.stderr.write(`[adapter] DSH SPAWN FAILED: ${e.message}\n`));
  if (shared) {
    // Port comes from the log file the detached server writes to. Start reading
    // at the CURRENT end so a previous run's `dsh web:` line can never be
    // mistaken for this server's port.
    let offset = 0;
    try { offset = fs.statSync(dshLogFile()).size; } catch {}
    const t = setInterval(() => {
      try {
        const st = fs.statSync(dshLogFile());
        if (st.size <= offset) return;
        const fd = fs.openSync(dshLogFile(), 'r');
        const len = st.size - offset;
        const buf = Buffer.alloc(len);
        fs.readSync(fd, buf, 0, len, offset);
        fs.closeSync(fd);
        offset = st.size;
        const m = buf.toString('utf8').match(/dsh web: http:\/\/127\.0\.0\.1:(\d+)/);
        if (m && !port) {
          port = Number(m[1]);
          publishPort(port);   // siblings attach to THIS server, not one of their own
          releaseLock();
          openMux();
          if (onPort) onPort();
          clearInterval(t);
        }
      } catch {}
    }, 120);
    setTimeout(() => clearInterval(t), 45000);
    return child;
  }
  child.on('exit', (code, signal) => {
    dsh = null;
    process.stderr.write(`[adapter] dsh server exited (code ${code} signal ${signal ?? 'none'})\n`);
  });
  return child;
}

function rpc(method, payload, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    if (!port) return reject(new Error('dsh server has no port yet'));
    const id = 'prts-' + (++rpcId);
    const timer = setTimeout(() => reject(new Error(`dsh rpc ${method} timed out`)), timeoutMs);
    fetch(`http://127.0.0.1:${port}/api/${method}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'client-request', rpcId: id, method, payload }),
    }).then(async (r) => {
      const txt = await r.text().catch(() => '');
      clearTimeout(timer);
      let body = null; try { body = txt ? JSON.parse(txt) : null; } catch {}
      if (!body || !body.result) return reject(new Error(`dsh rpc ${method}: http ${r.status} malformed response ${JSON.stringify(txt).slice(0, 200)}`));
      if (!body.result.ok) {
        // dsh carries its machine code inside result.error.code. Keep it as
        // data.code so the core can answer with the real reason (a locked agent
        // preset is not a missing model) instead of parsing our message text.
        const native = body.result.error && body.result.error.code;
        const err = new Error(`dsh rpc ${method}: ${JSON.stringify(body.result).slice(0, 300)}`);
        if (native) err.data = { code: native };
        return reject(err);
      }
      resolve(body.result.value);
    }, (e) => { clearTimeout(timer); reject(new Error(`dsh rpc ${method}: ${e.message}`)); });
  });
}

// --- event translation --------------------------------------------------------
// The adapter's own copy of the hub's event vocabulary: a type that is not here
// is a type the hub was never told to expect, and it is REFUSED (loudly, on
// stderr) rather than sent.
//
// That guard is only as good as this list. It was missing the two compaction
// events, so dsh's AUTOMATIC compactions — the ones nobody asks for, which are
// exactly what a caller must not miss — were dropped here with only a log line
// to show for it. `plan_changed` was missing too, which is why a plan flip that
// the hub learned about (it reads the state back) never arrived as an event.
const CORE_EVENTS = new Set([
  'text_delta', 'reasoning_delta', 'message_end', 'tool_started', 'tool_end',
  'turn_started', 'turn_end', 'plan_changed', 'compaction_started', 'compaction_ended',
  'title_changed',
]);

// A v1 adapter process serves ONE session (core spawns one per session). dsh
// itself is a single server several adapters may attach to — that sharing lives
// inside the adapter (see the shared-dsh section), NOT here: this process owns
// exactly one bus session.
let sid = null;          // dsh session id (== bus ref)
let sessionIdReported = false;
let turnActive = false;
let turnText = '';
let turnSawStart = false;
let callNames = new Map(); // callId → tool name
let pendingPrompt = null;      // settles the bus prompt request at turn end
let pendingPromptReject = null;
const crypto = require('crypto');

// --- core-surface transcript (PROTOCOL §2): adapter-owned history truth ---
// DATA_DIR declared above (line 50)
let busSid = null;         // the bus session id (events must carry THIS)
let currentRef = null;     // dsh sessionId once created — stable across resume
let liveMessage = null;
let cfgApplied = null;     // FD-5 connection binding
// Compaction facts seen on the live event stream, newest last. dsh's /compact
// result points AT the summary event (sourceEventSeq) instead of carrying the
// numbers, and its compaction/end names the compactionId — so both keys are
// kept, and the facts themselves are always the harness's own record, never
// something this adapter computed.
let compactionSummaries = [];
let lastCompactionStart = null;
let lastTitle = null;      // the session title this adapter last reported to the hub
function compactionSummary(bySeq) {
  for (let i = compactionSummaries.length - 1; i >= 0; i -= 1) {
    const item = compactionSummaries[i];
    if (bySeq.kind === 'seq' && item.seq === bySeq.value) return item.data;
    if (bySeq.kind === 'id' && item.data && item.data.compactionId === bySeq.value) return item.data;
    if (bySeq.kind === 'command' && item.data && item.data.sourceCommandId === bySeq.value) return item.data;
  }
  return null;
}
function transcriptPath(ref) {
  // A stable, collision-free key for one session's transcript. It used to be
  // Buffer.from(ref).toString('hex').slice(0, 80) - the first 40 BYTES of the
  // ref - which is not a hash: every session of one harness shares the
  // sessions/ directory, so every ref shares that prefix and they all mapped
  // to ONE file. Different sessions then read and appended each other's
  // history. A full digest is the fix; the ref itself is the identity.
  return require('path').join(DATA_DIR, 'transcripts', crypto.createHash('sha256').update(String(ref)).digest('hex') + '.json');
}
function loadTranscript(ref) {
  if (!DATA_DIR) return [];
  try { return JSON.parse(fs.readFileSync(transcriptPath(ref), 'utf8')); } catch { return []; }
}
function appendTranscript(entry, ref) {
  if (!DATA_DIR || !ref) return;
  fs.mkdirSync(require('path').join(DATA_DIR, 'transcripts'), { recursive: true });
  const entries = loadTranscript(ref);
  if (!entries.some((e) => e.id === entry.id)) entries.push(entry);
  fs.writeFileSync(transcriptPath(ref), JSON.stringify(entries));
}

// The transcript is this adapter's own record of a conversation IT took part in.
// A session can exist without that: a fork hands back a conversation this adapter
// has never seen, and so does a session another tool created. The harness's own
// log is then the only source — and answering an empty page would tell the caller
// the child has no history when the harness says it has one.
//
// So: with no transcript for this ref, import the harness's messages once, with
// the ids the harness already gave them (stable across restarts), and persist.
// Nothing is written when the log has no messages, so a session that later grows
// history is not frozen at "empty".
async function ensureTranscript(ref) {
  if (!DATA_DIR || !ref) return;
  if (fs.existsSync(transcriptPath(ref))) return;
  const hist = await rpc('session.history', { sessionId: ref, maxMessages: 1000 });
  const events = ((hist && hist.events) || []).map((e) => e.event).filter(Boolean);
  const entries = [];
  for (const e of events) {
    const isUser = e.type === 'user/message';
    if (!isUser && e.type !== 'assistant/message') continue;
    const msg = isUser ? (e.data || {}) : ((e.data || {}).message || null);
    if (!msg) continue;
    // Only the CONVERSATION is imported. dsh also writes user-role messages of
    // its own (a runtime-context snapshot from dsh-system-prompt arrives as
    // source.kind 'plugin'); those are the harness talking to itself, and the
    // live path never records them either — importing them would make a forked
    // child's history disagree with its parent's about the same turn.
    const kind = (msg.source && msg.source.kind) || null;
    if (isUser ? kind !== 'user' : kind !== 'model') continue;
    const blocks = Array.isArray(msg.content) ? msg.content : [];
    const text = blocks.filter((b) => b && typeof b.text === 'string').map((b) => b.text).join('');
    if (!text) continue;
    const id = (typeof msg.id === 'string' && msg.id) || (isUser ? 'u-' : 'a-') + e.seq;
    entries.push({ id, role: isUser ? 'user' : 'assistant', text, complete: true, inherited: true });
  }
  if (!entries.length) return;
  fs.mkdirSync(require('path').join(DATA_DIR, 'transcripts'), { recursive: true });
  fs.writeFileSync(transcriptPath(ref), JSON.stringify(entries));
  process.stderr.write(`[adapter] inherited ${entries.length} message(s) from the harness log into the transcript
`);
}

function emit(data) {
  if (!CORE_EVENTS.has(data.type)) {
    process.stderr.write(`[adapter] internal error: non-contract event ${data.type}\n`);
    return;
  }
  send({ jsonrpc: '2.0', method: 'event', params: { sid: busSid || sid, data } });
}

function statusOf(reason) {
  const kind = reason && reason.kind;
  if (kind === 'completed' || kind === 'max-tokens') return 'completed';
  if (kind === 'error' || kind === 'blocked') return 'failed';
  return 'aborted'; // aborted / interrupted / anything client-driven
}

function handleFrame(frame) {
  const p = frame.payload;
  if (!p) return;
  if (p.type === 'approval/requested') {
    pendingApprovals.set(frame.rpcId, p);
        send({
      jsonrpc: '2.0', id: `appr-${frame.rpcId}`, method: 'approval_need',
      params: {
        sid: busSid || sid,
        kind: 'confirm',
        detail: `deepseek-harness ${p.toolName}${p.callId ? ` (${p.callId})` : ''}`,
        approval_id: p.approvalId,
        respond_rpc_id: frame.rpcId,
        // dsh's approval vocabulary is a closed outcome set (allowed-once /
        // rejected); the answerer chooses. Surface it as the offered options so
        // the core/test see the same shape as the pi baseline.
        options: ['Allow Once', 'Reject'],
      },
    });
    return;
  }
  if (p.type === 'approval/resolved' || p.type === 'question/resolved' || p.type === 'session/queue' || p.type === 'session/projection' || p.type === 'session/subscribed' || p.type === 'session/jobs') {
    return; // outside the v0 event contract; dropped
  }
  if (p.type === 'question/requested') {
    // dsh asks through its user-questions domain: one ask carrying one or more
    // questions, answered as a whole batch. Carry it to the core as a QUESTION
    // — never as an approval (an approval permits an action; this seeks an
    // answer). `detail` and `intent` are preserved: the plan review rides here
    // (intent `plan-review`), and dropping them would lose the plan itself.
    pendingQuestions.set(frame.rpcId, p);
    send({
      jsonrpc: '2.0', id: `q-${frame.rpcId}`, method: 'question_need',
      params: {
        sid: busSid || sid,
        question_id: frame.rpcId,
        questions: (Array.isArray(p.questions) ? p.questions : []).map((q) => ({
          id: String(q.id),
          header: q.header != null ? q.header : null,
          question: String(q.question != null ? q.question : ''),
          detail: q.detail != null ? q.detail : null,
          options: Array.isArray(q.options) ? q.options.map((o) => ({ label: String(o.label), description: o.description != null ? o.description : null })) : null,
          multiSelect: q.multiSelect === true,
          intent: q.intent && typeof q.intent === 'object' ? { kind: String(q.intent.kind), approve: q.intent.approve != null ? String(q.intent.approve) : null } : null,
        })),
      },
    });
    return;
  }
  if (p.type !== 'session/event' || !p.sessionId || p.sessionId !== sid) return;
  const e = p.event;
  switch (e.type) {
    case 'turn/start':
      if (!turnSawStart) {
        turnSawStart = true;
        turnText = '';
        emit({ type: 'turn_started' });
      }
      turnActive = true;
      break;
    case 'assistant/chunk': {
      const ch = e.data && e.data.chunk;
      if (!ch) break;
      if (ch.type === 'text-delta' && ch.text) {
        if (!liveMessage) liveMessage = { id: 'a-' + crypto.randomUUID(), text: '' };
        liveMessage.text += ch.text;
        turnText += ch.text;
        emit({ type: 'text_delta', messageId: liveMessage.id, text: ch.text });
      }
      else if (ch.type === 'reasoning-delta' && ch.text) {
        if (!liveMessage) liveMessage = { id: 'a-' + crypto.randomUUID(), text: '' };
        emit({ type: 'reasoning_delta', messageId: liveMessage.id, text: ch.text });
      }
      break;
    }
    case 'tool/call':
      if (e.data && e.data.callId && e.data.name) callNames.set(e.data.callId, e.data.name);
      emit({ type: 'tool_started', tool: e.data.name || 'tool', toolCallId: e.data.callId || null, detail: JSON.stringify(e.data.arguments || {}).slice(0, 200) });
      break;
    case 'plan/mode': {
      // The harness owns plan state, and it can change without the core asking:
      // the model leaves plan mode when its plan is approved. Report the flip as
      // it happens so the core's view tracks the harness instead of the last
      // thing the core requested.
      const active = !!(e.data && e.data.active === true);
      if (!turnActive) break;
      send({ jsonrpc: '2.0', method: 'event', params: { sid: busSid || sid, data: { type: 'plan_changed', plan: active } } });
      break;
    }
    case 'tool/result': {
      const msg = e.data && e.data.message;
      const items = msg && Array.isArray(msg.content) ? msg.content : [];
      const err = !!(msg && msg.isError) || items.some((it) => it && it.isError === true);
      const callId = (msg && msg.source && msg.source.callId) || '';
      const name = callNames.get(callId);
      if (callId) callNames.delete(callId);
      let result = 'done';
      if (err) {
        const first = items.find((it) => it && typeof it.text === 'string' && it.text);
        result = first ? first.text.slice(0, 400) : 'tool reported an error';
      } else if (msg) {
        const r = msg.content !== undefined ? msg.content : (msg.result !== undefined ? msg.result : undefined);
        if (r !== undefined) result = (typeof r === 'string' ? r : JSON.stringify(r)).slice(0, 400);
      }
      emit({ type: 'tool_end', tool: name || callId || 'tool', toolCallId: callId || null, detail: result, ok: !err });
      break;
    }
    case 'turn/end': {
      if (!turnActive) break;
      turnActive = false;
      if (turnText) {
        const messageId = (liveMessage && liveMessage.id) || 'a-' + crypto.randomUUID();
        liveMessage = null;
        appendTranscript({ id: messageId, role: 'assistant', text: turnText, complete: true }, currentRef);
        emit({ type: 'message_end', messageId, role: 'assistant', text: turnText });
      }
      emit({ type: 'turn_end', status: statusOf(e.data && e.data.reason) });
      if (pendingPrompt) {
        const settle = pendingPrompt;
        pendingPrompt = null;
        settle();
      }
      break;
    }
    case 'session/title': {
      // dsh titles a session by itself (its title service folds session/title
      // events, and its own composition can write one from the first prompt).
      // Reported, so the hub follows the harness rather than showing a name the
      // session no longer has.
      const held = e.data && typeof e.data.title === 'string' && e.data.title ? e.data.title : null;
      if (held !== lastTitle) {
        lastTitle = held;
        emit({ type: 'title_changed', title: held });
      }
      break;
    }
    case 'compaction/start': {
      // dsh compacts by itself under pressure (turn: a number) or on demand
      // (turn: null). Both are reported: a caller watching the stream must not go
      // quiet while the agent rewrites its own context, and a compaction nobody
      // asked for is exactly the thing a hub must not hide.
      const d = e.data || {};
      lastCompactionStart = { compactionId: d.compactionId, sourceCommandId: d.sourceCommandId, turn: d.turn === undefined ? null : d.turn };
      emit({ type: 'compaction_started', reason: d.turn === null || d.turn === undefined ? 'manual' : 'auto' });
      break;
    }
    case 'compaction/summary': {
      const d = e.data || {};
      compactionSummaries.push({ seq: typeof e.seq === 'number' ? e.seq : null, data: d });
      if (compactionSummaries.length > 16) compactionSummaries.shift();
      break;
    }
    case 'compaction/end': {
      const d = e.data || {};
      const sum = compactionSummary({ kind: 'id', value: d.compactionId });
      const data = {
        type: 'compaction_ended',
        reason: 'manual',
        aborted: !!d.error,
      };
      if (lastCompactionStart && lastCompactionStart.compactionId === d.compactionId) {
        data.reason = lastCompactionStart.turn === null || lastCompactionStart.turn === undefined ? 'manual' : 'auto';
      }
      if (d.error) data.detail = String((d.error && d.error.message) || d.error).slice(0, 400);
      if (sum) {
        if (typeof sum.shadowedTokenCount === 'number') data.tokensBefore = sum.shadowedTokenCount;
        const text = summaryTextOf(sum.summary);
        if (text) data.summary = text;
        if (sum.usage) data.usage = sum.usage;
      }
      if (!d.error) {
        // The same 'after' number the manual route reports: dsh's own context
        // projection, read once now. It is read (not invented) and it is read
        // AFTER the rewrite, so the event carries both sides of the change.
        readContextPressure()
          .then((p) => { if (p && typeof p.tokens === 'number') data.tokensAfter = p.tokens; })
          .catch(() => {})
          .then(() => emit(data));
        break;
      }
      emit(data);
      break;
    }
    default:
      break; // trace-only frames
  }
}

function openMux() {
  const connect = () => {
    ws = new WebSocket(`ws://127.0.0.1:${port}/api/events.mux`);
    ws.onmessage = (ev) => {
      try { handleFrame(JSON.parse(ev.data)); } catch {}
    };
    ws.addEventListener('error', () => {
      // A shared dsh may still be registering its upgrade route when a sibling
      // attaches right after the port answers; retry rather than losing events.
      process.stderr.write(`[adapter] mux socket error; retrying\n`);
      setTimeout(() => { if (port) connect(); }, 400);
    });
    ws.addEventListener('open', () => process.stderr.write(`[adapter] mux connected\n`));
  };
  connect();
}

let onPort = null;
function waitPort() {
  return new Promise((resolve, reject) => {
    if (port) return resolve();
    const t = setTimeout(() => reject(new Error('dsh server did not announce its port within 45s')), 45000);
    onPort = () => { clearTimeout(t); onPort = null; resolve(); };
  });
}

let bootPromise = null;
function ensureBooted() {
  if (!bootPromise) {
    bootPromise = (async () => {
      process.stderr.write(`[adapter] booting dsh web: ${DSH_BIN}\n`);
      await startServerAsync();
      await waitPort();
      process.stderr.write(`[adapter] dsh web ready on 127.0.0.1:${port} (owned=${dshOwned})\n`);
      // approvals are FORCED over the RPC in private scope (the settings file
      // is create-only, so restarts never clobber dsh-owned data)
      {
        await settingsWrite(() => rpc('settings.update', { ns: 'permission', patch: { defaultPreset: 'workspace-write' } }));
      }
      // the hub's own provider routes are injected per session (credentials/grant) and
      // are therefore not configuration this harness should keep. Earlier the hub builds
      // wrote them into the USER's ~/.dsh (the removed system scope), the one-time
      // settings migration carried them in, and a route whose apiKeyEnv nobody sets
      // shows up in the model picker as `needs-auth` noise for models this hub does
      // not manage (measured: 160 such entries on one machine). Swept only by the
      // process that STARTED this server — an attached adapter must not delete a
      // route a running session injected.
      if (dshOwned) {
        try {
          const view = await nsView('llm-pi-ai');
          const routes = (view.value && view.value.providers) || {};
          const stale = Object.keys(routes).filter((id) => id.startsWith('prts-'));
          for (const id of stale) {
            await settingsWrite(() => rpc('settings.mutate', { ns: 'llm-pi-ai', ops: [{ op: 'unset', path: ['providers', id] }] }));
          }
          if (stale.length) process.stderr.write(`[adapter] swept ${stale.length} stale managed provider route(s): ${stale.join(', ')}\n`);
        } catch (e) {
          process.stderr.write(`[adapter] stale route sweep failed: ${e.message}\n`);
        }
      }
    })();
    bootPromise.catch(() => { bootPromise = null; if (dsh) { try { dsh.kill(); } catch {} dsh = null; } });
  }
  return bootPromise;
}

// --- approvals ---------------------------------------------------------------
const pendingApprovals = new Map(); // respond rpcId → approval payload

function answerApproval(respondRpcId, approved) {
  const payload = pendingApprovals.get(respondRpcId);
  if (!payload) return;
  pendingApprovals.delete(respondRpcId);
  fetch(`http://127.0.0.1:${port}/api/respond`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      type: 'client-response',
      rpcId: respondRpcId,
      result: {
        ok: true,
        value: {
          approvalId: payload.approvalId,
          sessionId: payload.sessionId,
          outcome: approved ? 'allowed-once' : 'rejected',
        },
      },
    }),
  }).catch((e) => process.stderr.write(`[adapter] approval respond failed: ${e.message}\n`));
}

// --- questions ---------------------------------------------------------------
// dsh's user-questions domain: one ask, one batch answer. Kept apart from
// approvals on purpose — the payload shapes differ and mixing them would force
// one to speak the other's language.
const pendingQuestions = new Map(); // respond rpcId → question payload

function answerQuestion(respondRpcId, answers) {
  const payload = pendingQuestions.get(respondRpcId);
  if (!payload) return;
  pendingQuestions.delete(respondRpcId);
  // dsh validates the batch against the questions it asked: one entry per
  // question id, each { id, selected[], custom? }. A partial answer still has
  // to name every id, so fill anything the caller left out with an empty
  // selection rather than dropping it (a dropped id reads as a malformed ask).
  const asked = Array.isArray(payload.questions) ? payload.questions : [];
  const byId = new Map((Array.isArray(answers) ? answers : []).map((a) => [String(a && a.id), a]));
  const batch = asked.map((q) => {
    const a = byId.get(String(q.id));
    const selected = a && Array.isArray(a.selected) ? a.selected.map(String) : [];
    const custom = a && typeof a.custom === 'string' && a.custom.length ? a.custom : undefined;
    return { id: String(q.id), selected, ...(custom !== undefined ? { custom } : {}) };
  });
  fetch(`http://127.0.0.1:${port}/api/respond`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      type: 'client-response',
      rpcId: respondRpcId,
      result: { ok: true, value: { sessionId: payload.sessionId, answer: { answers: batch } } },
    }),
  }).catch((e) => process.stderr.write(`[adapter] question respond failed: ${e.message}\n`));
}

function cancelQuestion(respondRpcId) {
  const payload = pendingQuestions.get(respondRpcId);
  if (!payload) return;
  pendingQuestions.delete(respondRpcId);
  fetch(`http://127.0.0.1:${port}/api/respond`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      type: 'client-response',
      rpcId: respondRpcId,
      result: { ok: false, error: { code: 'cancelled', message: 'no answer was given', details: {} } },
    }),
  }).catch((e) => process.stderr.write(`[adapter] question cancel failed: ${e.message}\n`));
}

// --- configuration plane (PROTOCOL §6) ---------------------------------------
// Bridges §6 to dsh's native settings.* / credentials.* / llm.* RPCs (all
// shapes measured live, see scripts/probe-dsh-config.cjs). Native machine codes
// observed: settings-rejected · settings-conflict · model-discovery-failed.
// Secrets: only apiKeyEnv REFS are ever written; values live in `grants`
// (memory) and the shell keychain, reaching dsh through the child env only.
function fail(code, message) { return { code: -32000, message: String(message).slice(0, 300), data: { code } }; }

// Map a dsh RPC rejection to a §6.3 machine code, keeping the (secret-free)
// native message. Unknown native failures surface as validation-failed.
// Two dsh servers can share one DSH_HOME: the hub runs one adapter per session and
// the private home is per harness (not per session), so a sibling server may hold
// settings.yaml open exactly when we rename over it. Windows answers EPERM for
// that momentary lock, and dsh reports it as "settings-rejected" — which reads
// like a rejected setting and is not: retry the write, and only report failure
// if it stays locked. (dsh's own rule is one server per home; this is what keeps
// a second session from failing for a reason that is not its own.)
const TRANSIENT_SETTINGS_LOCK = /EPERM|EBUSY|ENOTEMPTY|resource busy/i;
async function settingsWrite(call, attempts = 4) {
  for (let i = 1; ; i += 1) {
    try { return await call(); }
    catch (e) {
      if (i >= attempts || !TRANSIENT_SETTINGS_LOCK.test(String(e && e.message))) throw e;
      process.stderr.write(`[adapter] settings write collided with another dsh over the same home (attempt ${i}/${attempts}), retrying
`);
      await new Promise((r) => setTimeout(r, 250 * i));
    }
  }
}

function nativeCall(promise) {
  return promise.catch((e) => {
    const m = /(\{"code":.*)$/.exec(e.message || '');
    let code = null;
    if (m) { try { code = JSON.parse(m[1]).code; } catch {} }
    const map = { 'settings-conflict': 'revision-conflict', 'settings-rejected': 'validation-failed', 'model-discovery-failed': 'validation-failed' };
    const err = new Error(e.message);
    err.bus = fail(map[code] || 'validation-failed', e.message);
    throw err;
  });
}
function sendErr(id, e) {
  // Error → wrapped (with mapped bus code if present); a fail() object → as-is
  // (it already carries data.code, the §6.3 machine code must survive).
  // A native code carried on e.data (see rpc) also survives, so a refusal dsh
  // named — e.g. agent-preset-locked — reaches the core as that code rather
  // than a generic -32000 the core would have to guess at.
  let err;
  if (e instanceof Error) {
    err = e.bus || { code: -32000, message: e.message };
    if (!e.bus && e.data && e.data.code) err = { code: -32000, message: e.message, data: e.data };
  } else {
    err = e;
  }
  send({ jsonrpc: '2.0', id, error: err });
}

async function nsView(ns) {
  const d = await rpc('settings.describe', {});
  if (!d.writable) { const e = new Error('settings document is read-only on this host'); e.bus = fail('validation-failed', e.message); throw e; }
  const v = d.namespaces.find((n) => n.ns === ns);
  if (!v) { const e = new Error(`no settings namespace ${ns}`); e.bus = fail('unknown-provider', e.message); throw e; }
  return v;}

// Read the plan state back from dsh's own `plan` session projection — the
// capability's read half. The projection rides the history tail page
// (`projections.values.plan = { active, pending }`); a key that is absent means
// the domain plugin is not composed, so plan is unavailable, not false.
// The command plane takes its request under `args` (the typert remote shape) and
// the descriptor requires EVERY declared field: `images` is part of it even when
// there are none, and omitting it fails the whole call with
// 'args fields do not match the descriptor: missing "images"'. One helper, so the
// shape is written once instead of at each call site.
async function executeCommand(line, timeoutMs) {
  return rpc('commands/execute', { args: { agentId: currentRef, line, images: [] } }, timeoutMs);
}

async function readPlanState() {
  try {
    const h = await rpc('session.history', { sessionId: currentRef });
    const plan = h && h.projections && h.projections.values ? h.projections.values.plan : undefined;
    return plan && typeof plan.active === 'boolean' ? plan.active : null;
  } catch { return null; }
}

// A compaction is an LLM summarization call: the command plane's own 30s bound
// is too short for it, and a timeout here would report a failure for a
// compaction that is still running.
const COMPACT_TIMEOUT_MS = 300_000;

// dsh stores a compaction summary as CONTENT BLOCKS ({type:'text',text}), not as
// a string; the bus carries text. Only the text blocks are joined — nothing is
// rewritten, summarised again, or trimmed here. A field dsh did not send comes
// back null, so the caller can tell "no summary" from "empty summary".
function summaryTextOf(value) {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    const text = value
      .filter((b) => b && b.type === 'text' && typeof b.text === 'string')
      .map((b) => b.text)
      .join('\n')
      .trim();
    return text || null;
  }
  return null;
}

// dsh's own context occupancy for this session: the projection's pressure, the
// same number GET /v1/sessions/{id}/stats reports (never a hub-side calculation).
async function readContextPressure() {
  try {
    const h = await rpc('session.history', { sessionId: currentRef });
    const values = (h && h.projections && h.projections.values) || {};
    const p = values.contextPressure;
    if (!p) return null;
    const tokens = typeof p.projectedTokens === 'number' ? p.projectedTokens : (typeof p.pressureTokens === 'number' ? p.pressureTokens : null);
    if (tokens === null) return null;
    return { tokens, window: typeof p.contextWindow === 'number' ? p.contextWindow : null };
  } catch { return null; }
}

// Read one compaction's facts out of the session log at a known seq — the same
// record the live stream would have carried, for the case where the frame
// arrived before the adapter was attached.
async function readCompactionSummaryAt(seq) {
  try {
    const h = await rpc('session.history', { sessionId: currentRef });
    const events = (h && Array.isArray(h.events)) ? h.events : [];
    for (let i = events.length - 1; i >= 0; i -= 1) {
      const item = events[i];
      const e = item && item.event ? item.event : item;
      if (e && e.type === 'compaction/summary' && e.seq === seq) return e.data || {};
    }
    return null;
  } catch { return null; }
}

// The review switch is the hub plugin's own state, kept as a session-log event
// (it is not a dsh projection, because the plugin is not a dsh domain). Fold the
// newest record; no record means the mounted default (asking on).
async function readReviewState() {
  try {
    const h = await rpc('session.history', { sessionId: currentRef });
    // The page carries `events: HistoryEntry[]` ({ event, view? }), oldest
    // first, so the newest matching record is the last one found scanning back.
    const events = (h && Array.isArray(h.events)) ? h.events : [];
    for (let i = events.length - 1; i >= 0; i -= 1) {
      const item = events[i];
      const e = item && item.event ? item.event : item;
      if (e && e.type === 'prts-command-approval/state') return !!(e.data && e.data.asking === true);
    }
    return null;
  } catch { return null; }
}

const entryOf = (piValue, id) => (piValue && piValue.providers && piValue.providers[id]) || null;
const defaultRef = (id) => 'PRTS_' + String(id).replace(/[^A-Za-z0-9]+/g, '_').toUpperCase() + '_API_KEY';
const csvIds = (text) => String(text || '').split(',').map((s) => s.trim()).filter(Boolean);
// llm-pi-ai defaults a model's input modalities to ['text'] when the catalog
// entry does not declare them — which silently DROPS image parts. the hub-injected
// providers are OpenAI-compatible chat routes; declare text+image so an image
// part actually reaches the model (dsh checks the same field).
const toModels = (ids, models) => ids.map((id) => {
  // The hub hands each model's resolved facts (name, modalities, levels,
  // window). dsh carries a model's own statement as `reasoning.efforts` +
  // `defaultEffort`, the same shape here, so it is passed through rather than
  // translated. A model with no levels gets no reasoning block, which dsh reads
  // as "no levels to offer".
  const decl = (Array.isArray(models) ? models : []).find((m) => m && m.id === id) || null;
  const r = decl && decl.reasoning && Array.isArray(decl.reasoning.efforts) && decl.reasoning.efforts.length ? decl.reasoning : null;
  // The modality comes from the declaration; a model not declared as taking
  // images is not advertised as taking them.
  const input = Array.isArray(decl?.input) && decl.input.length ? decl.input : ['text'];
  // dsh's model profile carries id, name, contextWindow, maxTokens, input,
  // reasoningEfforts and compat — there is no cost field to put a cost in, so a
  // declared cost is simply not passed here rather than smuggled into a key dsh
  // does not define.
  return {
    id, name: (decl && typeof decl.name === 'string' && decl.name) || id, input,
    ...(r ? { reasoning: { efforts: r.efforts.map((e) => ({ id: e })), ...(r.default ? { defaultEffort: r.default } : {}) } } : {}),
    ...(decl && decl.contextWindow ? { contextWindow: decl.contextWindow } : {}),
    ...(decl && decl.maxTokens ? { maxTokens: decl.maxTokens } : {}),
  };
});

// GET <url>/models (OpenAI shape) to learn what an injected provider serves;
// dsh rejects a route that declares no models.
function probeModels(url, value) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch { return reject(new Error('invalid provider url: ' + url)); }
    const mod = u.protocol === 'https:' ? https : http;
    const base = u.pathname.replace(/\/$/, '');
    const req = mod.request({ method: 'GET', hostname: u.hostname, port: u.port || undefined, path: base + '/models', headers: { authorization: 'Bearer ' + value }, timeout: 15000 }, (res) => {
      let b = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { b += d; });
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) return reject(new Error(`provider ${url} /models -> ${res.statusCode}`));
        let j; try { j = JSON.parse(b); } catch { return reject(new Error('provider /models is not JSON')); }
        const list = Array.isArray(j.data) ? j.data : Array.isArray(j.models) ? j.models : null;
        if (!list) return reject(new Error('provider /models has no model array'));
        resolve(list.map((m) => (typeof m === 'string' ? m : m.id)).filter(Boolean));
      });
    });
    req.on('timeout', () => req.destroy(new Error('provider /models timed out')));
    req.on('error', reject);
    req.end();
  });
}

async function connectionRows() {
  const [lp, pi, dsp] = await Promise.all([rpc('llm.providers', {}), nsView('llm-pi-ai'), nsView('llm-deepseek')]);
  const rows = [];
  for (const p of lp.providers) {
    if (p.settingsNs === 'llm-deepseek') {
      rows.push({ id: 'deepseek-official', providerId: 'deepseek-official', label: p.displayName || 'DeepSeek',
        revision: dsp.revision, _ref: (dsp.value && dsp.value.apiKeyEnv) || 'DEEPSEEK_API_KEY' });
    } else if (p.settingsNs === 'llm-pi-ai' && p.declared) {
      const e = entryOf(pi.value, p.provider) || {};
      rows.push({ id: p.provider, providerId: p.provider, label: e.displayName || p.displayName || p.provider,
        revision: pi.revision, _ref: e.apiKeyEnv || defaultRef(p.provider), ...(e.baseURL ? { endpoint: e.baseURL } : {}) });
    }
  }
  for (const r of rows) { const okSec = await secretConfigured(r._ref); r.secretConfigured = okSec; r.status = okSec ? 'connected' : 'needs-auth'; }
  return rows;
}

async function secretConfigured(ref) {
  if (grants.has(ref)) return true;
  try {
    const c = await rpc('credentials.describe', { refs: [ref] });
    return !!(c.credentials && c.credentials[ref] && c.credentials[ref].configured);
  } catch { return false; }
}

// value-free view (internal fields stripped; never a secret, §6.2)
function viewRow(r) { const { _ref, ...v } = r; return v; }

// Restart a config-only server so a settings change takes effect. Only before
// this adapter has a session, and only when this adapter owns the server: a
// shared server is not ours to take down (see the boot section).
function restartIdle() {
  if (!dsh || !dshOwned || anySessionStarted()) return;
  try { if (ws && ws.close) ws.close(); } catch {}
  ws = null; port = null; bootPromise = null;
  try { dsh.kill(); } catch {}
  dsh = null;
}
function anySessionStarted() { return sessionIdReported; }

// Strict (re)attach: dsh's session.create is create-or-attach and would happily
// open a fresh session for an unknown id. For an EXTERNAL resume ref we verify
// the id exists first and that the server returns the SAME id; otherwise fail
// loudly. `trusted` is used only for a ref THIS process just created (post-grant
// reboot of our own live session): it must still return the same id, but need
// not appear in session.list yet (a session persists on first use).
async function attachSession(resumeRef, trusted = false) {
  if (!resumeRef) {
    const v = await rpc('session.create', { cwd: CWD });
    if (!v || !v.sessionId) throw new Error(`session.create returned no sessionId: ${JSON.stringify(v).slice(0, 200)}`);
    return v.sessionId;
  }
  if (!trusted) {
    const list = await rpc('session.list', {});
    const known = list && Array.isArray(list.items) && list.items.some((s) => s.sessionId === resumeRef);
    if (!known) throw new Error(`resume ref "${resumeRef}" has no persisted session — open a new session instead`);
  }
  const v = await rpc('session.create', { cwd: CWD, sessionId: resumeRef });
  if (!v || !v.sessionId) throw new Error(`session.create returned no sessionId: ${JSON.stringify(v).slice(0, 200)}`);
  if (v.sessionId !== resumeRef) throw new Error(`resume ref "${resumeRef}" did not reattach (server returned "${v.sessionId}")`);
  return v.sessionId;
}

function anyTurnActive() { return turnActive; }
function connInUse(connectionId) { return turnActive && cfgApplied && cfgApplied.connectionId === connectionId; }

function configPlane(method, id, p) {
  const ok = (result) => send({ jsonrpc: '2.0', id, result });
  switch (method) {
    case 'connections/schema': return ensureBooted().then(async () => {
      const rows = await connectionRows();
      const secretField = { name: 'apiKey', label: 'API key', type: 'secret', required: true };
      const modelsField = { name: 'customModels', label: 'Extra model ids (comma separated)', type: 'text', required: false };
      const providers = [{
        id: 'deepseek-official', displayName: 'DeepSeek (official)', authKind: 'api-key',
        supportsCustomEndpoint: false, supportsCustomModels: true,
        fields: [secretField, modelsField],
      }];
      for (const r of rows) if (r.id !== 'deepseek-official') providers.push({
        id: r.id, displayName: r.label, authKind: 'api-key',
        supportsCustomEndpoint: true, supportsCustomModels: true,
        fields: [secretField, { name: 'baseUrl', label: 'Base URL', type: 'url', required: true }, modelsField],
      });
      providers.push({
        id: 'custom', displayName: 'New upstream (OpenAI-compatible gateway)', authKind: 'api-key',
        supportsCustomEndpoint: true, supportsCustomModels: true,
        fields: [secretField,
          { name: 'baseUrl', label: 'Base URL', type: 'url', required: true },
          { name: 'api', label: 'Wire API', type: 'enum', required: true, values: ['openai-completions'] },
          modelsField],
      });
      ok({ providers });
    }).catch((e) => sendErr(id, e));

    case 'connections/list': return ensureBooted().then(async () => {
      ok({ connections: (await connectionRows()).map(viewRow) });
    }).catch((e) => sendErr(id, e));

    case 'connections/validate': return ensureBooted().then(async () => {
      const draft = p.draft || {};
      const f = draft.fields || {};
      const prov = draft.providerId;
      if (prov !== 'custom' && prov !== 'deepseek-official') {
        const pi = await nsView('llm-pi-ai');
        if (!entryOf(pi.value, prov)) return send({ jsonrpc: '2.0', id, error: fail('unknown-provider', `no provider ${prov}`) });
      }
      if (prov === 'custom' && !f.baseUrl) return ok({ ok: false, fieldErrors: [{ field: 'baseUrl', message: 'required' }] });
      if (!f.apiKey && prov !== 'custom') {
        const rows = await connectionRows();
        const row = rows.find((r) => r.id === prov);
        if (row && row.status !== 'connected') return ok({ ok: false, fieldErrors: [{ field: 'apiKey', message: 'required' }] });
      } else if (prov === 'custom' && !f.apiKey) {
        return ok({ ok: false, fieldErrors: [{ field: 'apiKey', message: 'required' }] });
      }
      // write-only probe: dsh's discoverModels apiKey is "never stored and never
      // returned" — this is the ONE place a draft value crosses to dsh.
      const req = prov === 'deepseek-official'
        ? { settingsNs: 'llm-deepseek', provider: 'deepseek-official', ...(f.apiKey ? { apiKey: f.apiKey } : {}) }
        : { settingsNs: 'llm-pi-ai', ...(prov !== 'custom' ? { provider: prov } : {}), ...(f.baseUrl ? { baseURL: f.baseUrl } : {}), ...(f.api ? { api: f.api } : {}), ...(f.apiKey ? { apiKey: f.apiKey } : {}) };
      try {
        await nativeCall(rpc('llm.discoverModels', req));
        ok({ ok: true });
      } catch (e) {
        // message may name the endpoint (fine), never the key (dsh guarantees it)
        ok({ ok: false, transportError: e.message });
      }
    }).catch((e) => sendErr(id, e));

    case 'connections/save': return ensureBooted().then(async () => {
      const f = p.fields || {};
      const policy = p.secretPolicy || 'keep';
      if (policy === 'replace' && (f.apiKey === undefined || f.apiKey === '')) throw fail('validation-failed', 'replace requires a value');
      const rows = await connectionRows();
      if (p.providerId === 'custom') {
        if (p.id) throw fail('validation-failed', 'providerId "custom" creates a new upstream; omit id');
        if (!f.baseUrl || !f.apiKey) throw fail('validation-failed', 'baseUrl and apiKey are required to create an upstream');
        const slug = (String(p.label || 'gateway').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'gateway').slice(0, 24);
        let newId = slug; let n = 2;
        while (rows.some((r) => r.id === newId)) newId = `${slug}-${n++}`;
        const ref = defaultRef(newId);
        const value = { api: f.api || 'openai-completions', baseURL: f.baseUrl, apiKeyEnv: ref, displayName: p.label || newId };
        const ids = csvIds(f.customModels);
        if (ids.length) { value.models = toModels(ids); cfgState.addedModels[newId] = ids; saveCfgState(); }
        await nativeCall(settingsWrite(() => rpc('settings.mutate', { ns: 'llm-pi-ai', ops: [{ op: 'set', path: ['providers', newId], value }], ...(p.expectedRevision !== undefined ? { expectedRevision: p.expectedRevision } : {}) })));
        grants.set(ref, String(f.apiKey)); // memory only; the file carries `ref`
        const all = await connectionRows(); // BEFORE restartIdle (which kills the server)
        restartIdle();
        return ok({ connection: viewRow(all.find((r) => r.id === newId) || { id: newId, providerId: newId, label: value.displayName, status: 'connected', revision: 0, secretConfigured: true }), requires: 'none' });
      }
      const row = rows.find((r) => r.id === p.providerId);
      if (!row || (p.id && p.id !== row.id)) throw fail('unknown-provider', `no connection for providerId ${p.providerId}`);
      if (p.expectedRevision !== undefined && p.expectedRevision !== row.revision) throw fail('revision-conflict', 'stale revision');
      if (row.id === 'deepseek-official') {
        const cur = (await nsView('llm-deepseek')).value || {};
        const patch = {};
        if (f.customModels !== undefined) {
          const added = cfgState.addedModels[row.id] || [];
          const keep = (cur.models || []).filter((m) => !added.includes(m.id));
          const ids = csvIds(f.customModels);
          patch.models = keep.concat(toModels(ids));
          cfgState.addedModels[row.id] = ids; saveCfgState();
        }
        if (Object.keys(patch).length) await nativeCall(settingsWrite(() => rpc('settings.update', { ns: 'llm-deepseek', patch, expectedRevision: row.revision })));
      } else {
        const ops = [];
        if (f.baseUrl) ops.push({ op: 'set', path: ['providers', row.id, 'baseURL'], value: f.baseUrl });
        if (p.label) ops.push({ op: 'set', path: ['providers', row.id, 'displayName'], value: p.label });
        if (f.customModels !== undefined) {
          const cur = entryOf((await nsView('llm-pi-ai')).value, row.id) || {};
          const added = cfgState.addedModels[row.id] || [];
          const keep = (cur.models || []).filter((m) => !added.includes(m.id));
          const ids = csvIds(f.customModels);
          ops.push({ op: 'set', path: ['providers', row.id, 'models'], value: keep.concat(toModels(ids)) });
          cfgState.addedModels[row.id] = ids; saveCfgState();
        }
        if (ops.length) await nativeCall(settingsWrite(() => rpc('settings.mutate', { ns: 'llm-pi-ai', ops, expectedRevision: row.revision })));
      }
      if (f.apiKey !== undefined && f.apiKey !== '') grants.set(row._ref, String(f.apiKey));
      else if (policy === 'clear') grants.delete(row._ref);
      const all = await connectionRows(); // BEFORE restartIdle
      const fresh = all.find((r) => r.id === row.id) || row;
      restartIdle();
      ok({ connection: viewRow(fresh), requires: 'none' }); // dsh applies settings live
    }).catch((e) => sendErr(id, e));

    case 'connections/delete': return ensureBooted().then(async () => {
      const rows = await connectionRows();
      const row = rows.find((r) => r.id === p.id);
      if (!row) return ok({}); // idempotent
      if (row.id === 'deepseek-official') throw fail('unsupported-for-provider', 'the official route IS the harness; it cannot be deleted');
      if (p.expectedRevision !== undefined && p.expectedRevision !== row.revision) throw fail('revision-conflict', 'stale revision');
      if (connInUse(row.id)) throw fail('busy-session-active', 'connection is in use by the active turn');
      await nativeCall(settingsWrite(() => rpc('settings.mutate', { ns: 'llm-pi-ai', ops: [{ op: 'unset', path: ['providers', row.id] }] })));
      grants.delete(row._ref);
      delete cfgState.addedModels[row.id]; saveCfgState();
      restartIdle();
      ok({});
    }).catch((e) => sendErr(id, e));

    case 'auth/start': return send({ jsonrpc: '2.0', id, error: fail('unsupported-for-provider', 'dsh has no browser/device auth flows (probed surface: none); api-key only') });
    case 'auth/status': return send({ jsonrpc: '2.0', id, error: fail('auth-expired', 'no auth operations exist for this harness') });
    case 'auth/cancel': return send({ jsonrpc: '2.0', id, result: {} }); // idempotent, nothing to cancel

    case 'presets/list': return ensureBooted().then(async () => {
      // dsh agent-preset roster. Content stays local; only id + metadata cross.
      const r = await rpc('agentPreset.list', {});
      const presets = (r && Array.isArray(r.presets) ? r.presets : []).map((p) => ({
        id: p.id, name: p.name != null ? p.name : null, description: p.description != null ? p.description : null,
        trust: p.trust === 'system' || p.trust === 'user' ? p.trust : null,
        isDefault: p.isDefault === true, broken: p.broken != null ? p.broken : null,
      }));
      ok({ presets });
    }).catch((e) => sendErr(id, e));

    case 'models/list': return ensureBooted().then(async () => {
      const [m, rows] = await Promise.all([rpc('llm.models', {}), connectionRows()]);
      const byId = new Map(rows.map((r) => [r.id, r]));
      const models = [];
      const failures = (m.failures || []).map((x) => ({ connectionId: x.id, providerId: x.id, message: x.message }));
      for (const g of m.groups || []) {
        const r = byId.get(g.id);
        const usable = r ? r.status === 'connected' : true;
        for (const x of g.models || []) models.push({
          id: x.id, connectionId: g.id, providerId: g.id, name: x.name || x.id,
          available: usable, ...(usable ? {} : { unavailableReason: 'needs-auth' }),
          ...(x.reasoning ? { reasoning: { efforts: (x.reasoning.efforts || []).map((e) => e.id), ...(x.reasoning.defaultEffort ? { default: x.reasoning.defaultEffort } : {}) }, thinkingLevels: (x.reasoning.efforts || []).map((e) => e.id) } : {}),
        });
      }
      // The CORE's providers, as first-class entries — the same rule the pi family
      // uses. Two reasons this cannot be left to dsh's own view:
      //   * a provider no session has injected yet does not exist in dsh at all, so
      //     its models would be missing from the picker on a fresh hub;
      //   * dsh answers availability from its own credential store, which knows
      //     nothing about a token the hub holds and hands over only at session
      //     start — so every managed model read `needs-auth` while pi said available.
      // The hub owns the token, so the hub's answer wins for its own providers.
      const hubProviders = new Map();
      for (const row of Array.isArray(p.providers) ? p.providers : []) {
        if (!row || typeof row.id !== 'string' || !row.id) continue;
        const routeId = 'prts-' + String(row.id).replace(/[^A-Za-z0-9_.-]/g, '_');
        hubProviders.set(routeId, row);
        for (const x of Array.isArray(row.models) ? row.models : []) {
          if (!x || typeof x.id !== 'string' || !x.id) continue;
          const at = models.findIndex((mm) => mm.providerId === routeId && mm.id === x.id);
          const efforts = x.reasoning && Array.isArray(x.reasoning.efforts) ? x.reasoning.efforts : null;
          const entry = {
            id: x.id, connectionId: routeId, providerId: routeId, name: x.name || x.id,
            available: row.hasCredential === true,
            ...(row.hasCredential === true ? {} : { unavailableReason: 'needs-auth' }),
            ...(efforts && efforts.length ? { thinkingLevels: efforts, reasoning: { efforts } } : {}),
            ...(Array.isArray(x.input) && x.input.length ? { input: x.input } : {}),
            ...(x.contextWindow ? { contextWindow: x.contextWindow } : {}),
            ...(x.maxTokens ? { maxTokens: x.maxTokens } : {}),
          };
          if (at >= 0) models[at] = { ...models[at], ...entry }; else models.push(entry);
        }
      }
      // A hub-managed route dsh already knows: dsh's own verdict may still be
      // `needs-auth` because the value lives in the runtime credential store, which
      // `secretConfigured` does not read. The hub's fact wins for these routes only.
      for (const mm of models) {
        if (!hubProviders.has(mm.providerId)) continue;
        const row = hubProviders.get(mm.providerId);
        mm.available = row.hasCredential === true;
        if (mm.available) delete mm.unavailableReason; else mm.unavailableReason = 'needs-auth';
      }
      for (const r of rows) if (r.status !== 'connected' && !(m.groups || []).some((g) => g.id === r.id)) failures.push({ connectionId: r.id, providerId: r.providerId, message: 'needs-auth' });
      ok({ models, failures });
    }).catch((e) => sendErr(id, e));

    case 'credentials/grant': return ensureBooted().then(async () => {
      // {connectionId, value, url?}. If a url is supplied and no route exists,
      // this is a hub-managed provider being INJECTED: create a prts-<id>
      // route whose apiKeyEnv points at an env var; the value itself only ever
      // rides the dsh child env (grants map), never the file.
      if (p.url) {
        const routeId = 'prts-' + String(p.connectionId || 'provider').replace(/[^A-Za-z0-9_.-]/g, '_');
        const ref = defaultRef(routeId);
        const ids = await probeModels(p.url, p.value).catch((e) => { throw fail('unknown-provider', `cannot inject provider ${p.url}: ${e.message}`); });
        const pi = await nsView('llm-pi-ai');
        // The provider's definition says which protocol it speaks; only a
        // provider registered without one falls back to the historical default.
        const value = { api: typeof p.api === 'string' && p.api ? p.api : 'openai-completions', baseURL: p.url, apiKeyEnv: ref, displayName: routeId, models: toModels(ids, p.models) };
        await nativeCall(settingsWrite(() => rpc('settings.mutate', { ns: 'llm-pi-ai', ops: [{ op: 'set', path: ['providers', routeId], value }] })));
        grants.set(ref, String(p.value));
        // credentials.set puts the value into the RUNNING dsh's credential store:
        // the value reaches the executor with no process restart. dsh resolves
        // the apiKeyEnv ref through this store, so a shared dsh can carry several
        // sessions' credentials at once (a reboot would have taken it down for
        // every other session).
        await nativeCall(rpc('credentials.set', { ref, value: String(p.value) }));
        process.stderr.write('[adapter] injected provider route ' + routeId + ' with ' + ids.length + ' models (value in credential store, never the file)\n');
        return ok({});
      }
      const rows = await connectionRows();
      const row = rows.find((r) => r.id === p.connectionId);
      if (!row) throw fail('unknown-provider', `no connection ${p.connectionId}`);
      grants.set(row._ref, String(p.value)); // never logged, never on disk
      try { await nativeCall(rpc('credentials.set', { ref: row._ref, value: String(p.value) })); } catch (e) { process.stderr.write(`[adapter] credentials.set failed for ${row._ref}: ${e.message}\n`); }
      process.stderr.write('[adapter] credential granted into the running dsh credential store (ref resolved, value not logged)\n');
      ok({});
    }).catch((e) => sendErr(id, e));

    default: return false;
  }
}

// --- bus contract ------------------------------------------------------------
function handle(msg) {
  const { id, method, params = {}, result } = msg;
  if (!method) {
    // An approval or question answer comes back as a JSON-RPC RESULT (core
    // replies to the adapter's *_need request), not as a `params` payload.
    if (typeof id === 'string' && id.startsWith('appr-')) {
      const r = result || {};
      answerApproval(id.slice(5), r.approved === true);
      return;
    }
    if (typeof id === 'string' && id.startsWith('q-')) {
      const r = result || {};
      // A cancelled question is the timeout path: tell dsh no answer came
      // rather than inventing one. Answering is the ordinary path.
      if (r.cancelled === true) cancelQuestion(id.slice(2));
      else answerQuestion(id.slice(2), r.answers);
    }
    return;
  }
  switch (method) {
    case 'session/start': {
      sid = params.sid;
      busSid = params.sid;
      ensureBooted()
        .then(async () => {
          // S-1: the hub is a front-end, not a security boundary. It MUST NOT refuse
          // to run because the user's own preset disables approvals — the user
          // runs that preset in their terminal regardless, and refusing only
          // makes the hub itself unusable without reducing any real risk. Keep
          // VISIBILITY only: report the preset, then run.
          // The shared dsh may still be finishing boot right after its port
          // answers (a sibling adapter just started it); retry the readiness
          // probe instead of failing the session on a transient.
          let pv = null;
          for (let i = 0; i < 40; i++) {
            try { pv = await nsView('permission'); break; } catch { await new Promise((r) => setTimeout(r, 250)); }
          }
          const preset = pv && pv.value && pv.value.defaultPreset;
          if (preset) process.stderr.write(`[adapter] permission preset: ${preset}\n`);
          // dsh's session.create treats sessionId as create-or-attach: it
          // ACCEPTS unknown ids and silently opens a fresh session. A resume
          // ref must therefore be verified against session.list first.
          if (!params.resume) return attachSession(null);
          return attachSession(params.resume);
        })
        .then((value) => {
          const sessionId = value;   // dsh's own sessionId (event routing)
          sid = sessionId;
          currentRef = sid;
          sessionIdReported = true;
          // additionalDirectories: dsh's own session.create takes cwd only and
          // its ACP layer rejects additionalDirectories explicitly. We do not
          // pretend: absent -> nothing to say; present -> report that this
          // harness did NOT take them, so the caller can see the truth rather
          // than assume they are active.
          const adReport = ADDITIONAL_DIRS.length
            ? { requested: ADDITIONAL_DIRS, applied: [], supported: false, reason: 'harness does not support additional directories' }
            : undefined;
          send({ jsonrpc: '2.0', id, result: { ref: sid, ...(adReport ? { additionalDirectories: adReport } : {}) } });
        })
        .catch((e) => send({ jsonrpc: '2.0', id, error: { code: -32000, message: `session/start failed: ${e.message}` } }));
      return;
    }
    case 'session/prompt': {
      
      if (!sessionIdReported) {
        send({ jsonrpc: '2.0', id, error: { code: -32000, message: 'deepseek: no live session' } });
        return;
      }
      if (!params.clientMessageId) {
        send({ jsonrpc: '2.0', id, error: { code: -32000, message: 'session/prompt requires clientMessageId (core surface)' } });
        return;
      }
      appendTranscript({ id: params.clientMessageId, role: 'user', text: params.message, complete: true }, currentRef);
      turnText = '';
      turnSawStart = false;
      // dsh's content parts are exactly {type:'text',text} | {type:'image',mediaType,data,name?};
      // the core's image parts already carry mediaType + base64 data. Omit an
      // empty text part so an image-only turn is a valid, non-empty content list.
      const parts = [];
      if (params.message) parts.push({ type: 'text', text: params.message });
      for (const im of Array.isArray(params.images) ? params.images : []) {
        if (im && typeof im.data === 'string' && im.data.length) {
          parts.push({ type: 'image', mediaType: im.mediaType || 'image/png', data: im.data, ...(im.name ? { name: im.name } : {}) });
        }
      }
      if (!parts.length) parts.push({ type: 'text', text: '' });
      rpc('session.prompt', { sessionId: currentRef, mode: 'queue', content: parts })
        .then(() => new Promise((resolve, reject) => {
          // ack on turn settlement (see turn/end handler), not on admission
          if (pendingPrompt) reject(new Error('another prompt is already in flight'));
          else {
            pendingPrompt = resolve;
            pendingPromptReject = reject;
          }
        }))
        .then(() => send({ jsonrpc: '2.0', id, result: {} }))
        .catch((e) => send({ jsonrpc: '2.0', id, error: { code: -32000, message: `turn refused: ${e.message}` } }));
      return;
    }
    case 'session/abort': {
      // The cancel is only an acknowledgement that we ASKED the harness to stop;
      // the turn's own turn_end is what proves it stopped. Do not swallow a
      // failure to send the request: the core distinguishes "asked and never
      // confirmed" (the turn is genuinely in doubt) from "could not even ask",
      // and it cannot make that distinction if we hide the error.
      if (!sessionIdReported) { send({ jsonrpc: '2.0', id, result: {} }); return; }
      rpc('session.cancel', { sessionId: currentRef })
        .then(() => send({ jsonrpc: '2.0', id, result: {} }))
        .catch((e) => {
          process.stderr.write(`[adapter] abort failed: ${e.message}\n`);
          send({ jsonrpc: '2.0', id, error: { code: -32000, message: `abort failed: ${e.message}`, data: { code: 'abort-failed' } } });
        });
      return;
    }
    case 'session/fork': {
      // A NEW conversation that inherits this one up to a completed turn. The
      // source session is not touched — dsh seeds the child from the prefix of
      // the parent's log and marks the boundary with session/end-seed.
      //
      // The anchor is a turn, not a raw seq: atSeq snaps to a completed-turn
      // boundary anyway (a seq inside turn N forks at the END of turn N), so
      // asking dsh for "turn N" is the same answer the hub promised, and the
      // hub never has to speak dsh's seq numbers.
      busSid = params.sid || busSid;   // the BUS session; `sid` becomes the dsh session id
      if (turnActive) {
        send({ jsonrpc: '2.0', id, error: { code: -32000, message: 'cannot fork while a turn is running', data: { code: 'session-busy' } } });
        return;
      }
      const source = params.from || currentRef;
      if (!source) { send({ jsonrpc: '2.0', id, error: { code: -32000, message: 'no source session to fork' } }); return; }
      const wants = params.throughTurn;
      ensureBooted()
        .then(async () => {
          // The hub spawns the CHILD's process and hands it where to branch from:
          // this process opens the source only to fork it, then adopts the result
          // as its own session. (pi's fork rebinds whichever process runs it, so a
          // fork must never be run on the source's own process — the same rule
          // holds here even though dsh would allow it.)
          if (params.from) currentRef = await attachSession(params.from);   // open the source only to branch from it
          let atSeq;
          if (wants !== undefined && wants !== null) {
            const n = Number(wants);
            if (!Number.isInteger(n) || n < 1) throw Object.assign(new Error('throughTurn must be a positive integer'), { data: { code: 'validation-failed' } });
            const hist = await rpc('session.history', { sessionId: currentRef, maxMessages: 1000 });
            const ends = ((hist && hist.events) || []).map((e) => e.event).filter((e) => e && e.type === 'turn/end');
            if (ends.length < n) throw Object.assign(new Error(`session has ${ends.length} completed turn(s), not ${n}`), { data: { code: 'unknown-turn' } });
            atSeq = ends[n - 1].seq;
          }
          const v = await rpc('session.fork', atSeq === undefined ? { sessionId: currentRef } : { sessionId: currentRef, atSeq });
          const child = v && v.sessionId;
          if (!child) throw new Error('dsh returned no child session');
          if (params.from) {
            // Attach the child in THIS server too: session.create is create-or-attach,
            // and an unattached session gets no event stream here — the first turn
            // would run in dsh and never report back (the hub saw a turn that never
            // ended). trusted=true: this very process just created it.
            const adopted = await attachSession(child, true);
            // `sid` is the DSH session id — the event dispatcher drops every frame
            // whose sessionId is not it, so both must move to the child together.
            sid = adopted;
            currentRef = adopted;
            sessionIdReported = true;
          }
          send({ jsonrpc: '2.0', id, result: { ref: child } });
        })
        .catch((e) => {
          const code = (e.data && e.data.code) || 'fork-failed';
          process.stderr.write(`[adapter] session/fork failed: ${e.message}\n`);
          send({ jsonrpc: '2.0', id, error: { code: -32000, message: `fork failed: ${e.message}`, data: { code } } });
        });
      return;
    }
case 'config/set': {
      process.stderr.write(`[adapter] config/set got ${JSON.stringify(params.config)}\n`);
      const cfg = params.config || {};
      const model = cfg.model;
      const presetId = cfg.presetId;
      const plan = cfg.plan;
      const review = cfg.review;
      const thinkingLevel = cfg.thinkingLevel;
      if (model === undefined && presetId === undefined && plan === undefined && review === undefined) {
        // connection-only set with no model/preset/plan/review: nothing applicable at creation
        if (!cfg.connectionId) { send({ jsonrpc: '2.0', id, result: {} }); return; }
      }
      ensureBooted().then(async () => {
        // Preset FIRST: it is what MOUNTS the plugins that provide /review and
        // /plan, so switching review before it hits a same-named command from the
        // base composition (which cheerfully says ok and records nothing). Only a
        // blank session may switch; dsh answers agent-preset-locked otherwise.
        let appliedPreset;
        if (presetId !== undefined) {
          const pr = await rpc('agentPreset.select', { sessionId: currentRef, agentPreset: presetId });
          appliedPreset = (pr && pr.agentPreset) || presetId;
          // Do NOT touch cfgApplied here: it holds the FD-5 connection
          // binding, written only when a model is applied. Writing a preset-only
          // record would blank `connectionId` and make the binding check below
          // reject the very model this same request is applying.
        }
        // Plan is a session-scoped capability dsh owns natively: drive its own
        // `/plan` command through the command plane, then read the state back
        // from the session projection. No composition change, no restart.
        let appliedPlan;
        if (plan !== undefined) {
          // A requested plan state that did not take effect is an ERROR, not a
          // null: `appliedPlan = null` on failure is exactly the silent downgrade
          // the contract forbids (and it hid a broken call for a while — the
          // payload was missing the `images` field the descriptor requires, so
          // every switch failed and was reported as "nothing asked").
          await executeCommand(plan === true ? '/plan' : '/plan off');
          appliedPlan = await readPlanState();
          if (appliedPlan === null && plan !== null) {
            throw Object.assign(new Error('plan state was not reported back by the harness'), { data: { code: 'plan-not-applied' } });
          }
        }
        // Review is the hub plugin's own switch, also driven through the
        // command plane. No composition change, no restart — and unlike preset
        // it is legal mid-session, which is the point of having it.
        let appliedReview;
        if (review !== undefined) {
          await executeCommand(review === true ? '/review on' : '/review off');
          // A command acknowledgement is not an observed review state.
          appliedReview = await readReviewState();
        }
        if (!model) {
          const a = {};
          if (appliedPreset !== undefined) a.preset = appliedPreset;
          if (appliedPlan !== undefined && appliedPlan !== null) a.plan = appliedPlan;
          if (appliedReview !== undefined) a.review = appliedReview;
          send({ jsonrpc: '2.0', id, result: Object.keys(a).length ? { applied: a, requires: 'none' } : {} });
          return;
        }
        const connId = cfg.connectionId || (cfgApplied && cfgApplied.connectionId) || 'deepseek-official';
        // An injected the hub provider becomes the route `prts-<connId>`; accept the
        // bare id as well and resolve it to the injected route when present.
        let routeId = connId;
        try {
          const m0 = await rpc('llm.models', {});
          const injected = 'prts-' + String(connId).replace(/[^A-Za-z0-9_.-]/g, '_');
          if ((m0.groups || []).some((g) => g.id === injected)) routeId = injected;
        } catch { /* fall through: use connId verbatim */ }
        process.stderr.write(`[adapter] config/set connId=${JSON.stringify(connId)} routeId=${JSON.stringify(routeId)}\n`);
        // Provider changes are session configuration, not a new session.
        // Core grants the selected provider before this call and serializes it
        // against turn admission; validate the model on that exact route.
        const m = await rpc('llm.models', {});
        const group = (m.groups || []).find((g) => g.id === routeId);
        if (!group) throw Object.assign(new Error(), { bus: fail('unknown-provider', `connection ${routeId} contributes no model catalog`) });
        const entry = (group.models || []).find((x) => x.id === model);
        if (!entry) {
          throw Object.assign(new Error(), { bus: fail('unknown-model', `model ${model} not offered by connection ${routeId}`) });
        }
        // dsh's agent-default-model applies LIVE: the next turn uses it (T10).
        // A migrated settings.yaml may carry a reasoningEffort this model does
        // NOT support (e.g. Qwen rejects "high") — align it to the model's own
        // efforts, or clear it, so switching models cannot leak an incompatible
        // effort. Never guess an effort the model does not list.
        const patch = { provider: routeId, model };
        const efforts = (entry.reasoning && entry.reasoning.efforts) || [];
        // A requested level must be one this model actually accepts; an omitted
        // level keeps dsh's own value rather than inventing one.
        if (thinkingLevel !== undefined && thinkingLevel !== null) {
          if (!efforts.length) throw Object.assign(new Error(), { bus: fail('unknown-model', `model ${model} does not accept a thinking level`) });
          if (!efforts.includes(thinkingLevel)) throw Object.assign(new Error(), { bus: fail('unknown-model', `thinking level ${thinkingLevel} is not offered by ${model}: ${efforts.join(', ')}`) });
          patch.reasoningEffort = thinkingLevel;
        }
        const unsetEffort = !entry.reasoning || efforts.length === 0;
        await nativeCall(settingsWrite(() => rpc('settings.update', { ns: 'agent-default-model', patch })));
        // A migrated settings.yaml may carry a reasoningEffort this route does
        // not support. When the model exposes no efforts, the stale key MUST be
        // removed for the turn to run; if removal fails, config/set fails
        // loudly — never report an applied config on a swallowed cleanup error.
        if (unsetEffort) {
          await nativeCall(settingsWrite(() => rpc('settings.mutate', { ns: 'agent-default-model', ops: [{ op: 'unset', path: ['reasoningEffort'] }] })));
        }
        cfgApplied = { connectionId: routeId, model };
        // Report the REAL route that was applied (prts-<id> for an injected
        // provider) — the caller uses it to verify no silent fallback.
        send({ jsonrpc: '2.0', id, result: { applied: { connectionId: routeId, modelProviderId: connId, model, ...(thinkingLevel !== undefined && thinkingLevel !== null ? { thinkingLevel } : {}), ...(appliedPreset !== undefined ? { preset: appliedPreset } : {}), ...(appliedPlan !== undefined && appliedPlan !== null ? { plan: appliedPlan } : {}), ...(appliedReview !== undefined ? { review: appliedReview } : {}), configRevision: cfg.configRevision ?? null }, requires: 'none' } });
      }).catch((e) => sendErr(id, e));
      return;
    }
    case 'skills/list': {
      // dsh's own catalogue: its skill.list RPC returns the user-invocable skills for
      // this session's project root, each with the model-invocation policy. Read from
      // dsh — it is the only side that knows which of the installed skills it refused
      // (a non-kebab name, a missing description, camelCase invocation keys, or a
      // nested bundle are all dropped with no message a hub could see).
      if (!currentRef) {
        send({ jsonrpc: '2.0', id, error: { code: -32000, message: 'no session open' } });
        return;
      }
      ensureBooted()
        .then(() => rpc('skill.list', { sessionId: currentRef }))
        .then((r) => {
          const skills = ((r && r.skills) || []).map((s) => ({
            name: String(s.name),
            ...(s.description ? { description: String(s.description) } : {}),
            ...(s.whenToUse ? { whenToUse: String(s.whenToUse) } : {}),
            ...(typeof s.modelInvocable === 'boolean' ? { modelInvocable: s.modelInvocable } : {}),
          }));
          send({ jsonrpc: '2.0', id, result: { skills } });
        })
        .catch((e) => send({ jsonrpc: '2.0', id, error: { code: -32000, message: `skills failed: ${e.message}` } }));
      return;
    }
    case 'session/rename': {
      // dsh NORMALIZES the title and answers with the one it accepted (plus the
      // seq of the session/title event it appended). That answer is the result:
      // a hub that echoed back the requested string would show a name the
      // harness does not hold.
      if (!currentRef) {
        send({ jsonrpc: '2.0', id, error: { code: -32000, message: 'no session open' } });
        return;
      }
      const title = params && typeof params.title === 'string' ? params.title.trim() : '';
      if (!title) {
        send({ jsonrpc: '2.0', id, error: { code: -32000, message: 'rename needs a non-empty title', data: { code: 'validation_failed' } } });
        return;
      }
      ensureBooted()
        .then(() => rpc('session.rename', { sessionId: currentRef, title }))
        .then((r) => {
          const held = r && typeof r.title === 'string' ? r.title : null;
          lastTitle = held;
          send({ jsonrpc: '2.0', id, result: { title: held } });
        })
        .catch((e) => send({ jsonrpc: '2.0', id, error: { code: -32000, message: `rename failed: ${e.message}`, data: { code: 'rename_failed' } } }));
      return;
    }
    case 'session/compact': {
      // dsh's /compact is a command, and its result names the session-log event
      // that carries the facts (sourceEventSeq → compaction/summary). So the
      // numbers come from dsh's own record: shadowedTokenCount is the span it
      // replaced. dsh reports no "after" count, so tokensAfter stays ABSENT here
      // rather than being invented — the projection's pressure is a different
      // measurement, already available through session/stats.
      if (!currentRef) {
        send({ jsonrpc: '2.0', id, error: { code: -32000, message: 'no session open' } });
        return;
      }
      ensureBooted()
        .then(() => executeCommand('/compact', COMPACT_TIMEOUT_MS))
        .then(async (res) => {
          // The wire shape is { commandId, result } | undefined — the CommandResult
          // is nested one level down, which is exactly the level a first version of
          // this read from. `res.result` absent = the command produced nothing.
          const r = (res && res.result) || null;
          const commandId = (res && res.commandId) || null;
          if (!r) {
            send({ jsonrpc: '2.0', id, error: { code: -32000, message: 'compact failed: the harness returned no command result', data: { code: 'compact_failed' } } });
            return;
          }
          if (r.kind !== 'success') {
            // busy / changed / summary / commit / persistence come back as
            // kind:'error' with dsh's own sentence. That is a failure, not a
            // nothing-to-do: it is reported as one.
            send({ jsonrpc: '2.0', id, error: { code: -32000, message: `compact failed: ${r.text || 'no result'}`, data: { code: 'compact_failed' } } });
            return;
          }
          if (typeof r.sourceEventSeq !== 'number') {
            // "No compactable history yet." — nothing was replaced, and dsh said so.
            send({ jsonrpc: '2.0', id, result: { compacted: false, detail: r.text || 'nothing to compact' } });
            return;
          }
          let sum = compactionSummary({ kind: 'seq', value: r.sourceEventSeq });
          if (!sum && commandId) sum = compactionSummary({ kind: 'command', value: commandId });
          if (!sum) sum = await readCompactionSummaryAt(r.sourceEventSeq);
          const out = { compacted: true, reason: 'manual' };
          if (sum) {
            if (typeof sum.shadowedTokenCount === 'number') out.tokensBefore = sum.shadowedTokenCount;
            const text = summaryTextOf(sum.summary);
            if (text) out.summary = text;
            if (sum.usage) out.usage = sum.usage;
          } else {
            // The command says it compacted; the record could not be read, so
            // the numbers are left out and the harness's own sentence is kept.
            // Saying "compacted" is still true; inventing counts would not be.
            out.detail = r.text || null;
          }
          // dsh's own view of the context AFTER the rewrite: its projection, read
          // now — the same number GET /stats reports, not a hub-side subtraction.
          if (sum) {
            const pressure = await readContextPressure();
            if (pressure && typeof pressure.tokens === 'number') out.tokensAfter = pressure.tokens;
          }
          send({ jsonrpc: '2.0', id, result: out });
        })
        .catch((e) => {
          const code = (e && e.data && e.data.code) || 'compact_failed';
          send({ jsonrpc: '2.0', id, error: { code: -32000, message: `compact failed: ${e.message}`, data: { code } } });
        });
      return;
    }
    case 'session/stats': {
      // dsh keeps its numbers in session projections: `tokenUsage` (totals) and
      // `contextPressure` (provider-reported occupancy and the window it was
      // measured against), plus `sessionStats` for the turn count. Same rule as
      // the pi family: a number dsh did not report stays ABSENT (a zero and an
      // unmeasured value are different claims), and `percent` is only filled when
      // both of its own numbers are there.
      if (!currentRef) {
        send({ jsonrpc: '2.0', id, error: { code: -32000, message: 'no session open' } });
        return;
      }
      rpc('session.history', { sessionId: currentRef }).then((h) => {
        const values = (h && h.projections && h.projections.values) || {};
        const out = {};
        // The projection rides the wire as the four buckets themselves (measured),
        // not as the fold's {totals,last} state.
        const totals = values.tokenUsage && (values.tokenUsage.totals || values.tokenUsage);
        if (totals) {
          // dsh's four buckets are disjoint and named in its own vocabulary:
          // `uncachedInputTokens` is the fresh prompt, cache reads/writes are
          // separate, and reasoning is already inside `outputTokens` (so it is
          // reported as a note, never added again).
          const t = {
            input: totals.uncachedInputTokens, output: totals.outputTokens,
            cacheRead: totals.cacheReadTokens, cacheWrite: totals.cacheWriteTokens,
          };
          t.total = t.input + t.output + t.cacheRead + t.cacheWrite;
          out.tokens = t;
        }
        const pressure = values.contextPressure;
        if (pressure && (typeof pressure.contextWindow === 'number' || typeof pressure.pressureTokens === 'number')) {
          // projectedTokens is dsh's forward-looking estimate (the provider sample
          // plus the surface's movement since, which is what lets it see a
          // compaction); pressureTokens is the last provider-reported prompt size.
          const tokens = typeof pressure.projectedTokens === 'number' ? pressure.projectedTokens : pressure.pressureTokens;
          const window_ = typeof pressure.contextWindow === 'number' ? pressure.contextWindow : null;
          out.context = {
            tokens: typeof tokens === 'number' ? tokens : null,
            window: window_,
            percent: (typeof tokens === 'number' && window_) ? Math.min(100, Math.round((tokens / window_) * 1000) / 10) : null,
          };
        }
        if (values.sessionStats && typeof values.sessionStats.turns === 'number') out.turns = values.sessionStats.turns;
        // dsh reports no cost for a route unless the model declares one; there is
        // nothing to invent here.
        send({ jsonrpc: '2.0', id, result: out });
      }).catch((e) => send({ jsonrpc: '2.0', id, error: { code: -32000, message: `stats failed: ${e.message}` } }));
      return;
    }
    case 'history/page': {
      if (!currentRef) {
        send({ jsonrpc: '2.0', id, error: { code: -32000, message: 'no session open' } });
        return;
      }
      // A forked (or externally created) session has history the adapter never
      // wrote down: import it before answering, or the page is a lie of omission.
      ensureTranscript(currentRef).catch((e) => process.stderr.write(`[adapter] transcript import failed: ${e.message}
`)).then(() => {
      const entries = loadTranscript(currentRef);
      const limit = Math.max(1, Number(params.limit) || 20);
      let end = entries.length;
      if (params.beforeId !== undefined && params.beforeId !== null) {
        const idx = entries.findIndex((e) => e.id === params.beforeId);
        if (idx < 0) {
          send({ jsonrpc: '2.0', id, error: { code: -32000, message: 'unknown beforeId: ' + params.beforeId } });
          return;
        }
        end = idx;
      }
      const start = Math.max(0, end - limit);
      const page = entries.slice(start, end).map((e) => ({ id: e.id, role: e.role, text: e.text, complete: true }));
      send({ jsonrpc: '2.0', id, result: { messages: page, hasMore: start > 0 } });
      });
      return;
    }
    // runtime/prepare: materialise the harness this plugin drives. The manifest pins it
            // (runtime.package + runtime.version) and this adapter installs exactly that
            // version into <plugin>/runtime, the directory the manifest's command is relative
            // to. The hub asks for this and verifies the result; it never installs a harness
            // itself and knows nothing about packages or release layouts.
                case 'runtime/prepare': {
              const mf = path.join(PLUGIN_DIR, 'manifest.json');
              let manifest = {};
              try { manifest = JSON.parse(fs.readFileSync(mf, 'utf8')); } catch (e) {
                send({ jsonrpc: '2.0', id, result: { ready: false, detail: `cannot read ${mf}: ${e.message}` } });
                return;
              }
              const rt = manifest.runtime;
              if (!rt || !rt.package || !rt.version) {
                send({ jsonrpc: '2.0', id, result: { ready: true, detail: 'no runtime declared: this adapter brings its own' } });
                return;
              }
              const dir = path.join(PLUGIN_DIR, 'runtime');
              const rel = Array.isArray(rt.command) ? rt.command.slice(1).find((p) => !String(p).startsWith('-')) : null;
              const target = rel ? path.resolve(PLUGIN_DIR, rel) : null;
              if (target && fs.existsSync(target)) {
                send({ jsonrpc: '2.0', id, result: { ready: true, package: rt.package, version: rt.version, target, detail: 'already present' } });
                return;
              }
              // npm's own output would corrupt the JSON-RPC stream on stdout, so it is echoed
              // to stderr: the hub keeps the last lines and shows them when something fails.
              const run = (cmd, args, opts) => {
                const r = spawnSync(cmd, args, { cwd: dir, windowsHide: true, shell: process.platform === 'win32', encoding: 'utf8', ...opts });
                if (r.stdout) process.stderr.write(String(r.stdout));
                if (r.stderr) process.stderr.write(String(r.stderr));
                return r;
              };
              const spec = `${rt.package}@${rt.version}`;
              fs.mkdirSync(dir, { recursive: true });
              let done = null;
              try {
                if (rt.mode === 'package') {
                  const pkg = path.join(dir, 'package.json');
                  if (!fs.existsSync(pkg)) fs.writeFileSync(pkg, JSON.stringify({ name: `agent-hub-runtime-${manifest.id}`, private: true }, null, 2) + String.fromCharCode(10));
                  const r = run('npm', ['install', '--omit=dev', '--no-audit', '--no-fund', spec]);
                  if (r.status !== 0) done = `npm install ${spec} exited ${r.status}`;
                } else {
                  const packed = run('npm', ['pack', spec]);
                  if (packed.status !== 0) done = `npm pack ${spec} exited ${packed.status}`;
                  else {
                    const tgz = String(packed.stdout || '').trim().split(String.fromCharCode(10)).pop();
                    const unpack = run('tar', ['xzf', tgz]);
                    if (unpack.status !== 0) done = `tar xzf ${tgz} exited ${unpack.status}`;
                    else {
                      const inner = path.join(dir, 'package');
                      if (fs.existsSync(inner)) {
                        for (const entry of fs.readdirSync(inner)) fs.renameSync(path.join(inner, entry), path.join(dir, entry));
                        fs.rmSync(inner, { recursive: true, force: true });
                      }
                      fs.rmSync(path.join(dir, tgz), { force: true });
                      if (fs.existsSync(path.join(dir, 'package.json'))) {
                        const r = run('npm', ['install', '--omit=dev', '--no-audit', '--no-fund']);
                        if (r.status !== 0) done = `npm install (dependencies) exited ${r.status}`;
                      }
                    }
                  }
                }
              } catch (e) {
                done = e.message;
              }
              const ready = !done && (!target || fs.existsSync(target));
              if (!done && target && !fs.existsSync(target)) done = `the install did not produce ${rel}, which the manifest's command points at`;
              send({ jsonrpc: '2.0', id, result: {
                ready,
                package: rt.package,
                version: rt.version,
                target,
                detail: done || `installed ${spec}`,
              } });
              return;
            }
        default:
      if (configPlane(method, id, params) !== false) return;
      send({ jsonrpc: '2.0', id, error: { code: -32601, message: `unknown plugin method ${method}` } });
  }
}

// --- main ---------------------------------------------------------------------
let lineBuf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => {
  lineBuf += d;
  let i;
  while ((i = lineBuf.indexOf('\n')) >= 0) {
    const line = lineBuf.slice(0, i);
    lineBuf = lineBuf.slice(i + 1);
    if (line.trim()) handle(JSON.parse(line));
  }
});
function shutdownSharedDsh() {
  // The OWNER stops the server; an adapter that merely attached has dsh === null
  // and leaves it alone. There is no "the user's daemon" left to preserve: the hub
  // owns the home the server runs in, so the branch that used to unref here went
  // away with the system scope.
  if (dsh) { try { dsh.kill(); } catch {} }
}
process.stdin.on('end', () => {
  shutdownSharedDsh();
  process.exit(0);
});
process.on('exit', () => { shutdownSharedDsh(); });
process.on('SIGTERM', () => { shutdownSharedDsh(); process.exit(0); });
process.on('SIGINT', () => { shutdownSharedDsh(); process.exit(0); });
