# sabishii-me-harness-deepseek — the DeepSeek Harness (`dsh`) plugin

The adapter spawns `dsh web --no-open --port 0` (the port is parsed from the server's stdout banner) and talks to it over loopback only: unary JSON-RPC (`POST /api/<method>`) plus one downlink WebSocket (`/api/events.mux`) carrying the harness's own session event stream — text and reasoning deltas, tool calls and results, approvals, questions, and real cross-process resume. Nothing in the harness is patched. Only the adapter that STARTED a home's server sweeps stale `hub-*` (and legacy `prts-*`) provider routes from it, so an attached adapter cannot delete a route a running session injected.

This repository is one harness plugin for
[`sabishii-me-agent-hub`](https://github.com/sabishii-me/sabishii-me-agent-hub): the
adapter that drives DeepSeek Harness (`dsh`), its manifest, the harness-side extensions it installs,
and (where the harness needs one) the preset definitions it applies. The hub's
`docs/PROTOCOL.md` is the contract this adapter implements.

```
manifest.json          id, command, runtime pin, extensions, capabilities
deepseek-adapter.cjs      the adapter (adapter-v1 over stdio)
extensions/            dsh-presets, hub-command-approval
```

* runtime: `@deepseek-ai/dsh@0.1.0-rc.7` → `node runtime/lib/bin.js` (materialised under `runtime/`, not committed)
* protocol: adapter-v1, version 0
* capabilities declared: models, providers, presets, plan, review, fork, stats, compact, rename, skills

## How the hub uses this directory

The hub never contains harness code. A deployment points it at a plugins directory
(`AGENT_HUB_PLUGINS_DIR`, default `<hub>/plugins`); the hub scans it for directories with a
`manifest.json`, and this directory *is* the plugin:

| what | who reads it |
| --- | --- |
| `manifest.json` | the hub: id, `command`, the runtime pin, the extension ids, and the capabilities this adapter implements |
| `deepseek-adapter.cjs` | the hub spawns it (`command`) and speaks `adapter-v1` with it |
| `extensions/<id>/` | the hub copies the ids the manifest declares into that harness's own data dir and hands the adapter the path (`AGENT_HUB_INSTALLED_EXTENSIONS_DIR`); the adapter places them where its harness reads extensions |
| `presets/` | the adapter, which lists them for `presets` and writes the chosen one where its harness-side extension reads it (`AGENT_HUB_PRESETS_DIR`) |
| `runtime/` | the harness itself — an official npm release, **never committed** (`.gitignore`) |

The runtime is materialised from the manifest's pin — by THIS ADAPTER, through its
`runtime/prepare` method, so "which version runs" is answered here and nowhere else:

```
POST /v1/hub/plugins/deepseek/prepare        # asks this adapter; answers {ready, package, version, target, detail}
```

The hub also asks for it by itself, before the first `session/start`, whenever the
declared command is not on disk yet — so a freshly installed plugin simply works: the
session waits for the install instead of failing. The hub installs no harness itself and
knows no package names.

A hub started against a plugins directory that contains this one lists `deepseek` in
`GET /v1/harnesses`, and the hub's boot self-check validates this manifest against
`contract/adapter-v1.json` (declared fields, protocol version, capability ⇔ adapter
method) before it serves anything.

## Changing it

This repository is the plugin's home: edit here, commit, push. A deployment that
composes plugins pins a commit (later a tag) of this repository and bumps the pointer
there. The harness's own protocol quirks live in the adapter and belong to whoever
tracks that harness.
