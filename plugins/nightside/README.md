# Nightside plugin 0.2.0

A Claude Code plugin that records the SHAPE of your agentic work in each project (which tools ran, how many
subagents, how long; never what you typed, which files, or what came back), shows you byte for byte what that
summary looks like, and, only when you confirm it, sends it to your planet on [Nightside](https://nightside.world).
It also keeps a private local archive of your agent transcripts and a metadata-only agent ledger for long
multi-agent builds.

Install with `/plugin marketplace add aaronius-ops/nightside-plugin` then `/plugin install nightside@nightside`.
First upload: [INSTALL.md](../../INSTALL.md).

| component | what it does |
|---|---|
| `commands/planet.md` | `/planet name \| privacy \| status \| preview [--label --category] \| upload \| withdraw \| remote`: your planet from the local capture, each project's public label (no back-fill); uploads only bytes you confirm |
| `hooks/hooks.json` | capture hooks that spool workflow metadata locally; `SessionEnd` + `PreCompact` hooks that archive transcripts locally |
| `scripts/capture/` | capture hook, Surveyor, allow-list, consent preview, opt-in rich summary, the privacy auditor |
| `commands/nightside-ledger.md` | `/nightside-ledger`: archive this session, then refresh the agent ledger |
| `agents/ledger-analyst.md` | Sonnet agent that maps agent runs to graph nodes and writes `LEDGER.md` |
| `skills/graph-engineered-workflows` | a working practice for multi-agent builds: program graph, event log, worktrees, review gate, gates, ledger |
| `scripts/agent_ledger/` | the stdlib extractor, renderer and archiver behind the ledger |

Requirements: Claude Code with plugin support, `python3` 3.9 or newer on your `PATH` (the macOS system Python is
fine), and git. No pip packages.

## Capture (local; uploads only what you confirm)

The plugin turns each project's hook events into a `WorkflowManifest` (`scripts/capture/workflow_manifest.schema.json`)
and shows you, byte for byte, what would leave. **Nothing leaves until you set a Nightside server and an upload
credential AND confirm a project's exact bytes** (see Upload below). The hooks, the Surveyor, the preview, `status` and
every other `/planet` subcommand open no network connection; `upload --confirm` and `withdraw --confirm`
(`scripts/capture/upload.py`) are the only requests, and tests pin that both by a grep of the whole plugin and with a
runtime socket guard. The opt-in rich summary below runs `claude -p`.

### What the hooks record

Hook events, per the Claude Code hooks reference (code.claude.com/docs/en/hooks, read 2026-10-22):
`SessionStart`, `UserPromptSubmit`, `PostToolUse`, `PostToolUseFailure`, `SubagentStart`, `SubagentStop`, `Stop`,
`PreCompact`, `PostModelSwitch`, `SessionEnd`. One spool line per event, and only:

| key | value |
|---|---|
| `ev`, `t` | the event name; a UTC timestamp the hook stamps (payloads carry none) |
| `s`, `a` | the session id and the agent id as keyed hashes (16 and 12 hex) |
| `at` | a built-in agent type (`Explore`, `general-purpose`, ...) as-is; any other (custom or plugin agent) as `custom-<keyed hash>`; `other` if not plainly a name |
| `tool`, `ms`, `ok` | a built-in tool NAME as-is, an MCP tool as `mcp__<keyed server hash>__<tool>`; the payload's `duration_ms`; success or failure |
| `model` | `SessionStart.model` / `PostModelSwitch.to_model` (`claude-...` only, else `other`) |
| `src`, `reason`, `trigger` | the SessionStart source, SessionEnd reason, PreCompact trigger enums |
| `k` | for the public label only: the CLASS of a written file's suffix (`ext-audio` for `.wav`) or of a Bash command's program word (`cmd-test` for `pytest`), from closed tables in `labels.py`; nothing when the value is not in a table. Stays local |

Never written: `tool_input` (two of its fields, Write/Edit's `file_path` and Bash's `command`, are looked up in the
closed tables above and dropped; the path, the file and folder names and the command line are never kept). Never read
or written: `tool_response`, `error`, `prompt`, `last_assistant_message`,
`custom_instructions`, `compact_summary`, `session_title`, `cwd` and every other path, `transcript_path` /
`agent_transcript_path` and the files they point to. The project is a keyed hash of its repository root (worktrees of
one repo are one project); the readable repo slug is written only to the local index `projects.json`, and the
readable MCP server names and custom agent types only to the local reverse map `names.json` (the preview shows them
to you as a legend; they are never in the bytes).

**Why command hooks and a spool, not an http hook and a collector.** The docs offer `http` hooks, but `SessionStart`
does not support them, and a collector is a long-running process listening on a port that something must start,
supervise and secure. A command hook with `"async": true` (supported on command hooks only) runs in the background,
cannot block Claude, and appends one line with one `O_APPEND` write. Every capture hook is async except `SessionEnd`
(5 s timeout; sessions share a 1.5 s SessionEnd budget raised to the largest per-hook timeout), which only appends
its line: the Surveyor and retention run in the next session's async `SessionStart` hook, or on `/planet`. The hook
prints nothing (an async hook's stdout would reach Claude on the next turn) and always exits 0. A call takes about
0.1-0.2 s of background time.

**The key.** Every hash is keyed with `key`, 32 random bytes created once: written in full to a temp file, fsynced,
then published with `os.link`, so concurrent first hooks agree and nobody reads a partial key. A key file that is not
exactly 64 hex characters (a crash, a full disk) fails closed: nothing is recorded and the hook logs it. Delete the
file to rotate (old hashes then stop matching).

### Where

`~/.nightside/capture/` (folders 700, files 600): `key`, `spool/<project_id>/<session hash>.jsonl`,
`sessions/<project_id>/<session hash>.json` (per-session summaries), `projects.json`, `names.json`,
`outbox/<project_id>.json` (latest manifest), `.envelope` (the bytes the last preview showed), `.lock`, `.spool.lock`, `_logs/`.
Retention: a summarized session's raw spool is folded into its summary and deleted once idle longer than
`spool_retention_days` (30); summaries older than `summary_retention_days` (365) are deleted, and that history is then
gone. Above `max_capture_mb` (32) the raw spool of closed, summarized sessions is folded and deleted, oldest first;
the size cap never deletes a summary or touches an open session's spool, and logs when it cannot get under the cap.
A session is closed while its last event is a `SessionEnd`; resuming it re-opens it. A session that resumes after its spool was evicted keeps its history. Eviction runs under `.spool.lock` (waited on briefly, then skipped), counts every spool byte exactly once even if it is interrupted, and leaves a file alone if a line landed after it was counted. Reads are capped at 32 MB, newest first. The root is refused inside a git work tree or a
cloud-synced folder, with the archive hook's own checks. Settings: `~/.config/nightside/capture.json` (written by
`/planet`). Off switch: `NIGHTSIDE_CAPTURE=0` or `"enabled": false`. Overrides: `NIGHTSIDE_CAPTURE_ROOT`,
`NIGHTSIDE_CAPTURE_CONFIG`.

### The Surveyor and the manifest

In the next session's async `SessionStart` (and on `/planet status --survey` and `/planet preview`)
`scripts/capture/surveyor.py` folds the spool (incrementally: closed sessions are cached as summaries), plus the repo's
`docs/agents/ledger.jsonl` rows if it has one (agent type, model, timings; never a description), into one manifest per
project. Deterministic, no model call. How each field is derived is in the module docstring. Then the allow-list
(`allowlist.py`) checks the schema and gives every string a rule for its exact key path; anything else is refused
and nothing is written.

Defaults: tier **metadata** (no project name, no summary, MCP tools folded to `mcp-<server hash>`), new projects
**private**, and a private project always leaves at the metadata tier. At every tier, custom agent types and MCP
server names leave only as keyed hashes. `/planet privacy rich` and `/planet privacy public` loosen that per user or
per project; a project name leaves only if you chose one (`/planet privacy public --name "My Project"`), never the
repo's folder name.

Synthetic example (two invented sessions from the test fixtures: one Explore subagent, Read/Grep/Write/Edit and a
GitHub PR tool), metadata tier, the 759 bytes the preview prints:

```json
{"manifest":{"agents":[{"minutes":10.0,"model_tier":"opus","role":"orchestrator","turns":4},{"minutes":4.0,"model_tier":"other","role":"Explore","turns":2}],"category":"unclassified","graph_shape":"orchestrator+subagents","infra_tags":[],"label":{"category":"unclassified","source":"heuristic","text":"Agentic workflow"},"links_to":[],"mcp_servers":["srv-755615af"],"outcomes":{"artifacts":0,"deploys":0,"files_written":2,"prs":2},"privacy_tier":"metadata","project_id":"0b852bd84dbf9866","runs":{"count":2,"first_at":"2027-01-15T08:00:00Z","last_at":"2027-01-15T10:05:00Z","total_minutes":10.0},"skills":[],"tools":{"Edit":2,"Grep":2,"Read":2,"Write":2,"mcp-755615af":2},"user_id":"local"},"schema":"nightside/upload-envelope/0-draft","visibility":"private"}
```

At the rich tier (public, with `--name "Demo Project"`) the same project adds `"project_name":"Demo Project"` and
keeps the MCP tool's own name after the hashed server, `mcp__755615af__create_pull_request` (806 bytes); the server
name (`github`) appears only in your local legend. The subagent's model tier is `other` because hook payloads do
not carry a subagent's model; a ledger row supplies it when the repo has one.

### Public label

Each project gets a short public label made on this machine: a phrase of at most 40 characters plus a category from
the world builder's vocabulary (`label_vocab.json`, a frozen copy of the server's list). The manifest carries it as `label: {text, category, source}` (`nightside/workflow-manifest/2`); the builder
places the island from it. Without it a metadata-tier manifest has no name at all.

- **heuristic** (default, no network): a fixed phrase chosen from the `k` classes and tool names, e.g. `.wav` writes
  plus `ffmpeg` give "Voice and audio pipeline" / `media-pipeline`. Never from a file, folder, repo or command name.
- **claude** (opt-in): the rich summary may propose one; model text must use only the closed word list.
- **user**: `/planet preview --label "..." --category <c>` (`--label auto` resets). At the metadata tier (every
  private project) only generic words from the list; at the rich tier free text with the project-name rules.

Every label passes the allow-list for the project's current tier (shape, 40 characters, no `. / : @ _`, no run of 3+
digits, guard-clean) and must not repeat a local name (the repo slug, raw MCP server and custom agent names, the
login); a failing label falls back to the next candidate, and the preview says which one leaves. The user's label
wins, and with it the manifest's `category` is the user's.

### No back-fill

A planet grows only from what the plugin captures from now on: one island per project you work in with it
installed. There is no import of past sessions, repositories or transcripts; `/planet backfill` and `/planet import`
print that and exit.

### Consent

`/planet preview` re-surveys, re-checks and prints, per project, the visibility, tier, byte count, sha256 and the
exact request body, with the project's PUBLIC LABEL printed above it, and saves exactly those bytes (`outbox/<project_id>.envelope`). A y/n per project, and a yes is
bound to the hash of the saved bytes (`/planet upload --confirm <sha256>`). Confirm never re-surveys, so the session's
own activity after the preview cannot change what you approved; it re-checks the saved bytes against the allow-list
and sends exactly them, and only if a server is configured. Without one it answers that upload is not enabled and
makes no network call. A new preview replaces the saved bytes. `invite` and `open` are not in the plugin yet.

### Upload

There is no default server: a fresh install never uploads.

1. Sign in on the Nightside site (https://nightside.world/reserve) and copy your plugin credential (it starts with
   `nsu2.`).
2. In your own terminal, not in a Claude chat (the credential is a secret):
   `python3 <plugin root>/scripts/capture/planet.py remote token`, paste, press Enter (or `--file <file>`). It is kept
   in the capture root (mode 600) and never printed.
3. `/planet remote set https://nightside.world` (the base URL; the plugin appends `/api/manifests`). `https` only
   (plain `http` is accepted for a loopback address, for local development). A raw `*.run.app` host gets a warning.
4. `/planet preview`, then `/planet upload --confirm <sha256>` per project you approve. Before sending, the plugin asks
   `GET <base>/api/plugin` which plugin version the server needs and stops (exit 7, nothing sent) when it is older.
   The request carries exactly the previewed bytes and `Authorization: Bearer <token>`; redirects are refused. The
   server stores them once (sending the same bytes again is a no-op) and answers with the sha256, which the plugin
   checks.

`/planet remote show` says what is configured; `/planet remote clear` removes the server, the token and the signing
key. `/planet status` counts the uploads the server acknowledged (`sent.jsonl` in the capture root).

### Withdraw

`/planet withdraw` prints this directory's project id. `/planet withdraw --confirm <project id>` sends one
`DELETE <base>/api/manifests/projects/<project id>` with your token: the server deletes every manifest of that project
you uploaded (never anyone else's). On this machine the project is set private and its saved preview and manifest
are deleted, so an old `--confirm <sha256>` cannot resend them; `upload --confirm` also refuses saved bytes whose
visibility differs from the project's current setting. When both `GET /api/plugin` and the upload answer 404, the
plugin says the server is not accepting uploads yet (rather than blaming the credential). The id must be a project captured on this machine.

### Signed manifests (envelope v1)

A planet shows only multi-agent workflows, so the server must not take the agent count on trust. The Nightside site gives you
ONE string, the **credential** `nsu2.<nsu1 token>.<signing key>`, and you paste it once with `remote token` (see Upload). The plugin splits it locally: the nsu1 part is the bearer token (`upload_token`), the key goes to
`upload_signing_key` (both mode 600, never printed; the key is never sent). A bare `nsu1` token still works, but
unsigned-only: pasting one removes any earlier signing key. A malformed credential saves nothing.

- **Run evidence.** At each `SubagentStart` the hook adds `r`, a random 16-hex run id (`secrets`, never derived from a
  name, id or time), and `rm`, a MAC of (project, session hash, agent hash, `r`) under the local capture key. Still no
  network in any hook. The Surveyor counts a run only when its `rm` verifies, and never counts forks or runs that
  only the repo's `docs/agents/ledger.jsonl` lists (that file is not hook evidence; those rows stay display-only).
- **Signing.** The preview builds the envelope, then adds `attestation` = `{v, key, runs, sig}`: `runs` = the
  attested run ids (sorted), `sig` = HMAC-SHA256 under the signing key over the sha256 of the canonical unsigned
  envelope (schema, visibility, manifest), the key id and the run ids. The preview shows these bytes, `--confirm`
  sends exactly them, and the G1 audit checks them (every attestation leaf must be the configured key id, a hook run
  id, or the recomputed MAC). With no signing key the preview saves an unsigned v0 envelope and says so.
- **What the server does.** v1: verifies the MAC under the key it derives from the token record (live, not revoked,
  same user and planet), requires `len(runs)` <= the subagent runs the rows claim, and counts **1 + len(runs)**
  agents (decided: the SIGNED runs decide the count; the check is `<=` claimed, not `==`, because rows may also
  hold ledger-only runs the hook never saw). A bad signature is refused (422 `attestation`). v0 (unsigned, or an nsu1
  token): stored, never publishable.

**Threat model, plainly.** The plugin runs on your machine, so it cannot hide a key from you. This stops casual
cheating: hand-editing a count in the preview, padding rows, appending made-up lines to the spool, re-using someone
else's signed manifest, or re-using bytes signed under a revoked token. It does not stop a determined user who reads
this code, takes the key file and writes their own signer, or who launches throwaway subagents to inflate the count.
The fix for that is server-side observation, which Nightside does not do because it would mean uploading transcripts.
Why per-run MACs and not an ordered hash chain: parallel subagents start in separate hook processes at the same
moment, so an on-disk chain would need a cross-process lock in the hook's hot path and would break on a race; a MAC
per run gives the same tamper evidence with no ordering. Why not a server nonce per session: hooks stay offline.

### Rich summary (opt-in, off by default)

`rich.py` asks Haiku for a summary of 60 words or fewer and a category. It runs only when the config has
`"rich_summary": true` (`/planet privacy rich --summary`), the project is at the rich tier (so public), and the user
passes `--rich` to `/planet status --survey`. Never in a hook. The model sees only a subset of the manifest that has
already passed the allow-list (graph shape, agent rows, top tool counts, run and outcome counts, the project name),
through `claude -p --safe-mode --model haiku --tools ""` (no CLAUDE.md, hooks, plugins or MCP; no session saved).
That sends those bytes to Anthropic under your own login (the plugin's other outbound path besides the confirmed upload), and a test asserts
`rich.py` is the only capture module that starts a process. The answer is untrusted: it must pass the allow-list or it
is dropped.

### The privacy gate (G1)

```bash
python3 scripts/capture/audit.py synthetic                    # planted secrets; exit 1 on any leak
python3 scripts/capture/audit.py replay --n 20 --out /tmp/capture-g1   # read-only real transcripts
```

Both feed hook payloads through the real hook, spool, Surveyor and allow-list, then check (a) every spool line,
session summary and manifest string against its provenance, tier by tier (a hash, the hook's clock, an enum, a
built-in name, or a keyed hash of a `tool_name` / `agent_type`; raw MCP or custom names nowhere, the MCP tool's own
name and a chosen project name at the rich tier only), (b) no raw MCP server name, custom agent type or repo slug as
any leaf, (c) every token of 10+ characters from every field capture must not record against the spool and the
outgoing bytes, and (d) 42 red-team cases, in both modes (the replay carries planted-secret sessions alongside the
real ones): secrets in every input field and recorded name field, a manifest poisoned field by field, and a summary
model that answers with secrets. Tests also mutate the hook and the Surveyor to leak and check that G1 fails. The
replay output stays outside the repo and is never committed.

## Agent ledger

Every graph-engineered program keeps two records of its agent work:

1. **A private archive of the raw transcripts.** The orchestrator transcript and every subagent transcript, copied to `~/.nightside/agent-archive/raw/<project>/<session>/` (folders 700, files 600). It lives outside every repo and every cloud-synced folder, because it holds everything the agents saw: prompts, reports, tool output. Claude Code deletes transcripts after `cleanupPeriodDays` (30 by default), so the archive is the record.
2. **A metadata-only ledger in the repo.** `docs/agents/ledger.jsonl`, one row per agent run, plus one row per session with the orchestrator's models, and `docs/agents/LEDGER.md`, the summary tables. No prompt or report text, no secrets, no data values.

### How the pieces fit

```
SessionEnd / PreCompact hook ─┐
/nightside-ledger (sync) ─────┴─> archive.py ─> ~/.nightside/agent-archive/raw/<project>/<session>/
                                                    │
               ledger-analyst (Sonnet) ─> agent_ledger extract ─> docs/agents/ledger.jsonl
                     │  maps runs to nodes via docs/agents/node_map.json (+ the graph file)
                     └─> agent_ledger render ─> docs/agents/LEDGER.md
```

### The hook

`hooks/hooks.json` runs `python3 scripts/agent_ledger/archive.py --hook` on `SessionEnd` (timeout 10 s; Claude Code's default budget for that event is 1.5 s) and `PreCompact` (30 s). It reads the hook JSON on stdin (`session_id`, `transcript_path`, `cwd`, `hook_event_name`), copies `<session>.jsonl` and `<session>/subagents/` incrementally (a file is recopied only when its size or mtime changed, through a temp file and a rename), and always exits 0: it never blocks or fails a session. A typical run takes under 100 ms. Errors go to `<archive root>/_logs/archive-hook.log`.

It copies the transcript and `subagents/` only. **`tool-results/` is intentionally not archived: raw outputs, highest leak risk, not needed for the ledger.** Symlinks are never followed (a symlinked transcript, subagent file or archive folder is skipped or refused), modes are re-applied on every run, and temp files a killed copy left behind are swept on the next run.

Timeout: Claude Code gives all `SessionEnd` hooks a shared 1.5 s budget, raised to the highest per-hook `timeout` (up to 60 s); `CLAUDE_CODE_SESSIONEND_HOOKS_TIMEOUT_MS` overrides it (code.claude.com/docs/en/hooks.md, SessionEnd and "Hook handler fields"). The docs do not say what happens to a hook still running when the budget runs out; the archiver assumes it may be killed, writes through a temp file and an atomic rename, and the next run (PreCompact, `/nightside-ledger`, the next session end) completes the copy.

It refuses an archive root inside a git work tree or under `~/Documents`, `~/Desktop`, `~/Library/Mobile Documents` or `~/Library/CloudStorage`, matched by file identity, case-insensitively (APFS) and through symlinks, and logs the refusal to `~/.nightside/logs/archive-hook.log` instead.

Configuration (optional; the defaults need none): `~/.config/nightside/archive.json` or `$NIGHTSIDE_ARCHIVE_CONFIG`:

```json
{"archive_root": "~/.nightside/agent-archive/raw", "enabled": true, "default_project": null,
 "projects": {"/abs/path/to/repo": "my-project"}}
```

Env overrides: `NIGHTSIDE_ARCHIVE_ROOT`, `NIGHTSIDE_ARCHIVE_PROJECT`, `NIGHTSIDE_ARCHIVE=0` (off). The default project slug is the repository's name (the main repo's, for a linked worktree), else the directory's.

### The extractor

```bash
L="${CLAUDE_PLUGIN_ROOT}/scripts/agent_ledger"
python3 "$L" extract ~/.nightside/agent-archive/raw/<project> --ledger docs/agents/ledger.jsonl \
  --map docs/agents/node_map.json --graph docs/design/GRAPH.yaml [--deny tools/deny.py]
python3 "$L" list --ledger docs/agents/ledger.jsonl --unmapped       # the mapping worklist
python3 "$L" render --ledger docs/agents/ledger.jsonl --out docs/agents/LEDGER.md --preamble docs/agents/LEDGER_NOTES.md
python3 "$L" sync --latest | --all | --session ID [--transcript PATH]
```

- **Inputs.** Archive folders (both the hook layout and the older `main.jsonl` + `session/subagents/` layout), a raw `~/.claude/projects/<project>` folder, or single `<session>.jsonl` files. The same session found twice is read once.
- **Fields.** `schema_version`, `record` (`agent_run` or `session`), `key`, `agent_id`, `session`, `project`, `kind`, `description`, `subagent_type`, `model_requested`, `model_used`, `node`, `workstream`, `node_basis`, `launched_at`, `finished_at`, `status`, `status_history`, `tokens`, `tool_uses`, `duration_ms`, `resumed_count`, `branch`, `commits`, `verdict`, `findings_count`, `findings_basis`, `notes`, `parent_agent_id`, `spawn_depth`, `launch`, `curated`, `description_redacted`. How each is derived is in `extract.py`'s docstring.
- **Idempotent and incremental.** Rows are keyed `<session>/<agent_id>`; a re-run rewrites the same bytes. Rows from sessions not in this run are kept. Fields listed in a row's `curated` list, and a hand-set `node`/`workstream`, survive a refresh; measured fields (tokens, status, timings) are refreshed.
- **Deny list.** `docs/agents/deny.json` next to the ledger (start from `scripts/agent_ledger/deny.template.json`) or `--deny <file>`. Every class in it is applied; `ledger_skip` / `LEDGER_SKIP` / `--deny-skip` leave classes out. **No deny file: descriptions are the run's kind only.** The generic secret, contact, URL/host/IP, money-amount and home-path scrub always runs, whatever the deny file says.
- **Metadata only, fail closed.** Prompts and reports are read in memory to derive a branch name, commit hashes, verdict words and a findings count, and are never written. The only free text is the Agent call's short `description`, scrubbed by `guard.py` (credentials, e-mails, URLs, hosts, IPs, phones, money amounts, home-directory paths, plus the project deny list) on the full string before it is cut to length. Every row is guarded again on every write, stored and hand-curated rows included. A deny file that fails to load stops the run; a credential-shaped field is nulled.
- **Stdlib only**, Python 3.9+.

## Tests

From the repository root: `python3 -m pytest plugins/nightside/scripts` (needs `pytest`; synthetic fixtures only, no
network: a socket guard refuses every connection).
