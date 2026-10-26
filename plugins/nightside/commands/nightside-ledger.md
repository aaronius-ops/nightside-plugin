---
description: Archive this session's transcripts to the private agent archive, then refresh the project's agent-work ledger (docs/agents/ledger.jsonl + LEDGER.md) with the ledger-analyst agent. Metadata only.
argument-hint: [--refresh-only] [--all-sessions] [--archive <dir>]
---

# /nightside-ledger

Preserve this session's agent work and bring the project's ledger up to date. Arguments: `$ARGUMENTS`.

1. **Find the extractor.** `LEDGER_PY="${CLAUDE_PLUGIN_ROOT}/scripts/agent_ledger"`. If that path does not exist, use `ls -d ~/.claude/plugins/cache/*/nightside/*/scripts/agent_ledger | tail -1`. Stop if neither exists.

2. **Sync the archive** (skip with `--refresh-only`). From the project root:

   ```bash
   python3 "$LEDGER_PY" sync --latest          # this session: the newest transcript of this directory
   python3 "$LEDGER_PY" sync --all             # with --all-sessions: every session of this directory
   ```

   It copies `<session>.jsonl` and `<session>/subagents/` into `<archive root>/<project>/<session>/` (700/600), only what changed, and prints counts. The same code runs in the plugin's `SessionEnd` and `PreCompact` hooks. If it prints `sync refused`, the archive root is inside a repo or a cloud-synced folder: stop and tell the user to set `NIGHTSIDE_ARCHIVE_ROOT` (or `archive_root` in `~/.config/nightside/archive.json`) to a folder outside every repo and synced folder; the default `~/.nightside/agent-archive/raw` is fine. Never copy transcripts anywhere else by hand, and never print their contents.

3. **Refresh the ledger.** Launch the `ledger-analyst` agent (Sonnet) with a brief that names: `REPO` (this repo root), `LEDGER_PY`, `ARCHIVE` (`--archive <dir>` if given, else `<archive root>/<project>` from step 2's output), and whether to commit (default: do not). Wait for its report.

4. **Report** to the user in a few lines: what was archived (files, bytes), the ledger's run count before and after, unmapped runs, and the files changed (`git diff --stat docs/agents`). Suggest committing `docs/agents/` when the diff looks right. The archive itself is private: it is never committed, uploaded or shared.
