"""Nightside agent ledger: a deterministic, metadata-only ledger of the agent runs in archived Claude Code sessions.

  python3 <plugin>/scripts/agent_ledger extract <session or project dirs...> --ledger docs/agents/ledger.jsonl
  python3 <plugin>/scripts/agent_ledger sync [--latest | --session ID --transcript PATH | --all]
  python3 <plugin>/scripts/agent_ledger/archive.py --hook        (the SessionEnd / PreCompact hook; stdin = hook JSON)

Stdlib only. Transcripts are read-only inputs; nothing from a prompt or a report is ever written, only metadata
derived from them (counts, models, timestamps, statuses, verdict words, branch names, commit hashes).
"""

SCHEMA_VERSION = 1
