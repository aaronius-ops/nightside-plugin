"""CLI: extract | render | sync. Prints counts only, never transcript text.

  extract <paths...> --ledger docs/agents/ledger.jsonl [--map docs/agents/node_map.json] [--graph GRAPH.yaml]
          [--deny tools/deny.py] [--deny-skip infra,file,code] [--project SLUG] [--no-merge]
      Without a deny file (no --deny and no deny.json next to the ledger) descriptions are written as the run's
      kind only, never free text.
      Parse the sessions under <paths> (archive dirs, ~/.claude/projects/<proj>, or single <session>.jsonl files),
      build rows, apply the node map, merge with the existing ledger (keeps curated/hand-mapped fields), write.
  render --ledger docs/agents/ledger.jsonl --out docs/agents/LEDGER.md [--title T] [--preamble NOTES.md]
      Deterministic summary tables (runs by kind/model/node, orchestrator models per session, tokens, verdicts).
  list --ledger docs/agents/ledger.jsonl [--unmapped]
      One line per agent run (id, session, kind, model, node, workstream, description): the mapping worklist.
  sync [--latest | --all | --session ID --transcript PATH] [--cwd DIR]
      Copy transcripts into the private archive (same code path as the hook). See archive.py.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import archive, render
from .extract import session_rows
from .guard import Guard, GuardError
from .ledger import apply_map, excluded, graph_node_ids, load_map, merge, read_ledger, write_ledger
from .transcripts import discover


def cmd_extract(a) -> int:
    deny = a.deny
    if not deny and (Path(a.ledger).parent / "deny.json").is_file():
        deny = str(Path(a.ledger).parent / "deny.json")  # the project's own deny list next to the ledger
    try:
        guard = Guard(deny, [x for x in (a.deny_skip or "").split(",") if x])
    except GuardError as e:
        print(f"ledger: {e}", file=sys.stderr)
        return 2
    sessions = discover(a.paths)
    if not sessions:
        print("ledger: no sessions found under the given paths", file=sys.stderr)
        return 1
    try:
        rows, stats = session_rows(sessions, guard, a.project)
    except GuardError as e:
        print(f"ledger: {e}", file=sys.stderr)
        return 2
    m = load_map(a.map)
    gids = graph_node_ids(a.graph)
    keep, dropped = [], set()
    for r in rows:
        if excluded(r, m):
            dropped.add(r["key"])
        else:
            keep.append(apply_map(r, m, gids))
    old = [] if a.no_merge else read_ledger(Path(a.ledger))
    stale = {r["key"] for r in old if excluded(r, m)}  # the map excludes stored rows too, transcript or not
    out = [r for r in merge(old, keep, dropped | stale) if r["key"] not in stale]
    try:
        changed = write_ledger(Path(a.ledger), out, guard)
    except GuardError as e:
        print(f"ledger: {e}", file=sys.stderr)
        return 2
    runs = [r for r in out if r.get("record") == "agent_run"]
    print(f"sessions {stats.get('sessions', 0)}, subagent transcripts {stats.get('subagent_transcripts', 0)}, "
          f"excluded by map {len(dropped | stale)}, guard changed {changed} stored field(s), redacted descriptions {stats.get('redacted_descriptions', 0)}; "
          f"ledger: {len(runs)} agent runs, {len(out) - len(runs)} session rows "
          f"({sum(1 for r in runs if r.get('node') in (None, 'unmapped'))} unmapped) -> {a.ledger}")
    return 0


def cmd_list(a) -> int:
    for r in read_ledger(Path(a.ledger)):
        if r.get("record") != "agent_run" or (a.unmapped and r.get("node") not in (None, "unmapped")):
            continue
        print("\t".join(str(x) for x in (r["agent_id"][:12], str(r.get("session"))[:8], r.get("kind"),
                                          str(r.get("model_used") or "").replace("claude-", ""), r.get("node"),
                                          r.get("workstream"), r.get("branch"), r.get("description"))))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="agent_ledger")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extract")
    e.add_argument("paths", nargs="+")
    e.add_argument("--ledger", required=True)
    e.add_argument("--map")
    e.add_argument("--graph")
    e.add_argument("--deny", help="deny file (.py with DENY / .json); default <ledger dir>/deny.json when present")
    e.add_argument("--deny-skip", help="comma-separated deny classes NOT applied to ledger text (e.g. infra,file,code)")
    e.add_argument("--project")
    e.add_argument("--no-merge", action="store_true")
    r = sub.add_parser("render")
    r.add_argument("--ledger", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--title", default="Agent-work ledger")
    r.add_argument("--preamble", help="markdown inserted after the title (e.g. docs/agents/LEDGER_NOTES.md)")
    li = sub.add_parser("list")
    li.add_argument("--ledger", required=True)
    li.add_argument("--unmapped", action="store_true")
    s = sub.add_parser("sync")
    archive.add_sync_args(s)
    a = ap.parse_args(argv)
    if a.cmd == "extract":
        return cmd_extract(a)
    if a.cmd == "list":
        return cmd_list(a)
    if a.cmd == "render":
        return render.main(Path(a.ledger), Path(a.out), a.title, Path(a.preamble) if a.preamble else None)
    return archive.cmd_sync(a)
