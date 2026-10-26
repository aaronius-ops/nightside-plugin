"""Ledger file I/O, the merge with an existing ledger, and node mapping.

Merge rules (idempotent, incremental):
  * rows are keyed by `key` ("<session>/<agent_id>" or "session/<session>"); legacy rows without a key get
    "<session>/<agent_id>". Re-running never duplicates a row.
  * a fresh extraction replaces the measured fields of an existing row; fields named in the row's `curated`
    list keep the stored value. `node` and `workstream` are always kept when the stored value is set and the new
    one is not, so hand mapping survives a refresh without a map file.
  * legacy rows (no schema_version, from an earlier hand-built ledger) were mapped and checked by hand: on first
    merge their judgement fields (LEGACY_CURATED) are marked curated and kept.
  * stored rows that this extraction did not produce (other sessions, or transcripts since deleted) are kept
    untouched (incremental); only a row the node map now excludes is dropped.

Node map (docs/agents/node_map.json, written by the ledger-analyst agent; all keys optional):
  {"rules":   [{"match": "<regex on description>", "node": "T05", "workstream": "client"},
               {"match": "Evaluate Jev", "exclude": true}],
   "agents":  {"<agent_id>": {"node": "W2", "workstream": "islands"}, "<agent_id>": {"exclude": true}},
   "sessions": {"<session id>": {"exclude": true} | {"include_only": ["<agent id prefix>", ...]}}}
Precedence: curated value > map "agents" > map "rules" (first match) > a graph node id named in the description
(--graph) > null. Every mapped row records how in `node_basis`.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from . import SCHEMA_VERSION

LEGACY_CURATED = ("node", "workstream", "kind", "description", "branch", "verdict", "findings_count",
                  "findings_basis", "notes")
ALWAYS_KEEP = ("node", "workstream")


def read_ledger(p: Path) -> list[dict]:
    if not p or not Path(p).is_file():
        return []
    out = []
    for line in Path(p).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(r, dict):
            out.append(normalise(r))
    return out


def normalise(r: dict) -> dict:
    """A stored row in the current shape (legacy rows get record/key/curated)."""
    r = dict(r)
    if "schema_version" not in r:
        r.setdefault("record", "agent_run")
        r["curated"] = sorted(set(r.get("curated") or []) | {k for k in LEGACY_CURATED if k in r})
        r["legacy"] = True
    r.setdefault("record", "agent_run")
    if not r.get("key"):
        r["key"] = (f"session/{r.get('session')}" if r["record"] == "session"
                    else f"{r.get('session')}/{r.get('agent_id')}")
    return r


def merge(old: list[dict], new: list[dict], dropped: set[str] = frozenset()) -> list[dict]:
    by = {r["key"]: r for r in old}
    out = {}
    for r in new:
        prev = by.get(r["key"])
        if prev is None:
            out[r["key"]] = r
            continue
        m = dict(r)
        cur = set(prev.get("curated") or [])
        for k in cur:
            if k in prev:
                m[k] = prev[k]
        if "node" in cur and prev.get("node") is not None:
            m["node_basis"] = prev.get("node_basis") or "curated"
        for k in ALWAYS_KEEP:
            if k not in cur and m.get(k) is None and prev.get(k) is not None:
                m[k] = prev[k]
                if k == "node":
                    m["node_basis"] = prev.get("node_basis") or "stored"
        if prev.get("project") and not prev.get("legacy"):
            m["project"] = prev["project"]  # the slug a run was first archived under stays (same session, 2 copies)
        m["curated"] = sorted(cur)
        out[r["key"]] = m
    for k, r in by.items():  # incremental: rows of sessions not in this extraction, and rows whose transcript is
        if k not in out and k not in dropped:  # gone (cleanup), stay as they were
            out[k] = r
    rows = list(out.values())
    for r in rows:
        r.pop("legacy", None)
        r["schema_version"] = SCHEMA_VERSION
    rows.sort(key=lambda r: (r.get("record") or "", r.get("launched_at") or r.get("first_ts") or "", r["key"]))
    return rows


SKILL_DESC = re.compile(r"^/code-review [A-Za-z0-9?][\w./,+?-]{0,99} \((?:skill-launched|unnamed) review\)$")
FREE_TEXT = ("description", "workstream", "node", "branch", "verdict", "findings_basis", "notes", "node_basis")


def guard_rows(rows: list[dict], guard) -> tuple[list[dict], int]:
    """Every row is guarded on every write, stored and curated rows included (they were written by older code or by
    hand). Free text is re-scrubbed; with no deny file a description becomes the run's kind; a field that still
    carries a credential shape is nulled. (rows, fields changed)."""
    from .guard import CREDENTIAL, Guard, check_row
    generic = Guard()  # notes are code-generated templates: generic scrub only, deny classes would mangle them
    changed = 0
    out = []
    for r in rows:
        r = dict(r)
        for k in FREE_TEXT:
            v = r.get(k)
            if v is None:
                continue
            if k == "description" and r.get("record") == "agent_run":
                if isinstance(v, str) and SKILL_DESC.match(v) and guard.scrub(v.split(" ")[1])[0] == v.split(" ")[1]:
                    continue
                if not guard.deny_loaded:
                    new = r.get("kind") or "other"
                    if new != v:
                        r[k], r["description_redacted"] = new, True
                        changed += 1
                    continue
            new, red = (generic if k == "notes" else guard).scrub(v, 400 if k == "notes" else 160)
            if new != v:
                r[k] = new
                changed += 1
                if k == "description":
                    r["description_redacted"] = True
        for k, v in list(r.items()):
            if isinstance(v, str) and CREDENTIAL.search(v):
                r[k] = None
                changed += 1
        check_row(r)  # still raises if a list or nested value carries one: nothing unguarded is written
        out.append(r)
    return out, changed


def write_ledger(p: Path, rows: list[dict], guard) -> int:
    """Guard every row (guard_rows), then write atomically. Returns the number of fields the guard changed."""
    rows, changed = guard_rows(rows, guard)
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=False) + "\n")
    os.replace(tmp, p)
    return changed


# ---------------------------------------------------------------------------------------------- mapping ---
def load_map(p: Path | None) -> dict:
    if not p:
        return {}
    p = Path(p)
    if not p.is_file():
        return {}
    m = json.loads(p.read_text(encoding="utf-8"))
    for r in m.get("rules") or []:
        re.compile(r["match"])  # a bad regex is an error, not a silent miss
    return m


def graph_node_ids(p: Path | None) -> list[str]:
    """Node ids from graph.json / GRAPH.yaml ({"nodes": [{"id": ...}]}). YAML needs PyYAML; without it, a
    line scan for `id:` entries under `nodes:` is used."""
    if not p:
        return []
    p = Path(p)
    if not p.is_file():
        return []
    txt = p.read_text(encoding="utf-8")
    nodes = None
    if p.suffix == ".json":
        nodes = (json.loads(txt) or {}).get("nodes")
    else:
        try:
            import yaml  # type: ignore
            nodes = (yaml.safe_load(txt) or {}).get("nodes")
        except ImportError:
            sect = re.split(r"^nodes:\s*$", txt, maxsplit=1, flags=re.M)
            body = re.split(r"^\S", sect[1], maxsplit=1, flags=re.M)[0] if len(sect) > 1 else ""
            return sorted(set(re.findall(r"\bid:\s*['\"]?([A-Za-z0-9._-]{1,24})", body)))
    if isinstance(nodes, dict):
        return sorted(nodes)
    return sorted({str(n.get("id")) for n in nodes or [] if isinstance(n, dict) and n.get("id")})


def excluded(row: dict, m: dict) -> bool:
    if row.get("record") != "agent_run":
        return False
    s = (m.get("sessions") or {}).get(row["session"]) or {}
    if s.get("exclude"):
        return True
    if s.get("include_only") is not None and not any(row["agent_id"].startswith(x) for x in s["include_only"]):
        return True
    a = (m.get("agents") or {}).get(row["agent_id"]) or {}
    if a.get("exclude"):
        return True
    if "include" in a:
        return not a["include"]
    for r in m.get("rules") or []:
        if r.get("exclude") and re.search(r["match"], row.get("description") or ""):
            return True
    return False


def apply_map(row: dict, m: dict, graph_ids: list[str]) -> dict:
    if row.get("record") != "agent_run":
        return row
    a = (m.get("agents") or {}).get(row["agent_id"]) or {}
    if a.get("node"):
        row.update(node=a["node"], workstream=a.get("workstream"), node_basis="map:agent")
        for k in ("kind",):
            if a.get(k):
                row[k] = a[k]
        return row
    d = row.get("description") or ""
    for r in m.get("rules") or []:
        if r.get("node") and re.search(r["match"], d):
            row.update(node=r["node"], workstream=r.get("workstream"), node_basis=f"map:rule {r['match'][:40]}")
            return row
    hits = [g for g in graph_ids if re.search(rf"(?<![\w-]){re.escape(g)}(?![\w-])", d)]
    if hits:
        row.update(node=",".join(hits), node_basis="graph id in description")
    return row
