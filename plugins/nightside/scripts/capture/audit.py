#!/usr/bin/env python3
"""The capture privacy gate (G1). Proves that only derived structure would leave the machine. Fails closed (exit 1).

  audit.py synthetic [--work DIR]          planted-secret sessions -> hook -> spool -> manifest -> envelope bytes
  audit.py replay --n 20 --out DIR         READ-ONLY replay of real ~/.claude/projects transcripts through the same
                                           path, into DIR (keep it under /private/tmp; never commit it)

For every run it checks, at every tier (metadata/private, rich/public):
  1. allow-list   check_envelope(): schema + a pattern for every leaf + the bytes re-parse to themselves, so every
                  byte that would leave is a JSON token or a leaf that matched its rule.
  2. provenance   every string leaf is traceable to an allowed source: a schema enum/key, a keyed hash, a minute
                  timestamp, a tool NAME or agent TYPE seen in a hook payload's tool_name / agent_type field (or its
                  keyed-hash form), the local project name (rich tier only), a vetted rich summary, or a label
                  text made only of the closed label vocabulary (labels.py; a free-text user label at the rich tier
                  only as a vetted name).
  3. leak scan    every token (>= 10 chars) of every field capture must NOT record (prompt, tool_input,
                  tool_response, error, last_assistant_message, custom_instructions, compact_summary, session_title,
                  cwd, transcript_path, agent_transcript_path, the subagent description) is searched for in the
                  spool bytes and the envelope bytes. A hit is "explained" only when it is a substring of an
                  allowed-provenance leaf (a prompt that names a tool, say); anything else fails the gate.
  4. red team     (synthetic) secrets planted in every input field, a manifest poisoned field by field, and a rich
                  summary model that answers with secrets: each must be refused or dropped.
Reports hold counts and field names only, never the matched text.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from capture import common as C  # noqa: E402
from capture import allowlist as A  # noqa: E402
from capture import hook as H  # noqa: E402
from capture import labels as L  # noqa: E402
from capture import rich as R  # noqa: E402
from capture import surveyor as S  # noqa: E402

FORBIDDEN_FIELDS = ("prompt", "tool_input", "tool_response", "error", "last_assistant_message",
                    "custom_instructions", "compact_summary", "session_title", "cwd", "transcript_path",
                    "agent_transcript_path", "description")
TOKEN = re.compile(r"[A-Za-z0-9_.@/+:~-]{10,}")
SCHEMA_WORDS = {"nightside/upload-envelope/0-draft", "orchestrator+subagents", "unclassified", "general-purpose",
                "statusline-setup", "claude-code-guide", "human-in-loop", "files_written", "total_minutes",
                "privacy_tier", "project_id", "project_name", "graph_shape", "mcp_servers", "infra_tags", "model_tier"}

# ------------------------------------------------------------------------------------------- canaries ---
SECRET = "sk-ant-api03-CanaryCanaryCanary0123456789abcdef"
CANARIES = {
    "prompt": f"please deploy with {SECRET} CANARY-PROMPT-71c2",
    "tool_input": {"command": "cat /Users/canary-user/.ssh/id_rsa CANARY-INPUT-5b1e", "token": "ghp_" + "C" * 36},
    "tool_response": {"stdout": "AKIAABCDEFGHIJKLMNOP canary.person@example.org CANARY-RESP-9d0a"},
    "error": "permission denied: /private/var/canary-err CANARY-ERROR-33f8",
    "last_assistant_message": "done; wired https://canary-host.example.com/x CANARY-LAST-0c4d",
    "custom_instructions": "keep CANARY-COMPACT-8e21",
    "compact_summary": "summary CANARY-SUMMARY-4a9b",
    "session_title": "CANARY-TITLE-6f70 (415) 555-0199",
    "description": "Email canary.person@example.org about CANARY-DESC-12ab",
}
CANARY_WORDS = ["CANARY-PROMPT-71c2", "CANARY-INPUT-5b1e", "CANARY-RESP-9d0a", "CANARY-ERROR-33f8", "CANARY-LAST-0c4d",
                "CANARY-COMPACT-8e21", "CANARY-SUMMARY-4a9b", "CANARY-TITLE-6f70", "CANARY-DESC-12ab", SECRET,
                "canary-user", "canary.person@example.org", "canary-host", "AKIAABCDEFGHIJKLMNOP", "ghp_CCCC",
                "canary-err", "canary-secret-dir", "555-0199", "CANARY-FILE-77aa", "CANARY-CMD-88bb"]
HOSTILE_NAMES = {  # values in the fields capture DOES record, crafted to smuggle data
    "tool_name": ["mcp__" + SECRET + "__run", "Bash; cat /etc/passwd", "mcp__canary.person@example.org__x",
                  "mcp__canary-host.example.com__x"],
    "agent_type": ["canary.person@example.org", "../../canary-secret-dir", "x:" + SECRET],
    "model": ["claude-" + SECRET.lower(), "gpt-4 CANARY-MODEL"],
}


def synthetic_session(sid: str, cwd: str, t0: float) -> list[tuple[dict, float]]:
    tp = f"{cwd}/.claude/{sid}.jsonl"
    base = {"session_id": sid, "cwd": cwd, "transcript_path": tp, "permission_mode": "default"}
    ev = []

    def add(dt, **kw):
        ev.append((dict(base, **kw), t0 + dt))

    add(0, hook_event_name="SessionStart", source="startup", model="claude-opus-5-5",
        session_title=CANARIES["session_title"])
    add(1, hook_event_name="UserPromptSubmit", prompt=CANARIES["prompt"])
    add(2, hook_event_name="PostToolUse", tool_name="Bash", tool_input=CANARIES["tool_input"],
        tool_response=CANARIES["tool_response"], tool_use_id="toolu_canary", duration_ms=812)
    add(3, hook_event_name="PostToolUseFailure", tool_name="Read", tool_input=CANARIES["tool_input"],
        error=CANARIES["error"], duration_ms=3)
    add(4, hook_event_name="PostToolUse", tool_name="Agent",
        tool_input={"description": CANARIES["description"], "prompt": CANARIES["prompt"]}, duration_ms=60000)
    add(5, hook_event_name="SubagentStart", agent_id="a0000canary0001", agent_type="Explore")
    add(6, hook_event_name="PostToolUse", agent_id="a0000canary0001", agent_type="Explore", tool_name="Grep",
        tool_input={"pattern": CANARIES["prompt"]}, tool_response=CANARIES["tool_response"], duration_ms=40)
    add(7, hook_event_name="PostToolUse", agent_id="a0000canary0001", agent_type="Explore",
        tool_name="mcp__claude_ai_Google_Drive__search_files", tool_input=CANARIES["tool_input"], duration_ms=900)
    add(65, hook_event_name="SubagentStop", agent_id="a0000canary0001", agent_type="Explore",
        agent_transcript_path=f"/Users/canary-user/canary-secret-dir/{sid}/subagents/agent-x.jsonl",
        last_assistant_message=CANARIES["last_assistant_message"], stop_hook_active=False)
    add(65.5, hook_event_name="SubagentStart", agent_id="a0000benign00001", agent_type="nightside:ledger-analyst")
    add(65.6, hook_event_name="PostToolUse", agent_id="a0000benign00001", agent_type="nightside:ledger-analyst",
        tool_name="mcp__plugin_canary_notes__notes_search", tool_input={"q": CANARIES["prompt"]}, duration_ms=30)
    add(65.9, hook_event_name="SubagentStop", agent_id="a0000benign00001", agent_type="nightside:ledger-analyst",
        last_assistant_message=CANARIES["last_assistant_message"])
    add(66, hook_event_name="PostToolUse", tool_name="Write", tool_input={"file_path": cwd + "/x", "content": SECRET},
        duration_ms=5)
    add(67, hook_event_name="PostToolUse", tool_name="mcp__github__create_pull_request", tool_input={}, duration_ms=9)
    # the label's closed-table signal: only the class of the suffix / program word may be recorded, never the name
    add(67.2, hook_event_name="PostToolUse", tool_name="Write", duration_ms=4,
        tool_input={"file_path": "/Users/canary-user/canary-secret-dir/CANARY-FILE-77aa.wav", "content": SECRET})
    add(67.4, hook_event_name="PostToolUse", tool_name="Bash", duration_ms=40,
        tool_input={"command": "FOO=CANARY-CMD-88bb ffmpeg -i /Users/canary-user/CANARY-CMD-88bb.mov out.wav"})
    for i, tn in enumerate(HOSTILE_NAMES["tool_name"]):
        add(68 + i, hook_event_name="PostToolUse", tool_name=tn, tool_input={}, duration_ms=1)
    for i, at in enumerate(HOSTILE_NAMES["agent_type"]):
        add(80 + i, hook_event_name="SubagentStart", agent_id=f"a0000hostile{i:04d}", agent_type=at)
        add(81 + i, hook_event_name="SubagentStop", agent_id=f"a0000hostile{i:04d}", agent_type=at,
            last_assistant_message=CANARIES["last_assistant_message"])
    for i, mo in enumerate(HOSTILE_NAMES["model"]):
        add(90 + i, hook_event_name="PostModelSwitch", from_model="claude-opus-5-5", to_model=mo)
    add(95, hook_event_name="Stop", last_assistant_message=CANARIES["last_assistant_message"], stop_hook_active=False)
    add(96, hook_event_name="PreCompact", trigger="manual", custom_instructions=CANARIES["custom_instructions"])
    add(97, hook_event_name="Notification", message=CANARIES["prompt"])  # not an event capture records
    add(98, hook_event_name="SessionEnd", reason="prompt_input_exit")
    return ev


# ------------------------------------------------------------------------------------------ the checks ---
def _strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield str(k)
            yield from _strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)


class Evidence:
    """What each replayed payload may contribute (allowed names) and must never contribute (forbidden tokens)."""

    def __init__(self):
        self.tools: set[str] = set()
        self.agent_types: set[str] = set()
        self.models: set[str] = set()
        self.forbidden: set[str] = set()
        self.fields_seen: dict[str, int] = {}

    def add(self, d: dict) -> None:
        if isinstance(d.get("tool_name"), str):
            self.tools.add(d["tool_name"])
        if isinstance(d.get("agent_type"), str):
            self.agent_types.add(d["agent_type"])
        for k in ("model", "to_model"):
            if isinstance(d.get(k), str):
                self.models.add(d[k])
        for f in FORBIDDEN_FIELDS:
            if f in d and d[f] not in (None, "", {}, []):
                self.fields_seen[f] = self.fields_seen.get(f, 0) + 1
                for s in _strings(d[f]):
                    for tok in TOKEN.findall(s[:200000]):
                        self.forbidden.add(tok)
                        for part in tok.split("/"):  # path components on their own, too
                            if len(part) >= 10:
                                self.forbidden.add(part)


def _schema_vocab() -> set[str]:
    words = (set(SCHEMA_WORDS) | A.ENVELOPE_KEYS | {A.ENVELOPE_SCHEMA, A.ENVELOPE_SCHEMA_SIGNED, "attestation"}
             | A.ATTEST_KEYS)

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.get("properties", {}).items():
                words.add(k)
                walk(v)
            for k in ("items", "additionalProperties"):
                if isinstance(x.get(k), dict):
                    walk(x[k])
            words.update(e for e in x.get("enum", []) if isinstance(e, str))
    walk(A.schema())
    return words


AUDIT_BUILTIN_AGENTS = {"general-purpose", "Explore", "Plan", "claude-code-guide", "statusline-setup", "fork"}
BUILTIN_TOOL_SHAPE = re.compile(r"^[A-Z][A-Za-z]{1,39}$")


def derived(ev: Evidence, key: bytes) -> dict:
    """The values capture may emit, derived here from the allowed payload fields by the documented rules (an
    independent restatement of hook.encode_*): built-in names as-is, everything else as keyed hashes."""
    mcp = [(t[5:].split("__", 1)) for t in ev.tools if t.startswith("mcp__") and t.count("__") >= 2]
    mcp = [(srv, part) for srv, part in mcp if srv]
    srv_h = {srv: C.kh(key, "server", srv, 8) for srv, _ in mcp}
    custom = {a: "custom-" + C.kh(key, "role", a, 6) for a in ev.agent_types
              if a and a not in AUDIT_BUILTIN_AGENTS}
    return {"builtin_tools": {t for t in ev.tools if BUILTIN_TOOL_SHAPE.match(t)},
            "builtin_agents": {a for a in ev.agent_types if a in AUDIT_BUILTIN_AGENTS},
            "mcp_rich": {f"mcp__{srv_h[s]}__{p}" for s, p in mcp},
            "mcp_meta": {f"mcp-{h}" for h in srv_h.values()},
            "srv": {f"srv-{h}" for h in srv_h.values()},
            "custom": set(custom.values()),
            "raw_names": {s for s in srv_h if len(s) >= 3} | {a for a in custom if len(a) >= 3}}


def provenance_ok(leaf: str, ev: Evidence, key: bytes, rich_names: set[str], summaries: set[str],
                  tier: str = "metadata", dv: dict | None = None) -> bool:
    """Tier-aware: the metadata tier allows no raw MCP or custom name at all; the rich tier adds only the MCP tool's
    own name after the hashed server, the project name the user chose, and a vetted summary."""
    dv = dv or derived(ev, key)
    if leaf in _schema_vocab() or leaf in A.BUILTIN_ROLES or C.HEX16.match(leaf) or A.MINUTE_TS.match(leaf):
        return True
    if leaf in ("local", "rich", "metadata", "public", "private", "single", "pipeline", "cron-agent", "other",
                "haiku", "sonnet", "opus", "fable") or leaf in A.schema()["properties"]["category"]["enum"]:
        return True
    if leaf in dv["builtin_tools"] or leaf in dv["builtin_agents"] or leaf in dv["custom"] or leaf in dv["srv"]:
        return True
    if tier == "metadata":
        return leaf in dv["mcp_meta"]
    return leaf in dv["mcp_rich"] or leaf in rich_names or leaf in summaries


def label_text_ok(t: str, tier: str, rich_names: set[str]) -> bool:
    return bool(L.TEXT_RE.match(t)) and (not L.unknown_words(t) or (tier == "rich" and t in rich_names))


def raw_name_hits(leaf_list, raw_names) -> int:
    """A raw MCP server name, custom agent type or local repo slug as a whole leaf or a __ / : segment of one."""
    n = 0
    for leaf in leaf_list:
        segs = {leaf} | set(re.split(r"__|:", leaf))
        n += bool(segs & raw_names)
    return n


def leaves(env: dict) -> list[str]:
    out = []

    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                out.append(k)
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str):
            out.append(v)
    walk(env)
    return out


def check_bytes(b: bytes, ev: Evidence, key: bytes, rich_names=(), summaries=(), canaries=(), tier="metadata",
                slugs=(), attest: dict | None = None) -> dict:
    """attest (signed envelopes): {"key_id", "key", "runs"}: the attestation may carry only that key id, run ids the
    hook recorded (a subset of `runs`, re-derived from the spool) and the MAC recomputed here; nothing else."""
    env = json.loads(b)
    dv = derived(ev, key)
    rep = {"bytes": len(b), "leaves": 0, "unprovenanced": 0, "raw_name_hits": 0, "leak_hits": 0,
           "explained_hits": 0, "canary_hits": 0}
    good = []
    lv = leaves(env)
    at = env.get("attestation")
    if at is not None:
        rep["attested_runs"] = len(at.get("runs") or []) if isinstance(at, dict) else 0
        ok_at = (attest is not None and isinstance(at, dict) and set(at) == A.ATTEST_KEYS and at["v"] == 1
                 and at["key"] == attest["key_id"] and set(at["runs"]) <= set(attest["runs"])
                 and at["sig"] == A.sign_envelope({k: env[k] for k in ("visibility", "manifest")}, at["runs"],
                                                  attest["key_id"], attest["key"])["attestation"]["sig"])
        for leaf in [at.get("key"), at.get("sig"), *(at.get("runs") or [])] if isinstance(at, dict) else []:
            if leaf in lv:
                lv.remove(leaf)
            rep["leaves"] += 1
            good.append(leaf) if ok_at else None
        rep["unprovenanced"] += 0 if ok_at else 1
    # label.text is the only leaf a closed-vocabulary string may fill (any tier); a free-text user label at the rich
    # tier only as a vetted name. It is checked here, at its own key path, and removed from the generic leaf list.
    lab = (env.get("manifest") or {}).get("label") if isinstance(env.get("manifest"), dict) else None
    if isinstance(lab, dict) and isinstance(lab.get("text"), str):
        t = lab["text"]
        lv.remove(t)
        rep["leaves"] += 1
        if label_text_ok(t, tier, set(rich_names)):
            good.append(t)
        else:
            rep["unprovenanced"] += 1
    rep["raw_name_hits"] = raw_name_hits(leaves(env), dv["raw_names"] | {x for x in slugs if x and len(x) >= 3})
    rep["custom_leaves"] = sum(x.startswith("custom-") for x in lv)
    rep["srv_leaves"] = sum(x.startswith("srv-") for x in lv)
    for leaf in lv:
        rep["leaves"] += 1
        if provenance_ok(leaf, ev, key, set(rich_names), set(summaries), tier, dv):
            good.append(leaf)
        else:
            rep["unprovenanced"] += 1
    text = b.decode("ascii")
    low = text.lower()
    for tok in ev.forbidden:
        if tok in text:
            if any(tok in g for g in good):
                rep["explained_hits"] += 1
            else:
                rep["leak_hits"] += 1
    rep["canary_hits"] = sum(1 for c in canaries if c.lower() in low)
    rep["ok"] = (rep["unprovenanced"] == 0 and rep["leak_hits"] == 0 and rep["canary_hits"] == 0
                 and rep["raw_name_hits"] == 0)
    return rep


SUMMARY_KEYS = {"spool_size", "partial", "base", "folded", "folded_sha"}
PARTIAL_KEYS = {"first", "last", "closed", "model", "prompts", "subs", "tools", "kinds", "out"}
SUMMARY_VOCAB = SUMMARY_KEYS | PARTIAL_KEYS | {"files_written", "artifacts", "prs", "type", "start", "stop", "r", "rm"} | set(
    L.KINDS)
ISO_MS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")


def spool_line_ok(x: dict, ev: Evidence, dv: dict) -> bool:
    """Provenance per spool key: each value is a hash, the hook's clock, an enum, a number, or a name derived from
    the payload field capture is allowed to record (built-in tool / agent names as-is; MCP servers and custom agent
    types only as keyed hashes; model / to_model), or "other"."""
    rules = {
        "v": lambda v: v == 1, "ev": lambda v: v in H.EVENTS, "t": lambda v: isinstance(v, str) and ISO_MS.match(v),
        "s": lambda v: isinstance(v, str) and C.HEX16.match(v),
        "a": lambda v: isinstance(v, str) and re.fullmatch(r"[0-9a-f]{12}", v),
        "at": lambda v: v == "other" or v in dv["builtin_agents"] or v in dv["custom"],
        "tool": lambda v: v == "other" or v in dv["builtin_tools"] or v in dv["mcp_rich"],
        "model": lambda v: v == "other" or v in ev.models,
        "ms": lambda v: isinstance(v, int) and not isinstance(v, bool) and v >= 0,
        "ok": lambda v: isinstance(v, bool), "src": lambda v: v in H.SOURCES, "reason": lambda v: v in H.REASONS,
        "trigger": lambda v: v in H.TRIGGERS, "k": lambda v: v in L.KINDS,
        "r": lambda v: isinstance(v, str) and C.HEX16.match(v), "rm": lambda v: isinstance(v, str) and C.HEX16.match(v)}
    if isinstance(x, dict) and ("r" in x or "rm" in x) and not (x.get("ev") == "SubagentStart" and {"a", "r", "rm"} <= set(x)):
        return False  # run evidence only on a subagent's start line, always as the pair
    return isinstance(x, dict) and set(x) <= set(rules) and all(rules[k](v) for k, v in x.items())


def _scan_strings(data: bytes) -> list[str]:
    """What the leak scan matches: every string value and key in the spool lines and summaries EXCEPT the hook's own
    clock ("t"). Numbers cannot carry text; the stamp is the capture's own structure, and a tool output that quotes a
    partial time ("10-22T16:50") would otherwise match it. Canaries are still matched against the raw bytes."""
    out: list[str] = []

    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                out.append(k)
                if k != "t":
                    walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str):
            out.append(v)
    for line in data.decode("utf-8", "replace").splitlines():
        try:
            walk(json.loads(line))
        except ValueError:
            out.append(line)  # not JSON: scan it whole
    return out


def spool_scan(root: Path, ev: Evidence, canaries=()) -> dict:
    data = b"".join(p.read_bytes() for p in sorted((root / "spool").rglob("*.jsonl")))
    summaries = [p.read_bytes() for p in sorted((root / "sessions").rglob("*.json"))]
    dv = derived(ev, C.install_key(root))
    bad_lines = 0
    for line in data.decode("utf-8", "replace").splitlines():
        if line.strip():
            try:
                ok = spool_line_ok(json.loads(line), ev, dv)
            except ValueError:
                ok = False
            bad_lines += not ok
    for sb in summaries:  # the per-session summaries hold the same encoded names, nothing else
        try:
            c = json.loads(sb)
            ok = (set(c) == SUMMARY_KEYS and isinstance(c["spool_size"], int) and isinstance(c["folded"], int)
                  and (c["folded_sha"] is None or (isinstance(c["folded_sha"], str)
                                                   and re.fullmatch(r"[0-9a-f]{64}", c["folded_sha"]))))
            for p in (c["partial"], c["base"]):
                if p is None:
                    continue
                vals = [{"tool": t} for t in p["tools"]] + [{"at": r["type"]} for r in p["subs"].values()
                                                            if r["type"]]
                vals += [{"model": p["model"]}] if p.get("model") else []
                vals += [{"k": k} for k in p.get("kinds") or {}]
                for r in p["subs"].values():  # a run's random id and its local MAC, nothing else
                    ok = ok and set(r) <= {"type", "start", "stop", "r", "rm"} and all(
                        isinstance(r[k], str) and C.HEX16.match(r[k]) for k in ("r", "rm") if k in r)
                # a summary written before the label build has no "kinds" (treated as empty)
                ok = ok and set(p) | {"kinds"} == PARTIAL_KEYS and all(spool_line_ok(v, ev, dv) for v in vals)
        except (ValueError, KeyError, TypeError, AttributeError):
            ok = False
        bad_lines += not ok
    data += b"\n".join(summaries)
    text = data.decode("utf-8", "replace")
    # the spool's own vocabulary: event names, the recorded names, and the hook-stamped timestamps (a replay stamps
    # the transcript's own times, so a tool output that quotes a time can match one)
    allowed_vals = (dv["builtin_tools"] | dv["builtin_agents"] | dv["mcp_rich"] | dv["custom"] | ev.models
                    | _schema_vocab() | set(H.EVENTS) | set(H.SOURCES) | set(H.REASONS) | set(H.TRIGGERS)
                    | SUMMARY_VOCAB)  # the summaries' own key names (a transcript about capture mentions them)
    stamp = re.compile(r"^\d{4}-\d\d-\d\d(?:T[0-9:.]*Z?)?$")
    scan = "\n".join(_scan_strings(data))
    hits = sum(1 for t in ev.forbidden if t in scan and not stamp.match(t) and not any(t in a for a in allowed_vals))
    can = sum(1 for c in canaries if c.lower() in text.lower())
    raw = sum(1 for r in dv["raw_names"] if re.search(r'(?:"|__|:)' + re.escape(r) + r'(?:"|__)', text))
    return {"spool_bytes": len(data), "lines": text.count("\n"), "unprovenanced_lines": bad_lines,
            "raw_name_hits": raw, "leak_hits": hits, "canary_hits": can,
            "ok": hits == 0 and can == 0 and bad_lines == 0 and raw == 0}


def redteam_manifest(m: dict, key: bytes) -> list[tuple[str, bool]]:
    """Poison a valid manifest one field at a time; every variant must be rejected (True = caught)."""
    cases = []

    def case(name, mut, vis=None):
        x = copy.deepcopy(m)
        env = A.envelope(x, vis or "public")
        mut(env)
        try:
            A.check_envelope(env, canaries=CANARY_WORDS)
            cases.append((name, False))
        except A.Rejected:
            cases.append((name, True))

    rich = dict(m, privacy_tier="rich")
    case("user_id email", lambda e: e["manifest"].update(user_id="canary.person@example.org"))
    case("project_id path", lambda e: e["manifest"].update(project_id="/Users/canary-user"))
    case("project_name at metadata tier", lambda e: e["manifest"].update(project_name="canary"))
    case("project_name secret (rich)", lambda e: e.update(manifest=dict(rich, project_name=SECRET[:40])))
    case("project_name path (rich)", lambda e: e.update(manifest=dict(rich, project_name="Users/canary-user")))
    case("summary at metadata tier", lambda e: e["manifest"].update(summary="a nice workflow"))
    case("summary email (rich)", lambda e: e.update(manifest=dict(rich, summary="mail canary.person@example.org")))
    case("summary secret (rich)", lambda e: e.update(manifest=dict(rich, summary="uses " + SECRET)))
    case("summary url (rich)", lambda e: e.update(manifest=dict(rich, summary="see https://canary-host.example.com")))
    case("summary amount (rich)", lambda e: e.update(manifest=dict(rich, summary="spent $40,000 on it")))
    case("summary canary word (rich)", lambda e: e.update(manifest=dict(rich, summary="CANARY-PROMPT-71c2")))
    case("role free text (metadata)", lambda e: e["manifest"]["agents"].append(
        {"role": "deal-reviewer", "model_tier": "opus", "turns": 1, "minutes": 1.0}))
    case("role secret (rich)", lambda e: e.update(manifest=dict(rich, agents=[
        {"role": "x:" + SECRET[:30], "model_tier": "opus", "turns": 1, "minutes": 1.0}])))
    case("tool key secret", lambda e: e["manifest"]["tools"].update({SECRET: 1}))
    case("tool key path", lambda e: e["manifest"]["tools"].update({"Bash /Users/canary-user": 1}))
    case("tool key mcp raw (metadata)", lambda e: e["manifest"]["tools"].update({"mcp__mailcanary__send": 1}))
    case("tool key mcp raw server (rich)", lambda e: e.update(manifest=dict(rich, tools={"mcp__github__x": 1})))
    case("mcp server raw (rich)", lambda e: e.update(manifest=dict(rich, mcp_servers=["github"])))
    case("custom role raw (rich)", lambda e: e.update(manifest=dict(rich, agents=[
        {"role": "nightside:ledger-analyst", "model_tier": "opus", "turns": 1, "minutes": 1.0}])))
    case("skills (rich)", lambda e: e.update(manifest=dict(rich, skills=["token-audit"])))
    case("mcp server raw (metadata)", lambda e: e["manifest"]["mcp_servers"].append("mail-canary-campus"))
    case("skills smuggle (metadata)", lambda e: e["manifest"]["skills"].append("canary-skill"))
    case("infra tag smuggle", lambda e: e["manifest"]["infra_tags"].append("canary-host.example.com"))
    case("links_to not hex", lambda e: e["manifest"]["links_to"].append("canary-user"))
    case("timestamp with seconds", lambda e: e["manifest"]["runs"].update(first_at="2026-10-22T19:20:13Z"))
    case("timestamp smuggle", lambda e: e["manifest"]["runs"].update(first_at="CANARY-TITLE-6f70"))
    case("negative count", lambda e: e["manifest"]["outcomes"].update(prs=-1))
    case("extra manifest key", lambda e: e["manifest"].update(transcript_path="/Users/canary-user/x.jsonl"))
    case("extra envelope key", lambda e: e.update(prompt=CANARIES["prompt"]))
    case("extra agent key", lambda e: e["manifest"]["agents"].append(
        {"role": "agent", "model_tier": "opus", "turns": 1, "minutes": 1.0, "prompt": "x"}))
    case("private + rich", lambda e: e.update(manifest=dict(rich, project_name="demo")), vis="private")
    case("bad visibility", lambda e: e.update(visibility="friends"))
    case("category free text", lambda e: e["manifest"].update(category="acquisition of canary corp"))
    case("NaN minutes", lambda e: e["manifest"]["runs"].update(total_minutes=float("nan")))
    lab = {"text": "Voice and audio pipeline", "category": "media-pipeline", "source": "heuristic"}

    def with_label(manifest, **kw):
        return lambda e: e.update(manifest=dict(manifest, label=dict(lab, **kw)))
    meta = dict(m, privacy_tier="metadata")
    case("label free word (metadata)", with_label(meta, text="Canary fundraise", source="user"))
    case("label person (metadata)", with_label(meta, text="Drafts for Jane Canary", source="user"))
    case("label path (rich)", with_label(rich, text="Users/canary-user", source="user"))
    case("label file name (rich)", with_label(rich, text="canary.py tool", source="user"))
    case("label email (rich)", with_label(rich, text="canary.person@example.org", source="user"))
    case("label secret (rich)", with_label(rich, text=SECRET[:40], source="user"))
    case("label digits (rich)", with_label(rich, text="Raise 40000 by Q4", source="user"))
    case("label canary word (rich)", with_label(rich, text="CANARY-PROMPT-71c2", source="user"))
    case("label too long", with_label(rich, text="x" * 41, source="user"))
    case("label underscore id (rich)", with_label(rich, text="canary_repo build", source="user"))
    case("label heuristic not a phrase", with_label(meta, text="Data pipeline"))
    case("label claude free word (rich)", with_label(rich, text="Canary Corp pipeline", source="claude"))
    case("label bad category", with_label(meta, category="acquisition"))
    case("label bad source", with_label(meta, source="server"))
    case("label extra key", lambda e: e.update(manifest=dict(meta, label=dict(lab, note="x"))))
    case("label missing key", lambda e: e.update(manifest=dict(meta, label={"text": lab["text"]})))
    case("label not an object", lambda e: e.update(manifest=dict(meta, label="Voice and audio pipeline")))
    case("label number text", with_label(meta, text=7))
    return cases


def redteam_rich(m: dict) -> list[tuple[str, bool]]:
    """The rich summary model answers with secrets: each must be dropped (True = caught). Its prompt must hold no
    canary (it is built from the allow-listed manifest only)."""
    seen = {}

    def runner_for(text):
        def run(prompt):
            seen["prompt"] = prompt
            return json.dumps({"result": json.dumps({"summary": text, "category": "build-deploy-infra",
                                                     "label": label_text})})
        return run

    label_text = "Build and deploy tooling"

    rm = dict(m)  # a rich-tier manifest (public project, user-chosen name)
    out = []
    for name, text in [("secret", "Deploys with " + SECRET), ("email", "Mails canary.person@example.org daily"),
                       ("url", "Posts to https://canary-host.example.com"), ("path", "Edits /Users/canary-user/x"),
                       ("too long", " ".join(["word"] * 61)), ("canary word", "CANARY-PROMPT-71c2 workflow")]:
        got = R.summarize(rm, runner=runner_for(text))
        dropped = not got or "summary" not in got or any(c.lower() in got["summary"].lower() for c in CANARY_WORDS)
        if got and name == "canary word":  # a plain word passes the guard; the canary check is the gate's job
            try:
                A.check_envelope(A.envelope(dict(rm, **got), "public"), canaries=CANARY_WORDS)
                dropped = False
            except A.Rejected:
                dropped = True
        out.append((f"rich summary {name}", dropped))
    good = R.summarize(rm, runner=runner_for("An orchestrator with research subagents that edits files."))
    out.append(("rich summary benign kept", bool(good and good.get("summary"))))
    out.append(("rich label benign kept", bool(good and (good.get("label") or {}).get("source") == "claude")))
    for name, text in [("secret", SECRET[:40]), ("email", "canary.person@example.org"), ("path", "Users/canary-user"),
                       ("name", "Canary Corp deal room"), ("canary word", "CANARY-PROMPT-71c2")]:
        label_text = text
        got = R.summarize(rm, runner=runner_for("An orchestrator with research subagents that edits files."))
        out.append((f"rich label {name}", not (got and "label" in got)))
    label_text = "Build and deploy tooling"
    out.append(("rich prompt holds no canary", not any(c.lower() in seen.get("prompt", "").lower()
                                                      for c in CANARY_WORDS)))
    return out


def _cfg(root: Path, tier: str, vis: str) -> dict:
    cfg = copy.deepcopy(C.DEFAULTS)
    cfg.update(capture_root=str(root), privacy_tier=tier, default_visibility=vis)
    return cfg


def _replay(payloads, root: Path, cfg: dict, ev: Evidence) -> set[str]:
    pids = set()
    keep = {k: os.environ.pop(k) for k in ("CLAUDE_PROJECT_DIR", "NIGHTSIDE_CAPTURE_ROOT", "NIGHTSIDE_CAPTURE")
            if k in os.environ}
    try:
        for d, t in payloads:
            ev.add(d)
            r = H.handle(d, cfg, now=t)
            if r:
                pids.add(r["pid"])
    finally:
        os.environ.update(keep)
    return pids


CHOSEN_NAME = "Chosen Project"


SIGNING_KEY_ID = "k1.AAAAAAAAAAAAAAAAAAAAAA"   # a synthetic per-token signing key (the auditor's, never a real one)
SIGNING_KEY = b"\x07" * 32


def tier_runs(root: Path, pids, ev: Evidence, canaries=(), require_hashes: bool = False) -> list[dict]:
    """Survey every project at every tier and check the bytes. The rich run gives each project a user-chosen name;
    local repo slugs must never appear at any tier."""
    reps = []
    key = C.install_key(root)
    slugs = {(C.read_index(root).get(p) or {}).get("name") for p in pids} - {None}
    for p in pids:  # the repo's agent ledger is an allowed source too: its subagent_type values (metadata only)
        for r in S.read_ledger((C.read_index(root).get(p) or {}).get("ledger")):
            if isinstance(r.get("subagent_type"), str):
                ev.agent_types.add(r["subagent_type"])
    for tier, vis in (("metadata", "private"), ("metadata", "public"), ("rich", "public")):
        cfg = _cfg(root, tier, vis)
        if tier == "rich":
            cfg["projects"] = {p: {"name": CHOSEN_NAME} for p in pids}
        for pid in sorted(pids):
            runs: list[str] = []
            m = S.survey(root, pid, cfg, runs_out=runs)
            for signed in (False, True):  # the unsigned v0 bytes and the plugin-signed v1 bytes
                att = {"key_id": SIGNING_KEY_ID, "key": SIGNING_KEY, "runs": runs} if signed else None
                try:
                    env = A.envelope(m, vis)
                    if signed:
                        env = A.sign_envelope(env, runs[:A.subagent_runs_claimed(m)], SIGNING_KEY_ID, SIGNING_KEY)
                    b = A.check_envelope(env, canaries)
                    rep = check_bytes(b, ev, key, rich_names={CHOSEN_NAME} if tier == "rich" else (),
                                      canaries=canaries, tier=tier, slugs=slugs, attest=att)
                except A.Rejected as e:
                    rep = {"ok": False, "rejected": str(e)}
                rep.update(tier=tier, visibility=vis, project=pid[:6], signed=signed)
                reps.append(rep)
    if require_hashes:  # the synthetic run must exercise the custom-<hash> and srv-<hash> paths at the private tier
        priv = [r for r in reps if r["tier"] == "metadata" and r["visibility"] == "private"]
        if (not any(r.get("custom_leaves") for r in priv) or not any(r.get("srv_leaves") for r in priv)
                or not any(r.get("attested_runs") for r in priv if r["signed"])):
            for r in priv:
                r["ok"], r["hash_paths_unexercised"] = False, True
    return reps


def _redteam(root: Path, pid: str) -> dict:
    key = C.install_key(root)
    base = S.survey(root, pid, _cfg(root, "metadata", "public"))
    rcfg = _cfg(root, "rich", "public")
    rcfg["projects"] = {pid: {"name": CHOSEN_NAME}}
    rich_base = S.survey(root, pid, rcfg)
    assert rich_base["privacy_tier"] == "rich"
    rt = redteam_manifest(base, key) + redteam_rich(rich_base)
    return {"cases": len(rt), "caught": sum(ok for _, ok in rt), "missed": [n for n, ok in rt if not ok]}


def _synthetic_payloads(cwd: str) -> list:
    t0 = 1_800_000_000.0
    return synthetic_session("11111111-2222-4333-8444-555555555555", cwd, t0) + \
        synthetic_session("66666666-7777-4888-9999-000000000000", cwd, t0 + 3600)


def run_synthetic(work: Path) -> dict:
    root = work / "capture-root"
    cwd = str(work / "Users" / "canary-user" / "canary-secret-dir" / "demo-project")
    Path(cwd).mkdir(parents=True, exist_ok=True)
    ev = Evidence()
    payloads = _synthetic_payloads(cwd)
    pids = _replay(payloads, C.ensure_root(root), _cfg(root, "metadata", "private"), ev)
    canaries = CANARY_WORDS
    rep = {"mode": "synthetic", "payloads": len(payloads), "projects": len(pids),
           "fields_planted": sorted(ev.fields_seen), "tiers": tier_runs(root, pids, ev, canaries, True),
           "spool": spool_scan(root, ev, canaries)}
    rep["redteam"] = _redteam(root, sorted(pids)[0])
    rep["example_manifest"] = S.survey(root, sorted(pids)[0], _cfg(root, "metadata", "public"))
    rep["label"] = rep["example_manifest"].get("label")  # from the closed-table signal only (ext-audio, cmd-media)
    rep["ok"] = (rep["spool"]["ok"] and all(t["ok"] for t in rep["tiers"]) and not rep["redteam"]["missed"]
                 and bool(rep["label"]) and rep["label"]["category"] == "media-pipeline")
    return rep


# ----------------------------------------------------------------------------------------- real replay ---
def transcript_payloads(path: Path, ev_cap: int = 200000) -> list[tuple[dict, float]]:
    """Hook payloads a real session would have produced, rebuilt from its transcript (read-only), with the REAL
    prompt / tool_input / tool_response / error / cwd / paths in them, so the leak scan has real material."""
    sid = path.stem
    out: list[tuple[dict, float]] = []
    pending: dict[str, tuple[str, dict, float, dict]] = {}

    def ts(o):
        return S._ts(o.get("timestamp")) or 0.0

    def feed(lines, extra):
        first = True
        for raw in lines:
            try:
                o = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(o, dict) or o.get("type") not in ("user", "assistant"):
                continue
            t = ts(o)
            base = {"session_id": sid, "cwd": o.get("cwd") or "/", "transcript_path": str(path), **extra}
            if first and not extra:
                out.append((dict(base, hook_event_name="SessionStart", source="startup", model=None), t))
            first = False
            msg = o.get("message") or {}
            content = msg.get("content")
            if o["type"] == "assistant":
                for b in content if isinstance(content, list) else []:
                    if isinstance(b, dict) and b.get("type") == "tool_use":
                        pending[b.get("id")] = (b.get("name"), b.get("input"), t, base)
                    elif isinstance(b, dict) and b.get("type") == "text" and not extra:
                        out.append((dict(base, hook_event_name="Stop", last_assistant_message=b.get("text")), t))
                if not extra and msg.get("model") and out and out[0][0].get("model") is None:
                    out[0][0]["model"] = msg["model"]
            else:
                if isinstance(content, str) and not extra:
                    out.append((dict(base, hook_event_name="UserPromptSubmit", prompt=content), t))
                for b in content if isinstance(content, list) else []:
                    if isinstance(b, dict) and b.get("type") == "tool_result" and b.get("tool_use_id") in pending:
                        name, inp, t1, b0 = pending.pop(b["tool_use_id"])
                        ms = max(0, int((t - t1) * 1000))
                        if b.get("is_error"):
                            out.append((dict(b0, hook_event_name="PostToolUseFailure", tool_name=name, tool_input=inp,
                                             error=json.dumps(b.get("content"))[:20000], duration_ms=ms), t))
                        else:
                            out.append((dict(b0, hook_event_name="PostToolUse", tool_name=name, tool_input=inp,
                                             tool_response=b.get("content"), duration_ms=ms), t))
                    elif isinstance(b, dict) and b.get("type") == "text" and not extra:
                        out.append((dict(base, hook_event_name="UserPromptSubmit", prompt=b.get("text")), t))
            if len(out) > ev_cap:
                break

    with open(path, encoding="utf-8", errors="replace") as f:
        feed(f, {})
    sub = path.parent / sid / "subagents"
    if sub.is_dir():
        for sf in sorted(sub.glob("agent-*.jsonl")):
            aid = sf.stem[len("agent-"):]
            meta = {}
            try:
                meta = json.loads(sf.with_suffix(".meta.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass
            at = meta.get("agentType") or "general-purpose"
            with open(sf, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            tss = [S._ts(json.loads(x).get("timestamp")) for x in lines[:1] + lines[-1:] if x.strip()]
            t_start, t_end = (tss[0] or 0.0), (tss[-1] or 0.0)
            ex = {"agent_id": aid, "agent_type": at}
            out.append(({"session_id": sid, "cwd": "/", "hook_event_name": "SubagentStart", **ex,
                         "description": meta.get("description")}, t_start))
            feed(lines, ex)
            out.append(({"session_id": sid, "cwd": "/", "hook_event_name": "SubagentStop", **ex,
                         "agent_transcript_path": str(sf)}, t_end))
    last = max((t for _, t in out), default=0.0)
    if out:
        out.append(({"session_id": sid, "cwd": out[0][0]["cwd"], "transcript_path": str(path),
                     "hook_event_name": "SessionEnd", "reason": "other"}, last))
    out.sort(key=lambda x: x[1])
    return out


def pick_transcripts(n: int, max_bytes: int, skip: set[str]) -> list[Path]:
    base = Path(os.path.expanduser(os.environ.get("CLAUDE_CONFIG_DIR") or "~/.claude")) / "projects"
    files = [p for p in base.glob("*/*.jsonl") if p.is_file() and not p.is_symlink() and p.stem not in skip
             and 10_000 < p.stat().st_size <= max_bytes]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[:n]


def run_replay(n: int, out: Path, max_bytes: int, skip: set[str]) -> dict:
    root = out / "capture-root"
    ev = Evidence()
    picked = pick_transcripts(n, max_bytes, skip)
    pids: set[str] = set()
    t0 = time.time()
    payload_count = 0
    for p in picked:
        pl = transcript_payloads(p)
        payload_count += len(pl)
        # the hook's cwd decides the project; real cwds are kept so the leak scan covers real paths
        pids |= _replay(pl, C.ensure_root(root), _cfg(root, "metadata", "private"), ev)
    # red team inside the replay: planted-secret sessions ride along with the real ones (own project), so every
    # check below also runs with canaries; then the poisoned-manifest and rich-summary cases on a real manifest
    rt_cwd = out / "redteam" / "Users" / "canary-user" / "canary-secret-dir" / "demo-project"
    rt_cwd.mkdir(parents=True, exist_ok=True)
    rt_payloads = _synthetic_payloads(str(rt_cwd))
    payload_count += len(rt_payloads)
    rt_pids = _replay(rt_payloads, root, _cfg(root, "metadata", "private"), ev)
    pids |= rt_pids
    real = sorted(pids - rt_pids)
    rep = {"mode": "replay", "transcripts": len(picked), "transcript_bytes": sum(p.stat().st_size for p in picked),
           "with_subagents": sum((p.parent / p.stem / "subagents").is_dir() for p in picked),
           "payloads": payload_count, "forbidden_tokens": len(ev.forbidden), "fields_seen": ev.fields_seen,
           "projects": len(pids), "tiers": tier_runs(root, pids, ev, CANARY_WORDS),
           "spool": spool_scan(root, ev, CANARY_WORDS),
           "redteam": _redteam(root, real[0] if real else sorted(rt_pids)[0]),
           "seconds": round(time.time() - t0, 1)}
    rep["ok"] = rep["spool"]["ok"] and all(t["ok"] for t in rep["tiers"]) and not rep["redteam"]["missed"]
    return rep


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="audit.py", description="G1 capture privacy gate")
    sub = ap.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("synthetic")
    p.add_argument("--work")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("replay")
    p.add_argument("--n", type=int, default=20)
    p.add_argument("--out", required=True)
    p.add_argument("--max-mb", type=int, default=30)
    p.add_argument("--skip", nargs="*", default=[])
    a = ap.parse_args(argv)
    os.umask(0o077)
    if a.mode == "synthetic":
        if a.work:
            rep = run_synthetic(Path(a.work))
        else:
            with tempfile.TemporaryDirectory() as d:
                rep = run_synthetic(Path(d))
    else:
        out = Path(a.out).resolve()
        C.check_root(out)
        C.secure_dir(out)
        rep = run_replay(a.n, out, a.max_mb << 20, set(a.skip))
        C.atomic_write(out / "g1_report.json", (json.dumps(rep, indent=1) + "\n").encode())
    rep_print = {k: v for k, v in rep.items() if k != "example_manifest"}
    print(json.dumps(rep_print, indent=1) if getattr(a, "json", False) or a.mode == "replay" else
          f"G1 synthetic: {'PASS' if rep['ok'] else 'FAIL'}; spool {rep['spool']}; red team "
          f"{rep['redteam']['caught']}/{rep['redteam']['cases']} caught; tiers "
          f"{[(t['tier'], t['visibility'], t.get('bytes'), t['ok']) for t in rep['tiers']]}")
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
