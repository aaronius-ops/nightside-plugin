#!/usr/bin/env python3
"""The Nightside capture hook. Hook JSON on stdin -> at most one line appended to the private local spool.

Recorded (and nothing else): the event type, a timestamp this hook stamps (payloads carry none), the session id and
agent id as keyed hashes, the agent type, the model name, the tool NAME, the tool's duration_ms, success/failure,
and three small enums (SessionStart source, SessionEnd reason, PreCompact trigger). Each value must match a strict
pattern or it is replaced by "other" / dropped. Names are encoded AT WRITE TIME: built-in tool names (Bash, Read,
...) and built-in agent types (Explore, general-purpose, ...) stay readable; an MCP tool becomes
mcp__<keyed server hash>__<tool>, and any other agent type (a custom or plugin agent) becomes custom-<keyed hash>.
The readable originals go only to the local reverse map names.json, for the owner's own preview.

One closed-table class per tool call, for the local public label (labels.py): "k" is the class of a written file's
SUFFIX (Write/Edit/MultiEdit: ".wav" -> "ext-audio") or of a Bash command's PROGRAM word ("ffmpeg" -> "cmd-media"),
looked up in labels.EXT_KIND / labels.CMD_KIND. Those two tool_input fields are read for that lookup only; the path,
the file or directory name and the command line are never written, and a value not in the tables records nothing.
"k" stays local: the manifest carries only the label made from it, which the user approves.

Never read, never written: tool_response, error, prompt, last_assistant_message, custom_instructions,
compact_summary, session_title, cwd and every other path, transcript_path / agent_transcript_path (and the files
they point to). The project is identified by a keyed hash of its repository root; the readable repo slug goes to
the local index (projects.json) only.

Spool line (one JSON object, keys from SPOOL_KEYS):
  {"v":1,"ev":"PostToolUse","t":"2026-10-22T19:20:01.123Z","s":"<16 hex>","a":"<12 hex>","at":"Explore",
   "tool":"Bash","ms":412,"ok":true,"k":"cmd-test"}

Run evidence (signed manifests): each SubagentStart line also gets "r", a RANDOM 16-hex run id (secrets, never
derived from a name, id or time), and "rm", a keyed MAC of (project, session hash, agent hash, r) under the local
capture key. The Surveyor counts a run as attested only when its "rm" verifies; the preview signs the attested run ids
(allowlist.sign_envelope). No network: the hook still only appends one local line.

Never blocks or fails a session: every path exits 0 and prints nothing (an async hook's stdout would reach Claude).
SessionEnd only appends its line (the session is then closed). The Surveyor and spool retention run later, in the
async SessionStart hook of the next session in the project, or on /planet status --survey / preview.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from capture import SPOOL_VERSION  # noqa: E402
from capture import common as C  # noqa: E402
from capture import labels as L  # noqa: E402

EVENTS = ("SessionStart", "UserPromptSubmit", "PostToolUse", "PostToolUseFailure", "SubagentStart", "SubagentStop",
          "Stop", "PreCompact", "PostModelSwitch", "SessionEnd")
SPOOL_KEYS = {"v", "ev", "t", "s", "a", "at", "tool", "ms", "ok", "model", "src", "reason", "trigger", "k", "r", "rm"}
SOURCES = ("startup", "resume", "clear", "compact", "fork")
REASONS = ("clear", "resume", "logout", "prompt_input_exit", "other")
TRIGGERS = ("manual", "auto")

TOOL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,127}$")          # no dots, slashes, @, colons, spaces
AGENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9:_-]{0,63}$")          # plugin agents are "plugin:name"
MODEL_RE = re.compile(r"^claude-[a-z0-9][a-z0-9.-]{0,40}(\[[0-9a-z]{1,8}\])?$")
SEG_LONG = re.compile(r"[A-Za-z0-9]{32,}")                        # a long opaque token inside a name segment
CRED = re.compile(r"(?i)\b(?:sk-|AIza|ya29|gh[pousr]_|github_pat_|glpat-|xox[abposr]-|AKIA|ASIA)|bearer|password|"
                  r"passwd|secret|apikey|api_key")


def clean_name(v, rx: re.Pattern) -> str | None:
    """A tool or agent name, or "other" when present but not plainly a name (None when absent)."""
    if v is None or v == "":
        return None
    if not isinstance(v, str) or not rx.match(v):
        return "other"
    for seg in re.split(r"__|:|-", v):
        if SEG_LONG.search(seg):
            return "other"
    if CRED.search(v):
        return "other"
    return v


def clean_model(v) -> str | None:
    if not v:
        return None
    if not isinstance(v, str) or not MODEL_RE.match(v) or CRED.search(v) or SEG_LONG.search(v):
        return "other"
    return v


BUILTIN_AGENTS = {"general-purpose", "Explore", "Plan", "claude-code-guide", "statusline-setup", "fork"}
BUILTIN_TOOL = re.compile(r"^[A-Z][A-Za-z]{1,39}$")
MCP_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
ENC_TOOL = re.compile(r"^(?:[A-Z][A-Za-z]{1,39}|mcp__[0-9a-f]{8}__[A-Za-z0-9][A-Za-z0-9_-]{0,63}|other)$")
ENC_AGENT = re.compile(r"^(?:custom-[0-9a-f]{6}|other)$")


def encode_tool(raw, key: bytes, names: dict | None = None) -> str:
    name = clean_name(raw, TOOL_RE)
    if name in (None, "other"):
        return "other"
    if BUILTIN_TOOL.match(name):
        return name
    if name.startswith("mcp__") and name.count("__") >= 2:
        srv, part = name[5:].split("__", 1)
        if srv and MCP_PART.match(part):
            h = C.kh(key, "server", srv, 8)
            if names is not None:
                names["srv-" + h] = srv
            return f"mcp__{h}__{part}"
    return "other"


def encode_agent(raw, key: bytes, names: dict | None = None) -> str | None:
    at = clean_name(raw, AGENT_RE)
    if at in (None, "other") or at in BUILTIN_AGENTS:
        return at
    h = "custom-" + C.kh(key, "role", at, 6)
    if names is not None:
        names[h] = at
    return h


def build_event(d: dict, key: bytes, now: float, names: dict | None = None) -> dict | None:
    ev = d.get("hook_event_name")
    sid = d.get("session_id")
    if ev not in EVENTS or not isinstance(sid, str) or not C.SID_RE.match(sid):
        return None
    rec = {"v": SPOOL_VERSION, "ev": ev, "t": C.iso_ms(now), "s": C.kh(key, "session", sid)}
    aid = d.get("agent_id")
    if isinstance(aid, str) and C.SID_RE.match(aid):
        rec["a"] = C.kh(key, "agent", f"{sid}/{aid}", 12)
    at = encode_agent(d.get("agent_type"), key, names)
    if at:
        rec["at"] = at
    if ev in ("PostToolUse", "PostToolUseFailure"):
        rec["tool"] = encode_tool(d.get("tool_name"), key, names)
        ms = d.get("duration_ms")
        if isinstance(ms, (int, float)) and not isinstance(ms, bool) and 0 <= ms < 10 ** 9:
            rec["ms"] = int(ms)
        rec["ok"] = ev == "PostToolUse"
        k = L.event_kind(rec["tool"], d.get("tool_input"))
        if k in L.KINDS:
            rec["k"] = k
    elif ev == "SessionStart":
        if d.get("source") in SOURCES:
            rec["src"] = d["source"]
        m = clean_model(d.get("model"))
        if m:
            rec["model"] = m
    elif ev == "PostModelSwitch":
        m = clean_model(d.get("to_model"))
        if m:
            rec["model"] = m
    elif ev == "SessionEnd":
        rec["reason"] = d.get("reason") if d.get("reason") in REASONS else "other"
    elif ev == "PreCompact":
        if d.get("trigger") in TRIGGERS:
            rec["trigger"] = d["trigger"]
    assert set(rec) <= SPOOL_KEYS
    return rec


def run_mac(key: bytes, pid: str, s: str, a: str, r: str) -> str:
    return C.kh(key, "run", f"{pid}|{s}|{a}|{r}", 16)


def handle(d: dict, cfg: dict | None = None, now: float | None = None) -> dict | None:
    """Spool one hook payload. Returns {"root","pid","rec"} or None (disabled / not an event we record).
    Raises C.Refused for an unsafe root; the CLI entry point turns every error into a log line and exit 0."""
    cfg = C.load_config() if cfg is None else cfg
    if not C.enabled(cfg) or not isinstance(d, dict):
        return None
    root = C.ensure_root(C.capture_root(cfg))
    key = C.install_key(root)
    names: dict = {}
    rec = build_event(d, key, time.time() if now is None else now, names)
    if rec is None:
        return None
    pdir = C.project_dir(d.get("cwd"))
    if pdir is None:
        return None
    pid, name = C.project_identity(key, pdir)
    if rec["ev"] == "SessionStart":
        from capture.surveyor import ledger_path
        lp = ledger_path(pdir)
        C.note_project(root, pid, name, str(lp) if lp else None)
    if rec["ev"] == "SubagentStart" and "a" in rec:
        rec["r"] = secrets.token_hex(8)
        rec["rm"] = run_mac(key, pid, rec["s"], rec["a"], rec["r"])
    C.note_names(root, names)
    sp = root / "spool" / pid
    C.secure_dir(root / "spool", root)
    C.secure_dir(sp, root)
    C.append_line(sp / f"{rec['s']}.jsonl", C.canonical(rec) + b"\n")
    return {"root": root, "pid": pid, "rec": rec, "pdir": pdir}


def main() -> int:
    os.umask(0o077)
    root = None
    try:
        cfg = C.load_config()
        if not C.enabled(cfg):
            return 0
        root = C.capture_root(cfg)  # resolved first, so every later error is logged under the capture root
        raw = sys.stdin.read(1 << 20)  # hook payloads are small; never read an unbounded stream
        d = json.loads(raw or "{}")
        r = handle(d, cfg)
        if r and r["rec"]["ev"] == "SessionStart":
            # deferred work, in the ASYNC SessionStart hook (never blocks): retention, then this project's survey
            from capture import surveyor
            surveyor.retention(r["root"], cfg)
            surveyor.survey_to_outbox(r["root"], r["pid"], cfg)
    except C.Refused as e:
        C.log(root, f"refused: {e}")
    except Exception as e:  # noqa: BLE001 - the hook never fails a session
        C.log(root, f"error: {type(e).__name__}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
