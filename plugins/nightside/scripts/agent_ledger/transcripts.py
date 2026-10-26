"""Find Claude Code sessions on disk and parse their transcripts into in-memory structures.

Accepted layouts (any of these paths may be passed; directories are searched up to three levels deep):
  raw Claude Code     ~/.claude/projects/<proj>/<session>.jsonl + <proj>/<session>/subagents/agent-<id>.jsonl
  archive (hook)      <root>/<project>/<session>/<session>.jsonl + <root>/<project>/<session>/subagents/
  archive (legacy)    <root>/<project>/<session>/main.jsonl + <root>/<project>/<session>/session/subagents/
  a single main transcript file (<session>.jsonl), its subagents taken from the sibling <session>/subagents/

Prompts and reports are held in memory only, so the extractor can derive branch names, verdict words and commit
hashes from them. Nothing here writes anything.
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

SID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
SKIP_DIRS = {"subagents", "tool-results", "memory", "session", "_logs", ".git", "node_modules"}
NOTIF_TAGS = ("task-id", "tool-use-id", "status")
NOTIF_INTS = ("subagent_tokens", "tool_uses", "duration_ms")


@dataclass
class Transcript:
    """One parsed jsonl transcript (main session or one subagent)."""
    models: Counter = field(default_factory=Counter)
    segments: list = field(default_factory=list)       # orchestrator model segments [model, first_ts, last_ts, n]
    synthetic: int = 0                                  # '<synthetic>' assistant messages (restarts, limits)
    first_ts: str | None = None
    last_ts: str | None = None
    cwd: str | None = None
    assistant_messages: int = 0
    tool_uses: int = 0
    uses: dict = field(default_factory=dict)            # Agent/Task tool_use id -> launch metadata (+ prompt, memory only)
    results: dict = field(default_factory=dict)         # Agent tool_use id -> agentId from its tool_result
    notifs: list = field(default_factory=list)          # parsed task-notifications, deduped by (task-id, ts)
    sends: list = field(default_factory=list)           # SendMessage targets
    workflows: int = 0
    prompt: str | None = None                           # first non-meta user text (memory only)
    handbacks: list = field(default_factory=list)       # SubagentHandback messages (memory only)
    last_text: str = ""                                 # last assistant text block (memory only)


@dataclass
class Session:
    session_id: str
    project: str
    layout: str
    main: Path | None
    subagent_dir: Path | None

    def size(self) -> int:
        n = self.main.stat().st_size if self.main and self.main.is_file() else 0
        if self.subagent_dir and self.subagent_dir.is_dir():
            n += sum(1 for _ in self.subagent_dir.glob("agent-*.jsonl")) * 1_000_000_000  # more subagents wins
        return n


def _text(c) -> str:
    if isinstance(c, str):
        return c
    out = []
    for b in c or []:
        if isinstance(b, dict):
            if b.get("type") == "text":
                out.append(b.get("text") or "")
            elif b.get("type") == "tool_result":
                out.append(_text(b.get("content")))
    return "\n".join(out)


def parse_notification(s: str) -> dict:
    d = {}
    for k in NOTIF_TAGS:
        m = re.search(f"<{k}>(.*?)</{k}>", s, re.S)
        d[k] = m.group(1).strip() if m else None
    for k in NOTIF_INTS:
        m = re.search(f"<{k}>(\\d+)</{k}>", s)
        d[k] = int(m.group(1)) if m else None
    return d


def _split_notifications(s: str) -> list[str]:
    parts = re.findall(r"<task-notification>.*?</task-notification>", s, re.S)
    return parts or ([s] if "<task-id>" in s else [])


def parse_transcript(path: Path) -> Transcript:
    T = Transcript()
    seen = set()
    queue_notifs, user_notifs = [], []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                o = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(o, dict):
                continue
            t, ts = o.get("type"), o.get("timestamp")
            if isinstance(ts, str):
                T.first_ts = ts if T.first_ts is None or ts < T.first_ts else T.first_ts
                T.last_ts = ts if T.last_ts is None or ts > T.last_ts else T.last_ts
            if T.cwd is None and isinstance(o.get("cwd"), str):
                T.cwd = o["cwd"]
            if t == "assistant":
                m = o.get("message") or {}
                md = m.get("model")
                if md == "<synthetic>":
                    T.synthetic += 1
                elif md:
                    T.models[md] += 1
                    T.assistant_messages += 1
                    if T.segments and T.segments[-1][0] == md:
                        T.segments[-1][2] = ts or T.segments[-1][2]
                        T.segments[-1][3] += 1
                    else:
                        T.segments.append([md, ts, ts, 1])
                for b in m.get("content") if isinstance(m.get("content"), list) else []:
                    if not isinstance(b, dict):
                        continue
                    if b.get("type") == "tool_use":
                        T.tool_uses += 1
                        n, i = b.get("name"), b.get("input") or {}
                        if n in ("Agent", "Task"):
                            T.uses[b.get("id")] = {"ts": ts, "description": i.get("description"),
                                                   "subagent_type": i.get("subagent_type"), "model": i.get("model"),
                                                   "background": i.get("run_in_background"),
                                                   "prompt": i.get("prompt") or ""}
                        elif n == "SendMessage":
                            T.sends.append({"ts": ts, "to": i.get("to") or i.get("recipient")})
                        elif n == "Workflow":
                            T.workflows += 1
                        elif n == "SubagentHandback":
                            T.handbacks.append(str(i.get("message") or ""))
                    elif b.get("type") == "text":
                        T.last_text = b.get("text") or ""
            elif t == "user":
                m = o.get("message") or {}
                c = m.get("content")
                if T.prompt is None:  # the brief: the first user turn with text of its own (a skill's brief is
                    own = c if isinstance(c, str) else "\n".join(  # an isMeta turn; tool results never count)
                        b.get("text") or "" for b in c or [] if isinstance(b, dict) and b.get("type") == "text")
                    if own.strip():
                        T.prompt = own
                if isinstance(c, list):
                    for b in c:
                        if isinstance(b, dict) and b.get("type") == "tool_result":
                            mm = re.search(r"agentId: (\w+)", _text(b.get("content")))
                            if mm:
                                T.results[b.get("tool_use_id")] = mm.group(1)
                s = _text(c)
                if "<task-notification>" in s:
                    for part in _split_notifications(s):
                        user_notifs.append((ts, part))
            elif t == "queue-operation" and o.get("operation") == "enqueue":
                c = o.get("content") or ""
                if isinstance(c, str) and "<task-id>" in c:
                    for part in _split_notifications(c):
                        queue_notifs.append((ts, part))
    # the main transcript records every notification twice (queued, then delivered as a user turn): use the queue
    # when it exists, else the delivered copies (subagent transcripts have no queue)
    for ts, part in queue_notifs or user_notifs:
        d = parse_notification(part)
        d["ts"] = ts
        k = (d["task-id"], ts)
        if d["task-id"] and k not in seen:
            seen.add(k)
            T.notifs.append(d)
    return T


# ------------------------------------------------------------------------------------------ discovery ---
def _session_dir(p: Path) -> Session | None:
    """A directory that is one session in an archive layout."""
    if (p / "main.jsonl").is_file():
        sub = p / "session" / "subagents" if (p / "session" / "subagents").is_dir() else p / "subagents"
        return Session(p.name, p.parent.name, "archive-legacy", p / "main.jsonl", sub if sub.is_dir() else None)
    if (p / f"{p.name}.jsonl").is_file():
        sub = p / "subagents"
        return Session(p.name, p.parent.name, "archive", p / f"{p.name}.jsonl", sub if sub.is_dir() else None)
    return None


def _main_file(f: Path) -> Session | None:
    if f.suffix != ".jsonl" or f.name.startswith("agent-") or f.name == "main.jsonl":
        return None
    sid = f.stem
    sub = f.parent / sid / "subagents"
    return Session(sid, f.parent.name, "raw", f, sub if sub.is_dir() else None)


def discover(paths, max_depth: int = 3) -> list[Session]:
    found: dict[str, Session] = {}

    def add(s: Session | None):
        if s is None or not SID_RE.match(s.session_id):
            return
        old = found.get(s.session_id)
        if old is None or s.size() > old.size():  # the same session archived twice: keep the fuller copy
            found[s.session_id] = s

    def walk(p: Path, depth: int):
        s = _session_dir(p)
        if s:
            add(s)
            return
        try:
            kids = sorted(p.iterdir())
        except OSError:
            return
        for k in kids:
            if k.is_file():
                add(_main_file(k))
        if depth < max_depth:
            for k in kids:
                if k.is_dir() and k.name not in SKIP_DIRS and not k.is_symlink():
                    walk(k, depth + 1)

    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_file():
            add(_main_file(p))
        elif p.is_dir():
            walk(p, 0)
    return [found[k] for k in sorted(found)]


def subagent_files(s: Session) -> list[tuple[str, Path, dict]]:
    out = []
    if not s.subagent_dir or not s.subagent_dir.is_dir():
        return out
    for f in sorted(s.subagent_dir.glob("agent-*.jsonl")):
        aid = f.name[len("agent-"):-len(".jsonl")]
        meta = {}
        mf = f.with_name(f"agent-{aid}.meta.json")
        if mf.is_file():
            try:
                meta = json.loads(mf.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                meta = {}
        out.append((aid, f, meta if isinstance(meta, dict) else {}))
    return out


def slug(s: str | None) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(s or "").lower()).strip("-")
    return s[:40] or "project"


def project_from_cwd(cwd: str | None) -> str | None:
    return slug(os.path.basename(cwd.rstrip("/"))) if cwd else None
