"""The Surveyor: the spool's event stream (never a transcript) + the repo's agent-ledger rows -> one
WorkflowManifest per project, deterministic, written to <capture root>/outbox/<project_id>.json after the allow-list
passes. Never runs in SessionEnd (that hook only closes the session): it runs in the async SessionStart hook of the
next session in the project and on demand (`/planet status --survey`, `/planet preview`).

Incremental: a closed session (its last event is a SessionEnd, or its spool file has not changed for a day) is folded
into a small per-session summary, sessions/<project_id>/<session hash>.json, reused while the spool file's size is
unchanged. Any event after a SessionEnd (a resumed session) re-opens it. Retention (retention()) folds and deletes the raw spool of summarized sessions idle longer than
"spool_retention_days" (30), drops summaries older than "summary_retention_days" (365), and above "max_capture_mb"
(32) folds and deletes the raw spool of CLOSED summarized sessions, oldest first: never a summary, never an open
session's spool (it logs when it cannot get under the cap). Summary writes and evictions run under the spool lock
(common.try_lock, waited on briefly, then skipped), and an eviction never deletes bytes it did not count.
Spool reads are capped at MAX_READ_BYTES, newest files first.

How each field is derived (tool NAMES and timings only; nothing here can see an input, an output or a prompt):
  user_id       "local" (the server assigns the owner on upload)
  project_id    keyed hash of the repository root (common.project_identity)
  project_name  rich tier only, and only a name the user chose (config projects[<id>].name, set with
                `/planet privacy public --name ...`); never the repo slug unprompted; must pass the guard unchanged
  summary       rich tier only, and only with the opt-in rich summary (rich.py); otherwise absent
  category      config projects[<id>].category if set, else "unclassified" (the server's classifier decides)
  graph_shape   "orchestrator+subagents" when any subagent ran, else "single"
  agents        orchestrator: one row per model tier, turns = prompts, minutes = session spans;
                subagents: grouped by (agent type, model tier), turns = runs, minutes = SubagentStart->Stop.
                Agent types are as the hook encoded them: built-in types readable, any other custom-<keyed hash>.
                Ledger rows (docs/agents/ledger.jsonl) add runs the spool never saw and the subagent model
                (hook payloads do not carry a subagent's model); only subagent_type / model_used / duration_ms /
                session / agent_id / launched_at / finished_at are read, never description or notes.
  tools         {tool: count}; built-in names readable; MCP tools are mcp__<server hash>__<tool> at the rich tier
                and fold to mcp-<server hash> at the metadata tier; anything else "other"
  skills, infra_tags  [] (a skill's name lives in tool_input, which capture never records)
  mcp_servers   srv-<keyed server hash> (both tiers)
  runs          sessions; first/last rounded down to the minute; total_minutes = summed session spans
  outcomes      files_written = successful Write/Edit/MultiEdit/NotebookEdit calls; prs = successful tools whose
                NAME creates a pull request; artifacts = successful Artifact calls; deploys = 0 (needs command text)
  links_to      []
  label         labels.py: {text <= 40 chars, category, source}. user (config projects[<id>].label, set with
                `/planet preview --label ... --category ...`) > claude (the opt-in rich summary) > heuristic (the
                closed-table kinds the hook recorded + tool names; a fixed phrase). Re-checked here every survey:
                a label that fails the allow-list for the CURRENT tier, or repeats a local name (repo slug, raw MCP
                server / custom agent names, login), is dropped for the next candidate; the user sees which in the
                preview. With a user label, category = the label's category.
  privacy_tier  project override > config default ("metadata"); a private project is always "metadata"
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from capture import common as C
from capture import allowlist as A
from capture import hook as H
from capture import labels as L

WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
PR_TOOL = re.compile(r"(?i)create_pull_request|pull_request_create|create_pr\b")
MAX_READ_BYTES = 32 << 20
MAX_AGENTS = 64
STALE_OPEN_S = 86400  # an open session whose spool has not changed for a day is treated as closed


def tier_of(model) -> str | None:
    if not isinstance(model, str) or not model:
        return None
    m = model.lower()
    for t in ("haiku", "sonnet", "opus", "fable"):
        if t in m:
            return t
    return "other"


def _ts(s) -> float | None:
    if not isinstance(s, str) or len(s) > 40:
        return None
    try:
        d = datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s)
    except ValueError:
        return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()


def _minute(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:00Z", time.gmtime(t))


# ------------------------------------------------------------------------------------------------ spool ---
def _spool_files(root: Path, pid: str) -> list[tuple[Path, os.stat_result]]:
    """(file, stat) newest first; symlinks and odd names skipped."""
    d = root / "spool" / pid
    out = []
    if d.is_dir() and not d.is_symlink():
        for f in d.glob("*.jsonl"):
            try:
                st = os.lstat(f)
            except OSError:
                continue
            if C.HEX16.match(f.stem) and not os.path.islink(f):
                out.append((f, st))
    out.sort(key=lambda x: (-x[1].st_mtime, x[0].name))
    return out


def read_events(f: Path) -> list[dict]:
    return _events_of(f.read_bytes())


def _events_of(data: bytes) -> list[dict]:
    out = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict) and set(r) <= H.SPOOL_KEYS and _ts(r.get("t")) is not None and C.HEX16.match(
                str(r.get("s"))):
            r["_t"] = _ts(r["t"])
            out.append(r)
    out.sort(key=lambda r: r["_t"])
    return out


def read_spool(root: Path, pid: str) -> list[dict]:
    """Every event of the project, newest files first up to MAX_READ_BYTES (older files beyond the cap are skipped
    and are the first that retention removes)."""
    out, total = [], 0
    for f, st in _spool_files(root, pid):
        total += st.st_size
        if total > MAX_READ_BYTES:
            break
        out += read_events(f)
    out.sort(key=lambda r: r["_t"])
    return out


def _tool(v) -> str:
    return v if isinstance(v, str) and H.ENC_TOOL.match(v) else "other"


def _agent(v) -> str:
    if not v:
        return "agent"
    return v if v in H.BUILTIN_AGENTS or H.ENC_AGENT.match(v) else "other"


def partial(events: list[dict]) -> dict:
    """One session's summary: everything the manifest needs, nothing more (all values already encoded)."""
    p = {"first": None, "last": None, "closed": False, "model": None, "prompts": 0, "subs": {}, "tools": {},
         "kinds": {}, "out": {"files_written": 0, "prs": 0, "artifacts": 0}}
    tools: Counter = Counter()
    kinds: Counter = Counter()
    for e in events:
        t, ev, a = e["_t"], e["ev"], e.get("a")
        p["first"] = t if p["first"] is None else min(p["first"], t)
        p["last"] = t if p["last"] is None else max(p["last"], t)
        p["closed"] = ev == "SessionEnd"  # closed only while its last event is a SessionEnd; a resume re-opens it
        if ev in ("SessionStart", "PostModelSwitch") and e.get("model") and not a:
            p["model"] = e["model"]
        elif ev == "UserPromptSubmit" and not a:
            p["prompts"] += 1
        elif ev in ("SubagentStart", "SubagentStop") and a:
            r = p["subs"].setdefault(a, {"type": None, "start": None, "stop": None})
            r["type"] = r["type"] or e.get("at")
            r["start" if ev == "SubagentStart" else "stop"] = t
            if ev == "SubagentStart" and C.HEX16.match(str(e.get("r"))) and C.HEX16.match(str(e.get("rm"))):
                r["r"], r["rm"] = e["r"], e["rm"]
        elif ev in ("PostToolUse", "PostToolUseFailure"):
            name = _tool(e.get("tool"))
            tools[name] += 1
            if e.get("k") in L.KINDS:
                kinds[e["k"]] += 1
            if e.get("ok"):
                p["out"]["files_written"] += name in WRITE_TOOLS
                p["out"]["artifacts"] += name == "Artifact"
                p["out"]["prs"] += bool(PR_TOOL.search(name))
    p["tools"] = dict(sorted(tools.items()))
    p["kinds"] = dict(sorted(kinds.items()))
    return p


def merge_partials(base: dict | None, new: dict) -> dict:
    """A session whose raw spool was evicted (folded into `base`) and that later resumed: base + the new lines."""
    if not base:
        return new
    if new["first"] is None:
        return base
    tools = dict(base.get("tools") or {})
    for k, v in (new.get("tools") or {}).items():
        tools[k] = tools.get(k, 0) + v
    kinds = dict(base.get("kinds") or {})
    for k, v in (new.get("kinds") or {}).items():
        kinds[k] = kinds.get(k, 0) + v
    out = {k: (base.get("out") or {}).get(k, 0) + (new.get("out") or {}).get(k, 0)
           for k in ("files_written", "prs", "artifacts")}
    subs = dict(base.get("subs") or {})
    for a, r in (new.get("subs") or {}).items():
        o = subs.get(a) or {"type": None, "start": None, "stop": None}
        subs[a] = {"type": o["type"] or r["type"], "start": o["start"] if o["start"] is not None else r["start"],
                   "stop": r["stop"] if r["stop"] is not None else o["stop"]}
        for k in ("r", "rm"):
            if o.get(k) or r.get(k):
                subs[a][k] = o.get(k) or r.get(k)
    return {"first": min(base["first"], new["first"]), "last": max(base["last"], new["last"]),
            "closed": new["closed"], "model": new.get("model") or base.get("model"),
            "prompts": base.get("prompts", 0) + new.get("prompts", 0), "subs": subs, "tools": dict(sorted(tools.items())),
            "kinds": dict(sorted(kinds.items())), "out": out}


def _read_cache(p: Path) -> dict | None:
    try:
        c = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return c if isinstance(c, dict) and isinstance(c.get("partial"), dict) else None


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _summarize(f: Path, c: dict | None) -> tuple[dict, dict] | None:
    """(partial, cache record) for spool file f. A record is {"spool_size", "partial", "base", "folded", "folded_sha"}:
    "base" is everything already evicted for this session PLUS the first "folded" bytes of the current file, whose
    sha256 is "folded_sha" (folded = 0 once an eviction has finished). Only the bytes after the folded prefix are
    merged into the base, so a file that survived a half-done eviction is never counted twice, and a NEW file (a
    session resumed after eviction: the prefix does not match) is counted whole on top of the base."""
    try:
        data = f.read_bytes()
    except OSError:
        return None
    data = data[:data.rfind(b"\n") + 1]  # whole lines only (a line being appended right now is read next time)
    base = c.get("base") if c else None
    folded = (c.get("folded") or 0) if c else 0
    sha = c.get("folded_sha") if c else None
    if folded and isinstance(folded, int) and len(data) >= folded and sha == _sha(data[:folded]):
        tail = data[folded:]
    else:
        tail, folded, sha = data, 0, None
    p = merge_partials(base, partial(_events_of(tail)))
    return p, {"spool_size": len(data), "partial": p, "base": base, "folded": folded, "folded_sha": sha}


def load_partials(root: Path, pid: str, now: float | None = None, _locked: bool = False) -> dict[str, dict]:
    """{session hash: partial}. A closed session (or one idle for a day) is cached in sessions/<pid>/<s>.json (see
    _summarize) and reused while its spool file's size is unchanged. "base" holds what an evicted spool file
    contained (retention folds it in before deleting the file), so a session that resumes after eviction keeps its
    history. A summary whose spool file is gone is still counted. Summaries are written only under the spool lock;
    if another process holds it, this still answers but writes nothing."""
    if _locked:
        return _load_partials(root, pid, now, True)
    with C.try_lock(root) as held:
        return _load_partials(root, pid, now, held)


def _load_partials(root: Path, pid: str, now: float | None, write: bool) -> dict[str, dict]:
    now = time.time() if now is None else now
    sd = root / "sessions" / pid
    out: dict[str, dict] = {}
    total = 0
    for f, st in _spool_files(root, pid):
        total += st.st_size
        if total > MAX_READ_BYTES:
            break
        cache = sd / f"{f.stem}.json"
        c = _read_cache(cache)
        if c and c.get("spool_size") == st.st_size and not c.get("folded"):
            out[f.stem] = c["partial"]
            continue
        r = _summarize(f, c)
        if r is None or r[0]["first"] is None:
            continue
        p, rec = r
        out[f.stem] = p
        if write and rec != c and (p["closed"] or now - st.st_mtime > STALE_OPEN_S):
            C.secure_dir(root / "sessions", root)
            C.secure_dir(sd, root)
            C.atomic_write(cache, C.canonical(rec))
    if sd.is_dir():
        for cf in sd.glob("*.json"):
            if cf.stem not in out and C.HEX16.match(cf.stem) and not cf.is_symlink():
                c = _read_cache(cf)
                if c:
                    out[cf.stem] = c["partial"]
    return out


def _evict(root: Path, pid: str, f: Path, st) -> int:
    """Fold a summarized spool file into its summary's base, then delete it. The caller holds the spool lock. Only
    when the summary covers exactly this file (same size, at fold time and again just before the unlink); a file
    that grew since it was counted is left alone. Every step is idempotent: the fold record keeps the file's size
    and prefix hash, so a crash or failed unlink leaves a file that is recognised as already folded (counted once),
    and re-running converges. Returns bytes freed (0 = not evicted)."""
    cache = root / "sessions" / pid / f"{f.stem}.json"
    c = _read_cache(cache)
    if not c or c.get("spool_size") != st.st_size:
        return 0
    try:
        data = f.read_bytes()
    except OSError:
        return 0
    n = len(data)
    if n != c["spool_size"] or not data.endswith(b"\n"):
        return 0
    P = c["partial"]
    fold = {"spool_size": n, "partial": P, "base": P, "folded": n, "folded_sha": _sha(data)}
    if c != fold:
        C.atomic_write(cache, C.canonical(fold))
    try:
        if os.lstat(f).st_size != n:  # a line landed after it was counted: keep the file (its tail counts next time)
            return 0
        f.unlink()
    except OSError:
        return 0
    C.atomic_write(cache, C.canonical({"spool_size": 0, "partial": P, "base": P, "folded": 0, "folded_sha": None}))
    return n


def _num(v, default):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0 else default


def retention(root: Path, cfg: dict, now: float | None = None, lock_wait: float = 2.0) -> dict:
    """1. age: the raw spool of a summarized session idle longer than spool_retention_days (30) is folded into its
          summary and deleted; summaries older than summary_retention_days (365) are deleted (that history is gone).
       2. size: above max_capture_mb (32), the raw spool of CLOSED, summarized sessions is folded and deleted,
          oldest first. The size cap never deletes a summary and never touches an open session's spool; if the
          capture is still over the cap it logs that and stops.
    Summaries are always made first (load_partials), so the age and size steps lose no counted history.
    Runs under the spool lock, waited on for `lock_wait` seconds; if another retention still holds it, this one is
    skipped ("skipped": True) rather than blocking the hook."""
    with C.try_lock(root, wait=lock_wait) as held:
        if not held:
            C.log(root, "retention: skipped, the spool lock is held by another retention")
            return {"aged": 0, "summaries_aged": 0, "size": 0, "over_cap": False, "skipped": True}
        return _retention(root, cfg, now)


def _retention(root: Path, cfg: dict, now: float | None) -> dict:
    now = time.time() if now is None else now
    days = _num(cfg.get("spool_retention_days"), 30)
    sdays = _num(cfg.get("summary_retention_days"), 365)
    cap = _num(cfg.get("max_capture_mb"), 32) * (1 << 20)
    removed = {"aged": 0, "summaries_aged": 0, "size": 0, "over_cap": False, "skipped": False}
    closed: list[tuple[float, str, Path, os.stat_result]] = []
    for pid in projects(root):
        parts = load_partials(root, pid, now, _locked=True)  # summarize before anything is deleted
        for f, st in _spool_files(root, pid):
            if now - st.st_mtime > days * 86400 and _evict(root, pid, f, st):
                removed["aged"] += 1
            elif os.path.exists(f) and (parts.get(f.stem) or {}).get("closed"):
                closed.append((st.st_mtime, pid, f, st))
        sd = root / "sessions" / pid
        for cf in sd.glob("*.json") if sd.is_dir() else []:
            try:
                if now - os.lstat(cf).st_mtime > sdays * 86400 and not (root / "spool" / pid / f"{cf.stem}.jsonl"
                                                                          ).exists():
                    cf.unlink()
                    removed["summaries_aged"] += 1
            except OSError:
                pass

    def total() -> int:
        n = 0
        for sub in ("spool", "sessions"):
            d = root / sub
            for f in d.glob("*/*") if d.is_dir() else []:
                try:
                    n += os.lstat(f).st_size
                except OSError:
                    pass
        return n
    size = total()
    for _mt, pid, f, st in sorted(closed, key=lambda x: (x[0], str(x[2]))):
        if size <= cap:
            break
        freed = _evict(root, pid, f, st)
        if freed:
            size -= freed
            removed["size"] += 1
    if size > cap:
        removed["over_cap"] = True
        C.log(root, f"retention: {size >> 10} KiB still over max_capture_mb after evicting closed, summarized spool "
                    "(open sessions and summaries are never evicted by the size cap)")
    return removed


# ------------------------------------------------------------------------------------------------ ledger ---
def ledger_path(pdir) -> Path | None:
    if pdir is None:
        return None
    wt, _ = C.git_root(Path(pdir))
    p = (wt or Path(pdir)) / "docs" / "agents" / "ledger.jsonl"
    return p if p.is_file() and not p.is_symlink() else None


LEDGER_FIELDS = ("agent_id", "session", "subagent_type", "model_used", "duration_ms", "launched_at", "finished_at")


def read_ledger(path) -> list[dict]:
    rows = []
    if not path:
        return rows
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return rows
    for line in lines:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict) and r.get("record", "agent_run") == "agent_run" and r.get("agent_id"):
            rows.append({k: r.get(k) for k in LEDGER_FIELDS})
    return rows


# ---------------------------------------------------------------------------------------------- manifest ---
def effective_privacy(cfg: dict, pid: str) -> tuple[str, str]:
    p = (cfg.get("projects") or {}).get(pid) or {}
    vis = p.get("visibility") if p.get("visibility") in C.VISIBILITY else cfg.get("default_visibility", "private")
    tier = p.get("tier") if p.get("tier") in C.TIERS else cfg.get("privacy_tier", "metadata")
    if vis == "private":
        tier = "metadata"
    return tier, vis


def _metadata_tool(name: str) -> str:
    m = re.match(r"^mcp__([0-9a-f]{8})__", name)
    return f"mcp-{m.group(1)}" if m else name


def pick_label(m: dict, kinds: Counter, tools: dict, cfg: dict, pid: str, names: set[str],
               claude: dict | None = None) -> dict | None:
    """The first label candidate that passes the allow-list for this manifest's tier and repeats no local name:
    the user's (config), then a claude proposal, then the heuristic candidates. None if nothing passes."""
    pcfg = (cfg.get("projects") or {}).get(pid) or {}
    cands = []
    u = pcfg.get("label")
    hs = L.candidates(kinds, tools)
    if isinstance(u, dict) and (u.get("text") or u.get("category")):
        cat = u.get("category") if u.get("category") in L.categories() else hs[0]["category"]
        text = u.get("text") or (hs[0]["text"] if hs[0]["category"] == cat else L.default_text(cat))
        cands.append({"text": text, "category": cat, "source": "user"})
    if isinstance(claude, dict):
        cands.append(claude)
    cands += hs
    for c in cands:
        if isinstance(c, dict) and not A.check_label(c, m["privacy_tier"]) and not L.mentions_local_name(
                str(c.get("text")), names):
            return c
    return None



def build_manifest(partials: dict, ledger_rows: list[dict], key: bytes, pid: str, cfg: dict,
                   names: set[str] | None = None, claude_label: dict | None = None) -> dict:
    tier, _vis = effective_privacy(cfg, pid)
    rich = tier == "rich"
    pcfg = (cfg.get("projects") or {}).get(pid) or {}
    spans: dict[str, tuple[float, float]] = {}
    sub: dict[str, dict] = {}
    tools: Counter = Counter()
    raw_tools: Counter = Counter()  # rich-tier names, local only: the label reads MCP tool parts at both tiers
    kinds: Counter = Counter()
    servers: set[str] = set()
    out: Counter = Counter()
    agents: dict[tuple, dict] = {}

    def add(role, mtier, turns, minutes):
        g = agents.setdefault((role, mtier or "other"), {"turns": 0, "minutes": 0.0})
        g["turns"] += turns
        g["minutes"] += minutes

    for s, p in sorted(partials.items()):
        spans[s] = (p["first"], p["last"])
        add("orchestrator", tier_of(p.get("model")), p.get("prompts", 0), (p["last"] - p["first"]) / 60)
        for a, r in (p.get("subs") or {}).items():
            sub[a] = dict(r, model=None, s=s)
        for name, n in (p.get("tools") or {}).items():
            name = _tool(name)
            tools[name if rich else _metadata_tool(name)] += n
            raw_tools[name] += n
            m = re.match(r"^mcp__([0-9a-f]{8})__", name)
            if m:
                servers.add("srv-" + m.group(1))
        out.update(p.get("out") or {})
        kinds.update({k: v for k, v in (p.get("kinds") or {}).items() if k in L.KINDS and isinstance(v, int)})
    ledger_sessions: set[str] = set()
    for r in ledger_rows:  # models for spool agents, and runs the spool never saw
        a = C.kh(key, "agent", f"{r.get('session')}/{r['agent_id']}", 12)
        st, fin = _ts(r.get("launched_at")), _ts(r.get("finished_at"))
        enc = H.encode_agent(r.get("subagent_type"), key)
        if a in sub:
            sub[a]["model"] = sub[a]["model"] or r.get("model_used")
            sub[a]["type"] = sub[a]["type"] or enc
            continue
        dur = r.get("duration_ms")
        if st is None and fin is None:
            continue
        ls = "L" + C.kh(key, "session", str(r.get("session")), 15)
        ledger_sessions.add(ls)
        sub[a] = {"type": enc, "model": r.get("model_used"), "start": st, "s": ls,
                  "stop": fin if fin is not None else (st + dur / 1000 if isinstance(dur, (int, float)) and st else st)}
    minutes = {s: (b - a) / 60 for s, (a, b) in spans.items()}
    points = [x for ab in spans.values() for x in ab]
    for ls in sorted(ledger_sessions):  # ledger-only sessions: the union of their runs' intervals
        iv = sorted((r["start"], r["stop"]) for r in sub.values() if r["s"] == ls and r["start"] is not None
                    and r["stop"] is not None and r["stop"] >= r["start"])
        tot, cur = 0.0, None
        for a0, b0 in iv:
            if cur and a0 <= cur[1]:
                cur[1] = max(cur[1], b0)
            else:
                tot += (cur[1] - cur[0]) if cur else 0.0
                cur = [a0, b0]
        tot += (cur[1] - cur[0]) if cur else 0.0
        minutes[ls] = tot / 60
        points += [x for r in sub.values() if r["s"] == ls for x in (r["start"], r["stop"]) if x is not None]
    for a, r in sub.items():
        mins = (r["stop"] - r["start"]) / 60 if r["start"] is not None and r["stop"] is not None else 0.0
        add(_agent(r["type"]), tier_of(r["model"]), 1, max(mins, 0.0))
    rows = sorted(({"role": k[0], "model_tier": k[1], "turns": v["turns"], "minutes": round(v["minutes"], 1)}
                   for k, v in agents.items()), key=lambda x: (-x["minutes"], x["role"], x["model_tier"]))
    if len(rows) > MAX_AGENTS:
        rest = rows[MAX_AGENTS - 1:]
        rows = rows[:MAX_AGENTS - 1] + [{"role": "other", "model_tier": "other", "turns": sum(x["turns"] for x in rest),
                                         "minutes": round(sum(x["minutes"] for x in rest), 1)}]
    m = {
        "user_id": "local",
        "project_id": pid,
        "category": pcfg.get("category") if pcfg.get("category") in A.schema()["properties"]["category"]["enum"]
        else "unclassified",
        "graph_shape": "orchestrator+subagents" if sub else "single",
        "agents": rows,
        "tools": dict(sorted(tools.items())),
        "skills": [],
        "mcp_servers": sorted(servers),
        "infra_tags": [],
        "runs": {"count": len(minutes), "first_at": _minute(min(points)) if points else _minute(0),
                 "last_at": _minute(max(points)) if points else _minute(0),
                 "total_minutes": round(sum(minutes.values()), 1)},
        "outcomes": {"files_written": out["files_written"], "prs": out["prs"], "deploys": 0,
                     "artifacts": out["artifacts"]},
        "links_to": [],
        "privacy_tier": tier,
    }
    if rich:
        name = pcfg.get("name")  # only a name the user chose for this project
        if isinstance(name, str) and A.NAME_RICH.match(name) and A._free_text_ok(name, 60):
            m["project_name"] = name
    lab = pick_label(m, kinds, dict(raw_tools), cfg, pid, set(names or ()), claude_label)
    if lab:
        m["label"] = lab
        if lab["source"] == "user":
            m["category"] = lab["category"]
    return m


def attested_runs(partials: dict, key: bytes, pid: str) -> list[str]:
    """The run ids the hook recorded at SubagentStart whose local MAC verifies (forks excluded: a fork is the
    orchestrator's own context, as the server counts agents). Ledger-only runs never appear here: the repo's
    ledger file is not hook evidence. Sorted, unique."""
    out = set()
    for s, p in partials.items():
        for a, r in (p.get("subs") or {}).items():
            rid, mac = r.get("r"), r.get("rm")
            if (isinstance(rid, str) and C.HEX16.match(rid) and isinstance(mac, str) and _agent(r.get("type")) != "fork"
                    and hmac.compare_digest(mac, H.run_mac(key, pid, s, a, rid))):
                out.add(rid)
    return sorted(out)


def survey(root: Path, pid: str, cfg: dict, ledger=None, claude_label: dict | None = None,
           runs_out: list | None = None) -> dict:
    """ledger: a path, or None for the one recorded in the local index at SessionStart (consistent everywhere).
    runs_out: filled with the attested run ids of the SAME partials the manifest was built from."""
    key = C.install_key(root)
    if ledger is None:
        ledger = (C.read_index(root).get(pid) or {}).get("ledger")
    partials = load_partials(root, pid)
    if runs_out is not None:
        runs_out[:] = attested_runs(partials, key, pid)
    return build_manifest(partials, read_ledger(ledger), key, pid, cfg,
                          names=L.local_names(root, pid), claude_label=claude_label)


def survey_to_outbox(root: Path, pid: str, cfg: dict, ledger=None, summary: dict | None = None,
                     runs_out: list | None = None) -> Path:
    """Survey, apply an optional rich summary, run the allow-list (fail closed), write outbox/<pid>.json (600)."""
    cl = summary.get("label") if summary else None
    m = survey(root, pid, cfg, ledger, claude_label=cl, runs_out=runs_out)
    if summary:
        m.update({k: v for k, v in summary.items() if k in ("summary", "category")})
        if (m.get("label") or {}).get("source") == "user":  # the user's category wins over the model's
            m["category"] = m["label"]["category"]
    _tier, vis = effective_privacy(cfg, pid)
    try:
        A.check_envelope(A.envelope(m, vis))
    except A.Rejected:
        if not summary:
            raise
        m = survey(root, pid, cfg, ledger, runs_out=runs_out)  # a rich summary that fails the allow-list is dropped, never sent
        A.check_envelope(A.envelope(m, vis))
    ob = root / "outbox"
    C.secure_dir(ob, root)
    p = ob / f"{pid}.json"
    C.atomic_write(p, (json.dumps(m, indent=1, sort_keys=True) + "\n").encode())
    return p


def projects(root: Path) -> list[str]:
    out = set()
    for sub in ("spool", "sessions"):
        d = root / sub
        if d.is_dir():
            out |= {p.name for p in d.iterdir() if p.is_dir() and C.HEX16.match(p.name)}
    return sorted(out)
