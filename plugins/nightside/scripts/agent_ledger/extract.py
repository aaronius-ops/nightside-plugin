"""Turn parsed sessions into ledger rows (schema_version 1). Deterministic: same transcripts, same rows.

Row kinds (field `record`):
  agent_run   one per subagent transcript: key "<session>/<agent_id>"
  session     one per session: key "session/<session>"; the orchestrator's model segments

Agent-run fields (the legacy ledger fields plus schema_version, record, key, project, parent_agent_id,
spawn_depth, launch, node_basis, curated, description_redacted):
  agent_id, session, kind, description, subagent_type, model_requested, model_used, node, workstream, launched_at,
  finished_at, status, status_history, tokens, tool_uses, duration_ms, resumed_count, branch, commits, verdict,
  findings_count, findings_basis, notes

How each is derived:
  description      the Agent tool call's `description` (else the subagent meta description), scrubbed by the guard;
                   skill-launched reviews get "/code-review <branch> (skill-launched review)" instead of skill text
  status, tokens   task-notifications in any transcript of the session, deduped by (task-id, ts); tokens = the max
                   subagent_tokens reported (it is cumulative across resumes); tool_uses and duration_ms are summed
                   (per segment); no usage in any notification -> tokens/duration null, tool_uses counted from the
                   subagent transcript
  model_used       the model on most of the subagent's assistant messages
  resumed_count    SendMessage calls addressed to the agent id
  branch, commits  from the launch prompt / the final report, in memory only; only the name / 7-char hashes are kept
  verdict          MERGE / MERGE-WITH-FIXES / BLOCK / DEPLOY / DEPLOY-WITH-FIXES words, or KEEP -> kept / SEND BACK -> sent_back, in a review's report
  findings_count   json `"file":` items, else a stated "N findings" in the first 1500 chars, else null + basis
  node, workstream null here; set by a node map (ledger.py), the graph, or by hand (kept on merge)
"""
from __future__ import annotations

import re
from collections import Counter

from . import SCHEMA_VERSION
from .guard import Guard, check_row
from .transcripts import Session, parse_transcript, project_from_cwd, subagent_files

VER = re.compile(r"\b(MERGE-WITH-FIXES|DEPLOY-WITH-FIXES|MERGE|BLOCK|DEPLOY)\b")
# Reviewer phrasings: "Verdict: KEEP", "**Verdict: SEND BACK.**", "SEND BACK (two small fixes)", "KEEP. No blocking issues".
# KEEP / SEND BACK are only taken in capitals after "Verdict:" or opening the report (prose "keep" is never a verdict).
VER2 = re.compile(r"(?:\bVerdict\W{0,6}|\A\W{0,6})(SEND BACK|KEEP)\b")
VER2MAP = {"KEEP": "kept", "SEND BACK": "sent_back"}
NUMITEM = re.compile(r"^\s*(?:[-*]\s+)?(\d{1,2})[.)]\s+\S", re.M)
FINDHDR = re.compile(r"^\W*Findings\b", re.M)
PRIOR = re.compile(r"\W{0,3}(?:are |were |is |all )?(?:now )?(?:closed|fixed|resolved|verified|addressed)\b", re.I)
SECHDR = re.compile(r"^\W*(?:non-blocking(?: findings)?\b|(?:new )?findings\b)(?![^\n]*\b(?:closed|fixed|resolved)\b)[^\n]{0,40}$", re.I | re.M)
ENDHDR = re.compile(r"^(?:\*\*[^\n]{1,60}\*\*|[A-Z][^.\n]{0,40}:)\W*$")
LOWLINE = re.compile(r"^\W{0,3}(?:Low|Nit|Minor)(?:,? non-blocking)?\b[:.]", re.M)
HEX = re.compile(r"(?<![\w/.-])([0-9a-f]{7,40})(?![\w-])")
BRANCH_OK = re.compile(r"^[A-Za-z0-9][\w./,+-]{0,99}$")
TOKEN_OK = re.compile(r"^[\w:.\[\]-]{1,80}$")
NUM = {"no": 0, "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
       "nine": 9, "ten": 10, "eleven": 11, "twelve": 12}
STATED = re.compile(r"(?<![\d.,])\b(\d{1,2}|no|zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)\s+"
                    r"(?:new\s+|confirmed\s+|possible\s+)?(?:findings?|issues?|defects?|problems?)\b", re.I)


def is_skill_review(desc: str, meta: dict, prompt: str) -> bool:
    return (desc.startswith("/code-review") or str(meta.get("name") or "").startswith("code-review")
            or (not desc and "Review target:" in prompt))


def kind_of(desc: str) -> str:
    if re.match(r"(Fix|Apply|Finish)\b", desc):
        return "fix"
    if re.search(r"Design critique|Art direction|UX:|UI/UX|Visual|Design |Sim city", desc):
        return "design"
    if re.search(r"review|Review|Audit|Adversarial", desc):
        return "review"
    if re.search(r"Research|Find |Inventory", desc):
        return "research"
    if re.search(r"Re-record|Impact Snapshot|Build Notes|Submission regen|^(?:Regenerate|Republish|Archive|Sync)\b", desc):
        return "ops"
    return "build" if desc else "other"


def _review_target(prompt: str) -> str:
    m = re.search(r"Review target: `[^\n]{0,260}", prompt)
    return m.group(0) if m else ""


def branch_of(desc: str, skill_review: bool, prompt: str, report: str) -> str | None:
    if skill_review:
        t = _review_target(prompt)
        m = re.search(r"origin/main\.\.origin/([\w.-]+)", t) or re.search(r"origin/([\w.-]+)", t)
        if m:
            return m.group(1)
        m = re.search(r"branch ([\w.-]+)", t)
        if m:
            return m.group(1)
        return "main" if " on main" in t else None
    for rx in (r"worktree add \S+ -b (\S+)", r"checkout -b (\S+)", r"on branch[ `]+([a-z][\w./-]{2,})"):
        m = re.search(rx, prompt)
        if m:
            return m.group(1).rstrip(".,;:`)")
    m = re.search(r"[Bb]ranch[: ]+`([a-z][\w./-]{2,})`", report)
    return m.group(1) if m else None


def commits_of(report: str) -> list[str]:
    out = []
    for m in HEX.finditer(report):
        t = m.group(1)
        if not re.search(r"\d", t) or not re.search(r"[a-f]", t) or len(t) not in (7, 8, 9, 10, 11, 12, 40):
            continue
        ctx = report[max(0, m.start() - 45):m.start()].lower()
        if re.search(r"commits?\W|head\W|pushed|merge|\bat\W|@|\bsha|\brev|on top of|\btip|\bmain\W|\bbase\W|\bfrom\W|"
                     r"\bto\W|\(", ctx) or report[max(0, m.start() - 3):m.start()].endswith(".."):
            c = t[:7]
            if c not in out:
                out.append(c)
    return out


def verdict_of(report: str) -> str | None:
    head = report[:1500]
    vm = VER.findall(head)
    if vm:  # a "with fixes" verdict means the author must change something: sent back (events kept:false)
        return "sent_back" if all(v.endswith("WITH-FIXES") for v in vm) else " / ".join(dict.fromkeys(vm))
    if re.search(r"\bmerge with fixes\b", head, re.I):
        return "sent_back"
    m = VER2.search(head)
    return VER2MAP[m.group(1)] if m else None


def findings_of(report: str) -> tuple[int | None, str]:
    j = len(re.findall(r'"file":', report))
    if j:
        return j, "json items"
    if not report.strip():
        return None, "no report"
    head = report[:1500]
    if re.match(r"\s*\(none\)", head):
        return 0, 'report starts "(none)"'
    for m in STATED.finditer(head):
        # "All 5 findings are closed" describes a prior round's findings, never this round's
        if PRIOR.match(head[m.end():m.end() + 30]) or re.search(r"\ball\W*$", head[max(0, m.start() - 6):m.start()], re.I):
            continue
        w = m.group(1).lower()
        return (int(w) if w.isdigit() else NUM[w]), "stated in report"
    sec = SECHDR.search(report[:6000])
    if sec:
        lines, seg = report[sec.end():6000].split("\n"), []
        for ln in lines:
            if seg and ENDHDR.match(ln.strip()):
                break
            seg.append(ln)
        txt = "\n".join(seg)
        n = 0
        for mm in NUMITEM.finditer(txt):
            if int(mm.group(1)) == n + 1:
                n += 1
        if not n:
            n = sum(1 for ln in seg if re.match(r"[-*] +(?!\W*(?:INFO|NOTE)\b)\S", ln))
        if n:
            return n, "findings list"
    low = LOWLINE.findall(report[:6000])
    if low and not FINDHDR.search(report[:6000]):
        return len(low), "low-severity line"
    # numbered findings list: only under a "Findings" header, or in a SEND BACK report (a KEEP report's numbered
    # lines are usually checks, not findings)
    if FINDHDR.search(report[:6000]) or (verdict_of(report) == "sent_back"):
        start = FINDHDR.search(report[:6000])
        seg = report[start.end():6000] if start else report[:6000]
        n = 0
        for mm in NUMITEM.finditer(seg):
            if int(mm.group(1)) == n + 1:
                n += 1
        if n:
            return n, "numbered findings"
    return None, "not derivable"


def _clean_token(v) -> str | None:
    return v if isinstance(v, str) and TOKEN_OK.match(v) else None


def session_rows(sessions: list[Session], guard: Guard, project: str | None = None) -> tuple[list[dict], dict]:
    """(rows, stats). Rows sorted by (record, launched_at/first_ts, key)."""
    rows, stats = [], Counter()
    for s in sessions:
        main = parse_transcript(s.main) if s.main and s.main.is_file() else None
        subs = subagent_files(s)
        parsed = {aid: (f, meta, parse_transcript(f)) for aid, f, meta in subs}
        transcripts = ([main] if main else []) + [p[2] for p in parsed.values()]
        proj = project or (project_from_cwd(main.cwd if main else None) if s.layout == "raw" else s.project)
        proj = _clean_token(proj) or "project"
        uses, results, sends, notes_by = {}, {}, Counter(), {}
        for T in transcripts:
            uses.update({k: v for k, v in T.uses.items() if k not in uses})
            results.update(T.results)
            for x in T.sends:
                sends[x["to"]] += 1
            for n in T.notifs:
                notes_by.setdefault(n["task-id"], {})[(n["ts"], n.get("status"), n.get("subagent_tokens"))] = n
        rev = {v: k for k, v in results.items()}
        stats["sessions"] += 1
        stats["subagent_transcripts"] += len(parsed)
        if main:
            rows.append(_session_row(s, proj, main, len(parsed)))
        for aid, (f, meta, T) in parsed.items():
            row = _agent_row(s, proj, aid, meta, T, uses.get(meta.get("toolUseId")) or uses.get(rev.get(aid)) or {},
                             sorted(notes_by.get(aid, {}).values(), key=lambda n: (n["ts"] or "")), sends.get(aid, 0),
                             guard)
            stats["redacted_descriptions"] += bool(row.get("description_redacted"))
            check_row(row)
            rows.append(row)
    rows.sort(key=lambda r: (r["record"], r.get("launched_at") or r.get("first_ts") or "", r["key"]))
    return rows, dict(stats)


def _session_row(s: Session, proj: str, T, n_sub: int) -> dict:
    row = {"schema_version": SCHEMA_VERSION, "record": "session", "key": f"session/{s.session_id}",
           "session": s.session_id, "project": proj, "first_ts": T.first_ts, "last_ts": T.last_ts,
           "orchestrator_models": [{"model": _clean_token(m), "first": a, "last": b, "messages": n}
                                   for m, a, b, n in T.segments],
           "assistant_messages": T.assistant_messages, "synthetic_messages": T.synthetic,
           "agent_runs": n_sub, "workflow_calls": T.workflows, "curated": []}
    check_row(row)
    return row


def _agent_row(s: Session, proj: str, aid: str, meta: dict, T, use: dict, ns: list, n_sends: int,
               guard: Guard) -> dict:
    raw_desc = str(use.get("description") or meta.get("description") or "")
    prompt = T.prompt or use.get("prompt") or ""
    report = T.handbacks[-1] if T.handbacks else T.last_text
    skill = not use and is_skill_review(raw_desc, meta, prompt)
    kind = "review" if skill else kind_of(raw_desc)
    br = branch_of(raw_desc, skill, prompt, report)
    br, _ = guard.scrub(br, 100) if br else (None, False)
    br = br if br and BRANCH_OK.match(br) else None
    notes = []
    if skill:
        desc, red = (f"/code-review {br or '?'} (skill-launched review)" if raw_desc else
                     f"/code-review {br or '?'} (unnamed review)"), False
        notes.append("launched via the /code-review skill, not the Agent tool; no SubagentHandback; report is the "
                     "final message")
    else:
        desc, red = guard.scrub(raw_desc)
    if not guard.deny_loaded and not skill:  # no project deny list: never free text, the kind only (fail closed)
        desc, red = kind, bool(raw_desc) and raw_desc != kind
    toks = [x["subagent_tokens"] for x in ns if x.get("subagent_tokens") is not None]
    tools = [x["tool_uses"] for x in ns if x.get("tool_uses") is not None]
    durs = [x["duration_ms"] for x in ns if x.get("duration_ms") is not None]
    hist = [x.get("status") for x in ns if x.get("status")]
    status = hist[-1] if hist else "no-notification"
    used = max(sorted(T.models), key=T.models.get) if T.models else None
    if len(T.models) > 1:
        notes.append("mixed models: " + ", ".join(f"{k}:{v}" for k, v in sorted(T.models.items())))
    if not toks:
        notes.append("no usage data in any task-notification; tokens, duration null; tool_uses counted from the "
                     "transcript")
    if toks and toks != sorted(toks):
        notes.append("token series not monotonic: " + ",".join(map(str, toks)))
    if status in ("failed", "killed") and toks:
        notes.append(f"final notification {status} after earlier completed run(s); tokens are the max reported "
                     "before it")
    if "failed" in hist[:-1]:
        notes.append("an earlier notification failed (session interruption) and the agent was later resumed")
    if status == "failed" and not toks:
        notes.append("failed with no completed run" + (" (session limit message in transcript)"
                                                        if "session limit" in report else ""))
    if status == "killed" and not toks:
        notes.append("killed before any completed run")
    verdict = fc = fb = None
    if kind == "review":
        verdict = verdict_of(report)
        fc, fb = findings_of(report)
    req = use.get("model") or meta.get("model")
    return {
        "schema_version": SCHEMA_VERSION, "record": "agent_run", "key": f"{s.session_id}/{aid}",
        "agent_id": aid, "session": s.session_id, "project": proj, "kind": kind, "description": desc,
        "subagent_type": _clean_token(meta.get("agentType") or use.get("subagent_type")),
        "model_requested": _clean_token(req), "model_used": _clean_token(used), "node": None, "workstream": None,
        "launched_at": use.get("ts") or T.first_ts, "finished_at": T.last_ts, "status": _clean_token(status),
        "status_history": [h for h in (_clean_token(x) for x in hist) if h], "tokens": max(toks) if toks else None,
        "tool_uses": sum(tools) if tools else T.tool_uses, "duration_ms": sum(durs) if durs else None,
        "resumed_count": n_sends, "branch": br, "commits": commits_of(report), "verdict": verdict,
        "findings_count": fc, "findings_basis": fb, "notes": "; ".join(notes) or None,
        "parent_agent_id": _clean_token(meta.get("parentAgentId")),
        "spawn_depth": meta.get("spawnDepth") if isinstance(meta.get("spawnDepth"), int) else None,
        "launch": "skill" if skill else ("fork" if meta.get("isFork") else ("agent_tool" if use else "unknown")),
        "node_basis": None, "curated": [], "description_redacted": red,
    }
