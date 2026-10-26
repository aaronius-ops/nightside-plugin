"""SYNTHETIC Claude Code transcripts (invented ids, text and numbers; never copied from a real session)."""
from __future__ import annotations

import json
from pathlib import Path

SID = "11111111-2222-4333-8444-555555555555"
A1, A2, A3, A4 = "a0000000000000001", "a0000000000000002", "a0000000000000003", "a0000000000000004"
CANARY_PROMPT = "CANARY-PROMPT-91f2"
CANARY_REPORT = "CANARY-REPORT-4c7d"


def notif(aid: str, tu: str, status: str, tokens=None, tools=None, ms=None) -> str:
    usage = (f"<usage><subagent_tokens>{tokens}</subagent_tokens><tool_uses>{tools}</tool_uses>"
             f"<duration_ms>{ms}</duration_ms></usage>") if tokens is not None else ""
    return (f"<task-notification><task-id>{aid}</task-id><tool-use-id>{tu}</tool-use-id><output-file>/x</output-file>"
            f"<status>{status}</status><summary>Agent finished</summary>{usage}</task-notification>")


def asst(ts, model, blocks):
    return {"type": "assistant", "timestamp": ts, "cwd": "/work/demo-repo", "message": {"model": model, "content": blocks}}


def user(ts, content, **kw):
    return {"type": "user", "timestamp": ts, "cwd": "/work/demo-repo", "message": {"content": content}, **kw}


def main_lines() -> list[dict]:
    return [
        user("2026-01-01T00:00:00Z", "please build the thing"),
        asst("2026-01-01T00:00:05Z", "claude-opus-9", [
            {"type": "tool_use", "id": "tu1", "name": "Agent", "input": {
                "description": "Build the widget", "subagent_type": "general-purpose", "model": "sonnet",
                "run_in_background": True, "prompt": f"git worktree add ../w -b feat-widget origin/main {CANARY_PROMPT}"}},
            {"type": "tool_use", "id": "tu2", "name": "Agent", "input": {
                "description": "Review widget branch", "subagent_type": "general-purpose", "model": "opus",
                "prompt": "review origin/feat-widget"}},
            {"type": "tool_use", "id": "tu3", "name": "Agent", "input": {
                "description": "Email ops@example.org about T02", "subagent_type": "general-purpose",
                "prompt": "do it"}}]),
        user("2026-01-01T00:00:06Z", [{"type": "tool_result", "tool_use_id": "tu1",
                                       "content": [{"type": "text", "text": f"Async agent launched. agentId: {A1} (x)"}]}]),
        {"type": "queue-operation", "operation": "enqueue", "timestamp": "2026-01-01T00:10:00Z",
         "content": notif(A1, "tu1", "completed", 1000, 10, 60000)},
        {"type": "queue-operation", "operation": "enqueue", "timestamp": "2026-01-01T00:10:00Z",  # duplicate enqueue
         "content": notif(A1, "tu1", "completed", 1000, 10, 60000)},
        user("2026-01-01T00:10:01Z", notif(A1, "tu1", "completed", 1000, 10, 60000)),  # delivered copy: not counted
        asst("2026-01-01T00:11:00Z", "claude-fable-9", [
            {"type": "tool_use", "id": "tu9", "name": "SendMessage", "input": {"to": A1, "message": "one more"}}]),
        {"type": "queue-operation", "operation": "enqueue", "timestamp": "2026-01-01T00:20:00Z",
         "content": notif(A1, "tu1", "completed", 1500, 4, 30000)},
        {"type": "queue-operation", "operation": "enqueue", "timestamp": "2026-01-01T00:30:00Z",
         "content": notif(A2, "tu2", "completed", 800, 7, 20000)},
        {"type": "queue-operation", "operation": "enqueue", "timestamp": "2026-01-01T00:31:00Z",
         "content": notif(A3, "tu3", "killed")},
        asst("2026-01-01T00:32:00Z", "<synthetic>", [{"type": "text", "text": "limit"}]),
        asst("2026-01-01T00:33:00Z", "claude-opus-9", [{"type": "text", "text": "done"}]),
    ]


def sub_lines(aid: str) -> list[dict]:
    if aid == A1:
        return [user("2026-01-01T00:00:07Z", f"git worktree add ../w -b feat-widget origin/main {CANARY_PROMPT}"),
                asst("2026-01-01T00:01:00Z", "claude-sonnet-9", [{"type": "tool_use", "id": "x1", "name": "Bash", "input": {}}]),
                asst("2026-01-01T00:19:00Z", "claude-sonnet-9", [
                    {"type": "tool_use", "id": "x2", "name": "SubagentHandback",
                     "input": {"message": f"Done. Pushed commit 1a2b3c4 on branch `feat-widget`. {CANARY_REPORT}"}}])]
    if aid == A2:
        rep = 'Verdict: MERGE-WITH-FIXES\n[{"file": "a.py", "line": 3}, {"file": "b.py", "line": 9}]'
        return [user("2026-01-01T00:00:08Z", "review origin/feat-widget"),
                asst("2026-01-01T00:29:00Z", "claude-opus-9", [
                    {"type": "tool_use", "id": "y1", "name": "SubagentHandback", "input": {"message": rep}}])]
    if aid == A3:
        return [user("2026-01-01T00:00:09Z", "do it"),
                asst("2026-01-01T00:05:00Z", "claude-haiku-9", [{"type": "text", "text": "working"}])]
    # A4: a /code-review skill run: no Agent call, the brief is an isMeta turn
    return [user("2026-01-01T00:40:00Z", "Review target: `origin/main..origin/feat-widget` (3 commits)", isMeta=True),
            user("2026-01-01T00:40:01Z", [{"type": "tool_result", "tool_use_id": "z", "content": "diff"}]),
            asst("2026-01-01T00:45:00Z", "claude-opus-9", [{"type": "text", "text": "Two findings: ... BLOCK"}])]


META = {A1: {"agentType": "general-purpose", "description": "Build the widget", "toolUseId": "tu1", "model": "sonnet",
             "spawnDepth": 1},
        A2: {"agentType": "general-purpose", "description": "Review widget branch", "toolUseId": "tu2", "spawnDepth": 1},
        A3: {"agentType": "general-purpose", "description": "Email ops@example.org about T02", "toolUseId": "tu3",
             "spawnDepth": 1},
        A4: {"agentType": "general-purpose", "description": "/code-review high origin/main..", "name": "code-review",
             "spawnDepth": 1}}


def _write(p: Path, lines: list[dict]):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("".join(json.dumps(x) + "\n" for x in lines) + "not json\n", encoding="utf-8")


def write_subagents(d: Path):
    for aid in (A1, A2, A3, A4):
        _write(d / f"agent-{aid}.jsonl", sub_lines(aid))
        (d / f"agent-{aid}.meta.json").write_text(json.dumps(META[aid]), encoding="utf-8")


def raw_layout(root: Path) -> Path:
    """~/.claude/projects/<proj>/ shape. Returns the project dir."""
    proj = root / "-work-demo-repo"
    _write(proj / f"{SID}.jsonl", main_lines())
    write_subagents(proj / SID / "subagents")
    return proj


def archive_layout(root: Path, project="demo") -> Path:
    d = root / project / SID
    _write(d / f"{SID}.jsonl", main_lines())
    write_subagents(d / "subagents")
    return root


def legacy_layout(root: Path, project="demo") -> Path:
    d = root / project / SID
    _write(d / "main.jsonl", main_lines())
    write_subagents(d / "session" / "subagents")
    return root
