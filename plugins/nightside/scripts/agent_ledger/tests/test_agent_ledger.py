"""Agent ledger: extraction, merge, guard, render and the archive hook, on SYNTHETIC transcripts only."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent_ledger import archive, cli, render
from agent_ledger.extract import session_rows
from agent_ledger.guard import Guard, GuardError, check_row
from agent_ledger.ledger import apply_map, merge, read_ledger
from agent_ledger.transcripts import discover

from . import fixtures as F

PKG = Path(__file__).resolve().parents[1]


DENY = {"classes": {"person": [r"\bZebulon\b"]}}  # synthetic project deny list


def deny_file(d: Path) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    p = d / "deny.json"
    p.write_text(json.dumps(DENY))
    return p


def rows_for(path, deny=True, **kw):
    g = Guard(deny_file(Path(path).parent / "_deny")) if deny else Guard()
    rows, _ = session_rows(discover([path]), g, **kw)
    return {r["key"]: r for r in rows}


def run(path, tmp_path, *extra, ledger=None):
    led = ledger or tmp_path / "ledger.jsonl"
    deny_file(led.parent)  # found next to the ledger
    rc = cli.main(["extract", str(path), "--ledger", str(led), *extra])
    assert rc == 0
    return led


# ---------------------------------------------------------------------------------------- extraction ---
def test_raw_layout_fields(tmp_path):
    R = rows_for(F.raw_layout(tmp_path))
    a1 = R[f"{F.SID}/{F.A1}"]
    assert a1["record"] == "agent_run" and a1["schema_version"] == 1
    assert a1["description"] == "Build the widget" and a1["kind"] == "build"
    assert a1["model_requested"] == "sonnet" and a1["model_used"] == "claude-sonnet-9"
    assert a1["tokens"] == 1500                       # max across notifications (cumulative)
    assert a1["tool_uses"] == 14 and a1["duration_ms"] == 90000  # summed per segment; duplicate + delivered not counted
    assert a1["status"] == "completed" and a1["status_history"] == ["completed", "completed"]
    assert a1["resumed_count"] == 1
    assert a1["branch"] == "feat-widget" and a1["commits"] == ["1a2b3c4"]
    assert a1["launched_at"] == "2026-01-01T00:00:05Z" and a1["finished_at"] == "2026-01-01T00:19:00Z"
    assert a1["project"] == "demo-repo" and a1["launch"] == "agent_tool" and a1["node"] is None


def test_review_verdict_and_findings(tmp_path):
    a2 = rows_for(F.raw_layout(tmp_path))[f"{F.SID}/{F.A2}"]
    assert a2["kind"] == "review" and a2["verdict"] == "sent_back"
    assert a2["findings_count"] == 2 and a2["findings_basis"] == "json items"


def test_killed_without_usage(tmp_path):
    a3 = rows_for(F.raw_layout(tmp_path))[f"{F.SID}/{F.A3}"]
    assert a3["status"] == "killed" and a3["tokens"] is None and a3["duration_ms"] is None
    assert a3["tool_uses"] == 0 and "killed before any completed run" in a3["notes"]


def test_skill_review_has_a_synthetic_description(tmp_path):
    a4 = rows_for(F.raw_layout(tmp_path))[f"{F.SID}/{F.A4}"]
    assert a4["launch"] == "skill" and a4["kind"] == "review"
    assert a4["description"] == "/code-review feat-widget (skill-launched review)"
    assert a4["verdict"] == "BLOCK" and a4["findings_count"] == 2 and a4["status"] == "no-notification"
    assert a4["model_requested"] is None


def test_session_row_orchestrator_models(tmp_path):
    s = rows_for(F.raw_layout(tmp_path))[f"session/{F.SID}"]
    assert s["record"] == "session" and s["agent_runs"] == 4 and s["synthetic_messages"] == 1
    assert [g["model"] for g in s["orchestrator_models"]] == ["claude-opus-9", "claude-fable-9", "claude-opus-9"]
    assert [g["messages"] for g in s["orchestrator_models"]] == [1, 1, 1]


@pytest.mark.parametrize("layout", [F.archive_layout, F.legacy_layout])
def test_archive_layouts_match_raw(tmp_path, layout):
    raw = rows_for(F.raw_layout(tmp_path / "raw"))
    arc = rows_for(layout(tmp_path / "arc"))
    assert set(raw) == set(arc)
    for k in raw:
        a, b = dict(raw[k]), dict(arc[k])
        assert b["project"] == "demo"
        a.pop("project"), b.pop("project")
        assert a == b


def test_discover_accepts_files_and_nested_roots(tmp_path):
    F.archive_layout(tmp_path / "root")
    assert [s.session_id for s in discover([tmp_path / "root"])] == [F.SID]
    assert [s.layout for s in discover([tmp_path / "root" / "demo" / F.SID])] == ["archive"]
    proj = F.raw_layout(tmp_path / "p")
    assert [s.layout for s in discover([proj / f"{F.SID}.jsonl"])] == ["raw"]


def test_same_session_twice_is_one_set_of_rows(tmp_path):
    F.archive_layout(tmp_path / "root", "one")
    F.archive_layout(tmp_path / "root", "two")
    rows, _ = session_rows(discover([tmp_path / "root"]), Guard())
    assert len([r for r in rows if r["record"] == "agent_run"]) == 4


# --------------------------------------------------------------------------------------- privacy ---
def test_no_prompt_or_report_text_reaches_the_ledger(tmp_path):
    led = run(F.raw_layout(tmp_path), tmp_path)
    body = led.read_text()
    assert F.CANARY_PROMPT not in body and F.CANARY_REPORT not in body
    assert "please build" not in body and "one more" not in body and "Review target" not in body
    for r in read_ledger(led):
        assert "prompt" not in r and "report" not in r


def test_guard_redacts_contacts_and_fails_closed(tmp_path):
    a3 = rows_for(F.raw_layout(tmp_path))[f"{F.SID}/{F.A3}"]
    assert a3["description"] == "Email [redacted] about T02" and a3["description_redacted"] is True
    g = Guard()
    assert g.scrub("deploy to https://example.io/x now")[0] == "deploy to [redacted] now"
    assert g.scrub("token: abc123")[0] == "[redacted]"
    assert g.scrub(12) == (None, True)
    assert g.scrub("Fix camera.js drag in three.js") == ("Fix camera.js drag in three.js", False)


def test_guard_project_deny_file(tmp_path):
    py = tmp_path / "deny.py"
    py.write_text('DENY = {"person": [r"\\bZebulon\\b"], "infra": [r"\\brepo\\b"]}\n')
    assert Guard(py).scrub("Ask Zebulon about the repo")[0] == "Ask [redacted] about the [redacted]"  # all classes
    py.write_text('DENY = {"person": [r"\\bZebulon\\b"], "infra": [r"\\brepo\\b"]}\nLEDGER_SKIP = ("infra",)\n')
    assert Guard(py).scrub("Ask Zebulon about the repo")[0] == "Ask [redacted] about the repo"
    with pytest.raises(GuardError):
        Guard(py, skip=["person"])  # skipping every class fails open: refused
    js = tmp_path / "deny.json"
    js.write_text(json.dumps({"classes": {"vendor": ["Acme"]}, "allow": ["Acme Park"]}))
    g = Guard(js)
    assert g.scrub("Acme units at Acme Park")[0] == "[redacted] units at Acme Park"


@pytest.mark.parametrize("body", ['DENY = {}', 'DENY = {"person": []}', 'raise RuntimeError("x")', None])
def test_guard_refuses_a_broken_deny_file(tmp_path, body):
    p = tmp_path / "deny.py"
    if body is not None:
        p.write_text(body)
    with pytest.raises(GuardError):
        Guard(p)


def test_cli_stops_on_a_broken_deny_file(tmp_path):
    led = tmp_path / "l.jsonl"
    assert cli.main(["extract", str(F.raw_layout(tmp_path)), "--ledger", str(led), "--deny", str(tmp_path / "nope.py")]) == 2
    assert not led.exists()


def test_check_row_refuses_credentials():
    with pytest.raises(GuardError):
        check_row({"key": "k", "notes": "sk-ant-" + "x" * 30})
    check_row({"key": "k", "notes": "fine", "commits": ["1a2b3c4"]})


def test_branch_with_a_secret_shape_is_dropped(tmp_path):
    proj = F.raw_layout(tmp_path)
    f = proj / F.SID / "subagents" / f"agent-{F.A1}.jsonl"
    f.write_text(f.read_text().replace("-b feat-widget", "-b ghp_" + "A1b2" * 10))
    a1 = rows_for(proj)[f"{F.SID}/{F.A1}"]
    assert a1["branch"] is None


# ---------------------------------------------------------------------------------- merge + map ---
def test_idempotent_bytes(tmp_path):
    proj = F.raw_layout(tmp_path)
    led = run(proj, tmp_path)
    first = led.read_bytes()
    run(proj, tmp_path, ledger=led)
    assert led.read_bytes() == first


def test_merge_keeps_hand_mapping_and_curated_fields(tmp_path):
    proj = F.raw_layout(tmp_path)
    led = run(proj, tmp_path)
    rows = read_ledger(led)
    for r in rows:
        if r.get("agent_id") == F.A1:
            r.update(node="N7", workstream="widgets", kind="design", curated=["kind"])
    led.write_text("".join(json.dumps(r) + "\n" for r in rows))
    run(proj, tmp_path, ledger=led)
    a1 = next(r for r in read_ledger(led) if r.get("agent_id") == F.A1)
    assert (a1["node"], a1["workstream"], a1["kind"]) == ("N7", "widgets", "design")
    assert a1["tokens"] == 1500  # measured fields still refreshed
    assert len([r for r in read_ledger(led) if r["record"] == "agent_run"]) == 4


def test_legacy_rows_are_migrated_and_their_judgement_kept(tmp_path):
    proj = F.raw_layout(tmp_path)
    led = tmp_path / "ledger.jsonl"
    legacy = {"agent_id": F.A2, "session": F.SID, "kind": "review", "description": "Hand-named review",
              "node": "N3", "workstream": "w", "verdict": "BLOCK", "findings_count": 9,
              "findings_basis": "counted by hand", "tokens": 1, "branch": "x", "notes": "hand"}
    other = {"agent_id": "a9", "session": "other-session", "kind": "build", "description": "Kept as is"}
    led.write_text(json.dumps(legacy) + "\n" + json.dumps(other) + "\n")
    run(proj, tmp_path, ledger=led)
    R = {r["key"]: r for r in read_ledger(led)}
    a2 = R[f"{F.SID}/{F.A2}"]
    assert (a2["description"], a2["verdict"], a2["findings_count"], a2["node"]) == ("Hand-named review", "BLOCK", 9, "N3")
    assert a2["tokens"] == 800 and a2["schema_version"] == 1 and "verdict" in a2["curated"]
    assert R["other-session/a9"]["description"] == "Kept as is"  # incremental: other sessions untouched


def test_map_rules_agents_graph_and_exclusion(tmp_path):
    proj = F.raw_layout(tmp_path)
    m = tmp_path / "node_map.json"
    m.write_text(json.dumps({"rules": [{"match": "^Review", "node": "G1", "workstream": "gate"},
                                       {"match": "^Build", "exclude": True}],
                             "agents": {F.A4: {"node": "G1", "workstream": "gate"}}}))
    g = tmp_path / "graph.json"
    g.write_text(json.dumps({"nodes": [{"id": "T02"}, {"id": "G1"}]}))
    led = run(proj, tmp_path, "--map", str(m), "--graph", str(g))
    R = {r["agent_id"]: r for r in read_ledger(led) if r["record"] == "agent_run"}
    assert F.A1 not in R
    assert R[F.A2]["node"] == "G1" and R[F.A2]["node_basis"].startswith("map:rule")
    assert R[F.A4]["node_basis"] == "map:agent"
    assert R[F.A3]["node"] == "T02" and R[F.A3]["node_basis"] == "graph id in description"


def test_graph_yaml_without_pyyaml_fallback(tmp_path, monkeypatch):
    import builtins
    from agent_ledger.ledger import graph_node_ids
    y = tmp_path / "GRAPH.yaml"
    y.write_text("agents:\n  - {id: eng}\nnodes:\n  - {id: T01, title: x}\n  - id: T02\n    title: y\nphases: []\n")
    real = builtins.__import__
    monkeypatch.setattr(builtins, "__import__", lambda n, *a, **k: (_ for _ in ()).throw(ImportError()) if n == "yaml" else real(n, *a, **k))
    assert graph_node_ids(y) == ["T01", "T02"]


def test_apply_map_leaves_session_rows_alone():
    r = {"record": "session", "key": "session/x"}
    assert apply_map(dict(r), {"rules": [{"match": ".", "node": "N"}]}, []) == r


def test_render_tables(tmp_path):
    led = run(F.raw_layout(tmp_path), tmp_path)
    out = tmp_path / "LEDGER.md"
    assert render.main(led, out, "Demo ledger") == 0
    t = out.read_text()
    assert "# Demo ledger" in t and "## Orchestrator models per session" in t and "opus-9 -> fable-9" in t
    assert "| review |" in t and "sent_back 1" in t
    assert F.CANARY_PROMPT not in t and F.CANARY_REPORT not in t


def test_cli_entrypoint_runs_as_a_directory(tmp_path):
    led = tmp_path / "l.jsonl"
    r = subprocess.run([sys.executable, str(PKG), "extract", str(F.raw_layout(tmp_path)), "--ledger", str(led)],
                       capture_output=True, text=True, cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert "4 agent runs" in r.stdout and F.CANARY_PROMPT not in r.stdout


# ------------------------------------------------------------------------------------- archive hook ---
@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    for k in ("NIGHTSIDE_ARCHIVE_ROOT", "NIGHTSIDE_ARCHIVE_PROJECT", "NIGHTSIDE_ARCHIVE", "NIGHTSIDE_ARCHIVE_CONFIG"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("NIGHTSIDE_ARCHIVE_CONFIG", str(h / "no-config.json"))
    return h


def hook(payload: dict, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(PKG / "archive.py"), "--hook"], input=json.dumps(payload),
                          capture_output=True, text=True, env={**os.environ, **(env or {})}, timeout=30)


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def test_hook_copies_transcript_and_subagents(fake_home, tmp_path):
    proj = F.raw_layout(tmp_path / "claude")
    repo = tmp_path / "work" / "My Repo"
    (repo / ".git").mkdir(parents=True)
    root = fake_home / ".nightside" / "agent-archive" / "raw"
    t0 = time.monotonic()
    r = hook({"session_id": F.SID, "transcript_path": str(proj / f"{F.SID}.jsonl"), "cwd": str(repo / "sub"),
              "hook_event_name": "SessionEnd", "reason": "other"})
    assert r.returncode == 0 and time.monotonic() - t0 < 2.0
    dest = root / "my-repo" / F.SID
    assert (dest / f"{F.SID}.jsonl").read_bytes() == (proj / f"{F.SID}.jsonl").read_bytes()
    assert len(list((dest / "subagents").iterdir())) == 8
    assert _mode(root) == _mode(dest) == _mode(dest / "subagents") == 0o700
    assert _mode(dest / f"{F.SID}.jsonl") == 0o600 and _mode(dest / "subagents" / f"agent-{F.A1}.jsonl") == 0o600
    log = (root / "_logs" / "archive-hook.log").read_text()
    assert "ok SessionEnd my-repo/" in log and _mode(root / "_logs" / "archive-hook.log") == 0o600
    # incremental: nothing changed -> nothing copied; an appended line -> recopied
    hook({"session_id": F.SID, "transcript_path": str(proj / f"{F.SID}.jsonl"), "cwd": str(repo),
          "hook_event_name": "PreCompact"})
    assert "copied=0" in (root / "_logs" / "archive-hook.log").read_text().splitlines()[-1]
    with open(proj / f"{F.SID}.jsonl", "a") as f:
        f.write("{}\n")
    hook({"session_id": F.SID, "transcript_path": str(proj / f"{F.SID}.jsonl"), "cwd": str(repo),
          "hook_event_name": "PreCompact"})
    assert (dest / f"{F.SID}.jsonl").read_bytes() == (proj / f"{F.SID}.jsonl").read_bytes()
    # the archive is readable by the extractor
    assert len(rows_for(root)) == 5


def test_hook_project_slug_for_a_worktree_is_the_main_repo(fake_home, tmp_path):
    main = tmp_path / "src" / "nightside"
    (main / ".git" / "worktrees" / "plug").mkdir(parents=True)
    wt = tmp_path / "src" / "nightside-plug"
    wt.mkdir(parents=True)
    (wt / ".git").write_text(f"gitdir: {main}/.git/worktrees/plug\n")
    assert archive.project_slug(wt, {}) == "nightside"
    assert archive.project_slug(wt, {"projects": {str(wt): "Custom Name"}}) == "custom-name"
    assert archive.project_slug(tmp_path / "loose", {"default_project": "dflt"}) == "dflt"


@pytest.mark.parametrize("where", ["Documents/arch", "Library/Mobile Documents/x", "Library/CloudStorage/G/x", "repo/arch"])
def test_hook_refuses_synced_or_repo_roots(fake_home, tmp_path, where):
    proj = F.raw_layout(tmp_path / "claude")
    (fake_home / "repo" / ".git").mkdir(parents=True)
    root = fake_home / where
    r = hook({"session_id": F.SID, "transcript_path": str(proj / f"{F.SID}.jsonl"), "cwd": str(tmp_path)},
             {"NIGHTSIDE_ARCHIVE_ROOT": str(root)})
    assert r.returncode == 0 and not root.exists()
    assert "refused:" in (fake_home / ".nightside" / "logs" / "archive-hook.log").read_text()


@pytest.mark.parametrize("stdin", ["", "not json", json.dumps({"session_id": "../../etc", "transcript_path": "/etc/passwd"}),
                                   json.dumps({"session_id": F.SID, "transcript_path": "/nope/x.jsonl"})])
def test_hook_never_fails_the_session(fake_home, stdin):
    r = subprocess.run([sys.executable, str(PKG / "archive.py"), "--hook"], input=stdin, capture_output=True,
                       text=True, timeout=30)
    assert r.returncode == 0 and r.stdout == ""
    assert not (fake_home / ".nightside" / "agent-archive" / "raw" / "etc").exists()


def test_hook_can_be_disabled(fake_home, tmp_path):
    proj = F.raw_layout(tmp_path / "claude")
    r = hook({"session_id": F.SID, "transcript_path": str(proj / f"{F.SID}.jsonl"), "cwd": str(tmp_path)},
             {"NIGHTSIDE_ARCHIVE": "0"})
    assert r.returncode == 0 and not (fake_home / ".nightside").exists()


def test_sync_latest_finds_the_directory_transcripts(fake_home, tmp_path, monkeypatch):
    cwd = tmp_path / "work" / "demo"
    cwd.mkdir(parents=True)
    claude = tmp_path / "cfg"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(claude))
    pd = archive.project_dir_for(cwd)
    assert pd.parent == claude / "projects" and "/" not in pd.name and "." not in pd.name
    src = F.raw_layout(tmp_path / "x")
    pd.mkdir(parents=True)
    os.rename(src / f"{F.SID}.jsonl", pd / f"{F.SID}.jsonl")
    os.rename(src / F.SID, pd / F.SID)
    assert cli.main(["sync", "--latest", "--cwd", str(cwd)]) == 0
    assert (fake_home / ".nightside" / "agent-archive" / "raw" / "demo" / F.SID / "subagents").is_dir()


# ------------------------------------------------------------------------------- review round 1 fixes ---
def test_no_deny_file_means_kind_only_descriptions(tmp_path):
    proj = F.raw_layout(tmp_path)
    m = proj / f"{F.SID}.jsonl"
    m.write_text(m.read_text().replace("Build the widget", "Email Zara Quill about the rent terms"))
    R = rows_for(proj, deny=False)
    a1, a2, a4 = (R[f"{F.SID}/{a}"] for a in (F.A1, F.A2, F.A4))
    assert a1["description"] == "build" and a1["description_redacted"] is True
    assert a2["description"] == "review"
    assert a4["description"] == "/code-review feat-widget (skill-launched review)"  # constructed, not free text
    led = tmp_path / "solo" / "ledger.jsonl"  # no deny.json beside it
    assert cli.main(["extract", str(proj), "--ledger", str(led)]) == 0
    assert "Zara" not in led.read_text() and "rent terms" not in led.read_text()


@pytest.mark.parametrize("tail", ["mail ops@example.org now", "key sk-ant-api03-" + "Q" * 30, "see https://example.io/x"])
def test_scrub_runs_on_the_full_string_before_the_cut(tail):
    g = Guard()
    s = "x" * 150 + " " + tail
    for cut in (155, 158, 160, 163):
        out, _ = g.scrub(s, cut)
        assert out is None or ("@" not in out and "sk-ant" not in out and "example" not in out and "http" not in out)
    out, red = g.scrub("word " * 40 + "ops@example.org", 160)
    assert red and "@" not in (out or "") and (out or "").endswith("…")


def test_scrub_drops_a_token_cut_in_half():
    out, _ = Guard().scrub("alpha beta gammadeltaepsilon", 15)
    assert out == "alpha beta…"


def test_write_guards_stored_and_curated_rows(tmp_path):
    proj = F.raw_layout(tmp_path)
    led = tmp_path / "ledger.jsonl"
    stored = {"schema_version": 1, "record": "agent_run", "key": "old-s/a7", "agent_id": "a7", "session": "old-s",
              "kind": "build", "description": "Ping Zebulon at z@example.org", "notes": "token sk-ant-" + "y" * 30,
              "curated": ["description", "notes"]}
    led.write_text(json.dumps(stored) + "\n")
    run(proj, tmp_path, ledger=led)
    r = next(x for x in read_ledger(led) if x["key"] == "old-s/a7")
    assert r["description"] == "Ping [redacted] at [redacted]" and r["description_redacted"] is True
    assert r["notes"] is None or "sk-ant" not in r["notes"]
    assert "example.org" not in led.read_text() and "sk-ant" not in led.read_text()


def test_map_exclusion_drops_stored_rows_whose_transcripts_are_gone(tmp_path):
    proj = F.raw_layout(tmp_path)
    led = tmp_path / "ledger.jsonl"
    led.write_text(json.dumps({"agent_id": "a8", "session": "gone-session", "kind": "research",
                               "description": "Evaluate a stack"}) + "\n")
    m = tmp_path / "node_map.json"
    m.write_text(json.dumps({"rules": [{"match": "^Evaluate", "exclude": True}]}))
    run(proj, tmp_path, "--map", str(m), ledger=led)
    assert "gone-session/a8" not in {r["key"] for r in read_ledger(led)}


def _hook_at(root, proj, cwd):
    return hook({"session_id": F.SID, "transcript_path": str(proj / f"{F.SID}.jsonl"), "cwd": str(cwd)},
                {"NIGHTSIDE_ARCHIVE_ROOT": str(root)})


@pytest.mark.parametrize("where", ["documents/arch", "DOCUMENTS/arch", "desktop/a", "library/mobile documents/x",
                                   "Library/cloudstorage/G/x", "library/CLOUDSTORAGE/x"])
def test_hook_refuses_case_variants(fake_home, tmp_path, where):
    for d in ("Documents", "Desktop", "Library/Mobile Documents", "Library/CloudStorage"):
        (fake_home / d).mkdir(parents=True, exist_ok=True)
    proj = F.raw_layout(tmp_path / "claude")
    assert _hook_at(fake_home / where, proj, tmp_path).returncode == 0
    assert not list((fake_home / "Documents").rglob("*.jsonl")) and not list((fake_home / "Library").rglob("*.jsonl"))
    assert not list((fake_home / "Desktop").rglob("*.jsonl"))
    assert "refused:" in (fake_home / ".nightside" / "logs" / "archive-hook.log").read_text()


def test_hook_refuses_case_variant_of_a_missing_synced_folder(fake_home, tmp_path):
    proj = F.raw_layout(tmp_path / "claude")
    _hook_at(fake_home / "documents" / "arch", proj, tmp_path)
    assert not (fake_home / "documents").exists()


@pytest.mark.parametrize("kind", ["root", "ancestor"])
def test_hook_refuses_symlinks_into_synced_folders(fake_home, tmp_path, kind):
    (fake_home / "Documents").mkdir()
    proj = F.raw_layout(tmp_path / "claude")
    if kind == "root":
        (fake_home / "Documents" / "arch").mkdir()
        os.symlink(fake_home / "Documents" / "arch", fake_home / "arch-link")
        root = fake_home / "arch-link"
    else:
        os.symlink(fake_home / "Documents", fake_home / "docs-link")
        root = fake_home / "docs-link" / "arch"
    _hook_at(root, proj, tmp_path)
    assert not list((fake_home / "Documents").rglob("*.jsonl"))


def test_hook_never_follows_symlinks(fake_home, tmp_path):
    secret = tmp_path / "outside.txt"
    secret.write_text("NOT-A-TRANSCRIPT")
    proj = F.raw_layout(tmp_path / "claude")
    link = proj / "22222222-2222-4333-8444-555555555555.jsonl"
    os.symlink(secret, link)
    root = fake_home / "arch"
    hook({"session_id": link.stem, "transcript_path": str(link), "cwd": str(tmp_path / "w")},
         {"NIGHTSIDE_ARCHIVE_ROOT": str(root)})
    assert "NOT-A-TRANSCRIPT" not in "".join(p.read_text() for p in root.rglob("*") if p.is_file() and p.suffix == ".jsonl")
    # a symlinked subagent file is skipped; a pre-planted symlinked archive dir is refused, nothing written through it
    os.symlink(secret, proj / F.SID / "subagents" / "agent-a00000000000000ff.jsonl")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / "w").mkdir(parents=True, exist_ok=True)
    os.symlink(elsewhere, root / "w" / F.SID)
    _hook_at(root, proj, tmp_path / "w")
    assert not list(elsewhere.iterdir())
    os.unlink(root / "w" / F.SID)
    _hook_at(root, proj, tmp_path / "w")
    sub = root / "w" / F.SID / "subagents"
    assert sub.is_dir() and not (sub / "agent-a00000000000000ff.jsonl").exists()
    assert not any(p.is_symlink() for p in (root / "w").rglob("*"))


def test_hook_sweeps_stale_temp_files_and_reapplies_modes(fake_home, tmp_path):
    proj = F.raw_layout(tmp_path / "claude")
    root = fake_home / "arch"
    _hook_at(root, proj, tmp_path / "w")
    dest = root / "w" / F.SID
    stale = dest / f".{F.SID}.jsonl.999999.tmp"
    stale.write_text("raw bytes")
    os.chmod(dest / f"{F.SID}.jsonl", 0o644)
    os.chmod(dest, 0o755)
    _hook_at(root, proj, tmp_path / "w")
    assert not stale.exists()
    assert _mode(dest / f"{F.SID}.jsonl") == 0o600 and _mode(dest) == 0o700


def test_hook_umask_on_a_refused_root(fake_home, tmp_path):
    proj = F.raw_layout(tmp_path / "claude")
    _hook_at(fake_home / "Documents" / "x", proj, tmp_path)
    assert _mode(fake_home / ".nightside") == 0o700 and _mode(fake_home / ".nightside" / "logs") == 0o700
    assert _mode(fake_home / ".nightside" / "logs" / "archive-hook.log") == 0o600


def test_hook_never_copies_tool_results(fake_home, tmp_path):
    """tool-results/ holds raw tool output, the highest leak risk, and the ledger needs none."""
    proj = F.raw_layout(tmp_path / "claude")
    tr = proj / F.SID / "tool-results"
    tr.mkdir()
    (tr / "toolu_1.txt").write_text("RAW-TOOL-OUTPUT")
    root = fake_home / "arch"
    _hook_at(root, proj, tmp_path / "w")
    dest = root / "w" / F.SID
    assert (dest / "subagents").is_dir() and not (dest / "tool-results").exists()
    assert all("RAW-TOOL-OUTPUT" not in p.read_text() for p in dest.rglob("*") if p.is_file())


def test_shipped_deny_template_loads_and_has_no_real_names():
    t = PKG / "deny.template.json"
    g = Guard(t)
    assert g.scrub("Email EXAMPLE PERSON about the rent and the investors")[0] == \
        "Email [redacted] about the [redacted] and the [redacted]"
    body = json.loads(t.read_text())
    pats = [p for v in body["classes"].values() for p in v]
    names = [p for p in body["classes"]["person"] + body["classes"]["organisation"]]
    assert all("EXAMPLE" in p for p in names) and pats


def test_generated_notes_skip_deny_classes_but_not_the_secret_scrub(tmp_path):
    proj = F.raw_layout(tmp_path)
    led = tmp_path / "ledger.jsonl"
    infra = tmp_path / "infra-deny.json"
    infra.write_text(json.dumps({"classes": {"infra": [r"/code-review", r"\bnotification\b"]}}))
    run(proj, tmp_path, "--deny", str(infra), ledger=led)
    R = {r["agent_id"]: r for r in read_ledger(led) if r["record"] == "agent_run"}
    assert "launched via the /code-review skill" in R[F.A4]["notes"]          # templated note kept verbatim
    assert "no usage data in any task-notification" in R[F.A4]["notes"]
    rows = read_ledger(led)
    for r in rows:
        if r.get("agent_id") == F.A1:
            r["notes"] = "mail ops@example.org key sk-ant-" + "z" * 30
    led.write_text("".join(json.dumps(r) + "\n" for r in rows))
    run(proj, tmp_path, "--deny", str(infra), ledger=led)
    assert "example.org" not in led.read_text() and "sk-ant" not in led.read_text()


def test_verdict_and_findings_phrasings():
    from agent_ledger.extract import findings_of, verdict_of
    cases = ["Verdict: KEEP. I found no blocking issues.", "**Verdict: SEND BACK.** One place is removed.",
             "SEND BACK (two small fixes). All pass.", "KEEP. No blocking issues", "Verdict: MERGE. Done."]
    assert [verdict_of(c) for c in cases] == ["kept", "sent_back", "sent_back", "kept", "MERGE"]
    assert verdict_of("We should keep the cache. Nothing else.") is None
    assert findings_of("Verdict: SEND BACK.\n\nFindings:\n\n1. **a.py:1 blocking.** x\n2. y\n3. z\n") == (3, "findings list")
    assert findings_of("**Verdict: SEND BACK.**\n\n**Findings**\n1. **Blocking.** x\n2. y\n") == (2, "findings list")
    assert findings_of("Verdict: KEEP. 10 findings in total.")[0] == 10
    assert findings_of("Verdict: KEEP.\n\n1. Places are correct.\n2. Flags fine.\n")[0] is None


def test_findings_prior_closed_not_counted():
    from agent_ledger.extract import findings_of
    r = "**Verdict: MERGE.** All 5 findings are closed.\n\n1. **Closed.** a\n2. **Closed.** b\n\n**New findings:**\n- **LOW:** esc\n- **INFO:** docs stale\n"
    assert findings_of(r) == (1, "findings list")
    assert findings_of("Verdict: KEEP. 3 findings fixed since last round.")[0] is None


def test_keep_with_findings_list_and_low_line():
    from agent_ledger.extract import findings_of
    r = "Verdict: KEEP. Nothing blocking.\n\nChecks:\n1. a\n2. b\n\nNon-blocking findings:\n1. x\n2. y\n3. z\n\nTests: ok\n"
    assert findings_of(r) == (3, "findings list")
    assert findings_of("Verdict: KEEP.\n\nFindings, all non-blocking:\n1. x\n2. y\n")[0] == 2
    assert findings_of("Verdict: KEEP.\n\n1. ok\n2. ok\n\nLow, non-blocking: hud.js:226 counts roles.\n") == (1, "low-severity line")
    assert findings_of("Verdict: KEEP. Fine.\n\n1. ok\n")[0] is None


def test_merge_with_fixes_is_sent_back():
    from agent_ledger.extract import verdict_of
    assert verdict_of("**Verdict: MERGE-WITH-FIXES.** x") == "sent_back"
    assert verdict_of("Re-review: merge with fixes. Two findings.") == "sent_back"
    assert verdict_of("Verdict: MERGE. ok") == "MERGE"
