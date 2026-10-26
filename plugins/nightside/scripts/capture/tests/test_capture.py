"""Capture and the privacy gate (G1). SYNTHETIC fixtures only: invented ids, paths and canaries.
conftest.py isolates HOME and every Nightside root per test and refuses the network in-process and in children."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from capture import allowlist as A
from capture import audit as G
from capture import common as C
from capture import consent as K
from capture import hook as H
from capture import planet as P
from capture import rich as R
from capture import surveyor as S

HERE = Path(__file__).resolve()
CAP = HERE.parents[1]                       # scripts/capture
SCRIPTS = HERE.parents[2]
PLUGIN = HERE.parents[3]                    # plugin/nightside
REPO = HERE.parents[5]
SID = "11111111-2222-4333-8444-555555555555"
SID2 = "66666666-7777-4888-9999-000000000000"
T0 = 1_800_000_000.0


@pytest.fixture
def env(tmp_path):
    proj = tmp_path / "work" / "demo-project"
    proj.mkdir(parents=True)
    return {"root": Path(os.environ["NIGHTSIDE_CAPTURE_ROOT"]), "cfg": Path(os.environ["NIGHTSIDE_CAPTURE_CONFIG"]),
            "proj": proj, "tmp": tmp_path}


def feed(payloads, cfg=None):
    pids = set()
    for d, t in payloads:
        r = H.handle(d, cfg, now=t)
        if r:
            pids.add(r["pid"])
    return pids


def simple_session(cwd: str, sid=SID, t0=T0):
    b = {"session_id": sid, "cwd": cwd}
    return [
        (dict(b, hook_event_name="SessionStart", source="startup", model="claude-opus-9-9"), t0),
        (dict(b, hook_event_name="UserPromptSubmit", prompt="CANARY-P"), t0 + 10),
        (dict(b, hook_event_name="PostToolUse", tool_name="Read", tool_input={"file_path": "/x"}, duration_ms=5),
         t0 + 20),
        (dict(b, hook_event_name="SubagentStart", agent_id="a01", agent_type="Explore"), t0 + 30),
        (dict(b, hook_event_name="PostToolUse", agent_id="a01", agent_type="Explore", tool_name="Grep",
              duration_ms=7), t0 + 40),
        (dict(b, hook_event_name="SubagentStop", agent_id="a01", agent_type="Explore",
              last_assistant_message="CANARY-L"), t0 + 150),
        (dict(b, hook_event_name="PostToolUse", tool_name="Write", duration_ms=3), t0 + 160),
        (dict(b, hook_event_name="PostToolUseFailure", tool_name="Edit", error="CANARY-E", duration_ms=1), t0 + 170),
        (dict(b, hook_event_name="PostToolUse", tool_name="mcp__github__create_pull_request", duration_ms=9),
         t0 + 180),
        (dict(b, hook_event_name="UserPromptSubmit", prompt="again"), t0 + 200),
        (dict(b, hook_event_name="SessionEnd", reason="prompt_input_exit"), t0 + 300),
    ]


def spool_text(root: Path) -> str:
    return "".join(f.read_text() for f in (root / "spool").rglob("*.jsonl"))


def run_py(script: Path, *args, stdin=None, env=None):
    return subprocess.run([sys.executable, str(script), *args], input=stdin, capture_output=True, text=True,
                          timeout=60, env=env or os.environ.copy())


# ------------------------------------------------------------------------------------------------ hook ---
def test_hook_records_only_allowed_keys_and_hashes_names(env):
    pids = feed(G.synthetic_session(SID, str(env["proj"]), T0))
    assert len(pids) == 1
    lines = [json.loads(x) for x in spool_text(env["root"]).splitlines()]
    assert lines and all(set(x) <= H.SPOOL_KEYS for x in lines)
    raw = spool_text(env["root"]).lower()
    for c in G.CANARY_WORDS + ["demo-project", str(env["tmp"]).lower()]:
        assert c.lower() not in raw
    for name in ("claude_ai_google_drive", "github", "plugin_canary_notes", "nightside:ledger-analyst"):
        assert name not in raw                                   # hashed at write time
    assert {x["ev"] for x in lines} <= set(H.EVENTS)            # Notification is not recorded
    assert all(re.fullmatch(r"[0-9a-f]{16}", x["s"]) for x in lines)
    tools = {x.get("tool") for x in lines if "tool" in x}
    assert {"Bash", "Read", "Grep", "Write", "other"} <= tools
    assert all(t in ("Bash", "Read", "Grep", "Write", "Agent", "other") or re.fullmatch(r"mcp__[0-9a-f]{8}__\w+", t)
               for t in tools)
    ats = {x.get("at") for x in lines if "at" in x}
    assert "Explore" in ats and "other" in ats and any(re.fullmatch(r"custom-[0-9a-f]{6}", a) for a in ats)
    assert {x.get("model") for x in lines if "model" in x} == {"claude-opus-5-5", "other"}
    names = C.read_names(env["root"])                            # the owner's local reverse map
    assert set(names.values()) >= {"claude_ai_Google_Drive", "github", "nightside:ledger-analyst"}


def test_spool_modes_and_index(env):
    feed(simple_session(str(env["proj"])))
    root = env["root"]
    for p in [root, *root.rglob("*")]:
        mode = stat.S_IMODE(os.lstat(p).st_mode)
        assert mode == (0o700 if p.is_dir() else 0o600), p
    idx = C.read_index(root)
    assert [v["name"] for v in idx.values()] == ["demo-project"]   # the slug lives only in the local index


def test_project_id_is_keyed_and_stable(env):
    feed(simple_session(str(env["proj"])))
    feed(simple_session(str(env["proj"] / "sub"), sid=SID2))       # a subdir of a non-repo is its own project
    pid = S.projects(env["root"])
    key = C.install_key(env["root"])
    unkeyed = hashlib.sha256(str(env["proj"]).encode()).hexdigest()[:16]
    assert C.kh(key, "project", str(env["proj"])) in pid and unkeyed not in pid


def test_worktrees_of_one_repo_are_one_project(env):
    repo = env["tmp"] / "repo"
    (repo / ".git" / "worktrees" / "wt").mkdir(parents=True)
    wt = env["tmp"] / "wt"
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {repo}/.git/worktrees/wt\n")
    feed(simple_session(str(repo)))
    feed(simple_session(str(wt / "src"), sid=SID2))
    assert len(S.projects(env["root"])) == 1


@pytest.mark.parametrize("stdin", ["", "garbage{", "[]", json.dumps({"hook_event_name": "PostToolUse"}),
                                   json.dumps({"hook_event_name": "Nope", "session_id": SID}),
                                   json.dumps({"hook_event_name": "PostToolUse", "session_id": "../../x"})])
def test_hook_cli_never_fails_or_prints(env, stdin):
    r = run_py(CAP / "hook.py", stdin=stdin)
    assert r.returncode == 0 and r.stdout == "" and r.stderr == ""
    assert not list((env["root"] / "spool").rglob("*.jsonl")) if (env["root"] / "spool").exists() else True


def test_hook_refuses_root_in_repo_or_synced(env, monkeypatch):
    repo = env["tmp"] / "somerepo"
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setenv("NIGHTSIDE_CAPTURE_ROOT", str(repo / "spool"))
    r = run_py(CAP / "hook.py", stdin=json.dumps(simple_session(str(env["proj"]))[0][0]))
    assert r.returncode == 0 and r.stdout == ""
    assert not (repo / "spool").exists()
    with pytest.raises(C.Refused):
        C.check_root(Path.home() / "Library" / "Mobile Documents" / "x" / "capture")
    with pytest.raises(C.Refused):
        C.check_root(Path.home() / "Documents" / "capture")


def test_disabled(env, monkeypatch):
    monkeypatch.setenv("NIGHTSIDE_CAPTURE", "0")
    assert feed(simple_session(str(env["proj"]))) == set()
    assert not env["root"].exists()


def test_hooks_json():
    h = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]
    have = {ev for ev, groups in h.items() for g in groups for x in g["hooks"] if "capture/hook.py" in x["command"]}
    assert have == set(H.EVENTS)
    for ev, groups in h.items():
        for g in groups:
            assert "matcher" not in g                           # every tool, every agent type
            for x in g["hooks"]:
                assert x["type"] == "command" and x["timeout"] <= 30
                if "capture/hook.py" in x["command"]:
                    assert x.get("async", False) is (ev != "SessionEnd")
                    assert x["timeout"] <= 10
                script = re.search(r"\$\{CLAUDE_PLUGIN_ROOT\}/([^\"]+\.py)", x["command"]).group(1)
                assert (PLUGIN / script).is_file()


# --------------------------------------------------------------------------------------------- the key ---
@pytest.mark.parametrize("content", [b"", b"abc", b"0" * 63, b"0" * 63 + b"\n", b"g" * 64, b"0" * 65])
def test_corrupt_key_fails_closed(env, content):
    C.ensure_root(env["root"])
    (env["root"] / "key").write_bytes(content)
    with pytest.raises(C.Refused):
        C.install_key(env["root"])
    with pytest.raises(C.Refused):
        H.handle(simple_session(str(env["proj"]))[0][0])
    r = run_py(CAP / "hook.py", stdin=json.dumps(simple_session(str(env["proj"]))[0][0]))
    assert r.returncode == 0 and r.stdout == ""
    assert not (env["root"] / "spool").exists()                  # nothing recorded with a bad key
    assert "key" in (env["root"] / "_logs" / "capture-hook.log").read_text()
    assert (env["root"] / "key").read_bytes() == content         # never silently replaced


def test_kh_refuses_a_short_key():
    for k in (b"", b"x" * 31, "x" * 32):
        with pytest.raises(C.Refused):
            C.kh(k, "project", "x")


def test_concurrent_key_creators_agree(env):
    code = ("import sys; sys.path.insert(0, sys.argv[1]); from pathlib import Path; from capture import common as C;"
            "print(C.install_key(Path(sys.argv[2])).hex())")
    procs = [subprocess.Popen([sys.executable, "-c", code, str(SCRIPTS), str(env["root"])], stdout=subprocess.PIPE,
                              text=True) for _ in range(12)]
    keys = {p.communicate(timeout=60)[0].strip() for p in procs}
    assert len(keys) == 1 and re.fullmatch(r"[0-9a-f]{64}", keys.pop())
    assert not [f for f in env["root"].iterdir() if f.name.startswith(".key.")]   # no temp left behind


def test_concurrent_index_updates_keep_every_entry(env):
    C.ensure_root(env["root"])
    code = ("import sys; sys.path.insert(0, sys.argv[1]); from pathlib import Path; from capture import common as C;"
            "[C.note_project(Path(sys.argv[2]), '%016x' % (int(sys.argv[3]) * 1000 + i), 'p') for i in range(20)]")
    procs = [subprocess.Popen([sys.executable, "-c", code, str(SCRIPTS), str(env["root"]), str(n)])
             for n in range(8)]
    assert all(p.wait(timeout=60) == 0 for p in procs)
    assert len(C.read_index(env["root"])) == 160


# -------------------------------------------------------------------------------------------- surveyor ---
def test_schema_copy_is_the_v2_manifest_schema():
    """The schema is a byte copy of the server's; here we pin its identity (the server rejects anything else)."""
    sch = json.loads((CAP / "workflow_manifest.schema.json").read_bytes())
    assert sch["$id"] == "nightside/workflow-manifest/2" and sch["additionalProperties"] is False


def test_manifest_numbers_and_shape(env):
    feed(simple_session(str(env["proj"])))
    feed(simple_session(str(env["proj"]), sid=SID2, t0=T0 + 7200))
    pid = S.projects(env["root"])[0]
    key = C.install_key(env["root"])
    m = S.survey(env["root"], pid, C.load_config())
    assert m["graph_shape"] == "orchestrator+subagents" and m["category"] == "unclassified"
    assert m["runs"] == {"count": 2, "first_at": "2027-01-15T08:00:00Z", "last_at": "2027-01-15T10:05:00Z",
                         "total_minutes": 10.0}
    h = C.kh(key, "server", "github", 8)
    assert m["tools"] == {"Edit": 2, "Grep": 2, "Read": 2, "Write": 2, f"mcp-{h}": 2}
    assert m["mcp_servers"] == [f"srv-{h}"]
    assert m["outcomes"] == {"files_written": 2, "prs": 2, "deploys": 0, "artifacts": 0}
    orch = [a for a in m["agents"] if a["role"] == "orchestrator"]
    assert orch == [{"role": "orchestrator", "model_tier": "opus", "turns": 4, "minutes": 10.0}]
    assert {"role": "Explore", "model_tier": "other", "turns": 2, "minutes": 4.0} in m["agents"]
    assert m["privacy_tier"] == "metadata" and "project_name" not in m and "summary" not in m
    assert A.check_envelope(A.envelope(m, "private"))
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(m, json.loads((CAP / "workflow_manifest.schema.json").read_text()))


def test_survey_is_deterministic_and_incremental(env):
    feed(simple_session(str(env["proj"])))
    pid = S.projects(env["root"])[0]
    a = S.survey_to_outbox(env["root"], pid, C.load_config()).read_bytes()
    summary = env["root"] / "sessions" / pid
    assert len(list(summary.glob("*.json"))) == 1              # the closed session was summarized
    b = S.survey_to_outbox(env["root"], pid, C.load_config()).read_bytes()
    assert a == b


def test_tiers_visibility_and_chosen_name(env):
    feed(simple_session(str(env["proj"])))
    feed([(dict(simple_session(str(env["proj"]))[3][0], agent_type="deal-desk-reviewer", agent_id="a02"), T0 + 31)])
    pid = S.projects(env["root"])[0]
    cfg = C.load_config()
    K.set_tier(cfg, "rich")
    m = S.survey(env["root"], pid, cfg)                      # default visibility is private: tier forced down
    assert m["privacy_tier"] == "metadata" and "project_name" not in m
    K.set_visibility(cfg, "public", pid)
    m = S.survey(env["root"], pid, cfg)
    assert m["privacy_tier"] == "rich" and "project_name" not in m   # never the repo slug unprompted
    assert "deal-desk-reviewer" not in json.dumps(m) and any(
        re.fullmatch(r"custom-[0-9a-f]{6}", a["role"]) for a in m["agents"])
    assert "github" not in json.dumps(m) and any(re.fullmatch(r"mcp__[0-9a-f]{8}__create_pull_request", t)
                                                 for t in m["tools"])
    K.set_project_name(cfg, pid, "Demo Project")
    m = S.survey(env["root"], pid, cfg)
    assert m["project_name"] == "Demo Project"
    A.check_envelope(A.envelope(m, "public"))
    with pytest.raises(A.Rejected):
        A.check_envelope(A.envelope(m, "private"))
    with pytest.raises(ValueError):
        K.set_project_name(cfg, pid, "me@example.org")


def test_ledger_rows_merge_without_text(env):
    feed(simple_session(str(env["proj"])))
    led = env["tmp"] / "ledger.jsonl"
    rows = [{"agent_id": "a01", "session": SID, "subagent_type": "Explore", "model_used": "claude-sonnet-9",
             "description": "CANARY-DESC email x@example.org", "notes": "CANARY-NOTE", "duration_ms": 1,
             "launched_at": "2027-01-15T08:00:30Z", "finished_at": "2027-01-15T08:02:30Z"},
            {"agent_id": "a99", "session": "old-session", "subagent_type": "general-purpose",
             "model_used": "claude-haiku-9", "description": "CANARY-DESC", "duration_ms": 60000,
             "launched_at": "2026-12-01T10:00:00.000Z", "finished_at": "2026-12-01T10:01:00.000Z"},
            {"agent_id": "a98", "session": "old-session", "subagent_type": "acme-deal-bot",
             "model_used": "claude-opus-9", "launched_at": "2026-12-01T10:00:30Z",
             "finished_at": "2026-12-01T10:02:00Z"},
            {"record": "session", "session": SID, "agent_id": "x"}]
    led.write_text("\n".join(json.dumps(r) for r in rows) + "\nnot json\n")
    pid = S.projects(env["root"])[0]
    m = S.survey(env["root"], pid, C.load_config(), ledger=led)
    assert {"role": "Explore", "model_tier": "sonnet", "turns": 1, "minutes": 2.0} in m["agents"]
    assert {"role": "general-purpose", "model_tier": "haiku", "turns": 1, "minutes": 1.0} in m["agents"]
    assert m["runs"]["count"] == 2 and m["runs"]["first_at"] == "2026-12-01T10:00:00Z"
    assert m["runs"]["total_minutes"] == 5.0 + 2.0              # 5 min session + the ledger runs' 2-min union
    assert "CANARY" not in json.dumps(m) and "example.org" not in json.dumps(m) and "acme" not in json.dumps(m)


def test_ledger_path_found_from_worktree(env):
    (env["proj"] / ".git").mkdir()
    (env["proj"] / "docs" / "agents").mkdir(parents=True)
    (env["proj"] / "docs" / "agents" / "ledger.jsonl").write_text("")
    assert S.ledger_path(env["proj"] / "docs") == env["proj"] / "docs" / "agents" / "ledger.jsonl"
    assert S.ledger_path(env["tmp"]) is None


def test_session_end_only_closes_and_next_start_surveys(env, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(env["proj"]))
    sess = simple_session(str(env["proj"]))
    for d, _ in sess[:-1]:
        assert run_py(CAP / "hook.py", stdin=json.dumps(d)).returncode == 0
    ob = list((env["root"] / "outbox").glob("*.json"))
    assert len(ob) == 1 and stat.S_IMODE(os.lstat(ob[0]).st_mode) == 0o600   # from this session's SessionStart
    before = (ob[0].read_bytes(), ob[0].stat().st_mtime_ns)
    t = time.monotonic()
    assert run_py(CAP / "hook.py", stdin=json.dumps(sess[-1][0])).returncode == 0
    assert time.monotonic() - t < 5
    assert (ob[0].read_bytes(), ob[0].stat().st_mtime_ns) == before          # SessionEnd did not survey
    assert not (env["root"] / "sessions").exists()
    start2 = dict(sess[0][0], session_id=SID2)
    assert run_py(CAP / "hook.py", stdin=json.dumps(start2)).returncode == 0  # next session: deferred survey
    m = json.loads(ob[0].read_text())
    A.check_manifest(m)
    assert m["runs"]["count"] == 2 and m["tools"]["Read"] == 1
    assert len(list((env["root"] / "sessions").rglob("*.json"))) == 1


def test_retention_keeps_history_as_summaries(env):
    feed(simple_session(str(env["proj"])))
    feed(simple_session(str(env["proj"]), sid=SID2, t0=T0 + 7200))
    pid = S.projects(env["root"])[0]
    cfg = C.load_config()
    m0 = S.survey(env["root"], pid, cfg)
    old = time.time() - 40 * 86400
    files = sorted((env["root"] / "spool" / pid).glob("*.jsonl"))
    os.utime(files[0], (old, old))
    r = S.retention(env["root"], cfg)
    assert r["aged"] == 1 and len(list((env["root"] / "spool" / pid).glob("*.jsonl"))) == 1
    assert S.survey(env["root"], pid, cfg) == m0                # the deleted spool lives on as its summary


def _files(root, sub):
    return sorted(p for p in (root / sub).rglob("*") if p.is_file()) if (root / sub).exists() else []


def test_size_cap_evicts_only_closed_summarized_spool_oldest_first(env):
    for i in range(6):
        feed(simple_session(str(env["proj"]), sid=f"{i:08d}-2222-4333-8444-555555555555", t0=T0 + i * 7200))
    pid = S.projects(env["root"])[0]
    files = sorted((env["root"] / "spool" / pid).glob("*.jsonl"), key=lambda f: f.name)
    for i, f in enumerate(files):
        os.utime(f, (T0 + i, T0 + i))
    cfg = C.load_config()
    m0 = S.survey(env["root"], pid, cfg)
    spool_bytes = sum(f.stat().st_size for f in files)
    cap_mb = (sum(p.stat().st_size for p in _files(env["root"], "sessions")) + spool_bytes // 2) / (1 << 20)
    r = S.retention(env["root"], dict(cfg, max_capture_mb=cap_mb))
    assert r["size"] >= 1 and not r["over_cap"]
    gone = [f for f in files if not f.exists()]
    assert gone == files[:len(gone)]                              # oldest first
    assert len(_files(env["root"], "sessions")) == 6               # no summary deleted
    assert S.survey(env["root"], pid, cfg) == m0                   # nothing counted was lost


def test_size_cap_never_touches_an_open_session_or_a_summary(env):
    sess = simple_session(str(env["proj"]))
    feed(sess[:-1])                                                # open: no SessionEnd, idle one hour
    feed(simple_session(str(env["proj"]), sid=SID2, t0=T0 + 7200))
    pid = S.projects(env["root"])[0]
    open_f = env["root"] / "spool" / pid / f"{C.kh(C.install_key(env['root']), 'session', SID)}.jsonl"
    hour_ago = time.time() - 3600
    os.utime(open_f, (hour_ago, hour_ago))
    r = S.retention(env["root"], dict(C.load_config(), max_capture_mb=0.0001))
    assert open_f.exists() and r["over_cap"]                       # still over: logged, not forced
    assert len(_files(env["root"], "sessions")) == 1               # the closed session's summary survives
    assert "still over max_capture_mb" in (env["root"] / "_logs" / "capture-hook.log").read_text()


def test_evicted_session_that_resumes_keeps_its_history(env):
    sess = simple_session(str(env["proj"]))
    feed(sess)
    pid = S.projects(env["root"])[0]
    cfg = C.load_config()
    S.retention(env["root"], dict(cfg, max_capture_mb=0.0001))     # closed + summarized: spool evicted
    assert not _files(env["root"], "spool") or not list((env["root"] / "spool" / pid).glob("*.jsonl"))
    feed([(dict(sess[2][0]), T0 + 400), (dict(sess[-1][0]), T0 + 500)])   # resumed: same session id
    m = S.survey(env["root"], pid, cfg)
    assert m["runs"]["count"] == 1 and m["tools"]["Read"] == 2 and m["runs"]["total_minutes"] == round(500 / 60, 1)


def test_summary_age_retention(env):
    feed(simple_session(str(env["proj"])))
    pid = S.projects(env["root"])[0]
    cfg = C.load_config()
    S.retention(env["root"], dict(cfg, max_capture_mb=0.0001))     # spool evicted, summary kept
    old = time.time() - 400 * 86400
    for f in _files(env["root"], "sessions"):
        os.utime(f, (old, old))
    r = S.retention(env["root"], cfg)
    assert r["summaries_aged"] == 1 and S.survey(env["root"], pid, cfg)["runs"]["count"] == 0


class _Crash(BaseException):
    """A process dying mid-step (not an OSError the code may catch)."""


def _closed_session(env):
    sess = simple_session(str(env["proj"]))
    feed(sess)
    pid = S.projects(env["root"])[0]
    cfg = C.load_config()
    m0 = S.survey(env["root"], pid, cfg)
    assert {k: m0["tools"][k] for k in ("Read", "Grep", "Write", "Edit")} == {"Read": 1, "Grep": 1, "Write": 1,
                                                                             "Edit": 1}
    return sess, pid, cfg, m0, dict(cfg, max_capture_mb=0.0001)


def _spool(env, pid):
    return list((env["root"] / "spool" / pid).glob("*.jsonl"))


def _fail_spool_unlink(monkeypatch, exc):
    real = Path.unlink

    def unlink(self, *a, **k):
        if self.suffix == ".jsonl":
            raise exc
        return real(self, *a, **k)
    monkeypatch.setattr(Path, "unlink", unlink)


def test_failed_unlink_mid_eviction_never_double_counts(env, monkeypatch):
    _sess, pid, cfg, m0, tiny = _closed_session(env)
    with monkeypatch.context() as mp:
        _fail_spool_unlink(mp, OSError("busy"))
        for _ in range(3):                                         # fold record written, unlink fails, re-run
            r = S.retention(env["root"], tiny)
            assert r["size"] == 0 and len(_spool(env, pid)) == 1
            assert S.survey(env["root"], pid, cfg) == m0           # P, never 2P (was Read 1 -> 2)
    assert S.retention(env["root"], tiny)["size"] == 1 and not _spool(env, pid)   # converges once unlink works
    assert S.survey(env["root"], pid, cfg) == m0


def test_crash_between_fold_and_unlink_counts_once(env, monkeypatch):
    sess, pid, cfg, m0, tiny = _closed_session(env)
    with monkeypatch.context() as mp, pytest.raises(_Crash):
        _fail_spool_unlink(mp, _Crash())
        S.retention(env["root"], tiny)
    assert len(_spool(env, pid)) == 1 and S.survey(env["root"], pid, cfg) == m0
    feed([(dict(sess[2][0]), T0 + 400)])                           # resumed into the SAME surviving file
    assert S.survey(env["root"], pid, cfg)["tools"]["Read"] == 2   # only the new line is added
    feed([(dict(sess[-1][0]), T0 + 500)])
    S.retention(env["root"], tiny)
    assert not _spool(env, pid) and S.survey(env["root"], pid, cfg)["tools"]["Read"] == 2


def test_crash_after_unlink_before_final_record_counts_once(env, monkeypatch):
    sess, pid, cfg, m0, tiny = _closed_session(env)
    real = C.atomic_write

    def aw(p, data):
        rec = json.loads(data)
        if isinstance(rec, dict) and rec.get("spool_size") == 0 and "folded" in rec:
            raise _Crash()                                          # the file is gone, the record still says folded
        return real(p, data)
    with monkeypatch.context() as mp, pytest.raises(_Crash):
        mp.setattr(C, "atomic_write", aw)
        S.retention(env["root"], tiny)
    assert not _spool(env, pid) and S.survey(env["root"], pid, cfg) == m0
    feed([(dict(sess[2][0]), T0 + 400), (dict(sess[-1][0]), T0 + 500)])   # resumed: a NEW file
    assert S.survey(env["root"], pid, cfg)["tools"]["Read"] == 2
    S.retention(env["root"], tiny)
    assert S.survey(env["root"], pid, cfg)["tools"]["Read"] == 2


def test_concurrent_retention_converges_to_one_count(env, monkeypatch):
    _sess, pid, cfg, m0, tiny = _closed_session(env)
    out, errs = [], []
    real = Path.unlink

    def slow_unlink(self, *a, **k):                                # widen the fold -> unlink window
        if self.suffix == ".jsonl":
            time.sleep(0.2)
        return real(self, *a, **k)
    monkeypatch.setattr(Path, "unlink", slow_unlink)

    def run():
        try:
            out.append(S.retention(env["root"], tiny))
        except BaseException as e:  # noqa: BLE001
            errs.append(e)
    ts = [threading.Thread(target=run) for _ in range(6)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errs and sum(r["size"] for r in out) == 1 and not _spool(env, pid)
    for _ in range(2):
        assert S.survey(env["root"], pid, cfg) == m0
        S.retention(env["root"], tiny)


def test_held_spool_lock_skips_retention_and_still_surveys(env):
    _sess, pid, cfg, m0, tiny = _closed_session(env)
    with C.try_lock(env["root"]) as held:
        assert held
        t = time.monotonic()
        r = S.retention(env["root"], tiny, lock_wait=0.2)
        assert r["skipped"] and time.monotonic() - t < 2 and len(_spool(env, pid)) == 1
        assert S.build_manifest(S.load_partials(env["root"], pid), [], C.install_key(env["root"]), pid, cfg) == m0
    assert S.retention(env["root"], tiny)["size"] == 1


def test_session_resumed_after_session_end_is_open_and_not_evicted(env):
    sess, pid, cfg, _m0, tiny = _closed_session(env)
    feed([(dict(sess[0][0], source="resume"), T0 + 400), (dict(sess[2][0]), T0 + 410)])   # resumed, still live
    s = C.kh(C.install_key(env["root"]), "session", SID)
    assert S.load_partials(env["root"], pid)[s]["closed"] is False
    r = S.retention(env["root"], tiny)
    assert r["size"] == 0 and r["over_cap"] and len(_spool(env, pid)) == 1
    assert S.survey(env["root"], pid, cfg)["tools"]["Read"] == 2


def test_lines_appended_during_eviction_are_kept_and_counted(env, monkeypatch):
    sess, pid, cfg, _m0, tiny = _closed_session(env)
    real = C.atomic_write

    def aw(p, data):
        real(p, data)
        rec = json.loads(data)
        if isinstance(rec, dict) and rec.get("folded"):           # a hook appends between the fold and the unlink
            monkeypatch.setattr(C, "atomic_write", real)
            feed([(dict(sess[2][0]), T0 + 400)])
    monkeypatch.setattr(C, "atomic_write", aw)
    r = S.retention(env["root"], tiny)
    assert r["size"] == 0 and len(_spool(env, pid)) == 1           # skipped: the file grew after it was counted
    assert S.survey(env["root"], pid, cfg)["tools"]["Read"] == 2
    S.retention(env["root"], tiny)
    assert S.survey(env["root"], pid, cfg)["tools"]["Read"] == 2


def test_reads_are_capped_newest_first(env, monkeypatch):
    for i in range(3):
        feed(simple_session(str(env["proj"]), sid=f"{i:08d}-2222-4333-8444-555555555555", t0=T0 + i * 7200))
    pid = S.projects(env["root"])[0]
    files = sorted((env["root"] / "spool" / pid).glob("*.jsonl"), key=lambda f: f.name)
    for i, f in enumerate(files):
        os.utime(f, (T0 + i, T0 + i))
    monkeypatch.setattr(S, "MAX_READ_BYTES", files[0].stat().st_size + 10)
    ev = S.read_spool(env["root"], pid)
    assert {e["s"] for e in ev} == {files[-1].stem}             # only the newest file fits


# ---------------------------------------------------------------------------------------- consent / CLI ---
def test_preview_saves_exact_bytes_and_confirm_uses_them(env):
    feed(simple_session(str(env["proj"])))
    cfg = C.load_config()
    items = K.preview(env["root"], cfg)
    assert len(items) == 1 and "rejected" not in items[0]
    it = items[0]
    saved = env["root"] / "outbox" / f"{it['project_id']}.envelope"
    assert saved.read_bytes() == it["bytes"] and stat.S_IMODE(os.lstat(saved).st_mode) == 0o600
    assert hashlib.sha256(it["bytes"]).hexdigest() == it["sha256"]
    text = K.render(items)
    assert it["bytes"].decode() in text.splitlines() and "Nothing left this machine" in text
    assert "local legend" in text and "github" in text and "github" not in it["bytes"].decode()
    feed([(dict(simple_session(str(env["proj"]))[2][0]), T0 + 400)])  # live session keeps working after preview
    rc, msg = K.confirm(K.saved(env["root"]), it["sha256"][:16])
    assert rc == 0 and "not enabled" in msg and str(len(it["bytes"])) in msg
    assert K.confirm(K.saved(env["root"]), "0" * 16)[0] == 3
    assert K.confirm(K.saved(env["root"]), "zz")[0] == 2
    K.preview(env["root"], cfg)                                  # a new preview replaces the saved bytes
    assert K.confirm(K.saved(env["root"]), it["sha256"][:16])[0] == 3


def test_tampered_saved_envelope_is_refused(env):
    feed(simple_session(str(env["proj"])))
    it = K.preview(env["root"], C.load_config())[0]
    p = env["root"] / "outbox" / f"{it['project_id']}.envelope"
    p.write_bytes(it["bytes"].replace(b'"user_id":"local"', b'"user_id":"me@example.org"'))
    assert "rejected" in K.saved(env["root"])[0]
    assert K.confirm(K.saved(env["root"]), hashlib.sha256(p.read_bytes()).hexdigest())[0] == 3


def run_planet(*args, stdin=None):
    return run_py(CAP / "planet.py", *args, stdin=stdin)


def test_planet_cli(env, monkeypatch):
    monkeypatch.chdir(env["proj"])
    feed(simple_session(str(env["proj"])))
    for sub in ("invite", "open"):
        r = run_planet(sub)
        assert r.returncode == 0 and "not available from the plugin yet" in r.stdout
    assert run_planet("name", "Night", "Owl").returncode == 0
    assert run_planet("name", "me@example.org").returncode == 2
    assert run_planet("privacy", "rich").returncode == 0
    assert run_planet("privacy", "public", "--name", "Demo Project").returncode == 0
    assert run_planet("privacy", "public", "--name", "x@example.org").returncode == 2
    cfg = json.loads(env["cfg"].read_text())
    assert cfg["planet_name"] == "Night Owl" and cfg["privacy_tier"] == "rich" and cfg["rich_summary"] is False
    assert list(cfg["projects"].values()) == [{"visibility": "public", "name": "Demo Project"}]
    assert stat.S_IMODE(os.lstat(env["cfg"]).st_mode) == 0o600
    st = json.loads(run_planet("status", "--survey", "--json").stdout)
    assert st["uploaded"] == 0 and st["projects"][0]["this_project"] and st["projects"][0]["tier"] == "rich"
    assert st["projects"][0]["sessions"] == 1 and st["projects"][0]["tool_calls"] == 5
    pv = run_planet("preview").stdout
    assert '"project_name":"Demo Project"' in pv and "Send these" in pv and "demo-project" not in pv.split(
        "exact request body:")[1].splitlines()[1]
    sha = re.search(r"sha256 ([0-9a-f]{64})", pv).group(1)
    feed([(dict(simple_session(str(env["proj"]))[2][0]), T0 + 400)])  # activity between preview and "y"
    r = run_planet("upload", "--confirm", sha)
    assert r.returncode == 0 and "not enabled" in r.stdout


def test_rich_summary_off_by_default_and_never_spawns(env, monkeypatch):
    feed(simple_session(str(env["proj"])))
    cfg = C.load_config()
    pid = S.projects(env["root"])[0]
    m = S.survey(env["root"], pid, cfg)
    assert R.opted_in(cfg, m)[0] is False
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("spawned")))
    monkeypatch.chdir(env["proj"])
    assert P.main(["status", "--survey", "--rich"]) == 0           # off: no claude -p
    cfg.update(rich_summary=True, privacy_tier="rich")
    assert R.opted_in(cfg, dict(m, privacy_tier="rich"))[0] is True
    assert R.CLAUDE_ARGV[:2] == ["claude", "-p"] and "--safe-mode" in R.CLAUDE_ARGV
    assert R.CLAUDE_ARGV[R.CLAUDE_ARGV.index("--tools") + 1] == ""


def test_rich_input_is_a_subset_of_the_manifest(env):
    feed(simple_session(str(env["proj"])))
    m = S.survey(env["root"], S.projects(env["root"])[0], C.load_config())
    li = R.llm_input(m)
    assert set(li) <= set(m) | {"project_name"}
    assert li["agents"] == m["agents"] and set(li["tools"].items()) <= set(m["tools"].items())


def test_remote_config_is_local_and_validated(env, monkeypatch, _isolate):
    monkeypatch.chdir(env["proj"])
    r = run_planet("remote", "show")
    assert r.returncode == 0 and "none: upload is not enabled" in r.stdout
    for bad in ("http://nightside.example", "ftp://x.example", "https://u:p@x.example", "https://x.example/api",
                "https://x.example/?a=1", "not a url", ""):
        assert run_planet("remote", "set", bad).returncode == 2, bad
    r = run_planet("remote", "set", "https://Nightside.World/")
    assert r.returncode == 0 and "https://nightside.world" in r.stdout and "warning" not in r.stdout
    assert json.loads(env["cfg"].read_text())["upload_endpoint"] == "https://nightside.world"
    r = run_planet("remote", "set", "https://nightside-api-abc123-uc.a.run.app")
    assert r.returncode == 0 and "warning" in r.stdout and "domain" in r.stdout
    assert run_planet("remote", "set", "http://127.0.0.1:8123").returncode == 0      # loopback: dev and tests only
    tok = "nsu1.k1." + "eyJzdWIiOiJrZXBsZXItbmluZSIsInBsbiI6ImtlcGxlci1uaW5lIn0" + "." + "A" * 43
    tf = env["tmp"] / "token.txt"
    tf.write_text(tok + "\n")
    r = run_planet("remote", "token", "--file", str(tf))
    assert r.returncode == 0 and tok not in r.stdout and "planet kepler-nine" in r.stdout
    saved = env["root"] / "upload_token"
    assert saved.read_text().strip() == tok and stat.S_IMODE(os.lstat(saved).st_mode) == 0o600
    assert tok not in run_planet("remote", "show").stdout
    assert run_planet("remote", "token", stdin="not-a-token\n").returncode == 2
    r = run_planet("remote", "clear")
    assert r.returncode == 0 and not saved.exists()
    assert json.loads(env["cfg"].read_text())["upload_endpoint"] is None
    assert not _isolate["attempts"]


def test_configured_server_still_sends_nothing_until_a_confirm(env, monkeypatch, _isolate):
    """With a server and a token configured, every path except `upload --confirm <shown sha>` stays off the network;
    the confirmed path is the one that tries (positive control: the guard catches exactly that attempt)."""
    monkeypatch.chdir(env["proj"])
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(env["proj"]))
    feed(simple_session(str(env["proj"])))
    assert P.main(["remote", "set", "http://127.0.0.1:9"]) == 0
    (env["tmp"] / "t").write_text("nsu1.k1." + "eyJzdWIiOiJrZXBsZXItbmluZSIsInBsbiI6ImtlcGxlci1uaW5lIn0" + "." + "A" * 43)
    assert P.main(["remote", "token", "--file", str(env["tmp"] / "t")]) == 0
    for argv in (["status", "--survey"], ["status", "--json"], ["preview"], ["upload"], ["upload", "--confirm", "0" * 16],
                 ["remote", "show"], ["privacy", "private"], ["invite"]):
        assert P.main(argv) in (0, 3)
        assert run_planet(*argv).returncode in (0, 3)
    assert G.run_synthetic(env["tmp"] / "g1")["ok"]
    assert not _isolate["attempts"] and not _isolate["log"].exists()
    pv = run_planet("preview").stdout
    assert "goes to http://127.0.0.1:9 only" in pv and "Nothing has been sent" in pv
    sha = re.search(r"sha256 ([0-9a-f]{64})", pv).group(1)
    rc, msg = K.upload(env["root"], C.load_config(), sha)
    assert rc == 5 and "Could not reach" in msg and _isolate["attempts"]           # the one path that connects
    _isolate["attempts"].clear()
    r = run_planet("upload", "--confirm", sha)
    assert r.returncode == 5 and "socket" in _isolate["log"].read_text()
    _isolate["log"].unlink()
    st = json.loads(run_planet("status", "--json").stdout)
    assert st["uploaded"] == 0 and st["remote"] == "http://127.0.0.1:9"           # failures are not counted
    assert not _isolate["attempts"] and not _isolate["log"].exists()


# ------------------------------------------------------------------------------------------- no network ---
NET = re.compile(r"\b(import socket|from socket|urllib|http\.client|import requests|httpx|aiohttp|websocket|"
                 r"smtplib|ftplib|telnetlib|import ssl|open_connection|__import__|importlib|curl\b|wget\b|"
                 r"\bnc\b|WebFetch|fetch\(|XMLHttpRequest|gcloud|gsutil)")

# agent_ledger/guard.py loads a deny-list module with importlib (a local file the owner names). Nothing else in the
# plugin may mention anything on the list.
LOCAL_EXCEPTIONS = {("scripts/agent_ledger/guard.py", "importlib")}


# The plugin's ONE network module. upload.py may name urllib (the transport is imported inside send(), ask_server()
# and withdraw_project() only), and send() is called from exactly one place: consent.upload(), after the saved-bytes confirm and with a configured server.
UPLOAD_EXCEPTIONS = {("scripts/capture/upload.py", "urllib")}


def test_no_network_anywhere_in_the_plugin_grep():
    """Second line of defence (the runtime guard in conftest is the first)."""
    hits = set()
    for p in PLUGIN.rglob("*"):
        if p.is_file() and p.suffix in (".py", ".json", ".sh", ".js", ".mjs", ".md") and "tests" not in p.parts:
            text = re.sub(r"(?i)never use a network tool", "", p.read_text(encoding="utf-8", errors="replace"))
            for m in NET.finditer(text):
                hits.add((str(p.relative_to(PLUGIN)), m.group(0)))
    assert hits - LOCAL_EXCEPTIONS - UPLOAD_EXCEPTIONS == set()
    capture_files = {str(p.relative_to(PLUGIN)) for p in (PLUGIN / "scripts" / "capture").glob("*")} | {
        "commands/planet.md", "hooks/hooks.json"}
    assert {f for f, _ in hits} & capture_files == {"scripts/capture/upload.py"}
    hooks = (PLUGIN / "hooks" / "hooks.json").read_text()
    assert '"http"' not in hooks and "mcp_tool" not in hooks


def test_the_only_network_call_is_the_confirmed_upload():
    """upload.py: the transport modules are imported only inside send(); send() is called only by consent.upload(),
    after select() matched a saved, re-checked envelope and configured() returned a server AND a token."""
    up = (CAP / "upload.py").read_text()
    body_of_send = up[up.index("def send("):]
    assert "import urllib.request" in body_of_send and "import urllib.error" in body_of_send
    head = up[:up.index("def send(")]
    assert not re.search(r"^import urllib\.(request|error)|^from urllib", head, re.M)
    assert not re.search(r"\b(socket|http\.client|ssl)\b", re.sub(r'""".*?"""', "", up, flags=re.S))
    callers = {}
    for p in CAP.glob("*.py"):
        for m in re.finditer(r"(?<!def )(?<![\w.])(?:\w+\.)?send\((?!\))", p.read_text()):
            callers.setdefault(p.name, []).append(m.group(0))
    assert callers == {"consent.py": ["U.send("]}
    c = (CAP / "consent.py").read_text()
    fn = c[c.index("def upload("):]
    assert fn.index("select(saved(root)") < fn.index("U.configured(") < fn.index("A.check_envelope(") < fn.index("U.send(")
    fn_up = c[c.index("def upload("):c.index("def withdraw(")]
    fn_wd = c[c.index("def withdraw("):]
    assert c.count("import upload") == 2  # imported only inside upload() and withdraw()
    assert "from capture import upload as U" in fn_up and "from capture import upload as U" in fn_wd
    # withdraw: the id must be a captured project before configured() and the one DELETE
    assert fn_wd.index("pid not in known") < fn_wd.index("U.configured(") < fn_wd.index("U.withdraw_project(")
    wcallers = {q.name for q in CAP.glob("*.py") if re.search(r"(?<!def )withdraw_project\(", q.read_text())}
    assert wcallers == {"consent.py"}
    hooks = (CAP / "hook.py").read_text() + (CAP / "surveyor.py").read_text() + (CAP / "audit.py").read_text()
    assert not re.search(r"import upload|capture\.upload|from capture import [^\n]*\bupload\b|\bU\.", hooks)


def test_only_rich_py_spawns_a_process():
    spawners = []
    for p in (PLUGIN / "scripts" / "capture").glob("*.py"):
        t = p.read_text()
        if re.search(r"subprocess|os\.system|os\.popen|os\.exec|os\.spawn|pty\.", t):
            spawners.append(p.name)
    assert spawners == ["rich.py"]


def test_network_guard_is_live(_isolate):
    """Positive controls: the in-process and child-process guards both catch a connection attempt."""
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", 9))
    with pytest.raises(OSError):
        subprocess.run(["curl", "-s", "http://127.0.0.1:9"])
    r = subprocess.run([sys.executable, "-c", "import socket; socket.create_connection(('127.0.0.1', 9))"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "socket.create_connection" in _isolate["log"].read_text()
    _isolate["attempts"].clear()
    _isolate["log"].unlink()


def test_every_capture_path_runs_under_the_network_guard(env, monkeypatch, _isolate):
    """Hooks (in-process and as the real CLI), Surveyor, retention, every /planet subcommand and the G1 synthetic
    replay all run with sockets refused; any attempt fails the test in the conftest teardown."""
    monkeypatch.chdir(env["proj"])
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(env["proj"]))
    for d, _ in G.synthetic_session(SID, str(env["proj"]), T0):
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(d)))
        assert H.main() == 0
    for d, _ in simple_session(str(env["proj"]), sid=SID2):
        assert run_py(CAP / "hook.py", stdin=json.dumps(d)).returncode == 0
    cfg = C.load_config()
    S.retention(env["root"], cfg)
    for pid in S.projects(env["root"]):
        S.survey_to_outbox(env["root"], pid, cfg)
    for argv in (["name", "Owl"], ["privacy", "rich"], ["privacy", "public", "--name", "Demo"], ["invite"], ["open"],
                 ["status", "--survey", "--rich"], ["status", "--json"], ["preview"], ["upload"],
                 ["upload", "--confirm", "0" * 16]):
        assert P.main(argv) in (0, 3)
        assert run_planet(*argv).returncode in (0, 3)
    assert G.run_synthetic(env["tmp"] / "g1")["ok"]
    assert not _isolate["attempts"]


# ------------------------------------------------------------------------------------------------- G1 ---
def test_g1_synthetic_passes(tmp_path):
    rep = G.run_synthetic(tmp_path)
    assert rep["ok"], {k: v for k, v in rep.items() if k != "example_manifest"}
    assert rep["redteam"]["missed"] == [] and rep["redteam"]["caught"] >= 40
    assert set(rep["fields_planted"]) >= {"prompt", "tool_input", "tool_response", "error", "cwd", "transcript_path",
                                          "last_assistant_message", "agent_transcript_path", "custom_instructions"}
    assert all(t["leaves"] > 20 for t in rep["tiers"])
    priv = [t for t in rep["tiers"] if t["visibility"] == "private"]
    assert priv[0]["custom_leaves"] >= 1 and priv[0]["srv_leaves"] >= 2  # the hash paths were exercised


def test_g1_fails_closed_on_a_leaky_hook(tmp_path, monkeypatch):
    real = H.build_event

    def leaky(d, key, now, names=None):
        r = real(d, key, now, names)
        if r is not None and isinstance(d.get("prompt"), str):
            r["at"] = d["prompt"][:40]                  # smuggle prompt text through an allowed spool key
        return r
    monkeypatch.setattr(H, "build_event", leaky)
    rep = G.run_synthetic(tmp_path)
    assert rep["ok"] is False and rep["spool"]["ok"] is False


def test_g1_fails_closed_on_raw_names_at_write_time(tmp_path, monkeypatch):
    monkeypatch.setattr(H, "encode_tool", lambda raw, key, names=None: H.clean_name(raw, H.TOOL_RE) or "other")
    monkeypatch.setattr(H, "encode_agent", lambda raw, key, names=None: H.clean_name(raw, H.AGENT_RE))
    rep = G.run_synthetic(tmp_path)
    assert rep["ok"] is False and rep["spool"]["raw_name_hits"] > 0


def test_g1_fails_closed_on_raw_mcp_names_with_a_loosened_allow_list(tmp_path, monkeypatch):
    """The review's mutation: the Surveyor emits raw server names at the metadata tier and SRV_META is loosened so
    the allow-list lets them through. G1 must still fail (tier-aware provenance + raw-name scan)."""
    monkeypatch.setattr(A, "SRV_META", re.compile(r"^.+$"))
    real = S.build_manifest

    def leaky(partials, ledger_rows, key, pid, cfg, **kw):
        m = real(partials, ledger_rows, key, pid, cfg, **kw)
        names = C.read_names(Path(os.environ.get("_G1_ROOT", tmp_path / "capture-root")))
        m["mcp_servers"] = sorted(names.get(s, s) for s in m["mcp_servers"])
        return m
    monkeypatch.setattr(S, "build_manifest", leaky)
    rep = G.run_synthetic(tmp_path)
    assert rep["ok"] is False
    assert all(t.get("raw_name_hits", 0) > 0 or t.get("rejected") for t in rep["tiers"])


def test_g1_fails_closed_on_a_leaky_surveyor(tmp_path, monkeypatch):
    real = S.build_manifest

    def leaky(*a, **k):
        m = real(*a, **k)
        m["tools"]["CANARYPROMPTTOOL"] = 1             # a builtin-shaped key with no provenance
        return m
    monkeypatch.setattr(S, "build_manifest", leaky)
    rep = G.run_synthetic(tmp_path)
    assert rep["ok"] is False and any(t.get("unprovenanced") for t in rep["tiers"])


def test_transcript_payload_rebuild(tmp_path):
    d = tmp_path / "proj"
    (d / SID / "subagents").mkdir(parents=True)
    t = d / f"{SID}.jsonl"
    lines = [{"type": "user", "timestamp": "2027-01-01T00:00:00Z", "cwd": "/w/demo", "message": {"content": "hi"}},
             {"type": "assistant", "timestamp": "2027-01-01T00:00:01Z", "cwd": "/w/demo",
              "message": {"model": "claude-opus-9", "content": [
                  {"type": "tool_use", "id": "tu1", "name": "Bash", "input": {"command": "ls"}}]}},
             {"type": "user", "timestamp": "2027-01-01T00:00:03Z", "cwd": "/w/demo",
              "message": {"content": [{"type": "tool_result", "tool_use_id": "tu1", "content": "ok"}]}}]
    t.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    (d / SID / "subagents" / "agent-a1.jsonl").write_text(json.dumps(dict(lines[1], timestamp="2027-01-01T00:00:02Z"))
                                                          + "\n")
    (d / SID / "subagents" / "agent-a1.meta.json").write_text(json.dumps({"agentType": "Explore",
                                                                          "description": "look"}))
    evs = [p["hook_event_name"] for p, _ in G.transcript_payloads(t)]
    assert evs[0] == "SessionStart" and evs[-1] == "SessionEnd"
    assert {"UserPromptSubmit", "PostToolUse", "SubagentStart", "SubagentStop"} <= set(evs)


# ------------------------------------------------------------------- plugin-signed manifests (2026-10-23) ---
SK = "nsk1.k1.AbCdEfGhIjKlMnOpQrStUv." + "S" * 43   # synthetic signing key (never a real one)


def _spool_lines(root):
    return [json.loads(x) for p in sorted((root / "spool").rglob("*.jsonl")) for x in p.read_text().splitlines()]


def test_hook_records_a_random_run_id_and_mac_on_subagent_start_only(env):
    feed(simple_session(str(env["proj"])) + simple_session(str(env["proj"]), sid=SID2, t0=T0 + 1000))
    lines = _spool_lines(env["root"])
    starts = [x for x in lines if x["ev"] == "SubagentStart"]
    assert len(starts) == 2 and all(C.HEX16.match(x["r"]) and C.HEX16.match(x["rm"]) for x in starts)
    assert starts[0]["r"] != starts[1]["r"]                                   # random per run, never derived
    assert not [x for x in lines if x["ev"] != "SubagentStart" and ("r" in x or "rm" in x)]
    [pid] = S.projects(env["root"])
    key = C.install_key(env["root"])
    assert S.attested_runs(S.load_partials(env["root"], pid), key, pid) == sorted(x["r"] for x in starts)


def test_hand_written_spool_runs_are_not_attested(env):
    feed(simple_session(str(env["proj"])))
    [pid] = S.projects(env["root"])
    f = next((env["root"] / "spool" / pid).glob("*.jsonl"))
    real = next(x for x in _spool_lines(env["root"]) if x["ev"] == "SubagentStart")
    fake = dict(real, a="abcdefabcdef", r="0123456789abcdef", rm="fedcba9876543210")   # MAC not made with the key
    with open(f, "ab") as fh:
        fh.write(C.canonical(fake) + b"\n")
    runs = S.attested_runs(S.load_partials(env["root"], pid), C.install_key(env["root"]), pid)
    assert runs == [real["r"]]


def test_signed_preview_round_trip_sends_exactly_the_saved_bytes(env):
    from capture import signing as SG
    feed(simple_session(str(env["proj"])))
    cfg = C.load_config()
    assert SG.save_signing_key(env["root"], SK + "\n") == "k1.AbCdEfGhIjKlMnOpQrStUv"
    assert stat.S_IMODE(os.lstat(SG.signing_path(env["root"])).st_mode) == 0o600
    [it] = K.preview(env["root"], cfg)
    assert it["signed"] and it["attested_runs"] == 1
    e = json.loads(it["bytes"])
    assert e["schema"] == A.ENVELOPE_SCHEMA_SIGNED and len(e["attestation"]["runs"]) == 1
    assert "S" * 43 not in it["bytes"].decode()                                # the key itself never leaves
    key_id, key = SG.load_signing_key(env["root"])
    assert A.sign_envelope({k: e[k] for k in ("visibility", "manifest")}, e["attestation"]["runs"], key_id, key) == e
    assert "SIGNED by this plugin" in K.render([it])
    [sv] = K.saved(env["root"])
    assert sv["bytes"] == it["bytes"] and sv["sha256"] == it["sha256"]          # confirm re-reads the same bytes
    assert K.confirm(K.saved(env["root"]), it["sha256"][:16])[0] == 0
    e["manifest"]["agents"][0]["turns"] += 5                                    # a hand edit keeps the old MAC
    assert A.sign_envelope({k: e[k] for k in ("visibility", "manifest")}, e["attestation"]["runs"], key_id,
                           key)["attestation"]["sig"] != e["attestation"]["sig"]
    SG.clear_signing_key(env["root"])
    [it2] = K.preview(env["root"], cfg)
    assert not it2["signed"] and json.loads(it2["bytes"])["schema"] == A.ENVELOPE_SCHEMA
    assert "UNSIGNED" in K.render([it2])
    with pytest.raises(ValueError):
        SG.save_signing_key(env["root"], "nsu1.k1.notasigningkey")


def _nsu1(jti="AbCdEfGhIjKlMnOpQrStUv"):
    import base64 as b64
    pl = b64.urlsafe_b64encode(json.dumps({"sub": "kepler-nine", "pln": "kepler-nine", "jti": jti, "iat": 1, "exp": 2},
                                          sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"nsu1.k1.{pl}." + "M" * 43


def test_one_paste_nsu2_credential_saves_token_and_key(env):
    from capture import signing as SG
    from capture import upload as U
    d = U.save_token(env["root"], f"nsu2.{_nsu1()}.{'S' * 43}\n")
    assert d["signed"] and d["kid"] == "k1" and U.load_token(env["root"]) == _nsu1()
    assert SG.load_signing_key(env["root"])[0] == "k1.AbCdEfGhIjKlMnOpQrStUv"
    feed(simple_session(str(env["proj"])))
    [it] = K.preview(env["root"], C.load_config())
    assert it["signed"] and "S" * 43 not in it["bytes"].decode() and _nsu1() not in it["bytes"].decode()


def test_nsu1_token_still_works_unsigned_only(env):
    from capture import signing as SG
    from capture import upload as U
    U.save_token(env["root"], f"nsu2.{_nsu1()}.{'S' * 43}")
    d = U.save_token(env["root"], _nsu1())                                     # back-compat: bare nsu1
    assert not d["signed"] and U.load_token(env["root"]) == _nsu1() and SG.load_signing_key(env["root"]) is None
    feed(simple_session(str(env["proj"])))
    [it] = K.preview(env["root"], C.load_config())
    assert not it["signed"] and json.loads(it["bytes"])["schema"] == A.ENVELOPE_SCHEMA


@pytest.mark.parametrize("bad", [
    "nsu2." + "x" * 60, "nsu2.{t}", "nsu2.{t}." + "S" * 42, "nsu2.{t}." + "S" * 44, "nsu2.{t}.{k}.extra",
    "nsu3.{t}.{k}", "nsk1.k1.AbCdEfGhIjKlMnOpQrStUv.{k}", "nsu2.{bad_jti}.{k}", ""])
def test_malformed_credentials_save_nothing(env, bad):
    from capture import signing as SG
    from capture import upload as U
    raw = bad.format(t=_nsu1(), k="S" * 43, bad_jti=_nsu1(jti="short"))
    with pytest.raises(ValueError):
        U.save_token(env["root"], raw)
    assert U.load_token(env["root"]) is None and SG.load_signing_key(env["root"]) is None
