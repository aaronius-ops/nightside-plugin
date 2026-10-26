"""The local public label (labels.py). SYNTHETIC fixtures only: invented ids, paths and canaries.
conftest.py isolates HOME and every Nightside root per test and refuses the network."""
from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from capture import allowlist as A
from capture import common as C
from capture import consent as K
from capture import hook as H
from capture import labels as L
from capture import rich as R
from capture import surveyor as S

HERE = Path(__file__).resolve()
CAP = HERE.parents[1]
REPO = HERE.parents[5]
T0 = 1_800_000_000.0
# frozen copy of the Nightside world builder's categories (the server validates against the same list)
BUILDER_CATEGORIES = ["finance-bookkeeping", "cron-daemon", "knowledge-research", "media-pipeline", "eval-hillclimb",
                      "harness-testing", "build-deploy-infra", "writing-drafting", "legal-governance",
                      "outreach-sales", "world-simulation", "personal-family", "unclassified"]


@pytest.fixture
def proj(tmp_path):
    p = tmp_path / "work" / "demo-project"
    p.mkdir(parents=True)
    return p


def root() -> Path:
    return C.ensure_root(C.capture_root(C.load_config()))


def session(cwd: str, calls, sid="11111111-2222-4333-8444-555555555555", t0=T0):
    """calls: [(tool_name, tool_input)] in one closed session with one Explore subagent."""
    b = {"session_id": sid, "cwd": cwd}
    ev = [(dict(b, hook_event_name="SessionStart", source="startup", model="claude-opus-9-9"), t0),
          (dict(b, hook_event_name="UserPromptSubmit", prompt="CANARY-P"), t0 + 1),
          (dict(b, hook_event_name="SubagentStart", agent_id="a01", agent_type="Explore"), t0 + 2)]
    for i, (tool, ti) in enumerate(calls):
        ev.append((dict(b, hook_event_name="PostToolUse", tool_name=tool, tool_input=ti, duration_ms=5), t0 + 3 + i))
    ev += [(dict(b, hook_event_name="SubagentStop", agent_id="a01", agent_type="Explore"), t0 + 500),
           (dict(b, hook_event_name="SessionEnd", reason="prompt_input_exit"), t0 + 600)]
    return ev


def label_of(cwd, calls, tier="metadata", vis="private"):
    for d, t in session(str(cwd), calls):
        H.handle(d, None, now=t)
    r = root()
    pid = S.projects(r)[0]
    cfg = C.load_config()
    cfg["privacy_tier"], cfg["default_visibility"] = tier, vis
    return S.survey(r, pid, cfg), r, pid, cfg


def W(path):
    return ("Write", {"file_path": path, "content": "CANARY-CONTENT"})


def B(cmd):
    return ("Bash", {"command": cmd})


# --------------------------------------------------------------------------------------- vocabulary ---
def test_categories_match_the_builder_and_the_schema():
    sch = A.schema()
    assert L.categories() == BUILDER_CATEGORIES
    assert sch["properties"]["category"]["enum"] == L.categories()
    assert sch["properties"]["label"]["properties"]["category"]["enum"] == L.categories()
    assert sch["properties"]["label"]["properties"]["source"]["enum"] == list(L.SOURCES)
    assert sch["$id"] == "nightside/workflow-manifest/2"


def test_every_heuristic_phrase_passes_the_allow_list_at_the_metadata_tier():
    assert set(L.PHRASES) == set(L.categories())
    for cat, d in L.PHRASES.items():
        for t in d.values():
            assert len(t) <= L.MAX_LEN and not L.unknown_words(t), t
            assert A.check_label({"text": t, "category": cat, "source": "heuristic"}, "metadata") == []


# --------------------------------------------------------------------------------------- heuristics ---
SESSIONS = {
    "voice pipeline": ([W("/w/a/take1.wav"), W("/w/a/take2.mp3"), B("ffmpeg -i in.mov out.wav"),
                        ("mcp__elevenlabs__text_to_speech", {}), B("git status")],
                       "media-pipeline", "Voice and audio pipeline"),
    "data analysis": ([W("/w/d/sales.csv"), ("NotebookEdit", {"notebook_path": "/w/d/a.ipynb"}),
                       B("python -m jupyter nbconvert x"), B("duckdb q.db"), W("/w/d/clean.py")],
                      "knowledge-research", "Data analysis workbench"),
    "web app": ([W("/w/s/App.tsx"), W("/w/s/app.css"), W("/w/s/index.html"), B("npm run dev"), B("git add -A")],
                "unclassified", "Web app build"),
    "web app + deploy": ([W("/w/s/App.tsx"), W("/w/s/app.css"), B("npm run build"), B("docker build ."),
                          B("terraform apply"), W("/w/s/infra.tf")], "build-deploy-infra", "Web app build and deploy"),
    "docs writing": ([W("/w/n/ch1.md"), W("/w/n/ch2.md"), ("Edit", {"file_path": "/w/n/ch3.md"}), W("/w/n/memo.docx"),
                      B("pandoc ch1.md -o ch1.pdf")], "writing-drafting", "Document drafting workflow"),
    "image generation": ([("mcp__gemini-image__generate_image", {}), ("mcp__gemini-image__generate_image", {}),
                          W("/w/i/hero.png"), B("magick hero.png -resize 50% small.png")],
                         "media-pipeline", "Image generation pipeline"),
    "test harness": ([B("pytest -q"), B("uv run pytest -x"), B("python3 -m pytest tests"), W("/w/t/test_x.py")],
                     "harness-testing", "Test harness and checks"),
    "nothing to go on": ([("Read", {"file_path": "/w/x"}), ("Grep", {"pattern": "x"})],
                         "unclassified", "Agentic workflow"),
}


@pytest.mark.parametrize("name", list(SESSIONS))
def test_heuristic_labels_for_synthetic_sessions(proj, name):
    calls, cat, text = SESSIONS[name]
    m, *_ = label_of(proj, calls)
    assert m["label"] == {"text": text, "category": cat, "source": "heuristic"}
    assert m["category"] == "unclassified"  # a heuristic label is a hint; only the user's sets the category
    A.check_envelope(A.envelope(m, "private"))


def test_kind_tables():
    assert L.ext_kind("/a/b/Song.WAV") == "ext-audio" and L.ext_kind("/a/.bashrc") is None
    assert L.ext_kind("/a/secret-plans") is None and L.ext_kind(7) is None
    assert L.cmd_kind("FOO=1 sudo /usr/bin/python3.12 -m pytest -q") == "cmd-test"
    assert L.cmd_kind("cd x && npm run test") is None                       # only the first program counts
    assert L.cmd_kind("uv run pytest") == "cmd-test" and L.cmd_kind("cat ~/.ssh/id_rsa") is None
    assert L.event_kind("Read", {"file_path": "/x.wav"}) is None            # reads are not signal


# ------------------------------------------------------------------------------------ red team: names ---
def test_spool_holds_only_the_class_never_the_name(proj):
    calls = [W("/Users/canary-user/CANARY-SECRET-DIR/CANARY-FILE-name.wav"),
             B("CANARY_ENV=CANARY-VAL ffmpeg -i /Users/canary-user/CANARY-CMD-x.mov out.wav"),
             B("acme-canary-tool --deploy CANARY-ARG")]
    m, r, pid, _ = label_of(proj, calls)
    spool = "".join(f.read_text() for f in (r / "spool").rglob("*.jsonl"))
    summaries = "".join(f.read_text() for f in (r / "sessions").rglob("*.json"))
    for blob in (spool, summaries, C.canonical(m).decode()):
        low = blob.lower()
        assert "canary" not in low and ".wav" not in low and "ffmpeg" not in low and "acme" not in low
    assert '"k":"ext-audio"' in spool and '"k":"cmd-media"' in spool and spool.count('"k":') == 2
    for line in spool.splitlines():
        assert set(json.loads(line)) <= H.SPOOL_KEYS


def test_label_ignores_file_and_directory_names(tmp_path):
    """Two projects that write the same KINDS of files under different names get byte-identical labels."""
    dirs = [tmp_path / "w1" / "acme-voice-deal", tmp_path / "w2" / "zz"]
    for d in dirs:
        d.mkdir(parents=True)
    names = [["/x/acme-voice-deal/notes-for-jane.md", "/x/acme/q.md", "/x/acme/r.md"], ["/y/1.md", "/y/2.md", "/y/3.md"]]
    sids = ["11111111-2222-4333-8444-555555555555", "66666666-7777-4888-9999-000000000000"]
    for d, ns, sid in zip(dirs, names, sids):
        for ev, t in session(str(d), [W(n) for n in ns], sid=sid):
            H.handle(ev, None, now=t)
    r, cfg = root(), C.load_config()
    key = C.install_key(r)
    labs = [S.survey(r, C.project_identity(key, d)[0], cfg)["label"] for d in dirs]
    assert labs[0] == labs[1] == {"text": "Document drafting workflow", "category": "writing-drafting",
                                  "source": "heuristic"}


def test_heuristic_label_that_repeats_the_repo_name_falls_back(tmp_path):
    repo = tmp_path / "work" / "web-app"     # the repo is literally named after the phrase
    repo.mkdir(parents=True)
    m, *_ = label_of(repo, [W("/s/App.tsx"), W("/s/app.css"), W("/s/index.html")])
    assert m["label"]["text"] == "Agentic workflow" and "web app" not in m["label"]["text"].lower()


@pytest.mark.parametrize("text,why", [
    ("canary.py tool", "file name"), ("src/canary build", "path"), ("mail me@example.org", "email"),
    ("sk-ant-api03-Canary0123456789abcdefghij", "secret"), ("Raise 40000 dollars", "number"),
    ("Drafts for Jane Canary", "person (metadata: generic words only)"), ("canary_repo build", "identifier"),
    ("demo project pipeline", "the repo slug"), ("x" * 41, "too long"), ("", "empty"),
])
def test_user_label_red_team(proj, text, why):
    label_of(proj, [W("/a/b.md")])
    r, cfg = root(), C.load_config()
    pid = S.projects(r)[0]
    with pytest.raises(ValueError):
        K.set_label(cfg, r, pid, text, "writing-drafting")
    assert "label" not in ((cfg.get("projects") or {}).get(pid) or {})


def test_rich_tier_user_label_is_free_text_but_still_guarded(proj):
    label_of(proj, [W("/a/b.md")])
    r, cfg = root(), C.load_config()
    pid = S.projects(r)[0]
    K.set_visibility(cfg, "public", pid)
    K.set_tier(cfg, "rich", pid)
    assert K.set_label(cfg, r, pid, "Night owl harbor tours", "media-pipeline")["text"] == "Night owl harbor tours"
    m = S.survey(r, pid, cfg)
    assert m["label"] == {"text": "Night owl harbor tours", "category": "media-pipeline", "source": "user"}
    assert m["category"] == "media-pipeline"
    K.set_visibility(cfg, "private", pid)    # now metadata: the free-text label no longer passes, the heuristic does
    m = S.survey(r, pid, cfg)
    assert m["label"]["source"] == "heuristic" and "harbor" not in C.canonical(m).decode().lower()


# --------------------------------------------------------------------------------------------- G1 ---
GOOD = {"text": "Voice and audio pipeline", "category": "media-pipeline", "source": "heuristic"}


@pytest.mark.parametrize("lab,tier,ok", [
    (GOOD, "metadata", True),
    (dict(GOOD, source="user", text="Pipeline for voice tests"), "metadata", True),
    (dict(GOOD, source="claude", text="Audio generation studio"), "metadata", True),
    (dict(GOOD, source="user", text="Night owl harbor tours"), "rich", True),
    (dict(GOOD, source="user", text="Night owl harbor tours"), "metadata", False),
    (dict(GOOD, source="claude", text="Night owl harbor tours"), "rich", False),
    (dict(GOOD, text="Audio generation studio"), "metadata", False),      # heuristic text must be a phrase
    (dict(GOOD, category="voice"), "metadata", False),
    (dict(GOOD, source="server"), "metadata", False),
    (dict(GOOD, extra=1), "metadata", False),
    ({"text": "Voice"}, "metadata", False),
    ("Voice and audio pipeline", "metadata", False),
    (dict(GOOD, text=None), "metadata", False),
    (dict(GOOD, text=" Voice and audio pipeline"), "metadata", False),
    (dict(GOOD, source="user", text="Audio  pipeline"), "metadata", False),
])
def test_g1_label_shape(lab, tier, ok):
    assert (A.check_label(lab, tier) == []) is ok
    base = {"user_id": "local", "project_id": "0" * 16, "category": "unclassified", "graph_shape": "single",
            "agents": [], "tools": {}, "skills": [], "mcp_servers": [], "infra_tags": [],
            "runs": {"count": 0, "first_at": "2026-10-23T00:00:00Z", "last_at": "2026-10-23T00:00:00Z",
                     "total_minutes": 0}, "outcomes": {"files_written": 0, "prs": 0, "deploys": 0, "artifacts": 0},
            "links_to": [], "privacy_tier": tier, "label": lab}
    if ok:
        A.check_manifest(base)
    else:
        with pytest.raises(A.Rejected):
            A.check_manifest(base)


# -------------------------------------------------------------------------------- consent round trip ---
def planet(*args, cwd):
    return subprocess.run([sys.executable, str(CAP / "planet.py"), *args], capture_output=True, text=True,
                          timeout=60, cwd=cwd)


def test_preview_shows_the_label_and_confirm_sends_those_bytes(proj, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(proj))
    label_of(proj, SESSIONS["voice pipeline"][0])
    pv = planet("preview", cwd=proj).stdout
    assert 'PUBLIC LABEL: "Voice and audio pipeline"   category: media-pipeline   (made by: heuristic)' in pv
    r = planet("preview", "--label", "Canary Corp deal room", "--category", "finance-bookkeeping", cwd=proj)
    assert r.returncode == 2 and "label refused" in r.stderr
    r = planet("preview", "--label", "Pipeline for voice tests", "--category", "media-pipeline", cwd=proj)
    assert r.returncode == 0 and 'PUBLIC LABEL: "Pipeline for voice tests"' in r.stdout
    body = r.stdout.split("exact request body:")[1].splitlines()[1]
    assert json.loads(body)["manifest"]["label"] == {"text": "Pipeline for voice tests",
                                                     "category": "media-pipeline", "source": "user"}
    sha = re.search(r"sha256 ([0-9a-f]{64})", r.stdout).group(1)
    saved = (root() / "outbox" / f"{S.projects(root())[0]}.envelope").read_bytes()
    assert saved.decode() == body
    assert planet("upload", "--confirm", sha, "--label", "Other", cwd=proj).returncode == 2
    ok = planet("upload", "--confirm", sha, cwd=proj)
    assert ok.returncode == 0 and f"Confirmed {len(saved)} bytes" in ok.stdout
    r = planet("preview", "--label", "auto", cwd=proj)
    assert '(made by: heuristic)' in r.stdout
    assert planet("upload", "--confirm", sha, cwd=proj).returncode == 3   # the approved bytes were replaced


def test_category_alone_keeps_a_generated_text(proj, monkeypatch):
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(proj))
    label_of(proj, SESSIONS["web app"][0])
    r = planet("preview", "--category", "outreach-sales", cwd=proj)
    assert r.returncode == 0 and 'PUBLIC LABEL: "Outreach and messaging"   category: outreach-sales   (made by: user)' \
        in r.stdout
    assert planet("preview", "--category", "fundraising", cwd=proj).returncode == 2


def test_no_back_fill_command(proj):
    for sub in ("backfill", "import"):
        r = planet(sub, "/some/old/repo", cwd=proj)
        assert r.returncode == 2 and "there is no back-fill" in r.stderr
    md = (CAP.parents[1] / "commands" / "planet.md").read_text()
    assert "no back-fill" in md.lower()


# -------------------------------------------------------------------------------------- rich (claude) ---
def test_claude_label_closed_vocabulary_and_user_wins(proj):
    m, r, pid, cfg = label_of(proj, SESSIONS["voice pipeline"][0], tier="rich", vis="public")

    def runner(lab):
        return lambda prompt: json.dumps({"result": json.dumps({"summary": "An orchestrator with one subagent.",
                                                                 "category": "media-pipeline", "label": lab})})
    got = R.summarize(m, runner=runner("Speech generation studio"))
    assert got["label"] == {"text": "Speech generation studio", "category": "media-pipeline", "source": "claude"}
    assert "label" not in R.summarize(m, runner=runner("Canary Corp voice deal"))
    assert "label" not in R.summarize(m, runner=runner("see canary.example.com"))
    S.survey_to_outbox(r, pid, cfg, summary=got)
    out = json.loads((r / "outbox" / f"{pid}.json").read_text())
    assert out["label"]["source"] == "claude"
    K.set_label(cfg, r, pid, "Pipeline for voice tests", None)
    S.survey_to_outbox(r, pid, cfg, summary=got)
    out = json.loads((r / "outbox" / f"{pid}.json").read_text())
    assert out["label"] == {"text": "Pipeline for voice tests", "category": "media-pipeline", "source": "user"}


# ------------------------------------------------------------------------------ review fixes (95b8d24) ---
from capture import audit as G  # noqa: E402


def _env_with(role: str, text: str = "Voice and audio pipeline") -> bytes:
    m = {"user_id": "local", "project_id": "0" * 16, "category": "unclassified", "graph_shape": "single",
         "agents": [{"role": role, "model_tier": "opus", "turns": 1, "minutes": 1.0}], "tools": {}, "skills": [],
         "mcp_servers": [], "infra_tags": [], "runs": {"count": 0, "first_at": "2026-10-23T00:00:00Z",
                                                        "last_at": "2026-10-23T00:00:00Z", "total_minutes": 0},
         "outcomes": {"files_written": 0, "prs": 0, "deploys": 0, "artifacts": 0}, "links_to": [],
         "privacy_tier": "metadata",
         "label": {"text": text, "category": "media-pipeline", "source": "heuristic"}}
    return C.canonical(A.envelope(m, "private"))


def test_g1_vocab_allowance_is_for_label_text_only():
    ev, key = G.Evidence(), b"k" * 32
    assert G.check_bytes(_env_with("orchestrator"), ev, key)["unprovenanced"] == 0
    assert G.check_bytes(_env_with("Audio pipeline"), ev, key)["unprovenanced"] == 1   # vocab words, wrong field
    assert G.check_bytes(_env_with("orchestrator", "Canary corp"), ev, key)["unprovenanced"] == 1


def _replayed(tmp_path, t0):
    root = C.ensure_root(tmp_path / "capture-root")
    cwd = tmp_path / "w" / "demo"
    cwd.mkdir(parents=True)
    ev = G.Evidence()
    pids = G._replay(session(str(cwd), [W("/a/b.wav")], t0=t0), root, G._cfg(root, "metadata", "private"), ev)
    for pid in pids:
        S.load_partials(root, pid)
    return root, ev


def test_spool_scan_ignores_partial_timestamps_but_not_real_leaks(tmp_path):
    t0 = 1792687800.0  # 2026-10-22T16:50:00Z
    root, ev = _replayed(tmp_path, t0)
    assert "10-22T16:50" in "".join(f.read_text() for f in (root / "spool").rglob("*.jsonl"))
    ev.forbidden = {"10-22T16:50", "2026-10-22T16:50"}           # a tool output quoting the time
    assert G.spool_scan(root, ev)["leak_hits"] == 0
    ev.models = set()
    ev.forbidden = {"claude-opus-9-9"}                            # a value the scan must still see
    assert G.spool_scan(root, ev)["leak_hits"] == 1
    assert G.spool_scan(root, G.Evidence(), canaries=["10-22T16:50"])["canary_hits"] == 1  # canaries: raw bytes


def test_spool_scan_accepts_pre_label_summaries_without_kinds(tmp_path):
    root, ev = _replayed(tmp_path, T0)
    files = list((root / "sessions").rglob("*.json"))
    assert files
    for f in files:
        c = json.loads(f.read_text())
        for k in ("partial", "base"):
            if c.get(k):
                c[k].pop("kinds", None)
        f.write_text(json.dumps(c))
    assert G.spool_scan(root, ev)["unprovenanced_lines"] == 0


def test_local_name_check_is_separator_free():
    assert L.mentions_local_name("Acmecorp tours", {"acme corp"})
    assert L.mentions_local_name("Dock 12 tours", {"dock12"})
    assert L.mentions_local_name("Dock12 tours", {"dock 12"})
    assert not L.mentions_local_name("Voice and audio pipeline", {"acme corp", "dock12"})


def test_claude_label_is_normalised():
    assert L.normalise("VOICE voice AUDIO Pipeline") == "Voice audio pipeline"
    assert L.normalise("3d WORLD build 3D") == "3D world build"
    m = {"privacy_tier": "rich", "graph_shape": "single", "agents": [], "tools": {}, "runs": {"count": 1,
         "total_minutes": 1}, "outcomes": {}, "user_id": "local", "project_id": "0" * 16, "category": "unclassified",
         "skills": [], "mcp_servers": [], "infra_tags": [], "links_to": []}
    m["runs"].update(first_at="2026-10-23T00:00:00Z", last_at="2026-10-23T00:00:00Z")
    m["outcomes"] = {"files_written": 0, "prs": 0, "deploys": 0, "artifacts": 0}
    got = R.summarize(m, runner=lambda p: json.dumps({"result": json.dumps(
        {"summary": "One agent.", "category": "media-pipeline", "label": "SPEECH speech Generation studio"})}))
    assert got["label"]["text"] == "Speech generation studio"
