"""Plugin and server pairing: the plugin asks GET /api/plugin before it uploads and stops when it is older than the server's min_version.
The network is stubbed at ask_server / send (the conftest guard refuses real sockets)."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from capture import common as C
from capture import consent as K
from capture import planet as P
from capture import upload as U
from capture.tests.test_capture import env, feed, run_planet, simple_session  # noqa: F401  (fixtures + helpers)

PLUGIN = Path(__file__).resolve().parents[3]
VERSION = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())["version"]
# The min_version the current nightside.world server answers (it predates this release; semver puts it below 0.2.0).
SERVER_MIN = "0.2.0-pilot.1"


def ready(env, monkeypatch):
    monkeypatch.chdir(env["proj"])
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(env["proj"]))
    feed(simple_session(str(env["proj"])))
    assert P.main(["remote", "set", "http://127.0.0.1:9"]) == 0
    (env["tmp"] / "t").write_text("nsu1.k1." + "eyJzdWIiOiJrZXBsZXItbmluZSIsInBsbiI6ImtlcGxlci1uaW5lIn0" + "." + "A" * 43)
    assert P.main(["remote", "token", "--file", str(env["tmp"] / "t")]) == 0
    pv = run_planet("preview").stdout
    return re.search(r"sha256 ([0-9a-f]{64})", pv).group(1)


def test_plugin_version_is_the_release():
    assert U.plugin_version() == VERSION == "0.2.0"


def test_this_release_passes_the_current_server_minimum():
    assert U.version_key(VERSION) >= U.version_key(SERVER_MIN)


def test_version_ordering():
    k = U.version_key
    assert k("0.1.0-alpha.4") < k("0.2.0-rc.1") < k("0.2.0-rc.2") < k("0.2.0-rc.10") < k("0.2.0") < k("0.10.0")
    assert k("garbage") < k("0.0.1-a")


@pytest.mark.parametrize("mine,need,ok", [(SERVER_MIN, SERVER_MIN, True), ("0.2.0", SERVER_MIN, True),
                                          ("0.1.0-alpha.4", SERVER_MIN, False), ("0.0.0", SERVER_MIN, False),
                                          ("0.2.0", "0.2.1", False)])
def test_check_server_compares_versions(monkeypatch, mine, need, ok):
    monkeypatch.setattr(U, "ask_server", lambda base, timeout=0: (200, {"min_version": need, "server": "nightside"}))
    good, rc, msg = U.check_server("https://nightside.world", mine=mine)
    assert good is ok
    if not ok:
        assert rc == 7 and mine in msg and need in msg and "Nothing was sent" in msg


@pytest.mark.parametrize("status,doc", [(404, {}), (500, {}), (200, {}), (200, {"min_version": "banana"}), (200, {"min_version": 3})])
def test_check_server_does_not_block_on_a_server_without_the_route(monkeypatch, status, doc):
    monkeypatch.setattr(U, "ask_server", lambda base, timeout=0: (status, doc))
    assert U.check_server("https://nightside.world", mine="0.0.0")[0] is True


def test_unreachable_server_stops_with_the_usual_message(monkeypatch):
    monkeypatch.setattr(U, "ask_server", lambda base, timeout=0: (0, {"error": "URLError"}))
    assert U.check_server("https://nightside.world")[:2] == (False, 5)


def test_old_plugin_sends_nothing(env, monkeypatch):
    sha = ready(env, monkeypatch)
    sent = []
    monkeypatch.setattr(U, "ask_server", lambda base, timeout=0: (200, {"min_version": "9.0.0", "server": "nightside"}))
    monkeypatch.setattr(U, "send", lambda *a, **k: sent.append(a) or (201, {}))
    rc, msg = K.upload(env["root"], C.load_config(), sha)
    assert rc == 7 and "9.0.0" in msg and VERSION in msg and sent == []


def test_current_plugin_uploads_and_a_422_unsigned_names_the_version(env, monkeypatch):
    sha = ready(env, monkeypatch)
    calls = []
    monkeypatch.setattr(U, "ask_server", lambda base, timeout=0: (200, {"min_version": VERSION, "server": "nightside"}))
    monkeypatch.setattr(U, "send", lambda base, tok, b: calls.append(1) or (
        422, {"detail": "rejected", "reason": "unsigned", "message": "This upload is unsigned: update to 0.2.0."}))
    rc, msg = K.upload(env["root"], C.load_config(), sha)
    assert calls == [1] and rc == 6 and "unsigned" in msg and "0.2.0" in msg


@pytest.mark.skipif(not Path("/usr/bin/python3").exists(), reason="no macOS system python")
def test_plugin_code_compiles_on_the_system_python(tmp_path):
    """macOS /usr/bin/python3 is 3.9: no 3.10+ syntax (match, X | Y outside annotations, parenthesised with) in the plugin."""
    py = shutil.which("python3", path="/usr/bin")
    v = subprocess.run([py, "-c", "import sys;print(sys.version_info[:2] < (3, 10))"], capture_output=True, text=True).stdout.strip()
    srcs = [str(p) for p in (PLUGIN / "scripts").rglob("*.py") if "tests" not in p.parts]
    r = subprocess.run([py, "-c", "import sys,ast\nfor f in sys.argv[1:]: ast.parse(open(f,encoding='utf-8').read(), f)"] + srcs,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-800:]
    assert v in ("True", "False")
