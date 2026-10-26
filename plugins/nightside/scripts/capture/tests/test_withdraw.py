"""/planet withdraw: take an uploaded project back. The network is stubbed at upload.withdraw_project (the conftest
guard refuses real sockets); one test checks the request the real transport builds, with the opener stubbed."""
from __future__ import annotations

import json

import pytest

from capture import common as C
from capture import consent as K
from capture import planet as P
from capture import surveyor as S
from capture import upload as U
from capture.tests.test_capture import env, feed, run_planet, simple_session  # noqa: F401  (fixtures + helpers)

TOKEN_FILE_TEXT = "nsu1.k1." + "eyJzdWIiOiJrZXBsZXItbmluZSIsInBsbiI6ImtlcGxlci1uaW5lIn0" + "." + "A" * 43


def captured(env, monkeypatch, server=True):
    monkeypatch.chdir(env["proj"])
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(env["proj"]))
    feed(simple_session(str(env["proj"])))
    if server:
        assert P.main(["remote", "set", "http://127.0.0.1:9"]) == 0
        (env["tmp"] / "t").write_text(TOKEN_FILE_TEXT)
        assert P.main(["remote", "token", "--file", str(env["tmp"] / "t")]) == 0
    (pid,) = S.projects(env["root"])
    return pid


def test_withdraw_without_confirm_is_local_and_names_the_id(env, monkeypatch):
    pid = captured(env, monkeypatch)
    monkeypatch.setattr(U, "withdraw_project", lambda *a, **k: pytest.fail("no confirm, no request"))
    r = run_planet("withdraw")
    assert r.returncode == 0 and pid in r.stdout and "Nothing was sent" in r.stdout


def test_withdraw_refuses_an_unknown_id_before_any_request(env, monkeypatch):
    captured(env, monkeypatch)
    monkeypatch.setattr(U, "withdraw_project", lambda *a, **k: pytest.fail("unknown id must not reach the network"))
    for bad in ("0" * 16, "not-an-id", "", "../../api"):
        rc, msg = K.withdraw(env["root"], C.load_config(), bad, S.projects(env["root"]))
        assert rc == 2 and "Nothing was sent" in msg


def test_withdraw_without_a_server_only_sets_private(env, monkeypatch):
    pid = captured(env, monkeypatch, server=False)
    monkeypatch.setattr(U, "withdraw_project", lambda *a, **k: pytest.fail("no server configured"))
    assert P.main(["privacy", "public"]) == 0
    assert P.main(["withdraw", "--confirm", pid]) == 0
    assert C.load_config()["projects"][pid]["visibility"] == "private"


def test_withdraw_confirmed_deletes_and_sets_private(env, monkeypatch):
    pid = captured(env, monkeypatch)
    assert P.main(["privacy", "public"]) == 0
    calls = []
    monkeypatch.setattr(U, "withdraw_project", lambda base, tok, p: calls.append((base, tok, p)) or (
        200, {"status": "withdrawn", "project_id": p, "deleted": 2}))
    rc, msg = K.withdraw(env["root"], C.load_config(), pid.upper(), S.projects(env["root"]))
    assert rc == 0 and "2 uploaded manifest(s)" in msg
    assert calls == [("http://127.0.0.1:9", TOKEN_FILE_TEXT, pid)]
    assert C.load_config()["projects"][pid]["visibility"] == "private"
    st = json.loads(run_planet("status", "--json").stdout)
    assert st["uploaded"] == 0  # a withdraw line is never counted as an upload


@pytest.mark.parametrize("status,rc,words", [(0, 5, "Could not reach"), (404, 6, "Not withdrawn"),
                                             (503, 6, "Not withdrawn")])
def test_withdraw_failures(env, monkeypatch, status, rc, words):
    pid = captured(env, monkeypatch)
    monkeypatch.setattr(U, "withdraw_project", lambda *a: (status, {"error": "URLError"} if status == 0 else {}))
    got, msg = K.withdraw(env["root"], C.load_config(), pid, S.projects(env["root"]))
    assert got == rc and words in msg


def test_withdraw_transport_builds_a_bodyless_delete_and_refuses_redirects(monkeypatch):
    """The real withdraw_project() up to the opener: the request it builds and the handler it installs. The opener is
    stubbed, so no socket is opened (the conftest guard stays on)."""
    import io
    import urllib.request
    seen = {}

    class Resp(io.BytesIO):
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Opener:
        def __init__(self, handlers):
            seen["handlers"] = handlers

        def open(self, req, timeout=None):
            seen["req"] = req
            return Resp(json.dumps({"status": "withdrawn", "project_id": "0123456789abcdef", "deleted": 1}).encode())
    monkeypatch.setattr(urllib.request, "build_opener", lambda *h: Opener(h))
    status, doc = U.withdraw_project("https://nightside.world", "tok", "0123456789abcdef")
    req = seen["req"]
    assert status == 200 and doc["deleted"] == 1
    assert req.get_method() == "DELETE" and req.data is None
    assert req.full_url == "https://nightside.world/api/manifests/projects/0123456789abcdef"
    assert req.get_header("Authorization") == "Bearer tok"
    (h,) = seen["handlers"]
    assert isinstance(h, urllib.request.HTTPRedirectHandler) and h.redirect_request(req, None, 302, "", {}, "x") is None
    for bad in ("../x", "0123456789ABCDEF0", "", "0123456789abcde/"):
        with pytest.raises(ValueError):
            U.withdraw_project("https://nightside.world", "tok", bad)
