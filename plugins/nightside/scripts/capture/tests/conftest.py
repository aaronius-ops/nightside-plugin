"""Capture tests: every test runs with HOME and every Nightside root inside its tmp dir, and with the network
refused in-process (socket patched) and in child Python processes (tests/netguard/sitecustomize.py)."""
import os
import pwd
import socket
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # plugin/nightside/scripts

NETGUARD = Path(__file__).resolve().parent / "netguard"
REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
NET_TOOLS = {"curl", "wget", "nc", "ncat", "ssh", "scp", "sftp", "gcloud", "gsutil", "claude", "telnet", "ftp"}


def _real_state():
    out = {}
    for sub in ("capture", "logs"):
        p = REAL_HOME / ".nightside" / sub
        out[sub] = sorted(str(x.relative_to(p)) for x in p.rglob("*")) if p.exists() else None
    return out


@pytest.fixture(scope="session", autouse=True)
def _real_home_untouched():
    before = _real_state()
    yield
    assert _real_state() == before, "a capture test wrote under the real ~/.nightside"


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("NIGHTSIDE_CAPTURE_ROOT", str(home / ".nightside" / "capture"))
    monkeypatch.setenv("NIGHTSIDE_CAPTURE_CONFIG", str(home / ".config" / "nightside" / "capture.json"))
    monkeypatch.setenv("NIGHTSIDE_ARCHIVE_ROOT", str(home / ".nightside" / "agent-archive" / "raw"))
    monkeypatch.setenv("NIGHTSIDE_ARCHIVE_CONFIG", str(home / ".config" / "nightside" / "archive.json"))
    for k in ("CLAUDE_PROJECT_DIR", "NIGHTSIDE_CAPTURE", "CLAUDE_CONFIG_DIR"):
        monkeypatch.delenv(k, raising=False)
    log = tmp_path / "net-guard.log"
    monkeypatch.setenv("NIGHTSIDE_NET_GUARD_LOG", str(log))
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([str(NETGUARD)] + [p for p in os.environ.get(
        "PYTHONPATH", "").split(os.pathsep) if p]))
    attempts = []

    def deny(what):
        def f(*a, **k):
            attempts.append(what)
            raise OSError(f"network disabled in capture tests ({what})")
        return f
    class DeniedSocket(socket.socket):  # a class, so modules that subclass socket.socket (ssl) still import
        def __init__(self, *a, **k):
            attempts.append("socket.socket")
            raise OSError("network disabled in capture tests (socket.socket)")
    monkeypatch.setattr(socket, "socket", DeniedSocket)
    for name in ("create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, deny(f"socket.{name}"))
    real_popen = subprocess.Popen

    class GuardedPopen(real_popen):
        def __init__(self, args, *a, **k):
            argv0 = args[0] if isinstance(args, (list, tuple)) else str(args).split()[0]
            if os.path.basename(str(argv0)) in NET_TOOLS:
                attempts.append(f"spawn {os.path.basename(str(argv0))}")
                raise OSError("network tool spawn refused in capture tests")
            super().__init__(args, *a, **k)
    monkeypatch.setattr(subprocess, "Popen", GuardedPopen)
    yield {"attempts": attempts, "log": log, "home": home}
    child = log.read_text() if log.exists() else ""
    assert not attempts and not child, f"network attempted: {attempts} {child}"
