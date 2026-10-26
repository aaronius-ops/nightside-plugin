"""Test-only network guard for child processes (put on PYTHONPATH by the capture tests' conftest). Never shipped to users; lives under tests/.

Default: every socket use is appended to $NIGHTSIDE_NET_GUARD_LOG and refused.
$NIGHTSIDE_NET_GUARD_ALLOW="host:port[,host:port]": connections to exactly those targets are allowed and logged to
$NIGHTSIDE_NET_GUARD_ALLOW_LOG; anything else is still refused and logged to $NIGHTSIDE_NET_GUARD_LOG. The guard is a
socket subclass (not a function), so modules that subclass socket.socket (ssl) still import."""
import os
import socket

_LOG = os.environ.get("NIGHTSIDE_NET_GUARD_LOG")
_ALLOW_LOG = os.environ.get("NIGHTSIDE_NET_GUARD_ALLOW_LOG")
_ALLOW = {x.strip() for x in os.environ.get("NIGHTSIDE_NET_GUARD_ALLOW", "").split(",") if x.strip()}
_real_socket = socket.socket
_real_gai = socket.getaddrinfo


def _write(path, line):
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{os.getpid()} {line}\n")


def _deny(what):
    def f(*a, **k):
        _write(_LOG, what)
        raise OSError(f"network disabled in capture tests ({what})")
    return f


def _target(addr):
    return f"{addr[0]}:{addr[1]}" if isinstance(addr, tuple) and len(addr) >= 2 else str(addr)


class _GuardedSocket(_real_socket):
    def __init__(self, *a, **k):
        if not _ALLOW:
            _write(_LOG, "socket.socket")
            raise OSError("network disabled in capture tests (socket.socket)")
        super().__init__(*a, **k)

    def connect(self, addr):
        t = _target(addr)
        if t in _ALLOW:
            _write(_ALLOW_LOG, f"connect {t}")
            return super().connect(addr)
        _write(_LOG, f"socket.connect {t}")
        raise OSError(f"network disabled in capture tests (connect {t})")

    def connect_ex(self, addr):
        self.connect(addr)
        return 0


def _gai(host, port, *a, **k):
    if f"{host}:{port}" in _ALLOW:
        return _real_gai(host, port, *a, **k)
    _write(_LOG, "socket.getaddrinfo")
    raise OSError("network disabled in capture tests (socket.getaddrinfo)")


socket.socket = _GuardedSocket
socket.getaddrinfo = _gai
for _name in ("socketpair", "fromfd"):
    if hasattr(socket, _name):
        setattr(socket, _name, _deny(f"socket.{_name}"))
if not _ALLOW:
    socket.create_connection = _deny("socket.create_connection")
