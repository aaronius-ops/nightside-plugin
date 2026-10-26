"""Shared paths, configuration, keyed hashing and safe file writes for capture. Reuses the archive hook's safe-path
helpers (agent_ledger/archive.py): the capture root is refused inside a git work tree or a cloud-synced folder
(~/Documents, ~/Desktop, iCloud, ~/Library/CloudStorage), directories are 700 and files 600, symlinks are refused.

Layout under the capture root (default ~/.nightside/capture):
  key                       32 random bytes (hex), 600. Keys every hash below; never leaves the machine.
  spool/<project_id>/<session_hash>.jsonl   the event stream (hook.py)
  projects.json             local-only index {project_id: {"name": <repo slug>, "ledger": <path or null>}}
  names.json                local-only reverse map of hashed MCP server names / custom agent types (owner's preview)
  sessions/<project_id>/<session_hash>.json   per-session summaries of closed sessions (surveyor.py)
  outbox/<project_id>.json  the latest surveyed WorkflowManifest (surveyor.py)
  outbox/<project_id>.envelope   the exact bytes the last /planet preview showed (what --confirm would send)
  .lock                     fcntl lock for the index files
  .spool.lock               fcntl lock for summary writes + spool eviction (surveyor.load_partials / retention)
  _logs/capture-hook.log    errors and refusals

Configuration, first match wins:
  root      $NIGHTSIDE_CAPTURE_ROOT  >  config "capture_root"  >  ~/.nightside/capture
  disabled  $NIGHTSIDE_CAPTURE=0 or config "enabled": false
  retention config "spool_retention_days" (30): raw spool of summarized sessions idle longer is folded + deleted;
            "summary_retention_days" (365): older session summaries are deleted (that history is then gone);
            "max_capture_mb" (32): above it, raw spool of CLOSED summarized sessions is folded + deleted, oldest
            first; the size cap never deletes a summary or an open session's spool (see surveyor.retention)
  config    $NIGHTSIDE_CAPTURE_CONFIG or ~/.config/nightside/capture.json (written by /planet)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent.parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from agent_ledger import archive as _arch  # noqa: E402  (safe-path helpers shared with the archive hook)

Refused = _arch.Refused
check_root = _arch.check_root
secure_dir = _arch._secure_dir
git_root = _arch.git_root
slug = _arch.slug

DEFAULT_ROOT = "~/.nightside/capture"
HEX16 = re.compile(r"^[0-9a-f]{16}$")
SID_RE = _arch.SID_RE

TIERS = ("rich", "metadata")
VISIBILITY = ("public", "private")
DEFAULTS = {"enabled": True, "privacy_tier": "metadata", "default_visibility": "private", "rich_summary": False,
            "planet_name": None, "projects": {}, "spool_retention_days": 30, "summary_retention_days": 365, "max_capture_mb": 32,
            "upload_endpoint": None}


def config_path() -> Path:
    return Path(os.environ.get("NIGHTSIDE_CAPTURE_CONFIG") or "~/.config/nightside/capture.json").expanduser()


def load_config() -> dict:
    cfg = json.loads(json.dumps(DEFAULTS))
    p = config_path()
    try:
        c = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
    except (OSError, ValueError):
        c = {}
    if isinstance(c, dict):
        cfg.update({k: v for k, v in c.items() if k in DEFAULTS or k == "capture_root"})
    if cfg.get("privacy_tier") not in TIERS:
        cfg["privacy_tier"] = "metadata"
    if cfg.get("default_visibility") not in VISIBILITY:
        cfg["default_visibility"] = "private"
    if not isinstance(cfg.get("projects"), dict):
        cfg["projects"] = {}
    if not isinstance(cfg.get("upload_endpoint"), str):
        cfg["upload_endpoint"] = None  # no default server, ever: nothing can leave until the user sets one
    return cfg


def save_config(cfg: dict) -> Path:
    p = config_path()
    os.umask(0o077)
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_write(p, (json.dumps(cfg, indent=2, sort_keys=True) + "\n").encode())
    return p


def enabled(cfg: dict) -> bool:
    return os.environ.get("NIGHTSIDE_CAPTURE") != "0" and cfg.get("enabled") is not False


def capture_root(cfg: dict) -> Path:
    r = os.environ.get("NIGHTSIDE_CAPTURE_ROOT") or cfg.get("capture_root") or DEFAULT_ROOT
    root = Path(os.path.expanduser(r)).resolve()
    check_root(root)
    return root


def ensure_root(root: Path) -> Path:
    os.umask(0o077)
    check_root(root)
    secure_dir(root)
    return root


KEY_RE = re.compile(rb"[0-9a-f]{64}\n?")


def _read_key(p: Path) -> bytes | None:
    """The key, or None when there is no key file. A key file that is not exactly 64 hex characters is refused."""
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as f:
        raw = f.read(200)
    if not KEY_RE.fullmatch(raw):
        raise Refused("capture key file is empty or corrupt; capture is off until it is fixed (delete it to rotate)")
    return bytes.fromhex(raw[:64].decode("ascii"))


def install_key(root: Path) -> bytes:
    """The per-install hash key, 32 bytes. Hashes are stable on this machine and not reversible without it: a project
    id cannot be brute-forced from a list of likely repo names.

    Created once, race-free: the key is written in full to a private temp file, fsynced, then published with
    os.link (which fails if a key already exists), so a reader never sees a partial key. A key file that exists but
    is not exactly 64 hex characters (a crash, a full disk, a hand edit) fails closed: Refused, nothing is recorded,
    the hook logs it. Never a fallback key."""
    p = root / "key"
    k = _read_key(p)
    if k is not None:
        return k
    ensure_root(root)
    tmp = root / f".key.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_hex(32).encode("ascii") + b"\n")
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(tmp, p)
        except FileExistsError:
            pass  # another hook published first: use its key
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    k = _read_key(p)
    if k is None or len(k) != 32:
        raise Refused("capture key could not be created")
    return k


def kh(key: bytes, kind: str, value: str, n: int = 16) -> str:
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise Refused("capture key is not 32 bytes")
    return hmac.new(key, f"{kind}\0{value}".encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:n]


def project_dir(payload_cwd) -> Path | None:
    """The project's directory: $CLAUDE_PROJECT_DIR (stable for the session), else the hook's cwd."""
    d = os.environ.get("CLAUDE_PROJECT_DIR") or payload_cwd
    if not isinstance(d, str) or not d.startswith("/"):
        return None
    return Path(d)


def project_identity(key: bytes, pdir: Path) -> tuple[str, str]:
    """(project_id, local slug). Keyed on the main repository root (so linked worktrees and subdirectories of one
    repo are one project), else the directory itself. The slug is for the local index only."""
    _, main = git_root(pdir)
    base = main or pdir
    return kh(key, "project", str(base)), slug(base.name)


def atomic_write(p: Path, data: bytes) -> None:
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def append_line(p: Path, line: bytes) -> None:
    """One os.write of one short line with O_APPEND (lines stay whole across concurrent async hooks)."""
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)


def iso_ms(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1000):03d}Z"


def log(root: Path | None, line: str) -> None:
    try:
        d = None
        if root is not None:
            try:
                check_root(root)
                d = root / "_logs"
            except Refused:
                d = None
        if d is None:
            d = _arch.home() / ".nightside" / "logs"
        secure_dir(d)
        fd = os.open(d / "capture-hook.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
                     0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + line[:300] + "\n")
    except Exception:  # noqa: BLE001 - logging must never fail the hook
        pass


class _Lock:
    """An exclusive fcntl lock on <root>/.lock for read-modify-write of the small local index files."""

    def __init__(self, root: Path):
        self.p = root / ".lock"

    def __enter__(self):
        import fcntl
        self.fd = os.open(self.p, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        import fcntl
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


SPOOL_LOCK = ".spool.lock"


class try_lock:
    """An exclusive fcntl lock on <root>/<name>, waited on for at most `wait` seconds. `with try_lock(...) as held:`
    held is False when another process (or thread) still holds it, so the caller skips its work instead of
    blocking a hook. Never raises an OSError (a lock that cannot be opened is reported as not held)."""

    def __init__(self, root: Path, name: str = SPOOL_LOCK, wait: float = 2.0):
        self.p, self.wait, self.fd, self.held = Path(root) / name, wait, None, False

    def __enter__(self) -> bool:
        import fcntl
        try:
            self.fd = os.open(self.p, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except OSError:
            return False
        deadline = time.monotonic() + max(self.wait, 0.0)
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.held = True
                return True
            except OSError:
                if time.monotonic() >= deadline:
                    return False
                time.sleep(0.02)

    def __exit__(self, *exc):
        import fcntl
        if self.fd is not None:
            try:
                if self.held:
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd, self.held = None, False


def _read_json(p: Path) -> dict:
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def read_index(root: Path) -> dict:
    return _read_json(root / "projects.json")


def read_names(root: Path) -> dict:
    """Local-only reverse map {"srv-<hash>": server name, "custom-<hash>": agent type} for the owner's preview."""
    return _read_json(root / "names.json")


def _merge(root: Path, fname: str, new: dict) -> None:
    """Add entries under the lock; atomic replace; no write when nothing is new."""
    p = root / fname
    if all(_read_json(p).get(k) == v for k, v in new.items()):
        return
    with _Lock(root):
        d = _read_json(p)
        if all(d.get(k) == v for k, v in new.items()):
            return
        d.update(new)
        atomic_write(p, (json.dumps(d, indent=1, sort_keys=True) + "\n").encode())


def note_project(root: Path, pid: str, name: str, ledger: str | None = None) -> None:
    _merge(root, "projects.json", {pid: {"name": name, "ledger": ledger}})


def note_names(root: Path, names: dict) -> None:
    if names:
        _merge(root, "names.json", names)


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
