#!/usr/bin/env python3
"""Archive Claude Code transcripts into the private agent archive. Used by the plugin's SessionEnd and PreCompact
hooks (`archive.py --hook`, hook JSON on stdin) and by `/nightside-ledger` (`agent_ledger sync`).

Copies <transcript_path> and its <session>/subagents/ directory to
    <archive_root>/<project>/<session>/<session>.jsonl
    <archive_root>/<project>/<session>/subagents/agent-<id>.jsonl (+ .meta.json)
Incremental: a file is copied only when its size or mtime changed (transcripts only grow), atomically (temp file
opened O_EXCL|O_NOFOLLOW, then rename); temp files a killed run left behind are swept first. Directories 700 and
files 600 are re-applied on every run; umask 077. Symlinks are never followed: a symlinked transcript, subagent file
or archive directory is refused, and every archive directory must resolve under the root.

Refuses (logs and skips) an archive root that is inside a git work tree, under ~/Documents, ~/Desktop,
~/Library/Mobile Documents (iCloud) or ~/Library/CloudStorage (Drive, Dropbox, OneDrive), matched by file identity
and case-insensitively (APFS), through symlinks.
The hook never blocks or fails the session: it always exits 0; errors go to <archive_root>/_logs/archive-hook.log
(or ~/.nightside/logs/archive-hook.log when the root itself is refused).

Configuration, first match wins:
  archive root   $NIGHTSIDE_ARCHIVE_ROOT  >  config "archive_root"  >  ~/.nightside/agent-archive/raw
  project slug   $NIGHTSIDE_ARCHIVE_PROJECT  >  config "projects"[<git root or cwd>]  >  config "default_project"
                 >  the sanitized name of the git repository (the main repo for a worktree), else of the cwd
  disabled       $NIGHTSIDE_ARCHIVE=0 or config "enabled": false
Config file (optional; the defaults above need none): $NIGHTSIDE_ARCHIVE_CONFIG or ~/.config/nightside/archive.json:
  {"archive_root": "~/.nightside/agent-archive/raw", "enabled": true, "default_project": null,
   "projects": {"/abs/path/to/repo": "my-project"}}
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import sys
import time
from pathlib import Path

DEFAULT_ROOT = "~/.nightside/agent-archive/raw"
SID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
README = ("Nightside agent-work archive. PRIVATE: raw Claude Code transcripts (prompts, reports, tool output). "
          "Never commit, upload or share. Layout: <project>/<session>/<session>.jsonl + subagents/.\n")


class Refused(Exception):
    pass


def home() -> Path:
    return Path(os.path.expanduser("~")).resolve()


def load_config() -> dict:
    p = Path(os.environ.get("NIGHTSIDE_ARCHIVE_CONFIG") or "~/.config/nightside/archive.json").expanduser()
    try:
        c = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
        return c if isinstance(c, dict) else {}
    except (OSError, ValueError):
        return {}


def slug(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(s or "").lower()).strip("-")
    return s[:40] or "project"


def git_root(start: Path) -> tuple[Path | None, Path | None]:
    """(work tree root, main repo root). For a linked worktree the main repo is the one its .git file points into."""
    p = start
    for _ in range(64):
        g = p / ".git"
        if g.is_dir():
            return p, p
        if g.is_file():
            try:
                m = re.match(r"gitdir:\s*(.+)", g.read_text(encoding="utf-8").strip())
            except OSError:
                m = None
            if m:
                gd = Path(m.group(1))
                gd = gd if gd.is_absolute() else (p / gd)
                parts = gd.resolve().parts
                if "worktrees" in parts:
                    i = len(parts) - 1 - parts[::-1].index("worktrees")
                    return p, Path(*parts[:i]).parent  # <main>/.git/worktrees/<name> -> <main>
            return p, p
        if p.parent == p:
            break
        p = p.parent
    return None, None


def project_slug(cwd: Path, cfg: dict) -> str:
    if os.environ.get("NIGHTSIDE_ARCHIVE_PROJECT"):
        return slug(os.environ["NIGHTSIDE_ARCHIVE_PROJECT"])
    wt, main = git_root(cwd)
    projects = cfg.get("projects") or {}
    for k in (str(wt) if wt else None, str(main) if main else None, str(cwd)):
        if k and k in projects:
            return slug(projects[k])
    if cfg.get("default_project"):
        return slug(cfg["default_project"])
    return slug((main or cwd).name)


def archive_root(cfg: dict) -> Path:
    r = os.environ.get("NIGHTSIDE_ARCHIVE_ROOT") or cfg.get("archive_root") or DEFAULT_ROOT
    return Path(os.path.expanduser(r)).resolve()


SYNCED = ("Documents", "Desktop", "Library/Mobile Documents", "Library/CloudStorage")
TMP_RE = re.compile(r"^\..+\.(\d+)\.tmp$")


def _ancestors(p: Path):
    yield p
    yield from p.parents


def _ident(p: Path):
    try:
        st = os.stat(p)
        return (st.st_dev, st.st_ino)
    except OSError:
        return None


def check_root(root: Path) -> None:
    """Refuse a root under a cloud-synced folder or inside a git work tree. APFS and HFS+ are case-insensitive and
    paths may run through symlinks, so a synced folder is matched three ways: by identity (device + inode) against
    every existing ancestor of the root, by its resolved path, and case-folded."""
    root = Path(os.path.realpath(root))
    homes = {home(), Path(os.path.expanduser("~"))}
    for bad in SYNCED:
        for h in homes:
            b = h / bad
            ids = {_ident(b)} - {None}
            names = {str(b).casefold(), os.path.realpath(b).casefold()}
            for anc in _ancestors(root):
                s = str(anc).casefold()
                if s in names or (ids and _ident(anc) in ids):
                    raise Refused(f"archive root is under ~/{bad} (cloud-synced); choose a path such as {DEFAULT_ROOT}")
    for anc in _ancestors(root):
        if os.path.lexists(anc / ".git"):
            raise Refused("archive root is inside a git work tree; choose a path outside every repository")


def _no_link(p: Path) -> None:
    try:
        if stat.S_ISLNK(os.lstat(p).st_mode):
            raise Refused(f"refusing a symlink in the archive path: {p.name}")
    except FileNotFoundError:
        pass


def _secure_dir(d: Path, root: Path | None = None) -> None:
    _no_link(d)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode):
        raise Refused(f"archive path is not a directory: {d.name}")
    if root is not None and not Path(os.path.realpath(d)).is_relative_to(Path(os.path.realpath(root))):
        raise Refused("archive directory resolves outside the archive root")
    os.chmod(d, 0o700)


def _sweep(d: Path) -> int:
    """Remove temp files a killed copy left behind (raw transcript bytes must not linger outside the archive layout)."""
    n = 0
    try:
        names = os.listdir(d)
    except OSError:
        return 0
    for name in names:
        m = TMP_RE.match(name)
        if not m:
            continue
        pid, p = int(m.group(1)), d / name
        alive = pid == os.getpid()
        if not alive:
            try:
                os.kill(pid, 0)
                alive = True
            except ProcessLookupError:
                alive = False
            except OSError:
                alive = True
        try:
            if not alive or time.time() - os.lstat(p).st_mtime > 600:
                os.unlink(p)
                n += 1
        except OSError:
            pass
    return n


def _copy(src: Path, dst: Path) -> int:
    """Copy when changed; returns bytes copied (0 = up to date). Never follows a symlink at either end."""
    try:
        st = os.lstat(src)
    except OSError:
        return 0
    if not stat.S_ISREG(st.st_mode):
        return 0  # a symlinked or special source is never read
    _no_link(dst)
    try:
        dt = os.lstat(dst)
        if dt.st_size == st.st_size and dt.st_mtime_ns >= st.st_mtime_ns:
            os.chmod(dst, 0o600)
            return 0
    except FileNotFoundError:
        pass
    tmp = dst.with_name(f".{dst.name}.{os.getpid()}.tmp")
    fi = os.open(src, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        fo = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except BaseException:
        os.close(fi)
        raise
    try:
        with os.fdopen(fi, "rb") as r, os.fdopen(fo, "wb") as w:
            shutil.copyfileobj(r, w, 1 << 20)
        os.chmod(tmp, 0o600)
        os.utime(tmp, ns=(st.st_atime_ns, st.st_mtime_ns))
        os.replace(tmp, dst)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return st.st_size


def archive_session(transcript: Path, session_id: str, cwd: Path, cfg: dict) -> dict:
    os.umask(0o077)
    if not SID_RE.match(session_id or ""):
        raise Refused("session id is not a plain id")
    transcript = Path(transcript)
    if transcript.suffix != ".jsonl":
        raise Refused("transcript_path is not a .jsonl file")
    try:
        tst = os.lstat(transcript)
    except OSError:
        raise Refused("transcript_path does not exist") from None
    if not stat.S_ISREG(tst.st_mode):
        raise Refused("transcript_path is a symlink or not a regular file")
    root = archive_root(cfg)
    check_root(root)
    proj = project_slug(cwd, cfg)
    _secure_dir(root)
    readme = root / "README.txt"
    if not os.path.lexists(readme):
        fd = os.open(readme, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(README)
    dest = root / proj / session_id
    _secure_dir(root / proj, root)
    _secure_dir(dest, root)
    _sweep(dest)
    copied = files = 0
    copied += _copy(transcript, dest / f"{session_id}.jsonl")
    files += 1
    sub = transcript.parent / transcript.stem / "subagents"
    if sub.is_dir() and not sub.is_symlink() and not (transcript.parent / transcript.stem).is_symlink():
        _secure_dir(dest / "subagents", root)
        _sweep(dest / "subagents")
        for f in sorted(sub.iterdir()):
            if f.name.startswith("agent-") and f.suffix in (".jsonl", ".json"):
                n = _copy(f, dest / "subagents" / f.name)
                copied += n
                files += 1 if (dest / "subagents" / f.name).exists() else 0
    return {"project": proj, "session": session_id, "files": files, "bytes_copied": copied, "dest": str(dest)}


def _log(cfg: dict, line: str) -> None:
    try:
        root = archive_root(cfg)
        try:
            check_root(root)
            d = root / "_logs"
        except Refused:
            d = home() / ".nightside" / "logs"
        _secure_dir(d)
        p = d / "archive-hook.log"
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + line + "\n")
    except Exception:  # noqa: BLE001 - logging must never fail the hook
        pass


def hook_main() -> int:
    """SessionEnd / PreCompact: stdin {session_id, transcript_path, cwd, hook_event_name, ...}. Always exits 0."""
    os.umask(0o077)  # before anything is created, on every path (a refused root still writes the fallback log)
    cfg = {}
    t0 = time.monotonic()
    try:
        cfg = load_config()
        if os.environ.get("NIGHTSIDE_ARCHIVE") == "0" or cfg.get("enabled") is False:
            return 0
        d = json.loads(sys.stdin.read() or "{}")
        ev = str(d.get("hook_event_name") or "?")[:20]
        r = archive_session(Path(d.get("transcript_path") or ""), str(d.get("session_id") or ""),
                            Path(d.get("cwd") or os.getcwd()), cfg)
        _log(cfg, f"ok {ev} {r['project']}/{r['session']} files={r['files']} copied={r['bytes_copied']} "
                  f"ms={int((time.monotonic() - t0) * 1000)}")
    except Refused as e:
        _log(cfg, f"refused: {e}")
    except Exception as e:  # noqa: BLE001
        _log(cfg, f"error: {type(e).__name__}: {str(e)[:200]}")
    return 0


# ------------------------------------------------------------------------------------- manual sync ---
def claude_projects_dir() -> Path:
    base = os.environ.get("CLAUDE_CONFIG_DIR") or "~/.claude"
    return Path(os.path.expanduser(base)) / "projects"


def project_dir_for(cwd: Path) -> Path:
    """Claude Code's per-directory transcript folder: the absolute cwd with every non-alphanumeric char as '-'."""
    return claude_projects_dir() / re.sub(r"[^A-Za-z0-9]", "-", str(cwd))


def add_sync_args(p) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--latest", action="store_true", help="the most recently written session of this directory")
    g.add_argument("--all", action="store_true", help="every session of this directory")
    g.add_argument("--session")
    p.add_argument("--transcript", help="with --session: the transcript path (default: looked up)")
    p.add_argument("--cwd", default=None)


def cmd_sync(a) -> int:
    os.umask(0o077)
    cfg = load_config()
    cwd = Path(a.cwd or os.getcwd()).resolve()
    pd = project_dir_for(cwd)
    if a.session:
        targets = [Path(a.transcript) if a.transcript else pd / f"{a.session}.jsonl"]
    else:
        targets = sorted(pd.glob("*.jsonl"), key=lambda f: f.stat().st_mtime) if pd.is_dir() else []
        if not a.all:
            targets = targets[-1:]
    if not targets:
        print(f"sync: no transcripts for this directory (looked in {pd.name})", file=sys.stderr)
        return 1
    rc = 0
    for t in targets:
        try:
            r = archive_session(t, a.session or t.stem, cwd, cfg)
            print(f"archived {r['project']}/{r['session']}: {r['files']} files, {r['bytes_copied']} bytes copied")
        except Refused as e:
            print(f"sync refused: {e}", file=sys.stderr)
            rc = 2
    return rc


if __name__ == "__main__":
    if "--hook" in sys.argv[1:]:
        sys.exit(hook_main())
    import argparse
    ap = argparse.ArgumentParser(prog="archive.py")
    add_sync_args(ap)
    sys.exit(cmd_sync(ap.parse_args()))
