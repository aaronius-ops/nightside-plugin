"""The plugin's ONE network module: send the exact bytes a user confirmed to the Nightside server they configured.

send() is called from exactly one place, consent.upload(), and only after all of these hold:
  * the user ran the preview, which saved the bytes it showed (outbox/<project_id>.envelope), and confirmed their
    sha256 with `/planet upload --confirm <sha256>`;
  * the saved bytes re-pass the allow-list (consent.saved) and are the canonical bytes the server will hash;
  * the user configured BOTH a server base URL (`/planet remote set <url>`, config key "upload_endpoint") and an
    upload token (`/planet remote token`, file <capture root>/upload_token, 600).
There is no default server: a fresh install has no endpoint, so the preview and confirm stay local ("no network call
was made"). Use a domain you control for the base URL (for example https://nightside.world), never a raw *.run.app
host: the URL is the only thing the plugin knows about where Nightside runs, so the server can move between cloud
projects without any plugin change.

Before the POST, the plugin asks the server GET <base>/api/plugin (no token, no body) which plugin version it needs
(`min_version`) and stops with a clear message when this plugin is older: a plugin built before signed manifests would
otherwise upload unsigned bytes the server can never publish (check_server below).

Withdraw (`/planet withdraw --confirm <project id>`, consent.withdraw) is the other request: an HTTPS DELETE of that
project's manifests with the same token, so a user can take back what they uploaded.

Transport: one HTTPS POST of the confirmed bytes to <base>/api/manifests with `Authorization: Bearer <token>` and
`Content-Type: application/json`. Redirects are refused (a redirect would carry the token elsewhere). Plain http is
accepted only for a loopback host (local development and tests).
"""
from __future__ import annotations

import base64
import json
import os
import re
import urllib.parse  # URL parsing only (no I/O); the transport modules are imported inside send()
from pathlib import Path

from capture import common as C

PATH = "/api/manifests"
INFO_PATH = "/api/plugin"
MANIFEST_FILE = Path(__file__).resolve().parents[2] / ".claude-plugin" / "plugin.json"  # <plugin root>/.claude-plugin
TOKEN_FILE = "upload_token"
TOKEN_RE = re.compile(r"nsu1\.[a-z0-9][a-z0-9-]{0,15}\.[A-Za-z0-9_-]{20,400}\.[A-Za-z0-9_-]{43}")
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
TIMEOUT_S = 20
MAX_RESPONSE = 4096


class BadEndpoint(ValueError):
    pass


def check_endpoint(url: str) -> tuple[str, str | None]:
    """(normalised base URL, warning or None). https only, except http on a loopback host; no user, query or fragment;
    the path is the base (the plugin appends /api/manifests)."""
    try:
        u = urllib.parse.urlsplit((url or "").strip())
    except ValueError:
        raise BadEndpoint("not a URL") from None
    host = (u.hostname or "").lower()
    if u.scheme not in ("https", "http") or not host:
        raise BadEndpoint("use https://<your domain>")
    if u.scheme == "http" and host not in LOOPBACK:
        raise BadEndpoint("plain http is allowed only for a loopback address (local development)")
    if u.username or u.password or u.query or u.fragment or "@" in u.netloc:
        raise BadEndpoint("no user, query or fragment in the base URL")
    if u.path not in ("", "/"):
        raise BadEndpoint("give the base URL only (for example https://nightside.world)")
    try:
        port = u.port
    except ValueError:
        raise BadEndpoint("bad port") from None
    netloc = (f"[{host}]" if ":" in host else host) + (f":{port}" if port else "")
    warn = None
    if host.endswith(".run.app"):
        warn = ("that is a raw Cloud Run host; ask the planet owner for the domain they control (it survives a move "
                "to another cloud project)")
    return f"{u.scheme}://{netloc}", warn


def token_path(root: Path) -> Path:
    return root / TOKEN_FILE


def save_token(root: Path, token: str) -> dict:
    """One paste: an nsu2 credential (token + manifest signing key: uploads are signed) or a bare nsu1 token
    (unsigned-only: any signing key saved for an earlier token is removed). Nothing is saved on a malformed value."""
    from capture import signing as SK  # local key file only
    token, key = SK.parse_credential(token)
    if not TOKEN_RE.fullmatch(token):
        raise ValueError("that is not a Nightside upload token (nsu1....)")
    C.ensure_root(root)
    if key is not None:
        SK.save_signing_key(root, key)
    else:
        SK.clear_signing_key(root)
    C.atomic_write(token_path(root), (token + "\n").encode("ascii"))
    return {**describe(token), "signed": key is not None}


def load_token(root: Path) -> str | None:
    p = token_path(root)
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as f:
        t = f.read(600).decode("ascii", "replace").strip()
    return t if TOKEN_RE.fullmatch(t) else None


def clear_token(root: Path) -> None:
    try:
        token_path(root).unlink()
    except FileNotFoundError:
        pass


def describe(token: str) -> dict:
    """What the token says about itself (key id, planet, expiry); never the token."""
    try:
        _, kid, payload, _ = token.split(".")
        c = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return {"kid": kid, "planet": c.get("pln"), "user": c.get("sub"), "expires": c.get("exp")}
    except (ValueError, AttributeError):
        return {}


def configured(cfg: dict, root: Path) -> tuple[str, str] | None:
    """(base URL, token) when BOTH are set and valid; None otherwise (the default: nothing is sent)."""
    ep = cfg.get("upload_endpoint")
    if not ep:
        return None
    try:
        base, _ = check_endpoint(ep)
    except BadEndpoint:
        return None
    tok = load_token(root)
    return (base, tok) if tok else None


def send(base: str, token: str, body: bytes, timeout: float = TIMEOUT_S) -> tuple[int, dict]:
    """POST the bytes. (HTTP status, parsed JSON body or {}); status 0 = no answer (network error). The transport is
    imported here, so no other path even loads it."""
    import urllib.error
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # refuse every redirect (token stays put)
            return None
    req = urllib.request.Request(base + PATH, data=body, method="POST", headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {token}", "Accept": "application/json",
        "User-Agent": "nightside-plugin-capture"})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as r:
            status, raw = r.status, r.read(MAX_RESPONSE)
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read(MAX_RESPONSE) if e.fp else b""
    except (urllib.error.URLError, OSError, ValueError) as e:
        return 0, {"error": type(e).__name__}
    try:
        doc = json.loads(raw.decode("utf-8", "replace")) if raw else {}
    except ValueError:
        doc = {}
    return status, doc if isinstance(doc, dict) else {}


def withdraw_project(base: str, token: str, project_id: str, timeout: float = TIMEOUT_S) -> tuple[int, dict]:
    """DELETE <base>/api/manifests/projects/<project_id>: the server deletes every manifest of that project that THIS
    token's user uploaded (it never touches anyone else's). No body leaves, only the project id in the path and the
    bearer token. (HTTP status, parsed JSON body or {}); status 0 = no answer. Same transport rules as send():
    imported here, redirects refused. Called only from consent.withdraw(), after the user named the project id."""
    import urllib.error
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    if not C.HEX16.fullmatch(project_id or ""):
        raise ValueError("not a project id")
    req = urllib.request.Request(base + PATH + "/projects/" + project_id, method="DELETE", headers={
        "Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "nightside-plugin-capture"})
    try:
        with urllib.request.build_opener(_NoRedirect()).open(req, timeout=timeout) as r:
            status, raw = r.status, r.read(MAX_RESPONSE)
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read(MAX_RESPONSE) if e.fp else b""
    except (urllib.error.URLError, OSError, ValueError) as e:
        return 0, {"error": type(e).__name__}
    try:
        doc = json.loads(raw.decode("utf-8", "replace")) if raw else {}
    except ValueError:
        doc = {}
    return status, doc if isinstance(doc, dict) else {}


# ----------------------------------------------------------------------------- plugin <-> server pairing ---
def plugin_version() -> str:
    """This plugin's own version (.claude-plugin/plugin.json); "0.0.0" when unreadable (treated as older than any minimum)."""
    try:
        v = json.loads(MANIFEST_FILE.read_text(encoding="utf-8")).get("version")
        return v if isinstance(v, str) else "0.0.0"
    except (OSError, ValueError):
        return "0.0.0"


_VER = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?")


def version_key(v: str) -> tuple:
    """Sortable key for "1.2.3" or "1.2.3-rc.1": a release outranks any of its pre-releases; pre-release identifiers
    compare numerically when numeric, else as text, numbers below text (semver precedence). Unparseable = oldest."""
    m = _VER.fullmatch((v or "").strip())
    if not m:
        return ((0, 0, 0), (0,))
    core = tuple(int(x) for x in m.groups()[:3])
    pre = m.group(4)
    if pre is None:
        return (core, (2,))
    return (core, (1,) + tuple((0, int(i), "") if i.isdigit() else (1, 0, i) for i in pre.split(".")))


def ask_server(base: str, timeout: float = TIMEOUT_S) -> tuple[int, dict]:
    """GET <base>/api/plugin. (HTTP status, parsed JSON body or {}); status 0 = no answer. Anonymous: no token leaves.
    Like send(), the transport is imported here and redirects are refused."""
    import urllib.error
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    req = urllib.request.Request(base + INFO_PATH, method="GET", headers={
        "Accept": "application/json", "User-Agent": "nightside-plugin-capture"})
    try:
        with urllib.request.build_opener(_NoRedirect()).open(req, timeout=timeout) as r:
            status, raw = r.status, r.read(MAX_RESPONSE)
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read(MAX_RESPONSE) if e.fp else b""
    except (urllib.error.URLError, OSError, ValueError) as e:
        return 0, {"error": type(e).__name__}
    try:
        doc = json.loads(raw.decode("utf-8", "replace")) if raw else {}
    except ValueError:
        doc = {}
    return status, doc if isinstance(doc, dict) else {}


def check_server(base: str, mine: str | None = None) -> tuple[bool, int, str]:
    """(ok, exit code, message). ok=False stops the upload before any manifest bytes leave: the server cannot be reached
    (code 5, same words as a failed upload) or says this plugin is older than its `min_version` (code 7). A server that
    has no /api/plugin route (404), answers with an error, or sends something unreadable does not block the upload: the
    upload route itself still decides, and says why."""
    status, doc = ask_server(base)
    if status == 0:
        return False, 5, f"Could not reach {base} ({doc.get('error', 'network error')}). Nothing was stored; try again."
    need = doc.get("min_version") if status == 200 else None
    if not isinstance(need, str) or not _VER.fullmatch(need.strip()):
        return True, 0, ""
    mine = plugin_version() if mine is None else mine
    if version_key(mine) < version_key(need):
        notes = doc.get("notes_url")
        more = f" See {notes}" if isinstance(notes, str) and notes.startswith("https://") else ""
        return False, 7, (f"Your Nightside plugin is {mine}; {base} needs {need.strip()} or newer. Update the Nightside plugin "
                          f"to that version, then preview and confirm again. "
                          f"Nothing was sent.{more}")
    return True, 0, ""
