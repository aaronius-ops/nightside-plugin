"""The per-token signing key for plugin-signed manifests (no network; upload.py stays the one network path).

The server mints it with the upload token (POST /api/upload-tokens -> "credential": nsu2.<nsu1 token>.<key>, the key
derived server-side from the upload keyring and the token id, so the server stores no new secret). The user pastes
that one string with `/planet remote token`; upload.save_token splits it (parse_credential) and keeps the key here as
nsk1.<kid>.<token id>.<key> (upload_signing_key, 600). The preview MACs each envelope with it (allowlist.sign_envelope). Revoking the
token, or retiring its keyring kid, makes every signature under it fail. Threat model: plugin README.
"""
from __future__ import annotations

import base64
import os
import re
from pathlib import Path

from capture import common as C

SIGNING_FILE = "upload_signing_key"
SIGNING_RE = re.compile(r"nsk1\.([a-z0-9][a-z0-9-]{0,15}\.[A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})")


CRED_RE = re.compile(r"nsu2\.(nsu1\.([a-z0-9][a-z0-9-]{0,15})\.([A-Za-z0-9_-]{20,400})\.[A-Za-z0-9_-]{43})"
                     r"\.([A-Za-z0-9_-]{43})")
JTI_RE = re.compile(r"[A-Za-z0-9_-]{22}")


def parse_credential(raw: str) -> tuple[str, str | None]:
    """The string the user pasted -> (nsu1 bearer token, nsk1 signing key or None). nsu2.<nsu1 token>.<key> carries
    both (one paste); a bare nsu1 token is accepted unsigned-only (key None). Raises ValueError otherwise."""
    import json
    raw = (raw or "").strip()
    if raw.startswith("nsu1."):
        return raw, None
    m = CRED_RE.fullmatch(raw)
    if not m:
        raise ValueError("that is not a Nightside upload credential (nsu2....) or token (nsu1....)")
    token, kid, payload, key = m.groups()
    try:
        jti = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("jti")
    except (ValueError, AttributeError):
        jti = None
    if not isinstance(jti, str) or not JTI_RE.fullmatch(jti):
        raise ValueError("that is not a Nightside upload credential (the token part is malformed)")
    return token, f"nsk1.{kid}.{jti}.{key}"


def signing_path(root: Path) -> Path:
    return root / SIGNING_FILE


def save_signing_key(root: Path, raw: str) -> str:
    """The per-token signing key the server returned with the upload token (nsk1.<kid>.<token id>.<key>). Stored 600
    beside the token; it never leaves this machine (the preview sends only the MAC it makes). Returns the key id."""
    raw = (raw or "").strip()
    m = SIGNING_RE.fullmatch(raw)
    if not m:
        raise ValueError("that is not a Nightside signing key (nsk1....)")
    C.atomic_write(signing_path(root), (raw + "\n").encode("ascii"))
    return m.group(1)


def load_signing_key(root: Path) -> tuple[str, bytes] | None:
    """(key id "<kid>.<token id>", key bytes) or None (no key: the preview saves an UNSIGNED envelope)."""
    try:
        fd = os.open(signing_path(root), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as f:
        t = f.read(200).decode("ascii", "replace").strip()
    m = SIGNING_RE.fullmatch(t)
    if not m:
        return None
    return m.group(1), base64.urlsafe_b64decode(m.group(2) + "=")


def clear_signing_key(root: Path) -> None:
    try:
        signing_path(root).unlink()
    except FileNotFoundError:
        pass
