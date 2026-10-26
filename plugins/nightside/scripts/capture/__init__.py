"""Nightside capture. LOCAL-ONLY: nothing in this package opens a network connection.

  hook.py       the capture hook: hook JSON on stdin -> one allow-listed line in the private local spool. Exits 0.
  surveyor.py   spool events (+ the repo's agent ledger rows) -> a WorkflowManifest per project, in the local outbox.
  allowlist.py  the fail-closed check every manifest passes before it is written, previewed or uploaded.
  consent.py    privacy settings and the "what would leave" preview (exact bytes + sha256); the confirmed upload
                calls upload.py, the one module that opens a connection, and only for bytes the user confirmed.
  rich.py       the opt-in rich tier: a <=60-word summary from the manifest itself, via `claude -p`. OFF by default.
  planet.py     the /planet command: name | privacy | invite | open | status | preview | upload |
                withdraw | remote.
  audit.py      the capture privacy auditor: synthetic and read-only real-transcript replays, red-team canaries.

Stdlib only, Python 3.9+.
"""

SPOOL_VERSION = 1
