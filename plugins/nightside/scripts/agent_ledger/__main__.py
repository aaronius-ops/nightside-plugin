"""`python3 <plugin>/scripts/agent_ledger ...` or `python3 -m agent_ledger ...` (with scripts/ on the path)."""
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from agent_ledger.cli import main
else:
    from .cli import main

sys.exit(main())
