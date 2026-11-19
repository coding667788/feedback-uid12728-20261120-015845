"""Worker entry point used to run operations in their own OS process.

Reads a JSON job from stdin, executes it against one database, prints the JSON
result on stdout.  ``crash_at`` in a publish operation hard-exits this process;
that is how the tests kill a writer mid-publish without touching the test
runner.
"""

from __future__ import annotations

import json
import sys

from .errors import GateError
from .runner import run_operation


def main() -> int:
    payload = json.loads(sys.stdin.read() or "{}")
    db_path = payload["db"]
    env = dict(payload.get("env") or {})
    records = []
    for op in payload.get("ops", []):
        records.append(run_operation(db_path, op, env))
    json.dump({"records": records}, sys.stdout)
    sys.stdout.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
