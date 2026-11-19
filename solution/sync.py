"""Deterministic cross-process rendezvous helpers.

Concurrency tests are only meaningful if the interleaving is *fixed*, not
hopeful.  Two primitives are used:

* :func:`barrier_wait` - every worker writes a "ready" file and blocks until a
  "go" file appears.  The parent creates the go file once all parties are
  ready, so worker N always enters its operation at the same logical moment.
* :func:`hold` - a worker stops at a named stage inside an operation, drops a
  signal file, and waits for a release file.  This pins one worker *inside* its
  write transaction while another one tries to act, which is the only way to
  prove that the second writer really blocks on the database lock instead of
  racing.

Both use small polling intervals and hard timeouts, so a stuck test fails
loudly rather than hanging.
"""

from __future__ import annotations

import os
import time

from .errors import GateError

POLL_S = 0.005
DEFAULT_TIMEOUT_S = 40.0


def _wait_for(path: str, timeout_s: float, label: str) -> None:
    deadline = time.monotonic() + timeout_s
    while not os.path.exists(path):
        if time.monotonic() >= deadline:
            raise GateError("E_BARRIER_TIMEOUT", f"timed out waiting for {label}", path=path)
        time.sleep(POLL_S)


def _touch(path: str) -> None:
    tmp = path + f".{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(str(os.getpid()))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def barrier_wait(directory: str, name: str, worker_id: str, parties: int,
                 timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
    """Block until ``parties`` workers have arrived, then let everyone through."""
    safe = worker_id.replace("/", "_").replace("\\", "_")
    ready = os.path.join(directory, f"{name}.{safe}.ready")
    _touch(ready)
    go = os.path.join(directory, f"{name}.go")
    deadline = time.monotonic() + timeout_s
    while not os.path.exists(go):
        if time.monotonic() >= deadline:
            raise GateError("E_BARRIER_TIMEOUT", f"barrier {name} never released", barrier=name)
        arrived = len([f for f in os.listdir(directory)
                       if f.startswith(f"{name}.") and f.endswith(".ready")])
        if arrived >= parties:
            try:
                _touch(go)
            except OSError:  # another worker won the race; that is fine
                pass
        time.sleep(POLL_S)


def hold(directory: str, stage: str, worker_id: str, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
    """Signal arrival at ``stage`` and block until the parent releases it."""
    safe = worker_id.replace("/", "_").replace("\\", "_")
    signal = os.path.join(directory, f"hold.{stage}.{safe}.reached")
    release = os.path.join(directory, f"hold.{stage}.{safe}.release")
    _touch(signal)
    _wait_for(release, timeout_s, f"release of stage {stage}")
