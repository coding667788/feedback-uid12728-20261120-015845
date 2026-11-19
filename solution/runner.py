"""Case file runner.

A case file is a JSON document:

.. code-block:: json

    {
      "case_id": "demo",
      "schema_version": 1,
      "initial": {...registries...},
      "operations": [{"op": "precheck", ...}],
      "workers": [{"worker_id": "w1", "operations": [...]}]
    }

The runner executes ``operations`` serially.  ``workers`` are separate OS
processes launched against the same database, which is how concurrent approve /
revoke / publish contention is exercised.  Every operation records either its
result or a stable error code; the resulting report is deterministic given the
same inputs.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from typing import Any

from . import db
from .errors import GateError
from .model import parse_initial
from .ops import dispatch
from .store import bootstrap

SCHEMA_VERSION = 1
PLACEHOLDER_RE = ("${",)


# ---------------------------------------------------------------------------
# placeholder interpolation
# ---------------------------------------------------------------------------


def _interp(value: Any, env: dict[str, Any]) -> Any:
    """Substitute ``${name}`` (whole string) or embedded ``${name}`` references."""
    if isinstance(value, str):
        if value.startswith("${") and value.endswith("}"):
            key = value[2:-1]
            if key not in env:
                raise GateError("E_UNKNOWN_REF", f"placeholder {value} has no value", placeholder=key)
            return env[key]
        if "${" in value:
            out = value
            for key, val in env.items():
                out = out.replace("${" + key + "}", str(val))
            return out
        return value
    if isinstance(value, list):
        return [_interp(v, env) for v in value]
    if isinstance(value, dict):
        return {k: _interp(v, env) for k, v in value.items()}
    return value


def _interp_op(op: dict[str, Any], env: dict[str, Any]) -> dict[str, Any]:
    return _interp(op, env)


# ---------------------------------------------------------------------------
# single operation
# ---------------------------------------------------------------------------


_ACTIVE_SPEC: dict[str, Any] | None = None


def set_sync_spec(spec: dict[str, Any] | None) -> None:
    """Publish the current worker's rendezvous spec for ``ops._hook``."""
    global _ACTIVE_SPEC
    _ACTIVE_SPEC = spec
    from . import ops as _ops

    _ops._LIFECYCLE.clear()
    if spec:
        _ops._LIFECYCLE.append(spec)


def run_operation(db_path: str, raw_op: dict[str, Any], env: dict[str, Any]) -> dict[str, Any]:
    """Execute one operation, capturing success or a stable error code."""
    expect = raw_op.get("expect")
    label = raw_op.get("label")
    name = raw_op.get("op", "<missing>")
    record: dict[str, Any] = {"op": name, "label": label, "request_id": raw_op.get("request_id")}
    sync_spec = raw_op.get("sync")
    saved = _ACTIVE_SPEC
    if isinstance(sync_spec, dict):
        set_sync_spec({**saved, **sync_spec} if saved else dict(sync_spec))
    try:
        op = _interp_op(raw_op, env)
        op.pop("expect", None)
        op.pop("label", None)
        op.pop("sync", None)
        result = dispatch(db_path, op)
        record["ok"] = True
        record["result"] = result
        if isinstance(result, dict):
            prefix = label or name
            for k in ("receipt_id", "precheck_token", "basis", "approval_id", "waiver_id",
                      "current_evidence_hash", "recorded_evidence_hash", "evidence_hash"):
                if isinstance(result.get(k), str):
                    env[f"{prefix}.{k}"] = result[k]
            env[f"{prefix}.result"] = result
        if expect is not None:
            record["expectation"] = _check_expectation(expect, result, None)
    except GateError as exc:
        record["ok"] = False
        record["error"] = exc.as_dict()
        if expect is not None:
            record["expectation"] = _check_expectation(expect, None, exc)
    finally:
        if isinstance(sync_spec, dict):
            set_sync_spec(saved)
    return record


def _check_expectation(expect: Any, result: dict[str, Any] | None, exc: GateError | None) -> dict[str, Any]:
    """Compare an operation's outcome with the case's declared expectation."""
    checks: list[dict[str, Any]] = []
    if isinstance(expect, dict):
        if "ok" in expect:
            checks.append({"field": "ok", "expected": expect["ok"], "actual": exc is None,
                           "pass": bool(expect["ok"]) == (exc is None)})
        if "code" in expect:
            actual = exc.code if exc else ""
            checks.append({"field": "code", "expected": expect["code"], "actual": actual,
                           "pass": actual == expect["code"]})
        for key, want in (expect.get("fields") or {}).items():
            actual = None if result is None else _dig(result, key)
            checks.append({"field": key, "expected": want, "actual": actual, "pass": actual == want})
    return {"pass": all(c["pass"] for c in checks), "checks": checks}


def _dig(obj: Any, dotted: str) -> Any:
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


# ---------------------------------------------------------------------------
# workers (separate OS processes)
# ---------------------------------------------------------------------------


def _worker_entry(db_path: str, ops: list[dict[str, Any]], env: dict[str, Any], out_path: str) -> None:
    records = [run_operation(db_path, op, env) for op in ops]
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump({"records": records, "env": {k: v for k, v in env.items() if not k.endswith(".result")}}, fh)
    sys.stdout.flush()


def run_workers(db_path: str, workers: list[dict[str, Any]], env: dict[str, Any],
                workdir: str) -> list[dict[str, Any]]:
    """Start every worker as a real subprocess and collect its records.

    Workers run concurrently against the same database file.  Each gets an
    optional ``sync`` directory so operations can rendezvous deterministically.
    """
    import multiprocessing as mp

    sync_dir = os.path.join(workdir, "sync")
    os.makedirs(sync_dir, exist_ok=True)
    ctx = mp.get_context("spawn")
    out_paths = [os.path.join(workdir, f"worker_{i}.json") for i in range(len(workers))]
    procs = []
    for i, w in enumerate(workers):
        wenv = dict(env)
        wenv.update({f"worker.{k}": v for k, v in (w.get("vars") or {}).items()})
        worker_id = w.get("worker_id", f"w{i}")
        ops = []
        worker_sync = dict(w.get("sync") or {})
        worker_sync.setdefault("dir", sync_dir)
        worker_sync.setdefault("worker", worker_id)
        worker_sync.setdefault("parties", len(workers))
        for raw in w.get("operations", []):
            op = dict(raw)
            op["sync"] = {**worker_sync, **(op.get("sync") or {})}
            ops.append(op)
        p = ctx.Process(
            target=_worker_entry,
            args=(db_path, ops, wenv, out_paths[i]),
            name=worker_id,
        )
        procs.append(p)
    for p in procs:
        p.start()
    for p in procs:
        p.join()

    results = []
    for i, w in enumerate(workers):
        records: list[dict[str, Any]] = []
        if os.path.exists(out_paths[i]):
            with open(out_paths[i], "r", encoding="utf-8") as fh:
                records = json.load(fh)["records"]
        elif procs[i].exitcode not in (0, None):
            records = [{"op": "<worker>", "ok": False,
                        "error": {"code": "E_WORKER_DIED", "detail": f"exit {procs[i].exitcode}"}}]
        results.append({
            "worker_id": w.get("worker_id", f"w{i}"),
            "exitcode": procs[i].exitcode,
            "records": records,
        })
    return results


def run_subprocess_ops(db_path: str, ops: list[dict[str, Any]], env: dict[str, Any]) -> list[dict[str, Any]]:
    """Run a batch of ops through ``python -m solution.worker``.

    Using the module entry point rather than an in-process call is what lets a
    test kill the writer at a chosen point and then inspect the database from
    the outside.
    """
    payload = json.dumps({"db": db_path, "ops": ops, "env": env})
    proc = subprocess.run(
        [sys.executable, "-I", "-m", "solution.worker"],
        input=payload,
        capture_output=True,
        text=True,
        cwd=os.getcwd(),
    )
    if proc.stdout.strip():
        try:
            return json.loads(proc.stdout)["records"]
        except json.JSONDecodeError:
            pass
    return [{"op": "<crashed>", "ok": False,
             "error": {"code": "E_WORKER_DIED", "detail": proc.stderr[-2000:]},
             "exitcode": proc.returncode}]


# ---------------------------------------------------------------------------
# case execution
# ---------------------------------------------------------------------------


@dataclass
class CaseReport:
    case_id: str
    db_path: str
    records: list[dict[str, Any]] = field(default_factory=list)
    workers: list[dict[str, Any]] = field(default_factory=list)
    final: dict[str, Any] = field(default_factory=dict)
    final_views: list[dict[str, Any]] = field(default_factory=list)
    workdir: str = ""
    failures: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "ok": not self.failures,
            "failures": self.failures,
            "operations": self.records,
            "workers": self.workers,
            "final_views": self.final_views,
            "final": self.final,
        }


def load_case(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        case = json.load(fh)
    if not isinstance(case, dict):
        raise GateError("E_INPUT", "case file must contain a JSON object")
    version = case.get("schema_version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise GateError("E_INPUT_VERSION", f"schema_version {version!r} is not supported",
                        supported=SCHEMA_VERSION)
    return case


def run_case(case: dict[str, Any], workdir: str | None = None, keep: bool = False) -> CaseReport:
    case_id = case.get("case_id", "case")
    workdir = workdir or tempfile.mkdtemp(prefix=f"gate-{case_id}-")
    db_path = os.path.join(workdir, "gate.db")
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(db_path + suffix):
            os.remove(db_path + suffix)
    db.initialize(db_path)

    report = CaseReport(case_id=case_id, db_path=db_path, workdir=workdir)
    env: dict[str, Any] = {}
    try:
        initial = parse_initial(case.get("initial") or {})
        bootstrap(db.connect_rw(db_path), initial, case.get("boot_at", "2026-01-01T00:00:00Z"))
    except GateError as exc:
        expect = case.get("bootstrap_expect")
        if isinstance(expect, dict) and expect.get("code") == exc.code:
            report.final = {"bootstrap_error": exc.as_dict()}
            return report
        report.failures.append("bootstrap: " + json.dumps(exc.as_dict()))
        report.final = {"bootstrap_error": exc.as_dict()}
        return report

    for raw in case.get("operations") or []:
        rec = run_operation(db_path, raw, env)
        if rec.get("expectation") and not rec["expectation"]["pass"]:
            report.failures.append(
                f"op {rec['op']} #{len(report.records)} expectation failed: "
                + json.dumps(rec["expectation"], sort_keys=True)
            )
        report.records.append(rec)

    if case.get("workers"):
        report.workers = run_workers(db_path, case["workers"], env, workdir)
        for w in report.workers:
            for rec in w["records"]:
                if rec.get("expectation") and not rec["expectation"]["pass"]:
                    report.failures.append(
                        f"worker {w['worker_id']}: expectation failed for {rec['op']}: "
                        + json.dumps(rec["expectation"], sort_keys=True)
                    )
        for raw in case.get("post_worker_ops") or []:
            rec = run_operation(db_path, raw, env)
            rec["phase"] = "post_worker"
            if rec.get("expectation") and not rec["expectation"]["pass"]:
                report.failures.append(
                    f"post-worker op {rec['op']}: expectation failed: "
                    + json.dumps(rec["expectation"], sort_keys=True)
                )
            report.records.append(rec)

    final_views = case.get("final_views") or [
        {"op": "status"},
        {"op": "launch_query", "tenant_id": _first_tenant(case), "app_id": _first_app(case),
         "environment": _first_env(case), "at": case.get("final_at", "2026-12-31T00:00:00Z")},
    ]
    for raw in final_views:
        rec = run_operation(db_path, raw, env)
        report.final_views.append(rec)
        if rec.get("expectation") and not rec["expectation"]["pass"]:
            report.failures.append(
                f"final view {rec['op']}: expectation failed: "
                + json.dumps(rec["expectation"], sort_keys=True)
            )
    status = [r for r in report.final_views if r.get("op") == "status" and r.get("ok")]
    report.final = status[-1]["result"] if status else {}
    if report.final.get("chain") and not report.final["chain"].get("ok"):
        report.failures.append("audit chain broken: " + json.dumps(report.final["chain"]))
    for raw in case.get("assertions") or []:
        passed, detail = run_assertion(raw, report)
        if not passed:
            report.failures.append(f"assertion {raw.get('name', raw.get('type'))}: {detail}")
    return report


def run_assertion(spec: dict[str, Any], report: CaseReport) -> tuple[bool, str]:
    """Evaluate a declarative post-condition over the case's own records."""
    kind = spec.get("type")
    if kind == "receipt_state":
        view = _find_record(report, spec.get("from", "receipt_query"))
        if view is None:
            return False, "no receipt view"
        want = spec.get("state")
        got = view["result"].get("state")
        return got == want, f"state {got!r} != {want!r}"
    if kind == "receipt_acked":
        view = _find_record(report, spec.get("from", "receipt_query"))
        if view is None:
            return False, "no receipt view"
        got = view["result"].get("acknowledged")
        return got is spec.get("value", True), f"acknowledged {got!r}"
    if kind == "chain_ok":
        chain = report.final.get("chain") or {}
        return bool(chain.get("ok")), f"chain {chain!r}"
    if kind == "ledger_count":
        chain = report.final.get("chain") or {}
        want = spec.get("entries")
        got = chain.get("entries")
        return got == want, f"ledger entries {got!r} != {want!r}"
    if kind == "record_count":
        want = spec.get("counts") or {}
        got = report.final.get("counts") or {}
        diffs = {k: (got.get(k), v) for k, v in want.items() if got.get(k) != v}
        return not diffs, f"counts differ (got, want): {diffs}"
    if kind == "evidence_intact":
        view = _find_record(report, spec.get("from", "receipt_query"))
        if view is None:
            return False, "no receipt view"
        return bool(view["result"].get("evidence_intact")), "evidence hash mismatch"
    return False, f"unknown assertion type {kind!r}"


def _find_record(report: CaseReport, label: str) -> dict[str, Any] | None:
    for rec in report.final_views + report.records:
        if rec.get("label") == label and rec.get("ok"):
            return rec
    for w in report.workers:
        for rec in w["records"]:
            if rec.get("label") == label and rec.get("ok"):
                return rec
    return None


def _first_tenant(case: dict[str, Any]) -> str:
    tenants = (case.get("initial") or {}).get("tenants") or []
    return tenants[0]["tenant_id"] if tenants else "t"


def _first_app(case: dict[str, Any]) -> str:
    apps = (case.get("initial") or {}).get("apps") or []
    return apps[0]["app_id"] if apps else "a"


def _first_env(case: dict[str, Any]) -> str:
    tenants = (case.get("initial") or {}).get("tenants") or []
    if tenants and tenants[0].get("environments"):
        return tenants[0]["environments"][0]
    return "prod"
