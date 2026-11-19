"""Command line entry point.

    python -m solution --input cases.json --output result.json
    python -m solution --input cases.json --output result.json --storedb out.db
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from .errors import GateError
from .runner import load_case, run_case


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m solution", description="Local secure release gate")
    p.add_argument("--input", required=True, help="path to cases.json")
    p.add_argument("--output", required=True, help="path to result.json")
    p.add_argument("--storedb", default=None, help="persist the gate database here instead of a temp dir")
    p.add_argument("--case", default=None, help="run only the case with this id")
    p.add_argument("--keep-workdir", action="store_true", help="do not delete the temporary database")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with open(args.input, "r", encoding="utf-8") as fh:
            document = json.load(fh)
    except OSError as exc:
        print(f"cannot read input: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"input is not valid JSON: {exc}", file=sys.stderr)
        return 2

    cases = document.get("cases") if isinstance(document, dict) and "cases" in document else [document]
    if not isinstance(cases, list):
        print("input must contain a 'cases' list", file=sys.stderr)
        return 2

    workdir = None
    if args.storedb:
        workdir = os.path.dirname(os.path.abspath(args.storedb)) or "."
        os.makedirs(workdir, exist_ok=True)
    results = []
    failures = 0
    for case in cases:
        cid = case.get("case_id", "case")
        if args.case and cid != args.case:
            continue
        case_dir = workdir if args.storedb else None
        report = run_case(case, workdir=case_dir)
        results.append(report.as_dict())
        if report.failures:
            failures += 1
        if not args.keep_workdir and not args.storedb:
            _cleanup(report.workdir)

    output = {
        "schema_version": 1,
        "summary": {
            "cases": len(results),
            "passed": len(results) - failures,
            "failed": failures,
        },
        "cases": results,
    }
    out_dir = os.path.dirname(os.path.abspath(args.output))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {args.output}: {output['summary']['passed']}/{output['summary']['cases']} cases passed")
    return 0 if failures == 0 else 1


def _cleanup(path: str) -> None:
    import shutil

    try:
        shutil.rmtree(path, ignore_errors=True)
    except OSError:  # pragma: no cover
        pass


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
