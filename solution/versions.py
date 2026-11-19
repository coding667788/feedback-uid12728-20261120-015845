"""Version parsing, constraint matching and dependency closure resolution.

The closure is the heart of the gate: a release is judged on every package it
would actually ship, not just the ones the manifest happens to name.  Two
properties drive the design:

* resolution is *deterministic* - ties are broken by the highest version, then
  by lexicographic version string, so the same inputs always yield the same
  closure fingerprint;
* a diamond (two apps, or two paths inside one app, needing the same package)
  is resolved to one concrete version, and any residual disagreement is an
  error rather than a silent pick.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .errors import GateError

_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.\-]+))?(?:\+([0-9A-Za-z.\-]+))?$")
_NAME_RE = re.compile(r"^[a-z][a-z0-9_.\-]{0,62}$")


@dataclass(frozen=True, order=False)
class Version:
    major: int
    minor: int
    patch: int
    pre: tuple[str, ...] = ()
    build: str = ""
    raw: str = ""

    @property
    def key(self) -> tuple:
        # A release version outranks any pre-release of the same base version.
        pre_key = () if not self.pre else tuple(
            (0, int(p), "") if p.isdigit() else (1, 0, p) for p in self.pre
        )
        rank = 1 if not self.pre else 0
        return (self.major, self.minor, self.patch, rank, pre_key)

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.raw


def parse_version(text: str) -> Version:
    m = _SEMVER_RE.match(text)
    if not m:
        raise GateError("E_BAD_FORMAT", f"not a semantic version: {text!r}", value=text)
    pre = tuple(m.group(4).split(".")) if m.group(4) else ()
    return Version(
        major=int(m.group(1)),
        minor=int(m.group(2)),
        patch=int(m.group(3)),
        pre=pre,
        build=m.group(5) or "",
        raw=text,
    )


def parse_constraint(spec: Any) -> dict[str, Any]:
    """Accept ``{"op": "range", "min": ..., "max": ...}`` or a plain version.

    Supported operators: ``exact``, ``min`` (>=), ``max`` (<=), ``range``
    (inclusive both ends), and ``any``.
    """
    if spec is None:
        return {"op": "any"}
    if isinstance(spec, str):
        parse_version(spec)
        return {"op": "exact", "version": spec}
    if not isinstance(spec, dict):
        raise GateError("E_BAD_TYPE", "constraint must be a string or an object")
    op = spec.get("op", "range")
    if op not in {"exact", "min", "max", "range", "any"}:
        raise GateError("E_BAD_FORMAT", f"unknown constraint operator: {op!r}", value=op)
    out: dict[str, Any] = {"op": op}
    if op == "any":
        return out
    if op == "exact":
        v = spec.get("version")
        if not isinstance(v, str):
            raise GateError("E_MISSING_FIELD", "exact constraint needs 'version'")
        parse_version(v)
        out["version"] = v
        return out
    for key in ("min", "max"):
        v = spec.get(key)
        if v is not None:
            if not isinstance(v, str):
                raise GateError("E_BAD_TYPE", f"constraint bound {key!r} must be a string")
            parse_version(v)
            out[key] = v
    if op in {"min", "max"} and out.get("min") is None and out.get("max") is None:
        raise GateError("E_MISSING_FIELD", f"constraint {op!r} needs min or max")
    if op == "range" and out.get("min") is None and out.get("max") is None:
        raise GateError("E_MISSING_FIELD", "range constraint needs min or max")
    return out


def constraint_text(cons: dict[str, Any]) -> str:
    op = cons["op"]
    if op == "any":
        return "any"
    if op == "exact":
        return f"=={cons['version']}"
    if op == "min":
        return f">={cons['min']}"
    if op == "max":
        return f"<={cons['max']}"
    return f">={cons['min']}<={cons['max']}"


def satisfies(version: str, cons: dict[str, Any]) -> bool:
    v = parse_version(version)
    op = cons["op"]
    if op == "any":
        return True
    if op == "exact":
        return version == cons["version"]
    if cons.get("min") is not None and v.key < parse_version(cons["min"]).key:
        return False
    if cons.get("max") is not None and v.key > parse_version(cons["max"]).key:
        return False
    return True


# ---------------------------------------------------------------------------
# package catalogue
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PackageVersion:
    name: str
    version: str
    content_digest: str
    deps: tuple[tuple[str, str], ...]  # (dep_name, constraint_text) in name order
    allowed_envs: tuple[str, ...]
    superseded: bool = False
    revoked: bool = False

    @property
    def identity(self) -> str:
        return f"{self.name}@{self.version}"

    def dep_specs(self) -> list[tuple[str, dict[str, Any]]]:
        out = []
        for name, text in self.deps:
            out.append((name, parse_constraint_text(text)))
        return out

def parse_constraint_text(text: str) -> dict[str, Any]:
    """Inverse of :func:`constraint_text` for stored dependency rows."""
    if text == "any":
        return {"op": "any"}
    if text.startswith("=="):
        return {"op": "exact", "version": text[2:]}
    if text.startswith(">=") and "<=" in text:
        lo, hi = text[2:].split("<=", 1)
        return {"op": "range", "min": lo, "max": hi}
    if text.startswith(">="):
        return {"op": "min", "min": text[2:]}
    if text.startswith("<="):
        return {"op": "max", "max": text[2:]}
    raise GateError("E_BAD_FORMAT", f"unparseable stored constraint: {text!r}")


@dataclass
class Catalogue:
    """All package versions visible to one tenant, indexed by name."""

    by_name: dict[str, list[PackageVersion]] = field(default_factory=dict)

    def add(self, pv: PackageVersion) -> None:
        self.by_name.setdefault(pv.name, []).append(pv)

    def names(self) -> list[str]:
        return sorted(self.by_name)

    def candidates(self, name: str, cons: dict[str, Any]) -> list[PackageVersion]:
        out = [pv for pv in self.by_name.get(name, []) if satisfies(pv.version, cons)]
        # Highest version first, then lexicographic, so ties are deterministic.
        out.sort(key=lambda pv: (parse_version(pv.version).key, pv.version), reverse=True)
        return out


def resolve(catalogue: Catalogue, roots: Iterable[tuple[str, dict[str, Any]]], environment: str) -> dict[str, PackageVersion]:
    """Resolve a full dependency closure.

    Greedy highest-satisfying-version resolution with a realised set: once a
    name has been pinned, later constraints must accept that pin, otherwise the
    graph is genuinely conflicting.  Newly discovered dependencies are appended
    breadth-first, so resolution terminates and is order independent for
    well-formed (acyclic) inputs.
    """
    pins: dict[str, PackageVersion] = {}
    pending: list[tuple[str, dict[str, Any], str]] = [(n, c, "<root>") for n, c in roots]
    seen_edges: set[tuple[str, str]] = set()

    while pending:
        name, cons, parent = pending.pop(0)
        if name not in catalogue.by_name:
            raise GateError("E_DEP_MISSING", f"unknown package {name!r}", package=name, parent=parent)
        if name in pins:
            pv = pins[name]
            if not satisfies(pv.version, cons):
                raise GateError(
                    "E_DEP_CONFLICT",
                    f"{name} pinned to {pv.version} but {parent} needs {constraint_text(cons)}",
                    package=name,
                    pinned=pv.version,
                    required=constraint_text(cons),
                    parent=parent,
                )
            continue
        options = catalogue.candidates(name, cons)
        if not options:
            raise GateError(
                "E_DEP_NO_VERSION",
                f"no version of {name!r} satisfies {constraint_text(cons)}",
                package=name,
                required=constraint_text(cons),
                parent=parent,
            )
        # Pick the highest acceptable, non-revoked, env-legal candidate.
        chosen: PackageVersion | None = None
        rejected: list[str] = []
        for candidate in options:
            if candidate.revoked:
                rejected.append(f"{candidate.version}:revoked")
                continue
            if candidate.allowed_envs and environment not in candidate.allowed_envs:
                rejected.append(f"{candidate.version}:env")
                continue
            chosen = candidate
            break
        if chosen is None:
            rev = options[0]
            if all(c.revoked for c in options):
                raise GateError(
                    "E_DEP_NO_VERSION",
                    f"every candidate for {name!r} is revoked",
                    package=name,
                    rejected=rejected,
                )
            raise GateError(
                "E_DEP_ENV_MISMATCH",
                f"no candidate for {name!r} is allowed in {environment}",
                package=name,
                environment=environment,
                rejected=rejected,
            )
        pins[name] = chosen
        for dep_name, dep_cons in chosen.dep_specs():
            edge = (chosen.identity, dep_name)
            if edge in seen_edges:
                continue
            seen_edges.add(edge)
            pending.append((dep_name, dep_cons, chosen.identity))

    # Cycle detection over the realised graph (defensive; greedy pinning above
    # already makes cycles harmless, but a cycle is still reported as invalid).
    _detect_cycle(pins)
    return pins


def _detect_cycle(pins: dict[str, PackageVersion]) -> None:
    state: dict[str, int] = {}

    def visit(name: str, stack: list[str]) -> None:
        state[name] = 1
        stack.append(name)
        for dep_name, _ in pins[name].dep_specs():
            if dep_name not in pins:
                continue
            if state.get(dep_name) == 1:
                cycle = stack[stack.index(dep_name):] + [dep_name]
                raise GateError("E_DEP_CYCLE", " -> ".join(cycle), cycle=cycle)
            if state.get(dep_name, 0) == 0:
                visit(dep_name, stack)
        stack.pop()
        state[name] = 2

    for name in sorted(pins):
        if state.get(name, 0) == 0:
            visit(name, [])


def closure_fingerprint(pins: dict[str, PackageVersion]) -> str:
    """Identity of a resolved closure: names, versions and content digests."""
    from .util import digest_of

    body = [
        {"name": pv.name, "version": pv.version, "digest": pv.content_digest}
        for pv in sorted(pins.values(), key=lambda p: p.name)
    ]
    return digest_of(body)


def closure_rows(pins: dict[str, PackageVersion]) -> list[dict[str, str]]:
    return [
        {"name": pv.name, "version": pv.version, "content_digest": pv.content_digest}
        for pv in sorted(pins.values(), key=lambda p: p.name)
    ]


def compare_closure(expected: dict[str, PackageVersion], declared: Iterable[dict[str, str]]) -> list[str]:
    """Return human readable differences between two closure descriptions."""
    declared_map = {d["name"]: (d["version"], d["content_digest"]) for d in declared}
    diffs: list[str] = []
    for name, pv in sorted(expected.items()):
        if name not in declared_map:
            diffs.append(f"missing {name}@{pv.version}")
            continue
        ver, dig = declared_map[name]
        if ver != pv.version:
            diffs.append(f"{name} version {ver} != {pv.version}")
        elif dig != pv.content_digest:
            diffs.append(f"{name} digest differs at {ver}")
    for name in sorted(set(declared_map) - set(expected)):
        diffs.append(f"unexpected extra {name}")
    return diffs
