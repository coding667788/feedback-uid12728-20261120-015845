"""Local secure release gate.

The package models a metadata-only release gate: software versions, dependency
manifests, registered risk findings, dual-control approvals, time bounded
waivers and a SQLite backed publish ledger.

Nothing in this package contacts an external system.  Every input is synthetic
and is supplied through the case file described in ``README.md``.
"""

__version__ = "1.0.0"
SCHEMA_VERSION = 1

__all__ = ["__version__", "SCHEMA_VERSION"]
