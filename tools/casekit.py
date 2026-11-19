"""Build ``cases.json``: the replayable scenario corpus.

Every scenario is synthetic metadata only.  The generator exists so the corpus
stays readable and so digests are always internally consistent; the produced
``cases.json`` is committed and is the artefact the CLI replays.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def dig(tag: str) -> str:
    """A deterministic content digest derived from a readable tag."""
    return "sha256:" + hashlib.sha256(f"pkg:{tag}".encode()).hexdigest()


def tenant(tid="t-acme", envs=None, roles=None):
    return {
        "tenant_id": tid,
        "environments": envs or ["prod", "stage"],
        "roles": roles or ["security", "engineering", "compliance"],
    }


def app(aid="app-portal", tid="t-acme", name="Customer Portal"):
    return {"app_id": aid, "tenant_id": tid, "name": name}


def pkg(tid, name, version, tag, deps=None, allowed_envs=None):
    out = {
        "tenant_id": tid,
        "name": name,
        "version": version,
        "content_digest": dig(tag),
        "published_at": "2026-01-01T00:00:00Z",
    }
    if deps:
        out["deps"] = deps
    if allowed_envs:
        out["allowed_envs"] = allowed_envs
    return out


def appver(aid, version, tid, deps, lock=None):
    out = {"app_id": aid, "version": version, "tenant_id": tid, "deps": deps}
    if lock is not None:
        out["lock"] = lock
    return out


def reviewer(rid, tid, role, person, epoch=1, version=1):
    return {"reviewer_id": rid, "tenant_id": tid, "role": role, "person_id": person,
            "duty_epoch": epoch, "duty_version": version, "active_from": "2026-01-01T00:00:00Z"}


def signature(sid, rid, tid, waiver, risk, aid, version, env, status="valid",
              at="2026-03-01T00:00:00Z"):
    return {"signature_id": sid, "reviewer_id": rid, "tenant_id": tid, "status": status,
            "signed_at": at, "subject": f"waive:{waiver}:{risk}:{aid}@{version}:{env}"}


def risk(rid, tid, aid, name, version, tag, severity="high", status="open"):
    return {"risk_id": rid, "tenant_id": tid, "app_id": aid, "dep_name": name,
            "dep_version": version, "content_digest": dig(tag), "severity": severity,
            "status": status, "registered_at": "2026-02-01T00:00:00Z"}


def waiver(wid, risk_id, tid, aid, tag, env, version, deadline="2026-12-01T00:00:00Z",
           created="2026-02-02T00:00:00Z", requester="p-sec"):
    return {"waiver_id": wid, "risk_id": risk_id, "tenant_id": tid, "app_id": aid,
            "content_digest": dig(tag), "environment": env, "evidence_version": version,
            "repair_deadline": deadline, "requested_by": requester, "created_at": created}


def approval(aid, wid, rid, role, sig, tid_app, app_version, env, risk_id, tag, version,
             severity="high", deadline="2026-12-01T00:00:00Z",
             at="2026-03-01T00:00:00Z", epoch=1, duty_version=1):
    return {"approval_id": aid, "waiver_id": wid, "reviewer_id": rid, "role": role,
            "signature_id": sig, "decision": "grant", "app_id": tid_app,
            "app_version": app_version, "environment": env, "risk_id": risk_id,
            "content_digest": dig(tag), "evidence_version": version,
            "severity_snapshot": severity, "deadline_snapshot": deadline,
            "duty_epoch": epoch, "duty_version": duty_version, "signed_at": at}
