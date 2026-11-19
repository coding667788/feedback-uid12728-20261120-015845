"""Generate ``cases.json`` from readable Python scenario definitions."""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.casekit import (  # noqa: E402
    app, approval, appver, dig, pkg, reviewer, risk, signature, tenant, waiver,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T = "t-acme"
A1 = "app-portal"
A2 = "app-mobile"
NOW = "2026-11-20T00:00:00Z"
LATE = "2026-12-15T00:00:00Z"


def base_registry():
    """Shared synthetic products, packages, reviewers and signature keys."""
    util = {"lib-util": {"op": "min", "min": "0.9.0"}}
    return {
        "tenants": [tenant(T)],
        "apps": [app(A1, T, "Customer Portal"), app(A2, T, "Mobile Client")],
        "software": [
            # lib-core exists in two versions under one name, and both pull
            # lib-util - so lib-util is only ever reached transitively.
            pkg(T, "lib-core", "1.0.0", "core-1.0.0", deps=util),
            pkg(T, "lib-core", "2.0.0", "core-2.0.0", deps=util),
            pkg(T, "lib-core", "2.1.0", "core-2.1.0", deps=util),
            # Diamond: both services pull lib-core, and lib-core pulls lib-util.
            pkg(T, "svc-auth", "3.0.0", "svc-auth-3.0.0",
                deps={"lib-core": {"op": "range", "min": "2.0.0", "max": "2.1.0"}}),
            pkg(T, "svc-billing", "4.0.0", "svc-billing-4.0.0",
                deps={"lib-core": {"op": "min", "min": "2.0.0"}}),
            pkg(T, "lib-util", "0.9.0", "lib-util-0.9.0"),
            # A package only usable in staging, to prove env filtering.
            pkg(T, "lib-debug", "1.0.0", "lib-debug-1.0.0", allowed_envs=["stage"]),
        ],
        "reviewers": [
            reviewer("rev-sec-a", T, "security", "p-alice"),
            reviewer("rev-sec-b", T, "security", "p-bob"),
            reviewer("rev-eng-a", T, "engineering", "p-carol"),
            reviewer("rev-comp-a", T, "compliance", "p-dave"),
        ],
        "signatures": [],
    }


def sig_for(reg, sid, rid, wid, risk_id, aid, version, env, status="valid",
            at="2026-03-01T00:00:00Z"):
    reg["signatures"].append(signature(sid, rid, T, wid, risk_id, aid, version, env,
                                       status=status, at=at))


def standard_waiver_scenario(*, severity="high", deadline="2026-12-01T00:00:00Z",
                             approvals=("ap-sec", "ap-eng"), env="prod"):
    """A released app whose closure pulls one package with a waived risk."""
    reg = base_registry()
    reg["app_versions"] = [
        appver(A1, "1.0.0", T, {"svc-auth": {"op": "min", "min": "3.0.0"}}),
        appver(A2, "1.0.0", T, {"svc-billing": {"op": "min", "min": "4.0.0"}}),
    ]
    reg["risks"] = [risk("risk-core", T, A1, "lib-core", "2.1.0", "core-2.1.0", severity)]
    reg["waivers"] = [waiver("wv-core", "risk-core", T, A1, "core-2.1.0", env, "2.1.0",
                             deadline=deadline)]
    sig_for(reg, "sg-sec-a", "rev-sec-a", "wv-core", "risk-core", A1, "1.0.0", env)
    sig_for(reg, "sg-eng-a", "rev-eng-a", "wv-core", "risk-core", A1, "1.0.0", env)
    sig_for(reg, "sg-sec-b", "rev-sec-b", "wv-core", "risk-core", A1, "1.0.0", env)
    sig_for(reg, "sg-comp-a", "rev-comp-a", "wv-core", "risk-core", A1, "1.0.0", env)
    reg["approvals"] = []
    if "ap-sec" in approvals:
        reg["approvals"].append(approval("ap-sec", "wv-core", "rev-sec-a", "security",
                                         "sg-sec-a", A1, "1.0.0", env, "risk-core",
                                         "core-2.1.0", "2.1.0", severity=severity,
                                         deadline=deadline))
    if "ap-eng" in approvals:
        reg["approvals"].append(approval("ap-eng", "wv-core", "rev-eng-a", "engineering",
                                         "sg-eng-a", A1, "1.0.0", env, "risk-core",
                                         "core-2.1.0", "2.1.0", severity=severity,
                                         deadline=deadline))
    return reg


CASES: list[dict] = []


# ---------------------------------------------------------------------------
# 01 - full closure coverage: the manifest cannot hide an indirect package
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "01_closure_covers_indirect_dependency",
    "title": "Publishing enforces the whole dependency closure, not the manifest",
    "initial": {
        "tenants": [tenant(T)],
        "apps": [app(A1, T, "Customer Portal")],
        "software": base_registry()["software"],
        "app_versions": [
            # The lock names only the two services and silently omits lib-core
            # and lib-util, which are reachable through them.
            appver(A1, "1.0.0", T, {"svc-auth": {"op": "min", "min": "3.0.0"}},
                   lock=[
                       {"name": "svc-auth", "version": "3.0.0",
                        "content_digest": dig("svc-auth-3.0.0")},
                   ]),
        ],
        "reviewers": base_registry()["reviewers"],
        "signatures": [],
        "risks": [],
    },
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre",
         "expect": {"fields": {"authorized": True, "closure_fingerprint": None}}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre.precheck_token}",
         "expect": {"ok": False, "code": "E_MANIFEST_INCOMPLETE"}},
    ],
    "final_views": [
        {"op": "status"},
        {"op": "launch_query", "tenant_id": T, "app_id": A1, "environment": "prod", "at": LATE,
         "expect": {"fields": {"live": None, "authorized": False}}},
    ],
    "assertions": [
        {"type": "chain_ok"},
        {"type": "record_count", "counts": {"receipt": 0, "release": 0}},
    ],
})


# ---------------------------------------------------------------------------
# 02 - the same lock, corrected, publishes; closure is fully recorded
# ---------------------------------------------------------------------------
def _full_lock():
    return [
        {"name": "lib-core", "version": "2.1.0", "content_digest": dig("core-2.1.0")},
        {"name": "lib-util", "version": "0.9.0", "content_digest": dig("lib-util-0.9.0")},
        {"name": "svc-auth", "version": "3.0.0", "content_digest": dig("svc-auth-3.0.0")},
    ]


CASES.append({
    "case_id": "02_closure_complete_publishes",
    "title": "A complete lock publishes and the receipt records every package",
    "initial": {
        "tenants": [tenant(T)],
        "apps": [app(A1, T, "Customer Portal")],
        "software": base_registry()["software"],
        "app_versions": [appver(A1, "1.0.0", T, {"svc-auth": {"op": "min", "min": "3.0.0"}},
                                lock=_full_lock())],
        "reviewers": base_registry()["reviewers"],
        "signatures": [],
        "risks": [],
    },
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre"},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre.precheck_token}", "label": "pub",
         "expect": {"ok": True}},
        {"op": "receipt_query", "receipt_id": "${pub.receipt_id}", "label": "rcpt",
         "expect": {"fields": {"evidence_intact": True, "acknowledged": True,
                               "state": "committed_acked"}}},
    ],
    "final_views": [
        {"op": "status"},
        {"op": "launch_query", "tenant_id": T, "app_id": A1, "environment": "prod", "at": LATE,
         "expect": {"fields": {"authorized": True, "history_matches_now": True}}},
    ],
    "assertions": [
        {"type": "chain_ok"},
        {"type": "evidence_intact", "from": "rcpt"},
        {"type": "record_count", "counts": {"receipt": 1, "release": 1}},
    ],
})


# ---------------------------------------------------------------------------
# 03 - dual control: same post, same person, and valid dual approval
# ---------------------------------------------------------------------------
_dual = standard_waiver_scenario(approvals=())
# Two signatures from the same post: both security.
_dual["approvals"] = [
    approval("ap-sec-a", "wv-core", "rev-sec-a", "security", "sg-sec-a", A1, "1.0.0",
             "prod", "risk-core", "core-2.1.0", "2.1.0"),
    approval("ap-sec-b", "wv-core", "rev-sec-b", "security", "sg-sec-b", A1, "1.0.0",
             "prod", "risk-core", "core-2.1.0", "2.1.0"),
]
CASES.append({
    "case_id": "03_dual_control_same_post_rejected",
    "title": "Two signatures from one post do not satisfy dual control",
    "initial": _dual,
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre",
         "expect": {"fields": {"authorized": False}}},
    ],
    "final_views": [
        {"op": "status"},
        {"op": "launch_query", "tenant_id": T, "app_id": A1, "environment": "prod", "at": LATE},
    ],
    "assertions": [{"type": "chain_ok"}, {"type": "record_count", "counts": {"receipt": 0}}],
})

# One person registered under both posts is refused at registration time.
_same = standard_waiver_scenario(approvals=("ap-sec", "ap-eng"))
_same["reviewers"] = [
    reviewer("rev-sec-a", T, "security", "p-alice"),
    reviewer("rev-eng-a", T, "engineering", "p-alice"),  # same human, second post
]
CASES.append({
    "case_id": "04_dual_control_same_person_rejected",
    "title": "One person cannot hold both approval posts",
    "initial": _same,
    "operations": [],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"}],
    # Bootstrap must refuse this registry outright; the case asserts the code.
    "bootstrap_expect": {"ok": False, "code": "E_SEGREGATION"},
})

CASES.append({
    "case_id": "05_dual_control_two_posts_accepted",
    "title": "Two distinct posts approve and the release proceeds",
    "initial": standard_waiver_scenario(approvals=("ap-sec", "ap-eng")),
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre",
         "expect": {"fields": {"authorized": True}}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre.precheck_token}", "label": "pub",
         "expect": {"ok": True}},
    ],
    "final_views": [
        {"op": "status"},
        {"op": "launch_query", "tenant_id": T, "app_id": A1, "environment": "prod", "at": NOW,
         "expect": {"fields": {"authorized": True}}},
    ],
    "assertions": [{"type": "chain_ok"}, {"type": "record_count",
                                          "counts": {"receipt": 1, "release": 1}}],
})


# ---------------------------------------------------------------------------
# 06 - critical severity can never be waived
# ---------------------------------------------------------------------------
_crit = standard_waiver_scenario(severity="critical", approvals=("ap-sec", "ap-eng"))
CASES.append({
    "case_id": "06_critical_severity_never_waivable",
    "title": "Critical findings block regardless of approvals",
    "initial": _crit,
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre",
         "expect": {"fields": {"authorized": False}}},
        {"op": "request_waiver", "waiver_id": "wv-new", "risk_id": "risk-core",
         "environment": "prod", "evidence_version": "2.1.0",
         "repair_deadline": "2026-12-01T00:00:00Z", "requested_by": "p-alice",
         "request_id": "req-w", "at": NOW,
         "expect": {"ok": False, "code": "E_APPROVAL_SEVERITY"}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"}, {"type": "record_count", "counts": {"receipt": 0}}],
})


# ---------------------------------------------------------------------------
# 07 - waiver binding: environment, evidence version, deadline
# ---------------------------------------------------------------------------
_env = standard_waiver_scenario(approvals=("ap-sec", "ap-eng"), env="stage")
CASES.append({
    "case_id": "07_waiver_wrong_environment",
    "title": "A staging waiver does not authorise production",
    "initial": _env,
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre",
         "expect": {"fields": {"authorized": False}}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"}],
})

CASES.append({
    "case_id": "08_waiver_expiry_boundary",
    "title": "Publishing exactly at the repair deadline counts as expired",
    "initial": standard_waiver_scenario(approvals=("ap-sec", "ap-eng"),
                                        deadline="2026-11-20T00:00:00Z"),
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre",
         "expect": {"fields": {"authorized": False}}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": "2026-11-19T23:59:59Z", "label": "pre-ok",
         "expect": {"fields": {"authorized": True}}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"}],
})

CASES.append({
    "case_id": "09_waiver_evidence_version_mismatch",
    "title": "Waiver evidence pinned to another dependency version is refused",
    "initial": standard_waiver_scenario(approvals=("ap-sec", "ap-eng")),
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre"},
        {"op": "request_waiver", "waiver_id": "wv-bad", "risk_id": "risk-core",
         "environment": "prod", "evidence_version": "2.0.0",
         "repair_deadline": "2026-12-01T00:00:00Z", "requested_by": "p-alice",
         "request_id": "req-w", "at": NOW,
         "expect": {"ok": False, "code": "E_WAIVER_EVIDENCE"}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"}],
})


# ---------------------------------------------------------------------------
# 10 - repair extension invalidates the approvals that backed the waiver
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "10_extension_invalidates_approvals",
    "title": "Extending the repair deadline retires earlier approvals",
    "initial": standard_waiver_scenario(approvals=("ap-sec", "ap-eng")),
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre-before",
         "expect": {"fields": {"authorized": True}}},
        {"op": "extend_waiver", "waiver_id": "wv-core", "repair_deadline": "2027-01-15T00:00:00Z",
         "request_id": "req-ext", "actor": "p-dave", "at": NOW,
         "expect": {"ok": True}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre-after",
         "expect": {"fields": {"authorized": False}}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre-before.precheck_token}",
         "expect": {"ok": False, "code": "E_PRECHECK_STALE"}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"}, {"type": "record_count", "counts": {"receipt": 0}}],
})


# ---------------------------------------------------------------------------
# 11 - severity escalation invalidates approvals
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "11_severity_raise_invalidates_approvals",
    "title": "Raising severity retires approvals signed at the lower level",
    "initial": standard_waiver_scenario(severity="medium", approvals=("ap-sec", "ap-eng")),
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre-before",
         "expect": {"fields": {"authorized": True}}},
        {"op": "raise_risk", "risk_id": "risk-core", "severity": "high",
         "request_id": "req-raise", "actor": "p-dave", "at": NOW,
         "expect": {"ok": True}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre-after",
         "expect": {"fields": {"authorized": False}}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre-before.precheck_token}",
         "expect": {"ok": False, "code": "E_PRECHECK_STALE"}},
    ],
    "final_views": [
        {"op": "status"},
        {"op": "audit", "kind": "risk.severity_raised", "label": "audit",
         "expect": {"fields": {"chain.ok": True}}},
    ],
    "assertions": [{"type": "chain_ok"}],
})


# ---------------------------------------------------------------------------
# 12 - reviewer transfer kills their approval; re-signing recovers
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "12_reviewer_transfer_invalidates_approval",
    "title": "A transferred reviewer's approval stops counting",
    "initial": standard_waiver_scenario(approvals=("ap-sec", "ap-eng")),
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre-before",
         "expect": {"fields": {"authorized": True}}},
        {"op": "transfer_reviewer", "reviewer_id": "rev-eng-a", "role": "compliance",
         "request_id": "req-move", "actor": "p-hr", "at": NOW,
         "expect": {"ok": True, "fields": {"revoked_approvals.0": "ap-eng"}}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre-after",
         "expect": {"fields": {"authorized": False}}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre-before.precheck_token}",
         "expect": {"ok": False, "code": "E_PRECHECK_STALE"}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"}, {"type": "record_count", "counts": {"receipt": 0}}],
})


# ---------------------------------------------------------------------------
# 13 - an indirect risk appears between precheck and publish
# ---------------------------------------------------------------------------
_c = standard_waiver_scenario(approvals=("ap-sec", "ap-eng"))
_c["risks"] = []
_c["waivers"] = []
_c["approvals"] = []
CASES.append({
    "case_id": "13_indirect_risk_after_precheck",
    "title": "A risk on a transitive package appearing after precheck forces a new decision",
    "initial": _c,
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre",
         "expect": {"fields": {"authorized": True}}},
        # lib-util is three hops down the graph: nobody listed it by hand, and
        # the precheck report proves the closure contained it.
        {"op": "register_risk", "risk_id": "risk-util", "tenant_id": T, "app_id": A1,
         "dep_name": "lib-util", "dep_version": "0.9.0", "content_digest": dig("lib-util-0.9.0"),
         "severity": "high", "request_id": "req-risk", "at": NOW,
         "expect": {"ok": True}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre.precheck_token}",
         "expect": {"ok": False, "code": "E_PRECHECK_STALE"}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre2",
         "expect": {"fields": {"authorized": False, "closure_fingerprint": None}}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [
        {"type": "chain_ok"},
        {"type": "record_count", "counts": {"receipt": 0}},
        {"type": "contains", "from": "pre2", "path": "blocked.0.risk_id", "value": "risk-util"},
        {"type": "closure_has", "from": "pre2", "package": "lib-util", "version": "0.9.0"},
    ],
})


# ---------------------------------------------------------------------------
# 14 - approval revoked, re-issued, published with the fresh token
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "14_revoke_and_reissue_approval",
    "title": "Revoking one signature forces a fresh approval before publishing",
    "initial": standard_waiver_scenario(approvals=("ap-sec", "ap-eng")),
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre-before",
         "expect": {"fields": {"authorized": True}}},
        {"op": "revoke_approval", "approval_id": "ap-eng", "request_id": "req-rev",
         "actor": "p-dave", "reason": "reassigned", "at": NOW, "expect": {"ok": True}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre-mid",
         "expect": {"fields": {"authorized": False}}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre-before.precheck_token}",
         "expect": {"ok": False, "code": "E_PRECHECK_STALE"}},
        {"op": "approve", "approval_id": "ap-eng-2", "waiver_id": "wv-core",
         "reviewer_id": "rev-eng-a", "signature_id": "sg-eng-a", "app_version": "1.0.0",
         "request_id": "req-ap2", "at": "2026-11-20T00:00:01Z", "expect": {"ok": True}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": "2026-11-20T00:00:02Z", "label": "pre-ok",
         "expect": {"fields": {"authorized": True}}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": "2026-11-20T00:00:03Z", "actor": "p-deploy",
         "request_id": "req-2", "precheck_token": "${pre-ok.precheck_token}",
         "expect": {"ok": True}},
    ],
    "final_views": [
        {"op": "status"},
        {"op": "launch_query", "tenant_id": T, "app_id": A1, "environment": "prod",
         "at": "2026-11-20T00:00:04Z", "expect": {"fields": {"authorized": True}}},
    ],
    "assertions": [{"type": "chain_ok"}, {"type": "record_count", "counts": {"receipt": 1}}],
})


# ---------------------------------------------------------------------------
# 15 - candidate reverted to a previously seen digest
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "15_reverted_digest_requires_fresh_judgement",
    "title": "Rolling content back to a retired digest is refused and flagged",
    "initial": {
        "tenants": [tenant(T)],
        "apps": [app(A1, T, "Customer Portal")],
        "software": [
            pkg(T, "lib-core", "2.0.0", "core-2.0.0"),
            pkg(T, "lib-core", "2.1.0", "core-2.1.0"),
            pkg(T, "svc-auth", "3.0.0", "svc-auth-3.0.0",
                deps={"lib-core": {"op": "min", "min": "2.0.0"}}),
            pkg(T, "lib-util", "0.9.0", "lib-util-0.9.0"),
        ],
        "app_versions": [appver(A1, "1.0.0", T, {"svc-auth": {"op": "min", "min": "3.0.0"}})],
        "reviewers": base_registry()["reviewers"],
        "signatures": [],
        "risks": [],
    },
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre",
         "expect": {"fields": {"authorized": True}}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre.precheck_token}", "label": "pub", "expect": {"ok": True}},
        # New content under 2.1.0 retires core-2.1.0 and starts epoch 2.
        {"op": "register_software", "tenant_id": T, "name": "lib-core", "version": "2.1.0",
         "content_digest": dig("core-2.1.0-hotfix"), "request_id": "req-new", "at": NOW,
         "expect": {"ok": True, "fields": {"outcome": "content_changed", "epoch": 2}}},
        # Now try to go back to the original digest: it was seen and retired.
        {"op": "register_software", "tenant_id": T, "name": "lib-core", "version": "2.1.0",
         "content_digest": dig("core-2.1.0"), "request_id": "req-revert", "at": NOW,
         "expect": {"ok": False, "code": "E_DIGEST_REVERTED"}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre-now",
         "expect": {"fields": {"authorized": True}}},
    ],
    "final_views": [
        {"op": "status"},
        {"op": "audit", "kind": "software.revert_refused", "label": "audit"},
    ],
    "assertions": [
        {"type": "chain_ok"},
        {"type": "contains", "from": "pre-now", "path": "revisit.reverted_digests.0.package",
         "value": "lib-core@2.1.0"},
        {"type": "contains", "from": "audit", "path": "result.entries.0.kind",
         "value": "software.revert_refused"},
    ],
})


# ---------------------------------------------------------------------------
# 16 - diamond across two apps sharing one dependency, plus a second version
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "16_diamond_across_apps",
    "title": "One dependency reached via a diamond from two apps resolves once per release",
    "initial": {
        "tenants": [tenant(T)],
        "apps": [app(A1, T, "Customer Portal"), app(A2, T, "Mobile Client")],
        "software": base_registry()["software"],
        "app_versions": [
            appver(A1, "1.0.0", T, {"svc-auth": {"op": "min", "min": "3.0.0"},
                                    "svc-billing": {"op": "min", "min": "4.0.0"}}),
            # The same lib-core name, pinned differently, stays a separate release.
            appver(A2, "1.0.0", T, {"lib-core": {"op": "min", "min": "2.0.0"}}),
            appver(A2, "2.0.0", T, {"lib-core": {"op": "min", "min": "2.1.0"}}),
        ],
        "reviewers": base_registry()["reviewers"],
        "signatures": [],
        "risks": [],
    },
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pa",
         "expect": {"fields": {"authorized": True}}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-a",
         "precheck_token": "${pa.precheck_token}", "label": "pub-a", "expect": {"ok": True}},
        {"op": "precheck", "tenant_id": T, "app_id": A2, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pb",
         "expect": {"fields": {"authorized": True}}},
        {"op": "publish", "tenant_id": T, "app_id": A2, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-b",
         "precheck_token": "${pb.precheck_token}", "expect": {"ok": True}},
        {"op": "precheck", "tenant_id": T, "app_id": A2, "version": "2.0.0",
         "environment": "prod", "at": NOW, "label": "pb2",
         "expect": {"fields": {"authorized": True}}},
        {"op": "publish", "tenant_id": T, "app_id": A2, "version": "2.0.0",
         "environment": "prod", "at": "2026-11-20T00:00:01Z", "actor": "p-deploy",
         "request_id": "req-b2", "precheck_token": "${pb2.precheck_token}",
         "label": "pub-b2", "expect": {"ok": True}},
    ],
    "final_views": [
        {"op": "status"},
        {"op": "launch_query", "tenant_id": T, "app_id": A1, "environment": "prod", "at": LATE},
        {"op": "launch_query", "tenant_id": T, "app_id": A2, "environment": "prod", "at": LATE,
         "expect": {"fields": {"live.version": "2.0.0"}}},
        {"op": "receipt_query", "app_id": A2, "tenant_id": T, "label": "hist"},
    ],
    "assertions": [{"type": "chain_ok"},
                   {"type": "record_count", "counts": {"release": 2, "receipt": 3}}],
})


# ---------------------------------------------------------------------------
# 17 - environment restriction inside the closure
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "17_env_restricted_package",
    "title": "A package allowed only in staging blocks the production release",
    "initial": {
        "tenants": [tenant(T)],
        "apps": [app(A1, T, "Customer Portal")],
        "software": base_registry()["software"],
        "app_versions": [
            appver(A1, "1.0.0", T, {"svc-auth": {"op": "min", "min": "3.0.0"},
                                    "lib-debug": {"op": "min", "min": "1.0.0"}}),
        ],
        "reviewers": base_registry()["reviewers"],
        "signatures": [],
        "risks": [],
    },
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre-prod",
         "expect": {"ok": False, "code": "E_DEP_ENV_MISMATCH"}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "stage", "at": NOW, "label": "pre-stage",
         "expect": {"fields": {"authorized": True}}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"}],
})


# ---------------------------------------------------------------------------
# 18 - dependency conflict and unknown package
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "18_dependency_conflict",
    "title": "Two paths demanding incompatible versions of one package is refused",
    "initial": {
        "tenants": [tenant(T)],
        "apps": [app(A1, T, "Customer Portal")],
        "software": [
            pkg(T, "lib-core", "1.0.0", "core-1.0.0"),
            pkg(T, "lib-core", "2.0.0", "core-2.0.0"),
            pkg(T, "svc-auth", "3.0.0", "svc-auth-3.0.0",
                deps={"lib-core": {"op": "min", "min": "2.0.0"}}),
            pkg(T, "svc-legacy", "1.0.0", "svc-legacy-1.0.0",
                deps={"lib-core": {"op": "exact", "version": "1.0.0"}}),
            pkg(T, "lib-util", "0.9.0", "lib-util-0.9.0"),
        ],
        "app_versions": [
            appver(A1, "1.0.0", T, {"svc-auth": {"op": "min", "min": "3.0.0"},
                                    "svc-legacy": {"op": "min", "min": "1.0.0"}}),
            appver(A1, "2.0.0", T, {"svc-ghost": {"op": "min", "min": "1.0.0"}}),
        ],
        "reviewers": base_registry()["reviewers"],
        "signatures": [],
        "risks": [],
    },
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW,
         "expect": {"ok": False, "code": "E_DEP_CONFLICT"}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "2.0.0",
         "environment": "prod", "at": NOW,
         "expect": {"ok": False, "code": "E_DEP_MISSING"}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"}],
})


# ---------------------------------------------------------------------------
# 19 - sealed risk resolved by an upgraded dependency, then by a fix signal
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "19_risk_retired_by_upgrade_and_fix",
    "title": "Bumping the dependency or landing a verified fix clears the finding",
    "initial": {
        "tenants": [tenant(T)],
        "apps": [app(A1, T, "Customer Portal")],
        "software": base_registry()["software"],
        "app_versions": [
            appver(A1, "1.0.0", T, {"svc-auth": {"op": "min", "min": "3.0.0"}}),
        ],
        "reviewers": base_registry()["reviewers"],
        "signatures": [],
        "risks": [risk("risk-core", T, A1, "lib-core", "2.1.0", "core-2.1.0", "high")],
    },
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre-blocked",
         "expect": {"fields": {"authorized": False}}},
        {"op": "record_fix", "fix_id": "fix-1", "risk_id": "risk-core",
         "content_digest": dig("core-2.1.0"), "evidence_version": "2.1.0",
         "verified": True, "request_id": "req-fix", "at": NOW,
         "expect": {"ok": True, "fields": {"risk_status": "fixed"}}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre-fixed",
         "expect": {"fields": {"authorized": True}}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre-fixed.precheck_token}", "expect": {"ok": True}},
    ],
    "final_views": [
        {"op": "status"},
        {"op": "launch_query", "tenant_id": T, "app_id": A1, "environment": "prod", "at": LATE,
         "expect": {"fields": {"authorized": True}}},
    ],
    "assertions": [{"type": "chain_ok"}],
})


# ---------------------------------------------------------------------------
# 20 - tenant isolation
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "20_tenant_isolation",
    "title": "A risk from another tenant can never authorise this release",
    "initial": {
        "tenants": [tenant(T), tenant("t-other")],
        "apps": [app(A1, T, "Customer Portal"), app("app-other", "t-other", "Other App")],
        "software": base_registry()["software"] + [
            pkg("t-other", "svc-auth", "3.0.0", "svc-auth-3.0.0"),
            pkg("t-other", "lib-util", "0.9.0", "lib-util-0.9.0"),
        ],
        "app_versions": [
            appver(A1, "1.0.0", T, {"svc-auth": {"op": "min", "min": "3.0.0"}}),
            appver("app-other", "1.0.0", "t-other", {}),
        ],
        "reviewers": base_registry()["reviewers"] + [
            reviewer("rev-other", "t-other", "security", "p-zoe"),
        ],
        "signatures": [],
        "risks": [],
    },
    "operations": [
        {"op": "register_risk", "risk_id": "risk-x", "tenant_id": "t-other",
         "app_id": "app-other", "dep_name": "lib-core", "dep_version": "2.1.0",
         "content_digest": dig("core-2.1.0"), "severity": "high",
         "request_id": "req-x", "at": NOW, "expect": {"ok": True}},
        {"op": "request_waiver", "waiver_id": "wv-x", "risk_id": "risk-x",
         "environment": "prod", "evidence_version": "2.1.0",
         "repair_deadline": "2026-12-01T00:00:00Z", "requested_by": "p-zoe",
         "request_id": "req-wx", "at": NOW, "expect": {"ok": True}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre",
         "expect": {"fields": {"authorized": True}}},
        {"op": "publish", "tenant_id": "t-other", "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-bad",
         "precheck_token": "${pre.precheck_token}",
         "expect": {"ok": False, "code": "E_PRECHECK_STALE"}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"}, {"type": "record_count", "counts": {"receipt": 0}}],
})


# ---------------------------------------------------------------------------
# 21 - concurrent approval and revocation from two processes
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "21_concurrent_approve_and_revoke",
    "title": "Two processes approving and revoking concurrently settle on one consistent state",
    "initial": {
        "tenants": [tenant(T)],
        "apps": [app(A1, T, "Customer Portal")],
        "software": base_registry()["software"],
        "app_versions": [appver(A1, "1.0.0", T, {"svc-auth": {"op": "min", "min": "3.0.0"}})],
        "reviewers": base_registry()["reviewers"],
        "signatures": [],
        "risks": [risk("risk-core", T, A1, "lib-core", "2.1.0", "core-2.1.0", "high")],
        "waivers": [waiver("wv-core", "risk-core", T, A1, "core-2.1.0", "prod", "2.1.0")],
    },
    "operations": [],
    "workers": [
        {
            "worker_id": "w-sec",
            "operations": [
                {"op": "approve", "approval_id": "ap-w-sec", "waiver_id": "wv-core",
                 "reviewer_id": "rev-sec-a", "signature_id": "sg-sec-a",
                 "signature_at": "2026-03-01T00:00:00Z", "app_version": "1.0.0",
                 "request_id": "req-w-sec", "at": "2026-11-20T00:00:00Z",
                 "sync": {"barrier": "start", "parties": 2}, "expect": {"ok": True}},
            ],
        },
        {
            "worker_id": "w-eng",
            "operations": [
                {"op": "approve", "approval_id": "ap-w-eng", "waiver_id": "wv-core",
                 "reviewer_id": "rev-eng-a", "signature_id": "sg-eng-a",
                 "app_version": "1.0.0", "request_id": "req-w-eng",
                 "at": "2026-11-20T00:00:01Z",
                 "sync": {"barrier": "start", "parties": 2}, "expect": {"ok": True}},
                {"op": "revoke_approval", "approval_id": "ap-w-sec", "request_id": "req-rv",
                 "actor": "p-dave", "reason": "concurrent revoke",
                 "at": "2026-11-20T00:00:02Z",
                 "sync": {"barrier": "start", "parties": 2}, "expect": {"ok": True}},
            ],
        },
    ],
    "post_worker_ops": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": "2026-11-20T00:00:05Z", "label": "final",
         "expect": {"fields": {"authorized": False}}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [
        {"type": "chain_ok"},
        {"type": "record_count", "counts": {"approval": 2, "receipt": 0}},
    ],
})


# ---------------------------------------------------------------------------
# 22 - concurrent publish of two versions: one wins, the other must re-precheck
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "22_concurrent_publish_single_winner",
    "title": "Two processes racing to publish leave exactly one pointer and one receipt",
    "initial": {
        "tenants": [tenant(T)],
        "apps": [app(A1, T, "Customer Portal")],
        "software": base_registry()["software"],
        "app_versions": [
            appver(A1, "1.0.0", T, {"svc-auth": {"op": "min", "min": "3.0.0"}}),
            appver(A1, "2.0.0", T, {"svc-billing": {"op": "min", "min": "4.0.0"}}),
        ],
        "reviewers": base_registry()["reviewers"],
        "signatures": [],
        "risks": [],
    },
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre1"},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "2.0.0",
         "environment": "prod", "at": NOW, "label": "pre2"},
    ],
    "workers": [
        {
            "worker_id": "w-1",
            "operations": [
                {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
                 "environment": "prod", "at": NOW, "actor": "p-deploy",
                 "request_id": "req-p1", "precheck_token": "${pre1.precheck_token}",
                 "sync": {"barrier": "go", "parties": 2}, "label": "p1"},
            ],
        },
        {
            "worker_id": "w-2",
            "operations": [
                {"op": "publish", "tenant_id": T, "app_id": A1, "version": "2.0.0",
                 "environment": "prod", "at": NOW, "actor": "p-deploy",
                 "request_id": "req-p2", "precheck_token": "${pre2.precheck_token}",
                 "sync": {"barrier": "go", "parties": 2}, "label": "p2"},
            ],
        },
    ],
    "final_views": [
        {"op": "status"},
        {"op": "launch_query", "tenant_id": T, "app_id": A1, "environment": "prod", "at": LATE},
        {"op": "receipt_query", "app_id": A1, "tenant_id": T, "label": "hist"},
    ],
    "assertions": [
        {"type": "chain_ok"},
        {"type": "record_count", "counts": {"receipt": 1, "release": 1}},
    ],
})


# ---------------------------------------------------------------------------
# 23 - fixed ordering: publish vs. risk escalation vs. waiver extension
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "23_ordered_contention_publish_first",
    "title": "Publish commits before the escalation and the extension: it stands",
    "initial": standard_waiver_scenario(severity="medium", approvals=("ap-sec", "ap-eng")),
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre",
         "expect": {"fields": {"authorized": True}}},
    ],
    "workers": [
        {
            "worker_id": "w-publish",
            "operations": [
                {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
                 "environment": "prod", "at": NOW, "actor": "p-deploy",
                 "request_id": "req-pub", "precheck_token": "${pre.precheck_token}",
                 "sync": {"barrier": "go", "parties": 3, "hold_after": []},
                 "label": "pub"},
            ],
        },
        {
            "worker_id": "w-escalate",
            "operations": [
                {"op": "raise_risk", "risk_id": "risk-core", "severity": "high",
                 "request_id": "req-raise", "actor": "p-dave", "at": NOW,
                 "sync": {"barrier": "go", "parties": 3},
                 "expect": {"ok": True}},
            ],
        },
        {
            "worker_id": "w-extend",
            "operations": [
                {"op": "extend_waiver", "waiver_id": "wv-core",
                 "repair_deadline": "2027-01-15T00:00:00Z",
                 "request_id": "req-ext", "actor": "p-dave", "at": NOW,
                 "sync": {"barrier": "go", "parties": 3},
                 "expect": {"ok": True}},
            ],
        },
    ],
    "post_worker_ops": [
        {"op": "launch_query", "tenant_id": T, "app_id": A1, "environment": "prod",
         "at": NOW, "label": "live"},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"},
                   {"type": "record_count", "counts": {"release": 1}}],
})


# ---------------------------------------------------------------------------
# 24 - precheck token single use and request replay
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "24_token_single_use_and_replay",
    "title": "A precheck token is spent once and a replayed request returns the same receipt",
    "initial": {
        "tenants": [tenant(T)],
        "apps": [app(A1, T, "Customer Portal")],
        "software": base_registry()["software"],
        "app_versions": [
            appver(A1, "1.0.0", T, {"svc-auth": {"op": "min", "min": "3.0.0"}}),
            appver(A1, "2.0.0", T, {"svc-billing": {"op": "min", "min": "4.0.0"}}),
        ],
        "reviewers": base_registry()["reviewers"],
        "signatures": [],
        "risks": [],
    },
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre"},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre.precheck_token}", "label": "pub",
         "expect": {"ok": True}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "2.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-2",
         "precheck_token": "${pre.precheck_token}",
         "expect": {"ok": False, "code": "E_PRECHECK_CONSUMED"}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre.precheck_token}", "label": "replay",
         "expect": {"ok": True, "fields": {"replayed": True}}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "2.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre.precheck_token}",
         "expect": {"ok": False, "code": "E_IDEMPOTENCY_CONFLICT"}},
    ],
    "final_views": [
        {"op": "status"},
        {"op": "receipt_query", "request_id": "req-1", "label": "rcpt",
         "expect": {"fields": {"evidence_intact": True}}},
    ],
    "assertions": [{"type": "chain_ok"},
                   {"type": "record_count", "counts": {"receipt": 1, "release": 1}}],
})


# ---------------------------------------------------------------------------
# 25 - read-only launch query sees authority withdrawn after the fact
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "25_launch_query_reflects_withdrawn_authority",
    "title": "History keeps the receipt; the live query reports authority withdrawn",
    "initial": standard_waiver_scenario(approvals=("ap-sec", "ap-eng")),
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre"},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre.precheck_token}", "label": "pub", "expect": {"ok": True}},
        {"op": "revoke_waiver", "waiver_id": "wv-core", "request_id": "req-rw",
         "actor": "p-dave", "reason": "vendor withdrew mitigation", "at": "2026-11-21T00:00:00Z",
         "expect": {"ok": True}},
    ],
    "final_views": [
        {"op": "status"},
        {"op": "receipt_query", "receipt_id": "${pub.receipt_id}", "label": "rcpt",
         "expect": {"fields": {"evidence_intact": True, "state": "committed_acked"}}},
        {"op": "launch_query", "tenant_id": T, "app_id": A1, "environment": "prod",
         "at": "2026-11-22T00:00:00Z", "label": "live",
         "expect": {"fields": {"authorized": False, "history_matches_now": False}}},
    ],
    "assertions": [{"type": "chain_ok"}, {"type": "evidence_intact", "from": "rcpt"}],
})


# ---------------------------------------------------------------------------
# 26 - a second release supersedes the first; both receipts stay readable
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "26_release_history_remains_queryable",
    "title": "Superseded receipts stay readable and the pointer moves once",
    "initial": {
        "tenants": [tenant(T)],
        "apps": [app(A1, T, "Customer Portal")],
        "software": base_registry()["software"],
        "app_versions": [
            appver(A1, "1.0.0", T, {"svc-auth": {"op": "min", "min": "3.0.0"}}),
            appver(A1, "2.0.0", T, {"svc-billing": {"op": "min", "min": "4.0.0"}}),
            appver(A1, "3.0.0", T, {"svc-auth": {"op": "min", "min": "3.0.0"},
                                    "svc-billing": {"op": "min", "min": "4.0.0"}}),
        ],
        "reviewers": base_registry()["reviewers"],
        "signatures": [],
        "risks": [],
    },
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre1"},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1",
         "precheck_token": "${pre1.precheck_token}", "label": "pub1", "expect": {"ok": True}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "req-1b",
         "precheck_token": "${pre1.precheck_token}",
         "expect": {"ok": False, "code": "E_PRECHECK_CONSUMED"}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "2.0.0",
         "environment": "prod", "at": "2026-11-21T00:00:00Z", "label": "pre2"},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "2.0.0",
         "environment": "prod", "at": "2026-11-21T00:00:00Z", "actor": "p-deploy",
         "request_id": "req-2", "precheck_token": "${pre2.precheck_token}",
         "label": "pub2", "expect": {"ok": True}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "3.0.0",
         "environment": "prod", "at": "2026-11-22T00:00:00Z", "label": "pre3"},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "3.0.0",
         "environment": "prod", "at": "2026-11-22T00:00:00Z", "actor": "p-deploy",
         "request_id": "req-3", "precheck_token": "${pre3.precheck_token}",
         "label": "pub3", "expect": {"ok": True, "fields": {"previous_version": "2.0.0"}}},
    ],
    "final_views": [
        {"op": "status"},
        {"op": "receipt_query", "receipt_id": "${pub1.receipt_id}", "label": "old",
         "expect": {"fields": {"evidence_intact": True, "state": "committed_acked"}}},
        {"op": "receipt_query", "app_id": A1, "tenant_id": T, "label": "all"},
        {"op": "launch_query", "tenant_id": T, "app_id": A1, "environment": "prod", "at": LATE,
         "expect": {"fields": {"live.version": "3.0.0", "live.generation": 3}}},
    ],
    "assertions": [
        {"type": "chain_ok"},
        {"type": "evidence_intact", "from": "old"},
        {"type": "record_count", "counts": {"receipt": 3, "release": 1}},
    ],
})


# ---------------------------------------------------------------------------
# 27 - unknown/invalid operations and malformed references
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "27_error_codes_are_stable",
    "title": "Invalid references and operations return their documented codes",
    "initial": standard_waiver_scenario(approvals=("ap-sec", "ap-eng")),
    "operations": [
        {"op": "nope", "request_id": "r", "expect": {"ok": False, "code": "E_UNKNOWN_OP"}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "9.9.9",
         "environment": "prod", "at": NOW, "expect": {"ok": False, "code": "E_VERSION_UNKNOWN"}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "nowhere", "at": NOW, "expect": {"ok": False, "code": "E_ENV_UNKNOWN"}},
        {"op": "precheck", "tenant_id": T, "app_id": "app-ghost", "version": "1.0.0",
         "environment": "prod", "at": NOW, "expect": {"ok": False, "code": "E_UNKNOWN_REF"}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "r-np",
         "expect": {"ok": False, "code": "E_PRECHECK_REQUIRED"}},
        {"op": "publish", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "actor": "p-deploy", "request_id": "r-np2",
         "precheck_token": "sha256:" + "9" * 64,
         "expect": {"ok": False, "code": "E_PRECHECK_CONSUMED"}},
        {"op": "revoke_approval", "approval_id": "ap-ghost", "request_id": "r-rv",
         "actor": "p-dave", "at": NOW, "expect": {"ok": False, "code": "E_UNKNOWN_REF"}},
        {"op": "record_fix", "fix_id": "fx", "risk_id": "risk-core",
         "content_digest": dig("wrong-content"), "request_id": "r-fx", "at": NOW,
         "expect": {"ok": False, "code": "E_DIGEST_MISMATCH"}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"}],
})


# ---------------------------------------------------------------------------
# 28 - approval staleness: duty epoch bump and post change after signing
# ---------------------------------------------------------------------------
CASES.append({
    "case_id": "28_stale_duty_epoch",
    "title": "A duty epoch bump after signing retires the approval",
    "initial": standard_waiver_scenario(approvals=("ap-sec", "ap-eng")),
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre-before",
         "expect": {"fields": {"authorized": True}}},
        {"op": "bump_duty", "reviewer_id": "rev-sec-a", "bump_epoch": 1,
         "request_id": "req-duty", "actor": "p-hr", "at": NOW, "expect": {"ok": True}},
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre-after",
         "expect": {"fields": {"authorized": False}}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"}, {"type": "record_count", "counts": {"receipt": 0}}],
})


# ---------------------------------------------------------------------------
# 29 - forged / withdrawn signature status rejected
# ---------------------------------------------------------------------------
_forged = standard_waiver_scenario(approvals=())
_forged["signatures"] = []
sig_for(_forged, "sg-forged", "rev-sec-a", "wv-core", "risk-core", A1, "1.0.0", "prod",
        status="revoked")
sig_for(_forged, "sg-eng-a", "rev-eng-a", "wv-core", "risk-core", A1, "1.0.0", "prod")
_forged["approvals"] = [
    approval("ap-sec", "wv-core", "rev-sec-a", "security", "sg-forged", A1, "1.0.0",
             "prod", "risk-core", "core-2.1.0", "2.1.0"),
    approval("ap-eng", "wv-core", "rev-eng-a", "engineering", "sg-eng-a", A1, "1.0.0",
             "prod", "risk-core", "core-2.1.0", "2.1.0"),
]
CASES.append({
    "case_id": "29_signature_status_gates_approval",
    "title": "Only a valid simulated signature authorises a waiver",
    "initial": _forged,
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre",
         "expect": {"fields": {"authorized": False}}},
        {"op": "approve", "approval_id": "ap-new", "waiver_id": "wv-core",
         "reviewer_id": "rev-sec-a", "signature_id": "sg-forged", "app_version": "1.0.0",
         "request_id": "req-ap", "at": NOW,
         "expect": {"ok": False, "code": "E_APPROVAL_SIGNATURE"}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"}],
})


# ---------------------------------------------------------------------------
# 30 - two approvals from the same person under two posts, declared up front
# ---------------------------------------------------------------------------
_dup = standard_waiver_scenario(approvals=("ap-sec", "ap-eng"))
_dup["reviewers"] = [
    reviewer("rev-sec-a", T, "security", "p-alice"),
    reviewer("rev-eng-a", T, "engineering", "p-carol"),
    reviewer("rev-comp-a", T, "compliance", "p-dave"),
]
_dup["signatures"] = []
sig_for(_dup, "sg-sec-a", "rev-sec-a", "wv-core", "risk-core", A1, "1.0.0", "prod")
sig_for(_dup, "sg-eng-a", "rev-sec-a", "wv-core", "risk-core", A1, "1.0.0", "prod")
_dup["approvals"] = [
    approval("ap-sec", "wv-core", "rev-sec-a", "security", "sg-sec-a", A1, "1.0.0",
             "prod", "risk-core", "core-2.1.0", "2.1.0"),
    # Same reviewer, claiming the engineering post.
    approval("ap-eng", "wv-core", "rev-sec-a", "engineering", "sg-eng-a", A1, "1.0.0",
             "prod", "risk-core", "core-2.1.0", "2.1.0"),
]
CASES.append({
    "case_id": "30_same_reviewer_claims_two_posts",
    "title": "One reviewer signing under two posts is rejected",
    "initial": _dup,
    "operations": [
        {"op": "precheck", "tenant_id": T, "app_id": A1, "version": "1.0.0",
         "environment": "prod", "at": NOW, "label": "pre",
         "expect": {"fields": {"authorized": False}}},
    ],
    "final_views": [{"op": "status"}],
    "assertions": [{"type": "chain_ok"}, {"type": "record_count", "counts": {"receipt": 0}}],
})


def build() -> dict:
    return {
        "schema_version": 1,
        "generated_by": "tools/build_cases.py",
        "note": "All data is synthetic. No case contacts or modifies a real system.",
        "cases": CASES,
    }


def main() -> int:
    target = os.path.join(ROOT, "cases.json")
    document = build()
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=False)
        fh.write("\n")
    print(f"wrote {target}: {len(document['cases'])} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
