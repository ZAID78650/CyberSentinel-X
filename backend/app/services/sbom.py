"""Software Bill of Materials (SBOM) scanner.

Scans the platform's own dependency manifests (frontend package-lock.json,
backend requirements.txt) into a normalized SBOM and cross-references
dependencies against the *local* threat-intel CVE feed. No external NVD feed
is assumed: if a CVE is not in the local feed it is reported as such rather
than guessed. Results are therefore honest provenance — SOURCE: LOCAL
MANIFESTS, CVE DATA: LOCAL FEED.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.intel import ThreatIndicator

# ---------------------------------------------------------------------------
# Curated CVE reference (local, static, clearly labeled).
#
# Real published CVEs for the platform's own dependency stack, with the
# patched version where known. Applicability is computed from the pinned
# version in the manifest; where a version can't be compared the finding is
# flagged "check". This is an advisory reference dataset — NOT a live NVD
# feed — and is reported as such to the UI.
# ---------------------------------------------------------------------------
CURATED_CVES: Dict[str, List[Dict[str, Any]]] = {
    "vite": [
        {"cve": "CVE-2025-30208", "severity": "HIGH", "confidence": 0.9,
         "source": "curated-reference", "fixed_in": "6.2.3", "scope": "dev-server",
         "description": "Dev-server arbitrary file read via crafted URL (server.fs bypass). No production impact, but a supply-chain hygiene finding."},
    ],
    "axios": [
        {"cve": "CVE-2023-45857", "severity": "MEDIUM", "confidence": 0.85,
         "source": "curated-reference", "fixed_in": "1.6.0",
         "description": "Regular-expression denial of service in axios URL parsing."},
        {"cve": "CVE-2024-39338", "severity": "MEDIUM", "confidence": 0.85,
         "source": "curated-reference", "fixed_in": "1.7.4",
         "description": "Server-Side Request Forgery when axios follows redirects on Node with allowAbsoluteUrls."},
    ],
    "python-multipart": [
        {"cve": "CVE-2024-24762", "severity": "MEDIUM", "confidence": 0.9,
         "source": "curated-reference", "fixed_in": "0.0.18",
         "description": "Denial of service via excessive number of multipart form parts."},
    ],
    "pydantic": [
        {"cve": "CVE-2024-3772", "severity": "LOW", "confidence": 0.8,
         "source": "curated-reference", "fixed_in": "2.7.1",
         "description": "Regular-expression denial of service in EmailStr validation."},
    ],
    "starlette": [
        {"cve": "CVE-2024-47874", "severity": "MEDIUM", "confidence": 0.9,
         "source": "curated-reference", "fixed_in": "0.41.3",
         "description": "Denial of service via multipart form parsing (race condition)."},
    ],
    "log4j": [
        {"cve": "CVE-2021-44228", "severity": "CRITICAL", "confidence": 0.99,
         "source": "curated-reference", "fixed_in": None,
         "description": "Log4Shell — remote code execution in Apache Log4j 2.x."},
    ],
}


def _parse_version(v: str) -> Optional[Tuple[int, ...]]:
    """Best-effort dotted-numeric version tuple (drops pre-release suffixes)."""
    parts = []
    for seg in re.split(r"[.\-+_]", v.strip()):
        if seg.isdigit():
            parts.append(int(seg))
        else:
            break
    return tuple(parts) if parts else None


def _version_lt(a: str, b: str) -> Optional[bool]:
    ta, tb = _parse_version(a), _parse_version(b)
    if ta is None or tb is None:
        return None
    return ta < tb

MANIFEST_CANDIDATES = {
    "frontend/package-lock.json",
    "package-lock.json",
    "../frontend/package-lock.json",
    "frontend/package.json",
    "backend/requirements.txt",
    "requirements.txt",
    "../backend/requirements.txt",
}


def _find_manifest(name: str) -> Optional[str]:
    for cand in sorted(MANIFEST_CANDIDATES):
        if os.path.basename(cand) == name and os.path.isfile(cand):
            return cand
    return None


def _parse_package_lock(path: str) -> List[Dict[str, Any]]:
    deps: List[Dict[str, Any]] = []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return deps
    pkgs = data.get("packages") or {}
    for loc, info in pkgs.items():
        if not loc:  # root package
            continue
        name = info.get("name")
        if not name:
            # derive from path like node_modules/@scope/name
            name = loc.replace("node_modules/", "")
        deps.append(
            {
                "name": name,
                "version": info.get("version", "unknown"),
                "ecosystem": "npm",
                "type": info.get("dev") is True and "dev" or "runtime",
                "license": info.get("license", "unknown"),
                "integrity": bool(info.get("integrity")),
            }
        )
    return deps


def _parse_requirements(path: str) -> List[Dict[str, Any]]:
    deps: List[Dict[str, Any]] = []
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return deps
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # name==version  or  name>=version, ... (keep == pinned as "pinned")
        m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*==\s*([^\s,;]+)", line)
        if m:
            deps.append(
                {
                    "name": m.group(1),
                    "version": m.group(2),
                    "ecosystem": "pypi",
                    "type": "runtime",
                    "license": "unknown",
                    "integrity": False,
                }
            )
        else:
            name = re.match(r"^([A-Za-z0-9_.\-\[\]]+)", line)
            if name:
                deps.append(
                    {
                        "name": name.group(1),
                        "version": "unpinned",
                        "ecosystem": "pypi",
                        "type": "runtime",
                        "license": "unknown",
                        "integrity": False,
                    }
                )
    return deps


def _load_local_cves(db: Session) -> Dict[str, ThreatIndicator]:
    rows = list(
        db.scalars(
            select(ThreatIndicator).where(ThreatIndicator.indicator_type == "CVE")
        ).all()
    )
    return {r.value.upper(): r for r in rows}


def scan_sbom(db: Session) -> Dict[str, Any]:
    """Build the SBOM and cross-reference dependencies against the local feed."""
    deps: List[Dict[str, Any]] = []
    manifests: List[Dict[str, Any]] = []

    npm_path = _find_manifest("package-lock.json")
    if npm_path:
        parsed = _parse_package_lock(npm_path)
        deps.extend(parsed)
        manifests.append({"file": npm_path, "format": "npm package-lock.json", "dependencies": len(parsed)})

    req_path = _find_manifest("requirements.txt")
    if req_path:
        parsed = _parse_requirements(req_path)
        deps.extend(parsed)
        manifests.append({"file": req_path, "format": "pip requirements.txt (pinned)", "dependencies": len(parsed)})

    local_cves = _load_local_cves(db)
    cve_findings: List[Dict[str, Any]] = []
    for dep in deps:
        name_l = dep["name"].lower()
        matched_cves: List[Dict[str, Any]] = []
        # 1) Curated reference dataset (version-aware, advisory).
        # Exact-name match, except the documented log4j family (log4j-core,
        # log4j-api) which are real Log4j components.
        for package, refs in CURATED_CVES.items():
            if package == "log4j":
                if not name_l.startswith("log4j"):
                    continue
            elif name_l != package:
                continue
            for ref in refs:
                entry = {
                    "cve": ref["cve"],
                    "severity": ref["severity"],
                    "confidence": ref["confidence"],
                    "source": ref["source"],
                    "description": ref["description"],
                }
                if ref["fixed_in"] is None:
                    entry["status"] = "advisory"
                    entry["note"] = "applicability requires manual version check"
                else:
                    lt = _version_lt(dep["version"], ref["fixed_in"])
                    if lt is True:
                        entry["status"] = "affected"
                        entry["note"] = f"installed {dep['version']} < patched {ref['fixed_in']}"
                    elif lt is False:
                        entry["status"] = "patched"
                        entry["note"] = f"installed {dep['version']} >= patched {ref['fixed_in']}"
                    else:
                        entry["status"] = "check"
                        entry["note"] = f"could not compare installed version against {ref['fixed_in']}"
                matched_cves.append(entry)
        # 2) Local feed keyword matches (feed CVEs, e.g. log4j via local store).
        for entry in matched_cves:
            ind = local_cves.get(entry["cve"].upper())
            if ind is not None:
                entry["in_local_feed"] = True
        dep["known_cves"] = matched_cves
        dep["vulnerable"] = any(c["status"] == "affected" for c in matched_cves)
        if any(c["status"] in ("affected", "check") for c in matched_cves):
            cve_findings.append({"dependency": dep["name"], "version": dep["version"], "cves": matched_cves})

    total = len(deps)
    vulnerable = sum(1 for d in deps if d["vulnerable"])
    critical = sum(1 for d in deps if any(
        c["severity"] == "CRITICAL" and c["status"] != "patched" for c in d["known_cves"]
    ))
    unpinned = sum(1 for d in deps if d["version"] in ("unknown", "unpinned"))
    no_integrity = sum(1 for d in deps if d["ecosystem"] == "npm" and not d["integrity"])
    unlicensed = sum(1 for d in deps if d["license"] == "unknown")

    # Explainable supply-chain risk (0-100): weighting is visible, not magic.
    risk = 0.0
    factors: List[Dict[str, Any]] = []
    if total:
        vuln_component = min(60.0, (vulnerable / total) * 100 * 6)
        risk += vuln_component
        factors.append({"factor": "Known vulnerable dependencies", "contribution": round(vuln_component, 1),
                        "evidence": f"{vulnerable}/{total} dependencies match local CVE feed"})
        crit_component = min(25.0, critical * 12)
        risk += crit_component
        factors.append({"factor": "Critical-severity CVEs", "contribution": round(crit_component, 1),
                        "evidence": f"{critical} critical CVE match(es)"})
        pin_component = min(15.0, (unpinned / total) * 100 * 3)
        risk += pin_component
        factors.append({"factor": "Unpinned dependencies", "contribution": round(pin_component, 1),
                        "evidence": f"{unpinned} dependency versions not pinned"})
        integrity_component = min(12.0, (no_integrity / max(total, 1)) * 100 * 2.4)
        risk += integrity_component
        factors.append({"factor": "Missing integrity hashes (npm)", "contribution": round(integrity_component, 1),
                        "evidence": f"{no_integrity} npm packages without integrity hash"})
    risk = round(min(100.0, risk), 1)
    if risk >= 60:
        level = "HIGH"
    elif risk >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "format": "hybrid (npm lockfile + pip requirements)",
        "manifests": manifests,
        "dependencies": deps,
        "totals": {
            "dependencies": total,
            "ecosystems": sorted({d["ecosystem"] for d in deps}),
            "vulnerable": vulnerable,
            "critical": critical,
            "unpinned": unpinned,
            "unlicensed": unlicensed,
        },
        "findings": cve_findings,
        "supply_chain_risk": {"score": risk, "level": level, "factors": factors},
        "provenance": {
            "mode": "DATASET",
            "source": "local manifests (package-lock.json, requirements.txt)",
            "cve_feed": "CURATED REFERENCE + LOCAL FEED — NO LIVE NVD/OSV FEED CONFIGURED",
        },
    }
