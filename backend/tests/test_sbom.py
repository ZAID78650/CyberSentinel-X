"""Tests for the SBOM / supply-chain scanner (Feature 31)."""
from app.services import sbom


def test_sbom_scans_real_manifests(db_session):
    result = sbom.scan_sbom(db_session)
    assert result["format"].startswith("hybrid")
    assert result["manifests"], "expected at least one manifest to be found"
    assert result["totals"]["dependencies"] > 0
    # Every affected finding must be reflected in the vulnerable count.
    affected_findings = sum(
        1 for f in result["findings"] if any(c["status"] == "affected" for c in f["cves"])
    )
    assert affected_findings == result["totals"]["vulnerable"]
    # The platform's own lockfile is a real manifest: vite 5.x is affected by
    # CVE-2025-30208 (dev-server file read, patched in 6.2.3).
    vite = next((d for d in result["dependencies"] if d["name"] == "vite"), None)
    if vite is not None:
        assert vite["vulnerable"]
        cves = {c["cve"]: c for c in vite["known_cves"]}
        assert cves["CVE-2025-30208"]["status"] == "affected"
    # Ecosystem list is populated from real deps.
    assert result["totals"]["ecosystems"]
    # Provenance is honest about the feed.
    assert "NO LIVE" in result["provenance"]["cve_feed"].upper()
    assert result["supply_chain_risk"]["score"] >= 0
    assert result["supply_chain_risk"]["level"] in ("LOW", "MEDIUM", "HIGH")
    assert result["supply_chain_risk"]["factors"]


def test_sbom_dependencies_have_fields(db_session):
    result = sbom.scan_sbom(db_session)
    for dep in result["dependencies"]:
        assert {"name", "version", "ecosystem", "type", "license"} <= set(dep)
        assert "known_cves" in dep
        assert dep["vulnerable"] == any(c["status"] == "affected" for c in dep["known_cves"])
