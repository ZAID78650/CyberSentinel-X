"""Tests for dataset upload, listing, deletion, and the dataset file scanner."""


def _make_csv(path: str, rows: list[list[str]], header: list[str]) -> str:
    import csv

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    return path


def test_upload_list_and_scan_roundtrip(client, admin_headers, tmp_path):
    # Craft a CSV carrying known indicators from the local intel feed.
    csv_path = _make_csv(
        tmp_path / "probe.csv",
        [
            ["b1946ac92492d2347c6235b4d2611184", "update-secure-check.xyz", "CVE-2021-44228", "RedLine Stealer"],
            ["b1946ac92492d2347c6235b4d2611184", "update-secure-check.xyz", "", "RedLine Stealer"],
            ["44d88612fea8a8f36de82e1278abb02f", "cdn-verify-service.net", "", "Backdoor"],
            ["", "", "", ""],
        ],
        ["file_hash", "c2_domain", "cve", "attack_cat"],
    )

    with open(csv_path, "rb") as f:
        r = client.post(
            "/api/dataset/upload",
            headers=admin_headers,
            files={"file": ("probe.csv", f, "text/csv")},
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["uploaded"] is True
    assert body["name"] == "probe.csv"
    assert body["rows"] == 4
    assert "file_hash" in body["columns"]

    # Listing includes the upload with metadata.
    r = client.get("/api/dataset/uploads", headers=admin_headers)
    assert r.status_code == 200, r.text
    names = [d["name"] for d in r.json()["datasets"]]
    assert "probe.csv" in names

    # Scan the uploaded dataset — indicators must resolve to RedLine + Backdoor.
    r = client.post("/api/malware/scan-dataset", headers=admin_headers,
                    json={"dataset": "probe.csv"})
    assert r.status_code == 200, r.text
    scan = r.json()
    assert scan["dataset"] == "probe.csv"
    assert scan["rows_scanned"] == 4
    assert scan["summary"]["artifacts_detected"] >= 1
    assert scan["summary"]["indicator_matches"] >= 1

    redline = next((a for a in scan["artifacts"] if "RedLine" in a["family"]), None)
    assert redline, "RedLine Stealer should be found from hash + family column"
    assert redline["hashes"]  # matched hash
    assert redline["c2_domains"]  # matched C2 domain
    assert redline["cves"]  # matched CVE
    assert redline["matched_indicators"]
    assert any(i["kind"] == "HASH" for i in redline["matched_indicators"])

    # Scan of a missing dataset -> 404.
    r = client.post("/api/malware/scan-dataset", headers=admin_headers,
                    json={"dataset": "nope.csv"})
    assert r.status_code == 404

    # Delete removes it from the registry.
    r = client.delete("/api/dataset/uploads/probe.csv", headers=admin_headers)
    assert r.status_code == 200, r.text
    r = client.get("/api/dataset/uploads", headers=admin_headers)
    names = [d["name"] for d in r.json()["datasets"]]
    assert "probe.csv" not in names


def test_upload_rejects_non_csv_and_duplicates(client, admin_headers, tmp_path):
    txt = tmp_path / "evil.txt"
    txt.write_text("not a csv")
    with open(txt, "rb") as f:
        r = client.post(
            "/api/dataset/upload",
            headers=admin_headers,
            files={"file": ("evil.txt", f, "text/plain")},
        )
    assert r.status_code == 400
    assert "csv" in r.json()["detail"].lower()

    csv_path = _make_csv(tmp_path / "dup.csv", [["x"]], ["col"])
    with open(csv_path, "rb") as f:
        r = client.post(
            "/api/dataset/upload",
            headers=admin_headers,
            files={"file": ("dup.csv", f, "text/csv")},
        )
    assert r.status_code == 200
    with open(csv_path, "rb") as f:
        r2 = client.post(
            "/api/dataset/upload",
            headers=admin_headers,
            files={"file": ("dup.csv", f, "text/csv")},
        )
    assert r2.status_code == 409
    client.delete("/api/dataset/uploads/dup.csv", headers=admin_headers)


def test_ingest_uploaded_dataset(client, admin_headers, tmp_path):
    """Uploaded CSVs can be kicked through the detection pipeline."""
    csv_path = _make_csv(
        tmp_path / "small.csv",
        [["0"], ["1"]],
        ["label"],
    )
    with open(csv_path, "rb") as f:
        r = client.post(
            "/api/dataset/upload",
            headers=admin_headers,
            files={"file": ("small.csv", f, "text/csv")},
        )
    assert r.status_code == 200

    r = client.post("/api/dataset/uploads/small.csv/ingest", headers=admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["started"] is True
    assert "small.csv" in r.json()["message"]

    # Missing upload -> 404
    r = client.post("/api/dataset/uploads/nope.csv/ingest", headers=admin_headers)
    assert r.status_code == 404

    client.delete("/api/dataset/uploads/small.csv", headers=admin_headers)


def test_upload_requires_admin(client, analyst_headers, tmp_path):
    csv_path = _make_csv(tmp_path / "a.csv", [["x"]], ["col"])
    with open(csv_path, "rb") as f:
        r = client.post(
            "/api/dataset/upload",
            headers=analyst_headers,
            files={"file": ("a.csv", f, "text/csv")},
        )
    assert r.status_code == 403
