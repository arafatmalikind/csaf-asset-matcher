import json
import os

from csafmatch import csaf, match
from csafmatch.cli import main

EX = os.path.join(os.path.dirname(__file__), "..", "examples")


def advisories():
    d = os.path.join(EX, "advisories")
    return [csaf.load(os.path.join(d, f)) for f in sorted(os.listdir(d))]


def findings():
    return match.match(advisories(), match.load_inventory(os.path.join(EX, "inventory.csv")),
                       match.Aliases(os.path.join(EX, "aliases.csv")))


def by_host(fs):
    out = {}
    for f in fs:
        out.setdefault(f.hostname, []).append(f)
    return out


def test_parse_product_tree():
    adv = {a.id: a for a in advisories()}["NBA-SA-2030-004"]
    p = adv.products["NX500-LT-421"]
    assert (p.vendor, p.name, p.range_text) == ("Northbridge Automation", "NX-500", "vers:generic/<4.2.1")
    v = adv.vulns[0]
    assert v.exploited and v.status["NX500-421"] == "fixed" and v.cvss["NX300-LE-30"][0] == 9.8


def test_relationship_products():
    adv = {a.id: a for a in advisories()}["CALDER-2030-0012"]
    p = adv.products["VH-LE-54:VP-72"]
    assert p.name == "ViewPoint Historian" and "ViewPoint HMI 7.2" in p.platform


def test_expected_matches():
    h = by_host(findings())
    status = {k: {(f.cve, f.status) for f in v} for k, v in h.items()}
    assert status["plc-intake-01"] == {("CVE-2030-11001", "affected")}
    assert status["plc-intake-02"] == {("CVE-2030-11001", "fixed")}
    assert status["plc-dosing-01"] == {("CVE-2030-11001", "affected")}       # via alias
    assert status["plc-filter-07"] == {("CVE-2030-11001", "affected")}       # legacy "and prior"
    assert "plc-sludge-02" not in h                                          # 3.1 is above V3.0
    assert status["hmi-ops-01"] == {("CVE-2030-12040", "affected")}
    assert status["hmi-ops-02"] == {("CVE-2030-12040", "fixed")}
    assert status["hist-01"] == {("CVE-2030-12041", "affected")}
    assert "hist-02" not in h
    assert status["sw-ctrl-a"] == {("CVE-2030-13377", "affected")}           # via CPE
    assert "sw-ctrl-b" not in h
    assert status["sw-field-12"] == {("CVE-2030-13377", "review")}
    assert "ews-01" not in h


def test_priorities_and_remediation():
    h = by_host(findings())
    f = h["plc-filter-07"][0]
    assert f.priority == "P1" and f.remediation.startswith("mitigation:")
    assert h["hist-01"][0].priority == "P2"            # medium CVSS on a high criticality asset
    assert h["sw-ctrl-a"][0].confidence == "high" and h["sw-ctrl-a"][0].matched_on.startswith("cpe")


def test_vendor_must_match():
    a = match.Asset("x", "x", "Other Vendor", "NX-500", "4.0")
    assert match.match(advisories(), [a]) == []


def test_contained_name_without_alias():
    a = match.Asset("x", "x", "Northbridge Automation", "NX-500 CPU 4 port", "4.0")
    (f,) = match.match(advisories(), [a])
    assert f.confidence == "medium" and f.matched_on.startswith("name-contained")


def test_rejects_non_csaf(tmp_path):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"document": {"csaf_version": "1.2"}}))
    try:
        csaf.load(str(p))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_cli_csv_and_fail_on(tmp_path, capsys):
    out = tmp_path / "f.csv"
    rc = main([os.path.join(EX, "advisories"), "-i", os.path.join(EX, "inventory.csv"),
               "-a", os.path.join(EX, "aliases.csv"), "-f", "csv", "-o", str(out), "--fail-on", "P1"])
    assert rc == 1
    lines = out.read_text().splitlines()
    assert lines[0].startswith("asset_id,hostname") and len(lines) == 9
