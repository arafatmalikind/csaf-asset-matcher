"""Write the sample advisories and inventory in examples/. All vendors,
products, CVE ids and URLs are fictional. Run from the repo root."""

import csv
import json
import os

HERE = os.path.join(os.path.dirname(__file__), "..", "examples")


def doc(tid, title, publisher, released, tree, vulns):
    return {
        "document": {
            "category": "csaf_security_advisory", "csaf_version": "2.0", "title": title, "lang": "en",
            "publisher": {"category": "vendor", "name": publisher, "namespace": "https://psirt.example.com"},
            "references": [{"category": "self", "summary": "Advisory", "url": "https://psirt.example.com/%s.json" % tid.lower()}],
            "tracking": {"id": tid, "status": "final", "version": "1", "initial_release_date": released,
                         "current_release_date": released,
                         "revision_history": [{"date": released, "number": "1", "summary": "Initial release"}]},
        },
        "product_tree": tree,
        "vulnerabilities": vulns,
    }


def score(products, s, sev, vec):
    return {"products": products, "cvss_v3": {"version": "3.1", "baseScore": s, "baseSeverity": sev, "vectorString": vec}}


adv1 = doc("NBA-SA-2030-004", "Authentication bypass in NX series PLC web server", "Northbridge Automation",
           "2030-02-11T09:00:00Z",
           {"branches": [{"category": "vendor", "name": "Northbridge Automation", "branches": [
               {"category": "product_name", "name": "NX-500", "branches": [
                   {"category": "product_version_range", "name": "vers:generic/<4.2.1",
                    "product": {"product_id": "NX500-LT-421", "name": "NX-500 firmware < 4.2.1"}},
                   {"category": "product_version", "name": "4.2.1",
                    "product": {"product_id": "NX500-421", "name": "NX-500 firmware 4.2.1"}}]},
               {"category": "product_name", "name": "NX-300", "branches": [
                   {"category": "product_version_range", "name": "V3.0 and prior",
                    "product": {"product_id": "NX300-LE-30", "name": "NX-300 V3.0 and prior"}}]}]}]},
           [{"cve": "CVE-2030-11001", "title": "Missing authentication for critical function", "cwe": {"id": "CWE-306", "name": "Missing Authentication for Critical Function"},
             "product_status": {"known_affected": ["NX500-LT-421", "NX300-LE-30"], "fixed": ["NX500-421"]},
             "scores": [score(["NX500-LT-421", "NX300-LE-30"], 9.8, "CRITICAL", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")],
             "threats": [{"category": "exploit_status", "details": "Vendor is aware of exploitation in the wild."}],
             "remediations": [
                 {"category": "vendor_fix", "details": "Update NX-500 firmware to 4.2.1 or later.", "product_ids": ["NX500-LT-421"],
                  "url": "https://psirt.example.com/downloads/nx500-4.2.1"},
                 {"category": "mitigation", "details": "NX-300 is end of life. Disable the web server and restrict TCP/80 and TCP/443 to the engineering workstation.",
                  "product_ids": ["NX300-LE-30"]}]}])

adv2 = doc("CALDER-2030-0012", "Multiple vulnerabilities in ViewPoint HMI", "Calder Systems", "2030-02-25T14:00:00Z",
           {"branches": [
               {"category": "vendor", "name": "Calder Systems", "branches": [
                   {"category": "product_name", "name": "ViewPoint HMI", "branches": [
                       {"category": "product_version", "name": "7.1", "product": {"product_id": "VP-71", "name": "ViewPoint HMI 7.1"}},
                       {"category": "product_version", "name": "7.2", "product": {"product_id": "VP-72", "name": "ViewPoint HMI 7.2"}},
                       {"category": "product_version", "name": "7.3", "product": {"product_id": "VP-73", "name": "ViewPoint HMI 7.3"}}]},
                   {"category": "product_name", "name": "ViewPoint Historian", "branches": [
                       {"category": "product_version_range", "name": "<= 5.4", "product": {"product_id": "VH-LE-54", "name": "ViewPoint Historian <= 5.4"}}]}]}],
            "relationships": [{"category": "default_component_of", "product_reference": "VH-LE-54", "relates_to_product_reference": "VP-72",
                               "full_product_name": {"product_id": "VH-LE-54:VP-72", "name": "ViewPoint Historian <= 5.4 bundled with ViewPoint HMI 7.2"}}]},
           [{"cve": "CVE-2030-12040", "title": "Path traversal in project import",
             "product_status": {"known_affected": ["VP-71", "VP-72"], "fixed": ["VP-73"]},
             "scores": [score(["VP-71", "VP-72"], 7.8, "HIGH", "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")],
             "remediations": [{"category": "vendor_fix", "details": "Upgrade to ViewPoint HMI 7.3.", "product_ids": ["VP-71", "VP-72"],
                               "url": "https://psirt.example.com/downloads/viewpoint-7.3"}]},
            {"cve": "CVE-2030-12041", "title": "Hard-coded credentials in historian service",
             "product_status": {"known_affected": ["VH-LE-54", "VH-LE-54:VP-72"]},
             "scores": [score(["VH-LE-54", "VH-LE-54:VP-72"], 6.5, "MEDIUM", "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")],
             "remediations": [{"category": "workaround", "details": "Change the historian service account password and block TCP/5450 from outside the SCADA zone.",
                               "product_ids": ["VH-LE-54", "VH-LE-54:VP-72"]}]}])

adv3 = doc("OSTARA-2030-03", "Denial of service in RSX industrial switches", "Ostara Networks", "2030-03-01T08:00:00Z",
           {"branches": [{"category": "vendor", "name": "Ostara Networks", "branches": [
               {"category": "product_family", "name": "RSX", "branches": [
                   {"category": "product_name", "name": "RSX-24", "branches": [
                       {"category": "product_version_range", "name": "2.0 to 2.4.9",
                        "product": {"product_id": "RSX24-20-249", "name": "RSX-24 2.0 to 2.4.9",
                                    "product_identification_helper": {"cpe": "cpe:2.3:o:ostara:rsx-24_firmware:*:*:*:*:*:*:*:*"}}}]},
                   {"category": "product_name", "name": "RSX-8", "branches": [
                       {"category": "product_version_range", "name": "builds before November 2029",
                        "product": {"product_id": "RSX8-OLD", "name": "RSX-8 builds before November 2029"}}]}]}]}]},
           [{"cve": "CVE-2030-13377", "title": "Crafted LLDP frame causes reboot",
             "product_status": {"known_affected": ["RSX24-20-249", "RSX8-OLD"]},
             "scores": [score(["RSX24-20-249", "RSX8-OLD"], 6.5, "MEDIUM", "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")],
             "remediations": [{"category": "vendor_fix", "details": "Install firmware 2.5.0.", "product_ids": ["RSX24-20-249", "RSX8-OLD"]}]}])

for name, d in (("nba-sa-2030-004.json", adv1), ("calder-2030-0012.json", adv2), ("ostara-2030-03.json", adv3)):
    with open(os.path.join(HERE, "advisories", name), "w") as f:
        json.dump(d, f, indent=2)
        f.write("\n")

inventory = [
    ("A-1001", "plc-intake-01", "Northbridge Automation Inc.", "NX-500", "4.1.7", "", "control", "high", "Process Control"),
    ("A-1002", "plc-intake-02", "Northbridge Automation Inc.", "NX-500", "4.2.1", "", "control", "high", "Process Control"),
    ("A-1003", "plc-dosing-01", "NBA", "NX-500 CPU", "V4.0.2", "", "control", "high", "Process Control"),
    ("A-1004", "plc-filter-07", "Northbridge Automation", "NX-300", "2.8", "", "control", "medium", "Process Control"),
    ("A-1005", "plc-sludge-02", "Northbridge Automation", "NX-300", "3.1", "", "control", "medium", "Process Control"),
    ("A-2001", "hmi-ops-01", "Calder Systems", "ViewPoint HMI", "7.2", "", "scada", "high", "Operations"),
    ("A-2002", "hmi-ops-02", "Calder Systems", "ViewPoint HMI", "7.3", "", "scada", "high", "Operations"),
    ("A-2003", "hmi-lab-01", "Calder Systems Ltd", "ViewPoint HMI", "7.1", "", "ops", "low", "Laboratory"),
    ("A-2101", "hist-01", "Calder Systems", "ViewPoint Historian", "5.4", "", "scada", "high", "Operations"),
    ("A-2102", "hist-02", "Calder Systems", "ViewPoint Historian", "6.0", "", "scada", "high", "Operations"),
    ("A-3001", "sw-ctrl-a", "Ostara", "RSX-24 switch", "2.4.2", "cpe:2.3:o:ostara:rsx-24_firmware:2.4.2:*:*:*:*:*:*:*", "control", "high", "Network"),
    ("A-3002", "sw-ctrl-b", "Ostara Networks", "RSX-24", "2.5.0", "", "control", "high", "Network"),
    ("A-3003", "sw-field-12", "Ostara Networks", "RSX-8", "1.9", "", "control", "medium", "Network"),
    ("A-9001", "ews-01", "Contoso", "Engineering Workstation", "22H2", "", "ops", "high", "Engineering"),
]
with open(os.path.join(HERE, "inventory.csv"), "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["asset_id", "hostname", "vendor", "product", "version", "cpe", "zone", "criticality", "owner"])
    w.writerows(inventory)
with open(os.path.join(HERE, "aliases.csv"), "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerows([["kind", "alias", "canonical"], ["vendor", "NBA", "Northbridge Automation"],
                 ["vendor", "Ostara", "Ostara Networks"], ["product", "NX-500 CPU", "NX-500"]])
print("wrote 3 advisories, %d assets" % len(inventory))
