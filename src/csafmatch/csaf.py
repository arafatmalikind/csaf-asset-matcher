"""Read CSAF 2.0 documents into a flat, matchable form."""

import json
import re
from dataclasses import dataclass, field
from typing import List, Optional

from .versions import Range, parse_range


@dataclass
class Product:
    product_id: str
    vendor: str = ""
    family: str = ""
    name: str = ""
    version: str = ""             # exact version, from a product_version branch
    range_text: str = ""          # raw product_version_range name
    range: Optional[Range] = None
    cpe: str = ""
    platform: str = ""            # set for relationship products ("installed on ...")
    label: str = ""


@dataclass
class Vuln:
    cve: str
    title: str
    status: dict                  # product_id -> affected | fixed | not_affected | investigating
    cvss: dict                    # product_id -> (score, severity, vector)
    remediations: list            # [{category, details, url, product_ids}]
    exploited: bool = False
    cwe: str = ""


@dataclass
class Advisory:
    id: str
    title: str
    publisher: str
    released: str
    url: str
    products: dict = field(default_factory=dict)
    vulns: List[Vuln] = field(default_factory=list)


_STATUS = {
    "known_affected": "affected", "first_affected": "affected", "last_affected": "affected",
    "fixed": "fixed", "first_fixed": "fixed",
    "known_not_affected": "not_affected",
    "under_investigation": "investigating",
}


def _walk(branches, ctx, out):
    for b in branches or []:
        c = dict(ctx)
        cat, name = b.get("category"), b.get("name", "")
        if cat == "vendor":
            c["vendor"] = name
        elif cat == "product_family":
            c["family"] = name
        elif cat == "product_name":
            c["name"] = name
        elif cat == "product_version":
            c["version"] = name
        elif cat == "product_version_range":
            c["range_text"] = name
        if "product" in b:
            p = b["product"]
            helper = p.get("product_identification_helper", {}) or {}
            prod = Product(product_id=p["product_id"], vendor=c.get("vendor", ""), family=c.get("family", ""),
                           name=c.get("name", "") or c.get("family", ""), version=c.get("version", ""),
                           range_text=c.get("range_text", ""), cpe=helper.get("cpe", ""), label=p.get("name", ""))
            if prod.range_text:
                prod.range = parse_range(prod.range_text)
            if not prod.name and prod.cpe:
                prod.name = _cpe_part(prod.cpe, 4)
            if not prod.vendor and prod.cpe:
                prod.vendor = _cpe_part(prod.cpe, 3)
            out[prod.product_id] = prod
        _walk(b.get("branches"), c, out)


def _cpe_part(cpe, idx):
    parts = cpe.split(":")
    return parts[idx].replace("_", " ") if len(parts) > idx else ""


def _full_name(fpn):
    helper = fpn.get("product_identification_helper", {}) or {}
    cpe = helper.get("cpe", "")
    p = Product(product_id=fpn["product_id"], label=fpn.get("name", ""), cpe=cpe)
    if cpe:
        p.vendor, p.name = _cpe_part(cpe, 3), _cpe_part(cpe, 4)
        ver = _cpe_part(cpe, 5)
        if ver not in ("", "*", "-"):
            p.version = ver
    return p


def load(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    return parse(doc)


def parse(doc):
    d = doc.get("document", {})
    if not str(d.get("csaf_version", "")).startswith("2."):
        raise ValueError("not a CSAF 2.x document (csaf_version=%r)" % d.get("csaf_version"))
    tracking = d.get("tracking", {})
    url = ""
    for ref in d.get("references", []) or []:
        if ref.get("category") == "self":
            url = ref.get("url", "")
            break
    adv = Advisory(id=tracking.get("id", "?"), title=d.get("title", ""),
                   publisher=(d.get("publisher") or {}).get("name", ""),
                   released=tracking.get("initial_release_date", ""), url=url)
    tree = doc.get("product_tree", {}) or {}
    _walk(tree.get("branches"), {}, adv.products)
    for fpn in tree.get("full_product_names", []) or []:
        adv.products.setdefault(fpn["product_id"], _full_name(fpn))
    for rel in tree.get("relationships", []) or []:
        fpn = rel.get("full_product_name", {})
        base = adv.products.get(rel.get("product_reference"))
        plat = adv.products.get(rel.get("relates_to_product_reference"))
        if not fpn or not base:
            continue
        p = Product(**{k: getattr(base, k) for k in base.__dataclass_fields__})
        p.product_id, p.label = fpn["product_id"], fpn.get("name", base.label)
        if plat:
            p.platform = " ".join(x for x in (plat.vendor, plat.name, plat.version or plat.range_text) if x)
        adv.products[p.product_id] = p
    groups = {g["group_id"]: g.get("product_ids", []) for g in tree.get("product_groups", []) or []}

    for v in doc.get("vulnerabilities", []) or []:
        status = {}
        for key, ids in (v.get("product_status") or {}).items():
            st = _STATUS.get(key)
            if st:
                for pid in ids:
                    status.setdefault(pid, st)
        cvss = {}
        for s in v.get("scores", []) or []:
            c = s.get("cvss_v3") or s.get("cvss_v4") or s.get("cvss_v2") or {}
            score = c.get("baseScore")
            if score is None:
                continue
            sev = c.get("baseSeverity") or _severity(score)
            for pid in s.get("products", []):
                if pid not in cvss or score > cvss[pid][0]:
                    cvss[pid] = (float(score), sev.upper(), c.get("vectorString", ""))
        rems = []
        for r in v.get("remediations", []) or []:
            ids = list(r.get("product_ids", []) or [])
            for g in r.get("group_ids", []) or []:
                ids.extend(groups.get(g, []))
            rems.append({"category": r.get("category", ""), "details": _oneline(r.get("details", "")),
                         "url": r.get("url", ""), "product_ids": ids})
        exploited = any(t.get("category") == "exploit_status" and re.search(r"exploited|in the wild|kev", t.get("details", ""), re.I)
                        for t in v.get("threats", []) or [])
        cwe = (v.get("cwe") or {}).get("id", "")
        adv.vulns.append(Vuln(cve=v.get("cve") or (v.get("ids") or [{}])[0].get("text", "N/A"),
                              title=v.get("title", ""), status=status, cvss=cvss, remediations=rems,
                              exploited=exploited, cwe=cwe))
    return adv


def _oneline(s):
    return re.sub(r"\s+", " ", s).strip()


def _severity(score):
    score = float(score)
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"
