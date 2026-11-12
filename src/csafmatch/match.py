"""Match advisory products to inventory assets and decide what applies."""

import csv
import re
from dataclasses import dataclass, asdict

from .versions import compare

_SUFFIX = re.compile(r"\b(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|gmbh|ag|sa|plc|group|se)\b\.?")
_GENERIC = {"family", "series", "all", "versions", "version", "the", "and", "devices", "device", "products", "product"}
_RANK = {"affected": 4, "review": 3, "investigating": 2, "fixed": 1, "not_affected": 0}


def norm(s):
    s = str(s or "").lower().replace("_", " ")
    s = _SUFFIX.sub(" ", s)
    s = re.sub(r"[^a-z0-9.+/-]+", " ", s)
    return " ".join(s.split())


def words(s):
    return {w for w in re.split(r"[\s/]+", norm(s)) if w and w not in _GENERIC}


@dataclass
class Asset:
    asset_id: str
    hostname: str
    vendor: str
    product: str
    version: str
    cpe: str = ""
    zone: str = ""
    criticality: str = ""
    owner: str = ""


def load_inventory(path):
    assets = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            r = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
            if not r.get("vendor") and not r.get("cpe"):
                continue
            assets.append(Asset(asset_id=r.get("asset_id") or r.get("id") or r.get("hostname", ""),
                                hostname=r.get("hostname") or r.get("name", ""), vendor=r.get("vendor", ""),
                                product=r.get("product") or r.get("model", ""),
                                version=r.get("version") or r.get("firmware", ""), cpe=r.get("cpe", ""),
                                zone=r.get("zone", ""), criticality=r.get("criticality", "").lower(),
                                owner=r.get("owner", "")))
    return assets


class Aliases:
    """CSV with columns kind,alias,canonical  (kind = vendor | product)."""

    def __init__(self, path=None):
        self.vendor, self.product = {}, {}
        if path:
            with open(path, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    table = self.vendor if row["kind"].strip() == "vendor" else self.product
                    table[norm(row["alias"])] = norm(row["canonical"])

    def v(self, s):
        n = norm(s)
        return self.vendor.get(n, n)

    def p(self, s):
        n = norm(s)
        return self.product.get(n, n)


def _cpe(c):
    parts = c.split(":")
    if len(parts) < 6:
        return None
    return parts[3], parts[4], parts[5]


def identify(product, asset, aliases):
    """How the advisory product names this asset: (confidence, how) or None."""
    if product.cpe and asset.cpe:
        a, b = _cpe(product.cpe), _cpe(asset.cpe)
        if a and b and a[0] == b[0] and a[1] == b[1]:
            return "high", "cpe"
    if not product.vendor or aliases.v(product.vendor) != aliases.v(asset.vendor):
        return None
    pname, aname = aliases.p(product.name), aliases.p(asset.product)
    if pname and pname == aname:
        return "high", "name"
    pw, aw = words(pname), words(aname)
    if pw and pw <= aw:
        return "medium", "name-contained"
    if product.family and words(product.family) and words(product.family) <= aw and not pw:
        return "medium", "family"
    return None


def version_applies(product, version):
    """True / False, or None when the advisory version text could not be read."""
    if product.version:
        return compare(version, product.version) == 0
    if product.range_text:
        if product.range is None:
            return None
        return product.range.contains(version)
    return True


_SPECIFIC = {"exact": 3, "range": 2, "any": 1, "unparsed": 0}


@dataclass
class Finding:
    asset_id: str
    hostname: str
    zone: str
    criticality: str
    vendor: str
    product: str
    version: str
    advisory: str
    advisory_title: str
    advisory_url: str
    cve: str
    title: str
    status: str
    cvss: float
    severity: str
    vector: str
    exploited: bool
    priority: str
    confidence: str
    matched_on: str
    advisory_product: str
    remediation: str
    remediation_url: str

    def row(self):
        return asdict(self)


def _priority(status, cvss, exploited, criticality):
    if status != "affected":
        return "-" if status in ("fixed", "not_affected") else "P3"
    if exploited or cvss >= 9.0:
        return "P1"
    if cvss >= 7.0 or (cvss >= 4.0 and criticality in ("high", "critical")):
        return "P2"
    return "P3"


def match(advisories, assets, aliases=None):
    aliases = aliases or Aliases()
    findings = []
    for adv in advisories:
        for asset in assets:
            ids = {}
            for pid, prod in adv.products.items():
                hit = identify(prod, asset, aliases)
                if hit:
                    ids[pid] = (prod, hit)
            if not ids:
                continue
            for v in adv.vulns:
                best = None
                for pid, (prod, (conf, how)) in ids.items():
                    st = v.status.get(pid)
                    if not st:
                        continue
                    ok = version_applies(prod, asset.version) if asset.version else None
                    if ok is False:
                        continue
                    spec = "unparsed" if ok is None else ("exact" if prod.version else "range" if prod.range_text else "any")
                    status = "review" if ok is None and st == "affected" else st
                    key = (_SPECIFIC[spec], _RANK[status])
                    if best is None or key > best[0]:
                        best = (key, pid, prod, status, conf if ok is not None else "low", how, spec)
                if not best:
                    continue
                _, pid, prod, status, conf, how, spec = best
                score, sev, vec = v.cvss.get(pid, (0.0, "", ""))
                if not score:
                    for p2 in ids:
                        if p2 in v.cvss:
                            score, sev, vec = v.cvss[p2]
                            break
                rem = [r for r in v.remediations if pid in r["product_ids"]] or \
                      [r for r in v.remediations if not r["product_ids"]]
                rem.sort(key=lambda r: {"vendor_fix": 0, "mitigation": 1, "workaround": 2}.get(r["category"], 3))
                label = prod.label or " ".join(x for x in (prod.vendor, prod.name, prod.version or prod.range_text) if x)
                if prod.platform:
                    label += " (on %s)" % prod.platform
                findings.append(Finding(
                    asset_id=asset.asset_id, hostname=asset.hostname, zone=asset.zone, criticality=asset.criticality,
                    vendor=asset.vendor, product=asset.product, version=asset.version, advisory=adv.id,
                    advisory_title=adv.title, advisory_url=adv.url, cve=v.cve, title=v.title, status=status,
                    cvss=score, severity=sev, vector=vec, exploited=v.exploited,
                    priority=_priority(status, score, v.exploited, asset.criticality), confidence=conf,
                    matched_on="%s/%s" % (how, spec), advisory_product=label,
                    remediation=("%s: %s" % (rem[0]["category"], rem[0]["details"])) if rem else "",
                    remediation_url=rem[0]["url"] if rem else ""))
    order = {"P1": 0, "P2": 1, "P3": 2, "-": 3}
    findings.sort(key=lambda f: (order[f.priority], -f.cvss, f.asset_id, f.cve))
    return findings
