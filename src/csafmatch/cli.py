import argparse
import csv
import io
import json
import os
import sys
from collections import Counter

from . import __version__, csaf, match


def _expand(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in sorted(files):
                    if f.endswith(".json"):
                        yield os.path.join(root, f)
        else:
            yield p


def _md(findings, advisories, assets, skipped):
    affected = [f for f in findings if f.status in ("affected", "review")]
    hosts = {f.asset_id for f in affected}
    pc = Counter(f.priority for f in affected)
    out = ["# CSAF advisory match report", "",
           "%d advisories, %d assets. **%d assets affected** by %d CVEs (P1: %d, P2: %d, P3: %d)." % (
               len(advisories), len(assets), len(hosts), len({f.cve for f in affected}), pc["P1"], pc["P2"], pc["P3"]), ""]
    if skipped:
        out += ["Skipped %d file(s) that are not CSAF 2.x: %s" % (len(skipped), ", ".join(skipped)), ""]
    out += ["## Affected assets", "",
            "| Priority | Asset | Zone | Product | Version | CVE | CVSS | Exploited | Advisory | Fix |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for f in affected:
        out.append("| %s | %s | %s | %s %s | %s | %s | %s | %s | %s | %s |" % (
            f.priority + ("?" if f.status == "review" else ""), f.hostname or f.asset_id, f.zone, f.vendor, f.product,
            f.version, f.cve, ("%.1f" % f.cvss) if f.cvss else "", "yes" if f.exploited else "",
            f.advisory, f.remediation.replace("|", "/")[:120]))
    review = [f for f in findings if f.status == "review"]
    if review:
        out += ["", "## Needs review", "",
                "The advisory gives a version range this tool could not parse. Check these by hand.", ""]
        for f in review:
            out.append("- %s %s %s: %s, advisory says `%s`" % (f.hostname, f.product, f.version, f.cve, f.advisory_product))
    fixed = [f for f in findings if f.status == "fixed"]
    if fixed:
        out += ["", "## Already on a fixed version", ""]
        for f in fixed:
            out.append("- %s %s %s: %s" % (f.hostname, f.product, f.version, f.cve))
    out += ["", "## Advisories", "", "| Advisory | Publisher | Released | Title | Assets affected |", "|---|---|---|---|---|"]
    for a in advisories:
        n = len({f.asset_id for f in affected if f.advisory == a.id})
        out.append("| %s | %s | %s | %s | %d |" % (a.id, a.publisher, a.released[:10], a.title, n))
    return "\n".join(out) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="csaf-match", description="Match CSAF 2.0 advisories against an asset inventory.")
    ap.add_argument("advisories", nargs="+", help="CSAF JSON files or directories")
    ap.add_argument("-i", "--inventory", required=True, help="asset inventory CSV")
    ap.add_argument("-a", "--aliases", help="vendor/product alias CSV (kind,alias,canonical)")
    ap.add_argument("-f", "--format", choices=["md", "csv", "json"], default="md")
    ap.add_argument("-o", "--output")
    ap.add_argument("--all", action="store_true", help="csv/json: include fixed and not-affected results")
    ap.add_argument("--fail-on", choices=["P1", "P2", "P3", "never"], default="never")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    try:
        assets = match.load_inventory(args.inventory)
        aliases = match.Aliases(args.aliases)
        advisories, skipped = [], []
        for p in _expand(args.advisories):
            try:
                advisories.append(csaf.load(p))
            except ValueError:
                skipped.append(os.path.basename(p))
    except (OSError, KeyError) as e:
        print("csaf-match: %s" % e, file=sys.stderr)
        return 2
    findings = match.match(advisories, assets, aliases)
    if args.format == "md":
        text = _md(findings, advisories, assets, skipped)
    else:
        rows = [f.row() for f in findings if args.all or f.status in ("affected", "review", "investigating")]
        if args.format == "json":
            text = json.dumps(rows, indent=2) + "\n"
        else:
            buf = io.StringIO()
            cols = list(match.Finding.__dataclass_fields__)
            w = csv.DictWriter(buf, fieldnames=cols, lineterminator="\n")
            w.writeheader()
            w.writerows(rows)
            text = buf.getvalue()
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    if args.fail_on != "never":
        levels = {"P1": {"P1"}, "P2": {"P1", "P2"}, "P3": {"P1", "P2", "P3"}}[args.fail_on]
        if any(f.priority in levels and f.status == "affected" for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
