# csaf-asset-matcher

Answer the question every OT security team gets when a vendor advisory lands: **which of our devices are affected, and what do we do about each one?**

CSAF 2.0 is the machine-readable format vendors and CISA use for ICS advisories. It describes affected products as a tree of vendors, products and version ranges, with a status per vulnerability (affected, fixed, not affected, under investigation). This tool reads that structure properly, including OT style version strings, and matches it against your asset inventory.

```
csaf-match examples/advisories -i examples/inventory.csv -a examples/aliases.csv
```

> 3 advisories, 14 assets. **8 assets affected** by 4 CVEs (P1: 3, P2: 4, P3: 1).

| Priority | Asset | Zone | Product | Version | CVE | CVSS | Exploited | Fix |
|---|---|---|---|---|---|---|---|---|
| P1 | plc-intake-01 | control | Northbridge Automation NX-500 | 4.1.7 | CVE-2030-11001 | 9.8 | yes | vendor_fix: Update NX-500 firmware to 4.2.1 or later. |
| P1 | plc-filter-07 | control | Northbridge Automation NX-300 | 2.8 | CVE-2030-11001 | 9.8 | yes | mitigation: NX-300 is end of life. Disable the web server... |
| P2 | hist-01 | scada | Calder Systems ViewPoint Historian | 5.4 | CVE-2030-12041 | 6.5 | | workaround: Change the historian service account password... |
| P3? | sw-field-12 | control | Ostara Networks RSX-8 | 1.9 | CVE-2030-13377 | 6.5 | | vendor_fix: Install firmware 2.5.0. (range needs review) |

Full report: [docs/sample-report.md](docs/sample-report.md). CSV for Splunk or a ticketing import: [docs/sample-findings.csv](docs/sample-findings.csv).

## Why not just grep for the product name

Because the version logic is where the work is:

| Advisory says | Asset runs | Correct answer |
|---|---|---|
| `vers:generic/<4.2.1` | `4.1.7` | affected |
| fixed in `4.2.1` | `4.2.1` | fixed, listed separately |
| `V3.0 and prior` | `3.1` | not affected |
| `2.0 to 2.4.9` | `2.5.0` | not affected |
| `<= 5.4` | `5.4` | affected |
| `builds before November 2029` | `1.9` | needs review, never silently dropped |

Supported range syntax:

- the CSAF recommended `vers:` form (`vers:generic/>=1.0|<1.4`, `!=` exclusions, `*`)
- the free-text forms found in real ICS advisories: `< V2.1`, `all versions < 2.1`, `3.0 and prior`, `prior to 7.3`, `up to 5.4`, `2.0 to 2.4.9`, `>= 1.2, < 1.8`, `all versions`

Version strings are compared token by token, so `V4.2.1` equals `4.2.1`, `2.10` is newer than `2.9`, `3.1 SP2` is newer than `3.1`, `2.0rc1` is older than `2.0`, and `8.1-HF3` is older than `8.1-HF10`.

Anything the tool cannot parse is reported as **review** with the original advisory text, rather than guessed.

## What else is read from the advisory

- `product_tree` branches (vendor, product family, product name, version, version range), `full_product_names` and `relationships` such as a historian bundled with an HMI
- CPE from `product_identification_helper`, used for matching when the inventory has CPEs
- `product_status`: known affected, fixed, first fixed, known not affected, under investigation
- CVSS v3 (or v4 or v2) scores per product
- `threats` with `exploit_status`, which raises the finding to P1
- `remediations`, preferring vendor fix, then mitigation, then workaround, including product groups

## Inventory

A CSV with these columns (extra columns are ignored):

```
asset_id,hostname,vendor,product,version,cpe,zone,criticality,owner
A-1001,plc-intake-01,Northbridge Automation Inc.,NX-500,4.1.7,,control,high,Process Control
```

Export it from your OT asset platform, CMDB or a Splunk lookup. Vendor names are normalized (case, punctuation, Inc, Ltd, GmbH and similar suffixes), so `Calder Systems Ltd` matches `Calder Systems`.

For names that differ more than that, add an alias file:

```
kind,alias,canonical
vendor,NBA,Northbridge Automation
product,NX-500 CPU,NX-500
```

Without an alias, an inventory product that contains every word of the advisory product name (`NX-500 CPU 4 port` vs `NX-500`) still matches, with confidence `medium`.

## Priority

| Priority | Rule |
|---|---|
| P1 | known exploited, or CVSS 9.0 and above |
| P2 | CVSS 7.0 and above, or CVSS 4.0 and above on an asset with `criticality` high |
| P3 | everything else that is affected, and all review items |

This is a triage order, not a risk score. Zone, exposure and compensating controls still belong to the engineer.

## Output

```
csaf-match ADVISORY_DIR -i inventory.csv                 # markdown report
csaf-match ADVISORY_DIR -i inventory.csv -f csv -o f.csv # one row per asset and CVE
csaf-match ADVISORY_DIR -i inventory.csv -f json --all   # include fixed and not affected
csaf-match ADVISORY_DIR -i inventory.csv --fail-on P1    # exit 1 for schedulers
```

The CSV works directly as a Splunk lookup:

```
| inputlookup csaf_findings.csv
| where status="affected"
| stats values(cve) as cves max(cvss) as max_cvss by hostname zone priority
| sort priority -max_cvss
```

## Getting advisories

CISA publishes ICS advisories in CSAF at `github.com/cisagov/CSAF`, and most large ICS vendors run a CSAF provider with a `provider-metadata.json`. Download the ones you need into a folder and point the tool at it. Files that are not CSAF 2.x are skipped and listed in the report.

The examples in this repository use fictional vendors, products and CVE ids.

## Development

```
pip install -e .[test]
pytest
python tools/make_sample.py
```

No third-party runtime dependencies.

## License

MIT. See [LICENSE](LICENSE).
