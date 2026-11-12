# CSAF advisory match report

3 advisories, 14 assets. **8 assets affected** by 4 CVEs (P1: 3, P2: 4, P3: 1).

## Affected assets

| Priority | Asset | Zone | Product | Version | CVE | CVSS | Exploited | Advisory | Fix |
|---|---|---|---|---|---|---|---|---|---|
| P1 | plc-intake-01 | control | Northbridge Automation Inc. NX-500 | 4.1.7 | CVE-2030-11001 | 9.8 | yes | NBA-SA-2030-004 | vendor_fix: Update NX-500 firmware to 4.2.1 or later. |
| P1 | plc-dosing-01 | control | NBA NX-500 CPU | V4.0.2 | CVE-2030-11001 | 9.8 | yes | NBA-SA-2030-004 | vendor_fix: Update NX-500 firmware to 4.2.1 or later. |
| P1 | plc-filter-07 | control | Northbridge Automation NX-300 | 2.8 | CVE-2030-11001 | 9.8 | yes | NBA-SA-2030-004 | mitigation: NX-300 is end of life. Disable the web server and restrict TCP/80 and TCP/443 to the engineering workstation |
| P2 | hmi-ops-01 | scada | Calder Systems ViewPoint HMI | 7.2 | CVE-2030-12040 | 7.8 |  | CALDER-2030-0012 | vendor_fix: Upgrade to ViewPoint HMI 7.3. |
| P2 | hmi-lab-01 | ops | Calder Systems Ltd ViewPoint HMI | 7.1 | CVE-2030-12040 | 7.8 |  | CALDER-2030-0012 | vendor_fix: Upgrade to ViewPoint HMI 7.3. |
| P2 | hist-01 | scada | Calder Systems ViewPoint Historian | 5.4 | CVE-2030-12041 | 6.5 |  | CALDER-2030-0012 | workaround: Change the historian service account password and block TCP/5450 from outside the SCADA zone. |
| P2 | sw-ctrl-a | control | Ostara RSX-24 switch | 2.4.2 | CVE-2030-13377 | 6.5 |  | OSTARA-2030-03 | vendor_fix: Install firmware 2.5.0. |
| P3? | sw-field-12 | control | Ostara Networks RSX-8 | 1.9 | CVE-2030-13377 | 6.5 |  | OSTARA-2030-03 | vendor_fix: Install firmware 2.5.0. |

## Needs review

The advisory gives a version range this tool could not parse. Check these by hand.

- sw-field-12 RSX-8 1.9: CVE-2030-13377, advisory says `RSX-8 builds before November 2029`

## Already on a fixed version

- plc-intake-02 NX-500 4.2.1: CVE-2030-11001
- hmi-ops-02 ViewPoint HMI 7.3: CVE-2030-12040

## Advisories

| Advisory | Publisher | Released | Title | Assets affected |
|---|---|---|---|---|
| CALDER-2030-0012 | Calder Systems | 2030-02-25 | Multiple vulnerabilities in ViewPoint HMI | 3 |
| NBA-SA-2030-004 | Northbridge Automation | 2030-02-11 | Authentication bypass in NX series PLC web server | 3 |
| OSTARA-2030-03 | Ostara Networks | 2030-03-01 | Denial of service in RSX industrial switches | 2 |
