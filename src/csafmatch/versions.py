"""Version parsing and range evaluation.

Vendor versions in OT advisories are rarely semver. "V3.1 SP2", "2.0.14.1",
"R4.20.1" and "8.1-HF3" all need to compare sensibly, so versions are split
into numeric and text tokens and compared token by token.
"""

import re

_TOKEN = re.compile(r"\d+|[a-z]+")
_PREFIX = re.compile(r"^(?:v|r|version|rev|release)\s*\.?\s*(?=\d)", re.I)
# pre-release markers sort before the release they belong to
_PRE = {"dev": -4, "alpha": -3, "a": -3, "beta": -2, "b": -2, "rc": -1, "pre": -1}


def tokens(v):
    v = _PREFIX.sub("", str(v).strip().lower())
    out = []
    for t in _TOKEN.findall(v):
        if t.isdigit():
            out.append((1, int(t)))
        elif t in _PRE:
            out.append((0, _PRE[t]))
        else:
            # sp, hf, update, patch, p: a post-release qualifier sorts after the base
            out.append((2, t))
    return out


def _pad(a, b):
    n = max(len(a), len(b))
    filler = (1, 0)
    return a + [filler] * (n - len(a)), b + [filler] * (n - len(b))


def compare(a, b):
    """-1, 0 or 1."""
    x, y = _pad(tokens(a), tokens(b))
    for p, q in zip(x, y):
        if p == q:
            continue
        if p[0] != q[0]:
            return -1 if p[0] < q[0] else 1
        return -1 if p[1] < q[1] else 1
    return 0


_OPS = {
    "<": lambda c: c < 0, "<=": lambda c: c <= 0, ">": lambda c: c > 0, ">=": lambda c: c >= 0,
    "=": lambda c: c == 0, "!=": lambda c: c != 0,
}


class Range:
    """A set of constraints. Each alternative is a list of (op, version) that must all hold."""

    def __init__(self, alternatives, text):
        self.alternatives = alternatives
        self.text = text

    def contains(self, version):
        for alt in self.alternatives:
            if all(_OPS[op](compare(version, v)) for op, v in alt):
                return True
        return False

    def __repr__(self):
        return "Range(%r)" % self.text


def _parse_vers(spec, text):
    # vers:<scheme>/<constraint>|<constraint>...   (package-url vers spec)
    body = spec.split("/", 1)[1] if "/" in spec else ""
    if body.strip() == "*":
        return Range([[]], text)
    cons = []
    for part in body.split("|"):
        part = part.strip()
        m = re.match(r"^(<=|>=|!=|<|>|=)?\s*(.+)$", part)
        if not m or not m.group(2):
            return None
        cons.append((m.group(1) or "=", m.group(2).strip()))
    # vers semantics: constraints are sorted; consecutive >= / < pairs form intervals,
    # bare = and != stand alone. Build intervals by walking the list.
    alts, lower = [], None
    for op, v in cons:
        if op in (">", ">="):
            lower = (op, v)
        elif op in ("<", "<="):
            alts.append(([lower] if lower else []) + [(op, v)])
            lower = None
        elif op == "=":
            alts.append([("=", v)])
        elif op == "!=":
            continue
    if lower:
        alts.append([lower])
    excluded = [v for op, v in cons if op == "!="]
    if excluded:
        alts = [alt + [("!=", v) for v in excluded] for alt in alts]
    return Range(alts, text) if alts else None


_V = r"[vr]?\s*\d[\w.\-]*"


def parse_range(text):
    """Parse a product_version_range name. Returns Range or None if not understood."""
    s = str(text).strip()
    low = s.lower()
    if low.startswith("vers:"):
        return _parse_vers(s, s)
    if low in ("all versions", "all", "*"):
        return Range([[]], s)
    m = re.match(r"^(?:all versions\s*)?(<=|>=|<|>)\s*(%s)$" % _V, low)
    if m:
        return Range([[(m.group(1), m.group(2))]], s)
    m = re.match(r"^(%s)\s*(?:and|or)\s*(?:prior|earlier|before|below|older)$" % _V, low)
    if m:
        return Range([[("<=", m.group(1))]], s)
    m = re.match(r"^(?:prior to|before|up to|below)\s+(%s)$" % _V, low)
    if m:
        op = "<=" if low.startswith("up to") else "<"
        return Range([[(op, m.group(1))]], s)
    m = re.match(r"^(%s)\s*(?:to|-|through)\s*(%s)$" % (_V, _V), low)
    if m:
        return Range([[(">=", m.group(1)), ("<=", m.group(2))]], s)
    m = re.match(r"^(>=|>)\s*(%s)\s*,?\s*(<=|<)\s*(%s)$" % (_V, _V), low)
    if m:
        return Range([[(m.group(1), m.group(2)), (m.group(3), m.group(4))]], s)
    return None
