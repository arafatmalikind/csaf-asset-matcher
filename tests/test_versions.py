import pytest

from csafmatch.versions import compare, parse_range


@pytest.mark.parametrize("a,b,r", [
    ("4.1.7", "4.2.1", -1), ("V4.2.1", "4.2.1", 0), ("4.2", "4.2.0", 0), ("2.10", "2.9", 1),
    ("3.1 SP2", "3.1", 1), ("3.1", "3.1 SP2", -1), ("2.0rc1", "2.0", -1), ("R4.20.1", "4.20", 1),
    ("8.1-HF3", "8.1-HF10", -1),
])
def test_compare(a, b, r):
    assert compare(a, b) == r


@pytest.mark.parametrize("text,inside,outside", [
    ("vers:generic/<4.2.1", ["4.2.0", "1.0"], ["4.2.1", "5"]),
    ("vers:semver/>=1.0.0|<1.4.0|>=2.0.0|<2.1.3", ["1.2", "2.1.0"], ["1.5", "2.1.3", "0.9"]),
    ("vers:generic/*", ["0.1", "99"], []),
    ("vers:generic/>=3.0|!=3.2", ["3.1", "4"], ["3.2", "2.9"]),
    ("V3.0 and prior", ["2.8", "3.0"], ["3.1"]),
    ("<= 5.4", ["5.4", "5"], ["5.4.1"]),
    ("2.0 to 2.4.9", ["2.0", "2.4.2"], ["1.9", "2.5.0"]),
    ("prior to 7.3", ["7.2.9"], ["7.3"]),
    ("all versions", ["1"], []),
    ("all versions < V2.1", ["2.0"], ["2.1"]),
    (">= 1.2, < 1.8", ["1.2", "1.7.9"], ["1.8", "1.1"]),
])
def test_ranges(text, inside, outside):
    r = parse_range(text)
    assert r is not None
    for v in inside:
        assert r.contains(v), v
    for v in outside:
        assert not r.contains(v), v


def test_unparseable_range_returns_none():
    assert parse_range("builds before November 2029") is None
