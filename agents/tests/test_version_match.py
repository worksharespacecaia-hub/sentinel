import pytest

from tools.version_match import AFFECTED, NOT_AFFECTED, UNKNOWN, compare, fixed_available, match, parse_dsm

PHP = [{"introduced": "8.2.0", "fixed": "8.2.35"}, {"introduced": "8.3.0", "fixed": "8.3.36"},
       {"introduced": "8.4.0", "fixed": "8.4.27"}, {"introduced": "8.1.0", "fixed": None}]


@pytest.mark.parametrize("a,b,expected", [("1.9", "1.10", -1), ("8.3.20", "8.3.36", -1), ("1.10", "1.9", 1), ("2.0", "2.0.0", 0)])
def test_numeric_compare(a, b, expected):
    assert compare(a, b) == expected


@pytest.mark.parametrize("version,expected", [
    ("8.1.27", AFFECTED), ("8.3.20", AFFECTED), ("8.3.35", AFFECTED), ("8.3.36", NOT_AFFECTED),
    ("8.4.26", AFFECTED), ("8.4.27", NOT_AFFECTED), ("8.2.35", NOT_AFFECTED), ("9.0.0", NOT_AFFECTED),
])
def test_php_patch_boundaries(version, expected):
    assert match(version, PHP, "php") == expected


def test_no_fix_branch_does_not_leak_to_newer_branches():
    assert match("8.4.27", [{"introduced": "8.1.0", "fixed": None}], "php") == NOT_AFFECTED
    assert fixed_available("8.1.27", PHP, "php") is False
    assert fixed_available("8.3.20", PHP, "php") is True


@pytest.mark.parametrize("spec,version,expected", [
    (">=14.0.0 <14.2.25 || >=15.0.0 <15.2.3", "14.1.0", AFFECTED),
    (">=14.0.0 <14.2.25 || >=15.0.0 <15.2.3", "15.2.3", NOT_AFFECTED),
    (">=14.0.0 <14.2.25 || >=15.0.0 <15.2.3", "15.1.0", AFFECTED),
    ("^2.0.0", "2.9.9", AFFECTED), ("^2.0.0", "3.0.0", NOT_AFFECTED),
    ("~2.3.0", "2.3.9", AFFECTED), ("~2.3.0", "2.4.0", NOT_AFFECTED),
    ("^1.0.0", "1.0.0-rc.1", NOT_AFFECTED),            # npm：預發行不符合一般範圍
    (">=1.0.0-beta.1 <1.0.0", "1.0.0-beta.2", AFFECTED),
])
def test_npm_ranges(spec, version, expected):
    assert match(version, spec, "npm") == expected


def test_dsm_parsing_and_ranges():
    assert parse_dsm("7.2.1-69057 Update 5") == (7, 2, 1, 69057, 5)
    assert parse_dsm("7.2.1-69057-12") == (7, 2, 1, 69057, 12)
    iv = [{"introduced": "7.2.1", "fixed": "7.2.1-69057-12"}, {"introduced": "7.2.2", "fixed": "7.2.2-72806-9"}]
    assert match("7.2.1-69057 Update 5", iv, "synology-dsm") == AFFECTED
    assert match("7.2.1-69057 Update 12", iv, "synology-dsm") == NOT_AFFECTED
    assert match("7.2.2-72806 Update 8", iv, "synology-dsm") == AFFECTED


@pytest.mark.parametrize("version,affected,eco", [
    (None, PHP, "php"), ("unknown", PHP, "php"), ("8.3.20", None, "php"), ("8.3.20", [], "php"),
    ("8.3.20", ">=8.0", "php"),            # 字串範圍只支援 npm
    ("1.2.3+backport", [{"introduced": "1.0", "fixed": "1.3"}], "generic"),
])
def test_unknown_cases_are_not_safe(version, affected, eco):
    assert match(version, affected, eco) == UNKNOWN
