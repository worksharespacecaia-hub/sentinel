"""版本範圍比對。各生態系使用各自的比較器，不一律套用 PEP 440。

- npm：npm semver 語意（OR、caret、tilde、預發行）— semantic_version.NpmSpec
- php：數字三段，`{introduced, fixed}` 區間；fixed 為 null 表示該分支無修補
- synology-dsm：`7.2.1-69057 Update 5` → (7, 2, 1, 69057, 5)
- generic：數字分段（1.9 < 1.10）；含無法解析字元時回傳 unknown

回傳 "affected" | "not_affected" | "unknown"。版本未知、範圍無法解析或 backport 不明時一律 unknown。
"""
from __future__ import annotations

import re
from typing import Iterable

import semantic_version

AFFECTED, NOT_AFFECTED, UNKNOWN = "affected", "not_affected", "unknown"


def _numeric_tuple(version: str) -> tuple[int, ...] | None:
    parts = re.split(r"[.]", version.strip())
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def parse_dsm(version: str) -> tuple[int, ...] | None:
    """支援 `7.2.1-69057 Update 5`、`7.2.1-69057-12`、`7.4-90075` 與只有分支的 `7.2.1`。"""
    m = re.fullmatch(r"\s*(?:DSM\s+)?(\d+)\.(\d+)(?:\.(\d+))?(?:-(\d+)(?:(?:\s+Update\s+|-)(\d+))?)?\s*",
                     version, flags=re.I)
    if not m:
        return None
    major, minor, patch, build, update = m.groups()
    return int(major), int(minor), int(patch or 0), int(build or 0), int(update or 0)


def _parser(ecosystem: str):
    if ecosystem == "synology-dsm":
        return parse_dsm
    return _numeric_tuple


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    a, b = _pad(a, b)
    return (a > b) - (a < b)


def in_intervals(version: str, intervals: Iterable[dict], ecosystem: str) -> str:
    """OSV 風格區間：[introduced, fixed)；fixed 為 None 代表沒有修補（仍受影響）。"""
    parse = _parser(ecosystem)
    v = parse(version) if version else None
    if v is None:
        return UNKNOWN
    intervals = list(intervals)
    if not intervals:
        return UNKNOWN
    for iv in intervals:
        lo = parse(str(iv.get("introduced"))) if iv.get("introduced") not in (None, "0") else (0,)
        if lo is None:
            return UNKNOWN
        hi_raw = iv.get("fixed")
        hi = parse(str(hi_raw)) if hi_raw is not None else _branch_end(lo)
        if hi_raw is not None and hi is None:
            return UNKNOWN
        if _cmp(v, lo) >= 0 and (hi is None or _cmp(v, hi) < 0):
            return AFFECTED
    return NOT_AFFECTED


def _branch_end(lo: tuple[int, ...]) -> tuple[int, ...] | None:
    """fixed 為 null 的區間只涵蓋 introduced 所在分支（major.minor）；introduced 為 0 時代表所有版本。"""
    if lo == (0,) or len(lo) < 2:
        return None
    return (lo[0], lo[1] + 1)


def fixed_available(version: str, intervals: Iterable[dict], ecosystem: str) -> bool | None:
    """命中的區間是否有修補版本（None 代表不在任何區間或無法判斷）。"""
    parse = _parser(ecosystem)
    v = parse(version) if version else None
    if v is None:
        return None
    for iv in intervals:
        lo = parse(str(iv.get("introduced"))) if iv.get("introduced") not in (None, "0") else (0,)
        if lo is None:
            return None
        hi = parse(str(iv["fixed"])) if iv.get("fixed") is not None else _branch_end(lo)
        if _cmp(v, lo) >= 0 and (hi is None or _cmp(v, hi) < 0):
            return iv.get("fixed") is not None
    return None


def in_npm_range(version: str, spec: str) -> str:
    try:
        v = semantic_version.Version(version)
        s = semantic_version.NpmSpec(spec)
    except ValueError:
        return UNKNOWN
    return AFFECTED if v in s else NOT_AFFECTED


def match(version: str | None, affected, ecosystem: str = "generic") -> str:
    """affected 可為 npm 範圍字串（ecosystem=npm）或 [{introduced, fixed}] 清單。"""
    if not version or affected in (None, "", []):
        return UNKNOWN
    if isinstance(affected, str):
        if ecosystem != "npm":
            return UNKNOWN
        return in_npm_range(version, affected)
    if ecosystem == "npm":
        # npm 也允許區間清單
        try:
            v = semantic_version.Version(version)
        except ValueError:
            return UNKNOWN
        for iv in affected:
            lo = semantic_version.Version(iv.get("introduced") or "0.0.0")
            hi = semantic_version.Version(iv["fixed"]) if iv.get("fixed") else None
            if v >= lo and (hi is None or v < hi):
                return AFFECTED
        return NOT_AFFECTED
    return in_intervals(version, affected, ecosystem)


def compare(a: str, b: str, ecosystem: str = "generic") -> int | None:
    parse = _parser(ecosystem)
    pa, pb = parse(a), parse(b)
    if pa is None or pb is None:
        return None
    return _cmp(pa, pb)
