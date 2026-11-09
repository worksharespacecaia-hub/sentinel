"""支援期限（讀 intel/eol.json）。EOL 是目前支援狀態；有無修補是漏洞屬性，分開儲存。"""
from __future__ import annotations

from datetime import datetime
from functools import lru_cache
from pathlib import Path

from tools.aliases import normalize
from tools.common import INTEL_DIR, parse_time, read_json


@lru_cache(maxsize=2)
def _data(path: str) -> dict:
    return read_json(Path(path), {}) or {}


def eol_status(name: str | None, version: str | None, as_of: datetime, *, path: Path | None = None) -> dict:
    """回傳 {eol: True|False|None, cycle, eol_date}；未知產品或版本為 None，不推論。"""
    product = normalize(name)
    table = _data(str(path or INTEL_DIR / "eol.json")).get(product or "", [])
    if not version or not table:
        return {"eol": None, "cycle": None, "eol_date": None}
    for entry in sorted(table, key=lambda e: -len(e["cycle"])):
        cycle = entry["cycle"]
        if version == cycle or version.startswith(cycle + "."):
            eol_date = entry.get("eol")
            ended = parse_time(eol_date) if eol_date else None
            return {"eol": bool(ended and as_of > ended), "cycle": cycle, "eol_date": eol_date}
    return {"eol": None, "cycle": None, "eol_date": None}
