"""產品名稱正規化（讀 intel/aliases.yaml）。

只正規化名稱；SAPI、映像變體（apache／fpm）、套件來源等利用條件以 qualifiers 保留，不可丟失。
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import yaml

from tools.common import INTEL_DIR


@lru_cache(maxsize=4)
def _table(path: str) -> dict[str, str]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    table: dict[str, str] = {}
    for canonical, spec in data.items():
        names = [canonical, *(spec or {}).get("aliases", []), *(spec or {}).get("purl", []), *(spec or {}).get("cpe", [])]
        for n in names:
            table[str(n).strip().lower()] = canonical
    return table


def normalize(name: str | None, *, path: Path | None = None) -> str | None:
    """回傳正規名稱；不認得的名稱回傳小寫原名（不猜測）。"""
    if not name:
        return None
    table = _table(str(path or INTEL_DIR / "aliases.yaml"))
    key = name.strip().lower()
    if key in table:
        return table[key]
    if key.startswith("pkg:"):
        base = key.split("@", 1)[0]
        if base in table:
            return table[base]
    return key


_IMAGE_RE = re.compile(r"^(?P<repo>[a-z0-9./_-]+):(?P<tag>[A-Za-z0-9._-]+)$")


def parse_image(image: str) -> dict:
    """例如 `php:8.1-apache` → {name: php, version_hint: 8.1, qualifiers: {variant: apache}}。"""
    m = _IMAGE_RE.match(image.strip())
    if not m:
        return {"name": normalize(image), "version_hint": None, "qualifiers": {}}
    repo, tag = m.group("repo").split("/")[-1], m.group("tag")
    version, _, variant = tag.partition("-")
    qualifiers = {"variant": variant} if variant else {}
    return {"name": normalize(repo), "version_hint": version if re.match(r"^\d", version) else None,
            "qualifiers": qualifiers}


def component_key(component: dict) -> dict:
    """正規化元件：保留版本與利用條件相關欄位。"""
    out = {"name": normalize(component.get("name")), "version": component.get("version")}
    for k in ("sapi", "ecosystem", "variant", "os", "vendor_backport", "source"):
        if component.get(k) is not None:
            out[k] = component[k]
    return out
