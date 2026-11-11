"""共用小工具：路徑、時間（一律接受明確 as_of）、canonical JSON 與雜湊。"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

AGENTS_DIR = Path(__file__).resolve().parents[1]
SENTINEL_ROOT = AGENTS_DIR.parent
INTEL_DIR = AGENTS_DIR / "intel"
RULES_DIR = SENTINEL_ROOT / "rules"
TAIPEI = timezone(timedelta(hours=8))
SCHEMA_VERSION = 1
# LLM 輸出的機敏值檢查（llm._validate、動態派工的建議格式檢查共用）
SECRET_RE = re.compile(r"DEMO-FAKE-[A-Z0-9-]{4,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|sk-ant-[A-Za-z0-9_-]{10,}|ghp_[A-Za-z0-9]{20,}")


def target_dir() -> Path:
    """Repo ① 的 checkout 位置；CI 為 target/，本機可用 TARGET_DIR 指到兄弟目錄。"""
    return Path(os.environ.get("TARGET_DIR", SENTINEL_ROOT / "target")).resolve()


def parse_time(value: str | datetime | date | None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    if len(text) == 10:
        text += "T00:00:00+00:00"
    dt = datetime.fromisoformat(text)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def days_between(earlier: str | datetime | None, later: datetime) -> int | None:
    e = parse_time(earlier)
    return None if e is None else (later - e).days


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_text(canonical_json(value))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path, default: Any = None) -> Any:
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8", newline="\n")


def stable_id(*parts: str) -> str:
    """穩定 ID：只由資產、credential／元件／控制項與弱點 ID 組成，不含行號或日期。"""
    return ":".join(p for p in parts if p)
