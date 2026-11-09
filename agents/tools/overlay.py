"""把修復 fixture 疊加到 baseline 凍結副本上（Phase 7「修復後」情境）。

overlay 目錄結構：
- target/：與 Repo ① 相同的相對路徑，只放「修正 PR 改過的檔案」，整檔覆蓋 baseline
- scanners/：重產的掃描結果（整檔覆蓋）；沒有提供的工具沿用 baseline
- fix.yaml：說明這次修了哪些風險、刻意沒修哪些（測試以此為預期值）

只在本機與測試使用；不修改 Repo ①，也不寫入 fixtures/target-baseline。
"""
from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from tools.common import AGENTS_DIR
from tools.loaders import FIXTURE_SCANNERS, FIXTURE_TARGET

AFTER_FIX_DIR = AGENTS_DIR / "fixtures" / "after-fix"


def load_fix(name: str) -> dict:
    path = AFTER_FIX_DIR / name / "fix.yaml"
    if not path.is_file():
        raise ValueError(f"找不到修復 fixture：{name}")
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def materialize(name: str, dest: Path, *, base_target: Path = FIXTURE_TARGET,
                base_scanners: Path = FIXTURE_SCANNERS) -> tuple[Path, Path]:
    """在 dest 下建立 target/ 與 scanners/，回傳兩者路徑。dest 必須是空目錄或不存在。"""
    overlay = AFTER_FIX_DIR / name
    if not (overlay / "fix.yaml").is_file():
        raise ValueError(f"找不到修復 fixture：{name}")
    dest = Path(dest)
    if dest.exists() and any(dest.iterdir()):
        raise ValueError(f"{dest} 不是空目錄")
    target, scanners = dest / "target", dest / "scanners"
    shutil.copytree(base_target, target)
    shutil.copytree(base_scanners, scanners)
    for sub, out in (("target", target), ("scanners", scanners)):
        src = overlay / sub
        if src.is_dir():
            shutil.copytree(src, out, dirs_exist_ok=True)
    return target, scanners
