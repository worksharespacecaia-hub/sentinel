"""LLM 結果快取（agents/cache/llm.json）與 replay 錄製（fixtures/replay/）共用的完整快取鍵（第 6.4 節）。

鍵 = SHA-256(canonical JSON)：scope + agent + subagent + 完整去敏輸入 + target_sha + advisory_revision
     + controls/rules/eol 版本 + prompt/Skill/references 雜湊 + 模型 ID + SDK/CLI 版本 + schema_version。
只快取 LLM 撰寫的文字；判定、處理狀態、燈號每次重算。不同 scope 不共用。
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

from tools.common import AGENTS_DIR, INTEL_DIR, RULES_DIR, SCHEMA_VERSION, SENTINEL_ROOT, read_json, sha256_json, write_json

CACHE_PATH = AGENTS_DIR / "cache" / "llm.json"
REPLAY_DIR = AGENTS_DIR / "fixtures" / "replay"


def _hash_files(paths: list[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted(paths):
        if p.is_file():
            h.update(str(p.relative_to(SENTINEL_ROOT)).replace("\\", "/").encode())
            h.update(p.read_bytes())
    return h.hexdigest()


@lru_cache(maxsize=64)
def skills_hash(skills: tuple[str, ...]) -> str:
    files = [p for s in skills for p in (SENTINEL_ROOT / ".claude" / "skills" / s).rglob("*") if p.is_file()]
    return _hash_files(files)


@lru_cache(maxsize=1)
def rules_hash() -> str:
    return _hash_files([INTEL_DIR / "controls.yaml", INTEL_DIR / "eol.json", INTEL_DIR / "aliases.yaml",
                        RULES_DIR / "baselines.json", AGENTS_DIR / "tools" / "scoring.py"])


def cache_key(*, scope: str, agent: str, subagent: str, payload, target_sha: str, advisory_revision: str | None,
              prompt: str, skills: list[str], model: str, sdk_version: str, cli_version: str) -> str:
    return sha256_json({
        "scope": scope, "agent": agent, "subagent": subagent, "input": payload, "target_sha": target_sha,
        "advisory_revision": advisory_revision, "rules": rules_hash(), "prompt": hashlib.sha256(prompt.encode()).hexdigest(),
        "skills": skills_hash(tuple(sorted(skills))), "model": model, "sdk": sdk_version, "cli": cli_version,
        "schema_version": SCHEMA_VERSION,
    })


class LLMCache:
    def __init__(self, path: Path = CACHE_PATH):
        self.path = Path(path)
        self.data: dict = read_json(self.path, {}) or {}
        self.new: dict = {}
        self.hits = self.misses = 0

    def get(self, key: str):
        entry = self.data.get(key) or self.new.get(key)
        if entry is None:
            self.misses += 1
            return None
        self.hits += 1
        return entry["output"]

    def put(self, key: str, output, meta: dict) -> None:
        self.new[key] = {"output": output, "meta": meta}

    def save_delta(self, path: Path) -> None:
        write_json(path, self.new)

    @property
    def hit_rate(self) -> float | None:
        total = self.hits + self.misses
        return None if total == 0 else round(self.hits / total, 3)


def merge_cache(base: dict, deltas: list[dict]) -> tuple[dict, list[str]]:
    """合併各 Job 的快取增量；相同 key 不同值不得靜默覆蓋，回報衝突。"""
    merged, conflicts = dict(base), []
    for d in deltas:
        for k, v in d.items():
            if k in merged and merged[k]["output"] != v["output"]:
                conflicts.append(k)
                continue
            merged[k] = v
    return merged, conflicts


class ReplayStore:
    def __init__(self, root: Path = REPLAY_DIR):
        self.root = Path(root)

    def _path(self, agent: str, subagent: str, key: str) -> Path:
        return self.root / agent / subagent / f"{key}.json"

    def get(self, agent: str, subagent: str, key: str):
        entry = read_json(self._path(agent, subagent, key))
        return None if entry is None else entry["output"]

    def put(self, agent: str, subagent: str, key: str, output, meta: dict) -> None:
        write_json(self._path(agent, subagent, key), {"output": output, "meta": meta})
