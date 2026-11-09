"""記錄 Agent／Subagent 執行過程到 trace.jsonl（不存金鑰、認證 header、完整個資或原始客訴）。"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from schemas import TraceEvent


class Tracer:
    def __init__(self, path: Path, agent: str):
        self.path = Path(path)
        self.agent = agent
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, kind: str, detail: str, *, subagent: str | None = None, source: str | None = None,
             cost_usd: float | None = None) -> dict:
        ev = TraceEvent(ts=datetime.now(timezone.utc).isoformat(timespec="seconds"), agent=self.agent, subagent=subagent,
                        kind=kind, detail=detail[:500], source=source, cost_usd=cost_usd).model_dump()
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        return ev


def read_trace(path: Path) -> list[dict]:
    if not Path(path).is_file():
        return []
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def merge_traces(paths: list[Path], out: Path) -> int:
    events = sorted((e for p in paths for e in read_trace(p)), key=lambda e: e["ts"])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events), encoding="utf-8")
    return len(events)
