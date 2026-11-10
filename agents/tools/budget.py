"""API 花費預留（第 11.2 節 /api/budget、第 15 節）。成本是估算，SDK 與 Console 限額都不是零超支保證。

- Workflow（live）：必須先向受保護的 /api/budget 成功預留，缺服務或額度不足 → 範本
- 本機 record：網站部署前使用本機成本簿與使用者單次授權上限（LOCAL_RECORD_CAP_USD），不要求 budget API
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

from tools.common import AGENTS_DIR, read_json, write_json

LOCAL_LEDGER = AGENTS_DIR / "cache" / "local-budget.json"


class LocalBudget:
    def __init__(self, cap_usd: float, ledger: Path = LOCAL_LEDGER):
        self.cap, self.ledger = cap_usd, ledger
        self.state = read_json(ledger, {"spent_usd": 0.0, "entries": []}) or {"spent_usd": 0.0, "entries": []}
        self.reserved = 0.0

    def reserve(self, agent: str, amount: float):
        if self.state["spent_usd"] + self.reserved + amount > self.cap:
            return None
        self.reserved += amount
        return {"agent": agent, "amount": amount}

    def settle(self, reservation: dict, actual: float) -> None:
        self.reserved -= reservation["amount"]
        self.state["spent_usd"] = round(self.state["spent_usd"] + actual, 6)
        self.state["entries"].append({"agent": reservation["agent"], "usd": actual})
        write_json(self.ledger, self.state)


class RemoteBudget:
    """冪等鍵：<run_id>-<attempt>/<agent>/<agent>/<序號>。重跑（新的 attempt）是新的預留；同一次重送網路請求不重複扣額。"""

    def __init__(self, base_url: str, token: str, run_key: str):
        if not base_url.startswith("https://"):
            raise ValueError("SENTINEL_BASE_URL 必須是 HTTPS")
        self.base, self.token, self.run_key = base_url.rstrip("/"), token, run_key
        self.seq = 0

    def _post(self, body: dict):
        req = urllib.request.Request(f"{self.base}/api/budget", data=json.dumps(body).encode(), method="POST",
                                     headers={"content-type": "application/json", "authorization": f"Bearer {self.token}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode() or "{}")

    def reserve(self, agent: str, amount: float):
        self.seq += 1
        try:
            res = self._post({"action": "reserve", "key": f"{self.run_key}/{agent}/{self.seq}", "amount_usd": amount})
        except Exception:
            return None
        return res if res.get("ok") else None

    def settle(self, reservation: dict, actual: float) -> None:
        try:
            self._post({"action": "settle", "key": reservation.get("key"), "actual_usd": actual})
        except Exception:
            pass   # 未結算的預留由用量對帳釋放，不視為零花費


def budget_for(mode: str, run_key: str):
    if mode == "record":
        cap = float(os.environ.get("LOCAL_RECORD_CAP_USD", "0") or 0)
        return LocalBudget(cap)
    if mode == "live":
        base, token = os.environ.get("SENTINEL_BASE_URL"), os.environ.get("NOTIFY_TOKEN")
        if base and token:
            return RemoteBudget(base, token, run_key)
        return _Unavailable()
    return None


class _Unavailable:
    def reserve(self, agent, amount):
        return None

    def settle(self, reservation, actual):
        pass
