"""圍堵建議（incident.yml，觸發 ④，第 7.2、14.5 節）：A3 關聯 → A4 從告警資產出發的攻擊路徑 → containment-advisor → Issue 留言。

- 權威上下文：以 NOTIFY_TOKEN 向受保護的 /api/alerts/context 取回「已存在」的告警；dispatch payload（ALERT_ID、ASSET_ID）只是查詢提示，
  不信任 payload 指定的 Issue 或資產
- 冪等：Issue 留言帶唯一 marker；已存在就不再產生建議（不重複付費／留言），只補回報 /api/alerts/advice
- NOTIFY_TOKEN、GH_TOKEN 不進入 LLM 子行程（llm.scrubbed_environ 只保留白名單）；LLM 另設較短逾時，失敗以程式範本降級
- 不 commit、不寫入任何 Repo；只留言到 Repo ② 的 Issue。只建議，不執行
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import replace
from typing import Callable

import yaml

from context import RunCtx
from llm import SECRET_RE, Task
from tools.common import SENTINEL_ROOT, read_json, write_json
from tools.findings import redact
from tools.graph_query import GraphQuery

ALERT_ID_RE = re.compile(r"^al-rt-[0-9]{3}-[a-f0-9]{16}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
GITHUB_API = "https://api.github.com"
LLM_TIMEOUT_S = 240          # Job timeout 10 分鐘含安裝與外部呼叫；LLM 另設較短逾時
LEVEL_ZH = {"high": "高", "medium": "中", "low": "低"}
VERIFY = "告警資產的異常活動停止、相關權杖已撤銷或輪替；管理者附證據後才在網站結案（系統不會自動結案）。"

# 只建議方向與驗證方式（精簡版劇本，第 7.3 節 remediation-playbooks/incident-containment）
TEMPLATES = {
    "RT-001": [
        "暫停 {asset} 對 production 的直接部署（例如要求部署必須經過 CI 與審核），直到確認這次部署者的身分與授權",
        "撤銷並重新發行可授權 {asset} 的權杖：{creds}",
        "保留這次部署的紀錄（部署者、ref、時間）作為證據，比對部署內容是否與 main 一致",
        "由負責團隊確認後，必要時回復到最近一次經 Pipeline 部署的版本",
    ],
    "RT-002": [
        "暫停帳號 {account} 對 orders 的讀取權限或要求重新驗證，直到確認讀取者身分",
        "限制資料庫只接受已知來源連線，並檢查可授權 {asset} 的憑證：{creds}",
        "保留資料庫稽核紀錄，確認被讀取的資料範圍與時間",
        "若確認資料外流，依個資事故流程評估通知品牌商與主管機關",
    ],
    "RT-003": [
        "請品牌商發布防詐提醒（官方不會來電要求操作 ATM 或提供驗證碼）",
        "檢查可存取訂單資料的路徑（客服系統、報表匯出、對外 API）是否有異常讀取",
        "保留客訴紀錄並建立事件處理單，追蹤是否有更多品牌回報",
        "若確認資料外流，依個資事故流程評估通報時限",
    ],
}

Http = Callable[[str, str, dict, dict | None], tuple[int, object]]


class IncidentError(RuntimeError):
    pass


def http_json(method: str, url: str, headers: dict, body: dict | None = None) -> tuple[int, object]:
    """最小 HTTP 用戶端：只接受 HTTPS；回傳 (status, json)。"""
    if not url.startswith("https://"):
        raise IncidentError("只允許 HTTPS")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={**headers, "user-agent": "sentinel-incident", **({"content-type": "application/json"} if data else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode() or "null"
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode() or "null")
        except ValueError:
            return exc.code, None


def rule_assets() -> set[str]:
    rules = yaml.safe_load((SENTINEL_ROOT / "rules" / "realtime.yaml").read_text(encoding="utf-8")) or []
    return {r["asset_key"] for r in rules}


def fetch_context(http: Http, base: str, token: str, alert_id: str, repo: str) -> dict:
    """取回已存在告警的權威上下文，逐一驗證：格式、所屬 Repo、Issue number、資產範圍。"""
    if not base.startswith("https://"):
        raise IncidentError("SENTINEL_BASE_URL 必須是 HTTPS")
    status, ctx = http("GET", f"{base.rstrip('/')}/api/alerts/context?alert_id={alert_id}", {"authorization": f"Bearer {token}"}, None)
    if status != 200 or not isinstance(ctx, dict):
        raise IncidentError(f"無法取得告警上下文（HTTP {status}）")
    if ctx.get("alert_id") != alert_id:
        raise IncidentError("上下文的 alert_id 不符")
    if ctx.get("repo") != repo:
        raise IncidentError("告警不屬於本 Repo")
    if not isinstance(ctx.get("issue_number"), int) or ctx["issue_number"] <= 0:
        raise IncidentError("告警缺少合法的 Issue number")
    if ctx.get("asset_id") not in rule_assets():
        raise IncidentError("資產不在即時規則範圍")
    if not re.match(r"^RT-\d{3}$", str(ctx.get("rule_id", ""))):
        raise IncidentError("rule_id 格式錯誤")
    return ctx


def advice_marker(alert_id: str) -> str:
    return f"<!-- sentinel-advice: {alert_id} -->"


def find_existing_comment(http: Http, repo: str, issue: int, gh_token: str, marker: str) -> str | None:
    for page in (1, 2, 3):
        status, rows = http("GET", f"{GITHUB_API}/repos/{repo}/issues/{issue}/comments?per_page=100&page={page}",
                            {"authorization": f"Bearer {gh_token}", "accept": "application/vnd.github+json"}, None)
        if status != 200 or not isinstance(rows, list):
            raise IncidentError(f"無法讀取 Issue 留言（HTTP {status}）")
        for c in rows:
            if marker in (c.get("body") or ""):
                return c.get("html_url")
        if len(rows) < 100:
            return None
    return None


# ------------------------------------------------------------------ A3／A4（讀已 commit 的 daily 結果，純程式）

def related(data_dir, asset: str) -> dict:
    """同資產的近期訊號與每日風險、經過該資產的攻擊路徑（從資產開始的片段）、可授權該資產的憑證。"""
    daily = data_dir / "daily"
    report = read_json(daily / "report.json", {}) or {}
    graph = read_json(daily / "graph.json", {"nodes": [], "edges": []}) or {"nodes": [], "edges": []}
    paths = read_json(daily / "attack_paths.json", {"paths": []}) or {"paths": []}
    signals = [{"id": s["id"], "summary": s.get("summary", "")} for s in report.get("signals", [])
               if asset in (s.get("assets") or []) or asset in json.dumps(s.get("evidence", []), ensure_ascii=False)]
    risks = [{"id": r["id"], "level": r["level"], "title": r["title"]} for r in report.get("risks", [])
             if r.get("status") != "fixed" and (r.get("asset_id") == asset or asset in (r.get("attack_path") or []))]
    through = []
    for p in paths.get("paths", []):
        nodes = p.get("nodes") or []
        if asset in nodes:
            through.append({"nodes": nodes, "from_asset": nodes[nodes.index(asset):], "assumption": p.get("assumption")})
    creds = sorted({e["from"] for e in graph.get("edges", []) if e.get("to") == asset and e.get("kind") == "authorizes"})
    reach = sorted({e["to"] for e in graph.get("edges", []) if e.get("from") == asset and e.get("kind") in ("authorizes", "network", "stores")})
    known = {n["id"] for n in graph.get("nodes", [])}
    return {"signals": signals[:10], "risks": risks[:10], "paths": through[:5], "credentials": creds, "reach": reach[:20],
            "in_graph": asset in known, "daily_run": report.get("run_id"), "graph": graph, "attack_paths": paths}


def template_advice(ctx_alert: dict, rel: dict) -> list[str]:
    creds = "、".join(rel["credentials"]) or "（每日評估未記錄可授權此資產的權杖，請人工確認）"
    lines = TEMPLATES.get(ctx_alert["rule_id"], ["限制告警資產的權限與連線，保留證據，再由負責人確認"])
    return [s.format(asset=ctx_alert["asset_id"], creds=creds, account=ctx_alert.get("account") or "（未知帳號）") for s in lines]


def compose_comment(alert: dict, advice: list[str] | str, rel: dict, source: str, run_id: str) -> str:
    sim = f"> 模擬告警（{alert.get('simulation_id')}）：只供排練，不改變正式燈號。\n\n" if alert.get("simulated") else ""
    if isinstance(advice, str):
        body = advice.strip()
    else:
        body = "\n".join(f"{i}. {s}" for i, s in enumerate(advice, 1))
    asset = alert["asset_id"]
    path_lines = [f"- {' → '.join(f'**{n}**' if n == asset else n for n in p['nodes'])}"
                  + (f"（{p['assumption']}）" if p.get("assumption") else "") for p in rel["paths"]]
    path_lines = path_lines or ["- 每日評估中沒有經過此資產的完整攻擊鏈"]
    if rel["credentials"]:
        path_lines.append(f"- 可授權 `{asset}` 的憑證：{'、'.join(rel['credentials'])}")
    if rel["reach"]:
        path_lines.append(f"- `{asset}` 可直接連到或授權：{'、'.join(rel['reach'])}")
    ctx_lines = [f"- 風險 {r['id']}（{LEVEL_ZH.get(r['level'], r['level'])}）：{r['title']}" for r in rel["risks"]]
    ctx_lines += [f"- 訊號 {s['id']}：{s['summary']}" for s in rel["signals"]]
    src = {"live": "即時呼叫", "replay": "重播錄製", "template": "程式範本"}[source]
    text = "\n".join([
        advice_marker(alert["alert_id"]),
        "### 圍堵建議（只建議、不執行）",
        "",
        sim + f"**告警**：{alert['rule_id']} {alert.get('rule_title', '')}（資產 `{alert['asset_id']}`）— {alert.get('summary', '')}",
        "",
        "**建議**",
        body,
        "",
        f"**經過告警資產的攻擊路徑**（每日評估 {rel.get('daily_run') or '—'}；粗體為告警資產）",
        *path_lines,
        "",
        "**同資產近期風險與訊號**",
        *(ctx_lines or ["- 無"]),
        "",
        f"**驗證方式**：{VERIFY}",
        "",
        f"<sub>文字來源：{src}｜incident 執行 {run_id}｜系統只建議，不執行任何變更</sub>",
    ])
    return redact(text)


def run(ctx: RunCtx, *, http: Http = http_json, env: dict | None = None) -> dict:
    env = env if env is not None else dict(os.environ)
    alert_id = env.get("ALERT_ID", "")
    hint_asset = env.get("ASSET_ID", "")
    repo = env.get("GITHUB_REPOSITORY", "")
    base, token, gh_token = env.get("SENTINEL_BASE_URL", ""), env.get("NOTIFY_TOKEN", ""), env.get("GH_TOKEN", "")
    if not ALERT_ID_RE.match(alert_id):
        raise IncidentError("ALERT_ID 格式錯誤")
    if not REPO_RE.match(repo):
        raise IncidentError("GITHUB_REPOSITORY 未設定")
    if not (base and token and gh_token):
        raise IncidentError("缺少 SENTINEL_BASE_URL、NOTIFY_TOKEN 或 GH_TOKEN")

    manifest = read_json(ctx.data_dir / "daily" / "manifest.json", {}) or {}
    ictx = replace(ctx, scope="incident", output_dir=f"incident/{alert_id}",
                   target_sha=manifest.get("target_sha") or ctx.target_sha)
    tr = ictx.tracer("incident")
    tr.emit("start", f"圍堵建議 {alert_id}")
    alert = fetch_context(http, base, token, alert_id, repo)
    if hint_asset and hint_asset != alert["asset_id"]:
        tr.emit("error", "dispatch 提示的資產與告警不符，以受保護 API 的資產為準")
    issue = alert["issue_number"]
    marker = advice_marker(alert_id)

    existing = find_existing_comment(http, repo, issue, gh_token, marker)
    if existing:
        tr.emit("skip", "Issue 已有本告警的圍堵建議留言，不重複產生", source="template")
        source, comment_url = (alert.get("advice") or {}).get("source") or "template", existing
    else:
        rel = related(ictx.data_dir, alert["asset_id"])
        tr.emit("tool", f"A3 關聯：{len(rel['signals'])} 個訊號、{len(rel['risks'])} 個風險")
        tr.emit("tool", f"A4 攻擊路徑：{len(rel['paths'])} 條經過 {alert['asset_id']}；可授權憑證 {len(rel['credentials'])} 個")
        payload = {"ids": [alert_id], "alert": {k: redact(str(alert.get(k) or "")) for k in ("rule_id", "rule_title", "asset_id", "summary")},
                   "simulated": bool(alert.get("simulated")), "signals": rel["signals"], "risks": rel["risks"],
                   "paths": [p["from_asset"] for p in rel["paths"]], "credentials": rel["credentials"]}
        scope = {alert["asset_id"], *rel["credentials"], *(n for p in rel["paths"] for n in p["nodes"])}
        gq = GraphQuery(rel["graph"], rel["attack_paths"], scope=scope)
        runner = ictx.runner("incident")
        runner.timeout_s = LLM_TIMEOUT_S
        res = runner.run([Task(id=alert_id, subagent="containment-advisor", payload=payload)], graph_query=gq).get(alert_id, {})
        source = res.get("source", "template")
        text = next((o["explanation"] for o in (res.get("output") or []) if o.get("id") == alert_id), None)
        advice = text if (source != "template" and text) else template_advice(alert, rel)
        if source != "template" and not text:
            source = "template"
        comment = compose_comment(alert, advice, rel, source, ictx.run_id)
        if SECRET_RE.search(comment):
            raise IncidentError("留言含疑似機敏值，已停止")
        status, posted = http("POST", f"{GITHUB_API}/repos/{repo}/issues/{issue}/comments",
                              {"authorization": f"Bearer {gh_token}", "accept": "application/vnd.github+json"}, {"body": comment})
        if status not in (200, 201) or not isinstance(posted, dict):
            raise IncidentError(f"留言失敗（HTTP {status}）")
        comment_url = posted.get("html_url", "")
        tr.emit("result", f"已留言到 Issue #{issue}（{source}）", source=source)
        write_json(ictx.out / "incident" / "result.json", {"alert_id": alert_id, "source": source, "comment_url": comment_url,
                                                            "cost_usd": ictx.cost["per_agent"].get("incident", 0.0)})

    status, _ = http("POST", f"{base.rstrip('/')}/api/alerts/advice", {"authorization": f"Bearer {token}"},
                     {"alert_id": alert_id, "comment_url": comment_url, "source": source, "run_id": ictx.run_id})
    if status != 200:
        raise IncidentError(f"回報圍堵建議狀態失敗（HTTP {status}）；重跑會沿用既有留言，不重複產生")
    tr.emit("result", "已回報 /api/alerts/advice")
    return {"alert_id": alert_id, "source": source, "comment_url": comment_url, "reused": bool(existing)}
