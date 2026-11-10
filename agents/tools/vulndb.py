"""程式查漏洞資料庫（不經過 LLM）：CISA KEV 全集與 NVD CVE API。

- kev：下載 CISA KEV 全集 → 已遭實際利用的 CVE 清單。A2／A4 用它標記「已遭利用」，intel-watch 用它找新列入的 CVE。
- nvd：圖譜中有版本、且 aliases.yaml 有 nvd 設定的元件 → 以 CPE 向 NVD 取候選 CVE → 本地以 version_match 重新確認。
  NVD 伺服器端比對會忽略部分版本細節（例如 DSM 的 Update 編號），候選不能直接當成受影響。
- 設定為 AND 的 CVE（例如「PHP 某版本，且執行於 Windows」）標為 conditional：執行環境未確認，不算確定受影響。
- 範圍是「所有版本」（criteria 版本為 * 且沒有上下界）的 CVE 視為版本無法判斷，同樣列為需確認。
- 網路一律經 safe_fetch（HTTPS、網域白名單、大小與型態限制）；NVD 沒有 API key 時每 30 秒最多 5 次請求，
  預設每次請求間隔 6.5 秒，有 NVD_API_KEY 時 0.7 秒。
用法：
  python agents/tools/vulndb.py kev <raw-dir>
  python agents/tools/vulndb.py nvd <raw-dir> --target <target-root>
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.aliases import normalize, nvd_products  # noqa: E402
from tools.common import iso, write_json  # noqa: E402
from tools.safe_fetch import fetch  # noqa: E402
from tools.version_match import AFFECTED, UNKNOWN, compare, match, parse_dsm  # noqa: E402

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_ALLOW = ["cisa.gov"]
KEV_MAX_BYTES = 8 * 1024 * 1024          # 2026-11 約 1.8 MB，持續增加
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_ALLOW = ["services.nvd.nist.gov"]
NVD_MAX_BYTES = 8 * 1024 * 1024
NVD_PAGE = 100
NVD_MAX_PAGES = 5                         # 單一 CPE 最多 500 筆；超過標記 truncated
NVD_TIMEOUT = 30
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
VERSION_SAFE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,39}$")
RANGE_KEYS = {"versionStartIncluding": "start_including", "versionStartExcluding": "start_excluding",
              "versionEndIncluding": "end_including", "versionEndExcluding": "end_excluding"}
MAX_PLATFORMS_PER_NODE = 20

Fetcher = Callable[..., object]


def _text(value, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def pace_seconds() -> float:
    return 0.7 if os.environ.get("NVD_API_KEY") else 6.5


def _nvd_headers() -> dict[str, str]:
    key = os.environ.get("NVD_API_KEY")
    return {"apiKey": key} if key else {}


# ---------------------------------------------------------------- KEV

def fetch_kev(fetcher: Fetcher = fetch) -> dict:
    res = fetcher(KEV_URL, KEV_ALLOW, max_bytes=KEV_MAX_BYTES, timeout=NVD_TIMEOUT)
    if res.status >= 400:
        raise RuntimeError(f"CISA KEV HTTP {res.status}")
    return json.loads(res.text)


def normalize_kev(raw: dict) -> dict:
    vulns = (raw or {}).get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        raise ValueError("KEV 缺少 vulnerabilities")
    cves = {}
    for v in vulns:
        if not isinstance(v, dict):
            continue
        cve = _text(v.get("cveID"), 20)
        if not CVE_RE.match(cve):
            continue
        cves[cve] = {"added": _text(v.get("dateAdded"), 10), "vendor": _text(v.get("vendorProject"), 80),
                     "product": _text(v.get("product"), 80), "name": _text(v.get("vulnerabilityName"), 160),
                     "ransomware": v.get("knownRansomwareCampaignUse") == "Known"}
    if not cves:
        raise ValueError("KEV 沒有合法的 CVE")
    return {"tool": "kev", "tool_version": _text(raw.get("catalogVersion"), 20) or None,
            "database_revision": _text(raw.get("dateReleased"), 40) or None, "count": len(cves), "cves": cves}


def kev_ids(kev_data: dict | None) -> set[str]:
    return set(((kev_data or {}).get("cves") or {}).keys())


# ---------------------------------------------------------------- CPE

def _split_cpe(cpe: str) -> list[str] | None:
    parts = cpe.split(":")
    return parts if len(parts) == 13 and parts[0] == "cpe" and parts[1] == "2.3" else None


def criteria_matches(criteria: str, template: str) -> bool:
    """part／vendor／product 相同，且 update 之後的欄位沒有互相矛盾（兩邊都有具體值時必須相同）。版本欄位另外比對。"""
    c, t = _split_cpe(criteria), _split_cpe(template)
    if not c or not t or c[2:5] != t[2:5]:
        return False
    for i in range(6, 13):
        if t[i] not in ("*", "-") and c[i] not in ("*", "-") and t[i] != c[i]:
            return False
    return True


def cpe_version(version: str | None, ecosystem: str) -> str | None:
    """元件版本 → CPE 版本欄位。DSM 去掉 Update（NVD 以 7.2.1-69057 列版本，Update 由本地重新比對）。"""
    if not version:
        return None
    if ecosystem == "synology-dsm":
        t = parse_dsm(version)
        if not t:
            return None
        major, minor, patch, build, _ = t
        v = f"{major}.{minor}.{patch}" + (f"-{build}" if build else "")
    else:
        v = version.strip()
    return v if VERSION_SAFE.match(v) else None


def cpe_name(template: str, version: str | None, ecosystem: str) -> str | None:
    v = cpe_version(version, ecosystem)
    return template.replace("{version}", v) if v and "{version}" in template else None


def _platform_label(criteria: str) -> str:
    c = _split_cpe(criteria)
    if not c:
        return criteria[:60]
    ver = "" if c[5] in ("*", "-") else f" {c[5]}"
    return f"{c[3]} {c[4]}{ver}".replace("_", " ")


# ---------------------------------------------------------------- NVD 回應整理

def _cvss(metrics: dict | None) -> float | None:
    """CVSS v4／v3.x 的最高 baseScore；都沒有時用 v2。"""
    metrics = metrics or {}
    best = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key) or []:
            s = ((m or {}).get("cvssData") or {}).get("baseScore")
            if isinstance(s, (int, float)) and not isinstance(s, bool):
                best = max(best or 0.0, float(s))
    if best is None:
        for m in metrics.get("cvssMetricV2") or []:
            s = ((m or {}).get("cvssData") or {}).get("baseScore")
            if isinstance(s, (int, float)) and not isinstance(s, bool):
                best = max(best or 0.0, float(s))
    return best


def trim_cve(cve: dict, templates: list[str]) -> dict | None:
    """只保留比對需要的欄位：本產品的 vulnerable cpeMatch、以及同一設定中的平台條件（非 vulnerable）。"""
    cid = _text(cve.get("id"), 20)
    if not CVE_RE.match(cid):
        return None
    desc = next((d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    confs = []
    for conf in cve.get("configurations") or []:
        nodes = []
        for n in conf.get("nodes") or []:
            ours, platforms = [], []
            for m in n.get("cpeMatch") or []:
                crit = _text(m.get("criteria"), 200)
                if not crit:
                    continue
                entry = {"criteria": crit, "vulnerable": bool(m.get("vulnerable"))}
                entry.update({k: _text(m[k], 40) for k in RANGE_KEYS if m.get(k)})
                if entry["vulnerable"] and any(criteria_matches(crit, t) for t in templates):
                    ours.append(entry)
                elif not entry["vulnerable"] and len(platforms) < MAX_PLATFORMS_PER_NODE:
                    platforms.append(entry)
            if ours or platforms:
                nodes.append({"operator": n.get("operator") or "OR", "negate": bool(n.get("negate")),
                              "cpe_match": ours + platforms})
        if any(m["vulnerable"] for nd in nodes for m in nd["cpe_match"]):
            confs.append({"operator": conf.get("operator") or "OR", "negate": bool(conf.get("negate")), "nodes": nodes})
    if not confs:
        return None
    return {"id": cid, "published": _text(cve.get("published"), 40) or None,
            "last_modified": _text(cve.get("lastModified"), 40) or None, "status": _text(cve.get("vulnStatus"), 40) or None,
            "kev_added": _text(cve.get("cisaExploitAdd"), 10) or None, "cvss": _cvss(cve.get("metrics")),
            "summary": _text(desc, 200), "configurations": confs}


# ---------------------------------------------------------------- 本地重新比對

def cpe_interval(m: dict, ecosystem: str) -> dict | None:
    """cpeMatch → version_match 的 NVD 區間。版本為 * 且沒有上下界（所有版本）回傳 None（無法判斷）。"""
    c = _split_cpe(m["criteria"])
    if not c:
        return None
    if c[5] not in ("*", "-"):
        exact = c[5].replace("\\", "")
        upd = re.fullmatch(r"update[_-]?(\d+)", c[6] or "", flags=re.I)
        if ecosystem == "synology-dsm" and upd:
            exact = f"{exact}-{upd.group(1)}"
        return {"exact": exact}
    iv = {RANGE_KEYS[k]: m[k] for k in RANGE_KEYS if m.get(k)}
    return iv or None


_RANK = {(AFFECTED, False): 3, (UNKNOWN, False): 2, (AFFECTED, True): 1, (UNKNOWN, True): 0}


def assess(cve: dict, templates: list[str], version: str, ecosystem: str) -> dict | None:
    """回傳 {verdict: affected|unknown, conditional, platforms, interval}；不受影響回傳 None。"""
    best = None
    for conf in cve.get("configurations") or []:
        if conf.get("negate"):
            continue
        hit, hit_iv, platforms = None, None, []
        for node in conf.get("nodes") or []:
            if node.get("negate"):
                continue
            for m in node.get("cpe_match") or []:
                if m.get("vulnerable") and any(criteria_matches(m["criteria"], t) for t in templates):
                    iv = cpe_interval(m, ecosystem)
                    r = UNKNOWN if iv is None else match(version, [iv], ecosystem)
                    if r == AFFECTED or (r == UNKNOWN and hit is None):
                        hit, hit_iv = r, iv
                elif not m.get("vulnerable"):
                    platforms.append(_platform_label(m["criteria"]))
        if hit not in (AFFECTED, UNKNOWN):
            continue
        conditional = (conf.get("operator") or "OR") == "AND" and bool(platforms)
        cand = {"verdict": hit, "conditional": conditional, "platforms": sorted(set(platforms))[:5] if conditional else [],
                "interval": hit_iv}
        if best is None or _RANK[(cand["verdict"], cand["conditional"])] > _RANK[(best["verdict"], best["conditional"])]:
            best = cand
    return best


def fixed_version(intervals: list[dict | None], ecosystem: str) -> str | None:
    """所有確定受影響的 CVE 都有「不含上界」時，取最大者（升到這個版本才全部修補）；否則 None。"""
    ends = [iv.get("end_excluding") for iv in intervals if iv]
    if not ends or len(ends) != len(intervals) or any(e is None for e in ends):
        return None
    best = ends[0]
    for e in ends[1:]:
        c = compare(e, best, ecosystem)
        if c is None:
            return None
        if c > 0:
            best = e
    return best


# ---------------------------------------------------------------- NVD 查詢

def nvd_components(graph) -> tuple[list[dict], list[dict]]:
    """回傳（要查 NVD 的元件，依名稱＋版本去重並記錄資產；未涵蓋的元件）。"""
    products = nvd_products()
    targets: dict[tuple[str, str], dict] = {}
    uncovered: dict[tuple[str, str], dict] = {}
    for nid, node in graph.nodes(data=True):
        for c in node.get("components", []):
            name, ver = normalize(c.get("name")), c.get("version")
            if not name:
                continue
            if c.get("ecosystem") == "npm":
                continue                               # npm 套件由 Trivy 依 lockfile 比對
            spec = products.get(name)
            key = (name, ver or "")
            if spec is None or not ver:
                u = uncovered.setdefault(key, {"name": name, "version": ver, "asset_ids": [],
                                               "reason": "版本未知" if not ver else "沒有 CPE 對照（aliases.yaml 未設定 nvd）"})
                u["asset_ids"].append(nid)
                continue
            t = targets.setdefault(key, {"name": name, "version": ver, "ecosystem": spec["ecosystem"],
                                         "templates": spec["cpe"], "asset_ids": []})
            t["asset_ids"].append(nid)
    for d in (*targets.values(), *uncovered.values()):
        d["asset_ids"] = sorted(set(d["asset_ids"]))
    return sorted(targets.values(), key=lambda d: (d["name"], d["version"])), \
        sorted(uncovered.values(), key=lambda d: (d["name"], d["version"] or ""))


def query_cpe(name: str, *, fetcher: Fetcher = fetch, pace: Callable[[], None] | None = None) -> tuple[list[dict], bool]:
    """回傳（NVD 原始 CVE 物件，是否被截斷）。"""
    out, truncated = [], False
    for page in range(NVD_MAX_PAGES):
        url = (f"{NVD_API}?cpeName={quote(name, safe=':*._-')}&isVulnerable"
               f"&resultsPerPage={NVD_PAGE}&startIndex={page * NVD_PAGE}")
        if pace:
            pace()
        res = fetcher(url, NVD_ALLOW, max_bytes=NVD_MAX_BYTES, timeout=NVD_TIMEOUT, headers=_nvd_headers())
        if res.status >= 400:
            raise RuntimeError(f"NVD HTTP {res.status}")
        data = json.loads(res.text)
        vulns = [v.get("cve") for v in data.get("vulnerabilities") or [] if isinstance(v, dict) and v.get("cve")]
        out += vulns
        total = int(data.get("totalResults") or 0)
        if (page + 1) * NVD_PAGE >= total or not vulns:
            return out, False
        truncated = True
    return out, truncated


def query_cve(cve_id: str, *, fetcher: Fetcher = fetch, pace: Callable[[], None] | None = None) -> dict | None:
    if not CVE_RE.match(cve_id):
        raise ValueError("CVE 編號格式不符")
    if pace:
        pace()
    res = fetcher(f"{NVD_API}?cveId={cve_id}", NVD_ALLOW, max_bytes=NVD_MAX_BYTES, timeout=NVD_TIMEOUT,
                  headers=_nvd_headers())
    if res.status >= 400:
        raise RuntimeError(f"NVD HTTP {res.status}")
    vulns = json.loads(res.text).get("vulnerabilities") or []
    return (vulns[0] or {}).get("cve") if vulns else None


def scan_components(targets: list[dict], *, fetcher: Fetcher = fetch, pace: Callable[[], None] | None = None) -> list[dict]:
    results = []
    for t in targets:
        cves: dict[str, dict] = {}
        queries = []
        for tpl in t["templates"]:
            name = cpe_name(tpl, t["version"], t["ecosystem"])
            if not name:
                queries.append({"cpe": tpl, "status": "skipped", "reason": "版本無法轉成 CPE"})
                continue
            try:
                raw, truncated = query_cpe(name, fetcher=fetcher, pace=pace)
            except Exception as exc:                  # 網路錯誤、逾時、HTTP 錯誤、格式不符
                queries.append({"cpe": name, "status": "failed", "reason": f"{type(exc).__name__}: {exc}"[:200]})
                continue
            for c in raw:
                tc = trim_cve(c, t["templates"])
                if tc:
                    cves[tc["id"]] = tc
            queries.append({"cpe": name, "status": "ok", "truncated": truncated, "candidates": len(raw)})
        ok = any(q["status"] == "ok" for q in queries)
        results.append({"name": t["name"], "version": t["version"], "ecosystem": t["ecosystem"], "templates": t["templates"],
                        "asset_ids": t["asset_ids"], "status": "ok" if ok else "failed", "queries": queries,
                        "cves": sorted(cves.values(), key=lambda c: c["id"])})
    return results


# ---------------------------------------------------------------- KEV 新列入 → 公告（intel-watch）

def advisory_from_cve(cve: dict, kev_entry: dict, *, as_of: datetime) -> dict | None:
    """NVD CVE（原始）＋ KEV 項目 → intel-watch 的公告。只有 CVE 涉及 aliases.yaml 有 nvd 設定的產品才產生。"""
    products = []
    for name, spec in nvd_products().items():
        tc = trim_cve(cve, spec["cpe"])
        if not tc:
            continue
        ranges = []
        for conf in tc["configurations"]:
            for node in conf["nodes"]:
                for m in node["cpe_match"]:
                    if m["vulnerable"] and any(criteria_matches(m["criteria"], t) for t in spec["cpe"]):
                        iv = cpe_interval(m, spec["ecosystem"])
                        if iv and iv not in ranges:
                            ranges.append(iv)
        conditional = any((c["operator"] == "AND") and any(not m["vulnerable"] for n in c["nodes"] for m in n["cpe_match"])
                          for c in tc["configurations"])
        products.append({"name": name, "ecosystem": spec["ecosystem"], "affected": ranges, "cvss": tc["cvss"],
                         "known_exploited": True, "impact": "other",
                         **({"platform_conditional": True} if conditional else {})})
    if not products:
        return None
    cid = _text(cve.get("id"), 20)
    desc = next((d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    title = kev_entry.get("name") or f"{kev_entry.get('vendor', '')} {kev_entry.get('product', '')}".strip()
    revision = _text(cve.get("lastModified"), 40) or iso(as_of)
    conditional = any(p.get("platform_conditional") for p in products)
    return {
        "id": f"kev-{cid.lower()}", "kind": "advisory", "generated_by": "kev-nvd", "revision": revision,
        "title": f"CISA KEV：{title}（{cid}）", "date": kev_entry.get("added") or iso(as_of)[:10], "industry": None,
        "summary": _text(desc, 300) or None, "attack_chain": [], "attck": [], "cves": [cid], "controls": [],
        "confidence": "confirmed", "products": products,
        "sources": [
            {"url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search={cid}",
             "title": f"CISA Known Exploited Vulnerabilities：{cid}", "quote": None, "published": kev_entry.get("added")},
            {"url": f"https://nvd.nist.gov/vuln/detail/{cid}", "title": f"NVD：{cid}", "quote": None,
             "published": _text(cve.get("published"), 10) or None},
        ],
        # NVD 設定含平台條件（例如特定作業系統）：版本命中後仍需人工確認執行環境，不直接算受影響
        **({"requires_manual_check": ["確認執行環境是否符合 NVD 設定中的平台條件（例如作業系統）"]} if conditional else {}),
    }


# ---------------------------------------------------------------- CLI（scanners 矩陣）

def _sleep_pacer(seconds: float) -> Callable[[], None]:
    state = {"first": True}

    def pace():
        if not state["first"]:
            time.sleep(seconds)
        state["first"] = False
    return pace


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("tool", choices=["kev", "nvd"])
    ap.add_argument("raw_dir", type=Path)
    ap.add_argument("--target", type=Path)
    a = ap.parse_args(argv)
    a.raw_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    if a.tool == "kev":
        write_json(a.raw_dir / "kev.json", fetch_kev())
        print(json.dumps({"tool": "kev", "status": "fetched"}))
        return 0
    if not a.target:
        ap.error("nvd 需要 --target")
    if not (a.target / "ops").is_dir():
        raise SystemExit(f"找不到 {a.target}/ops：不能把缺少的資產清單當成「沒有元件、沒有漏洞」")
    from tools.graph_builder import build_graph
    from tools.loaders import load_target
    from tools.reconcile import reconcile
    data = load_target(a.target, as_of=now)
    g = build_graph(data, reconcile(data))
    targets, uncovered = nvd_components(g)
    if not targets and not uncovered:
        raise SystemExit("圖譜中沒有任何元件：資產清單可能缺失，不輸出零結果")
    results = scan_components(targets, pace=_sleep_pacer(pace_seconds()))
    write_json(a.raw_dir / "nvd.json", {"tool": "nvd", "queried_at": iso(now), "api_key": bool(os.environ.get("NVD_API_KEY")),
                                        "results": results, "uncovered": uncovered})
    print(json.dumps({"tool": "nvd", "components": len(targets), "failed": sum(r["status"] != "ok" for r in results)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
