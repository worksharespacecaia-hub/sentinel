"""發布合併（第 10.1 節）：把本次 run 的不可變候選產物套用到最新 main 的乾淨工作樹。

- 只處理允許的路徑；不使用 git add .
- index.json：依各 key 合併，較舊的 generated_at 不覆蓋較新的
- llm.json：合併不同 key；相同 key 不同值不靜默覆蓋，回報衝突
- output_dir：候選比現有新（generated_at）才覆蓋；較舊的 run 不覆蓋新狀態
- digest/（資安事件整理）：只在 daily 合併；seen 聯集、store 依收錄與評估時間整組合併、latest 依 as_of→updated_at→run_id 選取，
  並以 publisher 本次時間（--now，重試固定同一值）清理 main 上的到期內容
用法：python agents/tools/publish_merge.py --candidate DIR --repo DIR --output-dir daily [--now 2026-11-11T00:20:00Z]
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import digest as dg  # noqa: E402
from tools.cache import merge_cache  # noqa: E402
from tools.common import parse_time, read_json, write_json  # noqa: E402

DATA = Path("dashboard/public/data")
ALLOWED_PREFIXES = ("daily", "advisories/", "scenarios/", "failures/", "intel-watch")
STATUS_RANK = {"done": 4, "running": 3, "pending": 2, "failed": 1, "queued": 1, "checked": 0}
AUTO_WINDOW = timedelta(days=30)          # 與 intel_watch.AUTO_WINDOW 相同：自動公告保留 30 天
CHECKED_KEEP = timedelta(days=7)          # 查過的 KEV CVE 在窗口內每天重查；7 天沒更新代表已移出窗口


def merge_watch(cand: dict | None, cur: dict | None) -> dict | None:
    """intel-watch.json：依 input_hash 合併；done 不會被較舊的 pending／failed 覆蓋。

    auto_advisories 依 ID 合併、kev_checked 依 CVE 合併，各取較新者：A5 發布時帶的是較早 checkout 的副本，
    不能因此蓋掉 intel-watch 之後才產生的自動公告。
    """
    if not cand:
        return cur
    items = {i.get("input_hash") or i["advisory_id"]: i for i in (cur or {}).get("items", [])}
    for i in cand.get("items", []):
        key = i.get("input_hash") or i["advisory_id"]
        old = items.get(key)
        if old is None or STATUS_RANK.get(i.get("status"), 0) >= STATUS_RANK.get(old.get("status"), 0):
            items[key] = i
    newest = cand if _newer({"generated_at": cand.get("checked_at")}, {"generated_at": (cur or {}).get("checked_at")}) else (cur or cand)
    out = {**newest, "items": list(items.values())}
    # 聯集之後依日期清除：否則 intel-watch 已刪除的過期項目會被 main 上的舊副本加回來，永遠刪不掉
    now = parse_time(out.get("checked_at"))
    adv_cutoff = (now - AUTO_WINDOW).date().isoformat() if now else ""
    checked_cutoff = now - CHECKED_KEEP if now else None
    advs = {a["id"]: a for a in (cur or {}).get("auto_advisories") or [] if isinstance(a, dict) and a.get("id")}
    for a in cand.get("auto_advisories") or []:
        if isinstance(a, dict) and a.get("id") and _newer(a, advs.get(a["id"])):
            advs[a["id"]] = a
    advs = {k: a for k, a in advs.items() if (a.get("date") or "") >= adv_cutoff}
    if advs:
        out["auto_advisories"] = sorted(advs.values(), key=lambda a: a["id"])
    else:
        out.pop("auto_advisories", None)
    checked = dict((cur or {}).get("kev_checked") or {})
    for k, v in (cand.get("kev_checked") or {}).items():
        if _newer({"generated_at": (v or {}).get("checked_at")}, {"generated_at": (checked.get(k) or {}).get("checked_at")}):
            checked[k] = v
    checked = {k: v for k, v in checked.items()
               if checked_cutoff is None or (parse_time((v or {}).get("checked_at")) or checked_cutoff) > checked_cutoff}
    if checked:
        out["kev_checked"] = dict(sorted(checked.items()))
    else:
        out.pop("kev_checked", None)
    return out


def _newer(a: dict | None, b: dict | None) -> bool:
    ta, tb = parse_time((a or {}).get("generated_at")), parse_time((b or {}).get("generated_at"))
    return tb is None or (ta is not None and ta >= tb)


def merge_index(cand: dict, cur: dict) -> dict:
    out = dict(cur or {})
    for key in ("latest_daily", "latest_complete_daily"):
        if cand.get(key) and _newer(cand[key], out.get(key)):
            out[key] = cand[key]
    for group in ("advisories", "scenarios", "failures"):
        merged = dict(out.get(group) or {})
        for k, v in (cand.get(group) or {}).items():
            if _newer(v, merged.get(k)):
                merged[k] = v
        out[group] = merged
    out["schema_version"] = 1
    stamps = [x for x in (cand.get("updated_at"), (cur or {}).get("updated_at")) if x]
    out["updated_at"] = max(stamps) if stamps else None
    return out


# ── 資安事件整理（specs/security-digest 第 5 節）：digest/ 不在 daily/ 底下，需另行合併與清理 ──

OBS_FIELDS = ("last_seen", "last_seen_at", "observed_run_id")


def _load_digest(directory: Path, name: str) -> tuple[dict | None, bool]:
    """回傳 (資料, 是否不合法)。不存在 → (None, False)；schema 或時間不合法 → (None, True)，不得覆蓋有效前版。"""
    try:
        return dg.load_valid(directory / name, name), False
    except dg.DigestError:
        return None, True


def merge_seen(seens: list[dict | None], stores: list[dict | None], latests: list[dict | None]) -> dict:
    """去重鍵聯集、日期取較早者；前版／候選 store 與 latest 的首次收錄日期也納入。"""
    out: dict[str, str] = {}

    def put(key: str, day: str):
        out[key] = min(out.get(key, day), day)

    for s in seens:
        for k, v in ((s or {}).get("first_seen_by_key") or {}).items():
            put(k, v)
    for st in stores:
        for ev in ((st or {}).get("events") or {}).values():
            put(dg.seen_key(ev["id"]), ev["first_seen"])
    for la in latests:
        for ev in dg.flatten_latest(la or {}):
            put(dg.seen_key(ev["id"]), ev["first_seen"])
    return {"schema_version": 1, "first_seen_by_key": dict(sorted(out.items()))}


def _content(ev: dict) -> dict:
    return {k: v for k, v in ev.items() if k not in (*OBS_FIELDS, "first_seen")}


def merge_digest_store(cand: dict | None, cur: dict | None, seen: dict) -> tuple[dict | None, list[str]]:
    """事件 ID 聯集。收錄資料依 (last_seen_at, observed_run_id) 取較新；事件內容與評估快照依 (evaluated_at, run_id)
    整組取最近的完整快照，較晚的不完整收錄不能覆蓋完整評估。相同評估 run 內容不同 → 記錄衝突並保留遠端。"""
    if cand is None and cur is None:
        return None, []
    conflicts: list[str] = []
    seen_map = seen["first_seen_by_key"]
    cur_events, cand_events = (cur or {}).get("events") or {}, (cand or {}).get("events") or {}
    events = {}
    for eid in sorted(set(cur_events) | set(cand_events)):
        a, b = cur_events.get(eid), cand_events.get(eid)
        if a is None or b is None:
            ev = copy.deepcopy(a or b)
        else:
            obs = b if dg._obs_key(b) > dg._obs_key(a) else a
            ka, kb = dg._eval_key(a.get("assessment")), dg._eval_key(b.get("assessment"))
            if ka is None and kb is None:
                src = obs
            elif ka is None or kb is None:
                src = a if kb is None else b
            elif ka != kb:
                src = a if ka > kb else b
            else:
                src = a
                if _content(a) != _content(b):
                    conflicts.append(eid)
            ev = {**copy.deepcopy(_content(src)), **{k: obs[k] for k in OBS_FIELDS},
                  "first_seen": min(a["first_seen"], b["first_seen"])}
            other = b if src is a else a
            win, lose = ev.get("assessment"), other.get("assessment")
            if win and lose and dg._eval_key(win) > dg._eval_key(lose) and win["relation"] != lose["relation"]:
                changed = parse_time(win.get("relation_changed_at"))
                if changed is None or changed <= parse_time(lose["evaluated_at"]):
                    win["relation_changed_at"] = win["evaluated_at"]   # 兩份快照之間關係有變：以較新的評估時間標示
        ev["first_seen"] = min(ev["first_seen"], seen_map.get(dg.seen_key(eid), ev["first_seen"]))
        events[eid] = ev
    updated = max((x["updated_at"] for x in (cur, cand) if x), key=parse_time)     # 取既有值，不刷新成發布時間
    issues = [i for i in (cur or cand).get("data_issues") or [] if i["code"] != "merge_conflict"]
    return {"schema_version": 1, "updated_at": updated, "data_issues": issues, "events": events}, conflicts


def _latest_key(latest: dict) -> tuple:
    """先比評估的 as_of，相同時才比實際 updated_at，最後以 run_id 穩定決勝（不使用只讀 generated_at 的 _newer）。"""
    return (parse_time(latest["as_of"]), parse_time(latest["updated_at"]), latest["run_id"])


def choose_latest(cand: dict | None, cur: dict | None, now, seen: dict) -> tuple[dict | None, bool]:
    """回傳 (所選 latest, 是否衝突)。保留所選快照的發布資格，不由 store 聯集重建。"""
    if cand is None or cur is None:
        return (cur or cand), False
    kc, ku = _latest_key(cand), _latest_key(cur)
    if kc > ku:
        return cand, False
    if kc < ku:
        return cur, False
    same = dg.prune_latest(cand, now, seen=seen) == dg.prune_latest(cur, now, seen=seen)
    return cur, not same


def _digest_files(cand_dir: Path | None, repo_dir: Path, now) -> tuple[dict[str, bytes], dict]:
    info: dict = {"conflicts": [], "issues": []}
    loaded = {}
    for side, d in (("cand", cand_dir), ("cur", repo_dir)):
        for name in dg.FILES:
            data, bad = _load_digest(d, name) if d is not None else (None, False)
            if bad:
                info["issues"].append(f"digest：{'候選' if side == 'cand' else '遠端'} {name} 格式或時間不合法，不採用")
            loaded[(side, name)] = data
    stores = [loaded[("cur", "store.json")], loaded[("cand", "store.json")]]
    latests = [loaded[("cur", "latest.json")], loaded[("cand", "latest.json")]]
    seen = merge_seen([loaded[("cur", "seen.json")], loaded[("cand", "seen.json")]], stores, latests)
    store, conflicts = merge_digest_store(stores[1], stores[0], seen)
    files: dict[str, bytes] = {}
    if store is not None:
        store, _, _ = dg.finalize_store(store, seen, now)
        if conflicts:
            store["data_issues"].append(dg._issue("merge_conflict", f"{len(conflicts)} 件事件的同一次評估內容不一致，保留遠端版本",
                                                  len(conflicts)))
            info["conflicts"] += [f"digest/store.json：{eid} 同一次評估內容不一致，保留遠端" for eid in conflicts]
        files["store.json"] = dg.validated_bytes("store.json", store)
    latest, conflict = choose_latest(latests[1], latests[0], now, seen)
    if conflict:
        info["conflicts"].append("digest/latest.json：相同評估與產生時間但內容不同，保留遠端")
    if latest is not None:
        files["latest.json"] = dg.validated_bytes("latest.json", dg.prune_latest(latest, now, seen=seen))
    if files or seen["first_seen_by_key"]:
        files["seen.json"] = dg.validated_bytes("seen.json", seen)
    return files, info


def merge_digest(cand_dir: Path, repo_dir: Path, *, now, staging_parent: Path) -> dict:
    """合併候選與 main 的 digest，並以 publisher 本次的時間清理 main 上的 store／latest（R5.2）。

    沒有候選、候選不合法或 daily 被略過時也照樣清理遠端既有 digest；整組驗證後才提交，錯誤不靜默發布。
    """
    result = {"applied": [], "conflicts": [], "issues": []}
    try:
        files, info = _digest_files(cand_dir if cand_dir.is_dir() else None, repo_dir, now)
    except (dg.DigestError, ValueError) as exc:
        result["issues"].append(f"digest：合併結果未通過檢查（{dg.safe_error_code(exc)}），改為只清理遠端")
        try:
            files, info = _digest_files(None, repo_dir, now)
        except (dg.DigestError, ValueError) as exc2:
            result["issues"].append(f"digest：遠端清理也未通過檢查（{dg.safe_error_code(exc2)}），維持原狀")
            return result
    result["conflicts"] += info["conflicts"]
    result["issues"] += info["issues"]
    if files:
        dg.commit_bundle(repo_dir, files, staging_parent)
        result["applied"] += [str(DATA / "digest" / n) for n in dg.FILES if n in files]
    return result


def apply(candidate: Path, repo: Path, output_dir: str, *, now: datetime | None = None) -> dict:
    """now：publisher 本次的實際 UTC 時間（digest 到期清理的基準）；重試時由呼叫端固定傳入同一個值。"""
    if ".." in Path(output_dir).parts or not output_dir.startswith(ALLOWED_PREFIXES):
        raise ValueError(f"不允許的 output_dir：{output_dir}")
    now = now or datetime.now(timezone.utc)
    report = {"applied": [], "skipped": [], "conflicts": []}
    watch = merge_watch(read_json(candidate / DATA / "intel-watch.json"), read_json(repo / DATA / "intel-watch.json"))
    if watch:
        write_json(repo / DATA / "intel-watch.json", watch)
        report["applied"].append(str(DATA / "intel-watch.json"))
    if output_dir == "intel-watch":
        return report
    src, dst = candidate / DATA / output_dir, repo / DATA / output_dir
    if src.is_dir():
        if _newer(read_json(src / "report.json"), read_json(dst / "report.json")):
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
            report["applied"].append(str(DATA / output_dir))
        else:
            report["skipped"].append(f"{output_dir}：遠端已有較新的結果")
    if output_dir == "daily":            # 情境、公告調查、failures、intel-watch 不合併候選 digest（避免 checkout 的舊副本）
        d = merge_digest(candidate / DATA / "digest", repo / DATA / "digest", now=now, staging_parent=repo)
        report["applied"] += d["applied"]
        report["conflicts"] += d["conflicts"]
        if d["issues"]:
            report["digest_issues"] = d["issues"]
    for sub in ("history",):
        s = candidate / DATA / sub
        if s.is_dir():
            (repo / DATA / sub).mkdir(parents=True, exist_ok=True)
            for f in s.glob("*.json"):
                shutil.copy2(f, repo / DATA / sub / f.name)
    cidx = read_json(candidate / DATA / "index.json")
    if cidx:
        write_json(repo / DATA / "index.json", merge_index(cidx, read_json(repo / DATA / "index.json", {}) or {}))
        report["applied"].append(str(DATA / "index.json"))
    ccache = read_json(candidate / "agents" / "cache" / "llm.json")
    if ccache is not None:
        merged, conflicts = merge_cache(read_json(repo / "agents" / "cache" / "llm.json", {}) or {}, [ccache])
        write_json(repo / "agents" / "cache" / "llm.json", merged)
        report["conflicts"] += conflicts
    for rel in ("reports/intel",):
        s = candidate / rel
        if s.is_dir():
            shutil.copytree(s, repo / rel, dirs_exist_ok=True)
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate", type=Path, required=True)
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--now", default=os.environ.get("PUBLISH_NOW"),
                    help="publisher 的 UTC 時間（ISO 8601）；push-with-retry.sh 每次重試傳入同一個值")
    a = ap.parse_args(argv)
    now = parse_time(a.now) if a.now else None
    rep = apply(a.candidate, a.repo, a.output_dir, now=now)
    print(json.dumps(rep, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
