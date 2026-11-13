#!/usr/bin/env python3
"""Orchestrator 訂閱步驟（claude-code-action）前後的檔案檢查（specs/orchestrator design §2 步驟 4～5、R6.1）。

訂閱方案的 Claude 只能寫提案檔 out/orchestrator-<m>/<m>-proposal.json。程式只在下列條件全部成立時，
原子寫入採用標記 out/orchestrator-<m>/<m>-proposal.accepted（內容為提案檔位元組的 sha256，
與 agents/agents/orchestrator_agent.read_subscription 的比對方式相同）：
- out/ 底下所有項目（含被 git 忽略的檔案、目錄與符號連結）除了提案檔之外，清單與雜湊和快照完全相同
  （新增、修改、刪除都算變動；採用標記本身也不能由 Claude 寫出）
- git 追蹤的檔案沒有變動（git status --porcelain --untracked-files=no 沒有輸出）。未追蹤的新檔案不檢查：
  claude-code-action 本身可能在工作目錄留下檔案，而 Claude 只能寫提案檔（hook 與 allowedTools 兩層限制）
- 提案檔存在、是一般檔案（不是符號連結）、不超過 64 KiB，而且是 UTF-8 的 JSON 物件
任何一項未通過時不寫標記，並移除已存在的標記（標記只能由通過的 verify 寫入）。

用法：
  python scripts/orchestrator-guard.py snapshot --out out --dest "$RUNNER_TEMP/<m>-snap.json" [--input out/orchestrator-<m>/<m>-input.json]
  python scripts/orchestrator-guard.py verify --mode <m> --snap "$RUNNER_TEMP/<m>-snap.json"
--input：公開輸入不存在或 available 不是 true（A1 結果缺失）時不記錄快照、回傳 1，workflow 因此跳過訂閱步驟（R6.1）。
結束碼：0 通過（snapshot 已記錄、verify 已寫入採用標記）；1 未通過（不寫標記）；2 參數錯誤。
只印路徑、數量與原因，不印任何檔案內容（公開 Repo 的 log 是公開的）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

MODES = ("dispatch", "review")
PLAN_DIRS = {"dispatch": "orchestrator-dispatch", "review": "orchestrator-review"}   # 與 tools.orchestration.PLAN_DIRS 一致（測試核對）
SNAP_SCHEMA = 1
MAX_PROPOSAL_BYTES = 64 * 1024
MAX_LISTED = 10
UNSAFE_RE = re.compile(r"[\x00-\x1f\x7f]")


class GuardError(Exception):
    """檢查無法進行（快照缺失、目錄無法讀取等）：一律視為未通過。"""


def proposal_rel(mode: str) -> str:
    return f"{PLAN_DIRS[mode]}/{mode}-proposal.json"


def accepted_rel(mode: str) -> str:
    return f"{PLAN_DIRS[mode]}/{mode}-proposal.accepted"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _raise(err: OSError) -> None:
    raise GuardError(f"無法讀取目錄（{type(err).__name__}）")


def scan(root: Path) -> dict[str, str]:
    """root 底下所有項目：相對路徑（/ 分隔）→ "file:<sha256>"、"dir"、"link:<連結目標的 sha256>" 或 "other"。

    不跟隨符號連結；目錄無法讀取時拋出 GuardError（不默默略過）。
    """
    if root.is_symlink() or not root.is_dir():
        raise GuardError("out 目錄不存在或不是一般目錄")
    entries: dict[str, str] = {}
    for cur, dirs, files in os.walk(root, followlinks=False, onerror=_raise):
        base = Path(cur)
        for name in [*dirs, *files]:
            p = base / name
            rel = p.relative_to(root).as_posix()
            try:
                st = os.lstat(p)
                if stat.S_ISLNK(st.st_mode):
                    entries[rel] = "link:" + hashlib.sha256(os.fsencode(os.readlink(p))).hexdigest()
                elif stat.S_ISDIR(st.st_mode):
                    entries[rel] = "dir"
                elif stat.S_ISREG(st.st_mode):
                    entries[rel] = "file:" + _sha256_file(p)
                else:
                    entries[rel] = "other"
            except OSError as exc:
                raise GuardError(f"無法讀取 {_show(rel)}（{type(exc).__name__}）") from exc
    return entries


def _show(rel: str) -> str:
    """印出用的相對路徑：去控制字元並截斷（不印檔案內容）。"""
    return UNSAFE_RE.sub("?", rel)[:200]


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------- snapshot
def input_available(path: Path) -> bool:
    """公開輸入存在、是 JSON 物件而且 available 為 true（A1 結果缺失時 orchestrator-input 會寫 available=false）。"""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return False
    return isinstance(data, dict) and data.get("available") is True


def snapshot(out_dir: str, dest: str, input_file: str | None = None) -> int:
    root = Path(out_dir).resolve()
    target = Path(dest).resolve()
    if _inside(target, root):
        print("::error::快照檔不能放在 out/ 底下（Claude 讀寫得到）；請放在 $RUNNER_TEMP", file=sys.stderr)
        return 2
    if input_file is not None and not input_available(Path(input_file)):
        # R6.1：artifact 缺失（A1 結果不可用）時不執行訂閱步驟，程式步驟照常（只跑必要任務）
        print("::notice::公開輸入不可用（A1 結果缺失或無法讀取），不執行訂閱步驟")
        return 1
    try:
        entries = scan(root)
    except GuardError as exc:
        print(f"::error::無法記錄 out/ 的檔案快照：{exc}")
        return 1
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_atomic(target, json.dumps({"schema_version": SNAP_SCHEMA, "out": str(root), "entries": entries},
                                     ensure_ascii=False, sort_keys=True))
    print(f"已記錄 out/ 的檔案快照：{len(entries)} 個項目")
    return 0


# ---------------------------------------------------------------- verify
def _load_snapshot(path: Path) -> tuple[Path, dict[str, str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise GuardError("讀不到訂閱步驟前的檔案快照") from exc
    if not (isinstance(data, dict) and data.get("schema_version") == SNAP_SCHEMA and isinstance(data.get("out"), str)
            and isinstance(data.get("entries"), dict)
            and all(isinstance(k, str) and isinstance(v, str) for k, v in data["entries"].items())):
        raise GuardError("檔案快照格式不符")
    return Path(data["out"]), data["entries"]


def _diff(before: dict[str, str], after: dict[str, str], skip: str) -> list[str]:
    keys = (set(before) | set(after)) - {skip}
    added = sorted(k for k in keys if k not in before)
    removed = sorted(k for k in keys if k not in after)
    changed = sorted(k for k in keys if k in before and k in after and before[k] != after[k])
    return [*(f"新增 {_show(k)}" for k in added), *(f"刪除 {_show(k)}" for k in removed), *(f"改動 {_show(k)}" for k in changed)]


def _git_changes(cwd: Path) -> list[str]:
    """git 追蹤檔的變動（R6.1；不含未追蹤的新檔案）；git 無法執行時拋出 GuardError。"""
    try:
        proc = subprocess.run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=no"], cwd=cwd,
                              capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GuardError("無法執行 git status") from exc
    if proc.returncode != 0:
        raise GuardError(f"git status 失敗（結束碼 {proc.returncode}）")
    out = proc.stdout.decode("utf-8", errors="replace")
    return [e for e in out.split("\0") if e.strip()]


def _parse_proposal(path: Path) -> tuple[bytes | None, str | None]:
    """回傳（提案檔位元組, 未通過原因）。只檢查是否為 JSON 物件；欄位與核准交給程式步驟（approve）。"""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None, "Claude 沒有寫出提案檔"
    except OSError:
        return None, "無法讀取提案檔"
    if not stat.S_ISREG(st.st_mode):
        return None, "提案檔不是一般檔案（可能是符號連結或目錄）"
    if st.st_size > MAX_PROPOSAL_BYTES:
        return None, f"提案檔超過 {MAX_PROPOSAL_BYTES // 1024} KiB"
    try:
        raw = path.read_bytes()
    except OSError:
        return None, "無法讀取提案檔"

    def reject_constant(name):
        raise ValueError(f"不允許 {name}")

    try:
        data = json.loads(raw.decode("utf-8"), parse_constant=reject_constant)
    except (UnicodeDecodeError, ValueError):
        return None, "提案檔不是合法的 UTF-8 JSON"
    if not isinstance(data, dict):
        return None, "提案檔不是 JSON 物件"
    return raw, None


def _drop_marker(root: Path, mode: str) -> None:
    """未通過時移除採用標記（標記只能由通過的 verify 寫入；其他來源的標記一律不留）。"""
    try:
        (root / accepted_rel(mode)).unlink(missing_ok=True)
    except OSError:
        print("::error::無法移除採用標記")


def verify(mode: str, snap: str) -> int:
    problems: list[str] = []
    details: list[str] = []
    try:
        root, before = _load_snapshot(Path(snap))
    except GuardError as exc:
        print(f"::error::訂閱步驟的提案不採用：{exc}")
        _drop_marker(Path("out").resolve(), mode)
        return 1
    try:
        after = scan(root)
    except GuardError as exc:
        print(f"::error::訂閱步驟的提案不採用：{exc}")
        _drop_marker(root, mode)
        return 1
    changes = _diff(before, after, proposal_rel(mode))
    if changes:
        problems.append(f"out/ 中提案檔以外的項目有變動（{len(changes)} 項）")
        details += changes[:MAX_LISTED]
    try:
        git = _git_changes(root)
    except GuardError as exc:
        problems.append(str(exc))
        git = []
    if git:
        problems.append(f"git 追蹤的檔案有變動或新增了未被忽略的檔案（{len(git)} 項）")
        details += [f"git：{_show(e)}" for e in git[:MAX_LISTED]]
    raw, why = _parse_proposal(root / proposal_rel(mode))
    if why:
        problems.append(why)
    if problems:
        for p in problems:
            print(f"::error::訂閱步驟的提案不採用：{p}")
        for d in details:
            print(f"  {d}")
        _drop_marker(root, mode)
        return 1
    digest = hashlib.sha256(raw).hexdigest()            # 與 orchestrator_agent.read_subscription 相同：提案檔位元組的 sha256
    _write_atomic(root / accepted_rel(mode), digest)
    print(f"提案通過檢查，已寫入採用標記 {accepted_rel(mode)}（sha256 前 12 碼 {digest[:12]}）")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Orchestrator 訂閱步驟的檔案快照與採用檢查")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot", help="記錄 out/ 底下所有項目的路徑與 sha256")
    s.add_argument("--out", required=True)
    s.add_argument("--dest", required=True)
    s.add_argument("--input", help="公開輸入；不存在或 available 不是 true 時不記錄快照、回傳 1（訂閱步驟跳過）")
    v = sub.add_parser("verify", help="檢查訂閱步驟只寫了提案檔，通過才寫入採用標記")
    v.add_argument("--mode", required=True, choices=MODES)
    v.add_argument("--snap", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "snapshot":
        return snapshot(a.out, a.dest, a.input)
    return verify(a.mode, a.snap)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
