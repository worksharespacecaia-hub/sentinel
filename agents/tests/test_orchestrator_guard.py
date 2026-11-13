"""scripts/orchestrator-guard.py：訂閱步驟前後的檔案快照與採用檢查（specs/orchestrator design §2 步驟 4～5、R6.1、§8）。

- 被 git 忽略的 out/ 檔案新增、修改、刪除，git 有變動，或提案不是 JSON 物件時，verify 失敗且不寫採用標記
- 全部通過才原子寫入標記，內容是提案檔位元組的 sha256，與 orchestrator_agent.read_subscription 的比對一致
- 輸出只有路徑與原因，不含檔案內容
"""
import hashlib
import importlib.util
import json
import os
import subprocess
from types import SimpleNamespace

import pytest

from agents import orchestrator_agent as oa
from tools import orchestration as o
from tools.common import SENTINEL_ROOT

spec = importlib.util.spec_from_file_location("orchestrator_guard", SENTINEL_ROOT / "scripts" / "orchestrator-guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

MODES = ("dispatch", "review")
CONTENT_MARK = "CONTENT-MARKER-DO-NOT-PRINT"


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """乾淨的 git 工作目錄：out/ 被忽略（寫在 .git/info/exclude，不產生追蹤檔），內含程式步驟寫好的檔案。
    工作目錄切到這裡（與 workflow 相同，guard 讀不到快照時以 ./out 移除標記），不碰本機的 out/。"""
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.chdir(root)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / ".git" / "info").mkdir(parents=True, exist_ok=True)
    (root / ".git" / "info" / "exclude").write_text("out/\n", encoding="utf-8")
    for mode in MODES:
        d = root / "out" / f"orchestrator-{mode}"
        (d / "internal").mkdir(parents=True)
        (d / f"{mode}-input.json").write_text(json.dumps({"mode": mode, "available": True}), encoding="utf-8")
        (d / "internal" / "context.json").write_text(json.dumps({"secret_note": CONTENT_MARK}), encoding="utf-8")
        (d / "trace.jsonl").write_text("{}\n", encoding="utf-8")
    (root / "out" / "a1").mkdir()
    (root / "out" / "a1" / "verified.json").write_text("[]", encoding="utf-8")
    (root / "out" / "intel-daily.json").write_text('{"events": []}', encoding="utf-8")
    temp = tmp_path / "runner-temp"
    temp.mkdir()
    assert _git_status(root) == ""
    return SimpleNamespace(root=root, out=root / "out", snap=temp / "snap.json")


def _git_status(root):
    return subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, check=True).stdout


def snapshot(r):
    return guard.main(["snapshot", "--out", str(r.out), "--dest", str(r.snap)])


def verify(r, mode):
    return guard.main(["verify", "--mode", mode, "--snap", str(r.snap)])


def proposal(r, mode):
    return r.out / f"orchestrator-{mode}" / f"{mode}-proposal.json"


def marker(r, mode):
    return r.out / f"orchestrator-{mode}" / f"{mode}-proposal.accepted"


def write_proposal(r, mode, data=None, raw=None):
    p = proposal(r, mode)
    p.write_bytes(raw if raw is not None else json.dumps(data if data is not None else {"extra_tasks": []}, ensure_ascii=False).encode("utf-8"))
    return p


def test_paths_match_program():
    """guard 的路徑與 orchestrator_agent 相同；PLAN_DIRS 與核准模組一致。"""
    assert guard.PLAN_DIRS == o.PLAN_DIRS and guard.MODES == o.MODES
    ctx = SimpleNamespace(out=SENTINEL_ROOT / "out")
    for mode in MODES:
        assert oa.proposal_path(ctx, mode) == ctx.out / guard.proposal_rel(mode)
        assert oa.accepted_path(ctx, mode) == ctx.out / guard.accepted_rel(mode)


@pytest.mark.parametrize("mode", MODES)
def test_pass_writes_marker_with_proposal_sha(repo, mode, capsys):
    assert snapshot(repo) == 0
    p = write_proposal(repo, mode, {"extra_tasks": [{"agent": "a5", "reason": CONTENT_MARK}], "summary": "摘要"})
    assert verify(repo, mode) == 0
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    assert marker(repo, mode).read_text(encoding="utf-8") == digest
    out = capsys.readouterr().out
    assert CONTENT_MARK not in out and "已寫入採用標記" in out
    # 程式步驟用同一個比對方式採用提案
    adopted, data, why = oa.read_subscription(SimpleNamespace(out=repo.out), mode)
    assert adopted is True and why is None and data["summary"] == "摘要"
    # 標記寫在暫存檔再替換：目錄裡沒有殘留的暫存檔
    assert sorted(x.name for x in marker(repo, mode).parent.iterdir()) == sorted(
        ["internal", f"{mode}-input.json", "trace.jsonl", f"{mode}-proposal.json", f"{mode}-proposal.accepted"])


def test_empty_object_is_a_valid_proposal(repo):
    assert snapshot(repo) == 0
    write_proposal(repo, "dispatch", raw=b"{}")
    assert verify(repo, "dispatch") == 0
    assert marker(repo, "dispatch").read_text(encoding="utf-8") == hashlib.sha256(b"{}").hexdigest()


def _add_ignored(r):
    (r.out / "a1" / "extra.json").write_text("{}", encoding="utf-8")


def _modify_ignored(r):
    (r.out / "a1" / "verified.json").write_text(f'["{CONTENT_MARK}"]', encoding="utf-8")


def _delete_internal(r):
    (r.out / "orchestrator-dispatch" / "internal" / "context.json").unlink()


def _modify_input(r):
    (r.out / "orchestrator-dispatch" / "dispatch-input.json").write_text("{}", encoding="utf-8")


def _forge_marker(r):
    marker(r, "dispatch").write_text(hashlib.sha256(proposal(r, "dispatch").read_bytes()).hexdigest(), encoding="utf-8")


def _new_dir(r):
    (r.out / "new-dir").mkdir()


def _other_mode_proposal(r):
    write_proposal(r, "review")


def _touch_trace(r):
    with (r.out / "orchestrator-dispatch" / "trace.jsonl").open("a", encoding="utf-8") as f:
        f.write("{}\n")


@pytest.mark.parametrize("mutate", [_add_ignored, _modify_ignored, _delete_internal, _modify_input, _forge_marker, _new_dir,
                                    _other_mode_proposal, _touch_trace])
def test_any_change_outside_proposal_fails(repo, mutate, capsys):
    assert snapshot(repo) == 0
    write_proposal(repo, "dispatch")
    mutate(repo)
    assert verify(repo, "dispatch") == 1
    out = capsys.readouterr().out
    assert "out/ 中提案檔以外的項目有變動" in out and CONTENT_MARK not in out
    assert not marker(repo, "dispatch").exists()                                  # 自行寫出的標記也會被移除


def test_git_staged_files_fail_but_untracked_files_do_not(repo):
    """R6.1 只檢查 git 追蹤的檔案：claude-code-action 可能在工作目錄留下未追蹤的檔案，不因此拒絕提案。"""
    assert snapshot(repo) == 0
    write_proposal(repo, "dispatch")
    (repo.root / "notes.txt").write_text(CONTENT_MARK, encoding="utf-8")         # 未追蹤的新檔案：不影響
    assert verify(repo, "dispatch") == 0 and marker(repo, "dispatch").exists()
    subprocess.run(["git", "add", "notes.txt"], cwd=repo.root, check=True)       # 追蹤檔變動：不採用，並移除標記
    assert verify(repo, "dispatch") == 1 and not marker(repo, "dispatch").exists()


@pytest.mark.parametrize("status,code", [(b" M agents/registry.py\0", 0), (b"D  CLAUDE.md\0", 0), (b"", 128)])
def test_git_tracked_changes_or_errors_fail(repo, monkeypatch, capsys, status, code):
    """追蹤檔被修改、刪除，或 git status 無法執行時都不採用（替身模擬已 commit 的 repo）。"""
    assert snapshot(repo) == 0
    write_proposal(repo, "dispatch")
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, code, stdout=status, stderr=b"")
    monkeypatch.setattr(guard.subprocess, "run", fake_run)
    assert verify(repo, "dispatch") == 1 and not marker(repo, "dispatch").exists()
    assert calls and calls[0][:2] == ["git", "status"]
    assert "git" in capsys.readouterr().out


@pytest.mark.parametrize("raw", [b"[]", b'"x"', b"null", b"{bad", b'{"a": NaN}', "﻿{}".encode("utf-8"), b"\xff\xfe{}", b""])
def test_proposal_must_be_json_object(repo, raw):
    assert snapshot(repo) == 0
    write_proposal(repo, "dispatch", raw=raw)
    assert verify(repo, "dispatch") == 1 and not marker(repo, "dispatch").exists()


def test_missing_oversized_or_non_file_proposal(repo):
    assert snapshot(repo) == 0
    assert verify(repo, "dispatch") == 1                                          # Claude 沒有寫出提案
    write_proposal(repo, "dispatch", raw=b'{"summary": "' + b"x" * guard.MAX_PROPOSAL_BYTES + b'"}')
    assert verify(repo, "dispatch") == 1
    proposal(repo, "dispatch").unlink()
    proposal(repo, "dispatch").mkdir()
    assert verify(repo, "dispatch") == 1 and not marker(repo, "dispatch").exists()


def test_snapshot_includes_ignored_files_and_stays_outside_out(repo, capsys):
    assert snapshot(repo) == 0
    data = json.loads(repo.snap.read_text(encoding="utf-8"))
    entries = data["entries"]
    assert entries["a1/verified.json"] == "file:" + hashlib.sha256(b"[]").hexdigest()
    assert entries["orchestrator-dispatch/internal"] == "dir"
    assert "orchestrator-dispatch/internal/context.json" in entries
    assert CONTENT_MARK not in repo.snap.read_text(encoding="utf-8") and CONTENT_MARK not in capsys.readouterr().out
    # 快照檔不能放在 out/ 底下（Claude 讀寫得到）
    assert guard.main(["snapshot", "--out", str(repo.out), "--dest", str(repo.out / "snap.json")]) == 2
    assert not (repo.out / "snap.json").exists()


@pytest.mark.parametrize("content", [None, "{bad", "[]", '{"available": false, "reason": "verified_missing"}', '{"available": "true"}'])
def test_snapshot_skips_when_input_unavailable(repo, content, capsys):
    """R6.1：A1 結果缺失時 orchestrator-input 寫 available=false；不記錄快照、回傳 1，workflow 跳過訂閱步驟。"""
    inp = repo.out / "orchestrator-dispatch" / "dispatch-input.json"
    if content is None:
        inp.unlink()
    else:
        inp.write_text(content, encoding="utf-8")
    assert guard.main(["snapshot", "--out", str(repo.out), "--dest", str(repo.snap), "--input", str(inp)]) == 1
    assert not repo.snap.exists() and "不執行訂閱步驟" in capsys.readouterr().out
    assert verify(repo, "dispatch") == 1                                          # 沒有快照就不可能通過


def test_snapshot_with_available_input(repo):
    inp = repo.out / "orchestrator-review" / "review-input.json"
    assert guard.main(["snapshot", "--out", str(repo.out), "--dest", str(repo.snap), "--input", str(inp)]) == 0
    write_proposal(repo, "review")
    assert verify(repo, "review") == 0


def test_verify_without_valid_snapshot_fails(repo, tmp_path):
    write_proposal(repo, "dispatch")
    _forge_marker(repo)
    assert verify(repo, "dispatch") == 1                                          # 沒有快照：不採用，也移除既有標記
    assert not marker(repo, "dispatch").exists()
    repo.snap.write_text('{"schema_version": 1, "out": 3, "entries": {}}', encoding="utf-8")
    assert verify(repo, "dispatch") == 1
    repo.snap.write_text(json.dumps({"schema_version": 1, "out": str(tmp_path / "missing"), "entries": {}}), encoding="utf-8")
    assert verify(repo, "dispatch") == 1 and not marker(repo, "dispatch").exists()


def test_symlinked_proposal_rejected(repo):
    assert snapshot(repo) == 0
    target = repo.out / "a1" / "verified.json"
    try:
        os.symlink(target, proposal(repo, "dispatch"))
    except (OSError, NotImplementedError):
        pytest.skip("這個環境不能建立符號連結")
    assert verify(repo, "dispatch") == 1 and not marker(repo, "dispatch").exists()


def test_usage_errors():
    for argv in ([], ["verify", "--mode", "other", "--snap", "x"], ["snapshot", "--out", "out"]):
        with pytest.raises(SystemExit) as exc:
            guard.main(argv)
        assert exc.value.code == 2


def test_cli_runs_as_script(repo):
    """workflow 以 python3 scripts/orchestrator-guard.py 執行：結束碼 0／1。"""
    import sys
    script = SENTINEL_ROOT / "scripts" / "orchestrator-guard.py"
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    run = lambda *a: subprocess.run([sys.executable, str(script), *a], capture_output=True, text=True, encoding="utf-8", env=env)  # noqa: E731
    assert run("snapshot", "--out", str(repo.out), "--dest", str(repo.snap)).returncode == 0
    assert run("verify", "--mode", "review", "--snap", str(repo.snap)).returncode == 1
    write_proposal(repo, "review")
    proc = run("verify", "--mode", "review", "--snap", str(repo.snap))
    assert proc.returncode == 0 and marker(repo, "review").is_file()
