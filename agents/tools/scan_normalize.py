"""把掃描工具的原始輸出轉成已遮蔽的正規化格式（與 fixtures/scanners 相同），並附 manifest。

工具「發現弱點」與「工具本身失敗」分開：原始輸出缺失或無法解析 → status=failed，不轉成零發現。
用法：python agents/tools/scan_normalize.py <gitleaks|trivy|checkov|kev|nvd> <raw-dir> <out-dir> --target-sha SHA --run-id ID
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.common import iso, sha256_file, write_json  # noqa: E402

KEEP_GITLEAKS = ["RuleID", "Description", "File", "StartLine", "EndLine", "Commit", "Date", "Fingerprint"]


def norm_gitleaks(raw_dir: Path) -> dict:
    data = json.loads((raw_dir / "gitleaks.json").read_text(encoding="utf-8") or "[]")
    return {"tool": "gitleaks", "redacted": True,
            "findings": [{k: f.get(k) for k in KEEP_GITLEAKS} | {"Secret": "REDACTED", "Match": "REDACTED"} for f in data]}


def norm_trivy(raw_dir: Path) -> dict:
    results = []
    for p in sorted(raw_dir.glob("trivy-*.json")):
        if p.name == "trivy-version.json":
            continue
        raw = json.loads(p.read_text(encoding="utf-8") or "{}")
        vulns = []
        for r in raw.get("Results") or []:
            for v in r.get("Vulnerabilities") or []:
                cv = max([float(x.get("V3Score") or 0) for x in (v.get("CVSS") or {}).values()] or [0])
                vulns.append({"VulnerabilityID": v["VulnerabilityID"], "PkgName": v["PkgName"],
                              "InstalledVersion": v["InstalledVersion"], "FixedVersion": v.get("FixedVersion"),
                              "Severity": v.get("Severity"), "CVSSv3": cv or None, "Title": (v.get("Title") or "")[:160],
                              "Target": r.get("Target")})
        results.append({"tool": "trivy", "target": f"services/{p.stem.removeprefix('trivy-')}", "vulnerabilities": vulns})
    if not results:
        raise FileNotFoundError("沒有 trivy 結果")
    ver = json.loads((raw_dir / "trivy-version.json").read_text(encoding="utf-8")) if (raw_dir / "trivy-version.json").is_file() else {}
    return {"tool_version": ver.get("Version"), "database_revision": (ver.get("VulnerabilityDB") or {}).get("UpdatedAt"),
            "results": results}


def norm_checkov(raw_dir: Path) -> dict:
    raw = json.loads((raw_dir / "checkov.json").read_text(encoding="utf-8") or "{}")
    reports = raw if isinstance(raw, list) else [raw]
    failed = [{"check_id": c.get("check_id"), "resource": c.get("resource"), "file": c.get("file_path"),
               "check_name": c.get("check_name")} for r in reports for c in (r.get("results") or {}).get("failed_checks", [])]
    return {"tool": "checkov", "failed_checks": failed}


def norm_kev(raw_dir: Path) -> dict:
    from tools.vulndb import normalize_kev
    return normalize_kev(json.loads((raw_dir / "kev.json").read_text(encoding="utf-8")))


def norm_nvd(raw_dir: Path) -> dict:
    """vulndb.py 已只保留比對需要的欄位；這裡再確認格式，全部查詢失敗時視為工具失敗（不轉成零發現）。"""
    raw = json.loads((raw_dir / "nvd.json").read_text(encoding="utf-8"))
    results = raw.get("results")
    if not isinstance(results, list):
        raise ValueError("nvd.json 缺少 results")
    keep = ("name", "version", "ecosystem", "templates", "asset_ids", "status", "queries", "cves")
    results = [{k: r.get(k) for k in keep} for r in results if isinstance(r, dict) and r.get("name")]
    if not results and not raw.get("uncovered"):
        raise ValueError("nvd.json 沒有任何元件（資產清單可能缺失），不轉成零發現")
    if results and not any(r["status"] == "ok" for r in results):
        raise RuntimeError("NVD 查詢全部失敗")
    return {"tool": "nvd", "tool_version": "NVD CVE API 2.0", "database_revision": raw.get("queried_at"),
            "api_key": bool(raw.get("api_key")), "results": results, "uncovered": raw.get("uncovered") or []}


NORMALIZERS = {"gitleaks": norm_gitleaks, "trivy": norm_trivy, "checkov": norm_checkov, "kev": norm_kev, "nvd": norm_nvd}
# kev／nvd 是輔助資料：失敗時報告註明涵蓋不足，但不影響 gitleaks／trivy／checkov 的沿用與完整性判斷
OPTIONAL_TOOLS = ("kev", "nvd")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("tool", choices=sorted(NORMALIZERS))
    ap.add_argument("raw_dir", type=Path)
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("--target-sha", required=True)
    ap.add_argument("--run-id", required=True)
    a = ap.parse_args(argv)
    now = datetime.now(timezone.utc)
    manifest = {"schema_version": 1, "run_id": a.run_id, "job": f"scanners-{a.tool}", "scope": "scanner",
                "target_sha": a.target_sha, "observed_at": iso(now), "valid_until": iso(now + timedelta(hours=24)),
                "tool_version": {}, "database_revision": {}, "files": {}}
    try:
        data = NORMALIZERS[a.tool](a.raw_dir)
        out = a.out_dir / f"{a.tool}.json"
        write_json(out, data)
        if "DEMO-FAKE-" in out.read_text(encoding="utf-8"):
            out.unlink()
            raise ValueError("正規化結果仍含金鑰值，拒絕輸出")
        manifest.update(status="ok", files={out.name: sha256_file(out)},
                        tool_version={a.tool: data.get("tool_version")}, database_revision={a.tool: data.get("database_revision")})
        code = 0
    except Exception as exc:
        manifest.update(status="failed", reason=f"{type(exc).__name__}: {exc}"[:300])
        code = 1
    write_json(a.out_dir / f"{a.tool}.manifest.json", manifest)
    print(json.dumps({"tool": a.tool, "status": manifest["status"]}))
    return code


if __name__ == "__main__":
    sys.exit(main())
