"""App 設定的規則檢查（AndroidManifest、build.gradle、config、Firebase、商店搜尋）。只做靜態規則，不打包 App。"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
# Demo 政策表：商店要求的最低 targetSdkVersion（正式導入時改讀版本化政策檔）
STORE_TARGET_SDK_POLICY = {"effective": "2025-08-31", "min_target_sdk": 35, "store": "google_play"}
CLONE_ICON_THRESHOLD = 0.85
CLONE_NAME_THRESHOLD = 0.8


def check_manifest(xml_text: str | None) -> list[dict]:
    if not xml_text:
        return []
    root = ET.fromstring(xml_text)
    app = root.find("application")
    issues = []
    if app is None:
        return issues
    if app.get(f"{ANDROID_NS}debuggable") == "true":
        issues.append({"rule": "android-debuggable", "title": "正式版 App 開啟 debuggable", "evidence": "AndroidManifest.xml: android:debuggable=\"true\""})
    if app.get(f"{ANDROID_NS}usesCleartextTraffic") == "true":
        issues.append({"rule": "android-cleartext", "title": "App 允許明文傳輸", "evidence": "AndroidManifest.xml: android:usesCleartextTraffic=\"true\""})
    exported = []
    for tag in ("activity", "receiver", "service", "provider"):
        for comp in app.findall(tag):
            if comp.get(f"{ANDROID_NS}exported") != "true" or comp.get(f"{ANDROID_NS}permission"):
                continue
            is_launcher = any(c.get(f"{ANDROID_NS}name") == "android.intent.category.LAUNCHER"
                              for f in comp.findall("intent-filter") for c in f.findall("category"))
            if not is_launcher:
                exported.append(f"{tag} {comp.get(f'{ANDROID_NS}name')}")
    if exported:
        issues.append({"rule": "android-exported-component", "title": "對外開放且無權限保護的元件",
                       "evidence": "AndroidManifest.xml: " + "、".join(exported)})
    return issues


def check_gradle(gradle_text: str | None) -> list[dict]:
    if not gradle_text:
        return []
    m = re.search(r"targetSdkVersion\s+(\d+)", gradle_text)
    if not m:
        return []
    target = int(m.group(1))
    if target < STORE_TARGET_SDK_POLICY["min_target_sdk"]:
        return [{"rule": "target-sdk-outdated", "title": f"targetSdkVersion {target} 低於商店要求",
                 "evidence": f"build.gradle: targetSdkVersion {target}（政策 {STORE_TARGET_SDK_POLICY['effective']} 起最低 "
                             f"{STORE_TARGET_SDK_POLICY['min_target_sdk']}）"}]
    return []


def app_package_sdks(package_json: dict | None) -> dict[str, str]:
    deps = (package_json or {}).get("dependencies") or {}
    return {k: v.lstrip("^~=") for k, v in deps.items() if k not in ("react", "react-native")}


def detect_clone_apps(store_scan: dict | None, official_developer: str, brand_names: dict[str, str]) -> list[dict]:
    clones = []
    for r in (store_scan or {}).get("results", []):
        if r.get("developer") == official_developer:
            continue
        brand = next((bid for bid, name in brand_names.items() if name.split("（")[0] in r.get("app_name", "")), None)
        if brand and (r.get("icon_similarity", 0) >= CLONE_ICON_THRESHOLD or r.get("name_similarity", 0) >= CLONE_NAME_THRESHOLD):
            clones.append({"brand_id": brand, "store": r["store"], "app_name": r["app_name"], "developer": r["developer"],
                           "package": r.get("package"), "icon_similarity": r.get("icon_similarity"),
                           "name_similarity": r.get("name_similarity"), "first_seen": r.get("first_seen")})
    return clones


def affected_installations(rows: list[dict], is_affected) -> dict:
    """逐品牌、逐 App 版本加總 active_installations；受影響品牌數以 distinct brand_id 計算，不相乘。

    每列以 (brand_id, platform, app_version, observed_at) 唯一，重複列只計一次；不提供「不重複使用者」。
    """
    seen = set()
    total = affected = 0
    brands = set()
    per_brand: dict[str, int] = {}
    for row in rows:
        key = (row["brand_id"], row["platform"], row["app_version"], row.get("observed_at"))
        if key in seen:
            continue
        seen.add(key)
        n = int(row.get("active_installations") or 0)
        total += n
        if is_affected(row):
            affected += n
            if n > 0:
                brands.add(row["brand_id"])
                per_brand[row["brand_id"]] = per_brand.get(row["brand_id"], 0) + n
    latest = max((r["app_version"] for r in rows), default=None, key=lambda v: tuple(int(x) for x in v.split(".")))
    old = sum(int(r.get("active_installations") or 0) for r in {(r["brand_id"], r["platform"], r["app_version"], r.get("observed_at")): r for r in rows}.values()
              if r["app_version"] != latest)
    return {"affected_installations": affected, "total_installations": total, "affected_brands": len(brands),
            "per_brand": per_brand, "latest_version": latest,
            "old_version_share": round(old / total, 3) if total else None,
            "note": "安裝數為逐品牌、逐版本加總；沒有跨平台去重依據，不代表不重複使用者"}
