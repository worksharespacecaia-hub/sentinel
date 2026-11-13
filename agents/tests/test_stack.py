"""stack.json 的系統清單 assets（specs/check-hints-ai R1、R7.3）：鍵與值都採白名單，AI 只看得到可以給它的系統。"""
import json
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx
import pytest

from tools import stack
from tools.digest import ASSET_LABELS_FILE, load_asset_label_file
from tools.stack import ALLOWED_TYPES, ai_assets, build_stack

FX_GRAPH = Path(__file__).parent / "fixtures" / "check-hints" / "graph.json"
AS_OF = datetime(2026, 11, 13, tzinfo=timezone.utc)
KEYS = {"id", "label", "type", "data_classes", "exposed", "management_interface", "crown_jewel", "env"}
TOKEN = "ghp_" + "a1b2c3d4e5" * 3 + "f6g7h8"                      # 假 token（不是真實金鑰）


@pytest.fixture(scope="module")
def fx_graph():
    return json.loads(FX_GRAPH.read_text(encoding="utf-8"))


def one(node: dict, label=None):
    """單一節點的匯出結果；沒有匯出時為 None。"""
    nid = node["id"]
    got = ai_assets({"nodes": [node]}, {nid: label} if label is not None else None)
    return got[0] if got else None


# ── 不含機敏欄位、不列 zone／app_version／sdk ───────────────────────

def test_assets_only_whitelisted_keys():
    node = {"id": "order-db-prod", "type": "datastore", "env": "prod", "data_classes": ["order", "pii"],
            "exposed_to_internet": False, "management_interface": False, "crown_jewel": True,
            "stored_in": "vault://order-db", "fingerprint": "SHA256:abcdef", "credential": "order-db-prod-cred",
            "ip": "10.0.0.5", "port": 5432, "owner": "某工程師", "components": [{"name": "mysql", "version": "8.0"}],
            "scope": ["read"], "display_name": "Order DB"}
    a = one(node, "正式訂單資料庫")
    assert a == {"id": "order-db-prod", "label": "正式訂單資料庫", "type": "datastore", "data_classes": ["order", "pii"],
                 "exposed": False, "management_interface": False, "crown_jewel": True, "env": "prod"}
    blob = json.dumps(a, ensure_ascii=False)
    for leaked in ("stored_in", "fingerprint", "vault://", "SHA256", "10.0.0.5", "5432", "某工程師", "mysql", "scope"):
        assert leaked not in blob


def test_assets_from_real_graph_have_no_secret_values(baseline):
    """A0 實際的 networkx 圖：stored_in、fingerprint 等屬性的值都不會出現在 assets。"""
    from agents.a0_assets import _stack_labels
    g = baseline["graph"]
    secret_values = {str(v) for _, n in g.nodes(data=True) for k, v in n.items()
                     if k in ("stored_in", "fingerprint", "credential", "ip_allowlist", "owner") and v}
    assert secret_values                                                 # 圖中確實有這些屬性（測試才有意義）
    st = build_stack(g, as_of=AS_OF, labels=_stack_labels(g))
    assert st["assets"] and all(set(a) == KEYS for a in st["assets"])
    blob = json.dumps(st["assets"], ensure_ascii=False)
    assert "stored_in" not in blob and "fingerprint" not in blob
    ids = [a["id"] for a in st["assets"]]
    checked = [v for v in secret_values if len(v) > 3 and not any(v in i for i in ids)]   # 是某個系統 ID 一部分的值（如 eng-03）不算
    assert checked and not any(v in blob for v in checked)
    types = {n.get("type") for _, n in g.nodes(data=True)}
    assert {a["type"] for a in st["assets"]} <= ALLOWED_TYPES and types - ALLOWED_TYPES


def test_assets_exclude_zone_app_version_sdk(fx_graph):
    ids = {a["id"] for a in ai_assets(fx_graph, None)}
    excluded = [n["id"] for n in fx_graph["nodes"] if n["type"] in ("zone", "app_version", "sdk")]
    assert set(excluded) == {"internet", "corp-vpn", "brand-app@2.9.1", "brand-app@3.1.0", "brand-app@3.2.0",
                             "brand-app@3.4.0", "@demo-vendor/push-sdk@1.9.2", "@demo-vendor/push-sdk@2.2.0",
                             "@demo-vendor/push-sdk@2.3.1"}
    assert not ids & set(excluded)
    for t in ("zone", "app_version", "sdk", "identity"):
        assert one({"id": "x-node", "type": t}) is None


# ── 污染測試：id、type、env、data_classes、label（R1.2a） ─────────────────

@pytest.mark.parametrize("nid", [
    "192.0.2.1", "::1", "::", "2001:db8::5", "db192.0.2.1", "10.0.0.8", "host-10.0.0.8", "web-01:8080", "web:80",
    "srv/path", "c:/ops", "c:\\ops", "a\\b", TOKEN, "Storefront", "-leading-dash", "有中文", "has space", "x" * 82,
    "storefront\n", "",
])
def test_polluted_id_excludes_whole_asset(nid):
    assert one({"id": nid, "type": "service", "env": "prod"}) is None


def test_polluted_id_db_ip_prefix_excluded():
    """db192.0.2.1：前面黏字母的 IPv4 也要被 IPV4_RE 抓到，整個資產不列入。"""
    assert stack.ASSET_ID_RE.fullmatch("db192.0.2.1") and not stack._safe("db192.0.2.1")
    assert ai_assets({"nodes": [{"id": "db192.0.2.1", "type": "datastore"}, {"id": "ok-db", "type": "datastore"}]},
                     None) == [{"id": "ok-db", "label": None, "type": "datastore", "data_classes": [], "exposed": False,
                                "management_interface": False, "crown_jewel": False, "env": None}]


@pytest.mark.parametrize("ntype", ["192.0.2.1", "service:8080", "/srv", "unknown", "SERVICE", "", None, 3, ["service"]])
def test_polluted_type_excludes_asset(ntype):
    assert one({"id": "x-node", "type": ntype}) is None


@pytest.mark.parametrize("env", ["192.0.2.1", "::1", "prod:8080", "/etc/prod", "c:\\prod", TOKEN, "PROD", "dev",
                                 "production", "", None, 1, ["prod"]])
def test_polluted_env_becomes_null(env):
    assert one({"id": "x-node", "type": "service", "env": env})["env"] is None


@pytest.mark.parametrize("env", sorted(stack.ALLOWED_ENV))
def test_allowed_env_kept(env):
    assert one({"id": "x-node", "type": "service", "env": env})["env"] == env


def test_polluted_data_classes_removed():
    dc = ["pii", "secret", "192.0.2.1", "::1", "/srv/data", "c:\\x", "pii:8080", TOKEN, "PII", "", None, 3, ["pii"],
          "session", "credential", "pii"]
    assert one({"id": "x-node", "type": "datastore", "data_classes": dc})["data_classes"] == ["credential", "pii", "session"]
    for bad in (None, "pii", {"pii": True}, 3):                          # 不是陣列 → 空陣列
        assert one({"id": "x-node", "type": "datastore", "data_classes": bad})["data_classes"] == []


@pytest.mark.parametrize("label", [
    "192.0.2.1", "::1", "::", "2001:db8::5", "本機服務 ::1", "伺服器 192.0.2.1", "位址2001:db8::5的主機",
    "主機 10.0.0.8:9 管理", "管理介面 :8443", "放在 /etc/app", "C:\\ops 資料夾", "D:/backup", "反斜線 a\\b",
    f"金鑰 {TOKEN}", "聯絡 someone@example.com", "含系統代號 x-node 的名稱", "", 123,
])
def test_polluted_label_becomes_null(label):
    a = one({"id": "x-node", "type": "service"}, label)
    assert a is not None and a["label"] is None


def test_ip_detection_cases():
    for s in ("192.0.2.1", "::1", "::", "2001:db8::5", "本機服務 ::1", "db192.0.2.1", "主機 10.0.0.8:9 管理", "x(192.0.2.1)"):
        assert not stack._safe(s), s
    for s in ("品牌 App 3.1.0 版", "App 推播套件 2.3.1 版", "API 閘道", "公司 VPN", "第 2 步", "QuickSite Builder", "a.b.c"):
        assert stack._safe(s), s


def test_bool_fields_only_true_is_true():
    for v in (True, "true", 1, None, "yes"):
        a = one({"id": "x-node", "type": "service", "exposed_to_internet": v, "management_interface": v, "crown_jewel": v})
        assert (a["exposed"], a["management_interface"], a["crown_jewel"]) == ((v is True,) * 3)


# ── 保留測試：既有 ID、名稱、display_name、session 類別 ────────────────

def test_frozen_graph_ids_all_kept(fx_graph):
    expected = sorted(n["id"] for n in fx_graph["nodes"] if n["type"] in ALLOWED_TYPES)
    assert len(expected) == 36
    got = ai_assets(fx_graph, None)
    assert [a["id"] for a in got] == expected and all(a["label"] is None for a in got)
    by = {a["id"]: a for a in got}
    assert by["cache-redis"]["data_classes"] == ["session"]
    node = {n["id"]: n for n in fx_graph["nodes"]}
    for aid, a in by.items():                                            # 白名單內的值原樣保留
        assert a["type"] == node[aid]["type"]
        assert a["env"] == node[aid]["env"]
        assert a["data_classes"] == sorted(set(node[aid]["data_classes"] or []))


def test_asset_label_file_names_all_kept(fx_graph):
    raw = json.loads(ASSET_LABELS_FILE.read_text(encoding="utf-8"))["labels"]
    labels, issues = load_asset_label_file()
    assert not issues and labels == raw                                 # 對照檔的名稱沒有任何一筆被 _label_text 擋下
    by = {a["id"]: a for a in ai_assets(fx_graph, labels)}
    for aid, a in by.items():
        assert a["label"] == raw[aid], aid                              # 凍結 graph 中的資產：名稱原樣保留
    for aid, name in raw.items():                                       # 每個名稱本身都通過值驗證
        assert one({"id": "x-node", "type": "service"}, name)["label"] == name, aid


def test_display_name_kept_and_file_labels_first(fx_graph):
    assert one({"id": "saas-quicksite-builder", "type": "saas"}, "QuickSite Builder")["label"] == "QuickSite Builder"
    from agents.a0_assets import _stack_labels
    g = nx.MultiDiGraph()
    g.add_node("saas-quicksite-builder", type="saas", display_name="QuickSite Builder")
    g.add_node("new-saas", type="saas", display_name="QuickSite Builder")
    g.add_node("bad-name", type="saas", display_name="主機 10.0.0.8:9 管理")
    g.add_node("id-name", type="saas", display_name="id-name 服務")
    labels = _stack_labels(g)
    assert labels["saas-quicksite-builder"] == "未登記的架站服務"           # 對照檔優先
    assert labels["new-saas"] == "QuickSite Builder" and "id-name" not in labels
    by = {a["id"]: a for a in build_stack(g, as_of=AS_OF, labels=labels)["assets"]}
    assert by["new-saas"]["label"] == "QuickSite Builder"
    assert by["bad-name"]["label"] is None and by["id-name"]["label"] is None


# ── build_stack ────────────────────────────────────────────────────

def test_build_stack_products_unchanged_and_assets_added():
    g = nx.MultiDiGraph()
    g.add_node("storefront", type="service", env="prod", exposed_to_internet=True, owner="team-web",
               components=[{"name": "next", "version": "15.0.0", "ecosystem": "npm"}])
    g.add_node("internet", type="zone")
    plain = build_stack(g, as_of=AS_OF)
    labeled = build_stack(g, as_of=AS_OF, labels={"storefront": "商店網站"})
    assert set(plain) == {"generated_at", "note", "products", "assets"} and "assets 為系統清單" in plain["note"]
    assert plain["products"] == labeled["products"] == [
        {"product": "next", "version": "15.0.0", "assets": ["storefront"], "exposed": True, "owners": ["team-web"],
         "qualifiers": {"ecosystem": "npm"}}]
    assert [a["label"] for a in plain["assets"]] == [None] and [a["label"] for a in labeled["assets"]] == ["商店網站"]
    assert [a["id"] for a in plain["assets"]] == ["storefront"]
