"""工具面測試：權限決策 decide() 以假工具呼叫驗證拒絕（不使用真實 Token、不呼叫 API）。"""
import pytest

from registry import AGENTS, COMMON_DISALLOWED, GRAPH_TOOLS, SENTINEL_ROOT, SKILLS_DIR, Policy, decide, options_for

POLICY = Policy(agents={"secret-analyst"}, skills={"sentinel-guardrails", "remediation-playbooks"}, graph_tools=True,
                scope_assets={"internal-tool"})


def denied(res):
    return res.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


@pytest.mark.parametrize("tool,inp", [
    ("Agent", {"subagent_type": "general-purpose"}),
    ("Agent", {"subagent_type": "news-scout"}),
    ("Task", {"subagent_type": "unknown"}),
    ("Bash", {"command": "ls"}),
    ("Write", {"file_path": "x"}),
    ("Edit", {"file_path": "x"}),
    ("WebFetch", {"url": "https://example.com"}),
    ("SomeFutureTool", {}),
    ("Skill", {"skill": "daily-intel"}),
    ("mcp__github__create_issue", {}),
    ("mcp__graph__get_asset_context", {"asset_id": "order-db-prod"}),
    ("Read", {"file_path": str(SENTINEL_ROOT / "agents" / "registry.py")}),
    ("Read", {"file_path": str(SKILLS_DIR / "remediation-playbooks" / ".." / ".." / ".." / "agents" / "registry.py")}),
    ("Read", {"file_path": str(SENTINEL_ROOT / ".env")}),
    ("Read", {"file_path": "\\\\server\\share\\x"}),
    ("Read", {"file_path": str(SKILLS_DIR / "secret-triage" / "SKILL.md")}),   # 不在本次白名單
])
def test_denied(tool, inp):
    assert denied(decide(tool, inp, POLICY))


@pytest.mark.parametrize("tool,inp", [
    ("Agent", {"subagent_type": "secret-analyst"}),
    ("Skill", {"skill": "remediation-playbooks"}),
    ("Read", {"file_path": str(SKILLS_DIR / "remediation-playbooks" / "references" / "key-rotation.md")}),
    ("mcp__graph__get_asset_context", {"asset_id": "internal-tool"}),
])
def test_allowed(tool, inp):
    assert decide(tool, inp, POLICY) == {}


def test_graph_tools_denied_when_not_enabled():
    p = Policy(agents=set(), skills=set(), graph_tools=False)
    assert denied(decide(GRAPH_TOOLS[0], {"asset_id": "x"}, p))


def test_every_registered_skill_exists():
    for spec in AGENTS.values():
        for s in [*spec.skills, *(sk for sub in spec.subagents.values() for sk in sub.skills)]:
            assert (SKILLS_DIR / s / "SKILL.md").is_file(), s


def test_skills_do_not_preapprove_tools():
    for p in SKILLS_DIR.rglob("SKILL.md"):
        assert "allowed-tools" not in p.read_text(encoding="utf-8"), p


def test_options_surface():
    for name in AGENTS:
        o = options_for(name)
        assert o.tools == ["Agent", "Skill", "Read"]
        assert {"Bash", "Write", "Edit", "WebFetch", "WebSearch", "Agent(general-purpose)", "Agent(news-scout)"} <= set(COMMON_DISALLOWED)
        assert o.disallowed_tools == COMMON_DISALLOWED
        assert o.strict_mcp_config is True and o.permission_mode == "dontAsk"
        assert o.cwd == str(SENTINEL_ROOT) and o.setting_sources == ["project"]
        assert o.env["CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS"] == "1"
        assert "NOTIFY_TOKEN" not in o.env and "GH_TOKEN" not in o.env
        assert set(o.agents) == set(AGENTS[name].subagents)
        for d in o.agents.values():
            assert "Bash" not in (d.tools or []) and "Write" not in (d.tools or [])
