# 動態派工建議（由 scripts/build-agent-plan-reference.py 依 agents/tools/agent_plan.py 產生，請勿手改）

`intel-daily.json` 頂層的 `agent_plan` 是給程式核准的**建議**：只能追加工作，不能要求跳過、停用或改變任何評估、分數與結論。
程式會逐項檢查，不合規則的建議會被拒絕並記錄原因。

## 格式

```json
{"extra_controls": [{"event_id": "事件 ID", "control_id": "C-...", "reason": "1 句理由"}],
 "extra_tasks": [{"agent": "a4", "subagent": "impact-analyst", "event_id": "事件 ID", "reason": "1 句理由"}]}
```

- 沒有建議時寫 `{}`；兩個陣列都可以省略
- `event_id`：本次 `events` 裡事件的 `id`（非空、唯一）；不要對 `seen.json` 的已知事件提出建議（新進度用自己的新 ID 可以）
- `extra_controls`：只放「值得一併確認」的控制項，ID 必須在 `references/controls.md`；事件能直接對應的控制項照舊寫在事件的 `controls`，兩者不要重複
- 只允許上面列出的欄位；多寫的欄位會讓整項建議被拒絕

## 上限

- 每件事件最多 3 個加查控制項，總共最多 8 個
- 追加工作總共最多 3 項
- 只處理日期最新的 5 件新同業事件
- 每項理由 1 句，最多 120 字

## 可追加的工作

| agent | subagent | 用途 |
|---|---|---|
| a4 | impact-analyst | 說明與此事件相關的風險影響（由程式挑選風險） |
