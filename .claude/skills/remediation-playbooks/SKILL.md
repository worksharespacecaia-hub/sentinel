---
name: remediation-playbooks
description: 建議解法劇本索引；只讀命中的那一份，只寫建議方向與驗證方式
---

# 建議解法劇本
依風險類型只讀一份 `references/`：key-rotation、internal-tool-exposure、php2shell、nas-ransomware、identity-token、takedown-decision、mobile-sdk、incident-containment。

規則：
- 只寫建議方向、建議負責團隊、建議期限與驗證方式，由工程團隊決定是否執行。
- 沒有修補版本時，提供「修補／緩解／暫時下架」三個選項與影響，交給 CEO 決策。

輸出：`[{"risk_id", "temporary", "permanent", "options": [{"name", "action", "cost", "timing"}], "suggested_owner", "verify"}]`
