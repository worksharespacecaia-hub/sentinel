---
name: attack-mapping
description: 把事件描述對應到 MITRE ATT&CK 技術 ID
---

# ATT&CK 對應
- 只對應來源中明確描述的行為，填技術 ID（例如 T1190、T1078）。
- 無法判斷就留空，不推測。

輸出：`{"attck": ["T...."], "confidence": "high|low"}`
