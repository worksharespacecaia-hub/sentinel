---
name: device-fingerprint
description: 依回應特徵辨識對帳不上的設備產品與版本
---

# 設備辨識
- 依 `references/fingerprints.md` 比對廠商與標題特徵。
- 版本只取特徵中明確出現的字串，沒有就填 null。

輸出：`[{"id", "explanation", "confidence"}]`
