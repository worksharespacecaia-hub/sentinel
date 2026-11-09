---
name: advisory-extract
description: 從公告文字抽取產品、版本範圍與修補版本，附原文引用
---

# 公告抽取
- 抽取產品、受影響版本範圍、修補版本、是否已確認遭利用。
- 每項附來源原文語言的逐字引用；原文沒有的欄位填 null。
- 來源分級：廠商官方 > GitHub Advisory > 資安媒體 > 社群。

輸出：`[{"id", "products": [{"name", "affected", "fixed"}], "quote"}]`
