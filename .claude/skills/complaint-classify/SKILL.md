---
name: complaint-classify
description: 判斷客訴是否為疑似外洩詐騙
---

# 客訴分類
- 疑似外洩詐騙：對方知道真實訂單資訊，或冒充客服要求轉帳。
- 一般客訴：商品、物流、退貨、優惠券。
- 只依去敏摘要判斷。

輸出：`[{"id", "explanation", "confidence"}]`
