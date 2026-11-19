# 日本行銷平台 PLAID KARTE 遭駭，JINS、DHC、思夢樂等零售與消費品牌會員個資外洩
`真實` `已確認`

**結論：1 項受影響，最高風險為中。mail-api-key：secrets.json: mail-api-key：466 天未輪替、無 IP 白名單。**

## 事件摘要
寄信服務金鑰（mail-api-key）466 天未輪替且無 IP 白名單，與此事件相符，程式判定為中風險（6 分）；建議換發金鑰並加上白名單。

## 受影響項目
| 資產 | 我們的狀況 | 比對依據 | 結論 | 風險 |
|------|----------|---------|------|------|
| mail-api-key | secrets.json: mail-api-key：466 天未輪替、無 IP 白名單 | control | 受影響 | 中（6 分） |

## 可能的解法：mail-api-key:C-THIRD-PARTY-KEY-ROTATION
| 選項 | 做法 | 代價 | 時效 |
|------|------|------|------|
| 緩解 | 撤銷並輪替金鑰 | 使用該金鑰的服務需同步更新 | 今天 |
建議負責團隊：security-team；驗證方式：工程團隊修正後，下次完整掃描不再命中才標示已修復

## 處理狀態
待處理

## 來源
- JINS、三菱UFJ銀行等數十家日本企業陸續發布資安事件公告，皆因第三方行銷科技業者PLAID旗下KARTE平臺遭駭：https://www.ithome.com.tw/news/180640
- 日本 DHC 爆 1,911 萬筆個資外洩，JINS、思夢樂也遭殃：https://infosecu.technews.tw/2026/11/19/japanese-dhc-data-breach-19-11-million-jins-shimamura-affected/
