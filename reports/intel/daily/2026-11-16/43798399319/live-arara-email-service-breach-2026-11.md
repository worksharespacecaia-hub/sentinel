# 日本 Arara 郵件發送服務遭駭，大阪市逾 100 萬電子郵件地址外洩
`真實` `暫定`

**結論：無法自動判定：事件沒有可比對的產品、CVE 或控制項，程式沒有比對任何資產，需要人工確認。**

## 事件摘要
大阪市通報，TKC 使用的 Arara 郵件發送服務遭駭，逾 100 萬個電子郵件地址外洩。Arara 稱 11 月 2 日的攻擊曝露近 400 家客戶共 7,700 萬個電子郵件地址，駭客並利用該服務寄出冒充信用卡公司與金融機構的惡意郵件。

## 不受影響與需確認
- 需確認：*：人工判斷事件的攻擊手法是否適用於我們的系統；把事件對應到 controls.yaml 的控制項；沒有合適的就建議新增
  - （推測）第三方寄信服務遭入侵後被用來寄出假冒通知信；查：確認寄信服務金鑰是否有 IP 白名單與輪替紀錄，並查寄信服務近期是否有異常大量寄出或未知收件人；系統：寄信服務、寄信服務金鑰

## 處理狀態
需確認

## 來源
- City of Osaka warns of data breach impacting 1 million as Japan reels from dozens of cyber incidents：https://therecord.media/city-of-osaka-japan-email-data-breach
