# WordPress 封鎖六個遭植入後門的 WP Connect 外掛
`真實` `暫定` `CVE-2026-135202`

**結論：不受影響：技術棧中沒有 air wp sync – airtable to wordpress（資產清單完整且新鮮）。**

## 事件摘要
WP Connect 開發者帳號疑似遭入侵，六個外掛於11月22日被植入可執行任意程式碼的後門，含 Orders Sync to Airtable for WooCommerce。惡意版本因 WordPress 冷卻機制未實際釋出，網站不太可能受影響，但仍應檢查是否安裝。

## 不受影響與需確認
- 技術棧中沒有 air wp sync – airtable to wordpress（資產清單完整且新鮮）
- 技術棧中沒有 wp sync for notion – notion to wordpress（資產清單完整且新鮮）
- 技術棧中沒有 add-on brevo for gravity forms（資產清單完整且新鮮）
- 技術棧中沒有 add-on for contact form 7 to airtable（資產清單完整且新鮮）
- 技術棧中沒有 add-on for contact form 7 to notion（資產清單完整且新鮮）
- 技術棧中沒有 orders sync to airtable for woocommerce（資產清單完整且新鮮）

## 處理狀態
不受影響

## 來源
- WordPress Blocks Six Backdoored WP Connect Plugins Before Malicious Releases Go Live：https://thehackernews.com/2026/11/wordpress-blocks-six-backdoored-wp.html
