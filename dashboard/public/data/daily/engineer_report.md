# 工程師報告（daily，2026-11-13T05:06:21Z）

燈號：red；20 個未處理的高風險

| 等級 | 分數 | 風險 | 資產 | 期限 | 證據 |
|---|---:|---|---|---|---|
| high | 11 | opsbuilder 1.88：OpsBuilder 1.90 以前版本的帳號接管漏洞（虛構產品） | internal-tool | 24h | adv-opsbuilder-2026-001：[{'introduced': '0', 'fixed': '1.90'}]；我們的狀況：opsbuilder 1.88，對外 |
| high | 10 | Git 中不得有正式環境金鑰：brand-app | brand-app | 24h | services/brand-app/src/config.ts:3 |
| high | 10 | node 22.11.0 有 17 個已知漏洞（NVD，最高 CVSS 9.8，CVE-2026-111497） | storefront | 24h | nvd: node@22.11.0 依 CPE 取得候選後，本地重新比對版本（17 確定、1 需確認）；修補版本：無法確定（部分漏洞沒有修補版本或範圍不明） |
| high | 9 | php 8.1.27 有 27 個已知漏洞（NVD，最高 CVSS 9.8，CVE-2024-11236） | marketing-site | 24h | nvd: php@8.1.27 依 CPE 取得候選後，本地重新比對版本（27 確定、3 需確認）；修補版本：8.2.35 |
| high | 8 | Git 中不得有正式環境金鑰：gitlab | gitlab | 24h | config/db.yml:4 |
| high | 8 | 內部工具不得對外開放：internal-tool | internal-tool | 24h | network.json: internet → internal-tool:443 |
| high | 8 | node 22.11.0 有 17 個已知漏洞（NVD，最高 CVSS 9.8，CVE-2026-111497） | internal-tool | 24h | nvd: node@22.11.0 依 CPE 取得候選後，本地重新比對版本（17 確定、1 需確認）；修補版本：無法確定（部分漏洞沒有修補版本或範圍不明） |
| high | 8 | apache-httpd 2.4.57 有 68 個已知漏洞（NVD，最高 CVSS 9.8，CVE-2024-38474） | marketing-site | 24h | nvd: apache-httpd@2.4.57 依 CPE 取得候選後，本地重新比對版本（68 確定、2 需確認）；修補版本：無法確定（部分漏洞沒有修補版本或範圍不明） |
| high | 8 | node 22.11.0 有 17 個已知漏洞（NVD，最高 CVSS 9.8，CVE-2026-111497） | member-api | 24h | nvd: node@22.11.0 依 CPE 取得候選後，本地重新比對版本（17 確定、1 需確認）；修補版本：無法確定（部分漏洞沒有修補版本或範圍不明） |
| high | 8 | synology-dsm 7.2.1-69057 Update 5 有 5 個已知漏洞（NVD，最高 CVSS 9.8，CVE-2024-10441） | nas-office-01 | 24h | nvd: synology-dsm@7.2.1-69057 Update 5 依 CPE 取得候選後，本地重新比對版本（5 確定、0 需確認）；修補版本：7.2.1-69057-7 |
| high | 8 | next 14.1.0 有 36 個已知漏洞（最高 CVSS 9.1，CVE-2025-29927） | storefront | 24h | trivy: services/storefront next@14.1.0；修補版本：13.5.9, 14.2.25, 15.2.3, 12.3.5 |
| high | 7 | nginx 1.27.2 有 16 個已知漏洞（NVD，最高 CVSS 9.2，CVE-2026-42055） | api-gateway | 24h | nvd: nginx@1.27.2 依 CPE 取得候選後，本地重新比對版本（16 確定、0 需確認）；修補版本：無法確定（部分漏洞沒有修補版本或範圍不明） |
| high | 7 | 雲端儲存空間不得公開讀取：firebase-brand-app-storage | firebase-brand-app-storage | 24h | firebase-config.json: /user-uploads/{allPaths=**} read if true；external-scan.json: storage.shopsaas-demo.example 可匿名列出內容 |
| high | 7 | 員工電腦不得持有正式部署權杖：laptop-eng-07 | laptop-eng-07 | 24h | mdm.json: laptop-eng-07 有 ~/.config/pipeline/token；secrets.json: deploy-token-eng07 → deploy-pipeline |
| high | 7 | 雲端儲存空間不得公開讀取：order-exports-bucket | order-exports-bucket | 24h | external-scan.json: shopsaas-demo-order-exports.s3.example 可匿名列出內容；infra/terraform/main.tf: aws_s3_bucket_acl acl = "public-read" |
| high | 7 | postcss 8.4.31 有 4 個已知漏洞（最高 CVSS 9.1，CVE-2026-45623） | storefront | 24h | trivy: services/storefront postcss@8.4.31；修補版本：8.5.12 |
| high | 4 | 未登記的資產：internal-tool | internal-tool | 24h | 對帳：清冊無、部署紀錄無、實際觀察有（external-scan, runtime） |
| high | 4 | 未登記的資產：marketing-site | marketing-site | 24h | 對帳：清冊無、部署紀錄無、實際觀察有（external-scan, runtime） |
| high | 4 | 未登記的資產：nas-office-01 | nas-office-01 | 24h | 對帳：未出現在任何清冊，但在 external-scan, lan-scan 被觀察到 |
| high | 2 | 未登記的資產：QuickSite Builder | saas-quicksite-builder | 24h | 對帳：QuickSite Builder 出現在 payments, sso，但不在第三方清冊 |
| medium | 6 | 影子 API：GET /internal/v1/members/export（7 天 95 次） | api-gateway | 168h | api-inventory.json: Gateway 實際流量中有，但未列在 OpenAPI 規格 |
| medium | 6 | 正式版 App 開啟 debuggable | brand-app | 168h | AndroidManifest.xml: android:debuggable="true" |
| medium | 6 | 第三方服務金鑰 90 天內輪替且有 IP 白名單：mail-api-key | mail-api-key | 168h | secrets.json: mail-api-key：460 天未輪替、無 IP 白名單 |
| medium | 6 | wordpress 6.4.3：CISA KEV | marketing-site | 168h | kev-cve-2026-119977：[{'start_including': '4.7', 'end_excluding': '4.7.39'}, {'start_including': '4.8', 'end_excluding': '4.8.34'}, {'start_including': '4.9', 'end_excluding': '4.9.35'}, {'start_including': '5.0', 'end_excluding': '5.0.31'}, {'start_including': '5.1', 'end_excluding': '5.1.28'}, {'start_including': '5.2', 'end_excluding': '5.2.30'}, {'start_including': '5.3', 'end_excluding': '5.3.27'}, {'start_including': '5.4', 'end_excluding': '5.4.25'}, {'start_including': '5.5', 'end_excluding': '5.5.24'}, {'start_including': '5.6', 'end_excluding': '5.6.23'}, {'start_including': '5.7', 'end_excluding': '5.7.21'}, {'start_including': '5.8', 'end_excluding': '5.8.19'}, {'start_including': '5.9', 'end_excluding': '5.9.20'}, {'start_including': '6.0', 'end_excluding': '6.0.18'}, {'start_including': '6.1', 'end_excluding': '6.1.16'}, {'start_including': '6.2', 'end_excluding': '6.2.15'}, {'start_including': '6.3', 'end_excluding': '6.3.14'}, {'start_including': '6.4', 'end_excluding': '6.4.14'}, {'start_including': '6.5', 'end_excluding': '6.5.14'}, {'start_including': '6.6', 'end_excluding': '6.6.11'}, {'start_including': '6.7', 'end_excluding': '6.7.11'}, {'start_including': '6.8', 'end_excluding': '6.8.12'}, {'start_including': '6.9', 'end_excluding': '6.9.11'}, {'start_including': '7.0', 'end_excluding': '7.0.8'}, {'start_including': '7.1', 'end_excluding': '7.1.4'}]；我們的狀況：wordpress 6.4.3，對外 |
| medium | 5 | App 允許明文傳輸 | brand-app | 168h | AndroidManifest.xml: android:usesCleartextTraffic="true" |
| medium | 5 | 對外開放且無權限保護的元件 | brand-app | 168h | AndroidManifest.xml: activity .DeepLinkOrderActivity、receiver .PushCommandReceiver |
| medium | 5 | targetSdkVersion 31 低於商店要求 | brand-app | 168h | build.gradle: targetSdkVersion 31（政策 2025-08-31 起最低 35） |
| medium | 5 | lodash 4.17.20 有 4 個已知漏洞（最高 CVSS 9.8，CVE-2026-4800） | member-api | 168h | trivy: services/member-api lodash@4.17.20；修補版本：4.18.0 |
| medium | 5 | 備份與來源設備隔離，且 90 天內做過還原測試：nas-office-01 | nas-office-01 | 168h | backups.json: nas-office-01：備份與來源未隔離（usb:attached-to-nas-office-01）、從未做過還原測試 |
| medium | 5 | 內部工具不得對外開放：nas-office-01 | nas-office-01 | 168h | network.json: internet → nas-office-01:5001 |
| medium | 5 | 非正式環境不得連線正式資料庫：order-db-prod | order-db-prod | 168h | network.json: order-db-test（test）→ order-db-prod:5432 |
| medium | 5 | postgresql 15.6 有 44 個已知漏洞（NVD，最高 CVSS 8.8，CVE-2024-10979） | order-db-prod | 168h | nvd: postgresql@15.6 依 CPE 取得候選後，本地重新比對版本（44 確定、0 需確認）；修補版本：15.19 |
| medium | 4 | 正式部署必須來自 Pipeline：ai-code-assistant | ai-code-assistant | 168h | secrets.json: ai-assistant-token 存放於 ai-code-assistant，可直接觸發 deploy-pipeline（繞過 Pipeline 審核） |
| medium | 4 | redis 7.0.15 有 11 個已知漏洞（NVD，最高 CVSS 9.9，CVE-2025-49844） | cache-redis | 168h | nvd: redis@7.0.15 依 CPE 取得候選後，本地重新比對版本（11 確定、0 需確認）；修補版本：8.6.3 |
| medium | 4 | 商店上有冒用「花漾美妝（虛構）」的山寨 App：花漾美妝 Bloom 會員福利 | clone:app.bloomrewards.example | 168h | app-store-scan.json: google_play app.bloomrewards.example（開發者 Bloom Rewards Studio，圖示相似度 0.93） |
| medium | 4 | gitlab-ce 18.4.1 有 163 個已知漏洞（NVD，最高 CVSS 10.0，CVE-2026-110264） | gitlab | 168h | nvd: gitlab-ce@18.4.1 依 CPE 取得候選後，本地重新比對版本（163 確定、0 需確認）；修補版本：19.3.6 |
| medium | 4 | php 8.1.27 已停止支援（2025-12-31） | marketing-site | 168h | runtime.json: marketing-site php 8.1.27；eol.json: 8.1 支援至 2025-12-31 |
| medium | 4 | body-parser 1.20.1 有 3 個已知漏洞（最高 CVSS 7.5，CVE-2024-45590） | member-api | 168h | trivy: services/member-api body-parser@1.20.1；修補版本：1.20.3 |
| medium | 4 | path-to-regexp 0.1.7 有 3 個已知漏洞（最高 CVSS 7.5，CVE-2024-45296） | member-api | 168h | trivy: services/member-api path-to-regexp@0.1.7；修補版本：1.9.0, 0.1.10, 8.0.0, 3.3.0, 6.3.0 |
| medium | 4 | qs 6.11.0 有 4 個已知漏洞（最高 CVSS 7.5，CVE-2025-15284） | member-api | 168h | trivy: services/member-api qs@6.11.0；修補版本：6.14.1 |
| medium | 4 | postgresql 15.6 有 44 個已知漏洞（NVD，最高 CVSS 8.8，CVE-2024-10979） | member-db-prod | 168h | nvd: postgresql@15.6 依 CPE 取得候選後，本地重新比對版本（44 確定、0 需確認）；修補版本：15.19 |
| medium | 4 | php 8.3.20 有 28 個已知漏洞（NVD，最高 CVSS 9.8，CVE-2025-14179） | phpmyadmin | 168h | nvd: php@8.3.20 依 CPE 取得候選後，本地重新比對版本（28 確定、3 需確認）；修補版本：8.3.36 |
| low | 3 | express 4.18.2 有 2 個已知漏洞（最高 CVSS 6.1，CVE-2024-29041） | member-api | 720h | trivy: services/member-api express@4.18.2；修補版本：4.19.2, 5.0.0-beta.3 |
| low | 3 | send 0.18.0 有 1 個已知漏洞（最高 CVSS 5.0，CVE-2024-43799） | member-api | 720h | trivy: services/member-api send@0.18.0；修補版本：0.19.0 |
| low | 3 | serve-static 1.15.0 有 1 個已知漏洞（最高 CVSS 5.0，CVE-2024-43800） | member-api | 720h | trivy: services/member-api serve-static@1.15.0；修補版本：1.16.0, 2.1.0 |
| low | 2 | 快取服務連線須加密：cache-redis | cache-redis | 720h | runtime.json: cache-redis tls=false |
| low | 2 | cookie 0.5.0 有 1 個已知漏洞（最高 CVSS 3.7，CVE-2024-47764） | member-api | 720h | trivy: services/member-api cookie@0.5.0；修補版本：0.7.0 |
| low | 2 | postgresql 15.6 有 44 個已知漏洞（NVD，最高 CVSS 8.8，CVE-2024-10979） | order-db-test | 720h | nvd: postgresql@15.6 依 CPE 取得候選後，本地重新比對版本（44 確定、0 需確認）；修補版本：15.19 |
| low | 2 | push-key-fcm-apns 存放在共用磁碟，所有辦公室人員可取用 | push-key-fcm-apns | 720h | mobile-keys.json: push-key-fcm-apns stored_in share:fileserver-01/mobile/push-keys；accessible_by all-office-staff |
| low | 2 | php 8.4.27 有 1 個漏洞需確認執行環境或版本（NVD） | report-svc | 720h | nvd: php@8.4.27 依 CPE 取得候選後，本地重新比對版本（0 確定、1 需確認）；修補版本：無法確定（部分漏洞沒有修補版本或範圍不明） |
| low | 1 | Git 中有測試環境金鑰（config/db.yml:7） | gitlab | 720h | config/db.yml:7 |
| low | 0 | phpmyadmin 5.2.1 有 7 個已知漏洞（NVD，最高 CVSS 8.8，CVE-2026-119426） | phpmyadmin | 720h | nvd: phpmyadmin@5.2.1 依 CPE 取得候選後，本地重新比對版本（7 確定、0 需確認）；修補版本：無法確定（部分漏洞沒有修補版本或範圍不明） |

## 攻擊路徑
- internet → brand-app → app-api-key → api-gateway → member-db-prod
- internet → internal-tool → gitlab-read-token-internal-tool → gitlab → order-db-prod-cred → order-db-prod
- laptop-eng-07 → deploy-token-eng07 → deploy-pipeline（假設 laptop-eng-07 已遭入侵（情境分析））
