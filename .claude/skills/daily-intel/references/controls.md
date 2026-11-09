# 控制項（由 agents/intel/controls.yaml 產生）

| ID | 說明 |
|---|---|
| C-SECRET-IN-GIT | Git 中不得有正式環境金鑰 |
| C-INTERNAL-TOOL-EXPOSED | 內部工具不得對外開放 |
| C-NET-SEGMENT | 非正式環境不得連線正式資料庫 |
| C-THIRD-PARTY-KEY-ROTATION | 第三方服務金鑰 90 天內輪替且有 IP 白名單 |
| C-NON-CI-DEPLOY | 正式部署必須來自 Pipeline |
| C-DEV-DEVICE-TOKEN | 員工電腦不得持有正式部署權杖 |
| C-BACKUP-ISOLATION | 備份與來源設備隔離，且 90 天內做過還原測試 |
| C-APP-SDK | App SDK 無已知漏洞，舊版使用者比例低於門檻 |
| C-CLOUD-STORAGE-PUBLIC | 雲端儲存空間不得公開讀取 |
| C-CACHE-TLS | 快取服務連線須加密 |
