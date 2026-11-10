# 來源與可信度

- 廠商官方公告、官方資安單位、GitHub Advisory、CISA KEV：可信度最高，單一來源即可確認
- 媒體：需要兩個獨立來源一致才算確認，否則標記暫定
- 社群貼文：一律標記暫定

## 抓得到的網站（WebFetch 只允許下列網域與其子網域）

後續程式也只會抓這些網站來確認引用。**每個事件至少要有一個來源在下列網域內**；其他網站的報導可以附上，但無法驗證、只會標記暫定。
從搜尋結果看到清單外網站的新聞時，請找同一事件在下列網站上的報導作為來源。

- 廠商官方（vendor）：`php.net`、`synology.com`、`nextjs.org`、`vercel.com`
- 公告與官方資安單位（advisory）：`github.com`、`cisa.gov`、`nvd.nist.gov`、`twcert.org.tw`、`nics.nat.gov.tw`
- 媒體（media）：`rapid7.com`、`stepsecurity.io`、`technews.tw`、`cyberq.tw`、`bnext.com.tw`、`ithome.com.tw`、`cna.com.tw`、`focustaiwan.tw`、`taipeitimes.com`、`inside.com.tw`、`informationsecurity.com.tw`、`bleepingcomputer.com`、`thehackernews.com`、`securityweek.com`、`therecord.media`
- 社群（community）：`heatalk.com`

清單由 `agents/intel/sources.yaml` 維護（此檔需與它一致，測試會檢查）。
