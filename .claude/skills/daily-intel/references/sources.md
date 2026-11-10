# 來源與可信度

- 廠商官方公告、官方資安單位、GitHub Advisory、CISA KEV：可信度最高，單一來源即可確認
- 媒體：需要兩個獨立來源一致才算確認，否則標記暫定
- 社群貼文：一律標記暫定

## 可信網站清單

每日文章由程式從下列網站的 RSS（以及 CISA KEV）事先抓好，放在 `out/news.json`；Claude 不抓網頁。
WebSearch 補充的事件，**至少要有一個來源在下列網域內**，程式才能抓頁面確認引用；只有清單外來源的事件不寫入。

- 廠商官方（vendor）：`php.net`、`synology.com`、`nextjs.org`、`vercel.com`
- 公告與官方資安單位（advisory）：`github.com`、`cisa.gov`、`nvd.nist.gov`、`twcert.org.tw`、`nics.nat.gov.tw`
- 媒體（media）：`rapid7.com`、`stepsecurity.io`、`technews.tw`、`cyberq.tw`、`bnext.com.tw`、`ithome.com.tw`、`cna.com.tw`、`focustaiwan.tw`、`taipeitimes.com`、`inside.com.tw`、`informationsecurity.com.tw`、`bleepingcomputer.com`、`thehackernews.com`、`securityweek.com`、`therecord.media`
- 社群（community）：`heatalk.com`

清單由 `agents/intel/sources.yaml` 維護（此檔需與它一致，測試會檢查）。
