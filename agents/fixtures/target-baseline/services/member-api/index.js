// 會員 API（虛構）。連線字串由環境變數注入，不寫在程式碼中。
const express = require("express");
const _ = require("lodash");

const app = express();
app.use(express.json());

app.get("/health", (_req, res) => res.json({ ok: true }));

app.post("/v1/members/preferences", (req, res) => {
  // 示範用：以 lodash 合併使用者偏好設定
  const prefs = _.merge({}, { newsletter: false }, req.body);
  res.json(prefs);
});

app.listen(process.env.PORT || 8080);
