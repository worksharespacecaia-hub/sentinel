// 模擬內部工具的版本端點；只供 Demo，不提供任何真實功能。
const http = require("http");

const VERSION = { product: "opsbuilder", version: "1.88" };

http
  .createServer((req, res) => {
    if (req.url === "/version") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(VERSION));
      return;
    }
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end("<title>OpsBuilder</title><h1>OpsBuilder 登入</h1>");
  })
  .listen(process.env.PORT || 8080);
