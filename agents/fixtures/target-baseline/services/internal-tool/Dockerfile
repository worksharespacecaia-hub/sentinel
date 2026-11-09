# 由工程師手動在 VM 上 docker run，沒有走 Pipeline
FROM node:22.11.0-alpine
LABEL org.opencontainers.image.title="opsbuilder" org.opencontainers.image.version="1.88"
WORKDIR /app
COPY server.js .
CMD ["node", "server.js"]
