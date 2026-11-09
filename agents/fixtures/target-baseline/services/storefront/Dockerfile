# 假設的自架環境：未部署，只供離線分析（不是公開的 Vercel Demo）
FROM node:22.11.0-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "run", "start"]
