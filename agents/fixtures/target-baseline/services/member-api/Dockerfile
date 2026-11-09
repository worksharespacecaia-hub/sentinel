FROM node:22.11.0-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY . .
CMD ["node", "index.js"]
