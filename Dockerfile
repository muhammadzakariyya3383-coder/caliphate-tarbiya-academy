FROM node:20-alpine

WORKDIR /app

COPY backend/package.json ./backend/package.json

WORKDIR /app/backend

RUN npm install --omit=dev

COPY backend/ ./

ENV NODE_ENV=production

EXPOSE 3000

CMD ["node", "server.js"]
