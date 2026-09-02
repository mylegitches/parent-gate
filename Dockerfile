FROM node:24-alpine

ENV NODE_ENV=production \
    PORT=8901 \
    DATA_DIR=/data

WORKDIR /app

COPY package.json ./
COPY src ./src
COPY public ./public
COPY client/windows ./client/windows

RUN addgroup -S crackdown && adduser -S -G crackdown crackdown \
    && mkdir -p /data && chown -R crackdown:crackdown /app /data

USER crackdown
EXPOSE 8901
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:${PORT}/healthz || exit 1

CMD ["node", "src/server.js"]
