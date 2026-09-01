FROM node:24-alpine

ENV NODE_ENV=production \
    PORT=8080 \
    DATA_DIR=/data

WORKDIR /app

COPY package.json ./
COPY src ./src
COPY public ./public

RUN addgroup -S crackdown && adduser -S -G crackdown crackdown \
    && mkdir -p /data && chown -R crackdown:crackdown /app /data

USER crackdown
EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

CMD ["node", "src/server.js"]

