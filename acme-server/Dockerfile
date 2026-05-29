FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json* ./
RUN npm install --omit=dev && npm cache clean --force
COPY --from=builder /app/dist ./dist
RUN addgroup -S acme && adduser -S -G acme acme \
    && mkdir -p /var/lib/secutor-acme /etc/secutor-acme /secutor \
    && chown -R acme:acme /var/lib/secutor-acme /etc/secutor-acme /secutor \
    && chmod 0755 /etc/secutor-acme /secutor
# /secutor — простой writable mountpoint для config/secrets/keys, чтобы
# bind-mount файлов работал без зависимости от ro-/etc.
# /etc/secutor-acme — исторический mountpoint, оставлен для обратной
# совместимости.
USER acme
EXPOSE 8443 8444
CMD ["node", "dist/server/index.js"]
