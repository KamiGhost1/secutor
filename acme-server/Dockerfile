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
    && mkdir -p /var/lib/secutor-acme /etc/secutor-acme \
    && chown -R acme:acme /var/lib/secutor-acme
USER acme
EXPOSE 8443
CMD ["node", "dist/server/index.js"]
