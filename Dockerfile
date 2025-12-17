# ==========================================
# Stage 1: Builder
# ==========================================
FROM node:24-bookworm-slim AS builder

WORKDIR /app

# 为了利用缓存，先复制 package 文件
COPY package.json package-lock.json* ./
RUN npm ci

# 复制源码并构建
COPY src ./src
COPY wrangler.jsonc ./
# 构建输出到 dist 目录
RUN npx wrangler deploy --dry-run --outdir dist --minify --name proxy

# ==========================================
# Stage 2: Runtime
# ==========================================
FROM node:24-bookworm-slim

WORKDIR /app

# 复制必要文件
COPY --from=builder /app/dist/index.js ./dist/index.js
COPY config.capnp ./

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*  && \
    npm install @cloudflare/workerd-linux-64 && \
    npm cache clean --force

EXPOSE 8080

CMD ["npx", "workerd", "serve", "config.capnp"]