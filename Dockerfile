# ==========================================
# Stage 1: Main Builder
# ==========================================
FROM node:24-alpine3.22 AS main-builder

WORKDIR /app

# 复制并安装wrangler依赖
COPY package.json package-lock.json* ./
RUN npm ci

# 复制源码并构建应用
COPY src ./src
COPY wrangler.jsonc ./
RUN npx wrangler deploy --dry-run --outdir dist --minify --name proxy

# ==========================================
# Stage 2: Workerd Builder
# ==========================================
FROM node:24-alpine3.22 AS workerd-builder

WORKDIR /workerd

# 安装binutils（包含strip命令），再安装workerd并剥离符号
RUN apk add --no-cache binutils && \
    npm install workerd && \
    WORKERD_PATH=$(find node_modules -name workerd -type f) && \
    echo "Workerd installed at: $WORKERD_PATH" && \
    strip $WORKERD_PATH && \
    apk del binutils

# ==========================================
# Stage 3: Runtime
# ==========================================
FROM frolvlad/alpine-glibc:alpine-3.22

WORKDIR /app

# 从主构建阶段复制应用文件
COPY --from=main-builder /app/dist/index.js ./dist/index.js
COPY config.capnp ./

# 从workerd构建阶段复制二进制文件
COPY --from=workerd-builder /workerd/node_modules/@cloudflare/workerd-linux-64/bin/workerd /usr/local/bin/

# 安装必要依赖
RUN apk add --no-cache ca-certificates && \
    chmod +x /usr/local/bin/workerd && \
    workerd --version

EXPOSE 8080

CMD ["sh", "-c", "workerd --version && workerd serve config.capnp"]