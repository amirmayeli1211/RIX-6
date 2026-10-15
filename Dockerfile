FROM python:3.12-slim
ARG TARGETARCH=amd64
ENV APP_ENV=production PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 DATA_DIR=/data XRAY_BIN=/usr/local/bin/xray
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip tar && rm -rf /var/lib/apt/lists/*
# Pin released binaries so a deploy is reproducible; no shell command is needed on a separate server.
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) CADDY_ARCH=amd64; XRAY_ARCH=64; XRAY_SHA256=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae ;; \
      arm64) CADDY_ARCH=arm64; XRAY_ARCH=arm64-v8a; XRAY_SHA256=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c ;; \
      *) echo "Unsupported build architecture: $TARGETARCH"; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/caddyserver/caddy/releases/download/v2.10.2/caddy_2.10.2_linux_${CADDY_ARCH}.tar.gz" -o /tmp/caddy.tar.gz; \
    tar -xzf /tmp/caddy.tar.gz -C /tmp caddy; install -m 0755 /tmp/caddy /usr/local/bin/caddy; \
    curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-${XRAY_ARCH}.zip" -o /tmp/xray.zip; \
    echo "$XRAY_SHA256  /tmp/xray.zip" | sha256sum -c -; \
    unzip -o /tmp/xray.zip xray -d /tmp/xray-bin; install -m 0755 /tmp/xray-bin/xray /usr/local/bin/xray; \
    rm -rf /tmp/caddy.tar.gz /tmp/xray.zip /tmp/xray-bin
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt
COPY . .
RUN chmod +x start.sh && mkdir -p /data
EXPOSE 8080
CMD ["sh", "/app/start.sh"]
