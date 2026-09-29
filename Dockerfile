FROM caddy:2 AS caddy

FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# CORE_URL: direct download URL of the core release zip (set it as a Railway variable)
ARG CORE_URL
RUN test -n "$CORE_URL" || (echo "CORE_URL build variable is required" && exit 1) \
    && curl -fsSL -o /tmp/c.zip "$CORE_URL" \
    && mkdir /tmp/c && unzip -o /tmp/c.zip -d /tmp/c \
    && f=$(find /tmp/c -maxdepth 1 -type f ! -name '*.dat' ! -name '*.md' ! -name 'LICENSE' | head -1) \
    && install -m 755 "$f" /usr/local/bin/appcore \
    && rm -rf /tmp/c /tmp/c.zip

COPY --from=caddy /usr/bin/caddy /usr/local/bin/caddy

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chmod +x start.sh
CMD ["./start.sh"]
