FROM python:3.12-slim

# iptables package ships both iptables-nft and iptables-legacy; the app picks the host's one.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

ENV PYTHONUNBUFFERED=1 \
    DB_PATH=/data/firewall.db \
    PERSIST_FILE=/host/iptables/rules.v4 \
    BIND_HOST=0.0.0.0 \
    PORT=8088

VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/healthz', timeout=4)"

# Single worker on purpose: the apply/confirm state machine lives in-process.
CMD ["sh", "-c", "exec uvicorn app.main:app --host \"$BIND_HOST\" --port \"$PORT\" --workers 1 --proxy-headers"]
