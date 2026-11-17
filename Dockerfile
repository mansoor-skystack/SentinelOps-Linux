FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY frontend ./frontend
COPY agent ./agent
COPY scripts ./scripts
RUN useradd --system --uid 10001 sentinelops \
    && mkdir -p /var/lib/sentinelops \
    && chown -R sentinelops:sentinelops /app /var/lib/sentinelops

USER sentinelops
EXPOSE 8000

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
