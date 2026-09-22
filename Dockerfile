FROM python:3.13-slim

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv && uv sync --frozen --no-dev
ENV PATH="/app/.venv/bin:$PATH"
COPY logging.json ./logging.json
COPY app ./app
COPY scripts ./scripts

ENV SESSION_NOTIFY_DB=/data/session_notify.db
EXPOSE 8765
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8765", "--log-config", "logging.json"]
