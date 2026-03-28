FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml ./
COPY backend/requirements.txt ./backend/requirements.txt

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

COPY agentshield/ ./agentshield/
COPY backend/ ./backend/

ENV AGENTSHIELD_REDIS_URL=redis://redis:6379
ENV AGENTSHIELD_HOST=0.0.0.0
ENV AGENTSHIELD_PORT=8000
ENV AGENTSHIELD_LOG_LEVEL=INFO

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
