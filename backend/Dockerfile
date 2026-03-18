FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m -u 1000 agentshield && chown -R agentshield:agentshield /app
USER agentshield
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8000/healthz || exit 1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]