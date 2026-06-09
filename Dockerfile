FROM python:3.14-slim

WORKDIR /app
COPY gateway ./gateway
COPY config ./config

ENV PYTHONUNBUFFERED=1
EXPOSE 8080

CMD ["python", "-m", "gateway", "--config", "config/gateway.dev.json"]

