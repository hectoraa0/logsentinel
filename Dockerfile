FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

# Run as an unprivileged user; /var/lib/logsentinel holds the SQLite database.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin logsentinel \
    && mkdir -p /var/lib/logsentinel \
    && chown logsentinel /var/lib/logsentinel

WORKDIR /app
COPY src ./src

USER logsentinel
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]

ENTRYPOINT ["python", "-m", "logsentinel"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000", "--db", "/var/lib/logsentinel/alerts.db"]
