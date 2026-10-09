# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp \
    MPLCONFIGDIR=/tmp/matplotlib \
    REPORT_DIR=/data/reports

WORKDIR /app

RUN addgroup --system --gid 10001 vulnhunter \
    && adduser --system --uid 10001 --ingroup vulnhunter --no-create-home vulnhunter

COPY backend/pyproject.toml ./pyproject.toml
COPY backend/vulnhunter ./vulnhunter
COPY backend/alembic.ini ./alembic.ini

RUN python -m pip install --no-cache-dir ".[infrastructure]" \
    && mkdir -p /data/reports /tmp/matplotlib \
    && chown -R vulnhunter:vulnhunter /data/reports /tmp/matplotlib

COPY infra/docker/backend-entrypoint.sh /usr/local/bin/vulnhunter-entrypoint
RUN chmod 755 /usr/local/bin/vulnhunter-entrypoint

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1

ENTRYPOINT ["vulnhunter-entrypoint"]
CMD ["uvicorn", "vulnhunter.main:app", "--host", "0.0.0.0", "--port", "8000"]
