FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY backend/pyproject.toml backend/requirements.txt ./
COPY backend/vulnhunter ./vulnhunter
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000
CMD ["uvicorn", "vulnhunter.main:app", "--host", "0.0.0.0", "--port", "8000"]
