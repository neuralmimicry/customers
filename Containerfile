FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY customers_service ./customers_service
RUN pip install --no-cache-dir .

EXPOSE 5010
CMD ["python", "-m", "customers_service"]
