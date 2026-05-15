ARG CUSTOMERS_VERSION=0.1.0

FROM python:3.13-slim AS builder
ARG CUSTOMERS_VERSION

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CUSTOMERS_VERSION=${CUSTOMERS_VERSION} \
    SETUPTOOLS_SCM_PRETEND_VERSION=${CUSTOMERS_VERSION} \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY pyproject.toml README.md ./
COPY customers_service ./customers_service

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install . \
    && /opt/venv/bin/python - <<'PY'
import compileall
import pathlib
import shutil
import site

package_dir = pathlib.Path(site.getsitepackages()[0]) / "customers_service"
compileall.compile_dir(str(package_dir), force=True, quiet=1, legacy=True)
for path in package_dir.rglob("*.py"):
    path.unlink()
for cache_dir in sorted(package_dir.rglob("__pycache__"), reverse=True):
    shutil.rmtree(cache_dir)
PY

FROM python:3.13-slim
ARG CUSTOMERS_VERSION

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CUSTOMERS_VERSION=${CUSTOMERS_VERSION} \
    PATH="/opt/venv/bin:${PATH}"

WORKDIR /app

LABEL org.opencontainers.image.title="customers" \
      org.opencontainers.image.version="${CUSTOMERS_VERSION}"

COPY --from=builder /opt/venv /opt/venv

EXPOSE 5010
CMD ["sh", "-c", "echo \"[customers] image version=${CUSTOMERS_VERSION}\"; exec python -m customers_service"]
