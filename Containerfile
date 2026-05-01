FROM python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
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

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}"

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv

EXPOSE 5010
CMD ["python", "-m", "customers_service"]
