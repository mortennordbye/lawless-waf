# syntax=docker/dockerfile:1

# ---- base: API runtime (lean) ----------------------------------------------
FROM python:3.14-slim AS base

# uv for fast, reproducible installs
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Azure CLI: the app reuses the operator's ambient `az login` session (mounted at runtime).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -sL https://aka.ms/InstallAzureCLIDeb | bash \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN uv pip install --system --no-cache .

ENV DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8000

CMD ["uvicorn", "lawless_waf.main:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-graceful-shutdown", "3"]

# ---- dev: adds test/lint tools, editable install so mounted src is live -----
FROM base AS dev
COPY tests ./tests
RUN uv pip install --system --no-cache -e ".[dev]"
