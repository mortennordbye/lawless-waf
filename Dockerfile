# syntax=docker/dockerfile:1

# ---- ui: build the SPA. Only the `app` stage needs this, so `dev` (tests, `make up`) never
#      pays for a node install — the dev UI is served by Vite from a bind mount instead.
FROM node:26-slim AS ui
WORKDIR /fe
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- base: API runtime (lean) ----------------------------------------------
FROM python:3.14-slim AS base

# uv for fast, reproducible installs
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Azure CLI: the app reuses the operator's ambient `az login` session (mounted at runtime).
# git: read a waf-exclusions.tf from a mounted repo at a chosen branch/ref (EXCLUSIONS_ROOT).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
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

# ---- app: base + the built UI, served by the API itself. This is the published image:
#      one `docker run`, whole app on :8000, no clone and no compose.
FROM base AS app
COPY --from=ui /fe/dist ./static
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["uvicorn", "lawless_waf.main:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-graceful-shutdown", "3"]
