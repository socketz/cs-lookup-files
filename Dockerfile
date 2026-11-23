FROM python:3.13-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
COPY config ./config

RUN uv sync --frozen --no-dev --no-install-project
RUN . /opt/venv/bin/activate && uv pip install --no-deps /app

FROM python:3.13-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=base /opt/venv /opt/venv

WORKDIR /data
COPY --from=base /app/src /app/src
COPY --from=base /app/config /app/config

VOLUME ["/data/output"]

ENTRYPOINT ["cs-lookup-files"]
CMD ["build", "--config-dir", "/app/config", "--output-dir", "/data/output"]

LABEL org.opencontainers.image.title="cs-lookup-files" \
      org.opencontainers.image.description="Aggregate free threat-intel feeds into CrowdStrike Falcon lookup files" \
      org.opencontainers.image.source="https://github.com/socketz/cs-lookup-files"