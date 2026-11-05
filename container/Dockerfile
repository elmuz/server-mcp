# syntax=docker/dockerfile:1
#
# Server MCP container image.
#
# One image exposes both console scripts:
#   remote-server-mcp
#   disk-health-mcp
#
# Build from the repository root:
#   docker build -f container/Dockerfile -t localhost/server-mcp:dev .

ARG PYTHON_IMAGE=python:3.13-slim

FROM ${PYTHON_IMAGE} AS builder

ARG UV_VERSION=0.13.6

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONDONTWRITEBYTECODE=1

RUN pip install --no-cache-dir "uv==${UV_VERSION}"

WORKDIR /src

# Copy the workspace metadata and sources. The lockfile is mandatory: the
# image must never resolve a different dependency set at build time.
COPY pyproject.toml uv.lock README.md ./
COPY packages ./packages
COPY apps ./apps

# Create the environment at its final runtime path. Installing into
# /src/.venv and copying it to /opt/venv would leave every console-script
# shebang pointing at /src/.venv/bin/python, which does not exist in the
# runtime image.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv
RUN uv venv /opt/venv --python /usr/local/bin/python3.13 \
    && uv sync \
        --frozen \
        --no-dev \
        --no-editable \
        --all-packages \
        --python /opt/venv/bin/python3.13 \
    && find /opt/venv -type d -name __pycache__ -prune -exec rm -rf {} +


FROM ${PYTHON_IMAGE} AS runtime

ARG UID=1000
ARG GID=1000
ARG VERSION=dev
ARG REVISION=unknown

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    PATH="/opt/venv/bin:${PATH}" \
    SERVER_MCP_CONTAINER=1

# ca-certificates is required for HTTPS metric endpoints. passwd provides
# groupadd/useradd on the slim base image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        passwd \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid "${GID}" mcp \
    && useradd --uid "${UID}" --gid "${GID}" --create-home \
        --shell /usr/sbin/nologin mcp

COPY --from=builder /opt/venv /opt/venv

# Egress policy proxy and the SSH ProxyCommand helper. Both are plain Python
# scripts so the same image can run the proxy container without a second build.
COPY container/egress_proxy.py /usr/local/bin/egress-proxy.py
COPY container/connect_proxy.py /usr/local/bin/server-mcp-connect
RUN chmod 0755 /usr/local/bin/egress-proxy.py /usr/local/bin/server-mcp-connect

# The config directory only holds operator-mounted files and must be traversable
# by whatever UID the container runs as; the files themselves stay 0600.
RUN install -d -o "${UID}" -g "${GID}" -m 0755 /etc/server-mcp \
    && install -d -o "${UID}" -g "${GID}" -m 0700 /var/lib/server-mcp \
    && install -d -o root -g root -m 0755 /run/secrets

LABEL org.opencontainers.image.title="Server MCP" \
      org.opencontainers.image.description="Security-first MCP servers for Linux server management" \
      org.opencontainers.image.source="https://github.com/elmuz/server-mcp" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="MIT"

USER ${UID}:${GID}
WORKDIR /home/mcp
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8000), 2).close()"]

CMD ["remote-server-mcp"]
