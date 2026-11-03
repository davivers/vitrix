# Vitrix image: API + web UI + CLI. The detections repository is mounted at /workspace.
#
# The web UI is NOT rebuilt here: src/vitrix/ui/ is committed and CI fails when it is stale, so
# the image ships exactly what was reviewed and no node toolchain is needed (smaller, reproducible).
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir build \
 && python -m build --wheel --outdir /dist

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
# git: `vitrix history/drift` and branch pushes shell out to it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && git config --system --add safe.directory '*'
COPY --from=build /dist/*.whl /tmp/
RUN pip install "$(ls /tmp/*.whl)[api]" && rm /tmp/*.whl
RUN useradd --create-home --uid 1000 vitrix && mkdir /workspace && chown vitrix /workspace
USER vitrix
# Accounts are on in the image (ADR 0002): the first screen is "create the owner", and drafts work.
# `auto` prints a one-time setup link in the container logs; whoever has it creates the owner.
ENV VITRIX_AUTH=on VITRIX_BOOTSTRAP_TOKEN=auto
WORKDIR /workspace
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"
ENTRYPOINT ["vitrix"]
# 0.0.0.0 is only the in-container bind. Publish the port on 127.0.0.1 (see docker-compose.yml).
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
