# syntax=docker/dockerfile:1
#
# Official container image for cachelint.
#
#   docker run --rm -v "$PWD":/work ghcr.io/0xabcd01/cachelint Dockerfile
#
# The tool is pure standard-library Python, so a slim base is enough.
FROM python:3.12-slim AS builder

# Build a wheel so the final stage stays small and dependency-free.
COPY src /src/src
COPY pyproject.toml README.md /src/
RUN pip install --no-cache-dir --upgrade build \
    && python -m build --wheel --outdir /dist /src

FROM python:3.12-slim

# Non-root user for CI safety.
RUN groupadd --system --gid 1001 cachelint \
    && useradd  --system --uid 1001 --gid cachelint \
                --create-home --home-dir /home/cachelint cachelint

# Install the prebuilt wheel from the builder stage.
COPY --from=builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl \
    && rm -f /tmp/*.whl

# Run as the non-root user from now on.
USER cachelint
WORKDIR /work

ENTRYPOINT ["cachelint"]
CMD ["--help"]
