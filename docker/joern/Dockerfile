# Joern — lightweight Docker image for code property graph generation
#
# Build:
#   docker build -t agies/joern:latest -f docker/joern/Dockerfile .
#
# Build with proxy:
#   docker build --network host \
#     --build-arg HTTP_PROXY=http://127.0.0.1:1080 \
#     --build-arg HTTPS_PROXY=http://127.0.0.1:1080 \
#     --build-arg NO_PROXY="dl-cdn.alpinelinux.org,*.alpinelinux.org,localhost,127.0.0.1" \
#     -t agies/joern:latest -f docker/joern/Dockerfile .
#
# Usage:
#   docker run --rm -v /path/to/source:/app:ro agies/joern joern-parse /app

FROM eclipse-temurin:21-jdk-alpine AS base

LABEL description="Joern — CPG generator for agies"

RUN apk add --no-cache curl bash

ARG JOERN_VERSION=v4.0.551
ARG JOERN_URL=https://github.com/joernio/joern/releases/download/${JOERN_VERSION}/joern-cli.zip

WORKDIR /opt/joern

# Step 1: download and extract (cached when URL/version don't change)
RUN curl -fsSL "${JOERN_URL}" -o joern-cli.zip && \
    unzip -q joern-cli.zip && \
    rm joern-cli.zip && \
    echo "Joern CLI downloaded and extracted"

# Step 2: create symlinks using absolute paths
RUN JOERN_BIN=$(find /opt/joern/joern-cli -type f -name "joern" | head -1) && \
    JOERN_DIR=$(dirname "$JOERN_BIN") && \
    ln -sf "$JOERN_DIR/joern" /usr/local/bin/joern && \
    ln -sf "$JOERN_DIR/joern-parse" /usr/local/bin/joern-parse && \
    ln -sf "$JOERN_DIR/joern-export" /usr/local/bin/joern-export && \
    ln -sf "$JOERN_DIR/joern-scan" /usr/local/bin/joern-scan && \
    echo '#!/bin/bash' > /usr/local/bin/joern-script && \
    echo 'exec joern --script "$@"' >> /usr/local/bin/joern-script && \
    chmod +x /usr/local/bin/joern-script

# Step 3: verify
RUN test -x /usr/local/bin/joern && \
    test -x /usr/local/bin/joern-parse && \
    test -x /usr/local/bin/joern-export && \
    ls -la /usr/local/bin/joern* && \
    echo "Joern CLI installed successfully"

# No ENTRYPOINT — user specifies the full command (joern, joern-parse, etc.)
CMD ["joern", "--help"]
