# Docker playground image using pre-built binaries from host
# Usage: make docker-playground       (multiarch)
#        make docker-playground-arm64 (arm64 only)
#        make docker-playground-amd64 (amd64 only)
#
# Binaries are cross-compiled on the host using musl for static linking,
# then packaged into this image.

ARG TARGETARCH

# Plugin build stage - install Node.js dependencies for external plugins
FROM node:20-alpine AS plugin-builder
WORKDIR /plugins

# Copy external plugins
COPY examples/external_plugins/echo-plugin /plugins/echo-plugin
COPY examples/external_plugins/reti /plugins/reti
COPY examples/external_plugins/tinymanswap /plugins/tinymanswap

# Install dependencies and build each plugin
RUN for dir in /plugins/*/; do \
    name=$(basename "$dir"); \
    if [ -f "$dir/package.json" ]; then \
        echo "Installing dependencies for $name..."; \
        cd "$dir" && npm install; \
        if grep -q '"build"' "$dir/package.json"; then \
            echo "Building $name..."; \
            cd "$dir" && npm run build; \
        fi; \
    fi; \
done

# Control file builder (runs on build platform)
FROM --platform=$BUILDPLATFORM golang:1.25.5-alpine AS control-builder
WORKDIR /build
COPY docker/scripts/create-control-file.go /build/
COPY internal/ /build/internal/
COPY go.mod go.sum /build/
RUN go mod download
RUN mkdir -p /out && go run create-control-file.go /out/users/default /out/passphrase

# Runtime stage
FROM alpine:latest
ARG TARGETARCH

# Install packages including locale support for proper TUI rendering
RUN apk add --no-cache tmux bash libc6-compat ncurses-terminfo-base nodejs npm musl-locales musl-locales-lang

# Set UTF-8 locale for proper box-drawing characters in TUI
# Use C.UTF-8 which is universally available in musl/Alpine
# Set APCLIENT_DATA and APSIGNER_DATA for config/plugin discovery
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    CHARSET=UTF-8 \
    TERM=xterm-256color \
    APCLIENT_DATA=/root/apshell \
    APSIGNER_DATA=/root/apsigner

# Copy pre-built binaries from host (built via make bin-arm64 or make bin-amd64)
COPY bin/${TARGETARCH}/ /usr/local/bin/

# Setup directories
RUN mkdir -p /root/apshell/plugins /root/apsigner/users/default

# Copy pre-created users directory and passphrase file
COPY --from=control-builder /out/users /root/apsigner/users
COPY --from=control-builder --chmod=600 /out/passphrase /root/apsigner/passphrase

# Copy external plugins (with npm dependencies already installed)
COPY --from=plugin-builder /plugins/ /root/apshell/plugins/

# Copy configs to their respective data directories
COPY docker/config/apshell-config.yaml /root/apshell/config.yaml
COPY docker/config/apsignerd.yaml /root/apsigner/config.yaml

# Fixed API token for both server and client (demo only - 64 hex chars = 256 bits)
# Server expects token at users/default/aplane.token
RUN echo "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" > /root/apsigner/users/default/aplane.token && \
    chmod 600 /root/apsigner/users/default/aplane.token && \
    cp /root/apsigner/users/default/aplane.token /root/apshell/aplane.token && \
    chmod 600 /root/apshell/aplane.token

# Example JS scripts
COPY examples/js/ /root/apshell/examples/

# Scripts
COPY docker/scripts/ /usr/local/bin/
COPY docker/tmux.conf /root/.tmux.conf
RUN chmod +x /usr/local/bin/*.sh

WORKDIR /root
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
