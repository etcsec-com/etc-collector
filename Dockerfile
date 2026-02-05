# Build stage
FROM golang:1.24-alpine AS builder

ARG VERSION=dev

# Install certificates and git
RUN apk add --no-cache ca-certificates git

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-w -s -X main.Version=${VERSION}" \
    -o etc-collector ./cmd/etc-collector

# Runtime stage
FROM alpine:3.19

# Install certificates for TLS
RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 collector && \
    adduser -u 1000 -G collector -D collector

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/etc-collector .

# Create data directory
RUN mkdir -p /app/data /app/keys && \
    chown -R collector:collector /app

# Switch to non-root user
USER collector

# Expose API port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8443/health || exit 1

# Default command
ENTRYPOINT ["/app/etc-collector"]
CMD ["server"]
