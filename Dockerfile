# Build stage
FROM golang:1.21-alpine AS builder

# Set working directory
WORKDIR /app

# Install dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY main.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o sparrowproxy main.go

# Final stage
FROM alpine:latest

# Install ca-certificates, wget for healthcheck, git for repository sync, and libcap for setcap
RUN apk --no-cache add ca-certificates wget git libcap curl

# Create app directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/sparrowproxy .

# Create directories for config and certs
RUN mkdir -p /app/certs /app/config-repo

# Grant capability to bind to privileged ports (< 1024) without running as root
RUN setcap CAP_NET_BIND_SERVICE=+eip /app/sparrowproxy

# Create a non-root user for security
RUN addgroup -g 1001 sparrow && \
    adduser -D -s /bin/sh -u 1001 -G sparrow sparrow && \
    chown -R sparrow:sparrow /app

# Switch to non-root user
USER sparrow

# Expose ports
EXPOSE 80 443 8000

# Set default environment variables
ENV CONFIG_PATH=/app/config-repo/config.yaml
ENV CONFIG_REPO_PATH=/app/config-repo

# Run the application
CMD ["./sparrowproxy"]
