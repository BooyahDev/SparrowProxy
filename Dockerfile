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

# Install ca-certificates, wget for healthcheck, and git for repository sync
RUN apk --no-cache add ca-certificates wget git

# Create app directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/sparrowproxy .

# Copy the default config file
COPY config.yaml .

# Create directories for config and certs
RUN mkdir -p /app/certs /app/config-repo

# Expose ports
EXPOSE 80 443 8000

# Set default environment variables
ENV CONFIG_PATH=/app/config.yaml
ENV CONFIG_REPO_PATH=/app/config-repo

# Run the application
CMD ["./sparrowproxy"]
