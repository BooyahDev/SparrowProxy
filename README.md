# SparrowProxy

A lightweight HTTP/HTTPS reverse proxy written in Go.

## Features

- HTTP to HTTPS redirect
- Multiple backend support with health checks
- TLS certificate management
- Configuration hot-reload
- Docker support

## Quick Start

### Using Docker Compose

1. Configure your settings in `config.yaml`
2. Place your TLS certificates in the `certs/` directory
3. Start the proxy:

```bash
docker-compose up -d
```

### Manual Build and Run

1. Build the application:
```bash
go build -o sparrowproxy main.go
```

2. Run with configuration:
```bash
./sparrowproxy -config config.yaml
```

## Configuration

Edit `config.yaml` to configure:
- TLS certificates
- Backend services
- Health check settings
- Redirect rules

## Ports

- **80**: HTTP (redirects to HTTPS)
- **443**: HTTPS (main proxy traffic)

## Health Check

The application provides health monitoring on the configured health check endpoints for backend services.
