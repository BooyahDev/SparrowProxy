# SparrowProxy

A lightweight HTTP/HTTPS reverse proxy written in Go with Git-based configuration synchronization.

## Features

- HTTP to HTTPS redirect
- Multiple backend support with health checks
- TLS certificate management
- Configuration hot-reload
- **Git repository configuration sync** - Automatically sync `config.yaml` and certificates from a private repository
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

2. Run with local configuration:
```bash
./sparrowproxy -config config.yaml
```

3. Run with Git repository synchronization:
```bash
./sparrowproxy \
  -config config.yaml \
  -config-repo git@github.com:BooyahDev/SparrowProxyConfig.git \
  -config-repo-path ./config-repo \
  -sync-interval 1m
```

## Git Repository Configuration Sync

SparrowProxy can automatically synchronize configuration and certificates from a private Git repository. This feature allows you to:

- Store `config.yaml` and `certs/` folder in a separate private repository
- Automatically pull changes every minute (configurable)
- Apply configuration changes without manual intervention
- Maintain security by using SSH key authentication

### Setup Git Sync

1. **Prepare SSH Keys**: Ensure you have SSH keys set up for accessing your private repository:
   ```bash
   # Generate SSH key if you don't have one
   ssh-keygen -t ed25519 -C "your_email@example.com"
   
   # Add the public key to your GitHub account
   cat ~/.ssh/id_ed25519.pub
   ```

2. **Create Configuration Repository**: Create a private repository with the following structure:
   ```
   your-config-repo/
   ├── config.yaml
   └── certs/
       ├── example.com.crt
       └── example.com.key
   ```

3. **Run with Git Sync**:
   ```bash
   ./sparrowproxy \
     -config-repo git@github.com:BooyahDev/SparrowProxyConfig.git \
     -sync-interval 1m
   ```

### Configuration Options

- `-config-repo`: Git repository URL (SSH format recommended for private repos)
- `-config-repo-path`: Local directory to clone the repository (default: `./config-repo`)
- `-sync-interval`: How often to check for repository changes (default: `1m`)

### Environment Variables

You can also use environment variables:

```bash
export CONFIG_REPO_URL="git@github.com:BooyahDev/SparrowProxyConfig.git"
export CONFIG_REPO_PATH="./config-repo"
./sparrowproxy
```

## Configuration

Edit `config.yaml` to configure:
- TLS certificates
- Backend services  
- Health check settings
- Redirect rules

When using Git sync, certificate paths in `config.yaml` can be relative to the repository root:

```yaml
tls:
  - sni_hosts: ["example.com"]
    cert_path: "certs/example.com.crt"  # Relative to repository root
    key_path: "certs/example.com.key"   # Relative to repository root
```

## Ports

- **80**: HTTP (redirects to HTTPS)
- **443**: HTTPS (main proxy traffic)
- **8000**: Health check API endpoint

## Health Check

The application provides health monitoring on port 8000:

- `GET /api/v1/status`: Returns proxy status and statistics

## Kubernetes Deployment

SparrowProxy supports Kubernetes deployment with minimal required manifests.

### Prerequisites

1. **SSH Keys**: Set up SSH keys for accessing the private configuration repository
2. **kubectl**: Kubernetes command-line tool installed and configured

### Quick Deploy

1. **Update Secrets**: Edit `k8s-secret.yaml` with your actual values:
   ```bash
   # SSH private key (base64 encoded)
   echo -n "$(cat ~/.ssh/id_ed25519)" | base64
   
   # Known hosts for GitHub (base64 encoded)
   echo -n "$(ssh-keyscan github.com 2>/dev/null)" | base64
   ```

2. **Deploy to Kubernetes**:
   ```bash
   kubectl apply -f k8s-secret.yaml
   kubectl apply -f k8s-deployment.yaml
   kubectl apply -f k8s-service.yaml
   ```

3. **Check Deployment Status**:
   ```bash
   kubectl get pods -l app=sparrowproxy
   kubectl get services sparrowproxy-service
   kubectl logs -l app=sparrowproxy -f
   ```

### Kubernetes Manifests

- `k8s-secret.yaml`: Contains SSH keys for Git repository access
- `k8s-deployment.yaml`: Deployment configuration with health checks
- `k8s-service.yaml`: LoadBalancer service for HTTP/HTTPS traffic

### Docker Image

The Docker image is automatically built and pushed to `docker-registry.booyah.dev/sparrowproxy` via GitHub Actions on:
- Push to `main` or `develop` branches
- Tagged releases (`v*`)
- Pull requests to `main`

### GitHub Actions Setup

The automated build and push workflow does not require any additional repository secrets as the registry is publicly accessible.

## Security Notes

- SSH key authentication is used for private repository access
- Certificate files are automatically resolved to the correct paths
- File watching monitors both local and repository-synced configurations
- Changes are applied with debouncing to prevent rapid reloads
