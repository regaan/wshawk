# WSHawk Docker Guide

## Quick Start

### Pull from Docker Hub

```bash
docker pull rothackers/wshawk:latest
```

### Run WSHawk

```bash
# Basic scan
docker run --rm rothackers/wshawk ws://target.com

# Defensive validation
docker run --rm rothackers/wshawk wshawk-defensive ws://target.com

# Interactive mode
docker run --rm -it rothackers/wshawk wshawk-interactive

# Advanced scan with all features
docker run --rm rothackers/wshawk wshawk-advanced ws://target.com --full
```

---

## Building Locally

```bash
# Build the image
docker build -t rothackers/wshawk:latest .

# Run the image
docker run --rm rothackers/wshawk --help
```

---

## Usage Examples

### 1. Basic WebSocket Scan

```bash
docker run --rm rothackers/wshawk ws://echo.websocket.org
```

### 2. Defensive Validation

```bash
docker run --rm rothackers/wshawk wshawk-defensive wss://secure-server.com
```

### 3. Save Reports

```bash
# Create reports directory
mkdir -p reports

# Run scan and save reports
docker run --rm -v $(pwd)/reports:/app/reports rothackers/wshawk ws://target.com
```

### 4. Scan Local Server

```bash
# Use host network to access localhost
docker run --rm --network host rothackers/wshawk ws://localhost:8765
```

### 5. Interactive Shell

```bash
# Get shell access inside container
docker run --rm -it --entrypoint /bin/bash rothackers/wshawk

# Then run commands
wshawk ws://target.com
wshawk-defensive ws://target.com
```

---

## Docker Compose

### Start Services

```bash
# Start WSHawk and test server
docker-compose up -d

# Run scan against test server
docker-compose exec wshawk wshawk ws://vulnerable-server:8765

# Stop services
docker-compose down
```

### Custom Configuration

Edit `docker-compose.yml` to customize:
- Port mappings
- Volume mounts
- Environment variables
- Network settings

---

## Environment Variables

```bash
# Set Python unbuffered output
docker run --rm -e PYTHONUNBUFFERED=1 rothackers/wshawk ws://target.com

# Set custom timeout
docker run --rm -e TIMEOUT=30 rothackers/wshawk ws://target.com
```

---

## Advanced Usage

### With Playwright (Browser Testing)

```bash
# Install Playwright browsers in container
docker run --rm -it rothackers/wshawk /bin/bash
playwright install chromium
wshawk-advanced ws://target.com --playwright
```

### Network Scanning

```bash
# Scan multiple targets
docker run --rm rothackers/wshawk ws://target1.com
docker run --rm rothackers/wshawk ws://target2.com

# Use custom network
docker network create wshawk-net
docker run --rm --network wshawk-net rothackers/wshawk ws://target.com
```

### CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: WebSocket Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run WSHawk
        run: |
          docker pull rothackers/wshawk:latest
          docker run --rm rothackers/wshawk ws://staging-server.com
```

---

## Troubleshooting

### Permission Issues

```bash
# Run as current user
docker run --rm --user $(id -u):$(id -g) rothackers/wshawk ws://target.com
```

### Network Issues

```bash
# Use host network
docker run --rm --network host rothackers/wshawk ws://localhost:8765

# Check container network
docker run --rm rothackers/wshawk ip addr
```

### Volume Mount Issues

```bash
# Use absolute path
docker run --rm -v /absolute/path/reports:/app/reports rothackers/wshawk ws://target.com
```

---

## Image Information

- **Base Image:** python:3.11-slim
- **Size:** ~150MB (optimized multi-stage build)
- **User:** Non-root (wshawk:1000)
- **Entrypoint:** wshawk
- **Working Directory:** /app

---

## Security Best Practices

1. **Always use specific version tags**
   ```bash
   docker pull rothackers/wshawk:2.0.7
   ```

2. **Run as non-root user** (default)
   ```bash
   docker run --rm --user wshawk rothackers/wshawk ws://target.com
   ```

3. **Use read-only filesystem**
   ```bash
   docker run --rm --read-only rothackers/wshawk ws://target.com
   ```

4. **Limit resources**
   ```bash
   docker run --rm --memory=512m --cpus=1 rothackers/wshawk ws://target.com
   ```

---

## Support

- **GitHub:** https://github.com/noobforanonymous/wshawk
- **Docker Hub:** https://hub.docker.com/r/rothackers/wshawk
- **Issues:** https://github.com/noobforanonymous/wshawk/issues

---

## License

AGPL-3.0 License - See LICENSE file for details
