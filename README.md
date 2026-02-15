[![Docker](https://github.com/amoisis/docker-dash/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/amoisis/docker-dash/actions/workflows/docker-publish.yml)
[![Dependabot Updates](https://github.com/amoisis/docker-dash/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/amoisis/docker-dash/actions/workflows/dependabot/dependabot-updates)
[![CodeQL](https://github.com/amoisis/docker-dash/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/amoisis/docker-dash/actions/workflows/github-code-scanning/codeql)

# Overview
`docker-dash` is a dynamic configuration service that automatically creates and manages Cloudflare Tunnels and Access Applications based on Docker container labels. It listens to the Docker event stream for container start/stop events and configures public hostnames and access policies in Cloudflare accordingly, providing a "set-it-and-forget-it" solution for exposing your services securely.

## Features

- **Automated Ingress Rules**: Automatically creates Cloudflare Tunnel ingress rules for your services.
- **Automated CNAME Records**: Automatically creates CNAME records for your services.
- **Automated Access Applications**: Automatically creates and infigures Cloudflare Access Applications to secure your public routes.
- **Label-Driven Configuration**: Use Docker labels as the single source of truth for all configurations.
- **Live State Caching**: Maintains an in-memory cache of your Cloudflare configuration for efficient updates.
- **Web UI**: lightweight web interface to view the application's cached state for easy troubleshooting.

## Usage

The recommended way to run `docker-dash` is as a Docker container with access to the host's Docker socket.

## Security Considerations

Giving `docker-dash` access to the Docker socket is a significant security consideration. The application runs with the same privileges as the Docker daemon, which is typically `root`. This means that a vulnerability in `docker-dash` could potentially be exploited to gain privileged access to the host system.

To mitigate this risk, it is strongly recommended to:

- Run `docker-dash` in a properly secured and isolated environment.
- Follow the principle of least privilege and only grant the necessary permissions to the application.
- Regularly update to the latest version of `docker-dash` to ensure you have the latest security patches.

## Cloudflare API Permissions

The API Token you provide requires the following permissions to function correctly:

| Permission Group | Permission | Access |
|---|---|---|
| Account | Zero Trust | Read |
| Account | Tunnels | Read, Edit |
| Account | Access: Apps and Policies | Read, Edit |
| Account | Access: Identity Providers | Read |
| Zone | DNS | Read, Edit |

### Docker Compose Example

```yaml
version: '3.8'

services:
  docker-dash:
    container_name: docker-dash
    image: amoisis/docker-dash:latest # Replace with your image if building locally
    restart: unless-stopped
    ports:
      - "3445:3445" 
    environment:
      # Required Cloudflare Credentials
      - CF_API_TOKEN=your_cloudflare_api_token
      - CF_ACCOUNT_ID=your_cloudflare_account_id
      
      # Set to DEBUG to enable the web UI
      - LOG_LEVEL=INFO 
    volumes:
      # Required to listen to Docker events
      # Option 1: Mount the Docker socket directly (default)
      - /var/run/docker.sock:/var/run/docker.sock:ro
      
      # Option 2: Use a Docker socket proxy
      # environment:
      #  - DOCKER_HOST=tcp://<proxy-host>:<proxy-port>
```

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `CF_API_TOKEN` | **Yes** | Your Cloudflare API Token with the required permissions. |
| `CF_ACCOUNT_ID` | **Yes** | Your Cloudflare Account ID. |
| `LOG_LEVEL` | **No** | Logging level. Defaults to `INFO`. |
| `CACHE_REFRESH_INTERVAL` | **No** | How often (in seconds) to refresh the Cloudflare cache. Defaults to `300` (5 minutes). |
| `MANAGE_DNS_RECORDS` | **No** | Set to `false` to disable automatic DNS record creation/updates. Defaults to `true`. |
| `DNS_HA_MODE` | **No** | Set to `true` to enable High Availability mode. When enabled, if a DNS record points to a different tunnel, it won't be updated (allows multiple tunnels to serve the same hostname). Defaults to `false`. |

## High Availability (HA) Configuration

Cloudflare Tunnels natively support high availability when multiple tunnels serve the same hostname. To enable this:

### How It Works

1. **Configure the same hostname in multiple tunnels** - Add ingress rules for the same hostname to different tunnels
2. **Cloudflare handles load balancing** - Cloudflare's infrastructure automatically:
   - Detects all active tunnels serving a hostname
   - Load balances traffic between them
   - Automatically fails over if a tunnel becomes unavailable

### Using docker-dash for HA

**Option 1: Enable DNS_HA_MODE (Recommended for HA)**

Set `DNS_HA_MODE=true` in your docker-dash environment. This tells docker-dash to:
- Create ingress rules in multiple tunnels without updating DNS
- Leave existing DNS records pointing to any tunnel (Cloudflare handles routing)
- Log when DNS points to a different tunnel without changing it

```yaml
environment:
  - DNS_HA_MODE=true
```

**Option 2: Manual DNS Management**

Set `MANAGE_DNS_RECORDS=false` to disable automatic DNS updates entirely:
- docker-dash will only manage tunnel ingress rules
- You manually create DNS records pointing to one of your tunnels
- Cloudflare automatically uses all tunnels with matching ingress rules

```yaml
environment:
  - MANAGE_DNS_RECORDS=false
```

**Option 3: Single Tunnel (Default)**

With default settings, docker-dash will:
- Update DNS records to point to the tunnel being configured
- Only one tunnel will actively serve each hostname

### Example HA Setup

```yaml
# On Server 1
services:
  app:
    labels:
      - "docker.dash.tunnel=server1-tunnel"
      - "docker.dash.hostname=app.example.com"
      - "docker.dash.service=http://app:8080"

# On Server 2  
services:
  app:
    labels:
      - "docker.dash.tunnel=server2-tunnel"
      - "docker.dash.hostname=app.example.com"
      - "docker.dash.service=http://app:8080"
```

With `DNS_HA_MODE=true`, both tunnels will serve `app.example.com` with automatic failover.

## Configuration via Docker Labels

The entire configuration is managed by adding labels to the Docker containers you wish to expose.

### Core Routing Labels

| Label | Required | Example | Description |
|---|---|---|---|
| `docker.dash.enable` | **Yes** | `true` | Must be set to `"true"` for `docker-dash` to process the container. |
| `docker.dash.tunnel` | **Yes** | `my-tunnel-name` | The name of the Cloudflare Tunnel to add the route to. |
| `docker.dash.hostname` | **Yes** | `app.example.com` | The public hostname for the service. |
| `docker.dash.service` | **Yes** | `http://app-container:8080` | The internal service URL that the tunnel will proxy to. |

### Access Application Labels (Optional)

These labels allow you to automatically secure the public hostname with a Cloudflare Access Application Policies.

| Label | Example | Description |
|---|---|---|
| `docker.dash.application.access.policy` | `Allow-Admins,Bypass-Internal` | A comma-separated list of Access Policy names to apply. The order determines the precedence. |
| `docker.dash.application.access.loginmethods` | `AzureAD` | A comma-separated list of Identity Provider names to allow for login. |
| `docker.dash.application.access.instantauth` | `true` | If set to `"true"` and only one login method is specified, users will be redirected to it instantly, skipping the login method selection screen. |
| `docker.dash.application.access.icon` | `https://example.com/icon.png` | A URL for the icon to display on the App Launcher. |

### Full Example with a Service

Here is how you would label a service (e.g., `ntfy`) in your `docker-compose.yml`:

```yaml
services:
  ntfy:
    image: binwiederhier/ntfy
    # ... other container configuration ...
    labels:
      # --- Core Routing ---
      - "docker.dash.enable=true"
      - "docker.dash.tunnel=my-main-tunnel"
      - "docker.dash.hostname=ntfy.example.com"
      - "docker.dash.service=http://ntfy:80"

      # --- Access Application ---
      - "docker.dash.application.access.policy=Admins-Only"
      - "docker.dash.application.access.loginmethods=Google"
      - "docker.dash.application.access.instantauth=true"
      - "docker.dash.application.access.icon=https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/ntfy.png"
```

## Debugging

To assist with setup and troubleshooting, `docker-dash` includes a lightweight web interface.

The web page will be available at `http://<host-ip>:3445`.

The page provides a read-only view of the application's internal cache, showing you exactly how it sees your Cloudflare configuration, including:
- Tunnels and their status
- Access Policies
- Identity Providers
- Access Applications
- A summary of all hostnames currently configured for each tunnel.