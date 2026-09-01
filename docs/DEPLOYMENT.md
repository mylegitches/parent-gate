# NAS deployment

## Requirements

- Docker Engine with Compose.
- Nginx Proxy Manager running on the NAS.
- A hostname such as `focus.example.net` with a valid TLS certificate.
- The dashboard and Nginx Proxy Manager attached to the same Docker network.

Clients must use a hostname with a normally trusted HTTPS certificate. Do not disable certificate validation.

## Configure the service

Copy `.env.example` to `.env` and set at least:

```dotenv
APP_BASE_URL=https://focus.example.net
HOUSEHOLD_TIMEZONE=America/Chicago
COOKIE_SECURE=true
```

The included Compose file expects an existing Docker network named `proxy`. If the Nginx Proxy Manager stack uses a differently named external network, change the `networks` entry in `compose.yaml` to that name. If a shared network does not exist yet, create one and attach Nginx Proxy Manager to it.

## Start the dashboard

From the repository directory on the NAS:

```powershell
docker compose up -d --build
```

The application listens on port `8901` inside the container and publishes it as port `8901` on the NAS. Other containers on the shared proxy network can reach it as `operation-crackdown:8901`; it is also reachable directly as `http://NAS-IP:8901` for local troubleshooting.

## Configure Nginx Proxy Manager

Create a Proxy Host with:

- Domain: the hostname used in `APP_BASE_URL`.
- Scheme: `http`.
- Forward hostname: `operation-crackdown`.
- Forward port: `8901`.
- WebSocket support: optional; the current clients use polling.
- SSL certificate: a valid certificate for the hostname.
- Force SSL: enabled.
- HTTP/2: enabled.

Open the HTTPS hostname and complete initial setup. The first parent supplies a dashboard username/password and a separate 4–8 digit local-client PIN.

Nginx Proxy Manager Access Lists must not block `/api/client/v1/*`; device clients authenticate with their own bearer credentials. Application authentication remains enabled even if an additional proxy access layer is used for the human dashboard.

## Enroll devices

Sign in, choose **Add device**, and create a one-time code. It expires after ten minutes and is consumed by the first successful enrollment.

Every client installation receives a unique device ID and a separate random credential. The dashboard shows every enrolled installation independently.

## Persistence and backup

Persistent data is stored under `./data` by default. It includes the SQLite database and write-ahead-log files.

For a simple consistent backup:

1. Stop the dashboard container.
2. Copy the complete `data` directory to the NAS backup destination.
3. Start the container again.

Do not copy only `crackdown.db` while the container is writing; the current state may also reside in its WAL file.

## Updating

Pull or copy the updated repository, then rebuild:

```powershell
docker compose up -d --build
```

Database migrations run automatically and are additive. Back up the data directory before upgrading.

## Health check

The container exposes `/healthz` internally and defines a Docker health check. A healthy response resembles:

```json
{"ok":true,"version":"0.1.0"}
```
