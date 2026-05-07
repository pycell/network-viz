# Network Policy Visualization

Read-only network policy visualization and explanation engine for pfSense, iptables, NAT, routing, VPNs, and later Kubernetes/WireGuard environments.

## Sprint 0 Stack

- Backend: Python 3.12, FastAPI, Pydantic, SQLAlchemy async.
- Package manager: `uv`.
- Frontend: React, TypeScript, Vite.
- Storage: PostgreSQL.
- Deployment foundation: Dockerfile and Docker Compose.

## Local Development

Install dependencies:

```sh
make install
```

Run the backend:

```sh
make dev-backend
```

Run the frontend:

```sh
make dev-frontend
```

The backend serves API endpoints on `http://localhost:8000`.
The frontend dev server runs on `http://localhost:5173`.

## Docker

Create an environment file:

```sh
cp .env.example .env
```

Run the app and PostgreSQL:

```sh
make docker-up
```

The containerized app is available at `http://localhost:8000`.

## Useful Commands

```sh
make test
make lint
make format
make typecheck
make docker-build
make docker-down
```

## Current Status

Sprint 0 foundation is in place. Sprint 1 should add the pfSense XML collector and normalized parsing tests.
