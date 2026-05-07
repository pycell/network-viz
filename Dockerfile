FROM node:25-bookworm-slim AS frontend-build

WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json frontend/tsconfig.json frontend/tsconfig.node.json frontend/vite.config.ts frontend/index.html ./
COPY frontend/src ./src
RUN npm ci
RUN npm run build

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS app

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

COPY pyproject.toml uv.lock README.md ./
COPY backend ./backend
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

RUN uv sync --no-dev

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "network_viz.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
