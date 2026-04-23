# Python → Assembly Tutorial

A full-stack web app that lets you write Python code and see it mapped line-by-line to equivalent C and then x86 Assembly. Each Python line is color-coded so you can trace it through the full compilation pipeline interactively.

## Architecture

```
User browser
    │
    ▼
Frontend (Vite + React, :5173)
    │  POST /compile  (JWT in Authorization header)
    ▼
Backend (FastAPI + uvicorn, :8000)
    ├── transpiler.py  Python AST → C  (tracks py_line → c_lines)
    ├── compile.py     C → gcc -S -O0 → parse .loc → combined line_map
    ├── auth.py        bcrypt + JWT
    └── main.py        routes: /auth/register  /auth/login  /compile  /health
    │
    ▼
PostgreSQL 16 (users table)
```

The response carries a `line_map` keyed by Python line number; clicking any line in the editor highlights the corresponding C and assembly lines.

---

## Prerequisites

| Tool | Minimum version | Notes |
|------|----------------|-------|
| Python | 3.12 | `python --version` |
| Node.js | 20 | `node --version` |
| npm | 10 | bundled with Node 20 |
| gcc | any recent x86-64 | `gcc --version`; must support `-S -O0` |
| PostgreSQL | 16 | only needed for the non-Docker path |
| Docker + Compose | 24 / v2 | only needed for the Docker path |

---

## Running locally without Docker

### 1. Clone and configure environment

```bash
git clone <repo-url>
cd ass-tut
cp .env.example backend/.env
```

Open `backend/.env` and set each variable:

| Variable | Example | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | `postgresql+asyncpg://postgres:postgres@localhost:5432/asstut` | Async PostgreSQL connection string |
| `SECRET_KEY` | output of `openssl rand -hex 32` | JWT signing secret — change before deploying |
| `JWT_ALGORITHM` | `HS256` | Algorithm used to sign tokens — do not change |
| `JWT_EXPIRE_MINUTES` | `1440` | How long a login token stays valid (minutes) |
| `DEBUG` | `true` | Seeds a dev account on startup (see below) |

#### Debug / dev account

When `DEBUG=true` is set in `backend/.env` (enabled by default in the checked-in `.env`), the backend automatically creates a test account on startup so you can log in immediately without registering:

| Field | Value |
|-------|-------|
| Email | `dev@example.com` |
| Password | `devpassword` |

The seed is idempotent — if the account already exists it is left unchanged. To disable this behaviour, remove or set `DEBUG=false` in `backend/.env`. Do **not** add `DEBUG=true` to production deployments.

### 2. Create the database

```bash
psql -U postgres -c "CREATE DATABASE asstut;"
```

### 3. Install backend dependencies and run migrations

```bash
cd backend
pip install -r requirements.txt
alembic upgrade head
```

### 4. Start the backend

```bash
uvicorn app.main:app --reload
```

The API is now available at `http://localhost:8000`. Visit `http://localhost:8000/health` to confirm it returns `{"status":"ok"}`.

### 5. Install frontend dependencies and start the dev server

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` in your browser. The Vite dev server proxies all `/api` requests to `:8000`.

---

## Running locally with Docker

Docker Compose starts PostgreSQL, the backend (with migrations), and the frontend in one command.

### 1. Set SECRET_KEY (optional for local dev)

In production, set `SECRET_KEY` to a strong random value before running:

```bash
export SECRET_KEY=$(openssl rand -hex 32)
```

For local development you can skip this step — `docker-compose.yml` provides a default value (`dev-secret-do-not-use-in-production-32x`) automatically. Never use that default in a production deployment.

### 2. Start all services

```bash
docker-compose up --build
```

The backend container automatically runs `alembic upgrade head` before starting uvicorn, so no manual migration step is needed.

### 3. Open the app

| Service | URL |
|---------|-----|
| Frontend | `http://localhost:5173` |
| Backend API | `http://localhost:8000` |
| PostgreSQL | `localhost:5432` (user: `postgres`, password: `postgres`, db: `asstut`) |

### 4. Dev / debug account

The default docker-compose setup sets `DEBUG=true`, which seeds a test account on startup so you can log in immediately without registering:

| Field | Value |
|-------|-------|
| Email | `dev@example.com` |
| Password | `devpassword` |

The seed is idempotent — restarting the stack will not duplicate the account.

### 5. Stop the stack

Preserve the postgres data volume:

```bash
docker-compose down
```

Also delete the postgres data volume:

```bash
docker-compose down -v
```

---

## Running Tests

Tests use an in-memory SQLite database — no running PostgreSQL instance needed.

```bash
cd backend
pytest
```

Run a single test file:

```bash
pytest tests/test_transpiler.py
```

Run a single test by name:

```bash
pytest tests/test_transpiler.py -k "test_for_loop"
```

Expected output ends with a line like:

```
====== X passed in 0.XXs ======
```

---

## API Reference

All routes are on the backend at `http://localhost:8000`.

### `POST /auth/register`
Register a new account. Returns a JWT.

```json
// Request
{ "email": "you@example.com", "password": "hunter2" }

// Response 201
{ "access_token": "<jwt>" }
```

### `POST /auth/login`
Authenticate an existing account. Returns a JWT.

```json
// Request
{ "email": "you@example.com", "password": "hunter2" }

// Response 200
{ "access_token": "<jwt>" }
```

### `POST /compile`
Transpile Python to C and Assembly. Requires `Authorization: Bearer <jwt>`.

```json
// Request
{ "code": "x = 1\nprint(x)" }

// Response 200
{
  "c_code": "...",
  "asm_code": "...",
  "line_map": {
    "1": { "c_lines": [3, 4], "asm_lines": [12, 13], "color": "#4e79a7" }
  }
}
```

Returns HTTP 422 if the Python uses unsupported constructs (e.g. classes, imports, list comprehensions).

### `GET /health`
Returns `{"status":"ok"}`. No auth required. Useful for liveness checks.

---

## Deployment

1. Generate a strong secret key:
   ```bash
   openssl rand -hex 32
   ```
2. Set `SECRET_KEY` to that value in your production environment (not in `.env`).
3. Build and start:
   ```bash
   docker-compose up --build -d
   ```
4. Migrations run automatically on backend startup (`alembic upgrade head` is the container entrypoint).

For production, put a TLS-terminating reverse proxy (nginx, Caddy, etc.) in front of port 5173.
