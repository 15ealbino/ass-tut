# Python → Assembly Tutorial

A full-stack web app that lets you write Python code and see it mapped line-by-line to equivalent C and then x86 Assembly. Each Python line is color-coded so you can trace it through the full compilation pipeline interactively.

## Architecture

```
User browser
    │
    ▼
Frontend (Vite + React, :5173)
    │  POST /compile  { code, method }
    ▼
Backend (FastAPI + uvicorn, :8000)
    ├── transpiler.py         Python AST → C  (tracks py_line → c_lines)
    │                         Stdlib shims for time / math / random / sys / json
    ├── compile.py            method=transpile: C → gcc -S -O0 → parse .loc → line_map
    ├── pyghidra_compile.py   method=pyghidra:  Nuitka → ELF → Ghidra (asm + decomp C)
    ├── auth.py               bcrypt + JWT
    └── main.py               routes: /auth/register  /auth/login  /compile  /health
    │
    ▼
PostgreSQL 16 (users table)
```

`method=transpile` is the default and the only path that requires no extra installs. `method=pyghidra` is an optional heavyweight backend covered in [Optional: PyGhidra alternative compile backend](#optional-pyghidra-alternative-compile-backend) below — if its toolchain is absent the endpoint returns HTTP 503 with a precise reason and the default path is unaffected.

Either path returns the same response shape. For `transpile`, the response carries a `line_map` keyed by Python line number so clicking any line in the editor highlights the corresponding C and assembly lines. For `pyghidra`, `line_map` is always `{}` (Nuitka's CPython glue makes line-accurate tracing infeasible).

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
Compile Python to C and Assembly. No auth required.

```json
// Request
{
  "code": "x = 1\nprint(x)",
  "method": "transpile"
}

// Response 200
{
  "c_code": "...",
  "asm_code": "...",
  "line_map": {
    "1": { "c_lines": [3, 4], "asm_lines": [12, 13], "color": "#4e79a7" }
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `code` | string (≤10 000 chars / ≤200 lines) | — | Python source |
| `method` | `"transpile"` \| `"pyghidra"` | `"transpile"` | Compile backend. `transpile` is the AST→C→gcc path with per-line tracing. `pyghidra` runs Nuitka → ELF → Ghidra and returns disassembly plus decompiled C; `line_map` is empty for this method. |

**Status codes**

| Code | Cause |
|------|-------|
| `200` | Success |
| `422` | Unsupported Python construct, oversize input, or a Nuitka/Ghidra failure (when `method=pyghidra`) |
| `503` | `method=pyghidra` was requested but the toolchain (Nuitka, pyghidra, or `GHIDRA_INSTALL_DIR`) is not configured — see the PyGhidra setup section below |

Supported Python for `transpile`: assignment, augmented assignment, `for x in range(...)`, `while`, `if`/`elif`/`else`, `print()`, `def`, `return`, `break`, `continue`, basic arithmetic, comparisons, boolean `and`/`or`, and the standard-library shims `time`, `math`, `random`, `sys`, `json.dumps`.

### `GET /health`
Returns `{"status":"ok"}`. No auth required. Useful for liveness checks.

---

## Optional: PyGhidra alternative compile backend

The `pyghidra` compile method runs the user's Python through **Nuitka** to produce a native ELF binary, then drives **Ghidra** (via the [`pyghidra`](https://pypi.org/project/pyghidra/) package) to extract the disassembly and decompiled C of `main`. It is purely additive — the default `transpile` backend keeps working with no extra installs, and selecting `method=pyghidra` on a server without the toolchain returns HTTP 503 with the missing dependency named.

This path is heavyweight: each call spawns Nuitka (which itself invokes gcc) and then runs a full Ghidra auto-analysis pass. Expect ~20–60 s per request on a small program, ~1 GB of RAM headroom, and a JDK on the host.

### Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| JDK | 17+ | Ghidra 11.x requires JDK 17 minimum |
| Ghidra | 11.x | Download from the [official release page](https://github.com/NationalSecurityAgency/ghidra/releases) |
| Python packages | — | `nuitka` and `pyghidra` are already listed in `backend/requirements.txt` |

### Step 1 — Install a JDK

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y openjdk-17-jdk

# Oracle Linux / RHEL / Fedora
sudo dnf install -y java-17-openjdk-devel
```

Verify:

```bash
java -version
# → openjdk version "17.x.x" ...
```

### Step 2 — Install Ghidra

Pick the latest release tagged `Ghidra_X.Y.Z_build` from the [GitHub releases](https://github.com/NationalSecurityAgency/ghidra/releases). The example below uses 11.2.1 — bump the version strings to whatever is current.

```bash
GHIDRA_VER=11.2.1_PUBLIC_20241105
cd /opt
sudo curl -L -o ghidra.zip \
  "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_${GHIDRA_VER}.zip"
sudo unzip -q ghidra.zip
sudo rm ghidra.zip
# Result: /opt/ghidra_11.2.1_PUBLIC/
```

### Step 3 — Export `GHIDRA_INSTALL_DIR` system-wide

`pyghidra` discovers Ghidra exclusively through this environment variable; without it, every `method=pyghidra` request returns 503.

```bash
echo 'export GHIDRA_INSTALL_DIR=/opt/ghidra_11.2.1_PUBLIC' \
  | sudo tee /etc/profile.d/ghidra.sh
sudo chmod +x /etc/profile.d/ghidra.sh
source /etc/profile.d/ghidra.sh
```

If the backend runs under systemd, also add it to the unit:

```ini
# /etc/systemd/system/ass-tut-backend.service
[Service]
Environment=GHIDRA_INSTALL_DIR=/opt/ghidra_11.2.1_PUBLIC
```

Then `sudo systemctl daemon-reload && sudo systemctl restart ass-tut-backend`.

### Step 4 — Install the Python deps

If you previously installed `backend/requirements.txt` before this feature was added, re-run it so Nuitka and pyghidra get picked up:

```bash
cd backend
pip install -r requirements.txt
```

### Step 5 — Restart the backend and verify

```bash
uvicorn app.main:app --reload
```

In another terminal:

```bash
curl -s -X POST http://localhost:8000/compile \
  -H 'Content-Type: application/json' \
  -d '{"code":"x = 1\nprint(x)","method":"pyghidra"}'
```

Expected outcomes:

| Response | Meaning |
|----------|---------|
| `200` with a non-empty `asm_code` containing entries like `00401000:` | Toolchain is healthy |
| `503` `{"detail":"PyGhidra unavailable: Nuitka not installed ..."}` | `pip install` did not run; redo Step 4 |
| `503` `{"detail":"PyGhidra unavailable: pyghidra not installed ..."}` | Same — `pip install -r requirements.txt` |
| `503` `{"detail":"PyGhidra unavailable: GHIDRA_INSTALL_DIR is not set ..."}` | The variable is not visible to the uvicorn process; redo Step 3, then restart the backend |
| `422` with a Nuitka stderr tail | The user's Python is valid for `transpile` but Nuitka rejected it — surface the error to the caller |

The default backend keeps working in parallel:

```bash
curl -s -X POST http://localhost:8000/compile \
  -H 'Content-Type: application/json' \
  -d '{"code":"x = 1\nprint(x)"}'   # implicit method=transpile
# → 200, same shape, with a populated line_map
```

### Docker

The image at `backend/Dockerfile` is `python:3.12-slim` and does **not** ship a JDK or Ghidra. To enable the PyGhidra backend in the containerized stack, extend the Dockerfile:

```dockerfile
FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
      gcc gcc-multilib \
      openjdk-17-jdk-headless \
      curl unzip \
    && rm -rf /var/lib/apt/lists/*

ENV GHIDRA_VER=11.2.1_PUBLIC_20241105
ENV GHIDRA_INSTALL_DIR=/opt/ghidra_11.2.1_PUBLIC

RUN curl -L -o /tmp/ghidra.zip \
      "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_${GHIDRA_VER}.zip" \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && rm /tmp/ghidra.zip

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

This roughly doubles the image size (~2 GB once Ghidra is extracted). If you only need the transpile backend in production, leave the original Dockerfile in place.

---

## Deployment

### Docker (self-hosted)

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

For production, put a TLS-terminating reverse proxy (nginx, Caddy, etc.) in front of port 80. The recommended path for a public deployment is the Oracle Cloud VM walkthrough below — it bundles Caddy and Let's Encrypt out of the box.

---

### Oracle Cloud VM with HTTPS (Caddy + Cloudflare)

This is the recommended production path. The stack runs as containers on an Oracle Cloud Always-Free VM; a Caddy sidecar terminates TLS, fetches and renews Let's Encrypt certificates automatically, and proxies traffic to the frontend.

**End state.** `https://assembly-tutorial.com` serves the app over HTTPS with a real (browser-trusted) certificate. The backend and frontend containers are not directly reachable from the public internet — only Caddy listens on `:80` and `:443`.

#### Prerequisites

- An Oracle Cloud VM instance (Always-Free `VM.Standard.E2.1.Micro` or larger), Oracle Linux 8/9 or Ubuntu 22.04+
- SSH access to the VM as a user in the `docker` group
- A domain registered and managed via Cloudflare (this guide uses `assembly-tutorial.com`)
- The repo cloned onto the VM (`/home/<user>/ass-tut` or similar)

#### Step 1 — Add the DNS A record in Cloudflare

In the Cloudflare dashboard, select `assembly-tutorial.com` → **DNS → Records → Add record**:

| Field | Value |
|-------|-------|
| Type | `A` |
| Name | `@` (the apex — Cloudflare resolves `@` to `assembly-tutorial.com`) |
| IPv4 address | the VM's public IP (find in OCI console → Instance details) |
| Proxy status | **DNS only** (gray cloud) — required so Let's Encrypt can complete the HTTP-01 challenge on first issuance |
| TTL | `Auto` |

Verify propagation from any machine:

```bash
dig +short assembly-tutorial.com
```

The output must be the VM's public IP. If it shows nothing or a Cloudflare IP (`104.x` / `172.x`), the record is not yet live or proxying is on.

Once Caddy has issued the certificate (after Step 5), you may flip the proxy status to **Proxied** (orange cloud) — set Cloudflare SSL/TLS mode to **Full (strict)** before doing so to avoid redirect loops.

#### Step 2 — Open ports 80 and 443 in the Oracle Cloud security list

In the OCI console: **Networking → Virtual Cloud Networks → your VCN → Security Lists → Default Security List → Add Ingress Rules**:

| Source CIDR | IP Protocol | Destination Port |
|-------------|-------------|------------------|
| `0.0.0.0/0` | TCP | `80` |
| `0.0.0.0/0` | TCP | `443` |
| `0.0.0.0/0` | UDP | `443` |

UDP `443` is for HTTP/3, which Caddy enables by default. Omit it if you don't want HTTP/3.

#### Step 3 — Open ports 80 and 443 in the VM firewall

Oracle Linux and Ubuntu ship with `iptables` blocking inbound traffic by default. Open the ports and persist the rules:

```bash
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p udp --dport 443 -j ACCEPT
```

Save the rules so they survive a reboot:

```bash
# Oracle Linux
sudo service iptables save

# Ubuntu / Debian
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

#### Step 4 — Install Docker and Docker Compose v2

```bash
# Oracle Linux 8/9
sudo dnf install -y docker
sudo systemctl enable --now docker

# Ubuntu 22.04+
sudo apt update && sudo apt install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
```

Add yourself to the `docker` group so you can run compose without `sudo`, then log out and back in:

```bash
sudo usermod -aG docker $USER
```

#### Step 5 — Configure environment and start the stack

From the cloned repo on the VM:

```bash
cd ~/ass-tut
cp .env.example .env
```

Edit `.env` and set both variables:

```bash
SECRET_KEY=$(openssl rand -hex 32)
DOMAIN=assembly-tutorial.com
```

Bring up the stack with the production overlay — this adds the Caddy reverse proxy and removes the direct public ports for the backend and frontend:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Watch the certificate issuance live:

```bash
docker compose logs -f caddy
```

You should see `certificate obtained successfully` for `assembly-tutorial.com` within ~30 seconds. Press `Ctrl-C` to detach (the container keeps running).

#### Step 6 — Verify

```bash
curl -I https://assembly-tutorial.com
# → HTTP/2 200
```

Open the URL in a browser — you should see the editor, served over a valid certificate with no warning.

#### Updating the deployment

After pulling new commits on the VM:

```bash
cd ~/ass-tut
git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

Caddy keeps its certificates in the `caddy_data` named volume, so rebuilds and restarts do not re-trigger Let's Encrypt issuance.

#### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `dig` returns a Cloudflare IP, not your VM IP | Proxy is on (orange cloud) | Set the record to **DNS only** for the first cert; re-enable proxy afterwards |
| Caddy logs `acme: error: 400 ... no TXT record` or hangs on challenge | Port 80 blocked on Oracle security list or VM iptables | Re-check Step 2 and Step 3 |
| Browser shows `too many redirects` after enabling Cloudflare proxy | Cloudflare SSL mode set to **Flexible** | Change to **Full (strict)** in Cloudflare SSL/TLS settings |
| `docker compose` reports `address already in use` for port 80 | System nginx or apache is bound to `:80` | `sudo systemctl disable --now nginx apache2` |
| HTTP 502 from Caddy | Frontend container not healthy | `docker compose logs frontend`; rebuild with `--build` |

---

### Vercel

> **gcc requirement**: The `/compile` endpoint shells out to `gcc` at runtime. Vercel's serverless runtime does not ship gcc. The auth endpoints (`/auth/register`, `/auth/login`, `/health`) work fine; the compile feature requires a runtime with gcc installed. If you need compile functionality in production, use the Docker path above on Railway, Render, or Fly.io. If you only need the auth layer on Vercel, proceed below.

#### Prerequisites

- [Vercel CLI](https://vercel.com/docs/cli): `npm i -g vercel`
- An external PostgreSQL database — [Neon](https://neon.tech) offers a free tier and works with `asyncpg`
- `openssl` to generate the secret key

---

#### Step 1 — Provision a PostgreSQL database

Create a database on Neon (or any managed PostgreSQL provider) and copy the connection string. Prefix it with `asyncpg`:

```
postgresql+asyncpg://user:password@host/dbname?sslmode=require
```

---

#### Step 2 — Run migrations against the production database

From your local machine, point Alembic at the production database and apply the schema:

```bash
cd backend
DATABASE_URL="postgresql+asyncpg://user:password@host/dbname?sslmode=require" alembic upgrade head
```

---

#### Step 3 — Add backend Vercel config

Create `backend/vercel.json`:

```json
{
  "builds": [
    { "src": "app/main.py", "use": "@vercel/python" }
  ],
  "routes": [
    { "src": "/(.*)", "dest": "app/main.py" }
  ]
}
```

---

#### Step 4 — Deploy the backend

```bash
cd backend
vercel --prod
```

In the Vercel dashboard under **Project → Settings → Environment Variables**, set:

| Variable | Value |
|----------|-------|
| `DATABASE_URL` | `postgresql+asyncpg://user:password@host/dbname?sslmode=require` |
| `SECRET_KEY` | output of `openssl rand -hex 32` |
| `JWT_ALGORITHM` | `HS256` |
| `JWT_EXPIRE_MINUTES` | `1440` |
| `DEBUG` | `false` |

Note the deployed backend URL (e.g., `https://ass-tut-backend.vercel.app`) — you need it in Step 7.

---

#### Step 5 — Update CORS to allow the production frontend

The backend currently only allows `localhost` origins. Edit `backend/app/main.py`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "https://your-frontend.vercel.app",   # replace with your actual frontend URL
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Redeploy after this change:

```bash
cd backend
vercel --prod
```

---

#### Step 6 — Wire the frontend to the production backend URL

The frontend sends all requests to the relative path `/api`, which the Vite dev proxy rewrites to `localhost:8000`. In production the Vite proxy is not active, so the frontend must target the backend URL directly.

Edit `frontend/src/api.ts`, line 1:

```diff
-const BASE = '/api'
+const BASE = import.meta.env.VITE_API_BASE_URL ?? '/api'
```

---

#### Step 7 — Add frontend Vercel config

Create `frontend/vercel.json` to handle client-side routing (React Router requires all paths to serve `index.html`):

```json
{
  "rewrites": [
    { "source": "/(.*)", "destination": "/index.html" }
  ]
}
```

---

#### Step 8 — Deploy the frontend

```bash
cd frontend
vercel --prod
```

In the Vercel dashboard for the **frontend** project under **Settings → Environment Variables**, set:

| Variable | Value |
|----------|-------|
| `VITE_API_BASE_URL` | `https://your-backend.vercel.app` (no trailing slash) |

Trigger a redeploy after setting the variable so Vite bakes it into the build:

```bash
cd frontend
vercel --prod
```

---

#### Step 9 — Verify

```bash
curl https://your-backend.vercel.app/health
# → {"status":"ok"}
```

Open `https://your-frontend.vercel.app` in a browser, register an account, and confirm login succeeds.
