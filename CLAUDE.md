# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A full-stack web app that lets users write Python code and see it mapped line-by-line to equivalent C and then x86 Assembly, with color-coded highlighting so each Python line traces through the full compilation pipeline.

## Commands

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload          # dev server on :8000
pytest                                  # run all tests
alembic upgrade head                   # apply DB migrations
```

### Frontend
```bash
cd frontend
npm install
npm run dev                            # dev server on :5173 (proxies /api → :8000)
npm run build
```

### Full stack (Docker)
```bash
docker-compose up --build              # postgres + backend + frontend
```

## Architecture

```
backend/app/
  transpiler.py   Python AST → C emitter; tracks py_lineno → [c_lineno] mapping
  compile.py      orchestrates transpile → gcc -S → asm line map → combined response
  auth.py         bcrypt hashing, JWT create/decode, DB helpers
  main.py         FastAPI routes: /auth/register, /auth/login, /compile, /health
  models.py       SQLAlchemy User model (UUID pk, email, password_hash)
  database.py     async engine + session factory
  config.py       pydantic-settings from .env

frontend/src/
  api.ts          fetch wrapper; JWT stored in memory (not localStorage)
  pages/Editor.tsx  three-pane view: CodeMirror input | C | Assembly + legend bar
  components/CodePane.tsx  colored stripe + line numbers for C/asm output
  pages/Login.tsx / Register.tsx
```

### Key data flow
1. User submits Python in CodeMirror editor → `POST /compile` (JWT required)
2. `compile.py` calls `transpiler.py` (Python AST → C with line map), then runs `gcc -S -O0` in a thread-pool executor
3. GCC `.loc` directives are parsed to build `c_lineno → [asm_lineno]` mapping
4. Combined `line_map: { py_line: { c_lines, asm_lines, color } }` returned to frontend
5. Frontend renders colored stripes + legend; clicking a Python line or legend chip highlights corresponding C and asm lines

### Concurrency
- FastAPI + uvicorn with multiple workers
- All `gcc` subprocess calls run in `asyncio.run_in_executor` so they never block the event loop
- 10-second timeout on gcc; 200-line / 10 000-char input cap

### Auth
- bcrypt via passlib; passwords never stored plain
- JWT via python-jose; frontend keeps token in JS memory only (lost on page refresh by design)

## Supported Python constructs
Assignment, augmented assignment, `for x in range(...)`, `while`, `if/elif/else`, `print()`, `def`, `return`, `break`, `continue`, basic arithmetic, comparisons, boolean `and`/`or`.

Anything else raises a `TranspileError` which the API returns as HTTP 422.
