# AGENTS.md

Guidance for coding agents (Claude Code and others) working in this repository.
See `CLAUDE.md` for the fuller working approach; this file is the quick command reference.

Everything runs inside Docker via the Makefile — no host Python/Node toolchain is assumed.

## Commands

| Task | Command |
| ---- | ------- |
| Run (API + web UI, hot reload) | `make up` |
| Stop | `make down` |
| Test | `make test` |
| Single test | `docker compose run --rm api pytest -q -k <name>` |
| Lint (Python, ruff) | `make lint` |
| Offline end-to-end test | `make e2e` |

The frontend lives in `frontend/` and is a Vite + React + TypeScript app; its own checks are
`npm run lint` (`tsc --noEmit`) and `npm run build`, run from that directory.

## Layout

- `src/lawless_waf/` — Python API, MCP server, WAF log analysis
- `frontend/` — Vite + React + TypeScript + Tailwind web UI
- `tests/` — pytest suite (`test_e2e.py` is the offline end-to-end test)
- `docs/` — documentation and screenshots

## Conventions

- Commits follow Conventional Commits (`type(scope): summary`).
- Never commit secrets or credentials; configuration lives in a gitignored `.env`.
- Keep changes surgical — touch only what the task requires.
