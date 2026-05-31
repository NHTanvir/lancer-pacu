# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-pacu` — A Rust clone of the `pacu` AWS exploitation framework, part of the Lancer 2026 AI-era bug bounty toolkit. It provides an interactive REPL for enumerating, escalating, exploiting, persisting, evading detection, and exfiltrating data from AWS environments. All state-mutating AWS API calls are disabled by default (dry-run mode) and require an explicit `--armed` flag with written authorization from the account owner.

## Architecture

- `src/main.rs` — Binary entry point; initializes tracing, parses CLI args, and launches the REPL.
- `src/repl.rs` — Interactive REPL loop powered by `rustyline`; dispatches commands.
- `src/module.rs` — Module trait and `inventory`-based registration system for pluggable attack modules.
- `src/imds.rs` — IMDS (EC2 Instance Metadata Service) credential fetching.
- `src/modules/` — 27 attack modules organized by phase (ENUM, ESCALATE, EXPLOIT, PERSIST, EVADE, EXFIL); each in its own subdirectory with a `mod.rs`.
- `src/commands/` — Built-in REPL commands: `list.rs`, `proxy.rs`, `search.rs`, `sessions.rs`, `whoami.rs`.
- `src/db/` — Session persistence layer; `session.rs` manages AWS credential and session state.
- `migrations/` — Database migration files for the SQLite session store.

## Conventions

- Error propagation uses `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- All write/mutating AWS operations must check `ctx.armed` before executing; in dry-run mode, print what would happen and return safely.
- Modules that can exploit or mutate state additionally require `--exploit` alongside `--armed`.
- Library code lives in `src/lib.rs` (if present); binary entry point in `src/main.rs`.
- New modules are registered via `inventory::submit!` so they appear automatically in `list` output.
- AWS SDK crates are pinned to specific minor versions in `Cargo.toml`; bump deliberately and test.

## Build / test / run

```
build.bat                   # Windows → build\lancer-pacu.exe
build-windows.bat           # Windows packaged dist → dist\lancer-pacu-windows-x86_64\bin\lancer-pacu.exe
./build-linux.sh            # Linux/macOS → build/lancer-pacu
cargo build --release       # standard release build
cargo test                  # unit + integration tests
```

## Repo notes

- `plan.md` is local-only and must NOT be committed. It is gitignored; if ever tracked, run `git rm --cached plan.md`.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.
