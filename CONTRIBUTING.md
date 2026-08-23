# Contributing

Thanks for considering a contribution to Sentinel.

## Workflow

1. Fork the repo and branch from `main`: `feat/<slug>`, `fix/<slug>`,
   `chore/<slug>`, `docs/<slug>`.
2. Make your change. Add or update tests for any behavioral change
   (`cargo test`).
3. Commit using [Conventional Commits](https://www.conventionalcommits.org/)
   — see [Commit format](#commit-format) below.
4. Open a PR against `main`. Describe what changed and why, and link any
   related issue.
5. Squash-merge once reviewed.

## Local checks (run before opening a PR)

```bash
cargo build --release   # zero warnings, zero errors is the bar
cargo test               # all unit/integration tests
cargo clippy              # lint
```

## Commit format

`<type>: <description>` — imperative, concise.

Allowed types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`,
`build`, `ci`.

## Versioning

This project follows [SemVer](https://semver.org/) and stays pre-1.0
(`0.x.x`) during active development:

| Segment | Meaning | When it bumps |
|---|---|---|
| `0.x.x` | Pre-1.0 / unstable | Default while the API/architecture can still change |
| `x.0.0` | Major | Breaking changes (only after an explicit decision to cut `1.0.0`) |
| `0.x.0` | Minor | New backwards-compatible functionality |
| `0.0.x` | Patch | Fixes |

## Adding a new module

Modules implement the `Module` trait (see `src/modules/mod.rs`) and are
registered in `ModuleRegistry::build_default()`. Read
[`docs/MODULES.md`](docs/MODULES.md) first — it documents the confidence-
level conventions and two-phase dispatch pipeline every module has to fit
into.

## Scope and ethics

Sentinel is an offensive-security tool. New capabilities should stay in the
enumeration/detection/reporting space this project already occupies —
active exploitation, weaponized payload delivery, or anything that removes
the "no AI, no black box, fully auditable" guarantee described in the
README's "Adaptive Orchestration" section is out of scope without a design
discussion first (open an issue).

## Reporting security issues

See [SECURITY.md](SECURITY.md) — do NOT open a public issue for a
vulnerability in Sentinel itself.
