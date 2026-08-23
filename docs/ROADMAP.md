# Roadmap

Sentinel's 9 modules, 7 workflow modes, adaptive orchestration engine, and
attack-path correlation engine are implemented and covered by 130+ tests
(see the README for the current feature set). This file tracks what's
next — not a commitment or timeline, just the maintainer's current
thinking, revised as work lands.

## Planned

- **`--resume`** — resume an interrupted scan from a saved session ID
  instead of starting over.
- **Bundled wordlists** — ship common wordlists by default, or fetch them
  on first `--docker` use, instead of relying solely on the small built-in
  lists.
- **Persistent test infrastructure** — standing HTTP/FTP/SMB services for
  CI, so integration tests exercise real protocol behavior instead of only
  unit-level mocks.
- **Docker toggle from the TUI setup screen** — currently `--docker` is a
  CLI flag only; wiring it into the interactive setup screen would let TUI
  users opt in without relaunching headless.
- **Async scanner concurrency tuning for large CIDR ranges** — profile and
  optimize throughput when scanning `/16`+ ranges.

## Explicitly out of scope

Consistent with [CONTRIBUTING.md](../CONTRIBUTING.md#scope-and-ethics):
active exploitation, automated payload delivery, or anything that would
turn Sentinel's deterministic, fully-logged adaptive orchestration into a
black box. Sentinel enumerates, correlates, scores, and reports — it
doesn't fire exploits.

## Contributing to the roadmap

Open a GitHub issue to propose or discuss an item above, or a new one —
see [CONTRIBUTING.md](../CONTRIBUTING.md).
