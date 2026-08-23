# Governance

Sentinel is maintained under a **BDFL (Benevolent Dictator For Life)** model.

## Decision-making

- **Navin B. Ruas** ([@naviNBRuas](https://github.com/naviNBRuas)) is the
  sole maintainer and has final say on scope, architecture, and what merges.
- Design discussions happen in GitHub Issues/Discussions and are open to
  anyone; the maintainer weighs community input but is not bound by vote.
- There is no formal committee, working group, or voting process at this
  project's current size. This will be revisited if the contributor base
  grows enough to justify it.

## Contribution acceptance

- Pull requests are reviewed against [CONTRIBUTING.md](CONTRIBUTING.md) and
  merged at the maintainer's discretion.
- Breaking changes, new modules, or anything touching the adaptive
  orchestration/correlation engine get extra scrutiny — see
  `docs/MODULES.md` and `docs/AGENTS.md` for why those subsystems are
  designed the way they are before proposing a change to them.

## Releases

- Versioning follows [SemVer](https://semver.org/), pre-1.0 — see
  [CONTRIBUTING.md](CONTRIBUTING.md#versioning) for the exact scheme.
- The maintainer cuts releases and owns the `main` branch; no one else has
  merge or release authority at this time.

## Stepping down / succession

If the maintainer becomes unavailable long-term, ownership transfer will be
handled via the repository's GitHub organization settings, favoring an
active, trusted contributor if one exists at that time. There is no
standing succession plan beyond that, given the project's current size.
