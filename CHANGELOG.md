# Changelog

All notable changes to this extension are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Odd minor versions are pre-releases.

## [Unreleased]

## [1.0.1] - 2026-11-03

### Fixed

- The Marketplace listing no longer shows a "Preview" badge; 1.0 is a stable release.

## [1.0.0] - 2026-11-03

First stable release (1.0.0) on the Visual Studio Marketplace.

### Added

- **27 new detections** (25 rules, 2 heuristics) for 2025–2026 supply-chain attacks:
  - Invisible Unicode payloads (GlassWorm) and Trojan Source bidirectional characters.
  - Tampering with VS Code/Cursor settings, AI coding agent files (`CLAUDE.md`, `AGENTS.md`,
    MCP config), and CI workflow files; prompt injection aimed at AI agents.
  - Worm self-publishing (`npm publish`, `twine upload`, `cargo publish`, ...), critical when
    combined with token theft, and GitHub API abuse with stolen tokens.
  - CI runner memory scraping, cloud metadata credential theft, secret-store dumping,
    secret-scanner abuse (TruffleHog, gitleaks) and CI token harvesting.
  - Discord/Telegram/Slack/Signal session theft and exfiltration, blockchain command-and-control,
    destructive disk-wiping commands, and download-and-execute loaders.
  - Typosquat detection for Go, Cargo, Composer and Maven, and info-level telemetry and
    error-reporting endpoint rules.
- **Markdown report**: `DepThreat: Export Report (Markdown)` and the `depthreat.report.autoWrite`
  setting, which writes `.depthreat/report.md` after every scan.

### Changed

- Published as a regular release so it installs without opting into pre-releases.
- Renamed to **DepThreat Analytics** (the extension ID `MdSazedurRahman.deep-threat-analytics` is
  unchanged).

## [0.1.0] - 2026-11-02

First pre-release.

### Added

- Local scanning of installed dependency source code for npm, pnpm, Yarn (node_modules layouts),
  Python (virtual environments, pip, Poetry, uv), Go, Rust, PHP and Java.
- Built-in rules for exfiltration, credential and secret-file access, environment dumps, shell
  execution, reverse shells, dynamic code, persistence, crypto mining and data-collection
  endpoints, plus heuristics for obfuscated payloads.
- Install-hook detection: npm lifecycle scripts, `setup.py` side effects and executable `.pth`
  files.
- Offline typosquat detection against bundled popular package lists.
- Opt-in OSV.dev vulnerability lookups (with fixed versions) and npm/PyPI registry reputation
  checks. Both are off by default.
- Inline diagnostics on manifest dependency lines, hovers, Quick Fixes (open code, ignore rule,
  allowlist package, update to fixed version), a findings sidebar and a status bar summary.
- Project configuration in `.depthreat/config.yaml`: allowlists, ignores, severity overrides
  and policy gates. Custom rules in `.depthreat/rules/*.yaml`. Inline ignores in manifests.
- Per-package result cache, JSON export, and Workspace Trust support (repository config and rules
  are ignored in untrusted workspaces).
- Go support: `go.mod` parsing (including `replace` and `// indirect`), scanning of modules in
  `vendor/` or the module cache, and Go rules for shell execution, environment exfiltration and
  network calls from `init()` functions.
- Rust support: `Cargo.toml` and `Cargo.lock` parsing (renames, target tables, path crates
  skipped), scanning of crates in `vendor/` or the Cargo registry cache, Rust rules, and
  `build.rs` scripts treated as install hooks.
- PHP support: `composer.json` and `composer.lock` parsing, scanning of `vendor/`, PHP rules for
  shell functions, `eval`, decode-and-execute and web shells, and Composer plugins treated as
  install hooks.
- Java support: `pom.xml` (properties, managed versions, exclusions) and `build.gradle(.kts)`
  parsing, code scanning of `-sources.jar` files from the Maven repository or Gradle cache (safe
  extraction with zip-slip and size guards), transitive dependencies from dependency POMs, and Java
  rules for processes, shells, environment exfiltration, runtime code loading and JNDI lookups.
