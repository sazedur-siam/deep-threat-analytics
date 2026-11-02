# Changelog

All notable changes to this extension are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Odd minor versions are pre-releases.

## [Unreleased]

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
