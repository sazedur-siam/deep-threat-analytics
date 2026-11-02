# Deep Threat Analytics

[![CI](https://github.com/sazedur-siam/deep-threat-analytics/actions/workflows/ci.yml/badge.svg)](https://github.com/sazedur-siam/deep-threat-analytics/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/sazedur-siam/deep-threat-analytics/blob/main/LICENSE)

**See what your dependencies actually do, not just which CVEs they have.**

Deep Threat Analytics is a Visual Studio Code extension that reads the source code of the packages installed in your project. It flags behavior that could compromise your machine or leak data: sending environment variables over the network, reading SSH keys or cloud credentials, spawning shells, running obfuscated code, or hooking into install scripts.

Its rules, allowlists, severities and policies are all yours to customize.

> **Pre-release.** Detection is pattern-based and tuned to avoid noise, but it can still flag legitimate packages. Use the Quick Fixes to ignore or allowlist them, and please [report false positives](https://github.com/sazedur-siam/deep-threat-analytics/issues).

## Why another dependency scanner?

Vulnerability scanners match package versions against databases of _known_ CVEs. That misses:

- **Malicious packages** that have not been reported yet, such as typosquats, hijacked maintainers, and protestware.
- **Install-time attacks**: `postinstall` scripts, `setup.py` code, and `.pth` files that run as soon as you install.
- **Risky capabilities** in packages you trust, such as a date library that opens network sockets.

Deep Threat Analytics looks at the code itself, entirely on your machine. When you opt in, it adds CVE and package-reputation checks on top.

## What it detects

| Category      | Examples                                                                                                  |
| ------------- | --------------------------------------------------------------------------------------------------------- |
| Exfiltration  | Reading `process.env` / `os.environ` or secret files **and** sending data over the network                |
| Secrets & FS  | Access to `~/.ssh`, `~/.aws/credentials`, `~/.npmrc`, `.env`, browser cookie stores, the keychain         |
| Exec          | `child_process.exec`, `subprocess` with `shell=True`, reverse-shell patterns                              |
| Dynamic code  | `eval` / `new Function` / `exec` on non-literal input, decode-and-execute, `marshal.loads`, `vm` contexts |
| Obfuscation   | High-entropy base64/hex payloads that get decoded and executed, javascript-obfuscator signatures          |
| Install hooks | npm lifecycle scripts, `setup.py` code, executable `.pth` files, Rust `build.rs`, Composer plugins        |
| Network       | Webhook, paste and tunneling endpoints, DNS exfiltration, hardcoded IP addresses, public-IP lookups       |
| Persistence   | Writes to shell profiles, crontab, LaunchAgents, systemd units, Windows Run keys                          |
| Crypto mining | Mining pool URLs, miner binaries, crypto-wallet file access                                               |
| Reputation    | Typosquats (offline); optional: new, deprecated, yanked or unregistered packages, maintainer changes      |
| Vulnerability | Known CVEs and malicious-package advisories from [OSV.dev](https://osv.dev) (opt-in)                      |

Correlation keeps the noise down. A capability on its own, such as starting a child process, is _low_. A package that reads your credentials **and** posts them to a webhook is _critical_. Comment lines are ignored, so documentation and commented-out examples don't trigger rules.

## Supported ecosystems

| Ecosystem                             | Manifests                                                                               | Status    |
| ------------------------------------- | --------------------------------------------------------------------------------------- | --------- |
| npm / pnpm / Yarn (classic and Berry) | `package.json` + `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock`                   | Supported |
| Python (pip, Poetry, uv)              | `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock`                         | Supported |
| Go                                    | `go.mod` (+ `vendor/` or the module cache)                                              | Supported |
| Rust (Cargo)                          | `Cargo.toml` + `Cargo.lock` (+ `vendor/` or `~/.cargo/registry`)                        | Supported |
| Java (Maven / Gradle)                 | `pom.xml`, `build.gradle(.kts)` (scans `-sources.jar` from `~/.m2` or the Gradle cache) | Supported |
| PHP (Composer)                        | `composer.json` + `composer.lock` (+ `vendor/`)                                         | Supported |

The extension scans what is **installed**: `node_modules` (including pnpm's symlinked store), the project's virtual environment (`.venv`, `venv` or `env`), Go modules in `vendor/` or the module cache (`GOMODCACHE`, `GOPATH/pkg/mod` or `~/go/pkg/mod`), crates in `vendor/` or `$CARGO_HOME/registry/src`, Composer packages in `vendor/`, and Java libraries whose `-sources.jar` is in `~/.m2/repository` or the Gradle cache (download them with `mvn dependency:sources` or your IDE). Sources jars are unpacked into the OS temp folder for scanning. No build tool (`go`, `cargo`, `mvn`, `gradle`) is ever run. Install your dependencies before scanning. Dependencies that are not installed still get the optional OSV and registry checks.

## Usage

Scans run only when you ask for one, never automatically on open or save:

- **Command Palette** → `DepThreat: Scan Workspace`
- Right-click a manifest in the Explorer or editor → `DepThreat: Scan This Manifest`

Results appear in three places:

- **Inline diagnostics** on each direct dependency in the manifest. Findings in transitive dependencies are shown on the direct dependency that pulls them in. Hover for details.
- **Quick Fixes** on a flagged dependency:
  - Show its findings in the sidebar
  - Open the offending line in the dependency's code
  - Ignore a rule for that package
  - Allowlist the package
  - Update it to the version that fixes its known vulnerabilities (when OSV is enabled)
- **The Deep Threat Analytics sidebar**: Manifest › Package › Finding. Click a finding to jump to the exact line. Right-click to ignore it or turn the rule off. Policy violations are grouped at the top.

The status bar shows the result of the last scan and turns red when a policy fails.

### Commands

| Command                                    | What it does                                               |
| ------------------------------------------ | ---------------------------------------------------------- |
| `DepThreat: Scan Workspace`                | Scan every manifest in the workspace                       |
| `DepThreat: Scan This Manifest`            | Scan the selected or open manifest                         |
| `DepThreat: Export Findings (JSON)`        | Save the last scan's findings, violations and stats        |
| `DepThreat: Create or Open Project Config` | Create `.depthreat/config.yaml` from a commented template  |
| `DepThreat: Open Custom Rules`             | Create `.depthreat/rules/custom.yaml` with an example rule |
| `DepThreat: Clear Scan Cache`              | Forget cached per-package results                          |

Results are cached per package version and rule set, so rescans only re-read packages that changed.

## Privacy and data

- **Code analysis is 100% local.** Dependency files are read from disk and never uploaded, and dependency code is **never executed**.
- **Online lookups are off by default.** When you enable them:
  - `depthreat.online.osv.enabled` sends package **name, ecosystem and version** to `api.osv.dev`.
  - `depthreat.online.registryMetadata.enabled` sends package **names** to `registry.npmjs.org` / `pypi.org`.
- **Typosquat checks run offline** against lists of popular package names bundled with the extension.
- **No telemetry** is collected.

### Workspace Trust

In an untrusted workspace the extension runs in restricted mode:

- It does not run the Python interpreter to locate `site-packages`, and only looks for a `.venv` on disk.
- It ignores workspace-level values for rule paths, the interpreter path, and online lookups. Only your user settings apply.
- It ignores the repository's own `.depthreat/config.yaml` and `.depthreat/rules/`, so an untrusted repository cannot allowlist its own dependencies or switch rules off.

In a trusted workspace, the interpreter runs in isolated mode (`python -I`) from a neutral directory, so files in your project cannot run during discovery.

## Configuration

### Settings

| Setting                                     | Default               | Description                                                    |
| ------------------------------------------- | --------------------- | -------------------------------------------------------------- |
| `depthreat.scanTransitive`                  | `true`                | Also scan dependencies of dependencies                         |
| `depthreat.includeDevDependencies`          | `false`               | Scan dev/test dependencies                                     |
| `depthreat.minSeverity`                     | `low`                 | Hide findings below this severity                              |
| `depthreat.severityMapping`                 | critical/high → Error | How each severity is shown (Error, Warning, Information, Hint) |
| `depthreat.exclude`                         | `node_modules`, venvs | Glob patterns for manifests to skip                            |
| `depthreat.maxFileSizeKB`                   | `1024`                | Skip larger files                                              |
| `depthreat.maxFilesPerPackage`              | `2000`                | Per-package file cap                                           |
| `depthreat.concurrency`                     | `4`                   | Packages scanned in parallel                                   |
| `depthreat.rulesPaths`                      | `[]`                  | Extra folders with custom rule files                           |
| `depthreat.python.interpreterPath`          | `""`                  | Python interpreter used to find `site-packages`                |
| `depthreat.online.osv.enabled`              | `false`               | Query OSV.dev for known vulnerabilities                        |
| `depthreat.online.registryMetadata.enabled` | `false`               | Check npm/PyPI metadata (age, deprecation, maintainers)        |

### Project config: `.depthreat/config.yaml`

Commit this file to share allowlists, ignores and policies with your team:

```yaml
allowlist:
  packages: ['esbuild', '@types/*', 'pypi:requests']
  rules: ['network/ip-lookup']

ignore:
  - { package: 'lodash', rule: 'obfuscation/*', reason: 'minified dist' }
  - { package: 'left-pad', version: '1.x' } # every rule, only for 1.x versions
  - { finding: 'a1b2c3d4e5f60718', reason: 'reviewed by security team' }

severityOverrides:
  - { rule: 'network/*', severity: low }

policies:
  - { name: no-install-hooks, deny: { category: install-hook }, action: error }
  - {
      name: no-network-in-crypto,
      packages: ['*crypto*'],
      deny: { category: [network, exfiltration] },
      action: error,
    }
  - { name: no-critical, deny: { minSeverity: critical }, action: error }
  - { name: known-vulns, deny: { source: osv, minSeverity: high }, action: warn }
```

- **Package patterns** are globs, and `*` also matches `/`, so `*crypto*` covers `@scope/crypto-lib`. Prefix them with `npm:` or `pypi:` to limit them to one ecosystem.
- **Policy `deny`** matches on any combination of `category`, `rule`, `source` (`code`, `install-hook`, `osv`, `reputation`) and `minSeverity`. All the criteria you list must match.
- **Actions:** `action: error` violations always show as errors and turn the status bar red. `action: warn` violations show at least as warnings.
- **Invalid entries** are reported in the **Deep Threat Analytics** output channel with their path, such as `ignore[2].package`. The rest of the file still applies.

### Custom rules: `.depthreat/rules/*.yaml`

Custom rules use the same format as the built-in ones. A rule with the same `id` as a built-in rule replaces it, and `enabled: false` turns it off.

```yaml
- id: custom/internal-telemetry-endpoint
  title: Talks to an unapproved endpoint
  category: network
  severity: high
  languages: [javascript, typescript, python]
  match:
    any:
      - regex: 'https?://[a-z0-9.-]*\.example\.invalid'
    not:
      - regex: 'localhost'
    scope: line # line | file | package
  message: '{package} contacts an unapproved host in {file}'
```

- **`all`**: every pattern must match within the `scope`.
- **`any`**: at least one pattern must match.
- **`not`**: any match vetoes the rule within the `scope`.
- **`scope`**: `file` or `package` lets you correlate signals that appear on different lines. For example, "reads env vars" **and** "makes HTTP requests" in the same file.
- **Patterns** are JavaScript regular expressions applied line by line. Comment-only lines are skipped.
- **`flags`** can add `i`, `s` or `u`.
- **`files`** restricts a rule to file names (globs), such as `['setup.py']`.
- **`message`** can use `{package}`, `{version}` and `{file}`.
- **Categories:** `network`, `exfiltration`, `exec`, `secrets-fs`, `env-access`, `obfuscation`, `install-hook`, `crypto-mining`, `dynamic-code`, `persistence`, `vulnerability`, `reputation`.

To change a built-in rule, copy it from [`rules/builtin`](https://github.com/sazedur-siam/deep-threat-analytics/tree/main/rules/builtin) into your rules folder under the same `id` and edit it. To switch a built-in rule off, set `enabled: false`.

### Inline ignores

```text
# requirements.txt
somepkg==1.2.3  # depthreat-ignore
otherpkg>=2     # depthreat-ignore[exec/python-shell, obfuscation/*]
```

```jsonc
// package.json (JSON has no comments, so use a top-level field)
"depthreat": { "ignore": { "some-package": ["network/*"], "other-package": "all" } }
```

## Known limitations

- **Detection is pattern-based, not a full program analysis.** Code that builds names at runtime can evade rules, and some legitimate packages can match. Correlated rules and severities are designed to keep false positives low.
- **Patterns match line by line.** `scope: file` and `scope: package` correlate across lines, but a single pattern cannot span lines.
- **Unsupported install layouts:** Yarn Plug'n'Play (no `node_modules`) and Python packages installed outside a virtual environment are not scanned unless the interpreter can be queried (trusted workspaces only).
- **Java:** only libraries with a downloaded `-sources.jar` get code scanning; the rest get the OSV and registry checks. Kotlin sources and versions inherited from parent POMs are not resolved yet.

## Roadmap

- [x] npm / pnpm / Yarn and Python adapters
- [x] Code scanner, obfuscation and install-hook detection, built-in rule packs
- [x] Project config, ignores, allowlists and policy gates
- [x] Diagnostics, hovers, Quick Fixes, sidebar, status bar
- [x] OSV.dev vulnerabilities, typosquats and registry reputation
- [ ] 0.1.0 pre-release on the Visual Studio Marketplace
- [x] Go, Rust, PHP and Java
- [ ] SARIF export

## Development

Requirements: Node.js 20+ and VS Code 1.90+.

```bash
npm ci
npm run build              # bundle to dist/extension.js
npm run check              # typecheck + lint + format check + unit tests with coverage
npm run test:integration   # run integration tests inside VS Code
npm run package            # build a .vsix
```

Press **F5** in VS Code to launch an Extension Development Host.

Project layout:

```text
src/core/       engine, shared types, cache (no VS Code API)
src/adapters/   one adapter per ecosystem (manifest parsing, lockfiles, installed files)
src/scanners/   code patterns, obfuscation, install hooks, OSV, reputation
src/rules/      rule schema and loader
rules/builtin/  built-in rule packs (YAML)
data/           bundled popular package names for typosquat checks
src/config/     settings and .depthreat/config.yaml
src/policy/     ignores, allowlists, policy gates
src/ui/         diagnostics, hovers, Quick Fixes, tree view, status bar
test/           unit tests, VS Code integration tests, fixtures
```

Test fixtures contain **fake** packages with harmless code that only imitates suspicious patterns. Never add real malware.

### Contributing

Issues and pull requests are welcome. Please:

- use [Conventional Commits](https://www.conventionalcommits.org/) (`feat(npm): …`, `fix(scanner): …`),
- keep commits small and focused,
- make sure `npm run check` passes.

## License

[MIT](https://github.com/sazedur-siam/deep-threat-analytics/blob/main/LICENSE)
