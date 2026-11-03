# DepThreat Analytics

VS Code extension that scans the **source code of installed dependencies** for behavior that can compromise the system or leak data (network exfiltration, secret/env reads, shell spawning, eval/obfuscation, install hooks), plus opt-in CVE (OSV.dev) and package-reputation checks. Published to the VS Code Marketplace as `MdSazedurRahman.deep-threat-analytics` (publisher ID `MdSazedurRahman`; the GitHub account and commit identity stay `sazedur-siam`).

## Commands

```bash
npm run build              # esbuild bundle -> dist/extension.js
npm run watch              # rebuild on change
npm run check              # STAGE GATE: typecheck + lint + format:check + unit tests with coverage
npm test                   # vitest unit tests (test/unit/**)
npm run test:integration   # builds, compiles tests, runs test/integration/** inside VS Code 1.90
npm run format             # prettier --write
npm run package            # vsce package -> .vsix
```

F5 ("Run Extension") opens an Extension Development Host.

## Architecture

- `src/core/` — engine, types, cache, concurrency. **Must not import `vscode`**, so it stays unit-testable.
- `src/adapters/` — one `EcosystemAdapter` per ecosystem (npm, python, go, cargo, composer, maven). New ecosystems plug in here without core changes. Adapters only read files; they never run package managers or build tools.
- `src/scanners/` — code pattern scanner, composite (correlated) rules, obfuscation, install hooks, OSV, reputation.
- `src/rules/builtin/*.yaml` — built-in rules; users add `.depthreat/rules/*.yaml` in the same schema (validated with zod).
- `src/config/`, `src/policy/` — VS Code settings (`depthreat.*`), `.depthreat/config.yaml` (allowlist, ignores, policies).
- `src/ui/` — diagnostics, hover, code actions, tree view, status bar. Only this layer and `src/extension.ts` touch the VS Code API.
- `test/fixtures/` — fake packages that _mimic_ malicious patterns with benign code. Never put real malware here.

Full plan and stage table: `~/.claude/plans/i-want-to-make-ticklish-toucan.md`.

## Non-negotiable behavior

- **Never execute dependency code.** Scanners only read files.
- Online lookups (OSV, registry metadata) are **off by default** and must not make any network call when disabled (covered by a test).
- In untrusted workspaces, don't run interpreters (e.g. Python discovery) or honor workspace-level paths for executables/rules.
- Scans are triggered manually (commands / context menus), not on open/save.

## Workflow rules

- **Small commits**: commit each logical change as soon as it's made, using Conventional Commits (`feat(npm): …`, `test(scanner): …`, `fix: …`, `chore: …`, `docs: …`, `build: …`, `ci: …`).
- **Test gate per stage**: when a stage finishes, `npm run check` must pass (plus `npm run test:integration` once UI exists) before starting the next stage. Then push `main`.
- **Git identity**: commits are authored as `sazedur-siam <37084945+sazedur-siam@users.noreply.github.com>` (repo-local config). Never commit with the org identity.
- **No AI attribution**: no `Co-Authored-By: Claude` trailers and no "Generated with Claude Code" lines in commits, PRs, or docs.
- Shell chains that pipe npm output must use `set -o pipefail` so failures aren't masked.

## Toolchain gotchas

- TypeScript is pinned to `~6.0` because typescript-eslint doesn't support TS 7 yet.
- TS 6 defaults `types` to `[]`; `tsconfig.json` lists `["node", "mocha"]` explicitly.
- `module: nodenext` lets TypeScript accept ESM-only deps such as `smol-toml` (esbuild bundles them for runtime).
- `@types/vscode` is pinned to `1.90.0` to match `engines.vscode: ^1.90.0`. Don't use newer APIs without bumping both.
- Runtime deps are bundled by esbuild; `node_modules` is excluded from the VSIX via `.vscodeignore`.

## Marketplace guidelines (must hold before every publish)

- `publisher` in package.json must match the Marketplace publisher ID (`MdSazedurRahman`, created at https://marketplace.visualstudio.com/manage). Publish with `vsce login MdSazedurRahman` + `vsce publish` using an Azure DevOps PAT (Marketplace › Manage scope). Never commit the PAT; CI uses a `VSCE_PAT` secret.
- `icon`: PNG, at least 128×128 (SVG is not allowed for the extension icon).
- README/CHANGELOG images must use `https` URLs; SVG images are only allowed from trusted badge providers.
- Required metadata: `displayName`, `description`, `repository`, `license` + `LICENSE` file, `engines.vscode`, valid `categories`, ≤30 `keywords`.
- Versions are plain `major.minor.patch`. Pre-releases use `vsce publish --pre-release` (convention: odd minor = pre-release, even minor = release). Bump version and update `CHANGELOG.md` for every publish.
- Do not set `"preview": true` in package.json: it shows a "Preview" badge on the whole listing (separate from `--pre-release`). Check `<GalleryFlags>` in the packaged `extension.vsixmanifest` reads `Public`.
- Keep the VSIX small: bundle with esbuild, check contents with `npx vsce ls`.
- UX: every command has the `DepThreat` category; avoid notification spam; the activity-bar view icon is a monochrome SVG or codicon.
- Declare workspace-trust support (`capabilities.untrustedWorkspaces`) and document data handling. The extension collects no telemetry; if any is ever added it must respect `vscode.env.isTelemetryEnabled`.
- Respect user privacy: describe exactly what leaves the machine (package name + version to OSV/registries, only when enabled).
