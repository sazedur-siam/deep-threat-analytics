# Publishing DepThreat Analytics

This guide is for the extension's maintainer. It covers building the VSIX and publishing it to the two registries:

| Registry                                                                                                               | Used by                                              | Extension ID                            |
| ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | --------------------------------------- |
| [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=MdSazedurRahman.deep-threat-analytics) | VS Code                                              | `MdSazedurRahman.deep-threat-analytics` |
| [Open VSX](https://open-vsx.org)                                                                                       | Cursor, Windsurf, VSCodium, Gitpod, Eclipse Theia, … | `MdSazedurRahman.deep-threat-analytics` |

Both registries get the **same VSIX file**. It is built once and uploaded unchanged.

Tokens are secrets. Never commit them, paste them into issues, or put them in `package.json` or `.npmrc`.

## Building

```bash
npm ci
npm run check                 # typecheck, lint, format check, unit tests
npm run test:integration      # integration tests inside VS Code
npm run package               # writes deep-threat-analytics-<version>.vsix
```

`vsce package` runs the `vscode:prepublish` script, which produces the minified esbuild bundle. Check what goes into the VSIX with `npx vsce ls`.

The publish scripts below expect the file to be called `deep-threat-analytics.vsix`, which is also the name the release workflow uses:

```bash
npx vsce package --out deep-threat-analytics.vsix                 # release (even minor)
npx vsce package --pre-release --out deep-threat-analytics.vsix   # pre-release (odd minor)
```

## Versioning

- Versions are plain `major.minor.patch`, with no `-beta` or other suffix (the Marketplace rejects them).
- **Even minor = release, odd minor = pre-release.** For example, `1.0.x` and `1.2.x` are releases and `1.1.x` is a pre-release. Pre-releases must be packaged with `--pre-release`. The flag is written into the VSIX manifest, and both registries read it from there.
- Never set `"preview": true` in `package.json`. It shows a "Preview" badge on the listing and is not how pre-releases work.
- Every publish needs a new version number. Neither registry accepts the same version twice.
- Bump `version` in `package.json` and add a section to `CHANGELOG.md` for every publish.

## Releasing from CI (normal flow)

[`.github/workflows/release.yml`](../.github/workflows/release.yml) runs when a `v*` tag is pushed:

1. Installs dependencies, runs `npm run check` and the integration tests.
2. Checks that the tag matches the `version` in `package.json` (tag `v1.2.0` needs version `1.2.0`).
3. Packages `deep-threat-analytics.vsix` once, with `--pre-release` for odd minor versions.
4. Publishes that file to the Visual Studio Marketplace (secret `VSCE_PAT`).
5. Publishes the same file to Open VSX (secret `OVSX_PAT`).
6. Creates a GitHub release with the VSIX attached and generated release notes.

A registry whose secret is not configured is skipped with a notice in the run summary, so a tag without secrets still produces the GitHub release. Both publish steps use `--skip-duplicate`, so re-running a failed job does not fail on a registry that already accepted the version.

To release:

```bash
# on main, after bumping package.json and updating CHANGELOG.md
git commit -am "chore: release 1.2.0"
git tag v1.2.0
git push origin main
git push origin v1.2.0
```

## Visual Studio Marketplace

### One-time setup

1. The publisher `MdSazedurRahman` is managed at https://marketplace.visualstudio.com/manage. It must match `publisher` in `package.json`.
2. In Azure DevOps (https://dev.azure.com), open **User settings › Personal access tokens** and create a token with:
   - **Organization:** All accessible organizations
   - **Scopes:** Custom defined › **Marketplace › Manage**
3. Save it as the GitHub repository secret `VSCE_PAT` (**Settings › Secrets and variables › Actions › New repository secret**), or with the GitHub CLI:

   ```bash
   gh secret set VSCE_PAT --repo sazedur-siam/deep-threat-analytics
   ```

Azure DevOps tokens expire (at most one year). When the release job starts failing with an authentication error, create a new token and update the secret.

### Manual publish

```bash
export VSCE_PAT=<token>        # vsce reads the token from this variable
npm run publish:vsce           # vsce publish --packagePath deep-threat-analytics.vsix
```

Alternatively, `npx vsce login MdSazedurRahman` stores the token locally and `npx vsce publish --packagePath deep-threat-analytics.vsix` uses it.

## Open VSX

Open VSX is run by the Eclipse Foundation. The extension's **namespace** on Open VSX is the `publisher` field from `package.json`, so it must be called exactly `MdSazedurRahman`.

The official instructions are at https://github.com/eclipse/openvsx/wiki/Publishing-Extensions. Check them if anything below no longer matches the website.

### One-time setup

1. **Create an Eclipse Foundation account** at https://accounts.eclipse.org/user/register. Enter your GitHub username (`sazedur-siam`) in the GitHub username field of the profile.
2. **Log in to https://open-vsx.org** with GitHub (the `sazedur-siam` account).
3. **Link the Eclipse account and sign the Publisher Agreement.** Open your avatar › **Settings** › **Profile**, log in with your Eclipse account when asked, and sign the **Eclipse Foundation Open VSX Publisher Agreement**. You cannot publish until it is signed.
4. **Create an access token** under **Settings › Access Tokens** (https://open-vsx.org/user-settings/tokens). Copy it right away; it is shown only once.
5. **Create the namespace:**

   ```bash
   npx ovsx create-namespace MdSazedurRahman -p <token>
   npx ovsx verify-pat MdSazedurRahman -p <token>     # optional: confirms the token can publish there
   ```

6. **Optional: claim ownership of the namespace.** A newly created namespace is not verified, and Open VSX marks extensions in unverified namespaces as such. To become its verified owner (and keep others from publishing into it), request ownership through the issue process in the [EclipseFdn/open-vsx.org](https://github.com/EclipseFdn/open-vsx.org/issues) repository. See the [wiki](https://github.com/eclipse/openvsx/wiki/Publishing-Extensions) for the current procedure.
7. **Add the token to GitHub** as the repository secret `OVSX_PAT`:

   ```bash
   gh secret set OVSX_PAT --repo sazedur-siam/deep-threat-analytics
   ```

From then on, every tag pushed publishes to Open VSX as well.

Open VSX also requires a license. `package.json` declares `MIT` and the repository has a `LICENSE` file, so nothing else is needed.

### First publish of an existing version

The release workflow only publishes on a new tag. To put the current Marketplace version on Open VSX without a new release, build the VSIX from the commit that was released to the Marketplace (or download it from that GitHub release) and publish it manually:

```bash
npx vsce package --out deep-threat-analytics.vsix   # add --pre-release for an odd minor version
export OVSX_PAT=<token>
npm run publish:ovsx
```

### Manual publish

```bash
export OVSX_PAT=<token>        # ovsx reads the token from this variable
npm run publish:ovsx           # ovsx publish deep-threat-analytics.vsix
```

or pass the token directly: `npx ovsx publish deep-threat-analytics.vsix -p <token>`.

`ovsx` ignores `--pre-release` for an already-built VSIX. A pre-release must be **packaged** with `vsce package --pre-release`.

After publishing, the extension appears at https://open-vsx.org/extension/MdSazedurRahman/deep-threat-analytics.

## Manual fallback (both registries)

If CI is unavailable, do the whole release by hand from a clean checkout of the tagged commit:

```bash
git checkout v1.2.0
npm ci
npm run check
npm run test:integration
npx vsce package --out deep-threat-analytics.vsix   # add --pre-release for an odd minor version

export VSCE_PAT=<marketplace-token>
export OVSX_PAT=<open-vsx-token>
npm run publish:vsce
npm run publish:ovsx
```

Then create the GitHub release for the tag and attach `deep-threat-analytics.vsix`, for example with `gh release create v1.2.0 deep-threat-analytics.vsix --generate-notes`.
