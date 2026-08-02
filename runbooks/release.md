# Runbook — releasing dig-relay (nightly cron + manual dispatch)

How this repo's `dig-relay` binary is built and released. The shape is copied from the ecosystem's
**reference nightlies system** (`dig-updater`, dig_ecosystem #590/#592); the normative contract is
`SPEC.md` §11.

## TL;DR

- Releases are **NOT cut on merge to `main`**. They are batched to a **nightly cron at midnight UTC**
  plus **manual dispatch**.
- **Stable** (`vX.Y.Z`): cut automatically when the `Cargo.toml` version was bumped (detected as
  "the `vX.Y.Z` tag doesn't exist yet"), or on demand. `prerelease: false`, marked `latest`.
- **Nightly**: built every night from `main` HEAD as a **pre-release** under a dated tag
  `nightly-YYYYMMDD` + a rolling `nightly` tag. `prerelease: true`, never `latest`. Keeps the newest
  14 dated nightlies.

## Prerequisites / credentials

- **`RELEASE_TOKEN`** — an org-level classic PAT (the ecosystem release token). Both channels no-op
  with a warning if it is absent. Used to push the changelog commit past branch protection and to
  push tags that trigger downstream workflows (`GITHUB_TOKEN` cannot do either). Set org-wide, or per
  repo under Settings → Secrets → Actions.

## If nightlies silently stop — check for the 60-day cron auto-disable

GitHub disables a `schedule:` trigger after **60 days of no repo activity** on a public repo, with
**no automatic re-enable** — and since this cron is the *only* automatic release trigger (there is
no more push-to-main tagger), a quiet repo can go dark with no error anywhere. If nightlies (or a
long-overdue stable release) stop appearing:

```bash
gh api repos/DIG-Network/dig-relay/actions/workflows/nightly-release.yml --jq .state
# "disabled_inactivity" means GitHub turned it off — re-enable it:
gh workflow enable nightly-release.yml --repo DIG-Network/dig-relay
```

Any repo activity (a merged PR, a manual dispatch) resets the 60-day counter, so this normally only
bites a repo that goes fully quiet for two months. (Fleet-wide re-enable checking across every
releasing submodule is a standing loop-housekeeping concern, not something this repo checks for
its siblings.)

## Cut a STABLE release (the normal path)

1. In your feature PR, bump `version` in `Cargo.toml` per SemVer and run `cargo update -p dig-relay`
   (or `cargo update --workspace`) so `Cargo.lock` matches (the version-increment CI gate requires
   the bump; `--locked` builds require the lock in sync). Merge the PR (squash) as usual.
2. Nothing releases on merge. At the next **midnight UTC** the `nightly-release.yml` cron runs its
   **stable** job: it sees the new version has no `vX.Y.Z` tag, regenerates `CHANGELOG.md` with
   git-cliff, commits `chore(release): vX.Y.Z` to `main`, tags it, and pushes with `RELEASE_TOKEN`.
3. The pushed `v*` tag fires `release.yml`, which builds every OS/arch and publishes the stable
   GitHub Release (with the changelog as notes).

### Cut a stable release NOW (don't wait for midnight)

Actions → **Nightly + stable release** → **Run workflow** → `channel: stable` (or `both`) → Run.

### Re-cut / re-release the current version (e.g. after a failed build)

Actions → **Nightly + stable release** → **Run workflow** → `channel: stable`, **`force: true`** →
Run. `force` bypasses the skip-if-tagged guard and moves the existing `vX.Y.Z` tag onto a fresh
changelog commit (`main` is never force-pushed), re-firing `release.yml`.

`force` is guarded, not a blanket override: it REFUSES (non-zero exit, clear error) when the tag
already has a PUBLISHED release AND currently points at a different commit than this run would
build — that combination would silently overwrite a shipped release's binaries with different code
under the same version. It only proceeds for a same-commit retry (the failed-build case above) or a
tag with no published release yet. If you actually need to ship new code, bump `Cargo.toml` and let
a normal (non-force) run cut the next version instead.

## Cut a NIGHTLY on demand

Actions → **Nightly + stable release** → **Run workflow** → `channel: nightly` (or `both`) → Run. It
builds `main` HEAD, publishes/refreshes today's `nightly-YYYYMMDD` pre-release, moves the rolling
`nightly` tag to it, and prunes old nightlies.

## Verify a release went live

- **Stable:** `gh release view vX.Y.Z --repo DIG-Network/dig-relay` — 4 OS/arch assets,
  `prerelease: false`, marked latest. Watch the build: `gh run watch <id>`.
- **Nightly:** `gh release view nightly --repo DIG-Network/dig-relay` (rolling) or
  `gh release view nightly-YYYYMMDD` — `prerelease: true`, 4 assets stamped with the nightly version.

## Workflows

| File | Trigger | Role |
|---|---|---|
| `nightly-release.yml` | midnight-UTC cron + `workflow_dispatch` | Orchestrator: stable (changelog + tag) + nightly (build + pre-release + prune). |
| `release.yml` | `push: tags: v*` (+ dispatch canary) | Builds + publishes the stable Release for a `vX.Y.Z` tag. |
| `build-binaries.yml` | `workflow_call` | Reusable cross-OS build (both channels call it). |
| `deploy.yml` | `push: tags: v*` (+ dispatch) | Ships the released commit to `relay.dig.net`: builds + pushes the image, hands the tag to that repo's terraform, watches the apply. |
| `ci.yml` | PR + push to main | The fmt/clippy/test/coverage gate (pre-merge). NOTE: `ubuntu-latest` only — cross-platform build breaks are first caught by the nightly channel, not PR CI (SPEC §11.6). |

## Shipping to relay.dig.net

The `vX.Y.Z` tag also fires `deploy.yml`, which ships the release to the canonical Fargate service.
It owns the **version** only: it builds the image, pushes it to ECR tagged with the git SHA, then
dispatches `DIG-Network/relay.dig.net`'s `deploy.yml` with that `image_tag` and watches the run. A
failed terraform apply therefore fails this deploy — a pushed image never silently fails to ship.

**This repo does not write the ECS task definition.** Ports, the container command, log config and
`DIG_RELAY_TRUSTED_PROXY_CIDRS` (the §2.9a security boundary) live in relay.dig.net's terraform, and
its deploy refuses an image that would move the running version backwards. Both pipelines used to
write that resource and each could silently undo the other — dig_ecosystem #1938; SPEC §11.7 makes
the split normative and `tests/relay_deploy_workflow_shape.rs` enforces it.

Nothing here needs a manual step. To ship a specific image or roll back, see
[relay.dig.net's runbook](https://github.com/DIG-Network/relay.dig.net/blob/main/runbooks/deploy.md).

### If a deploy fails

```bash
gh run list --repo DIG-Network/dig-relay   --workflow deploy.yml --limit 3
gh run list --repo DIG-Network/relay.dig.net --workflow deploy.yml --limit 3
```

The image push and the apply are separate halves. If the push succeeded and the dispatch or apply
did not, the image is already in ECR — re-dispatch the infra deploy with that SHA rather than
re-running the build.

## Local build (dev)

```bash
cargo build --release --locked
cargo test  --locked        # includes the workflow-shape guard tests
```
