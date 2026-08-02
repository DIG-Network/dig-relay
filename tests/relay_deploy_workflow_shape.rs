//! Shape guard for the relay.dig.net deploy hand-off (dig_ecosystem #1938).
//!
//! Two pipelines used to deploy `relay.dig.net` and either could silently undo the other. THIS
//! repo's `deploy.yml` read the LIVE ECS task definition, rendered a new image onto it and
//! registered a revision; `relay.dig.net`'s terraform applied its own idea of the same resource.
//! The damage was not theoretical:
//!
//!   * terraform's recorded task-definition revision trailed the running one by eighteen, so an
//!     apply meant to change one attribute would have rewritten the whole container contract;
//!   * because this workflow cloned whatever was LIVE, every hand edit was carried forward
//!     forever — which is how `--dashboard-listen`, the 8080 port mapping and
//!     `DIG_RELAY_TRUSTED_PROXY_CIDRS` came to exist in production while absent from the
//!     terraform source. A security boundary that decides who may forge a source IP was living
//!     in a console, reviewable by nobody.
//!
//! The settlement: **terraform owns the task definition's SHAPE, this repo owns its VERSION.**
//! These tests pin this side of it. They fail the moment an ECS write reappears here, because a
//! second writer is easy to re-add by reflex ("just roll the service after the push") and
//! impossible to notice afterwards — the two pipelines only disagree when someone looks.
//!
//! Read as text rather than parsed YAML, matching `nightly_release_workflow_shape.rs`: the
//! invariants are about the literal steps a maintainer reads, and a text guard fails with a
//! message pointing at the exact line to fix.

use std::path::PathBuf;

/// `dig-relay` is a single-package repo, so `CARGO_MANIFEST_DIR` IS the repo root.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The relay.dig.net deploy workflow.
fn deploy_workflow() -> String {
    let path = repo_root()
        .join(".github")
        .join("workflows")
        .join("deploy.yml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Everything CI can execute, as `(repo-relative path, contents)`.
///
/// The failure class is "a second pipeline appears", not "deploy.yml regresses" — a writer re-added
/// in `release.yml`, `nightly-release.yml`, or some new `roll.yml` would be just as invisible and
/// just as damaging. Scanning one file would have watched the wrong thing.
///
/// It also follows the obvious indirections: a `run: ./scripts/roll.sh` step mentions no ECS while
/// the script it calls does the write, and the same is true of a local composite action. Those
/// directories are scanned when present. What remains reachable is deliberate obfuscation
/// (`aws e""cs`, a `chr()`-assembled boto3 client) — a text guard should not pretend to catch a
/// determined author, and the point here is that the REFLEX re-add cannot slip through.
fn scanned_sources() -> Vec<(String, String)> {
    const ROOTS: &[&str] = &[".github/workflows", ".github/actions", "scripts"];
    const EXECUTABLE_EXTENSIONS: &[&str] = &["yml", "yaml", "sh", "py", "js"];

    let root = repo_root();
    let mut sources = Vec::new();
    let mut pending: Vec<PathBuf> = ROOTS
        .iter()
        .map(|relative| root.join(relative))
        // A repo need not have every root — `scripts/` may simply not exist yet.
        .filter(|path| path.exists())
        .collect();

    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("unreadable directory entry").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let is_executable_source = path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| EXECUTABLE_EXTENSIONS.contains(&extension));
            if !is_executable_source {
                continue;
            }
            let body = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let name = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            sources.push((name, body));
        }
    }

    assert!(
        sources.len() > 1,
        "found only {} scanned source(s) under {ROOTS:?} — this guard would pass near-vacuously",
        sources.len()
    );
    sources
}

/// Lines that are not comments and not blank, paired with their 1-based line number.
fn executable_lines(body: &str) -> impl Iterator<Item = (usize, &str)> {
    body.lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line))
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
}

/// Every way this workflow could WRITE the ECS task definition or roll the service itself — the AWS
/// CLI calls, and the official actions that wrap them.
///
/// `describe-task-definition` is deliberately absent: reading is not writing. The harm was never the
/// read, it was rendering an image onto what was read and registering the result — which is what
/// carried console edits forward forever. The workflow now reads the definition once, AFTER the
/// deploy, to assert the service actually took this release's image.
const ECS_WRITE_MARKERS: &[(&str, &str)] = &[
    (
        "register-task-definition",
        "only relay.dig.net's terraform may register a task-definition revision",
    ),
    (
        "amazon-ecs-render-task-definition",
        "rendering an image onto the live definition makes this a second writer of its shape",
    ),
    (
        "amazon-ecs-deploy-task-definition",
        "rolling the service from here bypasses the terraform that owns the definition",
    ),
    (
        "ecs update-service",
        "rolling the service from here bypasses the terraform that owns the definition",
    ),
];

#[test]
fn nothing_in_this_repo_writes_the_ecs_task_definition() {
    for (name, body) in scanned_sources() {
        for (marker, why) in ECS_WRITE_MARKERS {
            // The rationale lives in this file's header and in the workflows' own comments, so a
            // match inside a comment is expected — only an executable line is a finding.
            if let Some((line_number, _)) =
                executable_lines(&body).find(|(_, line)| line.contains(marker))
            {
                panic!(
                    "{name}:{line_number} uses `{marker}`: {why}. relay.dig.net's terraform is the \
                     single writer of the task definition (#1938); this repo builds the image and \
                     hands the tag over."
                );
            }
        }
    }
}

#[test]
fn nothing_in_this_repo_touches_ecs_except_the_one_permitted_read() {
    // Enumerating spellings is a losing game — `aws ecs \` split across a YAML continuation, an
    // `aws ecs "$VERB"`, a third-party `ecs-deploy` action, or boto3 all walk around a marker list
    // while doing exactly the forbidden thing. So the rule is inverted: NOTHING here may mention
    // ECS at all, except the two read-only calls that make up the post-deploy read-back. Re-adding a
    // writer then has to consciously widen this list, which is the whole point — this very list grew
    // by one entry when the read-back was made precise, and that is the intended way to change it.
    //
    // Both are strictly READS. Neither can register a revision or roll the service, which is what
    // relay.dig.net's terraform owns.
    const PERMITTED_READS: &[&str] = &[
        // Which revision the SERVICE is on — the thing the assertion is actually named after.
        "describe-services",
        // What image that revision carries.
        "describe-task-definition",
    ];

    for (name, body) in scanned_sources() {
        for (line_number, line) in executable_lines(&body) {
            let mentions_ecs = line.to_ascii_lowercase().contains("ecs");
            let is_permitted_read = PERMITTED_READS.iter().any(|read| line.contains(read));
            if mentions_ecs && !is_permitted_read {
                panic!(
                    "{name}:{line_number} mentions ECS outside the permitted read-only calls:\n  \
                     {}\nOnly {PERMITTED_READS:?} — the post-deploy read-back — are allowed in this \
                     repo. Everything else about the ECS service, including rolling it, is \
                     relay.dig.net's terraform to do (#1938). If this line is genuinely benign, \
                     widen this list deliberately rather than working around it.",
                    line.trim()
                );
            }
        }
    }
}

#[test]
fn deploy_hands_the_image_tag_to_the_infra_repo() {
    let workflow = deploy_workflow();
    assert!(
        workflow.contains("DIG-Network/relay.dig.net"),
        "deploy.yml must dispatch the deploy in DIG-Network/relay.dig.net, which owns the task \
         definition — otherwise a pushed image never reaches the service."
    );
    assert!(
        workflow.contains("gh workflow run"),
        "deploy.yml must dispatch relay.dig.net's deploy workflow after pushing the image."
    );
    assert!(
        workflow.contains("image_tag="),
        "the dispatch must pass `image_tag`: terraform owns the task definition's shape and takes \
         only the version as an input."
    );
}

#[test]
fn deploy_tags_the_image_with_this_commit() {
    let workflow = deploy_workflow();
    assert!(
        workflow.contains("$GITHUB_SHA") || workflow.contains("github.sha"),
        "the image must be tagged with this repo's commit SHA. The tag IS the provenance: \
         relay.dig.net's version gate resolves it against this repo's history to prove a deploy is \
         a forward step, and cannot do that for a tag that names no commit here."
    );
}

#[test]
fn deploy_fails_when_the_infra_deploy_fails() {
    let workflow = deploy_workflow();
    assert!(
        workflow.contains("gh run watch") && workflow.contains("--exit-status"),
        "deploy.yml must watch the dispatched relay.dig.net run with `--exit-status`. Without it a \
         failed terraform apply leaves this release green over a service that never took the new \
         image — the pushed-but-never-shipped hole #1938 set out to close."
    );
}

#[test]
fn deploy_watches_the_run_it_dispatched_and_not_merely_the_newest() {
    let workflow = deploy_workflow();
    // `gh workflow run` returns no run id, so the run must be FOUND. Matching "the newest dispatch"
    // silently latches onto a concurrent release, a manual deploy or a rollback, and reports that
    // run's result as this release's. relay.dig.net's `run-name` carries the image tag; the search
    // must filter on it.
    assert!(
        workflow.contains("displayTitle") && workflow.contains("IMAGE_TAG"),
        "the dispatched run must be identified by matching its title against this job's image tag, \
         not by taking the most recent workflow_dispatch run."
    );
}

#[test]
fn deploy_asserts_the_service_actually_took_this_image() {
    let workflow = deploy_workflow();
    // A watched run going green proves an apply succeeded, not that OUR image is serving. The only
    // unambiguous evidence is the service itself, so the release ends by reading it back.
    assert!(
        workflow.contains("describe-task-definition"),
        "deploy.yml must read the deployed task definition back after the apply to prove the \
         service is running this commit's image."
    );
    assert!(
        workflow.contains("!= \"$GITHUB_SHA\"") || workflow.contains("!= \"${GITHUB_SHA}\""),
        "the read-back must COMPARE the deployed image tag with this commit's SHA and fail on a \
         mismatch — printing it is not an assertion."
    );
}

#[test]
fn deploy_is_rerunnable_after_the_image_is_pushed() {
    let workflow = deploy_workflow();
    // The ECR repo has immutable tags, and every failure this workflow anticipates happens AFTER
    // the push. Without a skip-if-present guard the operator's first instinct — re-run the job —
    // dies at `docker push`, leaving the documented recovery path unusable.
    assert!(
        workflow.contains("ecr describe-images"),
        "deploy.yml must skip the build when the image tag is already in ECR, or a re-run after a \
         failed deploy cannot get past `docker push` (the repo has immutable tags)."
    );
}
