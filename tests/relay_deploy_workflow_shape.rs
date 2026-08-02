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

/// The relay.dig.net deploy workflow. `dig-relay` is a single-package repo, so
/// `CARGO_MANIFEST_DIR` IS the repo root.
fn deploy_workflow() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".github")
        .join("workflows")
        .join("deploy.yml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Every way this workflow could write the ECS task definition or roll the service itself — the
/// AWS CLI calls, and the official actions that wrap them.
const ECS_WRITE_MARKERS: &[(&str, &str)] = &[
    (
        "describe-task-definition",
        "reading the LIVE task definition is how hand edits were carried forward forever",
    ),
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
fn deploy_never_writes_the_ecs_task_definition() {
    let workflow = deploy_workflow();
    for (marker, why) in ECS_WRITE_MARKERS {
        // The rationale lives in this file's header, so a match inside a comment is expected and
        // must not fail the test — only an actual step may not use it.
        let used_in_a_step = workflow
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .any(|line| line.contains(marker));
        assert!(
            !used_in_a_step,
            "deploy.yml uses `{marker}` outside a comment: {why}. \
             relay.dig.net's terraform is the single writer of the task definition (#1938); this \
             workflow builds the image and hands the tag over."
        );
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
