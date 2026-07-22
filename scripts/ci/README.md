# CI maintenance

`verify-action-pins.sh` rejects third-party workflow actions that use a branch,
moving tag, shortened hash, or unpinned Docker image. GitHub Actions are pinned to
the full upstream commit SHA, with the reviewed release version in a comment.

Dependabot proposes weekly GitHub Actions updates. Before merging an update:

1. confirm the commit belongs to the expected official upstream repository and
   resolves from the release tag named in the comment;
2. review the release notes and workflow diff, including changes to transitive
   Node dependencies and permissions;
3. retain the full 40-character SHA and update the human-readable version comment;
4. run `./scripts/ci/verify-action-pins.sh` and all required workflows;
5. merge through the normal reviewed, protected-branch path.

The workflows declare read-only repository permission at workflow scope and do not
persist checkout credentials. A future publishing workflow must be separate, use
environment protection, and grant only the narrow OIDC or artifact permission it
requires. Never add package, deployment, issue, pull-request write, or `id-token`
permission to the validation workflows.
