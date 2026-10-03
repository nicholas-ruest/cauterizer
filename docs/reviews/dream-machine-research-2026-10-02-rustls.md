# Dream Machine Research — 2026-10-02 — Rustls Remediation

## Decision

Extend the existing substantive Cauterizer system instead of creating another rudimentary repository.

## Source snapshots

- Core-memory operating model: `nicholas-ruest/core-memory@515c6445e28e75d33ebe75f34ea3e8f3a31a2361`
- Dream Machine control plane: `nicholas-ruest/ruvnet-dream-machine@3edd426f6c9c4b1e80235f7447dc863e749345cc`
- Cauterizer baseline: `nicholas-ruest/cauterizer@dda4a1dab9b1e503f5c8203aeba63ee7539628f0`

## Candidate comparison

| Candidate | Evidence | Decision |
|---|---|---|
| New trajectory-verification repository | Relevant research exists, but repository/Gist creation is unavailable and a complete multi-upstream vertical slice cannot be responsibly finished in this run | Reject for this run |
| Populate the existing TrajProof repository | The repository contains only a short README; publishing a scaffold would violate the substantive-build gate | Reject |
| Repair Cauterizer's locked TLS dependency graph | Baseline `cargo deny check` found a current, actionable advisory in a substantive Rust workspace with 500 passing tests | Select |

## Primary-source finding

Rustls advisory [GHSA-2mjx-qc3c-rqvc](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc), published 2026-09-14, affects rustls 0.23.13 through 0.23.44 and identifies 0.23.45 as patched. Cauterizer's lockfile pinned 0.23.42 through reqwest, SQLx, hyper-rustls, and tokio-rustls.

The issue permits TLS 1.3 handshake messages to be accepted across the wrong encryption-level boundary. The authenticated transcript limits impact, but the upstream advisory still classifies the condition as a network-reachable confidentiality weakness and provides a patched release.

Google's [OSV-Scanner](https://github.com/google/osv-scanner) remains Cauterizer's enterprise OSS reference for advisory acquisition and machine-readable affected-version data. This increment does not replace the existing OSV adapter or alter domain authority.

## Ruvnet composition

- Ruflo Federation identity was verified through the connected `ruflo_federation_federation_identity` capability.
- Ruflo CLI 3.51.1 recorded task `task-murqe84p` and routed the work through its RuVector-backed hooks system.
- No new RuVector/RVF runtime dependency was added to Cauterizer in this bounded security increment.
- MetaHarness, Darwin, and Flywheel commands are not present in the Dream Machine repository snapshot, so no execution is claimed.

## Hypothesis

Updating the locked rustls graph from 0.23.42 to 0.23.45, with rustls-webpki moving from 0.103.13 to 0.103.15, will eliminate GHSA-2mjx-qc3c-rqvc without changing source code and without causing any formatting, strict-Clippy, workspace-test, license, ban, or source-policy regression.

## Rejected expansion

A larger provenance/trajectory project and new RVF evidence adapter remain worthwhile, but they require a full source-grounded architecture and live integration evaluation. They were not compressed into this security repair merely to manufacture a daily project.
