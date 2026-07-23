# P09 isolated execution admission and worker protocol

Status: implemented and verified on 2026-07-23.

## Trust boundary and protocol

Isolated Execution owns immutable execution, environment, capability, resource,
output, worker, lease, heartbeat, terminal, and cleanup envelopes. Acquisition,
solver, and verifier jobs use distinct pool identities, and a lease accepts only
its allocated worker. Terminal receipts report bounded observations rather than
policy verdicts, are authoritative exactly once, and cannot close a lease until
cleanup success or failure is durably recorded.

The closed v1 wire contract is signed with an explicitly selected Ed25519 key.
RFC 8785/JCS canonical bytes bind the protocol version, entire request, signer
identity, and algorithm. A fail-closed verifier port distinguishes invalid
signatures, unknown signers, and verifier outages; authentication completes
before request validation or any mutation. Receipt schemas carry only digest
references and bounded, redacted output metadata.

## Admission and local enforcement

Admission rejects missing or zero external limits, evaluation egress, secret-like
environment variables, privilege escalation, Linux capabilities, daemon sockets,
host and undeclared mounts, symlink/path traversal, shell-shaped commands, and
pool or worker substitution. The rootless Podman supervisor uses no daemon
socket, no evaluation network, a read-only root filesystem, a non-root identity,
all capabilities dropped, `no-new-privileges`, default seccomp confinement,
bounded tmpfs, PIDs, memory, CPU, wall time, and retained output, plus disabled
host-side container logging. Timeout, cancellation, worker loss, and ordinary
exit all converge on explicit mandatory cleanup.

Local Podman execution is immutable `non-conformant-local`; neither a request nor
a worker receipt can promote it to conformant. Resource and output enforcement is
outside the guest, and cleanup failure remains a governed terminal observation
instead of being hidden.

## Durability and verification evidence

The application facade enforces exact tenant/action/resource authorization and
mandatory audit. Its transactional repository couples aggregate state,
optimistic version, exact idempotency result, and outbox events. Exact retries do
not duplicate events; conflicting reuse and stale versions leave state and
outbox unchanged. Denials are audited without mutation.

- 21 context tests cover protocol closure, canonical signature authentication,
  tamper and signer substitution, admission attacks, identity and pool isolation,
  replay/conflict rollback, all terminal outcomes, output exhaustion, timeout,
  cancellation, worker loss, cleanup failure, and local non-conformance.
- Formatting, strict all-target Clippy with warnings denied, architecture tests,
  and the full locked workspace suite are release gates.
- The optimized context suite completed in 10.853 seconds including compilation;
  its tests completed in 2.04 seconds. This is a regression baseline, not an
  execution-service latency SLO.
