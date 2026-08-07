//! Cauterizer execution-plane worker supervisor.
//!
//! P14 built the generic transactional-outbox dispatch loop this process
//! would run — claim, invoke a handler, then acknowledge/retry/dead-letter —
//! as `cauterizer_infrastructure::dispatcher` (with a `PostgresMetadataStore`
//! adapter and full crash/retry test coverage). This binary intentionally
//! does not call it yet: the dispatcher needs a concrete per-context consumer
//! handler (e.g. a `patch-proposals` or `verification` handler that decodes
//! an envelope and calls its own `consume_inbox_atomic`-based effect), and no
//! such handler or handler registry exists in this workspace yet. Wiring one
//! in here now would mean shipping a placeholder handler that either drops
//! every real event on the floor or blindly acknowledges it unread — worse
//! than staying a stub. A future prompt that adds the first real consumer
//! wires this supervisor to `dispatcher::dispatch_batch` with that handler.

#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = cauterizer_worker::command::dispatch(std::env::args().skip(1)) {
        eprintln!("cauterizer worker failed: {error}");
        std::process::exit(2);
    }
}
