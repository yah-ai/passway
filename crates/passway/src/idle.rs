//! Idle self-reap (R779, W267 §"Free-tier ingress at 10k domains").
//!
//! kamaji's on-demand JIT tier (`oss/kamaji/crates/kamaji/src/jit.rs`)
//! deliberately does **not** own idle detection: it forks the workload on
//! the first connection, waits for the child to exit, and re-arms. "When am
//! I idle" is the runtime's call, because only the runtime knows what an
//! in-flight request is. This module is passway's answer: count requests
//! from `request_filter` to `logging`, remember the last time one ended,
//! and exit the process once both `in_flight == 0` and `idle > ttl` hold.
//!
//! ## Why `exit(0)`, not a graceful shutdown
//!
//! At the moment of reaping there are, by definition, zero requests in
//! flight. What can still exist is an idle keep-alive connection with no
//! request on it; dropping it costs the client one transparent reconnect
//! (browsers and HTTP clients retry an idle-connection reset without
//! surfacing it). Under kamaji's JIT the listen socket is kamaji's, not
//! ours, so connections that arrive *during* the exit sit in the kernel
//! accept queue and are served by the next fork — nothing is refused. A
//! pingora graceful shutdown would buy a drain of zero requests at the cost
//! of pingora's full shutdown choreography (which also tries the
//! upgrade-socket dance); not worth it for a process with nothing to drain.
//!
//! ## Why the tracker is in the proxy, not a pingora hook
//!
//! pingora exposes no connection or request counter; the only per-request
//! boundaries it guarantees are `request_filter` (first phase) and
//! `logging` (always called, even for requests the filter rejected). So the
//! count is maintained by [`crate::proxy::PassProxy`] at exactly those two
//! points. A request that is rejected in `request_filter` still reaches
//! `logging`, so the count stays balanced.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;

/// Shared in-flight counter + last-activity clock.
pub struct IdleTracker {
    in_flight: AtomicUsize,
    /// Milliseconds since `epoch` of the last request end (or start).
    last_active_ms: AtomicU64,
    epoch: Instant,
}

impl Default for IdleTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl IdleTracker {
    pub fn new() -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
            last_active_ms: AtomicU64::new(0),
            epoch: Instant::now(),
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// A request entered `request_filter`.
    pub fn begin(&self) {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        self.last_active_ms.store(self.now_ms(), Ordering::SeqCst);
    }

    /// A request reached `logging`.
    pub fn end(&self) {
        // Saturating: a spurious extra `end` must never wrap to usize::MAX
        // and make the process immortal.
        let _ = self
            .in_flight
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| Some(n.saturating_sub(1)));
        self.last_active_ms.store(self.now_ms(), Ordering::SeqCst);
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Time since the last request began or ended. Counts from process
    /// start when no request has been seen yet, so a fork that never gets
    /// its first request (the connection that woke kamaji was dropped by
    /// the client) still reaps.
    pub fn idle_for(&self) -> Duration {
        let last = self.last_active_ms.load(Ordering::SeqCst);
        Duration::from_millis(self.now_ms().saturating_sub(last))
    }

    /// The reap decision, pure over the two counters.
    pub fn should_reap(&self, ttl: Duration) -> bool {
        self.in_flight() == 0 && self.idle_for() >= ttl
    }
}

/// pingora background service that polls [`IdleTracker::should_reap`] once
/// a second and exits the process when it holds.
pub struct IdleReaper {
    tracker: Arc<IdleTracker>,
    ttl: Duration,
}

impl IdleReaper {
    pub fn new(tracker: Arc<IdleTracker>, ttl: Duration) -> Self {
        Self { tracker, ttl }
    }
}

#[async_trait]
impl BackgroundService for IdleReaper {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if self.tracker.should_reap(self.ttl) {
                        log::info!(
                            "passway idle for {:?} with 0 requests in flight (ttl {:?}) — exiting so the supervisor can re-arm",
                            self.tracker.idle_for(),
                            self.ttl
                        );
                        std::process::exit(0);
                    }
                }
                _ = shutdown.changed() => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reaps_only_when_idle_and_empty() {
        let t = IdleTracker::new();
        assert!(t.should_reap(Duration::ZERO));
        t.begin();
        assert!(!t.should_reap(Duration::ZERO), "in flight blocks reap");
        t.end();
        assert_eq!(t.in_flight(), 0);
        assert!(!t.should_reap(Duration::from_secs(60)), "just active");
        assert!(t.should_reap(Duration::ZERO));
    }

    #[test]
    fn extra_end_saturates_at_zero() {
        let t = IdleTracker::new();
        t.end();
        t.end();
        assert_eq!(t.in_flight(), 0);
        assert!(t.should_reap(Duration::ZERO));
    }

    #[test]
    fn idle_clock_counts_from_process_start_before_first_request() {
        let t = IdleTracker::new();
        std::thread::sleep(Duration::from_millis(20));
        assert!(t.idle_for() >= Duration::from_millis(20));
        assert!(t.should_reap(Duration::from_millis(10)));
    }
}
