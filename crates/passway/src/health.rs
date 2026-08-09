//! `/health` — mirrors yubaba's `GET /mesh/leader-health` pattern
//! (`oss/yubaba/crates/yubaba/src/lib.rs`'s `mesh_leader_health`): a bare
//! 200-vs-503 gate plus a small JSON body explaining *why*, so a
//! floating-IP/DNS health check (or Cloudflare break-glass health check)
//! can route traffic only to instances that return 200 (R594-F4 V0 MUST
//! #4).
//!
//! Two conditions gate readiness, matching the ticket verbatim: no ready
//! upstreams, or the instance is draining. Both collapse to 503 — the
//! caller (a health-check prober) doesn't need to distinguish "no capacity"
//! from "intentionally leaving rotation," it just needs to stop sending
//! traffic here.
//!
//! ## Aggregate node readiness, per-host detail (R594-F10)
//!
//! With one node fronting several services ([`crate::routing`]) the top-level
//! `ready` stays an **aggregate**: 200 while *any* upstream set can serve.
//! That is deliberate. This endpoint gates a floating-IP / DNS health check,
//! whose only lever is "is this node in rotation" — so reporting unready
//! because one of three services is down would take the two healthy ones
//! down with it, on every node at once (a service that's down is usually
//! down everywhere, not on one node). The per-set breakdown in
//! [`ReadinessBody::upstreams_by_host`] is what a *per-service* prober reads
//! instead; it's omitted entirely from the JSON for a single-set deployment,
//! so that body is byte-identical to the pre-R594-F10 one.

use serde::Serialize;

/// Ready/total upstream counts for one host's upstream set. `host` is the
/// routed hostname, or [`crate::routing::CATCH_ALL_LABEL`] for the catch-all
/// set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostReadiness {
    pub host: String,
    pub ready_upstreams: usize,
    pub total_upstreams: usize,
}

/// The `/health` response body. `Serialize` only — this module never talks
/// to a pingora `Session` directly (kept testable without a live proxy);
/// `proxy.rs` is what turns this into an actual HTTP response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadinessBody {
    pub ready: bool,
    pub ready_upstreams: usize,
    pub total_upstreams: usize,
    pub draining: bool,
    /// Per-host-set counts, present only when this node routes by host.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub upstreams_by_host: Vec<HostReadiness>,
}

impl ReadinessBody {
    /// Compute readiness from the raw signals. `ready` is `true` only when
    /// not draining *and* at least one upstream is ready — a proxy with
    /// zero ready upstreams is never "healthy," even if nothing is
    /// draining it (R594-F6's "fail-ready, not crash" gotcha extends to the
    /// health endpoint: an empty upstream set must read as unhealthy, not
    /// panic and not silently report 200).
    pub fn new(ready_upstreams: usize, total_upstreams: usize, draining: bool) -> Self {
        Self {
            ready: !draining && ready_upstreams > 0,
            ready_upstreams,
            total_upstreams,
            draining,
            upstreams_by_host: Vec::new(),
        }
    }

    /// Attach the per-host-set breakdown (R594-F10). Does not change
    /// [`Self::ready`] — see this module's doc for why node readiness stays
    /// an aggregate.
    pub fn with_hosts(mut self, upstreams_by_host: Vec<HostReadiness>) -> Self {
        self.upstreams_by_host = upstreams_by_host;
        self
    }

    /// The HTTP status this body should be served with: 200 only when
    /// [`Self::ready`], 503 otherwise.
    pub fn status_code(&self) -> u16 {
        if self.ready {
            200
        } else {
            503
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_when_upstreams_present_and_not_draining() {
        let b = ReadinessBody::new(2, 3, false);
        assert!(b.ready);
        assert_eq!(b.status_code(), 200);
        assert_eq!(b.ready_upstreams, 2);
        assert_eq!(b.total_upstreams, 3);
    }

    #[test]
    fn not_ready_when_zero_ready_upstreams() {
        let b = ReadinessBody::new(0, 3, false);
        assert!(!b.ready);
        assert_eq!(b.status_code(), 503);
    }

    #[test]
    fn not_ready_when_zero_total_upstreams() {
        // The empty-cold-start case: nothing has ever been discovered.
        let b = ReadinessBody::new(0, 0, false);
        assert!(!b.ready);
        assert_eq!(b.status_code(), 503);
    }

    #[test]
    fn not_ready_when_draining_even_with_ready_upstreams() {
        let b = ReadinessBody::new(3, 3, true);
        assert!(!b.ready);
        assert_eq!(b.status_code(), 503);
    }

    #[test]
    fn serializes_to_the_expected_json_shape() {
        let b = ReadinessBody::new(1, 2, false);
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(v["ready"], true);
        assert_eq!(v["ready_upstreams"], 1);
        assert_eq!(v["total_upstreams"], 2);
        assert_eq!(v["draining"], false);
        // A single-set deployment's body is unchanged by R594-F10.
        assert!(v.get("upstreams_by_host").is_none());
    }

    #[test]
    fn per_host_breakdown_is_reported_when_present() {
        let b = ReadinessBody::new(1, 3, false).with_hosts(vec![
            HostReadiness {
                host: "a.example.com".into(),
                ready_upstreams: 1,
                total_upstreams: 1,
            },
            HostReadiness {
                host: "b.example.com".into(),
                ready_upstreams: 0,
                total_upstreams: 2,
            },
        ]);
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(v["upstreams_by_host"][0]["host"], "a.example.com");
        assert_eq!(v["upstreams_by_host"][1]["ready_upstreams"], 0);
    }

    #[test]
    fn node_stays_ready_while_one_host_set_is_fully_down() {
        // The aggregate gate: b is dark, a still serves, so the node stays in
        // floating-IP rotation and b's outage is visible in the breakdown
        // rather than by pulling a's traffic too.
        let b = ReadinessBody::new(1, 3, false).with_hosts(vec![HostReadiness {
            host: "b.example.com".into(),
            ready_upstreams: 0,
            total_upstreams: 2,
        }]);
        assert!(b.ready);
        assert_eq!(b.status_code(), 200);
    }
}
