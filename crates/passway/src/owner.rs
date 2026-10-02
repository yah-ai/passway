//! Owner-following upstreams: route one hostname to wherever raft says a
//! floating singleton runs (R936-B1).
//!
//! The mesh coordinator (headscale) is an appliance that floats with the raft
//! **ingress owner**. Every front door serves `cloud.mesh.yah.dev`; exactly one
//! node runs the appliance. [`crate::discovery`] cannot express that: service
//! records are strictly per-node (R844-B11), so a door polling its own yubaba
//! only ever learns about workloads on its own node, and a *remote* door —
//! the case the whole follow-placement design exists for — learns nothing.
//! Before this module every door was therefore told statically
//! (`PASSWAY_UPSTREAMS=cloud.mesh.yah.dev=<owner ip>:443`), and a failover that
//! took raft 31 s left the fleet dark for 8 min while a human edited three env
//! files (R936-B1, measured on prod 2026-09-22).
//!
//! This source instead polls its **local** yubaba's `GET /cluster/ingress-owner`
//! — a read of replicated raft state, so every node answers the same owner —
//! and turns the answer into a route with [`plan_route`]:
//!
//! | what the local yubaba says | route |
//! |---|---|
//! | the owner is **this** node and the appliance is serving here | [`Route::Local`] — loopback, plain HTTP |
//! | the owner is another node, the record is settled, its public address is known | [`Route::Owner`] — that node's public IP, TLS + SNI |
//! | anything else: unsettled, no owner, owner without a public address, this node named but not serving | [`Route::Peers`] — the other doors' public IPs, TLS + SNI |
//!
//! ## Why the owner's PUBLIC address, never its mesh address
//!
//! This door is how tailscaled reaches the coordinator. A door that needed the
//! mesh to reach the thing that grants meshes would deadlock on a cold or
//! partitioned fleet, so every remote leg dials a public IP:443 (the peer's
//! SNI demux → its own passway-mesh door → its loopback headscale). That is the
//! exact shape the manual 2026-09-22 fix used, now derived instead of typed.
//!
//! ## Why "unsettled" falls back to the peer doors (R936-B5)
//!
//! A node returning from a power-off replays its own pre-failover raft state,
//! so its record can name *itself* as owner while its appliance is correctly
//! fenced and a survivor is serving. It also cannot catch raft up without the
//! mesh, and cannot get the mesh without a coordinator. Dialing loopback there
//! is the 4.5-minute blackout R936-B5 measured. The peer doors hold settled
//! views and route correctly, so they are the right fallback — and they are
//! configured statically ([`OwnerRouteConfig::peers`]) because the fallback
//! has to work when the local yubaba cannot be asked at all.
//!
//! The Local arm keys on **serving here**, not on `settled`: a term storm on
//! the owner (R936-B6) interrupts leader contact without stopping headscale,
//! and flipping the owner's own door to its peers then would bounce every
//! request straight back to it.
//!
//! ## Loop bound
//!
//! Peer fallback can chain: door A (unsettled) → door B → owner. Two doors
//! that are *both* in fallback would ping-pong forever, so every remote leg
//! carries [`DOOR_HOP_HEADER`], incremented per door, and a door refuses
//! (508) a request that arrives with [`MAX_DOOR_HOPS`] already spent — see
//! `PassProxy::request_filter`.
//!
//! ## Poll failure
//!
//! A failed poll keeps this process's last *successful* view. It never reads
//! one from disk: on a fresh boot the last view on disk is exactly the stale
//! pre-failover answer the fallback exists to ignore. With no view yet, the
//! route is [`Route::Peers`].

use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use crate::routing::UpstreamOpts;
use crate::upstream::{Upstream, UpstreamSource};

/// Request header counting how many front doors a request has already
/// crossed. Set on every remote leg this source produces.
pub const DOOR_HOP_HEADER: &str = "x-passway-door-hop";

/// A request arriving having crossed this many doors is refused. The longest
/// legitimate path is client → unsettled door → settled door → owner door, which
/// arrives at the owner with 2.
pub const MAX_DOOR_HOPS: u8 = 3;

/// Parse [`DOOR_HOP_HEADER`] off an arriving request. Absent or unparsable is
/// 0 — the header is advisory loop protection between our own doors, and a
/// client that forges a large value only gets itself refused.
pub fn arrival_door_hop(headers: &http::HeaderMap) -> u8 {
    headers
        .get(DOOR_HOP_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u8>().ok())
        .unwrap_or(0)
}

/// Marker in a backend's extensions: forwarding to it crosses a door, so the
/// proxy must increment [`DOOR_HOP_HEADER`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountsDoorHop;

/// The wire shape of yubaba's `GET /cluster/ingress-owner`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OwnerView {
    /// The answering node's own raft node id.
    pub node_id: u64,
    /// Whether the answering node has been in leader contact long enough for
    /// its applied record to be current (R858-B20).
    pub settled: bool,
    /// Whether the appliance is running on the answering node right now.
    #[serde(default)]
    pub serving_here: bool,
    /// The recorded owner, if any.
    pub owner: Option<OwnerRef>,
}

/// The recorded owner as the view names it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OwnerRef {
    pub node_id: u64,
    /// The owner's public address (its `--public-address`), if it declared one.
    #[serde(default)]
    pub public_address: Option<String>,
}

/// Where one door sends the owner-following hostname right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// This node serves it: dial the configured loopback address.
    Local,
    /// Another node serves it and the record is trustworthy: dial its public IP.
    Owner(IpAddr),
    /// This door cannot trust its own answer: hand the request to the others.
    Peers,
}

/// The pure decision. `None` = no view was ever obtained in this process.
pub fn plan_route(view: Option<&OwnerView>) -> Route {
    let Some(view) = view else {
        return Route::Peers;
    };
    let Some(owner) = view.owner.as_ref() else {
        return Route::Peers;
    };
    if owner.node_id == view.node_id {
        // Named as owner. Serving is the evidence; a record naming this node
        // with nothing running is the returning-node trap (R936-B5).
        return if view.serving_here {
            Route::Local
        } else {
            Route::Peers
        };
    }
    if !view.settled {
        return Route::Peers;
    }
    match owner
        .public_address
        .as_deref()
        .map(str::trim)
        .and_then(|a| a.parse::<IpAddr>().ok())
    {
        Some(ip) => Route::Owner(ip),
        None => Route::Peers,
    }
}

/// Configuration for [`OwnerUpstreams`].
#[derive(Debug, Clone)]
pub struct OwnerRouteConfig {
    /// The local yubaba's `/cluster/ingress-owner` URL.
    pub url: String,
    /// Where the appliance listens on this node (plain HTTP), e.g. `127.0.0.1:8080`.
    pub local: SocketAddr,
    /// The other doors' public `ip:port`, used for [`Route::Peers`]. Excludes
    /// this door.
    pub peers: Vec<SocketAddr>,
    /// Port the owner door answers on for [`Route::Owner`], normally 443.
    pub remote_port: u16,
    /// SNI presented on every remote leg.
    pub sni: String,
    /// Per-poll timeout.
    pub timeout: Duration,
}

/// Resolve a [`Route`] to concrete upstreams.
pub fn upstreams_for(route: &Route, cfg: &OwnerRouteConfig) -> Vec<Upstream> {
    let remote = |addr: SocketAddr| Upstream {
        addr,
        opts: Some(UpstreamOpts {
            tls: true,
            sni: cfg.sni.clone(),
        }),
        counts_door_hop: true,
    };
    match route {
        Route::Local => vec![Upstream {
            addr: cfg.local,
            opts: Some(UpstreamOpts {
                tls: false,
                sni: String::new(),
            }),
            counts_door_hop: false,
        }],
        Route::Owner(ip) => vec![remote(SocketAddr::new(*ip, cfg.remote_port))],
        Route::Peers => cfg.peers.iter().copied().map(remote).collect(),
    }
}

/// [`UpstreamSource`] that follows the raft ingress owner.
#[derive(Debug)]
pub struct OwnerUpstreams {
    client: reqwest::Client,
    cfg: OwnerRouteConfig,
    /// Last successful view in THIS process — never seeded from disk.
    last: Mutex<Option<OwnerView>>,
    /// Last route logged, so a change is said once rather than every poll.
    last_route: Mutex<Option<Route>>,
}

impl OwnerUpstreams {
    pub fn new(cfg: OwnerRouteConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .build()
            .expect("reqwest client builds with a timeout only");
        Self {
            client,
            cfg,
            last: Mutex::new(None),
            last_route: Mutex::new(None),
        }
    }

    async fn fetch(&self) -> Result<OwnerView, String> {
        let resp = self
            .client
            .get(&self.cfg.url)
            .send()
            .await
            .map_err(|e| format!("GET {}: {e}", self.cfg.url))?;
        if !resp.status().is_success() {
            return Err(format!("GET {}: HTTP {}", self.cfg.url, resp.status()));
        }
        resp.json::<OwnerView>()
            .await
            .map_err(|e| format!("GET {}: unparsable body: {e}", self.cfg.url))
    }

    /// The view to plan from after this poll: the fresh one, or the last good
    /// one in this process.
    fn settle_view(&self, fetched: Result<OwnerView, String>) -> Option<OwnerView> {
        let mut last = self.last.lock().unwrap();
        match fetched {
            Ok(view) => {
                *last = Some(view);
            }
            Err(e) => log::warn!(
                "ingress-owner poll failed ({e}); {}",
                if last.is_some() {
                    "keeping this process's last view"
                } else {
                    "no view yet, routing to the peer doors"
                }
            ),
        }
        last.clone()
    }
}

#[async_trait]
impl UpstreamSource for OwnerUpstreams {
    async fn addrs(&self) -> Vec<SocketAddr> {
        self.upstreams().await.into_iter().map(|u| u.addr).collect()
    }

    async fn upstreams(&self) -> Vec<Upstream> {
        let fetched = self.fetch().await;
        let view = self.settle_view(fetched);
        let route = plan_route(view.as_ref());
        {
            let mut prev = self.last_route.lock().unwrap();
            if prev.as_ref() != Some(&route) {
                log::info!("ingress-owner route is now {route:?} (view {view:?})");
                *prev = Some(route.clone());
            }
        }
        upstreams_for(&route, &self.cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(node: u64, settled: bool, serving: bool, owner: Option<(u64, Option<&str>)>) -> OwnerView {
        OwnerView {
            node_id: node,
            settled,
            serving_here: serving,
            owner: owner.map(|(id, pa)| OwnerRef {
                node_id: id,
                public_address: pa.map(str::to_string),
            }),
        }
    }

    fn cfg() -> OwnerRouteConfig {
        OwnerRouteConfig {
            url: "http://127.0.0.1:1/cluster/ingress-owner".into(),
            local: "127.0.0.1:8080".parse().unwrap(),
            peers: vec![
                "45.32.194.254:443".parse().unwrap(),
                "51.81.85.145:443".parse().unwrap(),
            ],
            remote_port: 443,
            sni: "cloud.mesh.yah.dev".into(),
            timeout: Duration::from_millis(200),
        }
    }

    #[test]
    fn the_serving_owner_dials_loopback_even_when_unsettled() {
        // Settled or not: a term storm on the owner must not bounce its door.
        for settled in [true, false] {
            assert_eq!(
                plan_route(Some(&view(2, settled, true, Some((2, Some("15.204.89.240")))))),
                Route::Local
            );
        }
    }

    #[test]
    fn a_node_named_owner_but_not_serving_falls_back_to_peers() {
        // R936-B5: the returning node's replayed record names itself.
        assert_eq!(
            plan_route(Some(&view(1, false, false, Some((1, Some("45.32.194.254")))))),
            Route::Peers
        );
        assert_eq!(
            plan_route(Some(&view(1, true, false, Some((1, Some("45.32.194.254")))))),
            Route::Peers
        );
    }

    #[test]
    fn a_remote_owner_is_dialed_on_its_public_address_when_settled() {
        assert_eq!(
            plan_route(Some(&view(3, true, false, Some((2, Some("15.204.89.240")))))),
            Route::Owner("15.204.89.240".parse().unwrap())
        );
    }

    #[test]
    fn an_unsettled_view_of_a_remote_owner_goes_to_peers() {
        assert_eq!(
            plan_route(Some(&view(3, false, false, Some((2, Some("15.204.89.240")))))),
            Route::Peers
        );
    }

    #[test]
    fn no_owner_no_address_or_no_view_goes_to_peers() {
        assert_eq!(plan_route(None), Route::Peers);
        assert_eq!(plan_route(Some(&view(3, true, false, None))), Route::Peers);
        assert_eq!(
            plan_route(Some(&view(3, true, false, Some((2, None))))),
            Route::Peers
        );
        assert_eq!(
            plan_route(Some(&view(3, true, false, Some((2, Some("vps-4c1efa56")))))),
            Route::Peers,
            "a hostname is not an address — R936-B3's trap must not become a dial"
        );
    }

    #[test]
    fn the_arrival_hop_parses_and_defaults_to_zero() {
        let mut h = http::HeaderMap::new();
        assert_eq!(arrival_door_hop(&h), 0);
        h.insert(DOOR_HOP_HEADER, "2".parse().unwrap());
        assert_eq!(arrival_door_hop(&h), 2);
        h.insert(DOOR_HOP_HEADER, "junk".parse().unwrap());
        assert_eq!(arrival_door_hop(&h), 0);
    }

    #[test]
    fn routes_resolve_to_the_right_scheme() {
        let c = cfg();
        let local = upstreams_for(&Route::Local, &c);
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].addr, c.local);
        assert!(!local[0].opts.as_ref().unwrap().tls);
        assert!(!local[0].counts_door_hop, "loopback crosses no door");

        let owner = upstreams_for(&Route::Owner("15.204.89.240".parse().unwrap()), &c);
        assert_eq!(owner[0].addr, "15.204.89.240:443".parse().unwrap());
        let o = owner[0].opts.as_ref().unwrap();
        assert!(o.tls);
        assert_eq!(o.sni, "cloud.mesh.yah.dev");
        assert!(owner[0].counts_door_hop);

        let peers = upstreams_for(&Route::Peers, &c);
        assert_eq!(peers.iter().map(|u| u.addr).collect::<Vec<_>>(), c.peers);
        assert!(peers.iter().all(|u| u.counts_door_hop && u.opts.as_ref().unwrap().tls));
    }

    #[test]
    fn the_wire_shape_parses() {
        let v: OwnerView = serde_json::from_str(
            r#"{"node_id":3,"settled":true,"serving_here":false,
                "owner":{"node_id":2,"machine":"vps-4c1efa56","addr":"100.64.0.1:7443","public_address":"15.204.89.240"}}"#,
        )
        .unwrap();
        assert_eq!(v, view(3, true, false, Some((2, Some("15.204.89.240")))));
        let none: OwnerView =
            serde_json::from_str(r#"{"node_id":3,"settled":false,"owner":null}"#).unwrap();
        assert_eq!(none, view(3, false, false, None));
    }

    #[tokio::test]
    async fn a_failed_poll_with_no_prior_view_routes_to_peers() {
        let src = OwnerUpstreams::new(cfg());
        let ups = src.upstreams().await;
        assert_eq!(ups.iter().map(|u| u.addr).collect::<Vec<_>>(), cfg().peers);
    }

    #[test]
    fn a_failed_poll_keeps_the_last_view_from_this_process() {
        let src = OwnerUpstreams::new(cfg());
        let good = view(2, true, true, Some((2, Some("15.204.89.240"))));
        assert_eq!(src.settle_view(Ok(good.clone())), Some(good.clone()));
        assert_eq!(src.settle_view(Err("down".into())), Some(good));
    }
}
