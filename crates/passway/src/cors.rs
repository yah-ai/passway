//! A mount's CORS allowlist (R826) — passway's copy of the rule the
//! `@mesofact/edge` Worker (`applyRouteHeaders` in
//! `oss/mesofact/packages/mesofact-edge/src/router.ts`) and mesofact's sovereign
//! door (`oss/mesofact/crates/mesofact/src/route_headers.rs`) apply to the same
//! domain-manifest field, `cors_origins`.
//!
//! On a mount that declares a list, every response it serves:
//!
//! - carries `Access-Control-Allow-Origin: <the request's Origin>` when that
//!   origin is listed, compared byte-for-byte;
//! - carries NO `Access-Control-Allow-Origin` otherwise — including one the
//!   upstream set itself, because the declared list is the policy and an
//!   upstream's `*` beside it would quietly be a second one;
//! - carries `Vary: Origin` regardless, merged into any `Vary` already there, so
//!   no cache between here and the browser can hand one origin's answer to
//!   another.
//!
//! Nothing is refused. An unlisted origin gets the bytes without the grant, and
//! the browser is what blocks the read. A mount with no list is untouched.
//!
//! The producer (yubaba's `validate_cors_origin`) checks each entry is a
//! serialized origin. This side refuses only `*` and `null`, the two entries
//! whose meaning would change rather than merely fail to match: `null` is the
//! origin of every sandboxed iframe and `file:` page.

use pingora::http::ResponseHeader;
use pingora::Result as PResult;

const ALLOW_ORIGIN: &str = "access-control-allow-origin";

/// Refuse a list carrying `*` or `null` — see the module doc.
pub fn refuse_wildcards(origins: &[String]) -> Result<(), String> {
    match origins.iter().find(|o| *o == "*" || *o == "null") {
        Some(bad) => Err(format!(
            "cors_origins lists {bad:?}, which would grant every site (or every sandboxed \
             page) rather than the ones named"
        )),
        None => Ok(()),
    }
}

/// What a mount's `cors_origins` decided for one request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CorsVerdict {
    /// The mount declares no list — the response is left exactly as served.
    #[default]
    Undeclared,
    /// The mount declares a list. `Some` is the request's `Origin`, which was
    /// on it.
    Declared(Option<String>),
}

impl CorsVerdict {
    /// Decide against the request's `Origin` header value, if it sent one.
    pub fn decide(origins: &[String], request_origin: Option<&str>) -> Self {
        if origins.is_empty() {
            return Self::Undeclared;
        }
        Self::Declared(
            request_origin
                .filter(|o| origins.iter().any(|listed| listed == o))
                .map(str::to_owned),
        )
    }

    /// Stamp the verdict onto the response going downstream.
    pub fn apply(&self, resp: &mut ResponseHeader) -> PResult<()> {
        let Self::Declared(granted) = self else {
            return Ok(());
        };
        resp.remove_header(ALLOW_ORIGIN);
        if let Some(origin) = granted {
            resp.insert_header(ALLOW_ORIGIN, origin.as_str())?;
        }
        if !varies_on_origin(resp) {
            resp.append_header("vary", "Origin")?;
        }
        Ok(())
    }
}

/// Whether an existing `Vary` already covers `Origin` — named, or `*`.
fn varies_on_origin(resp: &ResponseHeader) -> bool {
    resp.headers
        .get_all("vary")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|t| t == "*" || t.eq_ignore_ascii_case("origin"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listed() -> Vec<String> {
        vec![
            "https://noisetable.com".to_string(),
            "https://staging.noisetable.com".to_string(),
        ]
    }

    fn served(verdict: &CorsVerdict, upstream: &[(&str, &str)]) -> ResponseHeader {
        let mut resp = ResponseHeader::build(200, None).unwrap();
        for (name, value) in upstream {
            resp.append_header(name.to_string(), *value).unwrap();
        }
        verdict.apply(&mut resp).unwrap();
        resp
    }

    fn vary(resp: &ResponseHeader) -> Vec<String> {
        resp.headers
            .get_all("vary")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn each_listed_origin_is_echoed_with_vary() {
        for origin in listed() {
            let resp = served(&CorsVerdict::decide(&listed(), Some(&origin)), &[]);
            assert_eq!(resp.headers.get(ALLOW_ORIGIN).unwrap(), origin.as_str());
            assert_eq!(vary(&resp), vec!["Origin"]);
        }
    }

    #[test]
    fn an_unlisted_origin_gets_no_grant_but_still_varies() {
        let resp = served(
            &CorsVerdict::decide(&listed(), Some("https://evil.example")),
            &[],
        );
        assert!(resp.headers.get(ALLOW_ORIGIN).is_none());
        assert_eq!(vary(&resp), vec!["Origin"]);
    }

    #[test]
    fn no_origin_still_varies_so_a_cache_cannot_replay_it_cross_origin() {
        let resp = served(&CorsVerdict::decide(&listed(), None), &[]);
        assert!(resp.headers.get(ALLOW_ORIGIN).is_none());
        assert_eq!(vary(&resp), vec!["Origin"]);
    }

    #[test]
    fn matching_is_exact() {
        for near in [
            "https://noisetable.com/",
            "https://NOISETABLE.com",
            "http://noisetable.com",
            "https://noisetable.com.evil.example",
        ] {
            assert_eq!(
                CorsVerdict::decide(&listed(), Some(near)),
                CorsVerdict::Declared(None),
                "{near}"
            );
        }
    }

    #[test]
    fn the_list_overrides_an_upstream_grant() {
        let resp = served(
            &CorsVerdict::decide(&listed(), Some("https://evil.example")),
            &[("access-control-allow-origin", "*")],
        );
        assert!(resp.headers.get(ALLOW_ORIGIN).is_none());
    }

    #[test]
    fn vary_merges_rather_than_replacing() {
        let resp = served(
            &CorsVerdict::decide(&listed(), None),
            &[("vary", "Accept-Encoding")],
        );
        assert_eq!(vary(&resp), vec!["Accept-Encoding", "Origin"]);
        let already = served(
            &CorsVerdict::decide(&listed(), None),
            &[("vary", "accept-encoding, origin")],
        );
        assert_eq!(vary(&already), vec!["accept-encoding, origin"]);
    }

    #[test]
    fn an_undeclared_mount_is_untouched() {
        let resp = served(
            &CorsVerdict::decide(&[], Some("https://noisetable.com")),
            &[("access-control-allow-origin", "*")],
        );
        assert_eq!(resp.headers.get(ALLOW_ORIGIN).unwrap(), "*");
        assert!(vary(&resp).is_empty());
    }

    #[test]
    fn wildcards_are_refused() {
        assert!(refuse_wildcards(&listed()).is_ok());
        for bad in ["*", "null"] {
            assert!(refuse_wildcards(&[bad.to_string()]).is_err(), "{bad}");
        }
    }
}
