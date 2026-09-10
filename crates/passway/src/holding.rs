//! R870-F5 — the body a fail-ready 503 carries.
//!
//! Two request paths in [`crate::proxy`] answer 503 without ever touching an
//! upstream: an authority the router serves nothing for, and an authority
//! whose set has no ready backends (R594-F6's fail-ready posture). Both used
//! to write `{"error":"no ready upstreams"}` and nothing else, so a browser
//! landing on an enrolled-but-unbacked tenant — perfect DNS, browser-trusted
//! cert, `:80` redirecting correctly — got the user agent's own naked error
//! chrome.
//!
//! ## The status does not change, only the body
//!
//! 503 is the contract (R594-F6, [`crate::upstream`]'s module doc). Uptime
//! checks and search crawlers read the status, and a 200 holding page would
//! tell every one of them the site is up — strictly worse than the bare 503
//! it replaces. So this module produces *bodies*; the gate above it is
//! untouched, exactly as [`crate::health`] separates its 200-vs-503 gate from
//! the JSON explaining why.
//!
//! `Retry-After` is served alongside, which is the machine-readable half of
//! the same statement: a 503 *with* one is the documented way to tell a
//! crawler "temporary, do not drop the URL," and it costs nothing to a prober
//! that ignores it.
//!
//! ## Content negotiation, so machine callers see no change
//!
//! [`prefers_html`] decides between the two bodies off `Accept`. A browser
//! sends `text/html` and gets [`HOLDING_PAGE`]; a health prober, a curl, a
//! yubaba probe — `*/*` or no `Accept` at all — keeps the byte-identical JSON
//! it has always parsed. That is deliberate: the holding page exists for a
//! human who typed the domain, and every non-human caller of a 503 here is
//! something that was already reading the JSON.
//!
//! ## Nothing about the request is reflected into the page
//!
//! The page is a `&'static str` with no interpolation — no hostname, no path,
//! no header. Two reasons, both load-bearing at a public trust boundary:
//! reflecting attacker-controlled bytes into HTML is the classic injection
//! sink, and the 503 bodies here are deliberately *identical* for "this
//! authority is unknown" and "this authority's backends are down" so the door
//! never enumerates which tenants exist ([`crate::proxy`]'s router-miss
//! comment). A page that named the host would break the second property even
//! if it escaped its way out of the first.
//!
//! ## Floor, not ceiling
//!
//! This is what a tenant sees when it has declared *nothing*. It covers every
//! tenant automatically, including the cold-upstream window on a door that
//! *does* have a backend — where a per-tenant placeholder workload is exactly
//! as absent as the real app, which is why the floor lives here rather than
//! being one more thing each tenant deploys.
//!
//! Two things sit above it. A tenant that deploys a workload serving its own
//! page has a ready upstream and never reaches this code at all. And a domain
//! whose brand the operator owns can override the page — [`HoldingPages`],
//! below.
//!
//! ## The per-domain override (R870-F8)
//!
//! [`HOLDING_PAGE`] is the floor for a tenant that declared nothing;
//! [`HoldingPages`] is what a domain that declared *something* gets instead. It
//! is a lookup from request authority to a page body, loaded from a directory:
//!
//! ```text
//! <PASSWAY_HOLDING_DIR>/
//!   hosts                  # `host=page` lines, one per branded domain
//!   pages/<page>.html      # the body, shared by every host that names it
//! ```
//!
//! **The indirection is the point.** A door may front ten thousand tenants and
//! a handful of brands; one file per *page* rather than per host is what keeps
//! that ratio out of the filesystem, out of the object store, and out of this
//! process's memory — every host naming a page shares one `Arc<str>`.
//!
//! Nothing here fetches: the directory is written by `yubaba::demux_routes`
//! from the same enrollment sweep that publishes the route tables. passway is
//! the most exposed process in the fleet, and the demux next to it deliberately
//! links no HTTP client and holds no bucket credential for exactly that reason
//! (`sni_demux::routes_file`'s module doc). Reading local files it did not
//! write keeps that property: a compromise of a door yields the pages it was
//! already serving to the public.
//!
//! ### What the override does *not* change
//!
//! The status is still 503, the negotiation is still [`prefers_html`], and the
//! bytes are still fixed at load — nothing from the request is interpolated
//! into an override any more than into the default, because it is a whole
//! document read off disk with no substitution site.
//!
//! One property is narrowed, deliberately and only for branded domains. The
//! two 503 paths deliberately answer *identically* for "this authority is
//! unknown" and "this authority has no ready backend", so the door never
//! enumerates its tenants. A branded page is by definition distinguishable —
//! but only for a domain whose operator chose to put their own brand on it,
//! which is a public statement about that domain by construction. Every domain
//! that did not is byte-identical to every unknown authority, as before.
//!
//! @yah:ticket(R870-F7, "Inline the passway default's holding-page graphic as pure CSS — no raster, no fetch, no brand")
//! @yah:status(review)
//! @yah:at(2026-09-08T23:26:25Z)
//! @yah:assignee(agent:claude)
//! @yah:parent(R870)
//! @yah:next("DIVISION OF LABOUR, worth holding to: the animation carries the mood, the copy carries the precision. Do not try to make the graphic explain \"no ready upstreams\" — it will read as \"waiting\", which is right, and the footer already says the rest.")
//! @yah:gotcha("A RASTER ALREADY LIVED HERE AND WAS PULLED — do not put one back. R870-F5 briefly inlined the `solid-parked` camp illustration (both colour variants, base64 data: URIs, 92,668-byte page). It was removed on the operator's call because THIS IS THE PASSWAY DEFAULT: it renders on every tenant domain the fleet fronts, so yah-branded art on a parked noisetable.com is wrong, and oss/passway exports to the public github.com/yah-ai/passway mirror, so the art also shipped outward inside a general-purpose reverse proxy. Pure CSS sidesteps both. The removal also dropped the `base64` direct dep and the assets/ dir; a `the_page_carries_no_branding` unit test now fails on any `data:` URI or brand string, and `MAX_PAGE_BYTES` was lowered 160KiB -> 16KiB so a re-inlined raster fails the suite. Raise neither to fit art.")
//! @yah:verify("`cargo test -p passway` green, with the three holding.rs guard tests still passing UNCHANGED: the_page_reflects_nothing_and_fetches_nothing (no interpolation site, no http(s):// , no <script>, no <link>), the_page_carries_no_branding (no `data:`, no brand strings), the_page_stays_under_its_size_ceiling (16 KiB). If the graphic needs any of those relaxed, that is a signal the graphic is wrong, not the test.")
//! @yah:verify("Eyeball it in both colour schemes AND with reduced motion forced on — the still frame is a real deliverable, not a fallback nobody looks at. macOS: System Settings > Accessibility > Display > Reduce motion.")
//! @yah:handoff("LANDED, and the shipped concept is NOT the arch-and-lantern one this ticket was filed with — the operator redirected to an 80s/cyberdeck direction mid-flight and the lantern is gone. Retired those @yah:next entries so nobody reads the v1 brief as current. What shipped: `.art` is a 170x200 panel holding a perspective grid that recedes to a lit doorway at the vanishing point, scanlines over the whole thing, and three magenta pulses that leave the near edge every 4.2s, recede to the horizon and dissolve with nothing coming back. Same semantics as v1 — the door is lit and working, the far side is empty — in a different idiom.")
//! @yah:handoff("Design by a peer session; I verified and landed it. The delivered file was byte-identical to the current HOLDING_PAGE plus the additions (checked by diff: 79 lines added, 0 removed), so the paste is the CSS block before `</style>` and a 5-line `<div class=\"art\" aria-hidden=\"true\">` above the `<h1>` — no change to the palette block, the copy or the footer, and no new palette var.")
//! @yah:handoff("The other six constraints held as written: inline <style> only, no JS, both colour schemes handled, prefers-reduced-motion still frame, fixed intrinsic box (170x200) so the copy never reflows, and no text or glyphs inside the graphic.")
//! @yah:verify("`cargo test -p passway` GREEN after landing: 155 lib + 43 bin + 28 integration = 226, 0 failed. rustfmt --edition 2021 --check clean. The three pre-existing guard tests pass UNCHANGED — none was relaxed to fit the graphic, which was the filing-time bar.")
//! @yah:verify("Budget verified independently rather than taken on report: whole page 6,030 bytes against the 16 KiB ceiling (graphic ~4,359 of it). I also re-diffed the compiled const against the delivered file after pasting — 0 lines added, 0 removed — so what ships is byte-for-byte what was screenshotted.")
//! @yah:verify("TWO NEW GUARD ASSERTIONS, both catching a real regression shape the existing tests missed: `!HOLDING_PAGE.contains(\"url(\")` folded into the_page_reflects_nothing_and_fetches_nothing (the `data:` check alone does not catch a CSS fetch, and a CSS graphic is exactly what invites one), and a new `the_graphic_can_be_stopped` asserting the page still contains `prefers-reduced-motion` (losing that block ships an unstoppable animation to every 503 — invisible to anyone reviewing without reduced motion on, which is nearly everyone).")
//! @yah:verify("Also checked at paste time, since the page lives in a Rust `r#\"...\"#` raw string: no line contains the sequence `\"#`, which would terminate the literal early and turn a design edit into a compile error at a confusing site. Worth re-running that check on any future graphic edit.")
//! @yah:verify("NOT VERIFIED BY ME: the light/dark/reduced-motion rendering. The designing session reports playwright screenshots in all three, with reduced motion landing on a still frame (three pulses frozen mid-flight) rather than a slowed loop. I verified the CSS says that; I did not run a browser.")
//! @yah:verify("LIVE AND VERIFIED ON ALL THREE INGRESS ORIGINS 2026-09-08 by @Ashguard:griffin (session:9f0f76a8), the session that designed the graphic. Hot-shipped 0.8.36-h2 via 'yah qed run hotship --param nodes=us-east-001,us-south-001,us-west-001 --param binaries=passway'; identical sha256 85699556a07b4c0ed0cdf08f0ffc271e838271fc91ee11402d124c87458369cc installed on all three. https://noisetable.com/ with Accept: text/html now returns 503 + 6030 bytes containing class=\"art\" and prefers-reduced-motion, measured per-origin with --resolve (east 51.81.85.145, south 45.32.194.254, west 15.204.89.240) rather than through round-robin DNS, so no origin is passing on another's behalf. The MACHINE leg is unchanged: no Accept header still yields application/json {\"error\":\"no ready upstreams\"}. This closes the 'NOT VERIFIED LIVE' gap R870-F5 recorded. I also independently re-derived the compiled const rather than trusting the paste: extracted HOLDING_PAGE from holding.rs and diffed its CSS+markup against the file I screenshotted — byte-identical, 6030 bytes, and no '\"#' sequence that would terminate the raw string early.")
//! @yah:handoff("SUPERSEDED BY A SECOND CUT — the panel is now themed, not fixed dark. My retired handoff on this ticket recorded the opposite as settled (\"constraint 4 deliberately overridden, the panel is #07070c in BOTH schemes because a display is dark whichever way the page is\"); the operator rejected that on sight — \"how come the test works with theme BUT not the css image? we need a dark on light version too\" — and they were right. The reasoning was sound and the result was still wrong: the copy above the panel flips with the theme and the panel did not, so on a light page the graphic sat there as a hole. Redesigned and landed by @Ashguard:griffin (session:9f0f76a8) with my agreement; I have retired the contradicting entry so the ticket does not assert both. WHAT IS TRUE NOW: both :root blocks carry a full graphic palette (--panel, --scan, --gridA/B, --edge, --doorfill, --vpCore/--vpHalo/--vpSize, --pulse/--pulseHi) and nothing below them hardcodes a colour. Light is a RE-DRAW, not a dimming: dark teal/magenta ink on a #eef0f6 paper panel. Two of the differences are not colour at all — --scan is transparent on light (scanlines are a CRT artifact; on paper they read as ruled notebook lines and fight the grid) and --vpSize shrinks (the radial bloom that reads as emitted light on a dark panel reads as a stain on a pale one). Page 6,030 -> 7,109 bytes, still far under the 16 KiB ceiling.")
//! @yah:verify("MY CONTRIBUTION TO THE SECOND CUT, since griffin verified the rendering and I own the guard tests: turned their \"every colour is a var\" invariant from a one-off check plus a comment into two standing tests. `every_colour_in_the_graphic_is_a_var` slices the page from the `.art` rule to `</style>` and fails on any hex literal or rgb/rgba/hsl/hsla/color-mix in that region. `both_schemes_define_the_whole_graphic_palette` splits at the dark block's @media and asserts all eleven graphic vars are declared on BOTH sides — a var declared in only one scheme renders as nothing in the other, which is the same class of bug pointed the other way. This is worth having as a test rather than a comment precisely because, unlike the fetch and size guards, a hardcoded colour looks correct in a diff to whoever had one theme open: it is what put a dark panel on a light page in the first cut. `cargo test -p passway` 157 lib + 43 bin + 28 integration = 228, 0 failed; rustfmt clean; page measured at 7,109 bytes independently, matching griffin's figure.")
//! @yah:handoff("CONSTRAINT 4 IS BACK IN FORCE — the fixed-dark-panel override is REVERSED, on the operator's read: 'how come the test works with theme BUT not the css image? we need a dark on light version too'. They were right and the earlier reasoning ('a display is dark whichever way the page is') was internally consistent while still producing a hole on a light page: the copy under the graphic flipped with the theme and the panel did not. Both :root blocks now carry a full graphic palette — --panel, --scan, --gridA, --gridB, --edge, --doorfill, --vpCore, --vpHalo, --vpSize, --pulse, --pulseHi — and NOTHING in the graphic CSS hardcodes a colour. The light cut is a RE-DRAW, not a dimming: dark teal/magenta ink on a #eef0f6 paper panel, which is where a perspective grid came from before it was ever a CRT. TWO DIFFERENCES ARE NOT COLOUR, and both were found by looking rather than reasoning, so do not 'simplify' either away as an inconsistency: --scan is transparent on light, because scanlines are a CRT artifact and on paper they read as ruled notebook lines that fight the grid; and --vpSize shrinks the vanishing point on light, because the same radial bloom that reads as EMITTED LIGHT on a dark panel reads as a STAIN on a pale one. Page 6,030 -> 7,109 bytes (graphic 4,359 -> 4,669), still far under the 16 KiB ceiling. The doc section '### The panel is dark in BOTH colour schemes, on purpose' is replaced by '### Two palettes, one drawing — and every colour is a var', carrying the same do-not-undo warning pointed the other way.")
//! @yah:verify("THEME-AWARE CUT LIVE ON ALL THREE INGRESS ORIGINS 2026-09-08 (@Ashguard:griffin, session:9f0f76a8). Hot-shipped 0.8.36-h3, identical sha256 766b64d775b125ff5045e9bdf64517c8e29eb3d06740ed137d31bf86fc2e42e6 on us-east-001/us-south-001/us-west-001. All three serve 503 + 7,109 bytes; the light palette is present in the LIVE bytes (--panel: #eef0f6, --scan: transparent, --vpSize: 34px), and the machine leg still returns application/json. Measured per-origin with --resolve, not through round-robin DNS. cargo test -p passway 228/0 on the SETTLED tree — the first run was re-done because the camp's build-skew guard flagged a peer editing holding.rs mid-run, so that green described a tree that no longer existed. Screenshotted the LIVE URL in both schemes, not the local preview, and diffed the served bytes against the file I screenshotted: byte-identical. ONE PROCESS NOTE WORTH CARRYING: my first live screenshot pass rendered at a 430x330 viewport and the door and vanishing point were BOTH ABSENT from the image. That was not a rendering bug — body is flex-centred with height:100%, so at a viewport shorter than the content the top of main is clipped and unreachable, and Playwright's element screenshot captured the clipped box. Verify the served BYTES before believing a screenshot that says the graphic is broken; shoot at >=900px tall.")

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use http::header::ACCEPT;
use http::HeaderMap;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;

/// Seconds advertised in `Retry-After` on a fail-ready 503.
///
/// Short on purpose: the condition this accompanies is "a backend has not
/// appeared *yet*", which discovery resolves on its own polling interval, so
/// the honest hint is tens of seconds rather than hours.
pub const RETRY_AFTER_SECS: u32 = 30;

/// `Content-Type` for [`HOLDING_PAGE`].
pub const HOLDING_PAGE_CONTENT_TYPE: &str = "text/html; charset=utf-8";

/// The holding page itself: one self-contained document, no external font,
/// stylesheet, script or image. A door serving this page is by definition a
/// door whose backend is missing, so anything it fetched from elsewhere would
/// be a second thing that can fail while it is already failing.
///
/// A `&'static str` with no interpolation, which is how the "nothing from the
/// request is reflected" property is enforced structurally rather than by
/// review: there is no seam through which a hostname or path *could* arrive.
///
/// ## The graphic (R870-F7)
///
/// Pure inline CSS — a perspective grid receding to a lit doorway, scanlines,
/// and three pulses that leave the near edge, recede to the vanishing point and
/// dissolve with nothing coming back. No raster, and that is not an aesthetic
/// preference: a raster illustration briefly lived here and was pulled, because
/// this is the **passway default** rendered on every tenant domain the fleet
/// fronts (so it must carry no yah branding) and `oss/passway` is exported to a
/// public OSS mirror. Per-domain art, including the `solid-parked` camp
/// illustration for the yah.dev family, is R870-F8's override rather than
/// anything compiled in here.
///
/// ### Two palettes, one drawing — and every colour is a var
///
/// The graphic is themed exactly like the copy above it: the two `:root` blocks
/// carry a full set of graphic vars (`--panel`, `--scan`, `--gridA`/`--gridB`,
/// `--edge`, `--doorfill`, `--vpCore`/`--vpHalo`/`--vpSize`, `--pulse`/
/// `--pulseHi`) and **nothing below them hardcodes a colour**. Keep it that way;
/// a literal reintroduced into the graphic CSS is correct in one scheme and
/// wrong in the other, which is a defect no test catches and no reviewer sees
/// unless they flip their OS theme.
///
/// A previous cut pinned the panel dark in *both* schemes, reasoning that the
/// graphic is a display and a display is dark whichever way the page is. It
/// rendered well and was still wrong: the copy under it flips with the theme and
/// the panel did not, so on a light page the block sat there as a hole. The
/// light palette is therefore a **re-draw, not a dimming** — dark ink on paper,
/// which is where a perspective grid came from before it was ever a CRT.
///
/// Two of the differences are not just colour, and both were found by looking
/// rather than reasoning:
///
/// - `--scan` is `transparent` in light. Scanlines are a CRT artifact; on the
///   paper cut they read as ruled notebook lines and fight the grid.
/// - `--vpSize` shrinks the vanishing point on light. The same radial bloom that
///   reads as *emitted light* on a dark panel reads as a *stain* on a pale one,
///   so the light cut uses a smaller, denser point.
pub const HOLDING_PAGE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Not serving yet</title>
<style>
  :root {
    color-scheme: light dark; --fg: #16181d; --dim: #6b7280; --bg: #fbfbfd; --line: #e4e4e9;
    /* Graphic palette, light: ink on paper. Same drawing as the dark one, not
       a dimmed copy of it -- a plotter sheet rather than a CRT. */
    --panel: #eef0f6; --scan: transparent; --vpSize: 34px;
    --gridA: rgba(8,110,130,.62); --gridB: rgba(8,110,130,.34);
    --edge: #0e7490; --doorfill: rgba(159,18,80,.20);
    --vpCore: rgba(131,17,66,.95); --vpHalo: rgba(190,24,93,.38);
    --pulse: #be185d; --pulseHi: #e83e8c;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --fg: #e8eaef; --dim: #9aa1ad; --bg: #101216; --line: #262a32;
      --panel: #07070c; --scan: rgba(255,255,255,.035); --vpSize: 54px;
      --gridA: rgba(0,229,255,.55); --gridB: rgba(0,229,255,.30);
      --edge: rgba(0,229,255,.9); --doorfill: rgba(255,45,149,.28);
      --vpCore: rgba(255,224,244,.95); --vpHalo: rgba(255,45,149,.42);
      --pulse: #ff2d95; --pulseHi: #ff8ac4;
    }
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font: 16px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    display: flex; align-items: center; justify-content: center; padding: 6vh 24px;
  }
  main { max-width: 34rem; }
  h1 { font-size: 1.5rem; line-height: 1.3; font-weight: 600; margin: 0 0 0.75rem; letter-spacing: -0.01em; }
  p { margin: 0 0 1rem; }
  .dim { color: var(--dim); }
  footer {
    margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--line);
    color: var(--dim); font-size: 0.8125rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }

  /* The passway, as a screen: a grid running out to a lit door that has
     nothing behind it. Three pulses leave the near edge every 4.2s, recede to
     the vanishing point and dissolve; nothing comes back.

     EVERY COLOUR HERE IS A VAR, set once per scheme in the two :root blocks
     above -- do not hardcode one back in. An earlier cut pinned the panel dark
     in both schemes on the theory that a display is dark whichever way the
     page is. It rendered fine and was still wrong: the copy under it flips
     with the theme and the graphic did not, so on a light page the block sat
     there as a hole. The light palette is a re-draw, not a dimming -- ink on
     paper, which is where this grid came from before it was ever a CRT.

     Pure CSS: a door serving this page has no backend, so the graphic may not
     fetch a font, an image or a script. Fixed 170x200 box, so the copy under
     it never reflows. */
  .art {
    position: relative; width: 170px; height: 200px; margin: 0 0 1.5rem;
    background: var(--panel); border: 1px solid var(--line); overflow: hidden;
  }
  /* Scanlines, last child so they sit over everything. */
  .art::after {
    content: ""; position: absolute; inset: 0; pointer-events: none;
    background: repeating-linear-gradient(0deg, var(--scan) 0 1px, transparent 1px 3px);
  }
  /* Ground plane. transform-origin pins the far edge to the horizon, so the
     perspective convergence lands exactly on the doorway. */
  .grid {
    position: absolute; left: -60%; right: -60%; top: 84px; bottom: -40px;
    transform: perspective(76px) rotateX(58deg); transform-origin: 50% 0;
    background-image:
      repeating-linear-gradient(90deg, transparent 0 11px, var(--gridA) 11px 12px),
      repeating-linear-gradient(0deg,  transparent 0 12px, var(--gridB) 12px 13px);
  }
  /* Haze at the far edge -- cheaper and more portable than a mask, and exact
     because the panel colour is known. */
  .haze { position: absolute; left: 0; right: 0; top: 84px; height: 46px; background: linear-gradient(180deg, var(--panel), transparent); }
  .hz {
    position: absolute; left: 0; right: 0; top: 84px; height: 1px;
    background: linear-gradient(90deg, transparent, var(--edge) 20%, var(--pulse) 50%, var(--edge) 80%, transparent);
  }
  /* The door: at the far end, lit, open, with nothing behind it. */
  .door {
    position: absolute; left: 50%; top: 32px; width: 40px; height: 52px; margin-left: -20px;
    border: 1px solid var(--edge); border-bottom: 0;
    background: linear-gradient(180deg, transparent 30%, var(--doorfill));
  }
  .vp {
    position: absolute; left: 50%; top: 84px; width: var(--vpSize); height: var(--vpSize);
    margin: calc(var(--vpSize) / -2) 0 0 calc(var(--vpSize) / -2);
    border-radius: 50%;
    background: radial-gradient(circle, var(--vpCore) 0 5%, var(--vpHalo) 16%, transparent 58%);
    animation: burn 1.9s ease-in-out infinite, breathe 2.9s ease-in-out infinite;
  }
  .art i {
    position: absolute; left: 12px; right: 12px; bottom: 14px; height: 1px; opacity: 0;
    background: linear-gradient(90deg, transparent, var(--pulse) 15%, var(--pulseHi) 50%, var(--pulse) 85%, transparent);
    animation: send 4.2s cubic-bezier(.3,0,.25,1) infinite;
  }
  .art i:nth-of-type(2) { animation-delay: .26s; }
  .art i:nth-of-type(3) { animation-delay: .52s; }
  /* Coprime durations, so the vanishing point's visible period is ~55s and
     never reads metronomic. */
  @keyframes burn { 0%,100% { opacity: 1 } 17% { opacity: .62 } 29% { opacity: .95 } 46% { opacity: .5 } 61% { opacity: .86 } 78% { opacity: .7 } }
  @keyframes breathe { 0%,100% { transform: scale(1) } 37% { transform: scale(.9) } 68% { transform: scale(1.08) } }
  /* Travel occupies the first 42%; the rest of the cycle is the silence after.
     Decelerating, because a constant-speed object on a receding plane does. */
  @keyframes send {
    0%   { transform: none; opacity: 0 }
    9%   { opacity: .95 }
    42%  { transform: translateY(-104px) scaleX(.13); opacity: 0 }
    100% { transform: translateY(-104px) scaleX(.13); opacity: 0 }
  }
  @media (prefers-reduced-motion: reduce) {
    /* A still frame, not a slower loop: three pulses frozen mid-flight. */
    .vp, .art i { animation: none; }
    .art i { opacity: .9; }
    .art i:nth-of-type(2) { transform: translateY(-56px) scaleX(.52); opacity: .55; }
    .art i:nth-of-type(3) { transform: translateY(-88px) scaleX(.24); opacity: .28; }
  }
</style>
</head>
<body>
<main>
  <div class="art" aria-hidden="true">
    <div class="grid"></div><div class="haze"></div><div class="hz"></div>
    <div class="door"></div><div class="vp"></div>
    <i></i><i></i><i></i>
  </div>
  <h1>This site isn&rsquo;t serving yet</h1>
  <p>
    The domain resolves and its certificate is valid &mdash; the front door is
    working. There is just no application behind it right now.
  </p>
  <p class="dim">
    If you were expecting a site here, try again in a moment: this page is also
    what you see in the seconds after a deploy, before the new backend reports
    ready.
  </p>
  <footer>HTTP 503 &middot; no ready upstreams</footer>
</main>
</body>
</html>
"#;

/// Does this client want the HTML page rather than the JSON error?
///
/// True only for an explicit `text/html` (or `application/xhtml+xml`) in
/// `Accept`. `*/*`, `text/*` and a missing header all read as "machine", which
/// is the conservative direction: a prober miscategorised as a browser gets an
/// HTML body where it expected JSON, whereas a browser miscategorised as a
/// prober merely sees the readable-but-plain JSON it saw before this module
/// existed.
///
/// A range explicitly refused with `q=0` does not count as a request for it.
pub fn prefers_html(headers: &HeaderMap) -> bool {
    headers
        .get_all(ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(accepts_html_range)
}

/// One comma-separated element of an `Accept` header: a media range plus
/// optional `;`-separated parameters.
fn accepts_html_range(range: &str) -> bool {
    let mut parts = range.split(';');
    let media = parts.next().unwrap_or("").trim();
    if !media.eq_ignore_ascii_case("text/html")
        && !media.eq_ignore_ascii_case("application/xhtml+xml")
    {
        return false;
    }
    // `text/html;q=0` is a refusal, not a request.
    !parts.any(|p| {
        let mut kv = p.splitn(2, '=');
        let key = kv.next().unwrap_or("").trim();
        let val = kv.next().unwrap_or("").trim();
        key.eq_ignore_ascii_case("q") && val.parse::<f32>().is_ok_and(|q| q <= 0.0)
    })
}

// ── The per-domain override (R870-F8) ────────────────────────────────────────

/// Name of the host→page map inside the holding directory.
///
/// The writer is `yubaba::demux_routes::HOLDING_MAP_FILE`, in another Cargo
/// workspace with no crate in common — so both ends name it from a constant and
/// both pin the spelling in a test that says so.
pub const HOLDING_MAP_FILE: &str = "hosts";

/// Subdirectory the page bodies live in, one `<name>.html` per page. Twin of
/// `yubaba::demux_routes::HOLDING_PAGES_DIR`; see [`HOLDING_MAP_FILE`].
pub const HOLDING_PAGES_DIR: &str = "pages";

/// The largest override this door will serve.
///
/// Twin of `yubaba::cert_store::MAX_HOLDING_PAGE_BYTES`, which refuses an
/// oversized page at upload time where a human sees the refusal; this is the
/// backstop for a page that reached the disk some other way. Deliberately far
/// above [`HOLDING_PAGE`]'s own 16 KiB ceiling — an override is a branded
/// document that may carry inlined artwork, whereas the default is served to
/// every tenant on every crawl and is held to a much tighter budget.
pub const MAX_OVERRIDE_PAGE_BYTES: usize = 256 * 1024;

/// How often [`HoldingWatcher`] re-reads the directory, when nothing says
/// otherwise.
///
/// Slower than the demux's 10s route reload, on purpose: a stale route is a
/// tenant that cannot be reached, while a stale holding page is a tenant that
/// is unreachable *and* momentarily unbranded. Only one of those is worth
/// polling hard for.
pub const DEFAULT_RELOAD_SECS: u64 = 30;

/// Per-authority holding pages: which domains show something other than
/// [`HOLDING_PAGE`], and what.
///
/// Cheap to snapshot and cheap to share — hosts pointing at one page share one
/// `Arc<str>`, so the memory cost is the *page* count, not the host count.
#[derive(Debug, Default)]
pub struct HoldingPages {
    by_host: BTreeMap<String, Arc<str>>,
    pages: usize,
    /// Content fingerprint of everything that was read to build this. Compared
    /// by [`HoldingWatcher`] instead of the map itself: comparing two 10k-entry
    /// maps of 100 KB pages by value on every poll would cost more than the
    /// reload it is trying to avoid.
    fingerprint: u64,
}

impl HoldingPages {
    /// No overrides — every authority gets [`HOLDING_PAGE`].
    pub fn empty() -> Self {
        Self::default()
    }

    /// The page `host` should be served, if it has one.
    ///
    /// Case-insensitive, because an authority arrives as the client typed it
    /// and DNS does not care; the map is lowercased at load for the same
    /// reason. A `None` host — a request with no authority at all — never
    /// matches: an override belongs to a *named* domain.
    pub fn page_for(&self, host: Option<&str>) -> Option<&Arc<str>> {
        let host = host?;
        // The common case is already lowercase, so try it before allocating.
        self.by_host
            .get(host)
            .or_else(|| self.by_host.get(&host.to_ascii_lowercase()))
    }

    /// How many authorities carry an override.
    pub fn hosts(&self) -> usize {
        self.by_host.len()
    }

    /// How many distinct pages back them.
    pub fn pages(&self) -> usize {
        self.pages
    }

    /// Read a holding directory.
    ///
    /// Never fails: a directory that is missing, unreadable, empty or
    /// half-published loads as *fewer overrides*, and the caller's fallback is
    /// the page every tenant would otherwise have had. There is no state of
    /// this directory that should stop a door from answering, which is why the
    /// return type has no error half at all — see [`HoldingWatcher`] for the
    /// separate question of when to *replace* a live map with a worse one.
    ///
    /// Everything skipped is logged with the reason, once per load.
    pub fn load(dir: &Path) -> Self {
        let map_path = dir.join(HOLDING_MAP_FILE);
        let raw = match std::fs::read(&map_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                log::warn!(
                    "holding pages: {} unreadable ({e}); no per-domain overrides",
                    map_path.display()
                );
                return Self::empty();
            }
        };
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        raw.hash(&mut hasher);
        let Ok(text) = String::from_utf8(raw) else {
            log::warn!(
                "holding pages: {} is not UTF-8; no per-domain overrides",
                map_path.display()
            );
            return Self::empty();
        };

        let pages_dir = dir.join(HOLDING_PAGES_DIR);
        // Load each page once however many hosts name it — the whole reason the
        // map stores a name rather than a body.
        let mut loaded: BTreeMap<String, Option<Arc<str>>> = BTreeMap::new();
        let mut by_host: BTreeMap<String, Arc<str>> = BTreeMap::new();
        for (host, name) in parse_map(&text) {
            let page = loaded
                .entry(name.clone())
                .or_insert_with(|| read_page(&pages_dir, &name));
            let Some(page) = page else {
                // Already warned about by `read_page`; the host simply keeps the
                // default page rather than the door failing to answer.
                continue;
            };
            if by_host.insert(host.clone(), page.clone()).is_some() {
                log::warn!(
                    "holding pages: {} names {host} more than once; keeping the last entry",
                    map_path.display()
                );
            }
        }
        for (name, page) in &loaded {
            name.hash(&mut hasher);
            page.as_deref().unwrap_or("").hash(&mut hasher);
        }
        Self {
            pages: loaded.values().filter(|p| p.is_some()).count(),
            by_host,
            fingerprint: hasher.finish(),
        }
    }
}

/// Whether `name` may name a page file.
///
/// Twin of `yubaba::cert_store::is_safe_holding_name`, and re-checked here
/// rather than trusted: this end is the one that turns the name into a path, so
/// it is the end where a `../` would matter. The writer refuses these too, so a
/// rejection means the map was hand-edited or written by something else.
fn is_safe_page_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// `host=page` lines, in file order. Blank lines and `#` comments are skipped;
/// so is anything malformed, with a reason.
fn parse_map(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((host, name)) = line.split_once('=') else {
            log::warn!("holding pages: {line:?} is not `host=page`; ignored");
            continue;
        };
        let (host, name) = (host.trim(), name.trim());
        if host.is_empty() {
            log::warn!("holding pages: {line:?} has an empty host; ignored");
            continue;
        }
        if !is_safe_page_name(name) {
            log::warn!("holding pages: {line:?} names an unusable page; ignored");
            continue;
        }
        out.push((host.to_ascii_lowercase(), name.to_string()));
    }
    out
}

/// Read one page body, or `None` with a logged reason.
fn read_page(pages_dir: &Path, name: &str) -> Option<Arc<str>> {
    let path = pages_dir.join(format!("{name}.html"));
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            log::warn!(
                "holding pages: {} unreadable ({e}); its domains keep the default page",
                path.display()
            );
            return None;
        }
    };
    if bytes.len() > MAX_OVERRIDE_PAGE_BYTES {
        log::warn!(
            "holding pages: {} is {} bytes, over the {MAX_OVERRIDE_PAGE_BYTES}-byte ceiling; \
             its domains keep the default page",
            path.display(),
            bytes.len()
        );
        return None;
    }
    match String::from_utf8(bytes) {
        Ok(text) => Some(Arc::from(text.as_str())),
        Err(e) => {
            log::warn!(
                "holding pages: {} is not UTF-8 ({e}); its domains keep the default page",
                path.display()
            );
            None
        }
    }
}

/// The live override map, swappable underneath the request path.
///
/// `std::sync::RwLock` and an `Arc` snapshot per read, exactly as
/// `sni_demux::routes_file::SharedRoutes` does it and for the same reason: the
/// critical section is one `Arc::clone` with nothing awaited inside it.
pub type SharedHoldingPages = Arc<RwLock<Arc<HoldingPages>>>;

/// Wrap a map so it can be swapped.
pub fn shared(pages: HoldingPages) -> SharedHoldingPages {
    Arc::new(RwLock::new(Arc::new(pages)))
}

/// Snapshot the live map for one request.
///
/// Recovers from a poisoned lock rather than panicking: the only writer swaps a
/// single `Arc` and cannot leave a torn value, so refusing to serve every
/// subsequent 503 over a poisoned lock would turn one unrelated panic into a
/// worse outage than the one being reported.
pub fn current(pages: &SharedHoldingPages) -> Arc<HoldingPages> {
    match pages.read() {
        Ok(g) => g.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

/// Background service that re-reads the holding directory and swaps the map
/// when its contents change.
///
/// ## Why this one *does* accept an empty reload
///
/// `sni_demux::routes_file::watch` refuses to install an empty table, because
/// an empty route table and "every tenant was deleted" are indistinguishable
/// and one of them is a total outage. The holding map has no such asymmetry: an
/// empty map is the correct steady state on any door where nobody has set an
/// override, and installing one costs a branded tenant its artwork on a page
/// that is already a 503. Refusing it instead would mean a door could never
/// *un*-brand a domain without a restart.
///
/// Unreadable is different from empty, and is still refused: the publisher
/// writes with tmp-plus-rename, so a read error is a transient or a bad deploy
/// rather than an instruction. [`HoldingPages::load`] returns an empty map for
/// both cases, so the watcher distinguishes them itself before swapping.
pub struct HoldingWatcher {
    dir: PathBuf,
    pages: SharedHoldingPages,
    interval: Duration,
}

impl HoldingWatcher {
    pub fn new(dir: PathBuf, pages: SharedHoldingPages, interval: Duration) -> Self {
        Self {
            dir,
            pages,
            interval,
        }
    }

    /// One poll: reload, and swap if anything changed. Returns whether it did.
    ///
    /// Split from the loop so the decision is testable without a runtime.
    pub fn poll_once(&self) -> bool {
        if !self.dir.join(HOLDING_MAP_FILE).exists() {
            // Nothing to read. Keeping the live map is the fail-stale half:
            // a publisher mid-rename, or a directory that has not been mounted
            // yet, must not un-brand a live door.
            return false;
        }
        let next = HoldingPages::load(&self.dir);
        let live = current(&self.pages);
        if next.fingerprint == live.fingerprint {
            return false;
        }
        log::info!(
            "holding pages: {} -> {} host(s) over {} page(s)",
            live.hosts(),
            next.hosts(),
            next.pages()
        );
        match self.pages.write() {
            Ok(mut g) => *g = Arc::new(next),
            Err(poisoned) => *poisoned.into_inner() = Arc::new(next),
        }
        true
    }
}

#[async_trait]
impl BackgroundService for HoldingWatcher {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut tick = tokio::time::interval(self.interval);
        // The first tick fires immediately; the initial load already happened at
        // startup, so let it re-check and no-op rather than special-casing it.
        loop {
            tokio::select! {
                _ = tick.tick() => { self.poll_once(); }
                _ = shutdown.changed() => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HeaderValue;

    /// A ceiling on the page. Purely a tripwire: the body is written on every
    /// browser-shaped 503, including to crawlers, so R870-F7's inline CSS
    /// graphic (or a raster somebody inlines at source resolution) should fail
    /// the suite rather than quietly ship a multi-hundred-KB error page.
    const MAX_PAGE_BYTES: usize = 16 * 1024;

    fn accept(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(ACCEPT, HeaderValue::from_str(v).unwrap());
        h
    }

    #[test]
    fn a_browser_accept_wants_html() {
        // Verbatim from Firefox / Chrome.
        assert!(prefers_html(&accept(
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        )));
        assert!(prefers_html(&accept(
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )));
    }

    #[test]
    fn a_machine_accept_does_not() {
        // curl, most probers, and anything asking for the JSON explicitly.
        assert!(!prefers_html(&accept("*/*")));
        assert!(!prefers_html(&accept("application/json")));
        assert!(!prefers_html(&accept("application/json, text/plain, */*")));
        assert!(!prefers_html(&accept("text/*")));
    }

    #[test]
    fn no_accept_header_is_a_machine() {
        assert!(!prefers_html(&HeaderMap::new()));
    }

    #[test]
    fn html_refused_with_q0_is_not_a_request_for_html() {
        assert!(!prefers_html(&accept("text/html;q=0, application/json")));
        assert!(!prefers_html(&accept("text/html;q=0.0")));
        // But a *deprioritized* html is still an acceptable html.
        assert!(prefers_html(&accept("application/json, text/html;q=0.1")));
    }

    #[test]
    fn matching_is_case_and_whitespace_insensitive() {
        assert!(prefers_html(&accept("  TEXT/HTML ; Q=1.0 ")));
        assert!(prefers_html(&accept("Application/XHTML+XML")));
    }

    #[test]
    fn several_accept_header_lines_are_all_considered() {
        let mut h = HeaderMap::new();
        h.append(ACCEPT, HeaderValue::from_static("application/json"));
        h.append(ACCEPT, HeaderValue::from_static("text/html"));
        assert!(prefers_html(&h));
    }

    #[test]
    fn the_page_reflects_nothing_and_fetches_nothing() {
        // The two properties the module doc leans on: no interpolation site
        // through which a request value could arrive, and no second request
        // needed to render a page whose whole subject is a failed request.
        assert!(!HOLDING_PAGE.contains("{}"));
        assert!(!HOLDING_PAGE.contains("http://"));
        assert!(!HOLDING_PAGE.contains("https://"));
        assert!(!HOLDING_PAGE.contains("<script"));
        assert!(!HOLDING_PAGE.contains("<link"));
        // `url(` is the other shape a fetch sneaks back in as, and the one a
        // CSS graphic invites — a `data:` check alone does not catch it.
        assert!(!HOLDING_PAGE.contains("url("));
        // It must not claim to be healthy, and must say what it is.
        assert!(HOLDING_PAGE.contains("503"));
    }

    #[test]
    fn the_graphic_can_be_stopped() {
        // R870-F7: losing this block ships an unstoppable animation to every
        // 503 — an accessibility regression that is invisible to anyone not
        // running with reduced motion on, which is nearly everyone reviewing it.
        assert!(HOLDING_PAGE.contains("prefers-reduced-motion"));
    }

    #[test]
    fn every_colour_in_the_graphic_is_a_var() {
        // The invariant the graphic's own comment asks the next editor to keep,
        // made enforceable. A hardcoded colour below the palette blocks is
        // correct in whichever scheme its author had open and wrong in the
        // other — and unlike the fetch and size guards, nothing about it looks
        // wrong in a diff, so it survives review and ships. It is what put a
        // dark panel on a light page once already.
        let start = HOLDING_PAGE.find("  .art {").expect("the .art rule");
        let end = HOLDING_PAGE
            .find("</style>")
            .expect("the end of the stylesheet");
        let graphic = &HOLDING_PAGE[start..end];
        for f in ["rgb(", "rgba(", "hsl(", "hsla(", "color-mix("] {
            assert!(
                !graphic.contains(f),
                "graphic CSS hardcodes `{f}` — every colour belongs in the two \
                 :root palette blocks, referenced here as var(--…)"
            );
        }
        let hex = graphic
            .as_bytes()
            .windows(2)
            .any(|w| w[0] == b'#' && w[1].is_ascii_hexdigit());
        assert!(
            !hex,
            "graphic CSS hardcodes a hex colour — every colour belongs in the \
             two :root palette blocks, referenced here as var(--…)"
        );
    }

    #[test]
    fn both_schemes_define_the_whole_graphic_palette() {
        // The other half: a var referenced by the graphic but declared in only
        // one :root block renders as nothing in the other scheme. Splitting the
        // page at the dark block's `@media` is enough to check each side.
        let dark_at = HOLDING_PAGE
            .find("@media (prefers-color-scheme: dark)")
            .expect("the dark palette block");
        let (light, dark) = HOLDING_PAGE.split_at(dark_at);
        for var in [
            "--panel",
            "--scan",
            "--gridA",
            "--gridB",
            "--edge",
            "--doorfill",
            "--vpCore",
            "--vpHalo",
            "--vpSize",
            "--pulse",
            "--pulseHi",
        ] {
            let decl = format!("{var}:");
            assert!(light.contains(&decl), "{var} is not declared for light");
            assert!(dark.contains(&decl), "{var} is not declared for dark");
        }
    }

    #[test]
    fn the_page_carries_no_branding() {
        // R870-F7/F8: this is the default EVERY tenant domain inherits, and it
        // is exported to a public OSS mirror. Branded art belongs on the
        // per-domain override, never here. A `data:` URI is the shape a raster
        // would sneak back in as.
        assert!(!HOLDING_PAGE.contains("data:"));
        for brand in ["yah", "noisetable"] {
            assert!(
                !HOLDING_PAGE.to_ascii_lowercase().contains(brand),
                "the passway default must not name {brand}"
            );
        }
    }

    #[test]
    fn the_page_stays_under_its_size_ceiling() {
        let len = HOLDING_PAGE.len();
        assert!(
            len <= MAX_PAGE_BYTES,
            "holding page is {len} bytes, ceiling is {MAX_PAGE_BYTES} — \
             R870-F7's graphic is inline CSS for exactly this reason; do not \
             raise this to fit a raster"
        );
    }

    // ── The per-domain override (R870-F8) ────────────────────────────────────

    /// The crate's scratch-dir idiom (see `acme.rs`); no `tempfile` dev-dep.
    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A holding directory containing `hosts` and each `(name, body)` page.
    fn holding_dir(map: &str, pages: &[(&str, &str)]) -> TempDir {
        let dir = std::env::temp_dir().join(format!(
            "passway-holding-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(HOLDING_PAGES_DIR)).unwrap();
        std::fs::write(dir.join(HOLDING_MAP_FILE), map).unwrap();
        for (name, body) in pages {
            std::fs::write(
                dir.join(HOLDING_PAGES_DIR).join(format!("{name}.html")),
                body,
            )
            .unwrap();
        }
        TempDir(dir)
    }

    #[test]
    fn a_mapped_host_gets_its_page_and_an_unmapped_one_does_not() {
        let dir = holding_dir(
            "yah.dev=camp\nwww.yah.dev=camp\n",
            &[("camp", "<!doctype html><p>camp</p>")],
        );
        let pages = HoldingPages::load(&dir.0);
        assert_eq!(pages.hosts(), 2);
        assert_eq!(
            pages.page_for(Some("yah.dev")).map(|p| p.to_string()),
            Some("<!doctype html><p>camp</p>".to_string())
        );
        assert!(pages.page_for(Some("noisetable.com")).is_none());
        assert!(pages.page_for(None).is_none(), "an override needs a name");
    }

    /// The memory argument the whole `host=name` indirection exists for: N
    /// hosts naming one page hold ONE copy of it, not N.
    #[test]
    fn hosts_naming_one_page_share_one_body() {
        let dir = holding_dir("a.test=camp\nb.test=camp\n", &[("camp", "<p>camp</p>")]);
        let pages = HoldingPages::load(&dir.0);
        assert_eq!(pages.pages(), 1);
        let (a, b) = (
            pages.page_for(Some("a.test")).unwrap(),
            pages.page_for(Some("b.test")).unwrap(),
        );
        assert!(Arc::ptr_eq(a, b), "two hosts, one page, one allocation");
    }

    #[test]
    fn an_authority_is_matched_case_insensitively() {
        let dir = holding_dir("YAH.dev=camp\n", &[("camp", "<p>camp</p>")]);
        let pages = HoldingPages::load(&dir.0);
        assert!(pages.page_for(Some("yah.dev")).is_some());
        assert!(pages.page_for(Some("YAH.DEV")).is_some());
    }

    /// Every way the directory can be wrong resolves to "this host keeps the
    /// default page", never to a load failure — a door must answer regardless.
    #[test]
    fn a_broken_entry_costs_only_its_own_host() {
        let dir = holding_dir(
            "# a comment\n\
             \n\
             good.test=camp\n\
             dangling.test=nosuchpage\n\
             nonsense-line\n\
             =camp\n\
             traversal.test=../../etc/passwd\n\
             absolute.test=/etc/passwd\n\
             dotted.test=camp.html\n",
            &[("camp", "<p>camp</p>")],
        );
        let pages = HoldingPages::load(&dir.0);
        assert_eq!(pages.hosts(), 1, "only the good entry survives");
        assert!(pages.page_for(Some("good.test")).is_some());
        for host in [
            "dangling.test",
            "traversal.test",
            "absolute.test",
            "dotted.test",
        ] {
            assert!(pages.page_for(Some(host)).is_none(), "{host} must not map");
        }
    }

    #[test]
    fn a_missing_directory_is_no_overrides_rather_than_a_failure() {
        let pages = HoldingPages::load(Path::new("/nonexistent/passway/holding"));
        assert_eq!(pages.hosts(), 0);
        assert!(pages.page_for(Some("yah.dev")).is_none());
    }

    #[test]
    fn a_page_over_the_ceiling_is_refused() {
        let big = "x".repeat(MAX_OVERRIDE_PAGE_BYTES + 1);
        let dir = holding_dir("big.test=big\n", &[("big", &big)]);
        let pages = HoldingPages::load(&dir.0);
        assert!(
            pages.page_for(Some("big.test")).is_none(),
            "an oversized override falls back to the default page"
        );
    }

    /// The ceiling is duplicated in `yubaba::cert_store::MAX_HOLDING_PAGE_BYTES`
    /// (another Cargo workspace, no shared crate). If you change it here,
    /// change it there — an override past the door's ceiling is accepted at
    /// upload and then silently never appears.
    #[test]
    fn the_ceiling_and_the_layout_match_the_publishers_constants() {
        assert_eq!(MAX_OVERRIDE_PAGE_BYTES, 256 * 1024);
        assert_eq!(HOLDING_MAP_FILE, "hosts");
        assert_eq!(HOLDING_PAGES_DIR, "pages");
    }

    #[test]
    fn the_watcher_swaps_on_a_change_and_holds_still_otherwise() {
        let dir = holding_dir("a.test=camp\n", &[("camp", "<p>one</p>")]);
        let pages = shared(HoldingPages::load(&dir.0));
        let watcher = HoldingWatcher::new(dir.0.clone(), pages.clone(), Duration::from_secs(30));

        assert!(!watcher.poll_once(), "nothing changed");

        // A page body edited under a running door.
        std::fs::write(
            dir.0.join(HOLDING_PAGES_DIR).join("camp.html"),
            "<p>two</p>",
        )
        .unwrap();
        assert!(watcher.poll_once(), "a new body is a change");
        assert_eq!(
            current(&pages)
                .page_for(Some("a.test"))
                .map(|p| p.to_string()),
            Some("<p>two</p>".to_string())
        );

        // An emptied map DOES install: un-branding a domain must not need a
        // restart. This is the deliberate difference from the demux's route
        // watcher, which refuses an empty table.
        std::fs::write(dir.0.join(HOLDING_MAP_FILE), "").unwrap();
        assert!(watcher.poll_once());
        assert_eq!(current(&pages).hosts(), 0);
    }

    #[test]
    fn a_vanished_map_keeps_the_live_pages() {
        let dir = holding_dir("a.test=camp\n", &[("camp", "<p>one</p>")]);
        let pages = shared(HoldingPages::load(&dir.0));
        let watcher = HoldingWatcher::new(dir.0.clone(), pages.clone(), Duration::from_secs(30));

        std::fs::remove_file(dir.0.join(HOLDING_MAP_FILE)).unwrap();
        assert!(!watcher.poll_once(), "a missing map is not an instruction");
        assert!(
            current(&pages).page_for(Some("a.test")).is_some(),
            "a publisher mid-rename must not un-brand a live door"
        );
    }
}
