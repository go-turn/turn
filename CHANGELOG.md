# Changelog

Versions follow [semver](https://semver.org/); below v1, a breaking change
raises the MINOR. Releases are tagged on GitHub.

## Unreleased

### Fixed

- The collaboration page's *Sign in* button linked `/login`, which answers 400
  `origin not allowed` without the playground's `?origin=`. The button is gone;
  the page says the host signs in from the playground. `TestHomePageLinksAnswer`
  renders every page from the daemon's real mux and follows each same-host link
  (it was red on v0.8.0 with `/login`).

### Added

- turnd serves a home page at `GET /` (and `HEAD`), chosen by the `Host`
  header: the collaboration service's page on the `--public-url` host and on any
  unknown host (what it is, a link to the go-tex playground, a *Sign in* button
  to `/login`), the STUN/TURN relay's page on the hosts of `--stun-uri` and
  `--turn-uri` (what it is, the UDP/TCP/TLS transports and ports it advertises,
  that it is not a web service to browse, a link to the collaboration page).
  Every other unknown path stays a 404. Before, `/` was a bare
  `404 page not found`.
- The pages follow go-authn/bridge's look (bridge#104, commit d755751): Tailwind
  v4 standalone CSS and Lucide icons, seven languages (fr, en, de, es, ja, ko,
  zh-cn) with a combo, and a light, dark or system theme switch, both working
  without script (`/lang`, `/theme`); a strict Content-Security-Policy with no
  inline script or style. New routes: `/lang`, `/theme`, `/ui.js`,
  `/assets/{app.css,brand.css,logo.svg}`.
- The pages show only public configuration; tests assert that no secret, client
  address, count, session or room ID reaches them.

### Tests

- A real-browser lane (headless Chrome via chromedp, skipped without Chrome;
  `TURND_REQUIRE_BROWSER=1` to require it) that draws both pages in French and
  English, light and dark, checks the stylesheet applied under the CSP, the
  contrast, the switches and every language at 360 px, and writes screenshots to
  `<user config dir>/turnd/page-screenshots`.
