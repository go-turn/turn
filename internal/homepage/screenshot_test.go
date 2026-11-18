package homepage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
)

// The real-browser lane, as in go-authn/bridge (bridge#104): the pages are
// drawn in a headless Chrome under their real headers (a style the policy
// refuses would show as an unstyled page and fail the assertions below), and a
// PNG of each is written for review. TURND_REQUIRE_BROWSER=1 turns "no Chrome"
// from a skip into a failure (CI); TURND_CHROME names a binary.

// screenshotDir is TURND_SCREENSHOT_DIR, else <user config dir>/turnd/
// page-screenshots. Never a directory inside a repository: a capture of a page
// does not belong in one.
func screenshotDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("TURND_SCREENSHOT_DIR")
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			t.Skipf("no place for the screenshots: %v", err)
		}
		dir = filepath.Join(base, "turnd", "page-screenshots")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	for d := abs; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			t.Fatalf("the screenshot directory %s is inside the repository at %s", abs, d)
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		t.Fatal(err)
	}
	return abs
}

func startChrome(t *testing.T) context.Context {
	t.Helper()
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	opts = append(opts, chromedp.Flag("headless", true), chromedp.Flag("lang", "en-US"),
		// Two names for the one test server: the page chosen by the Host.
		chromedp.Flag("host-resolver-rules", "MAP collab.test 127.0.0.1, MAP turn.test 127.0.0.1"))
	if p := os.Getenv("TURND_CHROME"); p != "" {
		opts = append(opts, chromedp.ExecPath(p))
	}
	if os.Geteuid() == 0 || os.Getenv("CI") != "" {
		opts = append(opts, chromedp.Flag("no-sandbox", true))
	}
	actx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	t.Cleanup(cancel)
	ctx, cancel2 := chromedp.NewContext(actx)
	t.Cleanup(cancel2)
	ctx, cancel3 := context.WithTimeout(ctx, 3*time.Minute)
	t.Cleanup(cancel3)
	if _, err := chromedp.Run(ctx, chromedp.Navigate("about:blank")); err != nil {
		if os.Getenv("TURND_REQUIRE_BROWSER") != "" {
			t.Fatalf("TURND_REQUIRE_BROWSER is set and there is no Chrome: %v", err)
		}
		t.Skipf("no Chrome to run the pages in: %v", err)
	}
	return ctx
}

// emulate sets what the browser asks for (prefers-color-scheme) and the screen.
func emulate(ctx context.Context, scheme string, width int) error {
	_, err := chromedp.Run(ctx, chromedp.Func(func(ctx context.Context, tg *chromedp.Target) error {
		if _, err := cdp.Call(ctx, tg, emulation.SetEmulatedMedia, emulation.SetEmulatedMediaParams{
			Features: []*emulation.MediaFeature{{Name: "prefers-color-scheme", Value: scheme}}}); err != nil {
			return err
		}
		_, err := cdp.Call(ctx, tg, emulation.SetDeviceMetricsOverride, emulation.SetDeviceMetricsOverrideParams{Width: int64(width), Height: 800, DeviceScaleFactor: 1})
		return err
	}))
	return err
}

func eval[T any](t *testing.T, ctx context.Context, label, js string) T {
	t.Helper()
	v, err := chromedp.Run(ctx, chromedp.Evaluate[T](js))
	if err != nil {
		t.Fatalf("%s: %v\n%s", label, err, js)
	}
	return v
}

func TestPageScreenshots(t *testing.T) {
	ctx := startChrome(t)
	dir := screenshotDir(t)
	cfg := testConfig()
	cfg.CollabHost, cfg.TurnHosts, cfg.CollabURL, cfg.Secure = "collab.test", []string{"turn.test"}, "http://collab.test", false
	h, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	origin := func(host string) string { return "http://" + host + ":" + u.Port() }

	type shot struct {
		host, lang, theme, scheme string
		width                     int
		save                      bool
	}
	var shots []shot
	for _, host := range []string{"collab.test", "turn.test"} {
		for _, l := range []string{langFR, langEN} {
			shots = append(shots,
				shot{host, l, themeLight, "light", 900, true},
				shot{host, l, themeDark, "dark", 900, true},
				// A chosen theme beats the browser's scheme: asserted, not saved.
				shot{host, l, themeLight, "dark", 900, false},
				shot{host, l, themeDark, "light", 900, false},
				shot{host, l, themeSystem, "dark", 900, false})
		}
		// Every language fits a phone, CJK labels included.
		for _, l := range languages {
			shots = append(shots, shot{host, l.Code, themeLight, "light", 360, false})
		}
	}
	saved := 0
	for _, sh := range shots {
		label := fmt.Sprintf("%s (%s, %s theme, %s browser, %dpx)", sh.host, sh.lang, sh.theme, sh.scheme, sh.width)
		if err := emulate(ctx, sh.scheme, sh.width); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		// The switches are the page's own, through their GET forms: the
		// cookies are set as a person without script would set them.
		for _, p := range []string{"/lang?lang=" + sh.lang, "/theme?theme=" + sh.theme} {
			if _, err := chromedp.Run(ctx, chromedp.Navigate(origin(sh.host)+p)); err != nil {
				t.Fatalf("%s: %s: %v", label, p, err)
			}
		}
		if got := eval[string](t, ctx, label, `location.pathname`); got != "/" {
			t.Fatalf("%s: the switch went to %q, want /", label, got)
		}
		fail := func(f string, a ...any) {
			t.Helper()
			t.Fatalf("%s: %s\n%s", label, fmt.Sprintf(f, a...), eval[string](t, ctx, label, `document.body.innerText`))
		}
		if got := eval[string](t, ctx, label, `document.documentElement.lang`); got != langTag(sh.lang) {
			fail("<html lang> is %q, want %s", got, langTag(sh.lang))
		}
		look := sh.theme
		if look == themeSystem {
			look = sh.scheme
		}
		wantBg := map[string]string{"light": "248,250,252", "dark": "18,21,26"}[look]
		const rgb = `const rgb = (v) => { const c = document.createElement("canvas").getContext("2d"); c.fillStyle = v; c.fillRect(0, 0, 1, 1); return Array.from(c.getImageData(0, 0, 1, 1).data.slice(0, 3)); };
			const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]); };
			const ratio = (a, b) => { const l1 = lum(rgb(a)), l2 = lum(rgb(b)); return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05); };`
		// The stylesheet was applied under the page's own CSP: a card has rounded
		// corners, the body has the theme's background, the logo loaded, the page
		// does not scroll sideways, the accent and the button read at AA (4.5:1).
		var m struct {
			Radius, Bg      string
			Logo, Overflow  bool
			Ink, Btn        float64
			Options         int
			Value, Pressed  string
			GoShown         bool
			Accent, Heading string
		}
		js := `JSON.stringify((() => { ` + rgb + `
			const s = document.getElementById("lang-select"), g = document.getElementById("lang-go"), pr = document.querySelector('.seg [aria-pressed="true"]');
			const i = document.querySelector("header img"), ink = document.querySelector("section .text-brand-ink"), b = document.querySelector("a.btn-primary");
			return {Radius: getComputedStyle(document.querySelector("section")).borderTopLeftRadius,
				Bg: rgb(getComputedStyle(document.body).backgroundColor).join(","),
				Logo: !!i && i.complete && i.naturalWidth > 0,
				Overflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
				Ink: ratio(getComputedStyle(ink).color, getComputedStyle(document.body).backgroundColor),
				Btn: ratio(getComputedStyle(b).color, getComputedStyle(b).backgroundColor),
				Options: s.options.length, Value: s.value, Pressed: pr ? pr.value : "", GoShown: !!g && g.offsetParent !== null,
				Accent: getComputedStyle(b).backgroundColor, Heading: document.querySelector("h1").textContent}; })())`
		if err := json.Unmarshal([]byte(eval[string](t, ctx, label, js)), &m); err != nil {
			fail("%v", err)
		}
		if m.Radius == "0px" || m.Bg != wantBg || !m.Logo || m.Overflow {
			fail("radius=%q background=%q (want %s) logo=%v sideways=%v", m.Radius, m.Bg, wantBg, m.Logo, m.Overflow)
		}
		if m.Ink < 4.5 || m.Btn < 4.5 {
			fail("contrast: accent ink %.2f:1, button %.2f:1 (AA is 4.5:1)", m.Ink, m.Btn)
		}
		// brand.css's rose reaches the button: #be123c.
		if m.Accent != "rgb(190, 18, 60)" {
			fail("the accent is %q", m.Accent)
		}
		// The combo is on the page with the seven languages and the choice, the
		// script hid its submit button, the theme switch shows the choice.
		if m.Options != len(languages) || m.Value != sh.lang || m.GoShown || m.Pressed != sh.theme {
			fail("combo %+v", m)
		}
		want, _ := lookup(sh.lang, map[string]string{"collab.test": "collab.h1", "turn.test": "turn.h1"}[sh.host])
		if m.Heading != want {
			fail("heading %q, want %q", m.Heading, want)
		}
		if !sh.save {
			continue
		}
		png, err := chromedp.Run(ctx, chromedp.FullScreenshot(100))
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		file := filepath.Join(dir, fmt.Sprintf("%s-%s-%s.png", strings.TrimSuffix(sh.host, ".test"), sh.lang, sh.theme))
		if err := os.WriteFile(file, png, 0o644); err != nil {
			t.Fatal(err)
		}
		saved++
		t.Log(file)
	}
	t.Logf("%d screenshots in %s", saved, dir)
}
