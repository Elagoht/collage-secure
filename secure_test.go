package secure_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	secure "github.com/Elagoht/collage-secure"
	"github.com/Elagoht/collage/pkg/collage"
)

func site(t *testing.T, dev bool, opts secure.Options) *collage.App {
	t.Helper()
	app, err := collage.New(&collage.Config{
		DevMode: dev,
		Server:  collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: fstest.MapFS{
			"t/p.html": {Data: []byte(`<html><body><script nonce="{{cspNonce}}">go()</script></body></html>`)},
		}, Root: "t"},
		Cache:   collage.CacheConfig{Enabled: true, Type: "memory", DefaultTTL: time.Hour},
		Plugins: []collage.Plugin{secure.New(opts)},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Static: served from the cache after the first render, which is what the
	// nonce has to survive.
	if err := app.RegisterPage(collage.NewPage("home").WithContent(collage.NewFragment("home", "p.html").Build()).WithPath("en", "/").Static().Build()); err != nil {
		t.Fatal(err)
	}
	if err := app.RegisterDocument(collage.NewDocument("data", "application/json").AtRoot("/data.json").WithBody([]byte(`{"a":1}`)).Build()); err != nil {
		t.Fatal(err)
	}
	return app
}

func do(app *collage.App, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, r)
	return rec
}

func TestDefaults(t *testing.T) {
	rec := do(site(t, false, secure.Options{}), httptest.NewRequest(http.MethodGet, "/", nil))
	for name, want := range map[string]string{
		"X-Content-Type-Options":     "nosniff",
		"X-Frame-Options":            "SAMEORIGIN",
		"Referrer-Policy":            "strict-origin-when-cross-origin",
		"Cross-Origin-Opener-Policy": "same-origin",
		"Strict-Transport-Security":  "",
		"Permissions-Policy":         "",
		"Content-Security-Policy":    "",
	} {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestHSTSOnlyOverTLS(t *testing.T) {
	app := site(t, false, secure.Options{HSTSSubdomains: true, HSTSPreload: true, FrameOptions: "-", PermissionsPolicy: "camera=()"})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.TLS = &tls.ConnectionState{}
	rec := do(app, r)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=63072000; includeSubDomains; preload" {
		t.Errorf("HSTS = %q", got)
	}
	if rec.Header().Get("X-Frame-Options") != "" || rec.Header().Get("Permissions-Policy") != "camera=()" {
		t.Errorf("headers = %v", rec.Header())
	}
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if do(app, r).Header().Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS behind a TLS-terminating proxy")
	}
}

var nonceAttr = regexp.MustCompile(`nonce="([^"]+)"`)

// Every response gets its own nonce, in the header and on the page, though the
// page itself comes from the cache.
func TestNonceSurvivesTheCache(t *testing.T) {
	app := site(t, false, secure.Options{CSP: "script-src 'nonce-{nonce}'"})
	seen := map[string]bool{}
	for range 3 {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("If-None-Match", `"anything"`)
		rec := do(app, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
		m := nonceAttr.FindStringSubmatch(rec.Body.String())
		if m == nil || strings.Contains(m[1], "collage-csp-nonce") {
			t.Fatalf("page carries no nonce: %s", rec.Body.String())
		}
		if got := rec.Header().Get("Content-Security-Policy"); got != "script-src 'nonce-"+m[1]+"'" {
			t.Errorf("header %q does not name the page's nonce %q", got, m[1])
		}
		if seen[m[1]] {
			t.Errorf("nonce %q served twice", m[1])
		}
		seen[m[1]] = true
		if rec.Header().Get("ETag") != "" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("a page with a nonce is revalidatable: ETag %q, Cache-Control %q", rec.Header().Get("ETag"), rec.Header().Get("Cache-Control"))
		}
	}
}

// What is not HTML passes through untouched.
func TestOtherResponsesPassThrough(t *testing.T) {
	app := site(t, false, secure.Options{CSP: "default-src 'self'"})
	rec := do(app, httptest.NewRequest(http.MethodGet, "/data.json", nil))
	if rec.Body.String() != `{"a":1}` || rec.Header().Get("ETag") == "" {
		t.Errorf("document = %q, ETag %q", rec.Body.String(), rec.Header().Get("ETag"))
	}
}

// In development the policy only reports, so collage's inline reload script runs.
func TestDevelopmentOnlyReports(t *testing.T) {
	rec := do(site(t, true, secure.Options{CSP: "script-src 'self'"}), httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Header().Get("Content-Security-Policy") != "" || rec.Header().Get("Content-Security-Policy-Report-Only") != "script-src 'self'" {
		t.Errorf("headers = %v", rec.Header())
	}
}
