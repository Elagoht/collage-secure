package secure_test

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	compress "github.com/Elagoht/collage-compress"
	secure "github.com/Elagoht/collage-secure"
	"github.com/Elagoht/collage/pkg/collage"
)

func site(t *testing.T, dev bool, opts secure.Options) *collage.App {
	t.Helper()
	app, err := collage.New(&collage.Config{
		DevMode: dev,
		Server:  collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: fstest.MapFS{
			"t/p.html":  {Data: []byte(`<html><body><script nonce="{{cspNonce}}">go()</script></body></html>`)},
			"t/nf.html": {Data: []byte(`<html><body><script nonce='{{cspNonce}}'>go()</script></body></html>`)},
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
		// The core recomputes a personal page's ETag from the body sent and
		// answers it private, no-store: nothing stale can revalidate.
		if rec.Header().Get("Cache-Control") != "private, no-store" {
			t.Errorf("a page with a nonce is cacheable: Cache-Control %q", rec.Header().Get("Cache-Control"))
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

// A static build writes pages no middleware will ever serve, so the placeholder
// would reach the file — and a file cannot carry a per-response nonce at all.
// The attribute goes; the script stays.
func TestStaticRenderCarriesNoPlaceholder(t *testing.T) {
	app := site(t, false, secure.Options{CSP: "script-src 'nonce-{nonce}'"})
	notFound := collage.NewPage("not-found").WithContent(collage.NewFragment("nf", "nf.html").Build()).Build()
	if err := app.RegisterPage(notFound); err != nil {
		t.Fatal(err)
	}
	if err := app.RegisterNotFoundPage(notFound); err != nil {
		t.Fatal(err)
	}
	page, err := app.RenderPath(context.Background(), "/", "en", nil)
	if err != nil {
		t.Fatal(err)
	}
	missing, err := app.RenderNotFound(context.Background(), "en")
	if err != nil {
		t.Fatal(err)
	}
	for name, html := range map[string]string{"page": string(page.HTML), "404": string(missing.HTML)} {
		if strings.Contains(html, "collage-csp-nonce") || strings.Contains(html, "nonce") {
			t.Errorf("%s: static render carries a nonce: %s", name, html)
		}
		if !strings.Contains(html, "<script>go()</script>") {
			t.Errorf("%s: the script itself is gone: %s", name, html)
		}
	}

	// A request still gets its nonce: the static render changed nothing cached.
	rec := do(app, httptest.NewRequest(http.MethodGet, "/", nil))
	if m := nonceAttr.FindStringSubmatch(rec.Body.String()); m == nil || strings.Contains(m[1], "collage-csp-nonce") {
		t.Errorf("served page lost its nonce: %s", rec.Body.String())
	}
}

// Only a page carrying a nonce must be answered in full. Everything else behind
// the plugin is revalidated as usual: a handler's own ETag, a document's, a
// mounted file's Last-Modified.
func TestOthersAnswerConditionalRequests(t *testing.T) {
	app := site(t, false, secure.Options{CSP: "default-src 'self'"})
	if err := app.Handle("/feed", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/calendar; charset=utf-8")
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n"))
	})); err != nil {
		t.Fatal(err)
	}
	modified := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := app.Mount("/static/", fstest.MapFS{"app.css": {Data: []byte("body{}"), ModTime: modified}}); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/feed", nil)
	r.Header.Set("If-None-Match", `"v1"`)
	if rec := do(app, r); rec.Code != http.StatusNotModified {
		t.Errorf("handler: status %d, want 304", rec.Code)
	}

	etag := do(app, httptest.NewRequest(http.MethodGet, "/data.json", nil)).Header().Get("ETag")
	r = httptest.NewRequest(http.MethodGet, "/data.json", nil)
	r.Header.Set("If-None-Match", etag)
	if rec := do(app, r); rec.Code != http.StatusNotModified {
		t.Errorf("document: status %d, want 304", rec.Code)
	}

	r = httptest.NewRequest(http.MethodGet, "/static/app.css", nil)
	r.Header.Set("If-Modified-Since", modified.Format(http.TimeFormat))
	if rec := do(app, r); rec.Code != http.StatusNotModified {
		t.Errorf("mount: status %d, want 304", rec.Code)
	}
}

// "*" matches whatever ETag a page has, so it is the one validator a client can
// send for a page carrying a nonce without ever having been given one.
func TestWildcardDoesNotRevalidateANoncePage(t *testing.T) {
	app := site(t, false, secure.Options{CSP: "script-src 'nonce-{nonce}'"})
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodGet} {
		r := httptest.NewRequest(method, "/", nil)
		r.Header.Set("If-None-Match", "*")
		rec := do(app, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d, want 200", method, rec.Code)
		}
		if rec.Header().Get("Cache-Control") != "private, no-store" {
			t.Errorf("%s: Cache-Control %q", method, rec.Header().Get("Cache-Control"))
		}
		if method == http.MethodGet {
			if m := nonceAttr.FindStringSubmatch(rec.Body.String()); m == nil || strings.Contains(m[1], "collage-csp-nonce") {
				t.Errorf("page carries no nonce: %s", rec.Body.String())
			}
		}
	}
}

var nonceIn = regexp.MustCompile(`nonce="([^"]*)"`)

// nonceSite is a cached page with an inline script, behind secure and compress in
// the given order.
func nonceSite(t *testing.T, plugins ...collage.Plugin) http.Handler {
	t.Helper()
	app, err := collage.New(&collage.Config{
		Server: collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: fstest.MapFS{"t/p.html": {Data: []byte(
			`<html><body><script nonce="{{cspNonce}}">x()</script>` + strings.Repeat("<p>filler</p>", 300) + `</body></html>`)}}, Root: "t"},
		Cache:   collage.CacheConfig{Enabled: true, Type: "memory", DefaultTTL: time.Minute},
		Plugins: plugins,
	})
	if err != nil {
		t.Fatal(err)
	}
	frag := collage.NewFragment("p", "p.html").Build()
	if err := app.RegisterPage(collage.NewPage("home").WithContent(frag).WithPath("en", "/").
		WithFragmentPath("en", "/live", frag).Static().Build()); err != nil {
		t.Fatal(err)
	}
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}
	return app.Handler()
}

// fetch returns the decoded body and the nonce the CSP header carries.
func fetch(t *testing.T, h http.Handler, method, path string) (*httptest.ResponseRecorder, string, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Header().Get("Content-Encoding") == "gzip" && body != "" {
		zr, err := gzip.NewReader(strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(zr)
		body = string(b)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	header := ""
	if i := strings.Index(csp, "'nonce-"); i >= 0 {
		header = strings.TrimSuffix(strings.SplitN(csp[i+len("'nonce-"):], "'", 2)[0], "'")
	}
	return rec, body, header
}

func TestNonce_WithCompressInEitherOrder(t *testing.T) {
	csp := secure.Options{CSP: "script-src 'nonce-{nonce}'"}
	orders := map[string][]collage.Plugin{
		"secure first":   {secure.New(csp), compress.New(compress.Options{})},
		"compress first": {compress.New(compress.Options{}), secure.New(csp)},
	}
	for name, plugins := range orders {
		t.Run(name, func(t *testing.T) {
			h := nonceSite(t, plugins...)
			seen := map[string]bool{}
			etags := map[string]bool{}
			for range 2 { // the second is a cache hit
				rec, body, header := fetch(t, h, http.MethodGet, "/")
				m := nonceIn.FindStringSubmatch(body)
				if m == nil || header == "" || m[1] != header {
					t.Fatalf("body nonce %v, header nonce %q: want equal", m, header)
				}
				if strings.Contains(body, "collage-csp-nonce-") {
					t.Fatalf("the marker reached the reader")
				}
				// The core recomputes a personal response's ETag from the body sent
				// (spec): one per response, never a cached one.
				if cc := rec.Header().Get("Cache-Control"); cc != "private, no-store" {
					t.Errorf("Cache-Control %q, want private, no-store", cc)
				}
				seen[header] = true
				etags[rec.Header().Get("ETag")] = true
			}
			if len(seen) != 2 || len(etags) != 2 {
				t.Errorf("two responses shared a nonce or an ETag: nonces %v, etags %v", seen, etags)
			}
		})
	}
}

func TestNonce_FragmentPath(t *testing.T) {
	h := nonceSite(t, secure.New(secure.Options{CSP: "script-src 'nonce-{nonce}'"}))
	_, body, header := fetch(t, h, http.MethodGet, "/live")
	if m := nonceIn.FindStringSubmatch(body); m == nil || m[1] != header {
		t.Errorf("fragment path nonce %v vs header %q", m, header)
	}
}

// HEAD goes through a real server: the core writes the page body and leaves
// dropping it for HEAD to net/http, which an httptest.ResponseRecorder does not do.
func TestNonce_Head(t *testing.T) {
	srv := httptest.NewServer(nonceSite(t, secure.New(secure.Options{CSP: "script-src 'nonce-{nonce}'"})))
	defer srv.Close()
	resp, err := http.Head(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || len(body) != 0 {
		t.Errorf("HEAD = %d, body %q", resp.StatusCode, body)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "'nonce-") || strings.Contains(csp, "{nonce}") {
		t.Errorf("HEAD CSP = %q", csp)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "private, no-store" {
		t.Errorf("HEAD Cache-Control %q, want what GET sends", cc)
	}
}

// With no nonce to name in a policy — none configured, or one without "{nonce}"
// — a nonce on the page means nothing: it is removed as a static render removes
// it, and the page stays an ordinary cacheable one with a stable ETag.
func TestNoPolicyNonceStripsTheMarker(t *testing.T) {
	for name, csp := range map[string]string{"no policy": "", "policy without {nonce}": "script-src 'self'"} {
		for _, tmpl := range []string{"p.html", "nf.html"} {
			t.Run(name+" "+tmpl, func(t *testing.T) {
				app, err := collage.New(&collage.Config{
					Server: collage.ServerConfig{Host: "localhost", Port: 3000},
					Template: collage.TemplateConfig{FS: fstest.MapFS{
						"t/p.html":  {Data: []byte(`<html><body><script nonce="{{cspNonce}}">go()</script></body></html>`)},
						"t/nf.html": {Data: []byte(`<html><body><script nonce='{{cspNonce}}'>go()</script></body></html>`)},
					}, Root: "t"},
					Cache:   collage.CacheConfig{Enabled: true, Type: "memory", DefaultTTL: time.Hour},
					Plugins: []collage.Plugin{secure.New(secure.Options{CSP: csp})},
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := app.RegisterPage(collage.NewPage("home").WithContent(collage.NewFragment("home", tmpl).Build()).WithPath("en", "/").Static().Build()); err != nil {
					t.Fatal(err)
				}
				if err := app.Start(); err != nil {
					t.Fatal(err)
				}
				first := do(app, httptest.NewRequest(http.MethodGet, "/", nil))
				second := do(app, httptest.NewRequest(http.MethodGet, "/", nil))
				for _, rec := range []*httptest.ResponseRecorder{first, second} {
					body := rec.Body.String()
					if rec.Code != http.StatusOK || strings.Contains(body, "nonce") || !strings.Contains(body, "<script>go()</script>") {
						t.Fatalf("status %d body %q: want the script without a nonce", rec.Code, body)
					}
					if cc := rec.Header().Get("Cache-Control"); cc == "private, no-store" {
						t.Errorf("Cache-Control %q: a page with no nonce is not personal", cc)
					}
				}
				etag := first.Header().Get("ETag")
				if etag == "" || second.Header().Get("ETag") != etag {
					t.Errorf("ETags %q, %q: want one stable ETag", etag, second.Header().Get("ETag"))
				}
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("If-None-Match", etag)
				if rec := do(app, r); rec.Code != http.StatusNotModified {
					t.Errorf("revalidation = %d, want 304", rec.Code)
				}
			})
		}
	}
}

// gate answers /gate with a 403 from its own middleware, listed before secure's,
// so the error page is answered outside secure's middleware.
type gate struct{}

func (gate) Name() string                   { return "test/gate" }
func (gate) Version() string                { return "0" }
func (gate) Shutdown(context.Context) error { return nil }
func (gate) Init(_ context.Context, h collage.Host) error {
	return h.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/gate" {
				h.ServeStatus(w, r, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
}

// A page answered before secure's middleware ran has no nonce in its request:
// the hook makes one and names it in the header itself.
func TestNonce_OutsideTheMiddleware(t *testing.T) {
	app, err := collage.New(&collage.Config{
		Server: collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: fstest.MapFS{
			"t/err.html": {Data: []byte(`<p>err</p><script nonce="{{cspNonce}}">e()</script>`)},
		}, Root: "t"},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Plugins: []collage.Plugin{gate{}, secure.New(secure.Options{CSP: "script-src 'nonce-{nonce}'"})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := app.RegisterErrorPage(collage.NewPage("err").WithContent(collage.NewFragment("err", "err.html").Build()).Build()); err != nil {
		t.Fatal(err)
	}
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}
	rec, body, header := fetch(t, app.Handler(), http.MethodGet, "/gate")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", rec.Code)
	}
	if m := nonceIn.FindStringSubmatch(body); m == nil || header == "" || m[1] != header {
		t.Errorf("body nonce %v, header nonce %q: want equal", m, header)
	}
}
