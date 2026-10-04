// Package secure is a collage plugin that sends the security headers a site
// should, and a Content-Security-Policy with per-request nonces.
//
//	app, err := collage.New(&collage.Config{
//		Plugins: []collage.Plugin{secure.New(secure.Options{
//			CSP: "default-src 'self'; script-src 'self' 'nonce-{nonce}'",
//		})},
//	})
//
// With no options it sends X-Content-Type-Options, a Referrer-Policy, an
// X-Frame-Options and a Cross-Origin-Opener-Policy, and HSTS on requests that
// arrived over TLS.
//
// # Nonces and the page cache
//
// A nonce must be new on every response, and collage serves one rendered page to
// many readers from its cache. So {{cspNonce}} does not render a nonce: it renders
// a placeholder, and what is cached carries the placeholder. On the way out, the
// plugin's middleware makes a fresh nonce and names it in the header, and the
// plugin's PersonaliseHook puts the same nonce in the placeholder's place — the
// way collage itself puts each reader's forgery token into a cached form. That
// happens after the cache and before any compressor, so the order plugins are
// listed in does not matter. The core answers a page carrying a nonce private and
// no-store, with an ETag of the body sent, since a 304 would have the browser
// keep the old page under the new header. Other responses keep their validators
// and answer conditional requests as usual.
//
// # Static builds
//
// A page a static build writes is served by whatever hosts the files, never by
// this middleware, and a file cannot carry a nonce that changes per response. So
// in a static render the nonce attribute is removed, leaving the script, rather
// than writing the placeholder into the file. Allow those inline scripts in the
// host's own policy, by hash or otherwise.
package secure

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Elagoht/collage/pkg/collage"
)

// Name is the plugin's name, and the key its configuration is found under.
const Name = "elagoht/secure"

// Options configures the plugin. Each header has a default; "-" leaves one out.
type Options struct {
	// CSP is the Content-Security-Policy. "{nonce}" in it is replaced by the
	// response's nonce, which {{cspNonce}} puts on the page's inline scripts and
	// styles. Empty sends none.
	CSP string `json:"csp"`
	// CSPReportOnly sends the policy as Content-Security-Policy-Report-Only:
	// violations are reported, nothing is blocked. In development the policy is
	// always report-only, so collage's own reload script keeps working.
	CSPReportOnly bool `json:"cspReportOnly"`
	// HSTS is how long, in seconds, a browser should use only HTTPS for the site,
	// sent on requests that arrived over TLS — directly or, by
	// X-Forwarded-Proto, through a proxy. Default two years; negative sends none.
	HSTS int `json:"hsts"`
	// HSTSSubdomains and HSTSPreload add includeSubDomains and preload.
	HSTSSubdomains bool `json:"hstsSubdomains"`
	HSTSPreload    bool `json:"hstsPreload"`
	// FrameOptions is X-Frame-Options. Default "SAMEORIGIN".
	FrameOptions string `json:"frameOptions"`
	// ReferrerPolicy is Referrer-Policy. Default "strict-origin-when-cross-origin".
	ReferrerPolicy string `json:"referrerPolicy"`
	// PermissionsPolicy is Permissions-Policy: "camera=(), microphone=()".
	// Empty sends none.
	PermissionsPolicy string `json:"permissionsPolicy"`
	// CrossOriginOpenerPolicy is Cross-Origin-Opener-Policy. Default
	// "same-origin".
	CrossOriginOpenerPolicy string `json:"crossOriginOpenerPolicy"`
	// NoSniff turns X-Content-Type-Options: nosniff off when false is set in
	// configuration; it is on by default.
	NoSniff *bool `json:"noSniff"`
}

// Plugin sends the headers.
type Plugin struct {
	opts   Options
	dev    bool
	marker string
	// nonceAttr matches a nonce attribute holding the marker, quoted or not.
	nonceAttr *regexp.Regexp
	log       *slog.Logger
	warnOnce  sync.Once
}

// New returns a plugin with opts as its starting point, which the application's
// own configuration is then decoded over.
func New(opts Options) *Plugin { return &Plugin{opts: opts} }

func (p *Plugin) Name() string                   { return Name }
func (p *Plugin) Version() string                { return "0.2.0" }
func (p *Plugin) Shutdown(context.Context) error { return nil }

// Configure reads the configuration and adds {{cspNonce}}.
func (p *Plugin) Configure(_ context.Context, host collage.ConfigHost) error {
	if err := host.Config(&p.opts); err != nil {
		return err
	}
	p.dev = host.DevMode()
	// Random per process, like collage's own forgery marker: a page rendering
	// text a visitor supplied cannot contain it, and so cannot be handed a nonce.
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Errorf("secure: %w", err)
	}
	p.marker = "collage-csp-nonce-" + hex.EncodeToString(raw[:])
	m := regexp.QuoteMeta(p.marker)
	p.nonceAttr = regexp.MustCompile(`\s+nonce\s*=\s*(?:"` + m + `"|'` + m + `'|` + m + `\b)`)
	return host.AddTemplateFunc("cspNonce", func() string { return p.marker })
}

// Init wraps every request in the headers.
func (p *Plugin) Init(_ context.Context, host collage.Host) error {
	if p.marker == "" {
		return fmt.Errorf("secure: register the plugin in Config.Plugins, where Configure runs; {{cspNonce}} needs it")
	}
	p.log = host.Logger()
	return host.Use(p.middleware)
}

// OnAfterRender takes the placeholder out of a static render, which no
// middleware will serve: see "Static builds" above. A render for a request is
// left alone, since the middleware puts the nonce in on the way out.
func (p *Plugin) OnAfterRender(_ context.Context, ev *collage.AfterRenderEvent) error {
	if !ev.Static || p.marker == "" || !bytes.Contains(ev.HTML, []byte(p.marker)) {
		return nil
	}
	html := p.nonceAttr.ReplaceAll(ev.HTML, nil)
	// Wherever else it was written, it means nothing without a nonce.
	ev.HTML = bytes.ReplaceAll(html, []byte(p.marker), nil)
	p.warnOnce.Do(func() {
		if p.log != nil && p.opts.CSP != "" {
			p.log.Warn("secure: a static build cannot carry per-response CSP nonces; " +
				"they were removed, so allow the inline scripts in the host's own policy")
		}
	})
	return nil
}

func (p *Plugin) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.static(w.Header(), r)
		if p.opts.CSP == "" {
			next.ServeHTTP(w, r)
			return
		}
		nonce, err := newNonce()
		if err != nil {
			http.Error(w, "secure: no randomness for a nonce", http.StatusInternalServerError)
			return
		}
		name := "Content-Security-Policy"
		if p.opts.CSPReportOnly || p.dev {
			name += "-Report-Only"
		}
		w.Header().Set(name, strings.ReplaceAll(p.opts.CSP, "{nonce}", nonce))
		// A page answered 304 would be kept by the browser with the nonce it was
		// first sent, under this response's header. The core recomputes a
		// personalised page's ETag from the body sent, so only "*", which matches
		// anything, could revalidate it. That alone goes; every other conditional
		// request reaches the handler, so a feed, a document or a mounted file
		// still answers 304.
		if strings.TrimSpace(r.Header.Get("If-None-Match")) == "*" {
			r.Header.Del("If-None-Match")
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), nonceKey{}, nonce)))
	})
}

// static sets the headers that do not change between responses.
func (p *Plugin) static(h http.Header, r *http.Request) {
	o := p.opts
	if o.NoSniff == nil || *o.NoSniff {
		h.Set("X-Content-Type-Options", "nosniff")
	} else {
		// Turned off explicitly: remove it, in case the framework's own baseline
		// (collage v0.39.0 sends nosniff by default) already set it — "off" has to
		// mean off, not "off unless something below me set it".
		h.Del("X-Content-Type-Options")
	}
	set := func(name, value, def string) {
		switch value {
		case "-":
			// Omit deliberately: delete it, so it overrides a framework baseline
			// that set it (X-Frame-Options is a collage v0.39.0 default), not just
			// decline to set it ourselves.
			h.Del(name)
		case "":
			if def != "" {
				h.Set(name, def)
			}
		default:
			h.Set(name, value)
		}
	}
	set("X-Frame-Options", o.FrameOptions, "SAMEORIGIN")
	set("Referrer-Policy", o.ReferrerPolicy, "strict-origin-when-cross-origin")
	set("Cross-Origin-Opener-Policy", o.CrossOriginOpenerPolicy, "same-origin")
	set("Permissions-Policy", o.PermissionsPolicy, "")
	if o.HSTS >= 0 && secureRequest(r) {
		age := o.HSTS
		if age == 0 {
			age = int((2 * 365 * 24 * time.Hour).Seconds())
		}
		v := "max-age=" + strconv.Itoa(age)
		if o.HSTSSubdomains {
			v += "; includeSubDomains"
		}
		if o.HSTSPreload {
			v += "; preload"
		}
		h.Set("Strict-Transport-Security", v)
	}
}

func secureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func newNonce() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(raw[:]), nil
}

type nonceKey struct{}

// OnPersonalise puts this response's nonce where {{cspNonce}} left the marker.
// It runs after collage's page cache and inside every middleware, so before a
// compressor: the order plugins are listed in no longer matters.
func (p *Plugin) OnPersonalise(_ context.Context, ev *collage.PersonaliseEvent) error {
	if p.marker == "" || !bytes.Contains(ev.Body, []byte(p.marker)) {
		return nil
	}
	nonce, _ := ev.Request.Context().Value(nonceKey{}).(string)
	if nonce == "" {
		// Not through this plugin's middleware, or no CSP configured: there is
		// no header to match, so make the nonce and the header here.
		fresh, err := newNonce()
		if err != nil {
			return fmt.Errorf("secure: no randomness for a nonce: %w", err)
		}
		nonce = fresh
		if p.opts.CSP != "" {
			name := "Content-Security-Policy"
			if p.opts.CSPReportOnly || p.dev {
				name += "-Report-Only"
			}
			ev.Header.Set(name, strings.ReplaceAll(p.opts.CSP, "{nonce}", nonce))
		}
	}
	ev.Body = bytes.ReplaceAll(ev.Body, []byte(p.marker), []byte(nonce))
	ev.Personal = true
	return nil
}

var _ collage.PersonaliseHook = (*Plugin)(nil)
