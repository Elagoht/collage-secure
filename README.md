# elagoht/secure

A collage plugin that sends the security headers a site should, and a
Content-Security-Policy whose nonces survive collage's page cache.

```go
app, err := collage.New(&collage.Config{
	Plugins: []collage.Plugin{secure.New(secure.Options{
		CSP: "default-src 'self'; script-src 'self' 'nonce-{nonce}'",
	})},
})
```

Requires collage v0.22.0 or later. Register it in `Config.Plugins`: it adds a
template function, which only a plugin registered there can.

## Headers

| Header | Default | Option |
| --- | --- | --- |
| `X-Content-Type-Options` | `nosniff` | `NoSniff` |
| `X-Frame-Options` | `SAMEORIGIN` | `FrameOptions` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | `ReferrerPolicy` |
| `Cross-Origin-Opener-Policy` | `same-origin` | `CrossOriginOpenerPolicy` |
| `Strict-Transport-Security` | two years, over TLS only | `HSTS`, `HSTSSubdomains`, `HSTSPreload` |
| `Permissions-Policy` | none | `PermissionsPolicy` |
| `Content-Security-Policy` | none | `CSP`, `CSPReportOnly` |

`"-"` leaves a header out. HSTS is sent on a request that arrived over TLS, or
through a proxy that says so with `X-Forwarded-Proto: https`; a negative `HSTS`
sends none.

## Nonces

`{nonce}` in the policy is replaced with the response's nonce, and `{{cspNonce}}`
puts the same one on an inline script or style:

```html
<script nonce="{{cspNonce}}">window.config = {{.Config}}</script>
```

A nonce must be new on every response, and collage serves one rendered page to
many readers from its cache. So `{{cspNonce}}` renders a placeholder, and the cached
page carries the placeholder. The plugin's middleware makes a fresh nonce and names
it in the header; the plugin's `PersonaliseHook` puts the same nonce in the
placeholder's place. It is how collage itself puts each reader's forgery token into
a cached form.

That happens after collage's page cache and before any compressor, so the order
plugins are listed in does not matter. (Before v0.2.0 the nonce went in from a
middleware that buffered the page, and with secure listed before `elagoht/compress`
the placeholder was left inside the gzip body: the header's nonce matched nothing
and the browser blocked every inline script.)

The core answers a page carrying a nonce `Cache-Control: private, no-store`, with
an `ETag` of the body actually sent, so nothing can revalidate a stale page: a
`304` would have the browser keep the page with its old nonce under the new header,
and every inline script would be blocked. `If-None-Match: *`, which matches any
page, is dropped from requests. Every other conditional request reaches its handler
as sent, so a handler's own `ETag`, a document, a mounted file still answer `304`.
Only an HTML page or fragment is rewritten; an event stream, an image, a JSON
document pass straight through. (Before v0.1.5, with a policy set, every request
lost its `If-None-Match` and `If-Modified-Since`, and nothing behind the plugin
could answer `304`.)

With no policy, or a policy without `{nonce}`, there is no nonce to name: the
`nonce` attribute is removed, as in a static build, and the page stays an ordinary
cacheable one with a stable `ETag`.

Version 0.2.0 requires collage v0.43.0, which added `PersonaliseHook`.

## Static builds

A page `collage export` writes is served by whatever hosts the files, never by
this middleware, and a file cannot carry a nonce that changes per response. So
in a static render the `nonce` attribute is removed and the script kept, rather
than the placeholder written into the file; the build logs a warning once when a
policy is configured. Allow those inline scripts in the host's own policy — by
hash, for instance. (Before v0.1.2 the placeholder, `collage-csp-nonce-…`, was
left in the exported HTML.)

## Development

In development the policy is sent as `Content-Security-Policy-Report-Only`
whatever `CSPReportOnly` says: collage's live-reload script is an inline script
without a nonce, and a policy that blocked it would stop the page reloading.
Violations still appear in the browser's console.

## Known limits

The placeholder is random per process, so a page a disk cache kept across a
restart still carries the old process's placeholder, served as the nonce
attribute and matching no header until the entry expires: clear a disk cache on
deploy.

## Configuration

```json
{
  "elagoht/secure": {
    "csp": "default-src 'self'; script-src 'self' 'nonce-{nonce}'",
    "cspReportOnly": false,
    "hsts": 63072000,
    "hstsSubdomains": true,
    "frameOptions": "DENY",
    "permissionsPolicy": "camera=(), microphone=(), geolocation=()"
  }
}
```
