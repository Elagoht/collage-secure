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
page carries the placeholder; the plugin's middleware puts a fresh nonce in its
place on the way out, and names the same nonce in the header. It is how collage
itself puts each reader's forgery token into a cached form.

A page carrying a nonce is sent with `Cache-Control: no-store` and no `ETag`, and
its request is answered unconditionally: a `304` would have the browser keep the
page with its old nonce under the new header, and every inline script would be
blocked. Only HTML is held back to do this; an event stream, an image, a JSON
document pass straight through.

## Development

In development the policy is sent as `Content-Security-Policy-Report-Only`
whatever `CSPReportOnly` says: collage's live-reload script is an inline script
without a nonce, and a policy that blocked it would stop the page reloading.
Violations still appear in the browser's console.

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
