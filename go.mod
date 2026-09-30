// A collage plugin that sends the security headers a site should: HSTS,
// nosniff, frame and referrer policies, and a Content-Security-Policy whose
// nonces survive collage's page cache.
//
// It requires collage the way any consumer does, and reaches nothing the framework
// does not offer every plugin.
module github.com/Elagoht/collage-secure

go 1.26

require github.com/Elagoht/collage v0.39.0
