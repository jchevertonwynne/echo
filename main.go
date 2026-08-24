// Command echo reports an HTTP request exactly as the origin sees it.
//
// It exists to answer questions this setup keeps raising: which headers does
// Cloudflare add, what does Access inject once a user is authenticated, and
// what client address actually arrives at a pod behind a tunnel. Guessing at
// those from documentation is how you end up trusting the wrong header.
package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strings"

	"echo/internal/metrics"
)

// echo returns JSON, so there is no HTML head to declare a favicon in. A
// browser looking at the response therefore falls back to requesting
// /favicon.ico, which is why the same SVG is served at both paths — browsers
// honour the Content-Type over the file extension.
//
//go:embed icon.svg
var iconSVG []byte

func serveIcon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(iconSVG)
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /icon.svg", serveIcon)
	mux.HandleFunc("GET /favicon.ico", serveIcon)
	mux.HandleFunc("GET /{$}", handleEcho)
	mux.Handle("GET /metrics", metrics.Handler())

	log.Printf("echo listening on %s", *addr)
	if err := http.ListenAndServe(*addr, metrics.Instrument(mux)); err != nil {
		log.Fatal(err)
	}
}

type reply struct {
	// RemoteAddr is the pod's view: behind a tunnel this is cloudflared's
	// address inside the cluster, never the visitor's. The real client is in
	// Cf-Connecting-Ip, which is the whole point of printing both.
	RemoteAddr string            `json:"remote_addr"`
	Method     string            `json:"method"`
	Host       string            `json:"host"`
	Path       string            `json:"path"`
	Proto      string            `json:"proto"`
	Headers    map[string]string `json:"headers"`
	Notable    map[string]string `json:"notable,omitempty"`
}

// sensitive headers carry credentials. This service prints requests back to
// whoever made them, so echoing one of these hands the caller a token — most
// obviously on a hostname behind Access, where every request carries a signed
// JWT. That the header arrived is useful; its value never is.
var sensitive = map[string]bool{
	"Cf-Access-Jwt-Assertion": true,
	"Authorization":           true,
	"Cookie":                  true,
	"Proxy-Authorization":     true,
}

const redacted = "<present, redacted>"

// notable are the headers worth pulling out of the pile, because they are the
// ones people reason about incorrectly.
var notable = []string{
	"Cf-Connecting-Ip",
	"Cf-Ipcountry",
	"Cf-Ray",
	"X-Forwarded-For",
	"X-Forwarded-Proto",
	// Present only once Cloudflare Access has authenticated the request. On a
	// public hostname these are absent, which is itself the useful signal.
	"Cf-Access-Authenticated-User-Email",
	"Cf-Access-Jwt-Assertion",
}

func handleEcho(w http.ResponseWriter, r *http.Request) {
	res := reply{
		RemoteAddr: r.RemoteAddr,
		Method:     r.Method,
		Host:       r.Host,
		Path:       r.URL.Path,
		Proto:      r.Proto,
		Headers:    map[string]string{},
		Notable:    map[string]string{},
	}
	// Redaction happens here, on the way in, so there is exactly one place a
	// credential can be written to the response — an earlier version redacted
	// only the notable list and leaked the same JWT through the full dump.
	for name, values := range r.Header {
		if sensitive[http.CanonicalHeaderKey(name)] {
			res.Headers[name] = redacted
			continue
		}
		res.Headers[name] = strings.Join(values, ", ")
	}
	for _, n := range notable {
		if v := r.Header.Get(n); v != "" {
			if sensitive[n] {
				v = redacted
			}
			res.Notable[n] = v
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		log.Printf("encode: %v", err)
	}
}
