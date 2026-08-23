# echo

Reports an HTTP request exactly as the origin sees it. Runs on the k3s cluster
described in [homelab](https://github.com/jchevertonwynne/homelab), at
`echo.jchevertonwynne.uk`.

It exists to answer questions this setup keeps raising: which headers does
Cloudflare add, what does Access inject once a user is authenticated, and what
client address actually reaches a pod behind a tunnel. `remote_addr` is
cloudflared's address inside the cluster — never the visitor's — and the real
client is in `Cf-Connecting-Ip`. Printing both is the point.

Credential-bearing headers (`Cf-Access-Jwt-Assertion`, `Authorization`,
`Cookie`, `Proxy-Authorization`) are reported as present but never echoed. A
service that prints requests back to the caller hands out tokens otherwise —
most obviously behind Access, where every request carries a signed JWT.

```sh
go run . -addr :8092
curl -s localhost:8092/ | jq
```

Go, no dependencies, `FROM scratch`. Push to `main` and Flux deploys it.
