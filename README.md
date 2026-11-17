# turn

**STUN and TURN in pure Go**, for WebRTC peers that cannot reach each other
directly — a symmetric NAT, a full-tunnel VPN, a network that only lets HTTPS
out. `CGO_ENABLED=0`.

One daemon, `turnd`, serves on one host:

| | |
|---|---|
| **STUN** | Binding (RFC 8489): a peer learns the address the Internet sees |
| **TURN** | a relayed UDP address (RFC 8656), reached over UDP, TCP, or TLS on 443 (`turns:`) |
| **credentials** | short-lived TURN credentials (HMAC, the TURN REST API scheme), minted only after an OpenID Connect login through [go-authn](https://github.com/go-authn) |
| **rendezvous** | a room a host opens and shares as one link; the guest's answer comes back on its own |

It is the relay the [go-tex playground](https://go-tex.github.io/playground/)
uses for live collaboration over [go-crdt/collab](https://github.com/go-crdt/collab).

Status: under construction — the design is [#1](https://github.com/go-turn/turn/issues/1).

## The HTTP half (`turnd`)

```sh
turnd --issuer https://login.example.org --client-id turnd \
  --client-secret-file /etc/turnd/client-secret \
  --session-key-file /etc/turnd/session.key \
  --turn-secret-file /etc/turnd/turn.secret \
  --allowed-origin https://go-tex.github.io \
  --public-url https://turn.example.org --listen 127.0.0.1:8080 \
  --turn-uri 'turns:turn.example.org:443?transport=tcp'
```

Every secret is a file (refused when world-readable); none is a flag value or an
environment variable. Repeat `--session-key-file` / `--turn-secret-file` to
rotate: the first signs, the others only verify. Register
`<public-url>/callback` as the client's redirect URI at the issuer.

| Endpoint | Auth | |
|---|---|---|
| `GET /login?origin=<allowed origin>` | none | starts the OIDC login (code + PKCE) in a popup; an origin not in `--allowed-origin` is a 400, never a redirect |
| `GET /callback` | the login's cookie | page that `postMessage`s `{type:"turnd-session",token,expires}` (or `{type:"turnd-error",error}`) to `window.opener`, target origin = the allowlisted one |
| `POST /credentials` | session or issuer access token | `{iceServers:[{urls},{urls,username,credential}],ttl}` |
| `POST /rooms` | session | `{room,peer:"host",token,expires}` |
| `POST /rooms/{id}/join` | the room ID | `{room,peer,host,token,expires}` |
| `GET /rooms/{id}/events` | peer token | SSE: `event: message`, `data: {seq,from,to,kind,body}`; `event: closed` at the end |
| `POST /rooms/{id}/messages` | peer token | `{from,to,kind,body}` → 204 |
| `POST /rooms/{id}/credentials` | peer token | as `/credentials`, expiring with the room, charged to the host |
| `POST /rooms/{id}/leave`, `DELETE /rooms/{id}` | peer token | leave; host closes |

Tokens go in `Authorization: Bearer`, never in a URL. The credential scheme is
[draft-uberti-behave-turn-rest-00](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00).
The browser client is `github.com/go-turn/turn/rendezvous/client` (fetch through
`syscall/js`).

## Package `stun`

The RFC 8489 message codec with the RFC 8656 TURN attributes and ChannelData
framing. Decoding is strict and bounded: it refuses a length that overruns the
datagram, framing that is not 4-aligned, and more than `MaxAttributes` (64)
attributes; attributes after `MESSAGE-INTEGRITY` are not visible. It covers
`MESSAGE-INTEGRITY` (HMAC-SHA1), `MESSAGE-INTEGRITY-SHA256`, `FINGERPRINT`, the
long-term key derivations (MD5 and SHA-256) and `USERHASH`. Tested against the
RFC 5769 vectors (decode, verify, byte-identical re-encode); `FuzzDecode` and
`FuzzChannelData` have a committed seed corpus under `stun/testdata/fuzz`.
SASLprep (OpaqueString) is the caller's job.

## Package `server`

The RFC 8656 TURN server: UDP relayed transport, reached over UDP, TCP or TLS
(the caller passes the sockets), plus the STUN Binding answer. Long-term
credentials (MD5, and SHA-256 when the client asks) with NONCE expiry (438);
permissions last 300 s, channels 600 s.

```go
srv, err := server.New(server.Config{
	Realm:   "turn.example.org",
	Auth:    func(username string) (password string, ok bool) { /* wrap creds.Verify */ },
	RelayIP: netip.MustParseAddr("203.0.113.5"),
})
go srv.ServePacketConn(udpConn)         // UDP clients
go srv.ServeListener(tcpListener)       // TCP clients
go srv.ServeTLS(tcpListener443, tlsCfg) // turns:
```

By default the server never relays to or from loopback, `0.0.0.0/8`, RFC 1918,
`100.64/10`, link-local (169.254.169.254 included), multicast, ULA, the
NAT64/6to4/Teredo forms, IPv4-mapped forms of those, or its own addresses: it
answers 403. `Config.AllowPeers` re-enables ranges (tests use `127.0.0.0/8`).
Bounds, all in `Config`: allocations per user and in total, lifetime cap,
per-allocation byte rate, relay port range, permissions and channels per
allocation, concurrent connections, idle and handshake timeouts, datagram size.
`interop/` is the judge: github.com/pion/turn/v4 (test-only) allocates, permits,
binds a channel and round-trips data through the server over UDP and TCP.
`go test -bench . ./server` prints allocations/s and relayed packets/s;
the comparison with coturn on one core is still to do.

## Licence

BSD-3-Clause.
