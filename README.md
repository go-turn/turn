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

The API is gRPC, [`proto/turn/v1/turnd.proto`](proto/turn/v1/turnd.proto)
(service `turn.v1.Turnd`, generated code committed, CI regenerates it and fails
on a diff). A plain `grpc.Server` is served over a WebSocket at `/grpc`
([grpc-transports/websocket](https://github.com/grpc-transports/websocket)), which
is what a browser can speak, including the bidirectional stream. The WebSocket
upgrade enforces the exact origin allowlist (scheme and port included); a client
with no `Origin` header is a native client. Only browser navigations stay HTTP:

| HTTP | |
|---|---|
| `GET /login?origin=<allowed origin>` | starts the OIDC login (code + PKCE) in a popup; an origin not in `--allowed-origin` is a 400, never a redirect |
| `GET /callback` | page that `postMessage`s `{type:"turnd-session",token,expires}` (or `{type:"turnd-error",error}`) to `window.opener`, target origin = the allowlisted one |
| `GET /healthz` | `ok` |

| RPC | token (`authorization: Bearer …` metadata, never a URL) | |
|---|---|---|
| `Credentials` | session, or issuer access token | `IceServers{ice_servers[{urls,username,credential}], ttl}` |
| `CreateRoom` | session or access token | `{room, peer:"host", token, expires}`; the room ID is 128 random bits |
| `JoinRoom{room,name}` | none: the room ID | `{peer, host, token, expires, pending:true}`; the guest is **pending** |
| `Admit{room,peer}` / `Deny{room,peer}` | host token | admit a pending guest / refuse it (or remove an admitted one): its token is dead |
| `RoomCredentials{room}` | an **admitted** peer's token | `IceServers` expiring with the room, charged to the host |
| `CloseRoom{room}` | host token | ends the room |
| `Room(stream Envelope) returns (stream Envelope)` | peer token + `x-turn-room` metadata | the room's one stream: events down, messages up; ending it is leaving |

A leaked room link lets a stranger **knock**, not enter. A pending guest only
receives: it cannot send, cannot get credentials, counts against a separate
pending cap and a pending TTL. The host sees `sys.knock` (`from` = the guest,
`body` = its display name, at most 64 characters, no control characters) and
decides; only admitted guests count against `--max-guests` and produce `sys.join`.
Other system events: `sys.admitted`, `sys.denied`, `sys.leave`, `sys.closed`, and
`sys.error` (a message the other peer could not take; the stream stays open).
A message that breaks the protocol (too large, a spoofed `from`, a bad kind, a
pending sender, guest to guest) ends the sender's stream with a status:
`RESOURCE_EXHAUSTED`, `PERMISSION_DENIED`, `INVALID_ARGUMENT`. Other refusals:
`UNAUTHENTICATED` (no or dead token), `NOT_FOUND`, `ALREADY_EXISTS` (a second
stream for one peer), `FAILED_PRECONDITION` (already admitted), `UNAVAILABLE`
(server full).

The credential scheme is
[draft-uberti-behave-turn-rest-00](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00).
The Go client, for the browser and native, is
`github.com/go-turn/turn/rendezvous/client`: `Create`, `Join(name)` (blocks until
admitted, `ErrDenied` otherwise), `Admit`, `Deny`, `Send`, `Recv`, `Credentials`,
`Close`. It is a real grpc-go client dialed over the browser's WebSocket through
`syscall/js`; it adds about 16 MB to a wasm binary (4.9 MB gzipped), almost all of
it grpc, which the go-tex playground already ships through go-crdt/collab.

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

`turnd` starts the relay when a listen flag is set: `--relay-ip` (required;
`--relay-advertise-ip` behind a NAT), `--stun-listen :3478` (UDP),
`--turn-tcp-listen :3478`, `--turns-listen :443` (TLS, with `--tls-cert-file` and
`--tls-key-file`), `--relay-port-min` / `--relay-port-max`. Its credential hook
is the keyring's `Auth`, so the minted `username:expiry` credentials are what the
relay accepts.

## Licence

BSD-3-Clause.
