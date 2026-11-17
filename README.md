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

Status: v0.1 — the relay, the credentials, the login and the rendezvous work and
are tested; the go-tex playground is not wired to it yet. The design is
[#1](https://github.com/go-turn/turn/issues/1); what is still open is in the
[tracker](https://github.com/go-turn/turn/issues).

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
`syscall/js`; it adds about 16 MB to a wasm binary (3.5 MB more gzipped), almost
all of it grpc. go-crdt/collab's js/wasm build does not link grpc, so a page that
does not otherwise ship it should load this client in a separate wasm, fetched
when a collaboration starts.

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
`--tls-key-file`), `--relay-port-min` / `--relay-port-max`, and
`--proxy-protocol-from <prefix>` (repeatable) to accept a PROXY protocol v2 header
([haproxy's specification](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt))
on TCP and TLS connections from that prefix. Its credential hook is the
keyring's `Auth`, so the minted `<expiry>:<tag>.<subject>` usernames are what the
relay accepts (the tag says which of the rotating secrets signed it).

## Deploying

One host, one binary (`CGO_ENABLED=0 go install github.com/go-turn/turn/cmd/turnd@latest`).
Ports to open, at the host firewall **and** at the cloud security group:

| port | for |
|---|---|
| UDP 3478 | STUN and TURN over UDP (`--stun-listen :3478`) |
| TCP 3478 | TURN over TCP (`--turn-tcp-listen :3478`) |
| TCP 5349 | TURN over TLS (`--turns-listen :5349`), for networks that block UDP |
| UDP range | relayed addresses (`--relay-port-min 49160 --relay-port-max 49999`) |
| TCP 443 | HTTPS: `/login`, `/callback`, `/grpc`, through the host's reverse proxy to `--listen 127.0.0.1:8080` (the proxy must pass WebSocket upgrades) |

### TURN over TLS on 443, beside HTTPS

TURN over TLS can share 443 with the HTTPS site when Caddy demultiplexes by SNI
with [caddy-l4](https://github.com/mholt/caddy-l4). Caddy terminates TLS for
`turn.example.org` itself and proxies plain TCP to turnd with a PROXY protocol v2
header, so turnd still sees the real client address (XOR-MAPPED-ADDRESS, quotas
and logs). The build is
`xcaddy build --with github.com/mholt/caddy-l4@v0.1.3`, pinned because caddy-l4
calls itself experimental.

```
{
    servers :443 {
        listener_wrappers {
            layer4 {
                @turn tls sni turn.example.org
                route @turn {
                    tls
                    proxy {
                        proxy_protocol v2
                        upstream tcp/127.0.0.1:3478
                    }
                }
            }
            tls
        }
    }
}

# A site block makes Caddy obtain the certificate that the `tls` handler above
# presents for turn.example.org.
turn.example.org {
    respond "turnd relay" 200
}
```

turnd runs `--turn-tcp-listen 127.0.0.1:3478 --proxy-protocol-from 127.0.0.1/32`.
Clients use `turns:turn.example.org:443?transport=tcp`. The header is accepted
only from the listed prefixes: a connection from one of them without a valid
header is closed, and a header from any other source is never honoured. The
Caddyfile follows caddy-l4's `docs/examples/combining_apps.md`; it has not been
run against a Caddy here, only the header handling is tested (with pion's TCP
client behind a proxy that prepends a v2 header). The separate `--turns-listen`
(TLS handled by turnd, port 5349 or 443 on a second address) stays available
for a host without Caddy; there the PROXY header, if any, precedes the
ClientHello.

Secrets are files readable by the service account only: 32+ random bytes for
`--session-key-file`, 16+ for `--turn-secret-file`, the issuer's client secret
for `--client-secret-file`. Register `<public-url>/callback` as the redirect URI
of `--client-id` at the issuer.

## Checking a deployment

A deployed relay can be proven end to end without an OpenID Connect login. On the
host, mint short-lived credentials with the keyring turnd uses (the first
`--turn-secret-file` signs; the TTL is capped at 1h). The username is printed; the
password goes to a new `0600` file, never to stdout or the command line:

```sh
turnd mint-credentials --turn-secret-file /etc/turnd/turn.secret \
  --subject probe --ttl 10m --password-out ./probe.pw   # prints <expiry>:<tag>.probe
```

Then, from anywhere that can reach the relay, run `turnprobe`. For each `--server`
it sends a STUN Binding (printing the mapped address), opens two allocations,
permits each other's relayed address, and sends a datagram from relay A to relay B
and back; that proves relaying, with nothing else needed. A `turns:` certificate is
verified against the system roots with SNI set to the host.

```sh
go install github.com/go-turn/turn/cmd/turnprobe@latest
turnprobe --username '1763400000:ab12.probe' --password-file ./probe.pw \
  --realm turn.example.org \
  --server 'turn:turn.example.org:3478?transport=udp' \
  --server 'turn:turn.example.org:3478?transport=tcp' \
  --server 'turns:turn.example.org:443?transport=tcp'
```

```
PASS turn:turn.example.org:3478?transport=udp mapped=198.51.100.7:51234 relay-a=203.0.113.5:49160 relay-b=203.0.113.5:49161 roundtrip=3ms
FAIL turns:turn.example.org:443?transport=tcp stage=connect: tls: failed to verify certificate: ...
```

One line per server, `PASS` or `FAIL` with the stage that failed (`connect`,
`binding`, `allocate`, `permission`, `relay A->B`, `relay B->A`); the exit status
is 1 if any failed. `--realm` is turnd's `--realm`; a mismatch is reported at
`allocate`. The server refuses to relay to its own addresses by default (see
`server`), so a relay whose relayed address is one of its own interface addresses
fails at `permission` with `403`.

## Licence

BSD-3-Clause.
