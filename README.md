<p align="center"><img src="https://raw.githubusercontent.com/go-turn/brand/main/social/go-turn.png" alt="go-turn/turn" width="720"></p>

# turn

[![CI](https://github.com/go-turn/turn/actions/workflows/ci.yml/badge.svg)](https://github.com/go-turn/turn/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-turn/turn.svg)](https://pkg.go.dev/github.com/go-turn/turn)
[![license](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)

📖 **[go-turn.github.io](https://go-turn.github.io/)** · **[Documentation](https://go-turn.github.io/docs/)**

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
| `RenewSession` | a session token, valid or expired for under 5 minutes | `{token, expires}`: a new session token; `UNAUTHENTICATED` = sign in again (see below) |
| `CreateRoom` | session or access token | `{room, peer:"host", token, expires}`; the room ID is 128 random bits |
| `JoinRoom{room,name}` | none: the room ID | `{peer, host, token, expires, pending:true}`; the guest is **pending** |
| `Admit{room,peer}` / `Deny{room,peer}` | host token | admit a pending guest / refuse it (or remove an admitted one): its token is dead |
| `RoomCredentials{room}` | an **admitted** peer's token | `IceServers` expiring with the room, charged to the current host's person (see *A room outlives its host*) |
| `CloseRoom{room}` | host token | ends the room |
| `HandOver{room,to}` | host token | gives the host role to an admitted, connected guest; the old host's token is dead |
| `Reclaim{room}` | a **session** token whose subject was the host's | `{peer, host, host_peer, token, expires}`: the host role back (new token), or, after a handover, an admitted guest with the SAME peer ID |
| `Room(stream Envelope) returns (stream Envelope)` | peer token + `x-turn-room` metadata | the room's one stream: events down, messages up; ending it is leaving |

**Renewing a session.** At `/callback` turnd asks the issuer for `openid
offline_access`, keeps the refresh token in memory under a random family ID, and
embeds only that ID in the signed session token (`t2.`; a v0.4.0 `t1.` token has
none and cannot be renewed). `RenewSession` takes the current session token as
Bearer, valid or expired for less than 5 minutes, spends the stored refresh token
at the issuer (go-authn/rp `Refresh`), rotates the stored one and returns a new
session token. Concurrent renewals of one family share one issuer call (the
refresh token is spent once, every caller gets the same new token), and a
retired refresh token is never presented again. Any refusal from the issuer
(account, passkey or application session revoked, the refresh lifetime over:
`invalid_grant`, or any other error code it answers) ends the family: it is
deleted and the answer is `UNAUTHENTICATED`. Failing to reach the issuer is
`UNAVAILABLE` and leaves the family intact: retry. `UNIMPLEMENTED` when renewal
is off. Every outcome is logged with the pseudonymous subject, never a token.

In the playground: after the popup's `turnd-session` message, run
`client.KeepRenewed(ctx, client.Session{Token: tok, Expires: exp}, 5*time.Minute, func(ctx, t) { return client.RenewSession(ctx, base, t) }, store)`
in a goroutine. It renews 5 minutes before the expiry, retries `UNAVAILABLE`
every 30 s, and returns when `ctx` ends or on `UNAUTHENTICATED`: then open the
login popup again. `store` receives each new `Session`, which is the token to use
for `Credentials` and `CreateRoom` from then on. A page that dials its own
connection uses `RenewSessionConn`. Renew with the NEWEST token: an old one
still works while it is valid or within the grace, but a sleeping tab that
wakes up after more than the grace has to sign in again.

A leaked room link lets a stranger **knock**, not enter. A pending guest only
receives: it cannot send, cannot get credentials, counts against a separate
pending cap and a pending TTL. The host sees `sys.knock` (`from` = the guest,
`body` = its display name, at most 64 characters, no control characters) and
decides; only admitted guests count against `--max-guests` and produce `sys.join`.
Other system events: `sys.admitted`, `sys.denied`, `sys.leave`, `sys.closed`,
`sys.host-changed`, and
`sys.error` (a message the other peer could not take; the stream stays open).
A message that breaks the protocol (too large, a spoofed `from`, a bad kind, a
pending sender, guest to guest) ends the sender's stream with a status:
`RESOURCE_EXHAUSTED`, `PERMISSION_DENIED`, `INVALID_ARGUMENT`. Other refusals:
`UNAUTHENTICATED` (no or dead token), `NOT_FOUND`, `ALREADY_EXISTS` (a second
stream for one peer), `FAILED_PRECONDITION` (already admitted), `UNAVAILABLE`
(server full).

**A room outlives its host.** Collaboration is peer to peer, so a room must not
die with the one browser that opened it. When the host's stream ends the room
lives on for `--host-grace` (default `2m`; a negative value restores the old
behaviour, the host leaving closes the room).

- *Within the grace* the host back as the same person keeps the role, with
  nothing changed for the others: `Reclaim` with a session token of the host's
  subject (new host token, the old one dead), or simply a new `Room` stream with
  its own token. Messages sent to `"host"` meanwhile wait in its queue (the usual
  `--max-queue`; past it the sender gets `sys.error`) and are delivered on return.
  What can still be lost, and only this: a message the server wrote to the old
  host's connection before it noticed that the connection was dead (the
  rendezvous cannot know; the collab layer's rejoin with a version vector covers
  it).
- *Past the grace*, or when the host calls `HandOver{room,to}` first, the
  **earliest-admitted guest still connected** becomes the host (no version-vector
  election: the collab layer reconciles in both directions on rejoin). A
  pending, denied or disconnected guest is never promoted; if nobody qualifies the
  room closes (`promote` / `failed_precondition`). A guest cannot promote itself
  and a non-host cannot `HandOver` (`PERMISSION_DENIED`); to a pending guest it is
  `FAILED_PRECONDITION`, to a stranger `NOT_FOUND`. The role moves under the
  server's lock: there is exactly one host at any moment, whatever races.
- *What changes.* The promoted peer keeps its peer ID and its token (so the site
  identity a collab layer derives from the peer ID is stable) and gains the host's
  powers: `Admit`, `Deny`, `HandOver`, `CloseRoom`. Every peer, the old host
  included, receives `sys.host-changed` with body `{"from":"<peer>","to":"<peer>"}`.
  The new host is told again about the room: `sys.knock` for each pending guest,
  `sys.join` for each admitted one, then the messages that were queued for the old
  host, in order (the guests' messages sent to `"host"` during the outage are not
  dropped). `"host"` as the destination of a guest always means the current host.
  The room's TTL is **never** extended.
- *Who pays.* `RoomCredentials` are charged to the current host's person if it
  said who it is when it knocked (`x-turn-session` metadata, `client.WithSession`),
  else to the person who opened the room, until the TTL.
- *The old host returns after a promotion* with `Reclaim` and the same session:
  it keeps its peer ID (`"host"`) and is an **admitted** guest of the new host (no
  knock; the new host sees `sys.join`), with a new token and the lowest priority
  among the guests. Its old token stays dead.
- *What the collab layer does on `sys.host-changed`.* The new host starts its
  `collab.Server` seeded from its own replica; the others rejoin it through the
  rendezvous with their version vector (a rejoin syncs both ways, so a guest that
  is ahead of the new host pushes what it holds). In peer-to-peer mode nothing may
  purge history, or a purged replica could not serve a rejoin.

New observer actions (and `turnd.rendezvous.operations` actions): `hand_over`,
`reclaim`, and the two with no RPC, `host_lost` (the grace starts) and `promote`
(the grace ended); never a token, room, peer or name.

The credential scheme is
[draft-uberti-behave-turn-rest-00](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00).
The Go client, for the browser and native, is
`github.com/go-turn/turn/rendezvous/client`: `Create`, `Join(name)` (blocks until
admitted, `ErrDenied` otherwise; `WithSession(token)` says who the guest is),
`Admit`, `Deny`, `Send`, `Recv`, `Credentials`, `Close`, and for the handover
`HandOver`, `Reclaim`, `IsHost`, `CurrentHost` and `Event.HostChange`. It is a real grpc-go client dialed over the browser's WebSocket through
`syscall/js`; it adds about 16 MB to a wasm binary (3.5 MB more gzipped), almost
all of it grpc. go-crdt/collab's js/wasm build does not link grpc, so a page that
does not otherwise ship it should load this client in a separate wasm, fetched
when a collaboration starts.

### Observability (OpenTelemetry)

`turnd` exports traces, metrics and logs over OTLP (gRPC or HTTP) with the
official Go SDK. It is off, and costs nothing, until `--otel-endpoint` is set.

| Flag | Meaning |
|---|---|
| `--otel-endpoint` | `https://host:4318` (http) or `host:4317` (grpc); no credentials, query or fragment in it |
| `--otel-protocol` | `http` (default) or `grpc` |
| `--otel-token-file` | file holding the collector's bearer token, sent as `Authorization: Bearer …` |
| `--otel-insecure` | allow `http://` or plaintext gRPC (a token is then refused unless the collector is on loopback) |
| `--otel-sample-ratio` | fraction of traces kept, 0..1 (default 1) |
| `--otel-service-name` | `service.name` (default `turnd`); `service.version` is the build version, `service.instance.id` a random ID |
| `--otel-trust-client-context` | continue a caller's W3C `traceparent`; off, every request starts its own trace |

The token is read from a file only. `OTEL_EXPORTER_OTLP_HEADERS` (and the
per-signal variants) is ignored and reported at startup, so a token never travels
through the environment.

**Traces.** A server span for `/login`, `/callback` and `/healthz` (named
`GET /login`, status Error only for a 5xx, `turnd.outcome` on login), one for
every gRPC method (otelgrpc, `rpc.method`, `rpc.status_code`, plus
`turnd.room.action` and `turnd.outcome`), and a short root span per TURN control
request (`TURN allocate`, `refresh`, `create_permission`, `channel_bind`, with
`turnd.result` and `turnd.policy`). There is no span per relayed packet.

**Metrics** (units are UCUM; every attribute has a small fixed set of values):

| Instrument | Kind, unit | Attributes |
|---|---|---|
| `turnd.relay.allocations`, `.permissions`, `.channels` | gauge, `{allocation}` `{permission}` `{channel}` | |
| `turnd.relay.requests` | counter, `{request}` | `turnd.method`, `turnd.transport` (udp, tcp, tls), `turnd.result` |
| `turnd.relay.policy.refusals` | counter, `{refusal}` | `turnd.policy`: loopback, private, link_local, metadata, cgnat, multicast, translator, own_address, reserved, port_zero, family_mismatch |
| `turnd.relay.auth.failures` | counter, `{failure}` | `turnd.surface` (relay, api), `turnd.reason` |
| `turnd.relay.bytes`, `.packets` | counter, `By` `{packet}` | `turnd.direction` (client_to_peer, peer_to_client) |
| `turnd.relay.packets.dropped` | counter, `{packet}` | |
| `turnd.rooms` | gauge, `{room}` | |
| `turnd.guests` | gauge, `{guest}` | `turnd.state` (pending, admitted) |
| `turnd.rendezvous.operations` | counter, `{operation}` | `turnd.action`, `turnd.outcome` |
| `turnd.login.outcomes` | counter, `{login}` | `turnd.outcome` |
| `http.server.request.duration` | histogram, `s` | `http.request.method`, `http.route`, `http.response.status_code` |
| `rpc.server.*` | otelgrpc | |

Allocations created and refused are `turnd.relay.requests{turnd.method=allocate}`
by result; knocks, admits and denies are `turnd.rendezvous.operations`; TURN
credentials minted are its `credentials_host` and `credentials_room` actions with
outcome `ok`; sessions issued and refused are `turnd.login.outcomes`. The relay's
packet and byte counters are read when the metrics are pushed: the relay's hot
path does the same work with telemetry on or off.

**Logs.** `log/slog`, JSON on stderr (journald-friendly), with `trace_id` and
`span_id` when a span is active; with telemetry on the same records go over OTLP
through the OpenTelemetry slog bridge, from Info up, after redaction. The login
outcome lines of every callback are kept as they were.

**Privacy.** No token, code, cookie, credential, password, room ID or TURN
username, and no client or peer address (not even in the debug records), reaches
a span, a metric or a log record: attributes are fixed words, the SDK
instrumentation's own address attributes are removed before export, and the
pseudonymous login subject stays on stderr. Tests run the daemon against an
in-process collector and assert that none of those strings is in any request
body.

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
answers 403. The one exception is two clients relaying to each other: an own
address is a peer only at the relayed port of a live allocation (checked when the
permission or channel is made and again on every datagram, which is handed over in
memory), so SSH, 443 and the TURN listeners stay unreachable through the relay. `Config.AllowPeers` re-enables ranges (tests use `127.0.0.0/8`).
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

A relayed call outlives the credential that opened it. A username is checked for
expiry when it STARTS an allocation (Allocate); on an allocation that the same
username created from the same 5-tuple, Refresh, CreatePermission and ChannelBind
keep working after the expiry (`Config.AuthExisting`, the keyring's
`AuthExisting`): the MESSAGE-INTEGRITY check still needs the password derived from
the username, and another username on that allocation stays refused (RFC 8656
section 5). `--max-allocation-age` (`Config.MaxAllocationAge`, default 12 h) bounds
it: past that age a Refresh answers 403, and an expired username is no longer
accepted. A new call needs a fresh credential.

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

### Session renewal at go-authn/bridge

A session token lasts `--session-ttl` (1 h). So that a person is not sent back
through the login popup every hour, turnd asks for `offline_access` at the login
and keeps the issuer's **refresh token server side**, in memory, never sent to
the browser (see "Renewing a session" above). It needs the issuer to issue
refresh tokens to turnd's client. At [go-authn/bridge](https://github.com/go-authn/bridge)
that is `refresh_lifetime` on the client block (README, "Without a browser" and
"Several resource servers"; read from the v0.23.12 source, where refresh tokens
are issued when the client has a `refresh_lifetime`, unknown scopes such as
`offline_access` are accepted and ignored, and the family's end is fixed at the
login, rotation does not extend it). The client block turnd needs:

```hcl
client "turnd" {
  secret_file      = "/etc/authn-bridge/turnd.secret"      # the file behind --client-secret-file
  redirect_uris    = ["https://turn.example.org/callback"] # <public-url>/callback, exact
  refresh_lifetime = "168h"                                # refresh tokens on; 7 days from each login
}
```

(`id`, `secret_file` and `redirect_uris` are what the client already has; the
change is `refresh_lifetime`.) Set `--session-renewal-lifetime` to the same value
(default 168h): it is how long turnd keeps a family before bridge would refuse it
anyway. Without `refresh_lifetime` the login still works and the session is
simply not renewable (the log says "the provider issued no refresh token");
`--session-renewal-lifetime 0` turns renewal off and asks for `openid` alone.

The store is **bounded** (10000 families; when full the family closest to its end
is dropped) and **lost on a restart**: everybody signs in again once, as with a
session-key change. Revoking a person at bridge (account, passkey, application
session) ends their renewal at the next `RenewSession`; a session token already
issued stays valid until its own expiry (at most `--session-ttl`).

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
`allocate`.

## Licence

BSD-3-Clause.
