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

## Licence

BSD-3-Clause.
