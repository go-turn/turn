# Security policy

## Reporting a vulnerability

Report it privately, through GitHub's private vulnerability reporting: the
**Report a vulnerability** button on the
[Security tab](https://github.com/go-turn/turn/security) of this repository.
Please do not open a public issue or pull request for it.

Include the version (or commit), what you sent or did, and what `turnd` did
instead of refusing.

## In scope

- `turnd`, the daemon, and its commands.
- The relay: the STUN/TURN codec and server, including the address policy that
  stops it relaying to loopback, private, link-local or its own addresses, and
  its bounds.
- The credentials: the HMAC scheme, the keyring and the session tokens.
- The rendezvous: rooms, admission, the gRPC API and its WebSocket origin
  allowlist.

How these are meant to behave is in the
[security policy of the documentation](https://go-turn.github.io/docs/latest/security/).

## Supported versions

The latest minor version receives fixes.
