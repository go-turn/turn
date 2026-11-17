// Package turn is the root of go-turn: a STUN (RFC 8489) and TURN (RFC 8656)
// relay for WebRTC peers, ephemeral TURN credentials minted behind an OpenID
// Connect login, and a rendezvous so two peers meet with one link.
//
// The pieces live in subpackages: stun (the wire format), server (the relay),
// creds (ephemeral credentials), rendezvous (signalling rooms) and cmd/turnd
// (the daemon). Pure Go, CGO_ENABLED=0. The design is go-turn/turn#1.
package turn
