package creds

import "time"

// ICEServer is one entry of an RTCConfiguration's iceServers list
// (W3C WebRTC, RTCIceServer): urls, username, credential.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// Response is what the credential endpoints answer: a list a browser passes
// straight to RTCPeerConnection, and the lifetime in seconds (the draft's
// "ttl", §2.2).
type Response struct {
	ICEServers []ICEServer `json:"iceServers"`
	TTL        int         `json:"ttl"`
}

// NewResponse builds the answer for credentials valid until expiry, as of now.
// stun URLs carry no credentials; turn URLs carry the minted pair. The ttl is
// the whole seconds left, never negative.
func NewResponse(stun, turn []string, username, password string, expiry, now time.Time) Response {
	ttl := int(expiry.Sub(now) / time.Second)
	if ttl < 0 {
		ttl = 0
	}
	r := Response{TTL: ttl}
	if len(stun) > 0 {
		r.ICEServers = append(r.ICEServers, ICEServer{URLs: append([]string(nil), stun...)})
	}
	if len(turn) > 0 {
		r.ICEServers = append(r.ICEServers, ICEServer{
			URLs: append([]string(nil), turn...), Username: username, Credential: password})
	}
	if r.ICEServers == nil {
		r.ICEServers = []ICEServer{}
	}
	return r
}
