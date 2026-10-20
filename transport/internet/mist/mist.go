// Package mist implements the Mist (雾) v0.1 protocol as a native Xray
// transport (stream settings), for both dial (client) and listen (server)
// sides.
//
// Wire spec: ~/workspace/mist-protocol/SPEC.md, frozen at v0.1. The frame
// codec, AUTH/AUTH_OK/RESUME handshake, key derivation and nonce
// construction in protocol.go are byte-identical to proxy/mist (the
// outbound); this package only adapts them to the transport/internet
// dialer/listener framework. Mist mandates TLS: the dialer wraps the TCP
// connection with uTLS (default fingerprint hellochrome_155) and the
// listener terminates TLS before the AUTH handshake — AUTH is the first
// application data (SPEC 6.1).
package mist

// protocolName is the transport name registered with the internet package.
const protocolName = "mist"
