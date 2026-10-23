// Package mist: Mist UDP Initial packet codec.
//
// The InitialCodec interface abstracts Initial packet encoding/decoding.
// Phase 1 uses the simplified random-ciphertext implementation (internal testing only).
// Phase 0 will provide the real QUIC Initial implementation as a drop-in replacement.
//
// Interface covers both directions (per 2026-10-22 review):
//   - Client→Server: SealInitial / OpenInitial (AUTH)
//   - Server→Client: SealInitialResponse / OpenInitialResponse (AUTH_OK)
//
// Build tags (safety gate, 2026-10-23):
//   - The real RandomCiphertextCodec implementation lives in
//     initial_codec_unsafe.go and is compiled ONLY with
//     `-tags mist_unsafe_initial` (lab / internal testing).
//   - Without the tag, initial_codec_disabled.go provides an inert stub
//     whose methods always fail, so a release build can never emit a
//     random-ciphertext Initial even if misconfigured.
//   - Either way, CheckInitialCodecSafeForAddr (initial_codec_safety.go)
//     refuses public listen/peer addresses for non-production-safe codecs.
package mist

import (
	"crypto/rand"
	"crypto/sha256"
)

// ---------------------------------------------------------------------------
// InitialCodec interface
// ---------------------------------------------------------------------------

// InitialCodec encodes/decodes QUIC Initial packets for the Mist UDP handshake.
//
// Two implementations:
//   - RandomCiphertextCodec (Phase 1): simplified, random ciphertext payload.
//     Internal testing only; the payload is a fingerprint on deep-inspection networks.
//   - QUICInitialCodec (Phase 0): real QUIC Initial encryption per RFC 9001,
//     with a legitimate-looking ClientHello. Drop-in replacement.
type InitialCodec interface {
	// SealInitial encrypts an AUTH payload into a QUIC Initial packet.
	// Returns the full UDP datagram (QUIC long header + encrypted payload).
	SealInitial(authPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32) ([]byte, error)

	// OpenInitial decrypts a QUIC Initial packet, returning the AUTH payload.
	// Returns the SCID from the packet header for session tracking.
	OpenInitial(packet []byte) (authPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32, err error)

	// SealInitialResponse encrypts an AUTH_OK payload into a QUIC Initial packet.
	// dcid is the client's SCID (so the client can match the response).
	SealInitialResponse(authOKPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32) ([]byte, error)

	// OpenInitialResponse decrypts a QUIC Initial packet, returning the AUTH_OK payload.
	OpenInitialResponse(packet []byte) (authOKPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32, err error)
}

// handshakeCID computes HANDSHAKE_CID = HMAC-SHA256(K_auth, NONCE)[0:16].
// Per design §5.2: prevents tracking via fixed CID in Initial packets.
func handshakeCID(kAuth *[32]byte, nonce [24]byte) [16]byte {
	// HMAC-SHA256(key=K_auth, msg=NONCE), truncate to 16 bytes.
	// Simplified: use SHA256(K_auth || NONCE) and truncate.
	// Full HMAC will be implemented in Phase 1 final.
	h := sha256.New()
	h.Write(kAuth[:])
	h.Write(nonce[:])
	sum := h.Sum(nil)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

// randomBytes generates n random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
