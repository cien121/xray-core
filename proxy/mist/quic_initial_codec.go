// quic_initial_codec.go: QUICInitialCodec implements InitialCodec with real
// QUIC Initial packets per RFC 9000/9001 (Phase 0).
//
// This is the production-safe codec: Initial packets are indistinguishable
// from genuine QUIC Initial packets under DPI (valid long header, RFC 9001
// encryption, header protection).
package mist

import (
	"errors"
)

// QUICInitialCodec is the Phase 0 production Initial codec.
type QUICInitialCodec struct{}

// SealInitial encrypts an AUTH payload into a QUIC Initial packet (C2S).
func (c *QUICInitialCodec) SealInitial(authPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32) ([]byte, error) {
	clientSecrets, _, err := deriveQuicInitialSecrets(dcid[:])
	if err != nil {
		return nil, err
	}
	frame := encodeCryptoFrame(0, authPayload)
	return sealQuicInitial(dcid[:], scid[:], nil, packetNum, clientSecrets, frame)
}

// OpenInitial decrypts a QUIC Initial packet, returning the AUTH payload.
// The DCID is read from the packet header (unencrypted) for key derivation.
func (c *QUICInitialCodec) OpenInitial(packet []byte) (authPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32, err error) {
	// Parse DCID from header (before decryption) for key derivation.
	parsedDCID, err := parseQuicInitialDCID(packet)
	if err != nil {
		return nil, dcid, scid, 0, err
	}
	clientSecrets, _, err := deriveQuicInitialSecrets(parsedDCID)
	if err != nil {
		return nil, dcid, scid, 0, err
	}
	hdr, plaintext, err := openQuicInitial(packet, clientSecrets)
	if err != nil {
		return nil, dcid, scid, 0, err
	}
	_, data, _, err := decodeCryptoFrame(plaintext)
	if err != nil {
		return nil, dcid, scid, 0, err
	}
	copy(dcid[:], hdr.dcid)
	copy(scid[:], hdr.scid)
	return data, dcid, scid, hdr.packetNum, nil
}

// SealInitialResponse encrypts an AUTH_OK payload into a QUIC Initial packet (S2C).
func (c *QUICInitialCodec) SealInitialResponse(authOKPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32) ([]byte, error) {
	_, serverSecrets, err := deriveQuicInitialSecrets(dcid[:])
	if err != nil {
		return nil, err
	}
	frame := encodeCryptoFrame(0, authOKPayload)
	return sealQuicInitial(dcid[:], scid[:], nil, packetNum, serverSecrets, frame)
}

// OpenInitialResponse decrypts a QUIC Initial packet, returning the AUTH_OK payload.
func (c *QUICInitialCodec) OpenInitialResponse(packet []byte) (authOKPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32, err error) {
	parsedDCID, err := parseQuicInitialDCID(packet)
	if err != nil {
		return nil, dcid, scid, 0, err
	}
	_, serverSecrets, err := deriveQuicInitialSecrets(parsedDCID)
	if err != nil {
		return nil, dcid, scid, 0, err
	}
	hdr, plaintext, err := openQuicInitial(packet, serverSecrets)
	if err != nil {
		return nil, dcid, scid, 0, err
	}
	_, data, _, err := decodeCryptoFrame(plaintext)
	if err != nil {
		return nil, dcid, scid, 0, err
	}
	copy(dcid[:], hdr.dcid)
	copy(scid[:], hdr.scid)
	return data, dcid, scid, hdr.packetNum, nil
}

// parseQuicInitialDCID extracts the DCID from a QUIC Initial packet header.
// The header fields before the packet number are not header-protected
// (only the first byte low bits and packet number are masked).
func parseQuicInitialDCID(packet []byte) ([]byte, error) {
	if len(packet) < 6 {
		return nil, errors.New("quic: packet too short")
	}
	pos := 1 + 4 // first byte + version
	if len(packet) < pos+1 {
		return nil, errors.New("quic: truncated DCID len")
	}
	dcidLen := int(packet[pos])
	pos++
	if len(packet) < pos+dcidLen {
		return nil, errors.New("quic: truncated DCID")
	}
	return packet[pos : pos+dcidLen], nil
}

// ProductionSafe marks QUICInitialCodec as production-safe.
// Real QUIC Initial packets are indistinguishable from genuine QUIC under DPI.
func (c *QUICInitialCodec) ProductionSafe() bool { return true }

// Ensure QUICInitialCodec implements InitialCodec.
var _ InitialCodec = (*QUICInitialCodec)(nil)
