//go:build mist_unsafe_initial

// Real RandomCiphertextCodec implementation — LAB/INTERNAL TESTING ONLY.
//
// This file is compiled only with `-tags mist_unsafe_initial`. Release
// builds (no tag) use initial_codec_disabled.go instead, whose methods
// always fail, so a release binary can never emit a random-ciphertext
// Initial packet even if misconfigured.
//
// The payload here is random ciphertext inside a QUIC long header: a
// recognizable DPI fingerprint. It must never run on a public network.
// See CheckInitialCodecSafeForAddr in initial_codec_safety.go.
package mist

import (
	"encoding/binary"
	"errors"
)

// ---------------------------------------------------------------------------
// Simplified implementation: random ciphertext
// ---------------------------------------------------------------------------

// RandomCiphertextCodec is the Phase 1 simplified Initial codec.
//
// The payload is random ciphertext (not a real QUIC Initial). This is sufficient
// for internal testing but is a fingerprint on networks doing deep packet inspection.
// Phase 0 will replace this with the real QUIC Initial implementation.
type RandomCiphertextCodec struct{}

// QUIC version (fixed v1, per design §0.1 decision 1).
const quicVersion uint32 = 0x00000001

// sealInitialPacket builds a QUIC Initial long header + random-ciphertext payload.
//
// Long header format (§3.2):
//   [1|1|0|0|T T|R R|P P][Version(4)][DCID Len(1)][DCID(8)][SCID(8)][Token Len(varint=0)][Length(varint)][PacketNum(4 masked)][Payload]
//
// For the simplified version, header protection uses a fixed mask (not RFC 9001 §5.4.4).
// Phase 0 will implement the full header protection.
func (c *RandomCiphertextCodec) buildInitial(dcid, scid [8]byte, packetNum uint32, payloadLen int) []byte {
	// Fixed header: 1 + 4 + 1 + 8 + 8 + 1 + 2 (varint length, simplified) + 4 = 29 bytes
	// For simplicity, Length is encoded as 2-byte big-endian (not varint).
	headerLen := 1 + 4 + 1 + 8 + 8 + 1 + 2 + 4
	buf := make([]byte, headerLen+payloadLen)

	off := 0
	// Byte 0: 1|1|0|0|T T|R R|P P
	//   bit0=1, bit1=1 (long header), bits 2-3 = 0b00 (Initial), bits 4-5 = R R (0),
	//   bits 6-7 = P P = 0b11 (4-byte packet number)
	buf[off] = 0xC0 | 0x03 // 0b11000011
	off++

	// Version (4 bytes, big-endian)
	binary.BigEndian.PutUint32(buf[off:], quicVersion)
	off += 4

	// DCID Len (1 byte) = 8
	buf[off] = 8
	off++

	// DCID (8 bytes)
	copy(buf[off:], dcid[:])
	off += 8

	// SCID (8 bytes)
	copy(buf[off:], scid[:])
	off += 8

	// Token Length (1 byte, simplified as 1 byte not varint) = 0
	buf[off] = 0
	off++

	// Length (2 bytes, big-endian; simplified, not varint)
	// Length = packet number (4) + payload length
	binary.BigEndian.PutUint16(buf[off:], uint16(4+payloadLen))
	off += 2

	// Packet Number (4 bytes, big-endian)
	// Simplified: no header protection mask (fixed zero mask for Phase 1).
	// Phase 0 will implement RFC 9001 §5.4.4.
	binary.BigEndian.PutUint32(buf[off:], packetNum)
	off += 4

	return buf
}

// parseInitialPacket parses a QUIC Initial long header.
// Returns dcid, scid, packetNum, and the payload offset.
func (c *RandomCiphertextCodec) parseInitialPacket(packet []byte) (dcid, scid [8]byte, packetNum uint32, payloadOff int, err error) {
	if len(packet) < 29 {
		return dcid, scid, 0, 0, errors.New("initial: packet too short")
	}
	off := 0

	// Byte 0: check long header bits (1|1)
	if packet[off]&0xC0 != 0xC0 {
		return dcid, scid, 0, 0, errors.New("initial: not a long header")
	}
	// Check type = Initial (0b00)
	if packet[off]&0x30 != 0x00 {
		return dcid, scid, 0, 0, errors.New("initial: not an Initial packet")
	}
	off++

	// Version (4 bytes) - we accept any, but expect 0x00000001
	off += 4

	// DCID Len (1 byte)
	dcidLen := int(packet[off])
	off++
	if dcidLen != 8 {
		return dcid, scid, 0, 0, errors.New("initial: unexpected DCID length")
	}

	// DCID (8 bytes)
	copy(dcid[:], packet[off:off+8])
	off += 8

	// SCID (8 bytes) - note: simplified format has fixed 8-byte SCID, no length byte
	copy(scid[:], packet[off:off+8])
	off += 8

	// Token Length (1 byte)
	tokenLen := int(packet[off])
	off++
	if tokenLen != 0 {
		return dcid, scid, 0, 0, errors.New("initial: token not supported")
	}

	// Length (2 bytes)
	// We ignore this for parsing; payload is the rest.
	off += 2

	// Packet Number (4 bytes)
	// Simplified: no header protection to remove.
	packetNum = binary.BigEndian.Uint32(packet[off:])
	off += 4

	return dcid, scid, packetNum, off, nil
}

// SealInitial encrypts an AUTH payload into a QUIC Initial packet (simplified).
func (c *RandomCiphertextCodec) SealInitial(authPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32) ([]byte, error) {
	// Simplified: payload is the AUTH payload as-is (already encrypted by caller).
	// In the real implementation, this would be QUIC Initial encryption.
	packet := c.buildInitial(dcid, scid, packetNum, len(authPayload))
	copy(packet[len(packet)-len(authPayload):], authPayload)
	return packet, nil
}

// OpenInitial decrypts a QUIC Initial packet (simplified).
func (c *RandomCiphertextCodec) OpenInitial(packet []byte) ([]byte, [8]byte, [8]byte, uint32, error) {
	dcid, scid, packetNum, payloadOff, err := c.parseInitialPacket(packet)
	if err != nil {
		return nil, dcid, scid, 0, err
	}
	return packet[payloadOff:], dcid, scid, packetNum, nil
}

// SealInitialResponse encrypts an AUTH_OK payload (simplified).
func (c *RandomCiphertextCodec) SealInitialResponse(authOKPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32) ([]byte, error) {
	packet := c.buildInitial(dcid, scid, packetNum, len(authOKPayload))
	copy(packet[len(packet)-len(authOKPayload):], authOKPayload)
	return packet, nil
}

// OpenInitialResponse decrypts a QUIC Initial packet (simplified).
func (c *RandomCiphertextCodec) OpenInitialResponse(packet []byte) ([]byte, [8]byte, [8]byte, uint32, error) {
	return c.OpenInitial(packet)
}
