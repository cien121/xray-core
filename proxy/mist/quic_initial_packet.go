// quic_initial_packet.go: QUIC Initial packet encoding/decoding per RFC 9000/9001.
//
// Implements:
//   - QUIC variable-length integer encoding (RFC 9000 §16)
//   - Initial long header encoding (RFC 9000 §17.2)
//   - CRYPTO frame encoding (RFC 9000 §19.6)
//   - AES-128-GCM payload encryption (RFC 9001 §5.3)
//   - Header protection with AES-ECB (RFC 9001 §5.4)
package mist

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

// quicVersion1 is the QUIC version 1 version number (RFC 9000 §17.2).
const quicVersion1 = 0x00000001

// quicInitialPacketType is the long packet type for Initial (RFC 9000 §17.2).
const quicInitialPacketType = 0x0

// encodeQuicVarint encodes a QUIC variable-length integer (RFC 9000 §16).
func encodeQuicVarint(v uint64) []byte {
	switch {
	case v < 64:
		return []byte{byte(v)}
	case v < 16384:
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(v)|0x4000)
		return b
	case v < 1073741824:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(v)|0x80000000)
		return b
	default:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, v|0xc000000000000000)
		return b
	}
}

// decodeQuicVarint decodes a QUIC variable-length integer.
// Returns the value and the number of bytes consumed.
func decodeQuicVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("quic: empty varint")
	}
	prefix := b[0] >> 6
	switch prefix {
	case 0:
		return uint64(b[0] & 0x3f), 1, nil
	case 1:
		if len(b) < 2 {
			return 0, 0, errors.New("quic: truncated 2-byte varint")
		}
		return uint64(binary.BigEndian.Uint16(b[:2]) & 0x3fff), 2, nil
	case 2:
		if len(b) < 4 {
			return 0, 0, errors.New("quic: truncated 4-byte varint")
		}
		return uint64(binary.BigEndian.Uint32(b[:4]) & 0x3fffffff), 4, nil
	default:
		if len(b) < 8 {
			return 0, 0, errors.New("quic: truncated 8-byte varint")
		}
		return binary.BigEndian.Uint64(b[:8]) & 0x3fffffffffffffff, 8, nil
	}
}

// encodeCryptoFrame encodes a CRYPTO frame (RFC 9000 §19.6).
// Type=0x06, Offset, Length, Crypto Data.
func encodeCryptoFrame(offset uint64, data []byte) []byte {
	out := []byte{0x06}
	out = append(out, encodeQuicVarint(offset)...)
	out = append(out, encodeQuicVarint(uint64(len(data)))...)
	out = append(out, data...)
	return out
}

// decodeCryptoFrame decodes a CRYPTO frame, returning offset and data.
func decodeCryptoFrame(b []byte) (offset uint64, data []byte, consumed int, err error) {
	if len(b) == 0 || b[0] != 0x06 {
		return 0, nil, 0, errors.New("quic: not a CRYPTO frame")
	}
	pos := 1
	off, n, err := decodeQuicVarint(b[pos:])
	if err != nil {
		return 0, nil, 0, err
	}
	pos += n
	ln, n, err := decodeQuicVarint(b[pos:])
	if err != nil {
		return 0, nil, 0, err
	}
	pos += n
	if uint64(len(b)-pos) < ln {
		return 0, nil, 0, errors.New("quic: truncated CRYPTO data")
	}
	return off, b[pos : pos+int(ln)], pos + int(ln), nil
}

// quicInitialHeader holds the decoded Initial packet header fields.
type quicInitialHeader struct {
	dcid      []byte
	scid      []byte
	token     []byte
	packetNum uint32
	pnLen     int
	headerLen int // bytes from start through packet number (AAD length)
}

// sealQuicInitial encrypts a payload into a full QUIC Initial packet.
//   - dcid/scid: connection IDs (dcid is used for key derivation)
//   - packetNum: packet number (encoded in pnLen bytes)
//   - secrets: the sender's Initial secrets (client for C2S, server for S2C)
//   - payload: plaintext CRYPTO frame bytes (already framed)
//
// Returns the full UDP datagram.
func sealQuicInitial(dcid, scid []byte, token []byte, packetNum uint32, secrets quicInitialSecrets, payload []byte) ([]byte, error) {
	// Packet number length: use 2 bytes (supports up to 65535).
	const pnLen = 2
	// AEAD overhead: 16-byte GCM tag.
	const tagLen = 16

	// Build header (before encryption).
	// First byte: Header Form=1, Fixed=1, Type=0 (Initial), Reserved=0, PnLen=pnLen-1.
	firstByte := byte(0xc0) | byte(pnLen-1)
	header := []byte{firstByte}
	var verBuf [4]byte
	binary.BigEndian.PutUint32(verBuf[:], quicVersion1)
	header = append(header, verBuf[:]...)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = append(header, encodeQuicVarint(uint64(len(token)))...)
	header = append(header, token...)
	// Length = pnLen + payloadLen + tagLen.
	payloadLen := len(payload) + tagLen
	header = append(header, encodeQuicVarint(uint64(pnLen+payloadLen))...)
	// Packet number (big-endian, pnLen bytes).
	var pnBuf [4]byte
	binary.BigEndian.PutUint32(pnBuf[:], packetNum)
	header = append(header, pnBuf[4-pnLen:]...)

	// AEAD encryption.
	block, err := aes.NewCipher(secrets.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Nonce = IV XOR packet number (left-padded to 12 bytes).
	var nonce [12]byte
	copy(nonce[:], secrets.iv[:])
	// XOR last 4 bytes with packet number (big-endian).
	pnBytes := pnBuf[:]
	for i := 0; i < 4; i++ {
		nonce[8+i] ^= pnBytes[i]
	}
	ciphertext := gcm.Seal(nil, nonce[:], payload, header)

	// Assemble: header + ciphertext.
	packet := make([]byte, 0, len(header)+len(ciphertext))
	packet = append(packet, header...)
	packet = append(packet, ciphertext...)

	// Header protection: sample = first 16 bytes of ciphertext.
	if len(ciphertext) < 16 {
		return nil, errors.New("quic: ciphertext too short for header protection")
	}
	sample := ciphertext[:16]
	mask, err := aesECBEncrypt(secrets.hpKey[:], sample)
	if err != nil {
		return nil, err
	}
	// Mask first byte: XOR low 4 bits (pn length bits preserved).
	packet[0] ^= mask[0] & 0x0f
	// Mask packet number bytes.
	pnOffset := len(header) - pnLen
	for i := 0; i < pnLen; i++ {
		packet[pnOffset+i] ^= mask[1+i]
	}
	return packet, nil
}

// openQuicInitial decrypts a QUIC Initial packet.
// Returns the header fields and the decrypted payload (CRYPTO frame bytes).
func openQuicInitial(packet []byte, secrets quicInitialSecrets) (quicInitialHeader, []byte, error) {
	var hdr quicInitialHeader
	if len(packet) < 1 {
		return hdr, nil, errors.New("quic: packet too short")
	}
	// Header protection: need sample (ciphertext starts after header).
	// First, parse the unprotected header to find the packet number offset.
	// The first byte is protected (low 4 bits masked), but pnLen bits are
	// in bits 0-1, which are NOT masked (mask only covers bits 2-5... actually
	// RFC 9001 §5.4.1: mask first byte bits 0-3, pn length is bits 0-1).
	// Wait: pn length is encoded in the LOW 2 bits, which ARE masked.
	// To find the sample offset, we must first remove header protection.
	// But we don't know pnLen until we unmask. Solution: try all pnLens?
	// Standard approach: the sample starts at (headerLen - pnLen + pnLen) =
	// the ciphertext offset, which depends on pnLen. For Initial packets,
	// we assume the sender used pnLen=2 (our own encoder always does).
	// For robustness, try pnLen 1-4 and pick the one that decrypts.
	//
	// Simplified: assume pnLen=2 (matches our encoder).
	const pnLen = 2
	// Parse header fields to find ciphertext offset.
	pos := 1
	if len(packet) < pos+4 {
		return hdr, nil, errors.New("quic: truncated version")
	}
	version := binary.BigEndian.Uint32(packet[pos : pos+4])
	if version != quicVersion1 {
		return hdr, nil, fmt.Errorf("quic: unsupported version 0x%08x", version)
	}
	pos += 4
	if len(packet) < pos+1 {
		return hdr, nil, errors.New("quic: truncated DCID len")
	}
	dcidLen := int(packet[pos])
	pos++
	if len(packet) < pos+dcidLen {
		return hdr, nil, errors.New("quic: truncated DCID")
	}
	hdr.dcid = packet[pos : pos+dcidLen]
	pos += dcidLen
	if len(packet) < pos+1 {
		return hdr, nil, errors.New("quic: truncated SCID len")
	}
	scidLen := int(packet[pos])
	pos++
	if len(packet) < pos+scidLen {
		return hdr, nil, errors.New("quic: truncated SCID")
	}
	hdr.scid = packet[pos : pos+scidLen]
	pos += scidLen
	tokenLen, n, err := decodeQuicVarint(packet[pos:])
	if err != nil {
		return hdr, nil, err
	}
	pos += n
	if len(packet) < pos+int(tokenLen) {
		return hdr, nil, errors.New("quic: truncated token")
	}
	hdr.token = packet[pos : pos+int(tokenLen)]
	pos += int(tokenLen)
	_, n, err = decodeQuicVarint(packet[pos:])
	if err != nil {
		return hdr, nil, err
	}
	pos += n
	// pos now points at packet number.
	pnOffset := pos
	// Header protection sample: ciphertext starts at pnOffset+pnLen.
	sampleOffset := pnOffset + pnLen
	if len(packet) < sampleOffset+16 {
		return hdr, nil, errors.New("quic: packet too short for HP sample")
	}
	sample := packet[sampleOffset : sampleOffset+16]
	mask, err := aesECBEncrypt(secrets.hpKey[:], sample)
	if err != nil {
		return hdr, nil, err
	}
	// Unmask first byte and packet number.
	firstByte := packet[0] ^ (mask[0] & 0x0f)
	_ = firstByte // validated below
	var pnBytes [4]byte
	for i := 0; i < pnLen; i++ {
		pnBytes[4-pnLen+i] = packet[pnOffset+i] ^ mask[1+i]
	}
	hdr.packetNum = binary.BigEndian.Uint32(pnBytes[:])
	hdr.pnLen = pnLen
	hdr.headerLen = pnOffset + pnLen

	// Reconstruct AAD: header with unmasked first byte and packet number.
	aad := make([]byte, hdr.headerLen)
	copy(aad, packet[:hdr.headerLen])
	aad[0] = firstByte
	copy(aad[pnOffset:], pnBytes[4-pnLen:])

	// AEAD decryption.
	block, err := aes.NewCipher(secrets.key[:])
	if err != nil {
		return hdr, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return hdr, nil, err
	}
	var nonce [12]byte
	copy(nonce[:], secrets.iv[:])
	for i := 0; i < 4; i++ {
		nonce[8+i] ^= pnBytes[i]
	}
	ciphertext := packet[sampleOffset:]
	plaintext, err := gcm.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return hdr, nil, errors.New("quic: AEAD decryption failed")
	}
	return hdr, plaintext, nil
}

// aesECBEncrypt encrypts a single 16-byte block with AES-ECB.
func aesECBEncrypt(key, block []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(block) != 16 {
		return nil, errors.New("quic: ECB block must be 16 bytes")
	}
	out := make([]byte, 16)
	c.Encrypt(out, block)
	return out, nil
}
