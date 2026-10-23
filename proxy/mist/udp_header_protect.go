// Package mistcore: Mist UDP header protection.
//
// Implements QUIC-style header protection per UDP-DESIGN.md §3.2,
// following RFC 9001 §5.4.4 (ChaCha20 variant):
//
//   1. hp_key is derived per-direction (see UDPDeriveHPKey in udp_crypto.go).
//   2. Sample 16 bytes starting 4 bytes after the packet number
//      (= first byte of ciphertext).
//   3. mask = ChaCha20(hp_key, counter=sample[0:4] little-endian,
//      nonce=sample[4:16]) keystream, first 5 bytes.
//      (Counter/nonce come FROM the sample — a fixed counter would make
//      the mask constant per direction and the protection ineffective.)
//   4. Short header: mask[0] XORs the low 5 bits of byte 0
//      (R,R,K,P,P — spin bit S is NOT masked, stays random);
//      mask[1:5] XORs the 4-byte packet number.
//      Long header (Initial): mask[0] XORs the low 4 bits.
//
// This is separate from Phase 0's Initial AES-ECB protection; the two
// do not interact (short-header packets use this; Initial uses Phase 0).
package mist

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
)

// headerProtectMask generates the 5-byte header protection mask.
//
//   hpKey:  32-byte header protection key (per direction)
//   sample: 16-byte sample from ciphertext (must be ≥16 bytes)
//
// Per RFC 9001 §5.4.4 (ChaCha20 variant):
//   counter = little-endian uint32 of sample[0:4]
//   nonce   = sample[4:16] (12 bytes)
//   mask    = first 5 bytes of ChaCha20(hpKey, counter, nonce) keystream
func headerProtectMask(hpKey [32]byte, sample []byte) ([5]byte, error) {
	var mask [5]byte
	if len(sample) < 16 {
		return mask, errors.New("udp: header protection sample too short")
	}
	counter := binary.LittleEndian.Uint32(sample[0:4])
	var nonce [12]byte
	copy(nonce[:], sample[4:16])

	c, err := chacha20.NewUnauthenticatedCipher(hpKey[:], nonce[:])
	if err != nil {
		return mask, err
	}
	c.SetCounter(counter)
	// Generate 5 bytes of keystream by encrypting zeros.
	zeros := make([]byte, 5)
	keystream := make([]byte, 5)
	c.XORKeyStream(keystream, zeros)
	copy(mask[:], keystream)
	return mask, nil
}

// ApplyHeaderProtection applies the mask to a short header in place.
//
// header: 13-byte QUIC short header (will be modified).
// hpKey:  32-byte per-direction header protection key.
// sample: 16-byte ciphertext sample (from packet number + 4).
//
// Short header layout: [0|1|S|R|R|K|P P][DCID(8)][PN(4)]
//   - mask[0] XORs bits 0-4 (R,R,K,P,P); bit 5 (S, spin) untouched.
//   - mask[1:5] XORs the 4-byte packet number.
func ApplyHeaderProtection(header []byte, hpKey [32]byte, sample []byte) error {
	if len(header) < QUICShortHeaderLen {
		return errors.New("udp: header too short for protection")
	}
	mask, err := headerProtectMask(hpKey, sample)
	if err != nil {
		return err
	}
	// Low 5 bits of byte 0 (bits 0-4): R,R,K,P,P. Spin bit (bit 5) NOT masked.
	header[0] ^= mask[0] & 0x1F
	// 4-byte packet number.
	for i := 0; i < 4; i++ {
		header[9+i] ^= mask[1+i]
	}
	return nil
}

// RemoveHeaderProtection reverses ApplyHeaderProtection (XOR is symmetric).
//
// The caller must provide the same hpKey and sample used for masking.
// Sample is taken from the received packet's ciphertext (packet number + 4).
func RemoveHeaderProtection(header []byte, hpKey [32]byte, sample []byte) error {
	// XOR is its own inverse.
	return ApplyHeaderProtection(header, hpKey, sample)
}

// HeaderProtectSample extracts the 16-byte sample for header protection.
//
// Per §3.2: sample starts 4 bytes after the packet number start,
// which equals the first byte of ciphertext (header is 13 bytes,
// packet number occupies header[9:13], so ciphertext starts at offset 13).
//
// datagram: full UDP datagram (header + ciphertext).
// Returns the 16-byte sample, or error if ciphertext < 16 bytes.
func HeaderProtectSample(datagram []byte) ([]byte, error) {
	if len(datagram) < QUICShortHeaderLen+16 {
		return nil, errors.New("udp: datagram too short for header protection sample")
	}
	// Ciphertext starts right after the 13-byte header.
	return datagram[QUICShortHeaderLen : QUICShortHeaderLen+16], nil
}
