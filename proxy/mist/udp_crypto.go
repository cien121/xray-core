// Package mistcore: Mist UDP crypto.
//
// UDP uses XChaCha20-Poly1305 (same as TCP) with a 24-byte nonce:
//   NONCE = [SESSION_ID(8)][DIR(4)][PACKET_NUM(4)][RESERVED(8)]
//
// This differs from TCP's 12-byte nonce (epoch|dir|counter) expanded to 24.
// UDP has no EPOCH in the nonce; migration uses the MIGRATE frame instead.
package mist

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// UDP nonce layout (24 bytes, XChaCha20).
const (
	udpNonceLen = 24
	udpNonceSessionIDOff = 0
	udpNonceDirOff       = 8
	udpNoncePktNumOff    = 12
	udpNonceReservedOff  = 16
)

// UDPNonce builds the 24-byte XChaCha20 nonce for UDP packets.
//
//   sessionID: first 8 bytes of the 16-byte CONN_ID (§5.2)
//   dir:       udpDirC2S (0x00000000) or udpDirS2C (0xFFFFFFFF)
//   packetNum: 32-bit packet number (pre-mask real value, §4.2)
func UDPNonce(sessionID [8]byte, dir uint32, packetNum uint32) [24]byte {
	var n [24]byte
	copy(n[udpNonceSessionIDOff:], sessionID[:])
	binary.BigEndian.PutUint32(n[udpNonceDirOff:], dir)
	binary.BigEndian.PutUint32(n[udpNoncePktNumOff:], packetNum)
	// RESERVED(8) stays zero.
	return n
}

// udpAEAD creates an XChaCha20-Poly1305 AEAD from a 32-byte key.
func udpAEAD(key *[32]byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key[:])
}

// UDPSeal encrypts plaintext with the given key, nonce, and AAD.
// Returns ciphertext (includes 16-byte auth tag).
func UDPSeal(key *[32]byte, nonce [24]byte, plaintext, aad []byte) ([]byte, error) {
	aead, err := udpAEAD(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce[:], plaintext, aad), nil
}

// UDPOpen decrypts ciphertext with the given key, nonce, and AAD.
// Returns plaintext or an error (authentication failure = silent drop).
func UDPOpen(key *[32]byte, nonce [24]byte, ciphertext, aad []byte) ([]byte, error) {
	aead, err := udpAEAD(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, errors.New("udp: aead open failed")
	}
	return plain, nil
}

// UDPDeriveHPKey derives the header-protection key for one direction.
//
//   hp_key = HKDF-SHA256(salt=session_key, ikm=DCID, info="mist-udp/hp-c2s"|"mist-udp/hp-s2c", L=32)
//
// Per design §3.2: hp_key is derived per-direction (c2s and s2c use different keys).
func UDPDeriveHPKey(sessionKey *[32]byte, dcid [8]byte, dir uint32) [32]byte {
	var info string
	if dir == udpDirC2S {
		info = "mist-udp/hp-c2s"
	} else {
		info = "mist-udp/hp-s2c"
	}
	// hkdf.New(hash, secret=ikm, salt, info) does Extract(salt, secret) then Expand.
	kdf := hkdf.New(sha256.New, dcid[:], sessionKey[:], []byte(info))
	var out [32]byte
	// ReadFull is guaranteed by hkdf.Reader for L <= 255*HashLen.
	if _, err := io.ReadFull(kdf, out[:]); err != nil {
		// Should never happen; zero key on error.
		for i := range out {
			out[i] = 0
		}
	}
	return out
}
