// quic_initial_crypto.go: QUIC Initial key derivation per RFC 9001.
//
// Implements HKDF-Expand-Label (RFC 8446 §7.3) and Initial secret derivation
// (RFC 9001 §5.2). Used by QUICInitialCodec (Phase 0).
package mist

import (
	"crypto"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
)

// quicV1InitialSalt is the QUIC version 1 initial salt (RFC 9001 §5.2).
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// hkdfExpandLabel implements HKDF-Expand-Label from RFC 8446 §7.3:
//
//	HKDF-Expand-Label(Secret, Label, Context, Length) =
//	    HKDF-Expand(Secret, HkdfLabel, Length)
//
//	HkdfLabel = Length(2 bytes) || "tls13 "(6 bytes) || Label || Context
//	Context = ContextLength(1 byte) || Context
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	hkdfLabel := make([]byte, 0, 2+6+len(label)+1+len(context))
	// Length (2 bytes, big-endian)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(length))
	hkdfLabel = append(hkdfLabel, lenBuf[:]...)
	// "tls13 " prefix
	hkdfLabel = append(hkdfLabel, []byte("tls13 ")...)
	// Label
	hkdfLabel = append(hkdfLabel, []byte(label)...)
	// Context length + context
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	// hkdf.Expand returns ([]byte, error) in this Go version.
	expanded, err := hkdf.Expand(sha256.New, secret, string(hkdfLabel), length)
	if err != nil {
		return nil, err
	}
	return expanded, nil
}

// quicInitialSecrets holds the derived keys for one direction (client or server).
type quicInitialSecrets struct {
	key   [16]byte // AES-128-GCM key
	iv    [12]byte // AEAD nonce base
	hpKey [16]byte // header protection key (AES-ECB)
}

// deriveQuicInitialSecrets derives client/server Initial secrets from the DCID.
// Per RFC 9001 §5.2:
//
//	initial_secret = HKDF-Extract(salt, DCID)
//	client_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
//	server_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
//	key = HKDF-Expand-Label(secret, "quic key", "", 16)
//	iv  = HKDF-Expand-Label(secret, "quic iv", "", 12)
//	hp  = HKDF-Expand-Label(secret, "quic hp", "", 16)
func deriveQuicInitialSecrets(dcid []byte) (client, server quicInitialSecrets, err error) {
	// HKDF-Extract(salt, IKM=DCID)
	initialSecret, err := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	if err != nil {
		return client, server, err
	}

	derive := func(secret []byte) (quicInitialSecrets, error) {
		var s quicInitialSecrets
		key, err := hkdfExpandLabel(secret, "quic key", nil, 16)
		if err != nil {
			return s, err
		}
		copy(s.key[:], key)
		iv, err := hkdfExpandLabel(secret, "quic iv", nil, 12)
		if err != nil {
			return s, err
		}
		copy(s.iv[:], iv)
		hp, err := hkdfExpandLabel(secret, "quic hp", nil, 16)
		if err != nil {
			return s, err
		}
		copy(s.hpKey[:], hp)
		return s, nil
	}

	clientSecret, err := hkdfExpandLabel(initialSecret, "client in", nil, 32)
	if err != nil {
		return client, server, err
	}
	client, err = derive(clientSecret)
	if err != nil {
		return client, server, err
	}

	serverSecret, err := hkdfExpandLabel(initialSecret, "server in", nil, 32)
	if err != nil {
		return client, server, err
	}
	server, err = derive(serverSecret)
	if err != nil {
		return client, server, err
	}
	return client, server, nil
}

// Ensure crypto import is used (for future AEAD).
var _ = crypto.SHA256
