package mist

import (
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Nonce direction words (SPEC 7.2), shared with UDP crypto.
const (
	udpDirC2S uint32 = 0x00000000
	udpDirS2C uint32 = 0xFFFFFFFF
)

// deriveUDPSessionKeys derives the C2S/S2C session keys from the X25519
// shared secret (SPEC 6.4). Same KDF as the TCP version.
func deriveUDPSessionKeys(clientEphPub, serverEphPub, shared [32]byte) (kC2S, kS2C [32]byte) {
	salt := make([]byte, 0, 64)
	salt = append(salt, clientEphPub[:]...)
	salt = append(salt, serverEphPub[:]...)
	okm := make([]byte, 64)
	kdf := hkdf.New(sha256.New, shared[:], salt, []byte("mist-v0.1/session"))
	if _, err := kdf.Read(okm); err != nil {
		panic("mist: hkdf read failed: " + err.Error())
	}
	copy(kC2S[:], okm[0:32])
	copy(kS2C[:], okm[32:64])
	for i := range okm {
		okm[i] = 0
	}
	return kC2S, kS2C
}

// udpX25519Shared computes X25519(priv, pub).
func udpX25519Shared(priv, pub *[32]byte) ([32]byte, error) {
	var out [32]byte
	s, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return out, err
	}
	copy(out[:], s)
	for i := range s {
		s[i] = 0
	}
	return out, nil
}

// udpX25519Keypair generates an ephemeral X25519 keypair.
func udpX25519Keypair() (priv, pub [32]byte, err error) {
	p := make([]byte, 32)
	if _, err := rand.Read(p); err != nil {
		return priv, pub, err
	}
	q, err := curve25519.X25519(p, curve25519.Basepoint)
	if err != nil {
		return priv, pub, err
	}
	copy(priv[:], p)
	copy(pub[:], q)
	for i := range p {
		p[i] = 0
	}
	return priv, pub, nil
}
