// quic_initial_crypto_test.go: Tests for QUIC Initial key derivation.
package mist

import (
	"bytes"
	"testing"
)

func TestHKDFExpandLabelDeterministic(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	out1, err := hkdfExpandLabel(secret, "quic key", nil, 16)
	if err != nil {
		t.Fatalf("hkdfExpandLabel: %v", err)
	}
	out2, err := hkdfExpandLabel(secret, "quic key", nil, 16)
	if err != nil {
		t.Fatalf("hkdfExpandLabel: %v", err)
	}
	if !bytes.Equal(out1, out2) {
		t.Fatal("HKDF-Expand-Label not deterministic")
	}
	if len(out1) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(out1))
	}
	// Different labels give different outputs.
	out3, err := hkdfExpandLabel(secret, "quic iv", nil, 12)
	if err != nil {
		t.Fatalf("hkdfExpandLabel: %v", err)
	}
	if bytes.Equal(out1[:12], out3) {
		t.Fatal("different labels gave same output")
	}
}

func TestDeriveQuicInitialSecrets(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	client1, server1, err := deriveQuicInitialSecrets(dcid)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	client2, server2, err := deriveQuicInitialSecrets(dcid)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	// Deterministic.
	if client1 != client2 || server1 != server2 {
		t.Fatal("derivation not deterministic")
	}
	// Client != server.
	if client1 == server1 {
		t.Fatal("client and server secrets are equal")
	}
	// Keys are non-zero.
	var zero16 [16]byte
	var zero12 [12]byte
	if client1.key == zero16 || client1.iv == zero12 || client1.hpKey == zero16 {
		t.Fatal("client secrets contain zero key/iv/hp")
	}
	if server1.key == zero16 || server1.iv == zero12 || server1.hpKey == zero16 {
		t.Fatal("server secrets contain zero key/iv/hp")
	}
	// Different DCID gives different secrets.
	dcid2 := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	client3, _, err := deriveQuicInitialSecrets(dcid2)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if client1 == client3 {
		t.Fatal("different DCID gave same secrets")
	}
}
