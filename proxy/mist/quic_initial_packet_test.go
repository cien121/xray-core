// quic_initial_packet_test.go: Tests for QUIC Initial packet encode/decode.
package mist

import (
	"bytes"
	"testing"
)

func TestQuicVarintRoundtrip(t *testing.T) {
	cases := []uint64{0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903}
	for _, v := range cases {
		enc := encodeQuicVarint(v)
		dec, n, err := decodeQuicVarint(enc)
		if err != nil {
			t.Fatalf("decode %d: %v", v, err)
		}
		if dec != v {
			t.Fatalf("varint %d decoded as %d", v, dec)
		}
		if n != len(enc) {
			t.Fatalf("varint %d: consumed %d, encoded %d", v, n, len(enc))
		}
	}
}

func TestQuicInitialSealOpenRoundtrip(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	clientSecrets, serverSecrets, err := deriveQuicInitialSecrets(dcid)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	// Client seals with client secrets; server opens with client secrets
	// (server uses the client's Initial keys to decrypt C2S Initial).
	payload := encodeCryptoFrame(0, []byte("test-auth-payload-12345"))
	packet, err := sealQuicInitial(dcid, scid, nil, 1, clientSecrets, payload)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Server side: derive from DCID, open with CLIENT secrets (C2S direction).
	clientSecrets2, _, err := deriveQuicInitialSecrets(dcid)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	_ = serverSecrets
	hdr, plaintext, err := openQuicInitial(packet, clientSecrets2)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(hdr.dcid, dcid) {
		t.Fatalf("dcid mismatch: %x vs %x", hdr.dcid, dcid)
	}
	if !bytes.Equal(hdr.scid, scid) {
		t.Fatalf("scid mismatch: %x vs %x", hdr.scid, scid)
	}
	if hdr.packetNum != 1 {
		t.Fatalf("packetNum mismatch: %d", hdr.packetNum)
	}
	if !bytes.Equal(plaintext, payload) {
		t.Fatalf("payload mismatch: %x vs %x", plaintext, payload)
	}
	// Decode CRYPTO frame.
	off, data, _, err := decodeCryptoFrame(plaintext)
	if err != nil {
		t.Fatalf("decode CRYPTO: %v", err)
	}
	if off != 0 {
		t.Fatalf("CRYPTO offset %d", off)
	}
	if string(data) != "test-auth-payload-12345" {
		t.Fatalf("CRYPTO data mismatch: %s", data)
	}
}

func TestQuicInitialTamperFails(t *testing.T) {
	dcid := []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}
	scid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	clientSecrets, _, err := deriveQuicInitialSecrets(dcid)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	payload := encodeCryptoFrame(0, []byte("hello"))
	packet, err := sealQuicInitial(dcid, scid, nil, 1, clientSecrets, payload)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Flip a byte in the ciphertext.
	tampered := make([]byte, len(packet))
	copy(tampered, packet)
	tampered[len(tampered)-1] ^= 0xff
	_, _, err = openQuicInitial(tampered, clientSecrets)
	if err == nil {
		t.Fatal("tampered packet decrypted successfully (should fail)")
	}
	// Wrong DCID (different keys) fails.
	dcid2 := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	clientSecrets2, _, err := deriveQuicInitialSecrets(dcid2)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	_, _, err = openQuicInitial(packet, clientSecrets2)
	if err == nil {
		t.Fatal("wrong-key packet decrypted successfully (should fail)")
	}
}
