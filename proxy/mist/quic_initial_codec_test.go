// quic_initial_codec_test.go: Tests for QUICInitialCodec (Phase 0).
package mist

import (
	"bytes"
	"testing"
)

func TestQUICInitialCodecRoundtrip(t *testing.T) {
	codec := &QUICInitialCodec{}
	var dcid, scid [8]byte
	for i := range dcid {
		dcid[i] = byte(0x10 + i)
		scid[i] = byte(0x20 + i)
	}
	// C2S: client seals AUTH, server opens.
	authPayload := []byte("test-auth-data-12345")
	packet, err := codec.SealInitial(authPayload, dcid, scid, 1)
	if err != nil {
		t.Fatalf("SealInitial: %v", err)
	}
	opened, outDCID, outSCID, pn, err := codec.OpenInitial(packet)
	if err != nil {
		t.Fatalf("OpenInitial: %v", err)
	}
	if !bytes.Equal(opened, authPayload) {
		t.Fatalf("AUTH mismatch: %x vs %x", opened, authPayload)
	}
	if outDCID != dcid {
		t.Fatalf("DCID mismatch: %x vs %x", outDCID, dcid)
	}
	if outSCID != scid {
		t.Fatalf("SCID mismatch: %x vs %x", outSCID, scid)
	}
	if pn != 1 {
		t.Fatalf("packetNum mismatch: %d", pn)
	}
	// S2C: server seals AUTH_OK, client opens.
	authOK := []byte("test-auth-ok-67890")
	respPacket, err := codec.SealInitialResponse(authOK, dcid, scid, 2)
	if err != nil {
		t.Fatalf("SealInitialResponse: %v", err)
	}
	openedOK, _, _, pn2, err := codec.OpenInitialResponse(respPacket)
	if err != nil {
		t.Fatalf("OpenInitialResponse: %v", err)
	}
	if !bytes.Equal(openedOK, authOK) {
		t.Fatalf("AUTH_OK mismatch: %x vs %x", openedOK, authOK)
	}
	if pn2 != 2 {
		t.Fatalf("packetNum mismatch: %d", pn2)
	}
}

func TestQUICInitialCodecCrossDirectionFails(t *testing.T) {
	codec := &QUICInitialCodec{}
	var dcid, scid [8]byte
	for i := range dcid {
		dcid[i] = byte(0x10 + i)
		scid[i] = byte(0x20 + i)
	}
	// C2S packet cannot be opened as S2C response (different keys).
	packet, err := codec.SealInitial([]byte("auth"), dcid, scid, 1)
	if err != nil {
		t.Fatalf("SealInitial: %v", err)
	}
	_, _, _, _, err = codec.OpenInitialResponse(packet)
	if err == nil {
		t.Fatal("C2S packet opened as S2C response (should fail)")
	}
}
