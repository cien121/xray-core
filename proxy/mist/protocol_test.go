package mist

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
)

// TestNonce24Layout verifies the coordinator-mandated construction:
// nonce24 = 0x00*12 || nonce12, for both frame counters and wire nonces.
func TestNonce24Layout(t *testing.T) {
	n := nonce24Parts(0x01020304, 0x00000000, 0x05060708)
	for i := 0; i < 12; i++ {
		if n[i] != 0 {
			t.Fatalf("byte %d: want 0x00, got 0x%02x", i, n[i])
		}
	}
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x05, 0x06, 0x07, 0x08}
	if !bytes.Equal(n[12:24], want) {
		t.Fatalf("tail mismatch: %x", n[12:24])
	}
	n12 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	w := nonce24Wire(n12)
	if !bytes.Equal(w[:12], make([]byte, 12)) || !bytes.Equal(w[12:24], n12) {
		t.Fatalf("wire pad mismatch: %x", w)
	}
}

// TestFrameRoundTrip seals a frame and decodes it back through readRawFrame.
func TestFrameRoundTrip(t *testing.T) {
	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello mist frame with padding")
	frame, err := sealFrame(key[:], 7, dirC2S, 42, 0x83, payload, 100)
	if err != nil {
		t.Fatal(err)
	}
	// LEN field sanity: total bytes after LEN = 2 + enc + pad.
	ln := int(binary.BigEndian.Uint16(frame[0:2]))
	if ln != len(frame)-2 {
		t.Fatalf("LEN=%d, frame len=%d", ln, len(frame))
	}
	if frame[2] != 100 || frame[3] != 0x83 {
		t.Fatalf("header bytes wrong: %x", frame[:4])
	}
	sidFlags, pt, err := readRawFrame(bytes.NewReader(frame), key[:], 7, dirC2S, 42)
	if err != nil {
		t.Fatal(err)
	}
	if sidFlags != 0x83 || !bytes.Equal(pt, payload) {
		t.Fatalf("roundtrip mismatch: flags=%x payload=%q", sidFlags, pt)
	}
	// Wrong counter must fail (nonce never reused / strict ordering).
	if _, _, err := readRawFrame(bytes.NewReader(frame), key[:], 7, dirC2S, 43); err == nil {
		t.Fatal("decrypt with wrong counter should fail")
	}
	// Tampered AAD (header) must fail.
	bad := bytes.Clone(frame)
	bad[3] ^= 0x01
	if _, _, err := readRawFrame(bytes.NewReader(bad), key[:], 7, dirC2S, 42); err == nil {
		t.Fatal("decrypt with tampered header should fail")
	}
	// Oversize frame must be rejected at seal time.
	huge := make([]byte, maxFrameLen)
	if _, err := sealFrame(key[:], 0, dirC2S, 0, 0, huge, 0); err == nil {
		t.Fatal("oversize frame should be rejected")
	}
}

// TestAuthHandshakeSymmetric simulates both ends of the SPEC 6 handshake
// (client buildAuth/parseAuthOK/derive vs a test-local server) and checks
// the derived session keys match cross-wise.
func TestAuthHandshakeSymmetric(t *testing.T) {
	var cid [16]byte
	var kAuth [32]byte
	if _, err := io.ReadFull(rand.Reader, cid[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(rand.Reader, kAuth[:]); err != nil {
		t.Fatal(err)
	}

	// --- client builds AUTH ---
	wire, cliPriv, cliPub, err := buildAuth(cid, kAuth, 1760000000)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != authWireLen {
		t.Fatalf("AUTH wire len=%d, want %d", len(wire), authWireLen)
	}

	// --- server parses AUTH (test-local server side) ---
	if !bytes.Equal(wire[:16], cid[:]) {
		t.Fatal("CID not in clear at head")
	}
	srvAead, err := newXAEAD(kAuth[:])
	if err != nil {
		t.Fatal(err)
	}
	nonce12 := wire[16:28]
	nn := nonce24Wire(nonce12)
	plain, err := srvAead.Open(nil, nn[:], wire[28:], cid[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != authPlainLen || plain[0] != protoVersion {
		t.Fatalf("bad AUTH plain: len=%d ver=%x", len(plain), plain[0])
	}
	cliEphPub := bytes.Clone(plain[9:41])

	// --- server derives keys and builds AUTH_OK ---
	srvPrivKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvPub := srvPrivKey.PublicKey().Bytes()
	srvPriv := srvPrivKey.Bytes()
	var connID [16]byte
	var resumeTok [32]byte
	if _, err := io.ReadFull(rand.Reader, connID[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(rand.Reader, resumeTok[:]); err != nil {
		t.Fatal(err)
	}
	srvKC2S, srvKS2C, err := deriveSessionKeys(srvPriv, cliEphPub, cliEphPub, srvPub)
	if err != nil {
		t.Fatal(err)
	}
	okPlain := make([]byte, authOKPlainLen)
	copy(okPlain[0:32], srvPub)
	copy(okPlain[32:48], connID[:])
	copy(okPlain[48:80], resumeTok[:])
	binary.BigEndian.PutUint64(okPlain[80:88], 1760000001)
	okPlain[88] = 16
	binary.BigEndian.PutUint16(okPlain[89:91], 30)
	okNonce12 := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, okNonce12); err != nil {
		t.Fatal(err)
	}
	okN := nonce24Wire(okNonce12)
	okCT := srvAead.Seal(nil, okN[:], okPlain, []byte(authOKAAD))
	okWire := append(append([]byte{}, okNonce12...), okCT...)
	if len(okWire) != authOKWireLen {
		t.Fatalf("AUTH_OK wire len=%d, want %d", len(okWire), authOKWireLen)
	}

	// --- client parses AUTH_OK and derives ---
	info, err := parseAuthOK(okWire, kAuth)
	if err != nil {
		t.Fatal(err)
	}
	if info.connID != connID || info.resumeTok != resumeTok {
		t.Fatal("connID/resumeTok mismatch")
	}
	if info.heartbeatSec != 30 || info.maxStreams != 16 {
		t.Fatalf("params mismatch: hb=%d max=%d", info.heartbeatSec, info.maxStreams)
	}
	cliKC2S, cliKS2C, err := deriveSessionKeys(cliPriv, info.serverEphPub[:], cliPub, info.serverEphPub[:])
	if err != nil {
		t.Fatal(err)
	}
	if cliKC2S != srvKC2S || cliKS2C != srvKS2C {
		t.Fatal("session keys do not match between client and server")
	}
	// Cross-direction check: what client encrypts, server decrypts.
	ct := mustSealFrame(t, cliKC2S[:], 0, dirC2S, 0, 0x01, []byte("ping"), 0)
	_, pt, err := readRawFrame(bytes.NewReader(ct), srvKC2S[:], 0, dirC2S, 0)
	if err != nil || string(pt) != "ping" {
		t.Fatalf("cross-direction frame failed: %v %q", err, pt)
	}

	// Wrong K_auth must fail AUTH_OK parsing.
	var badAuth [32]byte
	if _, err := parseAuthOK(okWire, badAuth); err == nil {
		t.Fatal("AUTH_OK with wrong key should fail")
	}
}

func mustSealFrame(t *testing.T, key []byte, epoch, dir, ctr uint32, flags byte, pt []byte, pad int) []byte {
	t.Helper()
	f, err := sealFrame(key, epoch, dir, ctr, flags, pt, pad)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestResumeBodyLayout checks the RESUME plaintext layout (SPEC 10.2).
func TestResumeBodyLayout(t *testing.T) {
	var cid [16]byte
	var tok [32]byte
	body := buildResumeBody(cid, tok, 3)
	if len(body) != 1+16+32+4+4 {
		t.Fatalf("resume body len=%d", len(body))
	}
	if body[0] != ctrlResume {
		t.Fatalf("type=%x", body[0])
	}
	if binary.BigEndian.Uint32(body[49:53]) != 3 {
		t.Fatalf("epoch=%x", body[49:53])
	}
	if !bytes.Equal(body[53:57], make([]byte, 4)) {
		t.Fatal("RSVD not zero")
	}
}

// TestControlMessageOpcodes guards the 9.6 message table values.
func TestControlMessageOpcodes(t *testing.T) {
	if ctrlPing != 0x05 || ctrlPong != 0x06 || ctrlWindowUpdate != 0x04 ||
		ctrlResume != 0x07 || ctrlResumeOK != 0x08 || ctrlCloseSession != 0x09 ||
		ctrlUDPAssocReq != 0x03 {
		t.Fatal("control opcode drift from SPEC 9.6")
	}
}
