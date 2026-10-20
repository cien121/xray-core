// Package mist implements the client side of the Mist v0.1 proxy protocol
// as a native Xray outbound. Wire spec: ~/workspace/mist-protocol/SPEC.md.
//
// AEAD is XChaCha20-Poly1305 everywhere (chacha20poly1305.NewX). The
// spec's 12-byte nonce — epoch(4,BE)|dir(4)|ctr(4,BE) for frames, or the
// 12-byte明文 nonce on the wire for AUTH/AUTH_OK — is zero-padded to 24
// bytes before being handed to XChaCha20-Poly1305:
//
//	nonce24 = 0x00*12 || nonce12
//
// This applies to every AEAD call: frame payloads, AUTH, AUTH_OK, RESUME.
package mist

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Protocol constants (SPEC appendix B.1).
const (
	protoVersion byte = 0x01
	maxFrameLen       = 16384 // max LEN value: bytes after the LEN field itself

	authWireLen   = 89  // CID(16) + NONCE(12) + CT(61)
	authOKWireLen = 124 // NONCE(12) + CT(112)

	authPlainLen   = 45 // VER(1)+TS(8)+EPH_PUB(32)+FEAT(1)+RSVD(3)
	authOKPlainLen = 96 // SRV_EPH_PUB(32)+CONN_ID(16)+RESUME_TOK(32)+SRV_TS(8)+MAX_STREAMS(1)+HB(2)+RSVD(5)

	dirC2S uint32 = 0x00000000
	dirS2C uint32 = 0xFFFFFFFF

	authOKAAD = "mist-v0.1-auth-ok"
	kdfInfo   = "mist-v0.1/session"
)

// Frame flag bits: high 4 bits of the SID/F byte (SPEC 7.1).
const (
	flagSYN byte = 0x80
	flagFIN byte = 0x40
	flagRST byte = 0x20
)

// Control stream (SID=0) message types (SPEC 9.6).
const (
	ctrlConnectReq   byte = 0x01
	ctrlConnectResp  byte = 0x02
	ctrlUDPAssocReq  byte = 0x03
	ctrlWindowUpdate byte = 0x04
	ctrlPing         byte = 0x05
	ctrlPong         byte = 0x06
	ctrlResume       byte = 0x07
	ctrlResumeOK     byte = 0x08
	ctrlCloseSession byte = 0x09
)

// CONNECT result codes (SPEC 9.2).
const (
	codeSuccess            byte = 0x00
	codeNetUnreachable     byte = 0x01
	codeConnRefused        byte = 0x02
	codeTimeout            byte = 0x03
	codeUnsupportedAddress byte = 0x04
)

// Shaping defaults (SPEC appendix B.2). Only the heavy-packet count is
// configurable in v0.1; the rest follow the appendix defaults.
const (
	defaultShapingPadMin   = 64
	defaultShapingPadMax   = 512
	defaultShapingJitterMs = 15
	defaultHeavyPackets    = 32
	defaultHeartbeatSec    = 30
)

// nonce24Parts builds the 24-byte XChaCha20 nonce from the spec's 12-byte
// nonce parts: nonce24 = 0x00*12 || epoch(4,BE) || dir(4) || ctr(4,BE).
func nonce24Parts(epoch, dir, ctr uint32) [24]byte {
	var n [24]byte
	binary.BigEndian.PutUint32(n[12:16], epoch)
	binary.BigEndian.PutUint32(n[16:20], dir)
	binary.BigEndian.PutUint32(n[20:24], ctr)
	return n
}

// nonce24Wire pads a 12-byte明文 wire nonce (AUTH / AUTH_OK) to 24 bytes:
// nonce24 = 0x00*12 || nonce12.
func nonce24Wire(nonce12 []byte) [24]byte {
	var n [24]byte
	copy(n[12:24], nonce12)
	return n
}

func newXAEAD(key []byte) (aead cipher.AEAD, err error) {
	aead, err = chacha20poly1305.NewX(key)
	if err != nil {
		return nil, errors.New("mist: invalid AEAD key").Base(err)
	}
	return aead, nil
}

// sealFrame encrypts one Mist frame (SPEC 7).
// LEN = 2 + (len(plaintext)+16 tag) + padLen must be <= 16384.
func sealFrame(key []byte, epoch, dir, ctr uint32, sidFlags byte, plaintext []byte, padLen int) ([]byte, error) {
	if padLen < 0 || padLen > 255 {
		return nil, errors.New("mist: bad padLen")
	}
	aead, err := newXAEAD(key)
	if err != nil {
		return nil, err
	}
	encLen := len(plaintext) + aead.Overhead()
	total := 2 + encLen + padLen
	if total > maxFrameLen {
		return nil, errors.New("mist: frame too large: ", total)
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint16(header[0:2], uint16(total))
	header[2] = byte(padLen)
	header[3] = sidFlags
	nonce := nonce24Parts(epoch, dir, ctr)
	enc := aead.Seal(nil, nonce[:], plaintext, header)
	frame := make([]byte, 0, 4+len(enc)+padLen)
	frame = append(frame, header...)
	frame = append(frame, enc...)
	if padLen > 0 {
		padding := make([]byte, padLen)
		if _, err := io.ReadFull(rand.Reader, padding); err != nil {
			return nil, errors.New("mist: rand failed").Base(err)
		}
		frame = append(frame, padding...)
	}
	return frame, nil
}

// openFrame decrypts one Mist frame payload. header must be the 4 raw
// header bytes (used as AAD); enc is the ciphertext slice (without padding).
func openFrame(key []byte, epoch, dir, ctr uint32, header, enc []byte) ([]byte, error) {
	aead, err := newXAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := nonce24Parts(epoch, dir, ctr)
	pt, err := aead.Open(nil, nonce[:], enc, header)
	if err != nil {
		return nil, errors.New("mist: frame AEAD decrypt failed")
	}
	return pt, nil
}

// readRawFrame reads one full frame from r and decrypts it with the given
// nonce parameters. Returns the SID/F byte and the plaintext payload.
func readRawFrame(r io.Reader, key []byte, epoch, dir, ctr uint32) (byte, []byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	ln := int(binary.BigEndian.Uint16(header[0:2]))
	if ln < 2 || ln > maxFrameLen {
		return 0, nil, errors.New("mist: bad frame length: ", ln)
	}
	// LEN counts bytes after the LEN field itself; the 4-byte header is
	// already consumed, so ln-2 bytes remain (PLEN+SID/F | ENC | PADDING).
	// LEN counts bytes after the LEN field itself; the 4-byte header
	// ([LEN|PLEN|SIDF]) is already consumed, so ln-2 bytes remain:
	// ENC_PAYLOAD | PADDING. (SPEC 7.1 diagram; PLEN/SIDF live in the
	// header, and the 4-byte header is the AEAD AAD.)
	body := make([]byte, ln-2)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	padLen := int(header[2])
	sidFlags := header[3]
	encLen := len(body) - padLen
	if encLen < chacha20poly1305.Overhead {
		return 0, nil, errors.New("mist: frame too short for AEAD tag")
	}
	pt, err := openFrame(key, epoch, dir, ctr, header, body[:encLen])
	if err != nil {
		return 0, nil, err
	}
	return sidFlags, pt, nil
}

// buildAuth constructs the 89-byte AUTH message (SPEC 6.2):
// [CID(16)明文][NONCE(12)明文][CT], CT = XChaCha20(K_auth, nonce24(nonce12),
// VER|TS|EPH_PUB|FEAT|RSVD, aad=CID). Returns the wire bytes and the
// ephemeral private key (caller must zero it after KDF).
func buildAuth(cid [16]byte, kAuth [32]byte, ts int64) (wire []byte, ephPriv, ephPub []byte, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, errors.New("mist: x25519 keygen failed").Base(err)
	}
	pub := priv.PublicKey().Bytes() // 32 bytes
	ephPriv = priv.Bytes()          // copy; zeroed by deriveSessionKeys
	ephPub = bytes.Clone(pub)
	plain := make([]byte, authPlainLen)
	plain[0] = protoVersion
	binary.BigEndian.PutUint64(plain[1:9], uint64(ts))
	copy(plain[9:41], pub)
	plain[41] = 0x03 // FEAT bit0=migration, bit1=UDP relay
	// plain[42:45] RSVD = 0

	nonce12 := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce12); err != nil {
		zeroBytes(ephPriv)
		return nil, nil, nil, errors.New("mist: rand failed").Base(err)
	}
	aead, err := newXAEAD(kAuth[:])
	if err != nil {
		zeroBytes(ephPriv)
		return nil, nil, nil, err
	}
	nonce := nonce24Wire(nonce12)
	ct := aead.Seal(nil, nonce[:], plain, cid[:])
	wire = make([]byte, 0, authWireLen)
	wire = append(wire, cid[:]...)
	wire = append(wire, nonce12...)
	wire = append(wire, ct...)
	return wire, ephPriv, ephPub, nil
}

// authOKInfo holds the parsed AUTH_OK payload (SPEC 6.3).
type authOKInfo struct {
	serverEphPub [32]byte
	connID       [16]byte
	resumeTok    [32]byte
	maxStreams   byte
	heartbeatSec uint16
}

// parseAuthOK decrypts and parses the 124-byte AUTH_OK message:
// [NONCE(12)明文][CT], CT = XChaCha20(K_auth, nonce24(nonce12), plain,
// aad="mist-v0.1-auth-ok").
func parseAuthOK(wire []byte, kAuth [32]byte) (*authOKInfo, error) {
	if len(wire) != authOKWireLen {
		return nil, errors.New("mist: AUTH_OK length mismatch: ", len(wire))
	}
	nonce12 := wire[0:12]
	ct := wire[12:]
	aead, err := newXAEAD(kAuth[:])
	if err != nil {
		return nil, err
	}
	nonce := nonce24Wire(nonce12)
	pt, err := aead.Open(nil, nonce[:], ct, []byte(authOKAAD))
	if err != nil {
		return nil, errors.New("mist: AUTH_OK decrypt failed: bad client id/key or not a Mist server")
	}
	if len(pt) != authOKPlainLen {
		return nil, errors.New("mist: AUTH_OK plaintext length mismatch")
	}
	info := &authOKInfo{}
	copy(info.serverEphPub[:], pt[0:32])
	copy(info.connID[:], pt[32:48])
	copy(info.resumeTok[:], pt[48:80])
	// pt[80:88] SRV_TS, informational only
	info.maxStreams = pt[88]
	info.heartbeatSec = binary.BigEndian.Uint16(pt[89:91])
	// pt[91:96] RSVD
	return info, nil
}

// deriveSessionKeys runs the SPEC 6.4 KDF:
// shared = X25519(ephPriv, peerEphPub); salt = clientEphPub|serverEphPub;
// okm = HKDF-SHA256(salt, shared, "mist-v0.1/session", 64);
// kC2S = okm[0:32], kS2C = okm[32:64]. ephPriv is zeroed before return.
//
// Client calls with (cliPriv, srvPub, cliPub, srvPub); the server calls
// with (srvPriv, cliPub, cliPub, srvPub).
func deriveSessionKeys(ephPriv, peerEphPub, clientEphPub, serverEphPub []byte) (kC2S, kS2C [32]byte, err error) {
	defer zeroBytes(ephPriv)
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(ephPriv)
	if err != nil {
		return kC2S, kS2C, errors.New("mist: bad ephemeral private key").Base(err)
	}
	pub, err := curve.NewPublicKey(peerEphPub)
	if err != nil {
		return kC2S, kS2C, errors.New("mist: bad peer ephemeral public key").Base(err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return kC2S, kS2C, errors.New("mist: x25519 shared secret failed").Base(err)
	}
	defer zeroBytes(shared)
	salt := make([]byte, 0, 64)
	salt = append(salt, clientEphPub...)
	salt = append(salt, serverEphPub...)
	r := hkdf.New(sha256.New, shared, salt, []byte(kdfInfo))
	okm := make([]byte, 64)
	if _, err := io.ReadFull(r, okm); err != nil {
		return kC2S, kS2C, errors.New("mist: hkdf failed").Base(err)
	}
	defer zeroBytes(okm)
	copy(kC2S[:], okm[0:32])
	copy(kS2C[:], okm[32:64])
	return kC2S, kS2C, nil
}

// buildResumeBody builds the RESUME plaintext (SPEC 10.2):
// [TYPE=0x07][CONN_ID(16)][RESUME_TOK(32)][newEpoch(4,BE)][RSVD(4)].
func buildResumeBody(connID [16]byte, resumeTok [32]byte, newEpoch uint32) []byte {
	body := make([]byte, 1+16+32+4+4)
	body[0] = ctrlResume
	copy(body[1:17], connID[:])
	copy(body[17:49], resumeTok[:])
	binary.BigEndian.PutUint32(body[49:53], newEpoch)
	return body
}

// encodeAddrPort encodes [ATYP][ADDR][PORT(2,BE)] (SPEC 9.2).
// ATYP: 0x01=IPv4, 0x03=domain, 0x04=IPv6.
func encodeAddrPort(addrBytes []byte, atyp byte, port uint16) []byte {
	out := make([]byte, 0, len(addrBytes)+4)
	out = append(out, atyp)
	out = append(out, addrBytes...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	out = append(out, pb[:]...)
	return out
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
