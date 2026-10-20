package mist

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// authWindowSec is the maximum accepted AUTH timestamp skew (SPEC 6.2:
// the server checks |now - TS| against its window; mistcore used 60s).
const authWindowSec = 60

// NonceCache records AUTH wire nonces to block replays (SPEC G9).
// Ported from mist-protocol/mistcore/replay.go; entries expire after ttl
// and cleanup runs lazily on insert.
type NonceCache struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[[12]byte]int64 // nonce -> expiry unix nano
}

// NewNonceCache creates a cache with the given entry TTL.
func NewNonceCache(ttl time.Duration) *NonceCache {
	return &NonceCache{ttl: ttl, m: make(map[[12]byte]int64)}
}

// Seen reports whether nonce was already recorded. If not, it records it
// and returns false. Safe for concurrent use.
func (c *NonceCache) Seen(nonce [12]byte) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.m[nonce]; ok && exp > now.UnixNano() {
		return true
	}
	if len(c.m) > 65536 {
		for k, exp := range c.m {
			if exp <= now.UnixNano() {
				delete(c.m, k)
			}
		}
	}
	c.m[nonce] = now.Add(c.ttl).UnixNano()
	return false
}

// authResult is a successfully validated AUTH message (server side).
type authResult struct {
	cid    [16]byte
	ephPub [32]byte
	ts     int64
	feat   byte
}

// parseAuth validates an 89-byte AUTH message (SPEC 6.2, six steps).
// lookup resolves CID -> K_auth. On ANY failure it returns an error; the
// caller must close the connection silently and never signal the reason
// (anti-probing, SPEC B.3).
func parseAuth(wire []byte, lookup func(cid [16]byte) ([32]byte, bool), cache *NonceCache) (*authResult, error) {
	if len(wire) != authWireLen {
		return nil, errors.New("mist: bad AUTH length")
	}
	var cid [16]byte
	copy(cid[:], wire[0:16])
	nonce12 := wire[16:28]
	ct := wire[28:]

	kAuth, ok := lookup(cid)
	if !ok {
		return nil, errors.New("mist: unknown client id")
	}
	aead, err := newXAEAD(kAuth[:])
	if err != nil {
		return nil, err
	}
	nonce := nonce24Wire(nonce12)
	pt, err := aead.Open(nil, nonce[:], ct, cid[:])
	if err != nil || len(pt) != authPlainLen {
		return nil, errors.New("mist: AUTH decrypt failed")
	}
	if pt[0] != protoVersion {
		return nil, errors.New("mist: AUTH version mismatch")
	}
	ts := int64(binary.BigEndian.Uint64(pt[1:9]))
	if d := time.Now().Unix() - ts; d > authWindowSec || d < -authWindowSec {
		return nil, errors.New("mist: AUTH timestamp outside window")
	}
	var n12 [12]byte
	copy(n12[:], nonce12)
	if cache.Seen(n12) {
		return nil, errors.New("mist: replayed AUTH nonce")
	}
	res := &authResult{ts: ts, feat: pt[41]}
	res.cid = cid
	copy(res.ephPub[:], pt[9:41])
	return res, nil
}

// buildAuthOK constructs the 124-byte AUTH_OK message (SPEC 6.3, server
// side): [NONCE(12)明文][CT], CT = XChaCha20(K_auth, nonce24(nonce12),
// plain, aad="mist-v0.1-auth-ok").
func buildAuthOK(kAuth [32]byte, srvEphPub [32]byte, connID [16]byte, resumeTok [32]byte, maxStreams byte, hbSec uint16) ([]byte, error) {
	plain := make([]byte, authOKPlainLen)
	copy(plain[0:32], srvEphPub[:])
	copy(plain[32:48], connID[:])
	copy(plain[48:80], resumeTok[:])
	binary.BigEndian.PutUint64(plain[80:88], uint64(time.Now().Unix()))
	plain[88] = maxStreams
	binary.BigEndian.PutUint16(plain[89:91], hbSec)
	// plain[91:96] RSVD = 0

	nonce12 := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce12); err != nil {
		return nil, errors.New("mist: rand failed").Base(err)
	}
	aead, err := newXAEAD(kAuth[:])
	if err != nil {
		return nil, err
	}
	nonce := nonce24Wire(nonce12)
	ct := aead.Seal(nil, nonce[:], plain, []byte(authOKAAD))
	wire := make([]byte, 0, authOKWireLen)
	wire = append(wire, nonce12...)
	wire = append(wire, ct...)
	return wire, nil
}

// serverEphemeral generates a fresh X25519 ephemeral keypair for the
// AUTH_OK handshake. The private key must be zeroed after KDF (the caller
// does this via deriveSessionKeys, which zeroes ephPriv).
func serverEphemeral() (priv, pub [32]byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return priv, pub, errors.New("mist: x25519 keygen failed").Base(err)
	}
	copy(priv[:], k.Bytes())
	copy(pub[:], k.PublicKey().Bytes())
	return priv, pub, nil
}
