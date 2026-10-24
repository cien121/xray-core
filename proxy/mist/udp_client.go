package mist

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// UDPClient is the UDP transport client for the Mist protocol.
// It performs the §5.1 handshake over UDP and returns a UDPSession
// ready for encrypted frame exchange.
type UDPClient struct {
	serverAddr *net.UDPAddr
	cid        [16]byte
	kAuth      [32]byte
	codec      InitialCodec
	// dial creates the UDP socket. Nil means net.DialUDP to serverAddr.
	// Tests inject an in-memory pipe here.
	dial func() (UDPPacketConn, error)
}

// NewUDPClient creates a UDP client for the given server.
func NewUDPClient(serverAddr *net.UDPAddr, cid [16]byte, kAuth [32]byte) *UDPClient {
	return &UDPClient{
		serverAddr: serverAddr,
		cid:        cid,
		kAuth:      kAuth,
		codec:      &QUICInitialCodec{},
	}
}

// WithDial overrides the socket creation (for tests).
func (c *UDPClient) WithDial(dial func() (UDPPacketConn, error)) *UDPClient {
	c.dial = dial
	return c
}

func (c *UDPClient) getConn() (UDPPacketConn, error) {
	if c.dial != nil {
		return c.dial()
	}
	// Unconnected socket; all I/O uses explicit addresses via
	// WriteToUDP/ReadFromUDP. (A connected socket from net.DialUDP
	// rejects WriteToUDP with an address.)
	return net.ListenUDP("udp", nil)
}

// Handshake performs the UDP handshake (§5.1):
//  1. Build AUTH: [HANDSHAKE_CID(16)][NONCE(24)][CIPHERTEXT]
//     CIPHERTEXT = AEAD(K_auth, plaintext, aad=HANDSHAKE_CID)
//     plaintext = [VER(1)=0x02][TS(8)][EPH_PUB(32)][FEAT(1)][MODE(1)][RSVD(2)]
//  2. Send Initial packet, wait for AUTH_OK response (with retransmit).
//  3. Derive session keys, create UDPSession.
//
// Returns the session and the packet conn (caller owns the conn and must Close it).
// Use session.SealPacket/OpenPacket for crypto; do I/O on conn directly.
func (c *UDPClient) Handshake() (*UDPSession, UDPPacketConn, error) {
	conn, err := c.getConn()
	if err != nil {
		return nil, nil, errors.New("mist udp: dial failed").Base(err)
	}
	// Keep conn open; session owns it after handshake.
	// For Phase 3, we do a simple blocking handshake here.

	// Generate ephemeral keypair.
	ephPriv, ephPub, err := udpX25519Keypair()
	if err != nil {
		return nil, nil, errors.New("mist udp: keypair failed").Base(err)
	}

	// Build AUTH plaintext.
	// [VER(1)][TS(8)][EPH_PUB(32)][FEAT(1)][MODE(1)][RSVD(2)] = 45 bytes
	authPlain := make([]byte, 45)
	authPlain[0] = 0x02 // VER = UDP
	binary.BigEndian.PutUint64(authPlain[1:9], uint64(time.Now().Unix()))
	copy(authPlain[9:41], ephPub[:])
	// FEAT=0, MODE=0, RSVD=0 (already zero)

	// Encrypt with K_auth.
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		conn.Close()
		return nil, nil, errors.New("mist udp: nonce failed").Base(err)
	}
	// HANDSHAKE_CID = HMAC-SHA256(K_auth, NONCE)[0:16]
	mac := hmac.New(sha256.New, c.kAuth[:])
	mac.Write(nonce[:])
	var handshakeCID [16]byte
	copy(handshakeCID[:], mac.Sum(nil)[:16])

	aead, err := udpAEAD(&c.kAuth)
	if err != nil {
		conn.Close()
		return nil, nil, errors.New("mist udp: aead failed").Base(err)
	}
	ciphertext := aead.Seal(nil, nonce[:], authPlain, handshakeCID[:])

	// Wire: [HANDSHAKE_CID(16)][NONCE(24)][CIPHERTEXT]
	authWire := make([]byte, 0, 16+24+len(ciphertext))
	authWire = append(authWire, handshakeCID[:]...)
	authWire = append(authWire, nonce[:]...)
	authWire = append(authWire, ciphertext...)

	// Generate SCID for this handshake attempt.
	var scid [8]byte
	if _, err := rand.Read(scid[:]); err != nil {
		conn.Close()
		return nil, nil, errors.New("mist udp: scid failed").Base(err)
	}
	// DCID: server will fill in; use zeros for Initial.
	var dcid [8]byte

	initial, err := c.codec.SealInitial(authWire, dcid, scid, 0)
	if err != nil {
		conn.Close()
		return nil, nil, errors.New("mist udp: seal initial failed").Base(err)
	}

	// Send with retransmit (new NONCE/SCID per attempt per §7.2 Scheme A).
	// Simplified: 4 attempts, 1s timeout each.
	var response []byte
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			// New NONCE and SCID per retransmit.
			if _, err := rand.Read(nonce[:]); err != nil {
				break
			}
			if _, err := rand.Read(scid[:]); err != nil {
				break
			}
			mac := hmac.New(sha256.New, c.kAuth[:])
			mac.Write(nonce[:])
			copy(handshakeCID[:], mac.Sum(nil)[:16])
			ciphertext = aead.Seal(nil, nonce[:], authPlain, handshakeCID[:])
			authWire = authWire[:0]
			authWire = append(authWire, handshakeCID[:]...)
			authWire = append(authWire, nonce[:]...)
			authWire = append(authWire, ciphertext...)
			initial, err = c.codec.SealInitial(authWire, dcid, scid, 0)
			if err != nil {
				break
			}
		}
		if _, err := conn.WriteToUDP(initial, c.serverAddr); err != nil {
			conn.Close()
			return nil, nil, errors.New("mist udp: send initial failed").Base(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 2048)
		n, _, err := conn.ReadFromUDP(buf)
		if err == nil {
			response = buf[:n]
			break
		}
		// Timeout: retry.
	}
	if response == nil {
		conn.Close()
		return nil, nil, errors.New("mist udp: handshake timeout")
	}

	// Parse AUTH_OK response.
	authOKWire, respDCID, _, _, err := c.codec.OpenInitialResponse(response)
	if err != nil {
		conn.Close()
		return nil, nil, errors.New("mist udp: parse auth_ok failed").Base(err)
	}
	// Verify DCID matches our SCID (Scheme A: server echoes client's SCID).
	if respDCID != scid {
		conn.Close()
		return nil, nil, errors.New("mist udp: DCID mismatch")
	 }
	// authOKWire = [NONCE(24)][CIPHERTEXT]
	if len(authOKWire) < 24+16 {
		conn.Close()
		return nil, nil, errors.New("mist udp: auth_ok too short")
	}
	var okNonce [24]byte
	copy(okNonce[:], authOKWire[:24])
	okCipher := authOKWire[24:]
	okPlain, err := aead.Open(nil, okNonce[:], okCipher, nil)
	if err != nil {
		conn.Close()
		return nil, nil, errors.New("mist udp: auth_ok decrypt failed").Base(err)
	}
	// [SRV_EPH_PUB(32)][CONN_ID(16)]
	if len(okPlain) < 48 {
		conn.Close()
		return nil, nil, errors.New("mist udp: auth_ok plain too short")
	}
	var srvEphPub [32]byte
	copy(srvEphPub[:], okPlain[0:32])
	var sessionID [16]byte
	copy(sessionID[:], okPlain[32:48])

	// Derive shared secret and session keys.
	shared, err := udpX25519Shared(&ephPriv, &srvEphPub)
	if err != nil {
		conn.Close()
		return nil, nil, errors.New("mist udp: shared secret failed").Base(err)
	}
	kC2S, kS2C := deriveUDPSessionKeys(ephPub, srvEphPub, shared)

	// Create session.
	session := NewUDPSession(sessionID, kC2S, kS2C, c.serverAddr, c.codec)

	// Note: the UDP conn is owned by the caller. Use session.SealPacket/
	// OpenPacket for crypto, and do I/O on conn directly.
	// (We keep conn open here; caller must Close it when done.)
	return session, conn, nil
}
