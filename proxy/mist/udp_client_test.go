package mist

import (
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// TestUDPClientHandshake tests the full client-server UDP handshake.
// Uses the in-memory pipe (sandbox blocks UDP loopback).
func TestUDPClientHandshake(t *testing.T) {
	cid, kAuth := testCredentials()
	clientConn, serverConn := memPipe()
	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}

	codec := &RandomCiphertextCodec{}

	// Server handshake in background.
	serverDone := make(chan *UDPSession, 1)
	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		_ = serverConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, clientAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			serverErr <- errors.New("server read failed").Base(err)
			return
		}
		t.Logf("server received %d bytes from %v", n, clientAddr)
		result, err := UDPServerHandshake(codec, buf[:n], clientAddr,
			func(handshakeCID [16]byte, nonce [24]byte) (*[32]byte, [16]byte, bool) {
				// For test: accept any CID, return our kAuth.
				return &kAuth, cid, true
			})
		if err != nil {
			serverErr <- errors.New("server handshake failed").Base(err)
			return
		}
		t.Logf("server handshake ok, sending %d bytes response", len(result.Response))
		// Send response back.
		if _, err := serverConn.WriteToUDP(result.Response, clientAddr); err != nil {
			serverErr <- errors.New("server write failed").Base(err)
			return
		}
		t.Logf("server response sent")
		serverDone <- result.Session
	}()

	// Client handshake via mem pipe.
	client := NewUDPClient(serverAddr, cid, kAuth).WithDial(func() (UDPPacketConn, error) {
		return clientConn, nil
	})
	sess, conn, err := client.Handshake()
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	defer conn.Close()

	// Wait for server.
	select {
	case srvSess := <-serverDone:
		// Verify session IDs match.
		if sess.SessionID != srvSess.SessionID {
			t.Errorf("session ID mismatch")
		}
		// Verify keys match (C2S/S2C swapped).
		if sess.KeyC2S != srvSess.KeyC2S {
			t.Errorf("KeyC2S mismatch")
		}
		if sess.KeyS2C != srvSess.KeyS2C {
			t.Errorf("KeyS2C mismatch")
		}
	case err := <-serverErr:
		t.Fatalf("server handshake failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("handshake timeout")
	}
}

// TestUDPClientConfig verifies the UDP config option flows through.
func TestUDPClientConfig(t *testing.T) {
	cfg := &ClientConfig{
		Address:  "127.0.0.1",
		Port:     443,
		ClientId: "000102030405060708090a0b0c0d0e0f",
		AuthKey:  "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
		Udp:      true,
	}
	if !cfg.GetUdp() {
		t.Error("GetUdp should return true")
	}

	cfg2 := &ClientConfig{
		Address: "127.0.0.1",
		Udp:     false,
	}
	if cfg2.GetUdp() {
		t.Error("GetUdp should return false")
	}
}
