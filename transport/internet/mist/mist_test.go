package mist

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// testIdentity generates a random (clientID hex, authKey base64) pair.
func testIdentity(t *testing.T) (string, string) {
	t.Helper()
	cid := make([]byte, 16)
	if _, err := rand.Read(cid); err != nil {
		t.Fatal(err)
	}
	ak := make([]byte, 32)
	if _, err := rand.Read(ak); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(cid), base64.StdEncoding.EncodeToString(ak)
}

// testCertPEM generates a self-signed certificate for 127.0.0.1.
func testCertPEM(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mist-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func testServerSettings(t *testing.T, clientID, authKey string) *internet.MemoryStreamConfig {
	certPEM, keyPEM := testCertPEM(t)
	return &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{
			Accounts: []*Account{{ClientId: clientID, AuthKey: authKey}},
		},
		SecuritySettings: &tls.Config{
			Certificate: []*tls.Certificate{{Certificate: certPEM, Key: keyPEM}},
		},
	}
}

func testClientSettings(clientID, authKey string) *internet.MemoryStreamConfig {
	return &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{ClientId: clientID, AuthKey: authKey},
		SecuritySettings: &tls.Config{InsecureSkipVerify: true},
	}
}

// openProxyStream emulates what the proxy/mist outbound does on top of the
// transport: the first frame on a stream carries SYN (here with an empty
// payload; the real outbound piggybacks the CONNECT request, SPEC 9.2).
// The transport hub only accepts streams on SYN, like the reference
// mist-server.
func openProxyStream(t *testing.T, conn stat.Connection) {
	t.Helper()
	sc, ok := conn.(*streamConn)
	if !ok {
		t.Fatalf("expected *streamConn, got %T", conn)
	}
	if err := sc.s.sess.writeFrame(sc.s.id|flagSYN, nil); err != nil {
		t.Fatalf("SYN failed: %v", err)
	}
}

// TestMistTransportEcho runs a full loopback: ListenMist with an echo
// handler, Dial from the client, write/read/verify.
func TestMistTransportEcho(t *testing.T) {
	clientID, authKey := testIdentity(t)
	serverSettings := testServerSettings(t, clientID, authKey)

	echoed := make(chan struct{}, 16)
	handler := func(conn stat.Connection) {
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
				select {
				case echoed <- struct{}{}:
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ln, err := ListenMist(ctx, cnet.ParseAddress("127.0.0.1"), 0, serverSettings, handler)
	if err != nil {
		t.Fatalf("ListenMist failed: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	dest := cnet.Destination{
		Address: cnet.ParseAddress("127.0.0.1"),
		Port:    cnet.Port(port),
		Network: cnet.Network_TCP,
	}
	conn, err := Dial(ctx, dest, testClientSettings(clientID, authKey))
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()
	openProxyStream(t, conn)

	msg := []byte("hello mist transport")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", got, msg)
	}
	select {
	case <-echoed:
	case <-time.After(5 * time.Second):
		t.Fatal("server handler never received the stream")
	}
}

// TestMistTransportSecondStream verifies stream multiplexing: a second Dial
// reuses the pooled session and gets its own echo.
func TestMistTransportSecondStream(t *testing.T) {
	clientID, authKey := testIdentity(t)
	serverSettings := testServerSettings(t, clientID, authKey)

	handler := func(conn stat.Connection) {
		defer conn.Close()
		// Prefix every reply so the client can tell streams apart.
		if _, err := conn.Write([]byte("srv:")); err != nil {
			return
		}
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ln, err := ListenMist(ctx, cnet.ParseAddress("127.0.0.1"), 0, serverSettings, handler)
	if err != nil {
		t.Fatalf("ListenMist failed: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	dest := cnet.Destination{
		Address: cnet.ParseAddress("127.0.0.1"),
		Port:    cnet.Port(port),
		Network: cnet.Network_TCP,
	}
	settings := testClientSettings(clientID, authKey)

	for i := 0; i < 2; i++ {
		conn, err := Dial(ctx, dest, settings)
		if err != nil {
			t.Fatalf("Dial %d failed: %v", i, err)
		}
		openProxyStream(t, conn)
		prefix := make([]byte, 4)
		if _, err := io.ReadFull(conn, prefix); err != nil {
			conn.Close()
			t.Fatalf("read prefix %d failed: %v", i, err)
		}
		if string(prefix) != "srv:" {
			conn.Close()
			t.Fatalf("stream %d got wrong handler: %q", i, prefix)
		}
		conn.Close()
	}
}

// TestMistDialMissingClientID verifies Dial rejects an empty client_id
// before touching the network.
func TestMistDialMissingClientID(t *testing.T) {
	_, authKey := testIdentity(t)
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{AuthKey: authKey}, // no ClientId
		SecuritySettings: &tls.Config{InsecureSkipVerify: true},
	}
	dest := cnet.Destination{
		Address: cnet.ParseAddress("127.0.0.1"),
		Port:    cnet.Port(1),
		Network: cnet.Network_TCP,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Dial(ctx, dest, settings); err == nil {
		t.Fatal("expected Dial to fail with missing client_id")
	}
}

// TestMistListenNoAccounts verifies the listener requires an account table.
func TestMistListenNoAccounts(t *testing.T) {
	certPEM, keyPEM := testCertPEM(t)
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		ProtocolSettings: &Config{}, // no accounts
		SecuritySettings: &tls.Config{
			Certificate: []*tls.Certificate{{Certificate: certPEM, Key: keyPEM}},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ListenMist(ctx, cnet.ParseAddress("127.0.0.1"), 0, settings, nil); err == nil {
		t.Fatal("expected ListenMist to fail with no accounts")
	}
}

// TestMistListenRequiresTLS verifies Mist refuses to run without TLS.
func TestMistListenRequiresTLS(t *testing.T) {
	clientID, authKey := testIdentity(t)
	settings := &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		ProtocolSettings: &Config{
			Accounts: []*Account{{ClientId: clientID, AuthKey: authKey}},
		},
		// no SecuritySettings
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ListenMist(ctx, cnet.ParseAddress("127.0.0.1"), 0, settings, nil); err == nil {
		t.Fatal("expected ListenMist to fail without TLS settings")
	}
}
