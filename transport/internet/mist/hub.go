package mist

import (
	"context"
	"crypto/rand"
	gotls "crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, ListenMist))
}

// ListenMist implements internet.ListenFunc: a TLS-terminating TCP listener
// speaking the Mist server side (SPEC 6.2). Each accepted connection runs
// the AUTH handshake as its first application data; any failure closes the
// connection silently and never signals the reason (anti-probing, SPEC B.3).
func ListenMist(ctx context.Context, address cnet.Address, port cnet.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	cfg, ok := streamSettings.ProtocolSettings.(*Config)
	if !ok || cfg == nil {
		return nil, errors.New("mist: invalid stream settings")
	}
	if len(cfg.GetAccounts()) == 0 {
		return nil, errors.New("mist: at least one account is required")
	}
	accounts := make(map[[16]byte][32]byte, len(cfg.GetAccounts()))
	for _, a := range cfg.GetAccounts() {
		cid, err := hex.DecodeString(a.GetClientId())
		if err != nil || len(cid) != 16 {
			return nil, errors.New("mist: account client_id must be 16 bytes hex-encoded")
		}
		ak, err := base64.StdEncoding.DecodeString(a.GetAuthKey())
		if err != nil || len(ak) != 32 {
			return nil, errors.New("mist: account auth_key must be 32 bytes base64(std)-encoded")
		}
		var c16 [16]byte
		var k32 [32]byte
		copy(c16[:], cid)
		copy(k32[:], ak)
		accounts[c16] = k32
	}
	tlsCfg := tls.ConfigFromStreamSettings(streamSettings)
	if tlsCfg == nil {
		return nil, errors.New("mist: TLS is required")
	}

	ln, err := internet.ListenSystem(ctx, &cnet.TCPAddr{IP: address.IP(), Port: int(port)}, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}
	errors.LogInfo(ctx, "listening Mist on ", address, ":", port)

	hbSec := cfg.GetHeartbeatInterval()
	if hbSec == 0 {
		hbSec = defaultHeartbeatSec
	}
	l := &mistListener{
		Listener:  ln,
		tlsConfig: tlsCfg.GetTLSConfig(),
		accounts:  accounts,
		cache:     NewNonceCache(120 * time.Second),
		handler:   handler,
		hbSec:     uint16(hbSec),
	}
	go l.keepAccepting()
	return l, nil
}

// mistListener is the Mist transport listener. It embeds cnet.Listener
// (= std net.Listener), so Close and Addr are promoted and it satisfies
// internet.Listener.
type mistListener struct {
	cnet.Listener
	tlsConfig *gotls.Config
	accounts  map[[16]byte][32]byte
	cache     *NonceCache
	handler   internet.ConnHandler
	hbSec     uint16
}

func (l *mistListener) lookup(cid [16]byte) ([32]byte, bool) {
	k, ok := l.accounts[cid]
	return k, ok
}

// keepAccepting mirrors transport/internet/tcp's accept loop: "too many
// open files" backs off 500ms instead of spinning.
func (l *mistListener) keepAccepting() {
	for {
		conn, err := l.Accept()
		if err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "closed") {
				break
			}
			errors.LogWarningInner(context.Background(), err, "mist: failed to accept connection")
			if strings.Contains(errStr, "too many") {
				time.Sleep(500 * time.Millisecond)
			}
			continue
		}
		go l.serveConn(conn)
	}
}

// serveConn runs the TLS + AUTH handshake for one inbound connection and,
// on success, hands the session's read loop a goroutine. The session owns
// the connection from there; every failure path closes it silently.
func (l *mistListener) serveConn(raw cnet.Conn) {
	tlsConn := tls.Server(raw, l.tlsConfig)
	hsCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := tlsConn.(*tls.Conn).HandshakeContext(hsCtx); err != nil {
		tlsConn.Close()
		return // silent
	}

	// AUTH is the first application data (SPEC 6.1): exactly 89 bytes.
	_ = tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	wire := make([]byte, authWireLen)
	_, err := io.ReadFull(tlsConn, wire)
	_ = tlsConn.SetReadDeadline(time.Time{})
	if err != nil {
		tlsConn.Close()
		return // silent
	}
	ar, err := parseAuth(wire, l.lookup, l.cache)
	if err != nil {
		tlsConn.Close()
		return // silent: never signal the reason
	}

	srvPriv, srvPub, err := serverEphemeral()
	if err != nil {
		tlsConn.Close()
		return
	}
	// SPEC 6.4 KDF; the server calls with (srvPriv, cliPub, cliPub,
	// srvPub). deriveSessionKeys zeroes srvPriv before returning.
	kC2S, kS2C, err := deriveSessionKeys(srvPriv[:], ar.ephPub[:], ar.ephPub[:], srvPub[:])
	if err != nil {
		tlsConn.Close()
		return
	}
	var connID [16]byte
	if _, err := io.ReadFull(rand.Reader, connID[:]); err != nil {
		tlsConn.Close()
		return
	}
	var resumeTok [32]byte
	if _, err := io.ReadFull(rand.Reader, resumeTok[:]); err != nil {
		tlsConn.Close()
		return
	}
	kAuth, ok := l.lookup(ar.cid)
	if !ok {
		tlsConn.Close()
		return
	}
	okWire, err := buildAuthOK(kAuth, srvPub, connID, resumeTok, 15, l.hbSec)
	if err != nil {
		tlsConn.Close()
		return
	}
	_ = tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = tlsConn.Write(okWire)
	_ = tlsConn.SetWriteDeadline(time.Time{})
	if err != nil {
		tlsConn.Close()
		return
	}

	ss := newServerSession(tlsConn, kC2S, kS2C, l.handler)
	go ss.readLoop()
	// The session owns tlsConn from here; serveConn must not close it.
}
