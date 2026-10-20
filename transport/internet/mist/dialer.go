package mist

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// maxSessions caps the per-(server, client) session pool. Each session
// multiplexes up to 15 data streams (SPEC 9.1); a new TLS session is opened
// when all are full instead of blocking user traffic.
const maxSessions = 4

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

// Dial opens one Mist stream to the Mist server at dest and returns it as
// a net.Conn. dest is the Mist server's address (the outbound's server
// destination); the returned stream is a raw byte pipe — CONNECT/UDP
// framing is the proxy layer's job.
func Dial(ctx context.Context, dest cnet.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	cfg, ok := streamSettings.ProtocolSettings.(*Config)
	if !ok || cfg == nil {
		return nil, errors.New("mist: invalid stream settings")
	}
	cid, err := hex.DecodeString(cfg.GetClientId())
	if err != nil || len(cid) != 16 {
		return nil, errors.New("mist: clientId must be 16 bytes hex-encoded")
	}
	ak, err := base64.StdEncoding.DecodeString(cfg.GetAuthKey())
	if err != nil || len(ak) != 32 {
		return nil, errors.New("mist: authKey must be 32 bytes base64(std)-encoded")
	}

	var params sessionParams
	copy(params.cid[:], cid)
	copy(params.kAuth[:], ak)
	hbSec := cfg.GetHeartbeatInterval()
	if hbSec == 0 {
		hbSec = defaultHeartbeatSec
	}
	params.hb = time.Duration(hbSec) * time.Second
	heavy := cfg.GetShapingHeavyPackets()
	if heavy == 0 {
		heavy = defaultHeavyPackets
	}
	params.shaping = shapingParams{
		heavyPackets: heavy,
		padMin:       defaultShapingPadMin,
		padMax:       defaultShapingPadMax,
		jitterMaxMs:  defaultShapingJitterMs,
		tailPad:      0,
	}

	pool := getSessionPool(dest, streamSettings, params)
	st, sess, err := pool.getStream(ctx)
	if err != nil {
		return nil, err
	}
	return &streamConn{
		s:      st,
		local:  sess.conn.LocalAddr(),
		remote: sess.conn.RemoteAddr(),
	}, nil
}

// dialMistTLS opens the TCP connection and runs the uTLS handshake.
// Mist mandates TLS; a missing security config is a hard error.
func dialMistTLS(ctx context.Context, dest cnet.Destination, streamSettings *internet.MemoryStreamConfig) (net.Conn, error) {
	conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}
	cfg := tls.ConfigFromStreamSettings(streamSettings)
	if cfg == nil {
		conn.Close()
		return nil, errors.New("mist: TLS is required")
	}
	tlsConfig := cfg.GetTLSConfig(tls.WithDestination(dest))
	fpName := cfg.Fingerprint
	if fpName == "" {
		fpName = "hellochrome_155"
	}
	fp := tls.GetFingerprint(fpName)
	if fp == nil {
		conn.Close()
		return nil, errors.New("mist: unknown TLS fingerprint: ", fpName)
	}
	conn = tls.UClient(conn, tlsConfig, fp)
	if err := conn.(*tls.UConn).HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, errors.New("mist: TLS handshake failed").Base(err)
	}
	return conn, nil
}

// sessionPool multiplexes Mist streams over a small pool of TLS sessions,
// keyed by (server, client_id). Logic mirrors proxy/mist Client.getStream:
// prefer a live session with a free stream ID, then RESUME on the newest
// dead-but-resumable session, then a full AUTH handshake (SPEC 10.2).
type sessionPool struct {
	mu       sync.Mutex
	server   cnet.Destination
	settings *internet.MemoryStreamConfig
	params   sessionParams
	sessions []*Session
}

var (
	poolMu sync.Mutex
	pools  = make(map[string]*sessionPool)
)

func getSessionPool(server cnet.Destination, settings *internet.MemoryStreamConfig, params sessionParams) *sessionPool {
	key := server.NetAddr() + "|" + hex.EncodeToString(params.cid[:])
	poolMu.Lock()
	defer poolMu.Unlock()
	if p, ok := pools[key]; ok {
		return p
	}
	p := &sessionPool{server: server, settings: settings, params: params}
	pools[key] = p
	return p
}

// dial opens one TLS connection to the Mist server with a handshake timeout.
func (p *sessionPool) dial(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := dialMistTLS(ctx, p.server, p.settings)
	if err != nil {
		return nil, errors.New("mist: failed to dial server").Base(err)
	}
	return conn, nil
}

// newSession dials and runs the full AUTH handshake.
func (p *sessionPool) newSession(ctx context.Context) (*Session, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	sess, err := doAuth(conn, p.params)
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, err
	}
	errors.LogDebug(ctx, "mist: session established with ", p.server.NetAddr())
	return sess, nil
}

// getStream returns a fresh stream on a live session, creating or resuming
// a session as needed. It also returns the owning session so the caller
// can read the underlying connection's addresses.
func (p *sessionPool) getStream(ctx context.Context) (*Stream, *Session, error) {
	p.mu.Lock()
	for _, s := range p.sessions {
		if st, ok := s.openStream(); ok {
			p.mu.Unlock()
			return st, s, nil
		}
	}
	var old *Session
	for i := len(p.sessions) - 1; i >= 0; i-- {
		if p.sessions[i].resumable() {
			old = p.sessions[i]
			break
		}
	}
	p.mu.Unlock()

	var sess *Session
	if old != nil {
		conn, derr := p.dial(ctx)
		if derr == nil {
			_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
			sess, derr = old.resume(conn)
			_ = conn.SetDeadline(time.Time{})
			if derr != nil {
				errors.LogDebug(ctx, "mist: resume failed (", derr, "), falling back to full auth")
				sess = nil
			} else {
				errors.LogDebug(ctx, "mist: session resumed with ", p.server.NetAddr())
			}
		}
	}
	if sess == nil {
		var err error
		sess, err = p.newSession(ctx)
		if err != nil {
			return nil, nil, err
		}
	}

	p.mu.Lock()
	// Prune dead sessions, drop the replaced one, cap the pool.
	kept := p.sessions[:0]
	for _, s := range p.sessions {
		if s != old && s.alive() {
			kept = append(kept, s)
		}
	}
	kept = append(kept, sess)
	for len(kept) > maxSessions {
		kept[0].close()
		kept = kept[1:]
	}
	p.sessions = kept
	p.mu.Unlock()

	st, ok := sess.openStream()
	if !ok {
		return nil, nil, errors.New("mist: no free stream slot on fresh session")
	}
	return st, sess, nil
}

// resumable reports whether the (dead) session still holds resume material.
// A session that never completed AUTH has no connID/resume token.
func (s *Session) resumable() bool {
	if s.alive() {
		return false
	}
	var zeroID [16]byte
	var zeroTok [32]byte
	return s.connID != zeroID && s.resumeTok != zeroTok
}

// streamConn adapts one Mist Stream to net.Conn (== stat.Connection) for
// the transport framework.
type streamConn struct {
	s             *Stream
	local, remote net.Addr
}

func (c *streamConn) Read(p []byte) (int, error)  { return c.s.Read(p) }
func (c *streamConn) Write(p []byte) (int, error) { return c.s.Write(p) }
func (c *streamConn) Close() error                { c.s.done(); return nil }
func (c *streamConn) LocalAddr() net.Addr         { return c.local }
func (c *streamConn) RemoteAddr() net.Addr        { return c.remote }

// Multiplexed streams share one TLS connection, so per-stream deadlines
// cannot be honored; they are accepted and ignored.
func (c *streamConn) SetDeadline(t time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return nil }
