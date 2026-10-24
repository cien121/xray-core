package mist

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	stdnet "net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// maxSessions caps the per-client session pool. Each session multiplexes up
// to 15 data streams (SPEC 9.1); a new TLS session is opened when all are
// full instead of blocking user traffic.
const maxSessions = 4

// Client is the outbound handler for the Mist protocol. The TLS handshake
// (with uTLS Chrome fingerprint) is done by the Xray transport layer from
// the user's streamSettings — this client only speaks Mist frames on top
// of the established TLS connection (SPEC 4/6/7/8/9/10).
type Client struct {
	server        net.Destination
	policyManager policy.Manager
	params        sessionParams
	useUDP        bool

	mu       sync.Mutex
	sessions []*Session

	// UDP state (when useUDP is true).
	udpMu      sync.Mutex
	udpSession *UDPSession
	udpConn    UDPPacketConn
	udpMgr     *udpStreamManager
	udpClient  *UDPClient
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	v := core.MustFromContext(ctx)
	p := v.GetFeature(policy.ManagerType()).(policy.Manager)

	if config.Address == "" {
		return nil, errors.New("mist: address is not set")
	}
	cid, err := hex.DecodeString(config.ClientId)
	if err != nil || len(cid) != 16 {
		return nil, errors.New("mist: clientId must be 16 bytes hex-encoded")
	}
	ak, err := base64.StdEncoding.DecodeString(config.AuthKey)
	if err != nil || len(ak) != 32 {
		return nil, errors.New("mist: authKey must be 32 bytes base64(std)-encoded")
	}

	dest := net.Destination{
		Address: net.ParseAddress(config.Address),
		Port:    net.Port(config.Port),
		Network: net.Network_TCP,
	}
	if !dest.IsValid() {
		return nil, errors.New("mist: invalid address ", config.Address)
	}
	if dest.Port == 0 {
		dest.Port = 443
	}

	// Safety gate (2026-10-23 review): when UDP transport is enabled, the
	// Initial codec must not be a test-only implementation talking to a
	// public server. Random-ciphertext Initials are a DPI fingerprint.
	// Refuse the config here so no config path can push them onto a real
	// network; release builds additionally compile the codec out entirely
	// (initial_codec_disabled.go, needs -tags mist_unsafe_initial for lab).
	if config.GetUdp() {
		if err := CheckInitialCodecSafeForAddr(&QUICInitialCodec{}, config.Address); err != nil {
			return nil, err
		}
	}

	hbSec := config.HeartbeatInterval
	if hbSec == 0 {
		hbSec = defaultHeartbeatSec
	}
	heavy := config.ShapingHeavyPackets
	if heavy == 0 {
		heavy = defaultHeavyPackets
	}

	var params sessionParams
	copy(params.cid[:], cid)
	copy(params.kAuth[:], ak)
	params.hb = time.Duration(hbSec) * time.Second
	params.shaping = shapingParams{
		heavyPackets: heavy,
		padMin:       defaultShapingPadMin,
		padMax:       defaultShapingPadMax,
		jitterMaxMs:  defaultShapingJitterMs,
		tailPad:      0,
	}

	return &Client{
		server:        dest,
		policyManager: p,
		params:        params,
		useUDP:        config.GetUdp(),
	}, nil
}

// dialServer opens the TLS connection to the Mist server. TLS (uTLS) is
// handled by the transport layer from streamSettings; the returned conn is
// ready for the AUTH handshake as its first application data (SPEC 6.1).
func (c *Client) dialServer(ctx context.Context, dialer internet.Dialer) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := dialer.Dial(ctx, c.server)
	if err != nil {
		return nil, errors.New("mist: failed to dial server").Base(err)
	}
	return conn, nil
}

// newSession dials and runs the full AUTH handshake.
func (c *Client) newSession(ctx context.Context, dialer internet.Dialer) (*Session, error) {
	conn, err := c.dialServer(ctx, dialer)
	if err != nil {
		return nil, err
	}
	if dc, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		_ = dc.SetDeadline(time.Now().Add(20 * time.Second))
	}
	sess, err := doAuth(conn, c.params)
	if dc, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		_ = dc.SetDeadline(time.Time{})
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	errors.LogDebug(ctx, "mist: session established with ", c.server.NetAddr())
	return sess, nil
}

// getUDPMgr returns the shared UDP stream manager, creating the session
// and manager on first use. The UDP session is shared across all streams
// (unlike TCP which pools sessions).
func (c *Client) getUDPMgr(ctx context.Context) (*udpStreamManager, error) {
	c.udpMu.Lock()
	defer c.udpMu.Unlock()

	if c.udpMgr != nil {
		return c.udpMgr, nil
	}

	// Resolve server UDP address via safety gate (fail-closed).
	addr := c.server.Address.String()
	if addr == "" {
		return nil, errors.New("mist udp: server address not set")
	}
	udpAddr, err := ResolvePeerAddrSafe(context.Background(),
		stdnet.JoinHostPort(addr, itoa(int(c.server.Port))), &QUICInitialCodec{})
	if err != nil {
		return nil, errors.New("mist udp: resolve failed").Base(err)
	}

	udpClient := NewUDPClient(udpAddr, c.params.cid, c.params.kAuth)
	sess, conn, err := udpClient.Handshake()
	if err != nil {
		return nil, err
	}

	mgr := newUDPStreamManager(sess, conn, udpAddr)
	c.udpSession = sess
	c.udpConn = conn
	c.udpClient = udpClient
	c.udpMgr = mgr
	errors.LogDebug(ctx, "mist udp: session established with ", udpAddr.String())
	return mgr, nil
}

// getUDPSession is kept for compatibility; prefer getUDPMgr.
func (c *Client) getUDPSession(ctx context.Context) (*UDPSession, UDPPacketConn, error) {
	mgr, err := c.getUDPMgr(ctx)
	if err != nil {
		return nil, nil, err
	}
	return mgr.sess, mgr.conn, nil
}

// itoa is a tiny int-to-string helper to avoid strconv import churn.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [8]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

// getStream returns a live session and a fresh stream on it. It tries, in
// order: an existing live session with a free stream ID; RESUME on the
// newest dead-but-resumable session; a full AUTH handshake (SPEC 10.2).
func (c *Client) getStream(ctx context.Context, dialer internet.Dialer) (*Stream, error) {
	c.mu.Lock()
	for _, s := range c.sessions {
		if st, ok := s.openStream(); ok {
			c.mu.Unlock()
			return st, nil
		}
	}
	var old *Session
	for i := len(c.sessions) - 1; i >= 0; i-- {
		if c.sessions[i].resumable() {
			old = c.sessions[i]
			break
		}
	}
	c.mu.Unlock()

	var sess *Session
	if old != nil {
		conn, derr := c.dialServer(ctx, dialer)
		if derr == nil {
			if dc, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
				_ = dc.SetDeadline(time.Now().Add(20 * time.Second))
			}
			sess, derr = old.resume(conn)
			if dc, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
				_ = dc.SetDeadline(time.Time{})
			}
			if derr != nil {
				errors.LogDebug(ctx, "mist: resume failed (", derr, "), falling back to full auth")
				sess = nil
			} else {
				errors.LogDebug(ctx, "mist: session resumed with ", c.server.NetAddr())
			}
		}
	}
	if sess == nil {
		var err error
		sess, err = c.newSession(ctx, dialer)
		if err != nil {
			return nil, err
		}
	}

	c.mu.Lock()
	// Prune dead sessions, drop the replaced one, cap the pool.
	kept := c.sessions[:0]
	for _, s := range c.sessions {
		if s != old && s.alive() {
			kept = append(kept, s)
		}
	}
	kept = append(kept, sess)
	for len(kept) > maxSessions {
		kept[0].close()
		kept = kept[1:]
	}
	c.sessions = kept
	c.mu.Unlock()

	st, ok := sess.openStream()
	if !ok {
		return nil, errors.New("mist: no free stream slot on fresh session")
	}
	return st, nil
}

// resumable reports whether the (dead) session still holds resume material.
func (s *Session) resumable() bool {
	if s.alive() {
		return false
	}
	// A session that never completed AUTH has no connID/resume token.
	var zeroID [16]byte
	var zeroTok [32]byte
	return s.connID != zeroID && s.resumeTok != zeroTok
}

// connectResultText maps CONNECT failure codes (SPEC 9.2) to messages.
func connectResultText(code byte) string {
	switch code {
	case codeNetUnreachable:
		return "network unreachable"
	case codeConnRefused:
		return "connection refused"
	case codeTimeout:
		return "connection timed out"
	case codeUnsupportedAddress:
		return "unsupported address type"
	default:
		return "unknown failure"
	}
}

// encodeConnectRequest builds the SYN payload: [ATYP][ADDR][PORT] (SPEC 9.2).
func encodeConnectRequest(target net.Destination) ([]byte, error) {
	fam := target.Address.Family()
	var addrBytes []byte
	var atyp byte
	switch {
	case fam.IsIPv4():
		atyp = 0x01
		addrBytes = target.Address.IP().To4()
	case fam.IsIPv6():
		atyp = 0x04
		addrBytes = target.Address.IP().To16()
	case fam.IsDomain():
		d := target.Address.Domain()
		if len(d) == 0 || len(d) > 255 {
			return nil, errors.New("mist: invalid domain length")
		}
		atyp = 0x03
		addrBytes = append([]byte{byte(len(d))}, d...)
	default:
		return nil, errors.New("mist: unsupported address family")
	}
	return encodeAddrPort(addrBytes, atyp, uint16(target.Port)), nil
}

// buildUDPDatagram builds one UDP relay datagram frame payload:
// [ATYP][ADDR][PORT][LEN(2,BE)][DATA] (SPEC 9.4).
func buildUDPDatagram(target net.Destination, data []byte) ([]byte, error) {
	hdr, err := encodeConnectRequest(target)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(hdr)+2+len(data))
	out = append(out, hdr...)
	var lb [2]byte
	binary.BigEndian.PutUint16(lb[:], uint16(len(data)))
	out = append(out, lb[:]...)
	out = append(out, data...)
	return out, nil
}

// parseUDPDatagram splits a datagram frame payload into header and data.
func parseUDPDatagram(dgram []byte) ([]byte, error) {
	if len(dgram) < 1 {
		return nil, errors.New("mist: empty udp datagram")
	}
	off := 1
	switch dgram[0] {
	case 0x01:
		off += 4
	case 0x04:
		off += 16
	case 0x03:
		if len(dgram) < 2 {
			return nil, errors.New("mist: truncated udp datagram")
		}
		off += 1 + int(dgram[1])
	default:
		return nil, errors.New("mist: bad atyp in udp datagram")
	}
	off += 2 // PORT
	if len(dgram) < off+2 {
		return nil, errors.New("mist: truncated udp datagram")
	}
	dataLen := int(binary.BigEndian.Uint16(dgram[off : off+2]))
	off += 2
	if len(dgram) < off+dataLen {
		return nil, errors.New("mist: udp datagram length mismatch")
	}
	return dgram[off : off+dataLen], nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("mist: target not specified")
	}
	ob.Name = "mist"
	ob.CanSpliceCopy = 3
	target := ob.Target

	sessionPolicy := c.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
	}, sessionPolicy.Timeouts.ConnectionIdle)

	// UDP transport: use UDPSession instead of TCP Stream pool.
	if c.useUDP {
		return c.processUDPTransport(ctx, link, target, timer, sessionPolicy)
	}

	st, err := c.getStream(ctx, dialer)
	if err != nil {
		return err
	}
	defer st.done()

	errors.LogInfo(ctx, "tunneling request to ", target, " via mist ", c.server.NetAddr())

	if target.Network == net.Network_TCP {
		return c.processTCP(ctx, link, st, target, timer, sessionPolicy)
	}
	return c.processUDP(ctx, link, st, target, timer)
}

func (c *Client) processTCP(ctx context.Context, link *transport.Link, st *Stream, target net.Destination, timer *signal.ActivityTimer, sessionPolicy policy.Session) error {
	// SYN + CONNECT request (SPEC 9.2).
	req, err := encodeConnectRequest(target)
	if err != nil {
		return err
	}
	if err := st.sess.writeFrame(st.id|flagSYN, req); err != nil {
		return errors.New("mist: failed to open stream").Base(err)
	}
	// Server replies on the same stream: [CODE(1)].
	var code [1]byte
	if _, err := io.ReadFull(st, code[:]); err != nil {
		return errors.New("mist: failed to read connect result").Base(err)
	}
	if code[0] != codeSuccess {
		return errors.New("mist: server refused connection: ", connectResultText(code[0]))
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		defer st.CloseWrite() // FIN: half-close (SPEC 9.3)
		return buf.Copy(link.Reader, buf.NewWriter(st), buf.UpdateActivity(timer))
	}
	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(&buf.SingleReader{Reader: st}, link.Writer, buf.UpdateActivity(timer))
	}
	responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
		return errors.New("mist: connection ends").Base(err)
	}
	return nil
}

func (c *Client) processUDP(ctx context.Context, link *transport.Link, st *Stream, target net.Destination, timer *signal.ActivityTimer) error {
	// SPEC 9.4: announce the association on the control stream, then open a
	// data stream (SYN) as the bearer. The bearer is paired with the
	// association by ordering: the first stream opened right after
	// UDP_ASSOC_REQ is its bearer. Each frame on the bearer carries exactly
	// one datagram: [ATYP][ADDR][PORT][LEN][DATA].
	if err := st.sess.writeControl(ctrlUDPAssocReq, nil); err != nil {
		return errors.New("mist: failed to send udp associate request").Base(err)
	}
	if err := st.sess.writeFrame(st.id|flagSYN, nil); err != nil {
		return errors.New("mist: failed to open udp bearer stream").Base(err)
	}
	defer st.Reset() // RST closes the relay (SPEC 9.4: no connection semantics)

	uplinkDone := func() error {
		defer timer.SetTimeout(300 * time.Second)
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return err
			}
			for _, b := range mb {
				dgram, derr := buildUDPDatagram(target, b.Bytes())
				b.Release()
				if derr != nil {
					return derr
				}
				// One datagram must fit in exactly one frame (the bearer
				// stream is datagram-framed); larger ones can't be
				// represented on the wire, so drop them loudly.
				if len(dgram) > maxPlainPerFrameBase-defaultShapingPadMax {
					errors.LogDebug(ctx, "mist: dropping oversized udp datagram: ", len(dgram))
					continue
				}
				if _, werr := st.Write(dgram); werr != nil {
					return werr
				}
				timer.Update()
			}
		}
	}
	downlinkDone := func() error {
		defer timer.SetTimeout(300 * time.Second)
		for {
			dgram, err := st.ReadDatagram()
			if err != nil {
				return err
			}
			data, perr := parseUDPDatagram(dgram)
			if perr != nil {
				errors.LogDebug(ctx, "mist: dropping malformed udp datagram: ", perr)
				continue
			}
			b := buf.New()
			b.Write(data)
			if werr := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); werr != nil {
				b.Release()
				return werr
			}
			timer.Update()
		}
	}
	if err := task.Run(ctx, uplinkDone, downlinkDone); err != nil {
		return errors.New("mist: udp relay ends").Base(err)
	}
	return nil
}

// processUDPTransport handles outbound connections over the UDP transport.
// It uses the shared udpStreamManager (established via UDP handshake).
// The flow mirrors processTCP: SYN + CONNECT, read result code, then
// bidirectional copy. UDP targets use DATAGRAM frames instead.
func (c *Client) processUDPTransport(ctx context.Context, link *transport.Link, target net.Destination, timer *signal.ActivityTimer, sessionPolicy policy.Session) error {
	mgr, err := c.getUDPMgr(ctx)
	if err != nil {
		return err
	}

	errors.LogInfo(ctx, "tunneling request to ", target, " via mist-udp ", c.server.NetAddr())

	if target.Network == net.Network_TCP {
		return c.processUDPTransportTCP(ctx, link, mgr, target, timer, sessionPolicy)
	}
	return c.processUDPTransportUDP(ctx, link, mgr, target, timer)
}

// processUDPTransportTCP proxies one TCP connection over a UDP stream.
func (c *Client) processUDPTransportTCP(ctx context.Context, link *transport.Link, mgr *udpStreamManager, target net.Destination, timer *signal.ActivityTimer, sessionPolicy policy.Session) error {
	st := mgr.openStream()
	if st == nil {
		return errors.New("mist udp: no free stream ID")
	}
	defer st.done()

	// SYN + CONNECT request (SPEC 9.2, reused over UDP per UDP-DESIGN §4.1).
	req, err := encodeConnectRequest(target)
	if err != nil {
		return err
	}
	if err := mgr.sendFrames([][]byte{EncodeUDPFrame(UDPFrameSyn, st.sid, req)}); err != nil {
		return errors.New("mist udp: failed to open stream").Base(err)
	}
	// Server replies on the same stream: [CODE(1)].
	var code [1]byte
	if _, err := io.ReadFull(st, code[:]); err != nil {
		return errors.New("mist udp: failed to read connect result").Base(err)
	}
	if code[0] != codeSuccess {
		return errors.New("mist udp: server refused connection: ", connectResultText(code[0]))
	}

	requestDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		defer st.CloseWrite() // FIN: half-close
		return buf.Copy(link.Reader, buf.NewWriter(st), buf.UpdateActivity(timer))
	}
	responseDone := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(&buf.SingleReader{Reader: st}, link.Writer, buf.UpdateActivity(timer))
	}
	responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
		return errors.New("mist udp: connection ends").Base(err)
	}
	return nil
}

// processUDPTransportUDP relays UDP datagrams over DATAGRAM frames.
// Each datagram is wrapped as [ATYP][ADDR][PORT][LEN][DATA] (same layout
// as the TCP bearer) and sent unreliably; inbound datagrams are parsed
// and written back. There is no connection semantic: the relay ends when
// either direction's copy loop returns.
func (c *Client) processUDPTransportUDP(ctx context.Context, link *transport.Link, mgr *udpStreamManager, target net.Destination, timer *signal.ActivityTimer) error {
	sid := mgr.allocSID()
	if sid == 0 {
		return errors.New("mist udp: no free stream ID")
	}
	dgramCh := mgr.registerDatagram(sid)
	defer mgr.unregisterDatagram(sid)

	uplinkDone := func() error {
		defer timer.SetTimeout(300 * time.Second)
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			if err != nil {
				return err
			}
			for _, b := range mb {
				dgram, derr := buildUDPDatagram(target, b.Bytes())
				b.Release()
				if derr != nil {
					return derr
				}
				if len(dgram) > MaxUDPPlaintext-4 {
					errors.LogDebug(ctx, "mist udp: dropping oversized datagram: ", len(dgram))
					continue
				}
				if serr := mgr.sendFrames([][]byte{EncodeUDPFrame(UDPFrameDatagram, sid, dgram)}); serr != nil {
					return serr
				}
				timer.Update()
			}
		}
	}
	downlinkDone := func() error {
		defer timer.SetTimeout(300 * time.Second)
		for {
			select {
			case dgram, ok := <-dgramCh:
				if !ok {
					return errors.New("mist udp: datagram channel closed")
				}
				data, perr := parseUDPDatagram(dgram)
				if perr != nil {
					errors.LogDebug(ctx, "mist udp: dropping malformed datagram: ", perr)
					continue
				}
				b := buf.New()
				b.Write(data)
				if werr := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); werr != nil {
					b.Release()
					return werr
				}
				timer.Update()
			case <-ctx.Done():
				return ctx.Err()
			case <-mgr.doneCh:
				return errors.New("mist udp: session closed")
			}
		}
	}
	if err := task.Run(ctx, uplinkDone, downlinkDone); err != nil {
		return errors.New("mist udp: udp relay ends").Base(err)
	}
	return nil
}
