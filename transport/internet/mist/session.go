package mist

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// sessionParams carries everything needed to (re)build a session.
type sessionParams struct {
	cid     [16]byte
	kAuth   [32]byte
	hb      time.Duration
	shaping shapingParams
}

// Shaping parameters, SPEC 8 / appendix B.2. Only heavyPackets is
// configurable in v0.1; the rest follow the appendix defaults.
type shapingParams struct {
	heavyPackets uint32 // frames with heavy shaping, per direction
	padMin       int
	padMax       int
	jitterMaxMs  int
	tailPad      int
}

// Session is one Mist session: a TLS connection carrying multiplexed
// encrypted frames (SPEC 7/9/10). Client side only.
//
// Transport-layer note: the server side (server.go) reuses this type as
// the Stream host, with keys remapped to the server's perspective and
// writeDir set to dirS2C (see newServerSession). This is a mechanical
// reuse — the wire format is unchanged: the client always writes with
// writeDir == dirC2S, exactly as before.
type Session struct {
	conn net.Conn
	cfg  sessionParams

	kC2S      [32]byte
	kS2C      [32]byte
	connID    [16]byte
	resumeTok [32]byte
	epoch     uint32

	c2sCtr    uint32 // atomic: next C2S frame counter
	s2cCtr    uint32 // atomic: next expected S2C frame counter
	heavySent uint32 // atomic: C2S frames already sent (shaping count)

	// writeDir is the nonce direction word used for written frames:
	// dirC2S for the client, dirS2C for the server-side reuse. It is the
	// only client/server difference in the write path; everything else
	// (shaping, counters, Stream flow control) is shared verbatim.
	writeDir uint32

	writeMu sync.Mutex // serializes all frame writes on conn

	mu      sync.Mutex
	streams map[byte]*Stream
	nextSID byte // 1..15 round-robin

	pingMu       sync.Mutex
	pendingPings map[[8]byte]chan struct{}

	doneCh    chan struct{}
	closeOnce sync.Once

	ctx    context.Context
	cancel context.CancelFunc
}

func newSession(conn net.Conn, cfg sessionParams) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{
		conn:         conn,
		cfg:          cfg,
		writeDir:     dirC2S,
		streams:      make(map[byte]*Stream),
		nextSID:      1,
		pendingPings: make(map[[8]byte]chan struct{}),
		doneCh:       make(chan struct{}),
		ctx:          ctx,
		cancel:       cancel,
	}
}

func (s *Session) alive() bool {
	select {
	case <-s.doneCh:
		return false
	default:
		return true
	}
}

// close shuts the session down exactly once: all streams die, the read
// loop and heartbeat loop exit, the connection is closed.
func (s *Session) close() {
	s.closeOnce.Do(func() {
		s.cancel()
		close(s.doneCh)
		s.conn.Close()
		s.mu.Lock()
		for _, st := range s.streams {
			st.closeOnce.Do(func() { close(st.deadCh) })
		}
		s.mu.Unlock()
	})
}

// start launches the frame read loop and the heartbeat loop.
func (s *Session) start() {
	go s.readLoop()
	go s.heartbeatLoop()
}

// ---- handshake ----

// doAuth performs the full AUTH handshake on an already-TLS-established
// conn (SPEC 6.1/6.2/6.3/6.4). Returns the established session.
func doAuth(conn net.Conn, cfg sessionParams) (*Session, error) {
	wire, ephPriv, ephPub, err := buildAuth(cfg.cid, cfg.kAuth, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(wire); err != nil {
		zeroBytes(ephPriv)
		return nil, errors.New("mist: failed to send AUTH").Base(err)
	}
	resp := make([]byte, authOKWireLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		zeroBytes(ephPriv)
		return nil, errors.New("mist: authentication failed: no AUTH_OK from server (wrong client id/key, or server is not Mist)").Base(err)
	}
	info, err := parseAuthOK(resp, cfg.kAuth)
	if err != nil {
		zeroBytes(ephPriv)
		return nil, err
	}
	kC2S, kS2C, err := deriveSessionKeys(ephPriv, info.serverEphPub[:], ephPub, info.serverEphPub[:])
	if err != nil {
		return nil, err
	}
	sess := newSession(conn, cfg)
	sess.kC2S = kC2S
	sess.kS2C = kS2C
	sess.connID = info.connID
	sess.resumeTok = info.resumeTok
	sess.epoch = 0
	if info.heartbeatSec >= 10 && info.heartbeatSec <= 120 {
		sess.cfg.hb = time.Duration(info.heartbeatSec) * time.Second
	}
	sess.start()
	return sess, nil
}

// resume attempts a session migration over a fresh TLS connection using the
// old session's keys (SPEC 10.2/10.3, A.4). The RESUME frame is encrypted
// with the old keys under the OLD epoch and the old session's next C2S
// counter; the server's RESUME_OK is expected under the NEW epoch, S2C
// direction, counter 0 — after a disconnect the client cannot know any
// old-epoch S2C counter value, so the new epoch is the only
// self-consistent choice (the server implementation must match this).
func (old *Session) resume(conn net.Conn) (*Session, error) {
	newEpoch := old.epoch + 1
	ns := newSession(conn, old.cfg)
	ns.kC2S = old.kC2S
	ns.kS2C = old.kS2C
	ns.connID = old.connID
	ns.resumeTok = old.resumeTok

	body := buildResumeBody(old.connID, old.resumeTok, newEpoch)
	ctr := atomic.AddUint32(&old.c2sCtr, 1) - 1
	if ctr >= 0x7FFFFFFF {
		ns.close()
		return nil, errors.New("mist: nonce counter exhausted")
	}
	if err := ns.writeFrameEpoch(old.epoch, 0x00, body, &ctr); err != nil {
		ns.close()
		return nil, errors.New("mist: failed to send RESUME").Base(err)
	}
	sidFlags, pt, err := readRawFrame(conn, ns.kS2C[:], newEpoch, dirS2C, 0)
	if err != nil {
		ns.close()
		return nil, errors.New("mist: resume failed: no RESUME_OK").Base(err)
	}
	if sidFlags&0x0F != 0 || len(pt) < 5 || pt[0] != ctrlResumeOK {
		ns.close()
		return nil, errors.New("mist: resume rejected by server, falling back to full auth")
	}
	if got := binary.BigEndian.Uint32(pt[1:5]); got != newEpoch {
		ns.close()
		return nil, errors.New("mist: resume epoch mismatch")
	}
	ns.epoch = newEpoch
	ns.start()
	return ns, nil
}

// ---- frame IO with shaping ----

// nextC2SCtr allocates the next C2S nonce counter value. Values are never
// reused: at the 2^31-1 ceiling the session is killed so the client is
// forced to re-authenticate (SPEC 7.2).
func (s *Session) nextC2SCtr() (uint32, error) {
	ctr := atomic.AddUint32(&s.c2sCtr, 1) - 1
	if ctr >= 0x7FFFFFFF {
		s.close()
		return 0, errors.New("mist: nonce counter exhausted, session must re-authenticate")
	}
	return ctr, nil
}

// writeOneFrameLocked seals and sends exactly one frame. Caller holds writeMu.
func (s *Session) writeOneFrameLocked(epoch, ctr uint32, sidFlags byte, plaintext []byte) error {
	heavy := atomic.AddUint32(&s.heavySent, 1) <= s.cfg.shaping.heavyPackets
	// SPEC appendix B.2: light-phase PLEN = rand(0, tailPad). A fixed
	// padLen would be a writable rule signature; the wire format is
	// unchanged (still a single PLEN byte, padding bytes stay CSPRNG
	// inside sealFrame).
	padLen := randIntN(s.cfg.shaping.tailPad + 1)
	delayMs, fragment := 0, false
	if heavy {
		// SPEC 8.2: random padding, pre-send jitter, irregular fragmentation.
		padLen = s.cfg.shaping.padMin + randIntN(s.cfg.shaping.padMax-s.cfg.shaping.padMin+1)
		delayMs = randIntN(s.cfg.shaping.jitterMaxMs + 1)
		fragment = true
	}
	// PLEN is a single byte on the wire (SPEC 7.1); clamp to 255.
	// (Coordinator: appendix B "64-1400" range cannot be honored beyond 255.)
	if padLen > 255 {
		padLen = 255
	}
	if len(plaintext) > maxPlainPerFrameBase-padLen {
		return errors.New("mist: single frame payload too large")
	}
	frame, err := sealFrame(s.kC2S[:], epoch, s.writeDir, ctr, sidFlags, plaintext, padLen)
	if err != nil {
		s.close()
		return err
	}
	if delayMs > 0 {
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}
	if err := writeFragmented(s.conn, frame, fragment); err != nil {
		s.close()
		return errors.New("mist: frame write failed").Base(err)
	}
	return nil
}

// writeFragmented writes a frame, optionally split into irregular chunks
// (SPEC 8.2 heavy phase).
func writeFragmented(conn net.Conn, frame []byte, fragment bool) error {
	if !fragment || len(frame) <= 1 {
		_, err := conn.Write(frame)
		return err
	}
	for len(frame) > 0 {
		n := 1 + randIntN(minInt(len(frame), 1460))
		if _, err := conn.Write(frame[:n]); err != nil {
			return err
		}
		frame = frame[n:]
	}
	return nil
}

// writeFrame encrypts plaintext (chunked across frames if needed) and sends
// it under the session epoch. Every frame consumes a fresh C2S counter —
// nonces are never reused.
func (s *Session) writeFrame(sidFlags byte, plaintext []byte) error {
	return s.writeFrameEpoch(s.epoch, sidFlags, plaintext, nil)
}

// writeFrameEpoch is writeFrame with an explicit epoch; when fixedCtr is
// non-nil the (single-frame) payload uses that counter value instead of
// allocating a new one. Used by the RESUME handshake.
func (s *Session) writeFrameEpoch(epoch uint32, sidFlags byte, plaintext []byte, fixedCtr *uint32) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if !s.alive() {
		return errors.New("mist: session closed")
	}
	if fixedCtr != nil {
		if len(plaintext) > maxPlainPerFrameBase-defaultShapingPadMax {
			return errors.New("mist: fixed-counter frame too large")
		}
		return s.writeOneFrameLocked(epoch, *fixedCtr, sidFlags, plaintext)
	}
	if len(plaintext) == 0 {
		ctr, err := s.nextC2SCtr()
		if err != nil {
			return err
		}
		return s.writeOneFrameLocked(epoch, ctr, sidFlags, nil)
	}
	for len(plaintext) > 0 {
		// Conservative chunk bound: worst-case heavy pad is padMax.
		chunkLen := len(plaintext)
		if maxC := maxPlainPerFrameBase - defaultShapingPadMax; chunkLen > maxC {
			chunkLen = maxC
		}
		ctr, err := s.nextC2SCtr()
		if err != nil {
			return err
		}
		if err := s.writeOneFrameLocked(epoch, ctr, sidFlags, plaintext[:chunkLen]); err != nil {
			return err
		}
		plaintext = plaintext[chunkLen:]
	}
	return nil
}

// writeControl sends one control-stream message (SID=0, SPEC 9.6).
func (s *Session) writeControl(typ byte, body []byte) error {
	msg := make([]byte, 0, 1+len(body))
	msg = append(msg, typ)
	msg = append(msg, body...)
	return s.writeFrame(0x00, msg)
}

// ---- read loop ----

func (s *Session) readLoop() {
	defer s.close()
	for s.alive() {
		ctr := atomic.AddUint32(&s.s2cCtr, 1) - 1
		sidFlags, pt, err := readRawFrame(s.conn, s.kS2C[:], s.epoch, dirS2C, ctr)
		if err != nil {
			// AEAD failure or IO error: silent close (anti-probing, SPEC B.3).
			return
		}
		s.dispatch(sidFlags, pt)
	}
}

func (s *Session) dispatch(sidFlags byte, pt []byte) {
	sid := sidFlags & 0x0F
	flags := sidFlags & 0xF0
	if sid == 0 {
		s.handleControl(pt)
		return
	}
	s.mu.Lock()
	st := s.streams[sid]
	s.mu.Unlock()
	if st == nil {
		// Unknown or already-released stream ID: ignore.
		return
	}
	if flags&flagRST != 0 {
		st.onReset()
		return
	}
	// v0.1: only the client initiates streams; a server SYN is ignored.
	if len(pt) > 0 {
		select {
		case st.inCh <- pt:
		case <-st.deadCh:
			// Stream was released/reset concurrently; drop the frame
			// instead of stalling the read loop.
		case <-s.doneCh:
			return
		}
	}
	if flags&flagFIN != 0 {
		st.onRemoteFin()
	}
}

func (s *Session) handleControl(pt []byte) {
	if len(pt) == 0 {
		return
	}
	switch pt[0] {
	case ctrlPong:
		if len(pt) < 9 {
			return
		}
		var cookie [8]byte
		copy(cookie[:], pt[1:9])
		s.pingMu.Lock()
		ch := s.pendingPings[cookie]
		delete(s.pendingPings, cookie)
		s.pingMu.Unlock()
		if ch != nil {
			close(ch)
		}
	case ctrlWindowUpdate:
		if len(pt) < 6 {
			return
		}
		sid := pt[1]
		inc := binary.BigEndian.Uint32(pt[2:6])
		s.mu.Lock()
		st := s.streams[sid]
		s.mu.Unlock()
		if st != nil {
			st.addWindow(inc)
		}
	case ctrlCloseSession:
		s.close()
	}
}

// ---- heartbeat (SPEC 10.1) ----

// heartbeatJitterFrac is the anti-targeting jitter applied to the heartbeat
// period and to the PONG timeout: every interval is drawn uniformly from
// hb*(1-frac)..hb*(1+frac) with crypto/rand as the only entropy source.
// A fixed heartbeat period is a writable rule signature (SPEC B.5). The
// "two consecutive missed PONGs = dead session" semantics (SPEC 10.1) are
// unchanged.
const heartbeatJitterFrac = 0.25

func (s *Session) heartbeatLoop() {
	hb := s.cfg.hb
	if hb <= 0 {
		hb = defaultHeartbeatSec * time.Second
	}
	missed := 0
	for {
		// Jittered inter-ping wait (replaces the old fixed time.NewTicker).
		wait := time.NewTimer(jitterDuration(hb, heartbeatJitterFrac))
		select {
		case <-s.doneCh:
			wait.Stop()
			return
		case <-wait.C:
		}
		var cookie [8]byte
		if _, err := io.ReadFull(rand.Reader, cookie[:]); err != nil {
			continue
		}
		ch := make(chan struct{})
		s.pingMu.Lock()
		s.pendingPings[cookie] = ch
		s.pingMu.Unlock()
		body := append([]byte{ctrlPing}, cookie[:]...)
		if err := s.writeFrame(0x00, body); err != nil {
			s.pingMu.Lock()
			delete(s.pendingPings, cookie)
			s.pingMu.Unlock()
			return
		}
		// Jittered PONG timeout; the death rule still counts consecutive
		// misses, so "2 missed periods -> disconnect" is preserved.
		pongWait := time.NewTimer(jitterDuration(hb, heartbeatJitterFrac))
		select {
		case <-ch:
			pongWait.Stop()
			missed = 0
		case <-pongWait.C:
			missed++
			s.pingMu.Lock()
			delete(s.pendingPings, cookie)
			s.pingMu.Unlock()
		case <-s.doneCh:
			pongWait.Stop()
			return
		}
		if missed >= 2 {
			// SPEC 10.1: two consecutive periods without PONG = dead.
			s.close()
			return
		}
	}
}

// ---- stream management & flow control ----

// openStream allocates a stream ID (1..15, SPEC 9.1) and registers the stream.
func (s *Session) openStream() (*Stream, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.alive() {
		return nil, false
	}
	for i := 0; i < 15; i++ {
		id := s.nextSID
		s.nextSID++
		if s.nextSID > 15 {
			s.nextSID = 1
		}
		if _, used := s.streams[id]; !used {
			st := newStream(s, id)
			s.streams[id] = st
			return st, true
		}
	}
	return nil, false
}

// accountRx tracks consumed inbound bytes and advertises window updates:
// every 128KB consumed, the receiver sends WINDOW_UPDATE (SPEC 9.5).
func (s *Session) accountRx(st *Stream, n int64) {
	if n <= 0 {
		return
	}
	st.mu.Lock()
	st.recvSinceUpdate += n
	if st.recvSinceUpdate < windowUpdateThreshold {
		st.mu.Unlock()
		return
	}
	inc := uint32(st.recvSinceUpdate)
	st.recvSinceUpdate = 0
	st.mu.Unlock()
	body := make([]byte, 6)
	body[0] = ctrlWindowUpdate
	body[1] = st.id
	binary.BigEndian.PutUint32(body[2:6], inc)
	_ = s.writeFrame(0x00, body) // best effort
}

// ---- helpers ----

func randIntN(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		// crypto/rand failure is effectively impossible on supported
		// platforms; degrade to 0 (unjittered/unpadded) rather than to
		// math/rand, whose deterministic output would itself be a
		// fingerprintable signature.
		return 0
	}
	return int(v.Int64())
}

// jitterDuration returns base scaled by a crypto/rand uniform factor in
// [1-frac, 1+frac]. It is the single choke point for all anti-targeting
// timer jitter in this package: no caller may substitute math/rand.
// On RNG failure it degrades to the unjittered base.
func jitterDuration(base time.Duration, frac float64) time.Duration {
	if base <= 0 || frac <= 0 {
		return base
	}
	const ppm = int64(1_000_000)
	span := int64(2*frac*float64(ppm)) + 1 // inclusive upper bound
	lo := int64((1 - frac) * float64(ppm))
	v, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return base
	}
	return time.Duration(lo+v.Int64()) * base / time.Duration(ppm)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
