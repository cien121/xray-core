package mist

// Mist UDP client data path: stream multiplexing over a shared UDPSession.
//
// Design (per UDP-DESIGN.md v1.0 and chan's 2026-10-23 refinements):
//   - One udpStreamManager per UDPSession. It owns the receive loop and the
//     RTO timer, and routes incoming frames to streams by SID.
//   - UDPStream mirrors the TCP Stream API (Read/Write/CloseWrite/Reset/done)
//     so processUDPTransport can follow the same structure as processTCP.
//   - Half-close: a stream is recycled only when BOTH sides have closed
//     (local FIN sent + remote FIN received), or on RST / session death.
//     This avoids leaking stream state when one side half-closes.
//   - Backpressure: per-stream receive buffer is bounded (1MB). When the
//     target connection drains slowly, we stop advertising window updates,
//     so the peer's send window stalls instead of our memory growing
//     without bound. Dropped-by-overflow packets are retransmitted by the
//     peer's reliability layer.
//   - UDPPacketConn abstracts the UDP socket so tests can use an in-memory
//     pipe (sandbox blocks UDP loopback).
//
// Lock ordering (to avoid deadlock):
//   recvMu -> sendMu -> lifeMu -> flowMu. Never nest in reverse order.
//   Manager mu is leaf-level (only guards maps). sendMu (manager) is only
//   taken in sendFrames/sendAck, never while holding stream locks.

import (
	"encoding/binary"
	"io"
	stdnet "net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// UDPPacketConn is the subset of net.UDPConn used by the UDP data path.
// *stdnet.UDPConn implements it; tests use an in-memory implementation.
type UDPPacketConn interface {
	ReadFromUDP(b []byte) (n int, addr *stdnet.UDPAddr, err error)
	WriteToUDP(b []byte, addr *stdnet.UDPAddr) (n int, err error)
	Close() error
	SetReadDeadline(t time.Time) error
	SetDeadline(t time.Time) error
	LocalAddr() stdnet.Addr
}

// udpStreamRecvBufMax bounds per-stream receive buffering (backpressure).
// When full, inbound STREAM data is dropped (peer retransmits) and window
// updates are withheld until the app drains the buffer.
const udpStreamRecvBufMax = 1 << 20 // 1MB

// udpStreamInitialWindow is the initial per-stream send window advertised
// to the peer (matches UDPStreamWindowInitial in the reliability layer).
const udpStreamInitialWindow = 256 * 1024 // 256KB

// ---------------------------------------------------------------------------
// udpStreamManager
// ---------------------------------------------------------------------------

// udpStreamManager multiplexes proxy streams over one UDPSession.
// It is shared by all concurrent Process calls using UDP transport.
type udpStreamManager struct {
	sess *UDPSession
	conn UDPPacketConn
	peer *stdnet.UDPAddr // server address for WriteToUDP

	mu      sync.Mutex
	streams map[byte]*UDPStream
	dgrams  map[byte]chan []byte // SID -> inbound DATAGRAM channel (UDP relay)
	nextSID byte

	sendMu sync.Mutex // serializes sendAck (data goes via scheduler)

	sched *UDPSendScheduler // centralized pacing + cwnd gate for data

	doneCh chan struct{}
	wg     sync.WaitGroup

	// onSendFrames is a test hook called with frames before sealing.
	onSendFrames func(frames [][]byte)
}

// newUDPStreamManager creates the manager and starts its loops.
// The caller must call Close when the session is torn down.
func newUDPStreamManager(sess *UDPSession, conn UDPPacketConn, peer *stdnet.UDPAddr) *udpStreamManager {
	m := &udpStreamManager{
		sess:    sess,
		conn:    conn,
		peer:    peer,
		streams: make(map[byte]*UDPStream),
		dgrams:  make(map[byte]chan []byte),
		doneCh:  make(chan struct{}),
		nextSID: 1,
	}
	// Centralized send scheduler: pacing + cwnd gate (replaces WaitForPacing).
	m.sched = NewUDPSendScheduler(sess, udpDirC2S, func(pkt []byte) error {
		_, err := conn.WriteToUDP(pkt, peer)
		return err
	})
	m.sched.Start()
	// Wire reliability callbacks.
	if sess.Rel != nil {
		sess.Rel.OnRetransmit = func(frames [][]byte) error {
			// Errors propagate: CheckRTO keeps the old sentPackets
			// entries and retries instead of silently dropping data.
			return m.sched.WriteRetransmitChunked(frames)
		}
		sess.Rel.OnAckNeeded = func(largest uint32, ranges [][2]uint32) {
			m.sendAck(largest, ranges)
		}
	}
	m.wg.Add(2)
	go m.recvLoop()
	go m.rtoLoop()
	return m
}

// Close shuts down the manager: stops loops, fails all streams.
func (m *udpStreamManager) Close() {
	select {
	case <-m.doneCh:
		return
	default:
		close(m.doneCh)
	}
	m.wg.Wait()
	if m.sched != nil {
		m.sched.Stop()
	}
	m.mu.Lock()
	for _, st := range m.streams {
		st.onSessionDead()
	}
	m.streams = make(map[byte]*UDPStream)
	for _, ch := range m.dgrams {
		close(ch)
	}
	m.dgrams = make(map[byte]chan []byte)
	m.mu.Unlock()
}

// allocSID allocates a stream ID (1-255). Returns 0 if exhausted.
func (m *udpStreamManager) allocSID() byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := 0; i < 255; i++ {
		sid := m.nextSID
		m.nextSID++
		if m.nextSID == 0 {
			m.nextSID = 1
		}
		if _, ok := m.streams[sid]; !ok {
			if _, ok := m.dgrams[sid]; !ok {
				return sid
			}
		}
	}
	return 0
}

// openStream creates a new proxy stream. Returns nil if IDs are exhausted.
func (m *udpStreamManager) openStream() *UDPStream {
	sid := m.allocSID()
	if sid == 0 {
		return nil
	}
	st := newUDPStream(sid, m)
	m.mu.Lock()
	m.streams[sid] = st
	m.mu.Unlock()
	return st
}

// maybeStreamDone recycles the stream if both directions are done.
// Must not be called while holding any stream lock.
func (m *udpStreamManager) maybeStreamDone(st *UDPStream) {
	if st.bothDone() {
		st.cleanup()
		m.mu.Lock()
		if cur, ok := m.streams[st.sid]; ok && cur == st {
			delete(m.streams, st.sid)
		}
		m.mu.Unlock()
	}
}

// registerDatagram registers an inbound DATAGRAM channel for UDP relay.
func (m *udpStreamManager) registerDatagram(sid byte) chan []byte {
	ch := make(chan []byte, 64)
	m.mu.Lock()
	m.dgrams[sid] = ch
	m.mu.Unlock()
	return ch
}

// unregisterDatagram removes a DATAGRAM registration.
func (m *udpStreamManager) unregisterDatagram(sid byte) {
	m.mu.Lock()
	if ch, ok := m.dgrams[sid]; ok {
		delete(m.dgrams, sid)
		close(ch)
	}
	m.mu.Unlock()
}

// sendFrames seals and transmits frames (tracked for reliability).
// Frames are chunked so no packet exceeds MaxUDPPlaintext; oversized
// batches (e.g., from RTO retransmit) are split across multiple packets
// instead of being silently dropped by SealPacket.
func (m *udpStreamManager) sendFrames(frames [][]byte) error {
	if m.onSendFrames != nil {
		m.onSendFrames(frames)
	}
	// Via scheduler: pacing + cwnd gate, chunked to MaxUDPPlaintext.
	// (Scheduler replaces the old WaitForPacing + direct SealPacket path;
	// do NOT add pacing here, it would pace twice.)
	return m.sched.Write(frames)
}

// sendAck transmits an ACK frame (untracked: ACKs are never retransmitted
// and don't consume congestion window).
func (m *udpStreamManager) sendAck(largest uint32, ranges [][2]uint32) {
	m.sendMu.Lock()
	defer m.sendMu.Unlock()
	ack := EncodeAckFrame(0, largest, ranges)
	pkt, err := m.sess.SealPacketUntracked(udpDirC2S, [][]byte{ack})
	if err != nil {
		return
	}
	_, _ = m.conn.WriteToUDP(pkt, m.peer)
}

// recvLoop reads datagrams, decrypts, and routes frames.
func (m *udpStreamManager) recvLoop() {
	defer m.wg.Done()
	buf := make([]byte, 2048)
	for {
		select {
		case <-m.doneCh:
			return
		default:
		}
		_ = m.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(stdnet.Error); ok && ne.Timeout() {
				continue
			}
			// Conn closed or fatal: tear everything down.
			// Close() is idempotent; avoid double-close via select.
			select {
			case <-m.doneCh:
			default:
				m.Close()
			}
			return
		}
		if n < QUICShortHeaderLen {
			continue
		}
		// Open without ACKing: the ACK is withheld if any STREAM frame
		// is dropped due to receive-buffer overflow, so the peer
		// retransmits instead of the data being silently lost.
		frames, pktNum, err := m.sess.OpenPacketNoAck(udpDirS2C, buf[:n])
		if err != nil {
			continue // decrypt/auth failed: silent drop
		}
		ackPacket := true
		for _, f := range frames {
			if !m.handleFrame(f) {
				// STREAM data dropped (buffer overflow): do NOT ACK
				// this packet; the peer must retransmit.
				ackPacket = false
			}
		}
		if ackPacket {
			m.sess.MarkPacketReceived(pktNum)
		}
		// else: packet not marked; peer's RTO will retransmit.
	}
}

// rtoLoop periodically checks for retransmission timeouts.
func (m *udpStreamManager) rtoLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-m.doneCh:
			return
		case <-ticker.C:
			m.sess.Tick() // RTO check -> OnRetransmit -> scheduler
		}
	}
}

// handleFrame routes one decoded frame. Never holds manager mu across
// stream callbacks.
//
// Returns false if a STREAM frame was dropped due to receive-buffer
// overflow. The caller must withhold the packet ACK in that case, so the
// peer retransmits (packet-level ACK + stream-level drop = permanent loss).
func (m *udpStreamManager) handleFrame(f UDPFrame) bool {
	switch f.Type {
	case UDPFramePadding:
		return true // skip
	case UDPFrameStream:
		if len(f.Payload) < 8 {
			return true
		}
		offset := binary.BigEndian.Uint64(f.Payload[:8])
		data := f.Payload[8:]
		st := m.getStream(f.SID)
		if st == nil {
			// Unknown stream: tell peer to drop its state.
			_ = m.sendFrames([][]byte{EncodeUDPFrame(UDPFrameRst, f.SID, nil)})
			return true
		}
		return st.onStreamData(offset, data)
	case UDPFrameFin:
		if len(f.Payload) < 8 {
			return true
		}
		finalSize := binary.BigEndian.Uint64(f.Payload[:8])
		if st := m.getStream(f.SID); st != nil {
			st.onRemoteFin(finalSize)
		}
		return true
	case UDPFrameRst:
		if st := m.getStream(f.SID); st != nil {
			st.onReset()
		}
		return true
	case UDPFrameAck:
		largest, ranges, err := DecodeAckFrame(f.Payload)
		if err != nil {
			return true
		}
		if m.sess.Rel != nil {
			m.sess.Rel.ProcessAck(largest, ranges)
		}
		return true
	case UDPFramePing:
		_ = m.sendFrames([][]byte{EncodeUDPFrame(UDPFramePong, 0, nil)})
		return true
	case UDPFramePong:
		return true // ignore (could feed RTT)
	case UDPFrameMaxStreamData, UDPFrameWindowUpdate:
		if len(f.Payload) < 8 {
			return true
		}
		maxOffset := binary.BigEndian.Uint64(f.Payload[:8])
		if st := m.getStream(f.SID); st != nil {
			st.onPeerWindow(maxOffset)
		}
		return true
	case UDPFrameDatagram:
		m.mu.Lock()
		ch := m.dgrams[f.SID]
		m.mu.Unlock()
		if ch != nil {
			select {
			case ch <- f.Payload:
			default:
				// Receiver slow: drop (UDP has no delivery guarantee).
			}
		}
		return true
	case UDPFrameSyn:
		// Server never initiates streams in the client role; ignore.
		return true
	case UDPFrameMigrate, UDPFramePathChallenge, UDPFramePathResponse:
		// Path validation is server-driven; client role ignores for now.
		return true
	default:
		return true
	}
}

func (m *udpStreamManager) getStream(sid byte) *UDPStream {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streams[sid]
}

// ---------------------------------------------------------------------------
// UDPStream
// ---------------------------------------------------------------------------

// UDPStream is one proxy stream over the shared UDPSession.
// API mirrors the TCP Stream (Read/Write/CloseWrite/Reset/done) so the
// outbound data path follows the same structure.
type UDPStream struct {
	sid byte
	mgr *udpStreamManager

	// Receive reassembly (guarded by recvMu).
	recvMu       sync.Mutex
	recvBuf      map[uint64][]byte // out-of-order chunks keyed by offset
	recvNext     uint64            // next expected offset
	recvReady    chan []byte       // in-order chunks for Read
	recvClosed   bool              // recvReady closed after clean FIN drain
	recvCloseOnce sync.Once
	recvBuffered int    // bytes held in recvBuf + recvReady + cur
	cur          []byte // partial chunk for Read
	remoteFin    bool
	finSize      uint64

	// Send state (guarded by sendMu).
	sendMu     sync.Mutex
	sendOffset uint64 // total bytes sent (STREAM offsets)
	peerMax    uint64 // max offset peer allows (flow control)
	peerWinCh  chan struct{}
	localFin   bool

	// Receive flow control / backpressure (guarded by flowMu).
	flowMu         sync.Mutex
	flowRecvOff    uint64 // total bytes delivered to app
	flowAdvertised uint64 // window currently advertised to peer
	updatePending  bool   // WINDOW_UPDATE withheld due to full buffer

	// Lifecycle (guarded by lifeMu).
	lifeMu   sync.Mutex
	dead     bool // fully recycled
	rst      bool // reset (local or remote)
	sessDead bool // session torn down
	doneCh   chan struct{}
}

func newUDPStream(sid byte, mgr *udpStreamManager) *UDPStream {
	return &UDPStream{
		sid:            sid,
		mgr:            mgr,
		recvBuf:        make(map[uint64][]byte),
		recvReady:      make(chan []byte, 64),
		peerMax:        udpStreamInitialWindow,
		peerWinCh:      make(chan struct{}, 1),
		flowAdvertised: udpStreamInitialWindow,
		doneCh:         make(chan struct{}),
	}
}

// bothDone reports whether the stream is fully finished: both directions
// closed, or reset, or session dead. Only then may it be recycled.
func (s *UDPStream) bothDone() bool {
	// Take locks in order: recvMu -> sendMu -> lifeMu.
	s.recvMu.Lock()
	rf := s.remoteFin
	s.recvMu.Unlock()
	s.sendMu.Lock()
	lf := s.localFin
	s.sendMu.Unlock()
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	return (lf && rf) || s.rst || s.sessDead || s.dead
}

func (s *UDPStream) isDead() bool {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	return s.dead || s.rst || s.sessDead
}

// closeRecvReady closes the receive channel exactly once (clean EOF path).
func (s *UDPStream) closeRecvReady() {
	s.recvMu.Lock()
	s.recvClosed = true
	s.recvMu.Unlock()
	s.recvCloseOnce.Do(func() { close(s.recvReady) })
}

// Read implements io.Reader. Returns io.EOF after the remote FIN is
// received and all preceding data is drained.
func (s *UDPStream) Read(p []byte) (int, error) {
	if len(s.cur) > 0 {
		n := copy(p, s.cur)
		s.cur = s.cur[n:]
		s.accountRead(n)
		return n, nil
	}
	for {
		select {
		case chunk, ok := <-s.recvReady:
			if !ok {
				return 0, io.EOF
			}
			s.cur = chunk
			n := copy(p, s.cur)
			s.cur = s.cur[n:]
			s.accountRead(n)
			return n, nil
		case <-s.doneCh:
			if s.wasReset() {
				return 0, s.getErr()
			}
			// Clean shutdown: drain any last chunk, else EOF.
			if len(s.cur) > 0 {
				n := copy(p, s.cur)
				s.cur = s.cur[n:]
				s.accountRead(n)
				return n, nil
			}
			return 0, io.EOF
		case <-s.mgr.doneCh:
			return 0, errors.New("mist udp: session closed")
		}
	}
}

func (s *UDPStream) wasReset() bool {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	return s.rst
}

func (s *UDPStream) getErr() error {
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	if s.rst {
		return errors.New("mist udp: stream reset")
	}
	if s.sessDead {
		return errors.New("mist udp: session closed")
	}
	return errors.New("mist udp: stream closed")
}

// accountRead tracks consumed bytes for receive flow control.
//
// Backpressure: WINDOW_UPDATE is withheld while the buffer is more than
// half full; a pending update is flushed once it drains below a quarter.
// This stops the peer's send window from advancing when the app drains
// slowly, instead of buffering without bound.
func (s *UDPStream) accountRead(n int) {
	if n <= 0 {
		return
	}
	s.recvMu.Lock()
	s.recvBuffered -= n
	if s.recvBuffered < 0 {
		s.recvBuffered = 0
	}
	buffered := s.recvBuffered
	s.recvMu.Unlock()

	s.flowMu.Lock()
	s.flowRecvOff += uint64(n)
	shouldUpdate := false
	var newWindow uint64
	// Advertise more window when half the current window is consumed.
	if s.flowRecvOff >= s.flowAdvertised/2 {
		if buffered < udpStreamRecvBufMax/2 {
			s.flowAdvertised = s.flowRecvOff + udpStreamInitialWindow
			s.updatePending = false
			shouldUpdate = true
		} else {
			// Backpressure: withhold the update; peer stalls.
			s.updatePending = true
		}
	} else if s.updatePending && buffered < udpStreamRecvBufMax/4 {
		// Buffer drained enough: flush the withheld update.
		s.flowAdvertised = s.flowRecvOff + udpStreamInitialWindow
		s.updatePending = false
		shouldUpdate = true
	}
	newWindow = s.flowAdvertised
	s.flowMu.Unlock()

	if shouldUpdate {
		upd := EncodeUDPFrame(UDPFrameWindowUpdate, s.sid, uint64Bytes(newWindow))
		_ = s.mgr.sendFrames([][]byte{upd})
	}
}

// Write implements io.Writer: chunks into STREAM frames honoring the
// peer's flow-control window. Blocks when the window is exhausted.
func (s *UDPStream) Write(p []byte) (int, error) {
	s.sendMu.Lock()
	if s.localFin {
		s.sendMu.Unlock()
		return 0, errors.New("mist udp: write after FIN")
	}
	s.sendMu.Unlock()
	if s.isDead() {
		return 0, s.getErr()
	}

	total := 0
	for len(p) > 0 {
		// Wait for flow-control window.
		for {
			s.sendMu.Lock()
			avail := int64(s.peerMax) - int64(s.sendOffset)
			fin := s.localFin
			s.sendMu.Unlock()
			if fin || s.isDead() {
				if total > 0 {
					return total, nil
				}
				return 0, s.getErr()
			}
			if avail > 0 {
				break
			}
			select {
			case <-s.peerWinCh:
			case <-s.doneCh:
				if total > 0 {
					return total, nil
				}
				return 0, s.getErr()
			case <-s.mgr.doneCh:
				return total, errors.New("mist udp: session closed")
			}
		}

		s.sendMu.Lock()
		avail := int64(s.peerMax) - int64(s.sendOffset)
		if avail <= 0 {
			s.sendMu.Unlock()
			continue
		}
		// Chunk to fit one datagram: frame overhead = 4 (frame hdr) + 8 (offset).
		maxChunk := MaxUDPPlaintext - 12
		n := int64(len(p))
		if n > avail {
			n = avail
		}
		if n > int64(maxChunk) {
			n = int64(maxChunk)
		}
		offset := s.sendOffset
		chunk := p[:n]
		s.sendOffset += uint64(n)
		s.sendMu.Unlock()

		frame := EncodeStreamFrame(s.sid, offset, chunk)
		if err := s.mgr.sendFrames([][]byte{frame}); err != nil {
			return total, err
		}
		total += int(n)
		p = p[n:]
	}
	return total, nil
}

// CloseWrite sends FIN (half-close). Idempotent. The read side stays open
// until the peer's FIN arrives; the stream is recycled only when both
// directions are done.
func (s *UDPStream) CloseWrite() error {
	s.sendMu.Lock()
	if s.localFin {
		s.sendMu.Unlock()
		return nil
	}
	s.localFin = true
	finalSize := s.sendOffset
	s.sendMu.Unlock()

	fin := EncodeFinFrame(s.sid, finalSize)
	// Best effort: if the session is dying the FIN is moot anyway.
	_ = s.mgr.sendFrames([][]byte{fin})
	// Wake any blocked writers so they observe localFin.
	select {
	case s.peerWinCh <- struct{}{}:
	default:
	}
	s.mgr.maybeStreamDone(s)
	return nil
}

// Reset sends RST and releases the stream immediately.
func (s *UDPStream) Reset() {
	_ = s.mgr.sendFrames([][]byte{EncodeUDPFrame(UDPFrameRst, s.sid, nil)})
	s.lifeMu.Lock()
	s.rst = true
	s.lifeMu.Unlock()
	s.cleanup()
	s.mgr.maybeStreamDone(s)
}

// done releases the stream. If it did not terminate cleanly (local FIN
// sent AND remote FIN received), an RST is sent first so the peer drops
// its state promptly. Mirrors the TCP Stream.done semantics.
func (s *UDPStream) done() {
	s.recvMu.Lock()
	rf := s.remoteFin
	s.recvMu.Unlock()
	s.sendMu.Lock()
	lf := s.localFin
	s.sendMu.Unlock()
	s.lifeMu.Lock()
	rst := s.rst
	s.lifeMu.Unlock()
	if !rst && !(lf && rf) {
		_ = s.mgr.sendFrames([][]byte{EncodeUDPFrame(UDPFrameRst, s.sid, nil)})
	}
	s.cleanup()
	s.mgr.maybeStreamDone(s)
}

// cleanup releases stream resources (idempotent). It does NOT close
// recvReady: a clean FIN already closed it via closeRecvReady; on reset
// or session death, readers are woken via doneCh and observe the error.
func (s *UDPStream) cleanup() {
	s.lifeMu.Lock()
	if s.dead {
		s.lifeMu.Unlock()
		return
	}
	s.dead = true
	s.lifeMu.Unlock()
	// Wake blocked readers/writers.
	select {
	case s.peerWinCh <- struct{}{}:
	default:
	}
	func() {
		defer func() { _ = recover() }()
		close(s.doneCh)
	}()
	s.recvMu.Lock()
	s.recvBuf = nil
	s.cur = nil
	s.recvMu.Unlock()
}

func (s *UDPStream) onSessionDead() {
	s.lifeMu.Lock()
	s.sessDead = true
	s.lifeMu.Unlock()
	s.cleanup()
}

// onStreamData handles an inbound STREAM frame (called by recvLoop).
// Reassembles by OFFSET; out-of-order chunks are buffered.
//
// Returns false if the data was dropped due to receive-buffer overflow.
// In that case the caller must NOT ACK the packet, so the peer
// retransmits (packet-level ACK + stream-level drop = permanent loss).
func (s *UDPStream) onStreamData(offset uint64, data []byte) bool {
	s.recvMu.Lock()
	if s.recvClosed {
		s.recvMu.Unlock()
		return true // already closed: not an overflow drop
	}
	// Backpressure: bound the buffer. Drop overflow; the peer's
	// reliability layer will retransmit after RTO (because we withhold
	// the packet ACK — see recvLoop).
	if s.recvBuffered+len(data) > udpStreamRecvBufMax {
		s.recvMu.Unlock()
		return false
	}
	// Trim overlap with already-delivered data.
	if offset < s.recvNext {
		skip := s.recvNext - offset
		if skip >= uint64(len(data)) {
			s.recvMu.Unlock()
			return true // fully duplicate: already delivered, safe to ACK
		}
		data = data[skip:]
		offset = s.recvNext
	}
	// Enforce FIN boundary: ignore data beyond FINAL_SIZE.
	if s.remoteFin && offset+uint64(len(data)) > s.finSize {
		if offset >= s.finSize {
			s.recvMu.Unlock()
			return true
		}
		data = data[:s.finSize-offset]
	}

	var toDeliver [][]byte
	if offset == s.recvNext {
		toDeliver = append(toDeliver, data)
		s.recvNext += uint64(len(data))
		s.recvBuffered += len(data)
		// Drain contiguous buffered chunks.
		for {
			buf, ok := s.recvBuf[s.recvNext]
			if !ok {
				break
			}
			delete(s.recvBuf, s.recvNext)
			toDeliver = append(toDeliver, buf)
			s.recvNext += uint64(len(buf))
			s.recvBuffered += len(buf)
		}
	} else if offset > s.recvNext {
		// Out-of-order: buffer (copy; caller reuses the slice).
		if _, ok := s.recvBuf[offset]; !ok {
			cp := make([]byte, len(data))
			copy(cp, data)
			s.recvBuf[offset] = cp
			s.recvBuffered += len(data)
		}
	}
	// else: offset < recvNext fully handled by trim above.
	finComplete := s.remoteFin && s.recvNext >= s.finSize
	s.recvMu.Unlock()

	for _, d := range toDeliver {
		select {
		case s.recvReady <- d:
		case <-s.doneCh:
			return true
		case <-s.mgr.doneCh:
			return true
		}
	}
	if finComplete {
		s.closeRecvReady()
		s.mgr.maybeStreamDone(s)
	}
	return true
}

// onRemoteFin handles an inbound FIN frame.
func (s *UDPStream) onRemoteFin(finalSize uint64) {
	s.recvMu.Lock()
	if s.remoteFin {
		s.recvMu.Unlock()
		return
	}
	s.remoteFin = true
	s.finSize = finalSize
	complete := s.recvNext >= finalSize
	s.recvMu.Unlock()
	if complete {
		s.closeRecvReady()
	}
	s.mgr.maybeStreamDone(s)
}

// onReset handles an inbound RST frame.
func (s *UDPStream) onReset() {
	s.lifeMu.Lock()
	s.rst = true
	s.lifeMu.Unlock()
	s.cleanup()
	s.mgr.maybeStreamDone(s)
}

// onPeerWindow handles MAX_STREAM_DATA / WINDOW_UPDATE from the peer.
func (s *UDPStream) onPeerWindow(maxOffset uint64) {
	increased := false
	s.sendMu.Lock()
	if maxOffset > s.peerMax {
		s.peerMax = maxOffset
		increased = true
	}
	s.sendMu.Unlock()
	if increased && s.mgr != nil && s.mgr.sess.Rel != nil {
		// The peer drained its receive buffer: any RTO backoff that
		// accumulated while our packets' ACKs were withheld was
		// receiver-induced, not congestion. Reset it so the retransmit
		// of the dropped data happens promptly instead of waiting out
		// the inflated backoff.
		s.mgr.sess.Rel.ResetRTOBackoff()
		// Kick an immediate RTO check rather than waiting for the
		// 20ms ticker, so recovery starts without delay.
		s.mgr.sess.Rel.CheckRTO()
	}
	select {
	case s.peerWinCh <- struct{}{}:
	default:
	}
}

// uint64Bytes encodes a uint64 big-endian (for flow-control frames).
func uint64Bytes(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}
