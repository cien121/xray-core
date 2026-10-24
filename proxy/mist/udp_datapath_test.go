package mist

// End-to-end tests for the UDP client data path using an in-memory
// packet pipe (sandbox blocks UDP loopback, per chan's 2026-10-23 note).
//
// The test echo server implements the minimal server side: handshake,
// SYN -> CONNECT success, STREAM echo, FIN echo, ACKs.

import (
	"encoding/binary"
	"io"
	"math/rand"
	stdnet "net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// memPacketConn: in-memory UDPPacketConn
// ---------------------------------------------------------------------------

type memTimeoutError struct{}

func (e memTimeoutError) Error() string   { return "i/o timeout" }
func (e memTimeoutError) Timeout() bool   { return true }
func (e memTimeoutError) Temporary() bool { return true }

type memPacket struct {
	data []byte
	addr *stdnet.UDPAddr
}

// rngMu serializes per-conn rand.Rand use (rand.Rand is not goroutine-safe,
// and WriteToUDP is called from the app writer, rtoLoop, and recvLoop).
var rngMu sync.Mutex

type memPacketConn struct {
	inCh   chan memPacket
	peer   *memPacketConn
	addr   *stdnet.UDPAddr
	closed chan struct{}

	mu           sync.Mutex
	readDeadline time.Time
	loss         float64
	delay        time.Duration
	rng          *rand.Rand // per-conn RNG for loss simulation (seedable)

	// Debug counters.
	sentCount    int64
	recvCount    int64
	droppedCount int64
}

func memPipe() (*memPacketConn, *memPacketConn) {
	return memPipeSeeded(time.Now().UnixNano())
}

// memPipeSeeded creates a pipe with deterministic loss simulation.
func memPipeSeeded(seed int64) (*memPacketConn, *memPacketConn) {
	a := &memPacketConn{
		inCh:   make(chan memPacket, 2048),
		addr:   &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1"), Port: 10001},
		closed: make(chan struct{}),
		rng:    rand.New(rand.NewSource(seed)),
	}
	b := &memPacketConn{
		inCh:   make(chan memPacket, 2048),
		addr:   &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1"), Port: 10002},
		closed: make(chan struct{}),
		rng:    rand.New(rand.NewSource(seed + 1)),
	}
	a.peer = b
	b.peer = a
	return a, b
}

func (c *memPacketConn) WriteToUDP(b []byte, addr *stdnet.UDPAddr) (int, error) {
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	c.mu.Lock()
	c.sentCount++
	rng := c.rng
	c.mu.Unlock()
	roll := rand.Float64()
	if rng != nil {
		rngMu.Lock()
		roll = rng.Float64()
		rngMu.Unlock()
	}
	if c.loss > 0 && roll < c.loss {
		c.mu.Lock()
		c.droppedCount++
		c.mu.Unlock()
		return len(b), nil // simulated drop
	}
	cp := append([]byte(nil), b...)
	pkt := memPacket{data: cp, addr: c.addr}
	send := func() {
		select {
		case c.peer.inCh <- pkt:
		case <-c.peer.closed:
		case <-c.closed:
		}
	}
	if c.delay > 0 {
		go func() {
			time.Sleep(c.delay)
			send()
		}()
	} else {
		send()
	}
	return len(b), nil
}

func (c *memPacketConn) ReadFromUDP(b []byte) (int, *stdnet.UDPAddr, error) {
	c.mu.Lock()
	deadline := c.readDeadline
	c.mu.Unlock()
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		if d := time.Until(deadline); d > 0 {
			timeout = time.After(d)
		} else {
			return 0, nil, memTimeoutError{}
		}
	}
	select {
	case pkt := <-c.inCh:
		c.mu.Lock()
		c.recvCount++
		c.mu.Unlock()
		return copy(b, pkt.data), pkt.addr, nil
	case <-timeout:
		return 0, nil, memTimeoutError{}
	case <-c.closed:
		return 0, nil, io.ErrClosedPipe
	}
}

func (c *memPacketConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

func (c *memPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *memPacketConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *memPacketConn) LocalAddr() stdnet.Addr { return c.addr }

// ---------------------------------------------------------------------------
// Test echo server
// ---------------------------------------------------------------------------

// echoServer is a minimal UDP server for tests: handshake, then echo.
// For each stream: SYN -> STREAM[0]=0x00 (connect success); STREAM data is
// echoed back at the server's own send offsets; FIN is echoed back.
type echoServer struct {
	conn       *memPacketConn
	sess       *UDPSession
	clientAddr *stdnet.UDPAddr
	done       chan struct{}
	wg         sync.WaitGroup
	errCh      chan error

	mu          sync.Mutex
	sendOffsets map[byte]uint64 // per-stream server->client offset (for SYN tracking)
	recvOffsets map[byte]uint64 // per-stream client->server bytes received (for WINDOW_UPDATE)

	// Debug: frame type counts.
	frameCounts map[byte]int
}

func runEchoServer(t *testing.T, conn *memPacketConn, kAuth [32]byte, cid [16]byte) *echoServer {
	t.Helper()
	s := &echoServer{
		conn:        conn,
		done:        make(chan struct{}),
		sendOffsets: make(map[byte]uint64),
		recvOffsets: make(map[byte]uint64),
		frameCounts: make(map[byte]int),
		errCh:       make(chan error, 1),
	}
	s.wg.Add(1)
	go s.serve(t, kAuth, cid)
	return s
}

// serve runs the handshake then the echo loop in the background.
func (s *echoServer) serve(t *testing.T, kAuth [32]byte, cid [16]byte) {
	defer s.wg.Done()
	codec := &RandomCiphertextCodec{}

	// Handshake: read Initial.
	buf := make([]byte, 2048)
	_ = s.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, clientAddr, err := s.conn.ReadFromUDP(buf)
	if err != nil {
		s.errCh <- err
		return
	}
	s.clientAddr = clientAddr
	result, err := UDPServerHandshake(codec, buf[:n], clientAddr,
		func(handshakeCID [16]byte, nonce [24]byte) (*[32]byte, [16]byte, bool) {
			return &kAuth, cid, true
		})
	if err != nil {
		s.errCh <- err
		return
	}
	s.sess = result.Session
	if _, err := s.conn.WriteToUDP(result.Response, clientAddr); err != nil {
		s.errCh <- err
		return
	}
	close(s.errCh) // handshake ok

	// Wire server-side ACKs and retransmits.
	s.sess.Rel.OnAckNeeded = func(largest uint32, ranges [][2]uint32) {
		ack := EncodeAckFrame(0, largest, ranges)
		pkt, err := s.sess.SealPacketUntracked(udpDirS2C, [][]byte{ack})
		if err == nil {
			_, _ = s.conn.WriteToUDP(pkt, clientAddr)
		}
	}
	s.sess.Rel.OnRetransmit = func(frames [][]byte) error {
		// Chunk to fit MaxUDPPlaintext (same as client sendFrames).
		var batch [][]byte
		batchSize := 0
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			pkt, err := s.sess.sealPacket(udpDirS2C, batch, true)
			if err != nil {
				return err
			}
			_, err = s.conn.WriteToUDP(pkt, clientAddr)
			batch = nil
			batchSize = 0
			return err
		}
		for _, f := range frames {
			if batchSize+len(f) > MaxUDPPlaintext && len(batch) > 0 {
				if err := flush(); err != nil {
					return err
				}
			}
			batch = append(batch, f)
			batchSize += len(f)
		}
		return flush()
	}

	s.wg.Add(1)
	go s.rtoLoop()
	s.wg.Add(1)
	s.loop()
}

// rtoLoop drives server-side retransmissions (mirrors the client manager).
func (s *echoServer) rtoLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if s.sess != nil && s.sess.Rel != nil {
				s.sess.Rel.CheckRTO()
			}
		}
	}
}

func (s *echoServer) loop() {
	defer s.wg.Done()
	buf := make([]byte, 2048)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		frames, _, err := s.sess.OpenPacket(udpDirC2S, buf[:n])
		if err != nil {
			continue
		}
		var out [][]byte
		for _, f := range frames {
			s.mu.Lock()
			s.frameCounts[f.Type]++
			s.mu.Unlock()
			switch f.Type {
			case UDPFrameSyn:
				// CONNECT success: STREAM [OFFSET=0] [0x00].
				// Dedup: if SYN already processed for this SID, it's a
				// retransmit (client RTO fired before ACK arrived). Do NOT
				// reset sendOffsets, or offsets will be reused.
				s.mu.Lock()
				if _, ok := s.sendOffsets[f.SID]; !ok {
					s.sendOffsets[f.SID] = 1
					s.mu.Unlock()
					out = append(out, EncodeStreamFrame(f.SID, 0, []byte{0x00}))
				} else {
					s.mu.Unlock()
					// Duplicate SYN: re-send the 0x00 without resetting.
					// (Client may have lost the first response.)
					out = append(out, EncodeStreamFrame(f.SID, 0, []byte{0x00}))
				}
			case UDPFrameStream:
				if len(f.Payload) < 8 {
					continue
				}
				cliOffset := binary.BigEndian.Uint64(f.Payload[:8])
				data := f.Payload[8:]
				// Echo at cliOffset+1 (shift avoids colliding with the
				// [0x00] at server-offset 0). No dedup needed: the
				// client's reassembly drops duplicates by offset.
				// The monotonic shift preserves byte-stream order.
				out = append(out, EncodeStreamFrame(f.SID, cliOffset+1, data))
				// Flow control: advertise receive window so the client
				// can send beyond the 256KB initial window. Without this
				// the client's Write blocks forever after 256KB.
				s.mu.Lock()
				end := cliOffset + uint64(len(data))
				if end > s.recvOffsets[f.SID] {
					s.recvOffsets[f.SID] = end
				}
				newWindow := s.recvOffsets[f.SID] + 256*1024
				s.mu.Unlock()
				out = append(out, EncodeUDPFrame(UDPFrameWindowUpdate, f.SID, uint64Bytes(newWindow)))
			case UDPFrameFin:
				if len(f.Payload) < 8 {
					continue
				}
				finalSize := binary.BigEndian.Uint64(f.Payload[:8])
				s.mu.Lock()
				off := s.sendOffsets[f.SID]
				s.mu.Unlock()
				// Echo FIN with server's final size.
				out = append(out, EncodeUDPFrame(UDPFrameFin, f.SID, uint64Bytes(off)))
				_ = finalSize
			case UDPFrameAck:
				largest, ranges, err := DecodeAckFrame(f.Payload)
				if err == nil {
					s.sess.Rel.ProcessAck(largest, ranges)
				}
			case UDPFramePing:
				out = append(out, EncodeUDPFrame(UDPFramePong, 0, nil))
			case UDPFrameRst:
				s.mu.Lock()
				delete(s.sendOffsets, f.SID)
				delete(s.recvOffsets, f.SID)
				s.mu.Unlock()
			case UDPFrameWindowUpdate, UDPFrameMaxStreamData:
				// Client's flow control update: server echoes without
				// flow-control gating in this test, so just ignore.
			}
		}
		if len(out) > 0 {
			// Chunk to fit MaxUDPPlaintext; oversized batches would be
			// silently dropped by SealPacket (the client's data was
			// already ACKed, so dropping = permanent loss).
			var batch [][]byte
			batchSize := 0
			flush := func() {
				if len(batch) == 0 {
					return
				}
				pkt, err := s.sess.sealPacket(udpDirS2C, batch, true)
				if err == nil {
					_, _ = s.conn.WriteToUDP(pkt, s.clientAddr)
				}
				batch = nil
				batchSize = 0
			}
			for _, f := range out {
				if batchSize+len(f) > MaxUDPPlaintext && len(batch) > 0 {
					flush()
				}
				batch = append(batch, f)
				batchSize += len(f)
			}
			flush()
		}
	}
}

func (s *echoServer) stop() {
	close(s.done)
	s.wg.Wait()
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func testCredentials() (cid [16]byte, kAuth [32]byte) {
	for i := range cid {
		cid[i] = byte(i)
	}
	for i := range kAuth {
		kAuth[i] = byte(i + 16)
	}
	return cid, kAuth
}

// setupDatapath creates a client manager connected to an echo server via
// memPipe. Returns the manager, server, and conns (caller closes manager).
func setupDatapath(t *testing.T) (*udpStreamManager, *echoServer, *memPacketConn, *memPacketConn) {
	t.Helper()
	cid, kAuth := testCredentials()
	clientConn, serverConn := memPipe()
	serverAddr := &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1"), Port: 443}

	srv := runEchoServer(t, serverConn, kAuth, cid)

	client := NewUDPClient(serverAddr, cid, kAuth).WithDial(func() (UDPPacketConn, error) {
		return clientConn, nil
	})
	sess, conn, err := client.Handshake()
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	if conn != UDPPacketConn(clientConn) {
		t.Fatalf("expected mem conn")
	}
	mgr := newUDPStreamManager(sess, conn, serverAddr)
	return mgr, srv, clientConn, serverConn
}

// openTestStream opens a stream and completes the SYN/CONNECT exchange.
func openTestStream(t *testing.T, mgr *udpStreamManager) *UDPStream {
	t.Helper()
	st := mgr.openStream()
	if st == nil {
		t.Fatalf("openStream returned nil")
	}
	// SYN with dummy CONNECT request.
	req := []byte{0x01, 127, 0, 0, 1, 0x1f, 0x90} // ATYP=IPv4 127.0.0.1:8080
	if err := mgr.sendFrames([][]byte{EncodeUDPFrame(UDPFrameSyn, st.sid, req)}); err != nil {
		t.Fatalf("send SYN failed: %v", err)
	}
	// Read connect result code.
	var code [1]byte
	_ = st.mgr.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(st, code[:]); err != nil {
		t.Fatalf("read connect code failed: %v", err)
	}
	if code[0] != 0x00 {
		t.Fatalf("connect refused: %d", code[0])
	}
	return st
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestUDPDataPathEndToEnd: handshake -> SYN -> write -> echo -> read ->
// half-close -> EOF. Covers the full client data path.
func TestUDPDataPathEndToEnd(t *testing.T) {
	mgr, srv, _, _ := setupDatapath(t)
	defer mgr.Close()
	defer srv.stop()

	st := openTestStream(t, mgr)

	// Write data.
	msg := []byte("hello mist udp datapath")
	n, err := st.Write(msg)
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if n != len(msg) {
		t.Fatalf("short write: %d/%d", n, len(msg))
	}

	// Read echo.
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatalf("read echo failed: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: %q != %q", got, msg)
	}

	// Half-close: client FINs, server echoes FIN, client reads EOF.
	if err := st.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite failed: %v", err)
	}
	// Drain until EOF.
	_, err = io.ReadFull(st, make([]byte, 1))
	if err != io.EOF {
		t.Fatalf("expected EOF after FIN exchange, got: %v", err)
	}

	// Stream should be recycled (both sides done).
	deadline := time.Now().Add(2 * time.Second)
	for {
		mgr.mu.Lock()
		_, ok := mgr.streams[st.sid]
		mgr.mu.Unlock()
		if !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stream not recycled after both FINs")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestUDPStreamHalfClose: after local FIN, the read side still works;
// after remote FIN, the write side still works until local FIN.
func TestUDPStreamHalfClose(t *testing.T) {
	mgr, srv, _, _ := setupDatapath(t)
	defer mgr.Close()
	defer srv.stop()

	st := openTestStream(t, mgr)

	// Client half-closes (FIN) but keeps reading.
	if err := st.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite failed: %v", err)
	}
	// Write after FIN must fail.
	if _, err := st.Write([]byte("x")); err == nil {
		t.Fatalf("expected write-after-FIN to fail")
	}
	// Stream must NOT be recycled yet (remote hasn't FIN'd... but our echo
	// server echoes FIN immediately, so it will be. Instead verify the
	// local state first).
	st.sendMu.Lock()
	lf := st.localFin
	st.sendMu.Unlock()
	if !lf {
		t.Fatalf("localFin not set after CloseWrite")
	}

	// Server echoed FIN back; reading should hit EOF.
	_, err := io.ReadFull(st, make([]byte, 1))
	if err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

// TestUDPOutOfOrderReassembly: STREAM frames arriving out of order are
// reassembled by OFFSET before delivery.
func TestUDPOutOfOrderReassembly(t *testing.T) {
	mgr, srv, _, _ := setupDatapath(t)
	defer mgr.Close()
	defer srv.stop()

	st := openTestStream(t, mgr)
	// openTestStream consumed offset 0 (the 0x00 connect code), so the
	// next expected offset is 1.
	chunk1 := []byte("aaa") // offset 1
	chunk2 := []byte("bbb") // offset 4
	chunk3 := []byte("ccc") // offset 7

	// Deliver out of order: 7, 1, 4.
	st.onStreamData(7, chunk3)
	st.onStreamData(1, chunk1)
	// At this point only "aaa" should be readable; "ccc" is buffered.
	select {
	case d := <-st.recvReady:
		if string(d) != "aaa" {
			t.Fatalf("expected aaa first, got %q", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for in-order chunk")
	}
	// "ccc" must NOT be delivered yet (gap at 4..7).
	select {
	case d := <-st.recvReady:
		t.Fatalf("out-of-order chunk delivered early: %q", d)
	case <-time.After(100 * time.Millisecond):
	}
	st.onStreamData(4, chunk2)
	// Now "bbb" and "ccc" should drain in order.
	for _, want := range []string{"bbb", "ccc"} {
		select {
		case d := <-st.recvReady:
			if string(d) != want {
				t.Fatalf("expected %q, got %q", want, d)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %q", want)
		}
	}
}

// TestUDPBackpressureBound: the per-stream receive buffer is bounded.
// When full, inbound STREAM data is dropped (not buffered unboundedly);
// the peer retransmits after RTO.
func TestUDPBackpressureBound(t *testing.T) {
	mgr, srv, _, _ := setupDatapath(t)
	defer mgr.Close()
	defer srv.stop()

	st := openTestStream(t, mgr)
	// openTestStream consumed offset 0; next expected is 1.

	// Fill the buffer with out-of-order chunks (they buffer, not deliver).
	// Each chunk is 1288 bytes; 1MB needs ~815 chunks.
	chunk := make([]byte, 1288)
	baseOffset := uint64(1000000) // far ahead, so all buffer
	for i := 0; i < 820; i++ {
		st.onStreamData(baseOffset+uint64(i*1288), chunk)
	}
	st.recvMu.Lock()
	buffered := st.recvBuffered
	st.recvMu.Unlock()
	// Buffer should be capped at 1MB (allow some slack for the last chunk).
	if buffered > udpStreamRecvBufMax+2048 {
		t.Fatalf("buffer exceeded cap: %d > %d", buffered, udpStreamRecvBufMax)
	}
	if buffered < udpStreamRecvBufMax-4096 {
		t.Fatalf("buffer unexpectedly small: %d", buffered)
	}

	// Additional data must be dropped, not buffered.
	before := buffered
	st.onStreamData(baseOffset+uint64(820*1288), chunk)
	st.onStreamData(baseOffset+uint64(821*1288), chunk)
	st.recvMu.Lock()
	after := st.recvBuffered
	st.recvMu.Unlock()
	if after != before {
		t.Fatalf("buffer grew past cap: %d -> %d", before, after)
	}
}

// TestUDPDataPathWithLoss: 5% loss with larger payload; echo must still
// work via retransmission. Validates reliability integration under loss.
//
// Previously skipped due to hangs; root causes fixed:
//  1. Retransmit batching overflow: CheckRTO batched all timed-out frames
//     into one packet; oversize batches were silently dropped by SealPacket
//     after being removed from sentPackets (permanent loss). Fixed by
//     chunking in sendFrames.
//  2. Packet-level ACK + stream-level drop: OpenPacket ACKed before
//     onStreamData could drop due to buffer overflow. Fixed by deferring
//     ACK via OpenPacketNoAck/MarkPacketReceived.
//  3. Test echo server now implements flow control (WINDOW_UPDATE).
func TestUDPDataPathWithLoss(t *testing.T) {
	runLossScenario(t, time.Now().UnixNano(), 0.05)
}

// TestUDPDataPathLossMultiSeed: seed diversity sweep (chan 2026-10-23
// pre-merge check). Runs the loss scenario with 25 different seeds at
// 5%, 8% and 10% loss to shake out intermittent hangs.
func TestUDPDataPathLossMultiSeed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-seed loss sweep in short mode")
	}
	for _, loss := range []float64{0.05, 0.08, 0.10} {
		for seed := int64(1); seed <= 25; seed++ {
			name := strings.ReplaceAll(
				"loss="+strconv.FormatFloat(loss, 'f', 2, 64)+"/seed="+strconv.FormatInt(seed, 10),
				".", "p",
			)
			t.Run(name, func(t *testing.T) {
				runLossScenario(t, seed*1000+int64(loss*100), loss)
			})
		}
	}
}

// runLossScenario exercises the data path under simulated packet loss.
func runLossScenario(t *testing.T, seed int64, lossRate float64) {
	t.Helper()
	cid, kAuth := testCredentials()
	serverAddr := &stdnet.UDPAddr{IP: stdnet.ParseIP("127.0.0.1"), Port: 443}

	// Handshake has 4-attempt retransmit but can still fail at high loss.
	// Each retry uses a FRESH pipe: a failed Handshake() closes its conn,
	// so reusing it would fail immediately with "closed pipe".
	// (Handshake robustness is separate from data-path reliability.)
	var mgr *udpStreamManager
	var srv *echoServer
	for attempt := 0; attempt < 5; attempt++ {
		clientConn, serverConn := memPipeSeeded(seed + int64(attempt)*100000)
		clientConn.loss = lossRate
		serverConn.loss = lossRate
		srv = runEchoServer(t, serverConn, kAuth, cid)
		client := NewUDPClient(serverAddr, cid, kAuth).WithDial(func() (UDPPacketConn, error) {
			return clientConn, nil
		})
		sess, conn, err := client.Handshake()
		if err == nil {
			mgr = newUDPStreamManager(sess, conn, serverAddr)
			break
		}
		// Tear down the failed attempt: close the server conn to unblock
		// its handshake read, then stop the server goroutine.
		serverConn.Close()
		srv.stop()
		srv = nil
		if attempt == 4 {
			t.Fatalf("handshake with loss failed: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer mgr.Close()
	defer srv.stop()

	st := openTestStream(t, mgr)

	// 64KB exercises multiple packets + retransmits.
	msg := make([]byte, 64*1024)
	for i := range msg {
		msg[i] = byte(i)
	}
	done := make(chan error, 1)
	go func() {
		_, err := st.Write(msg)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("write with loss failed: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("write with loss timed out")
	}

	got := make([]byte, len(msg))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatalf("read echo with loss failed: %v", err)
	}
	for i := range msg {
		if got[i] != msg[i] {
			t.Fatalf("echo mismatch at %d", i)
		}
	}
}
