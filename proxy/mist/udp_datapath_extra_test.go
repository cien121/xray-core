package mist

// Additional data-path tests per chan's 2026-10-23 08:02 review:
// half-close edge cases and backpressure hysteresis boundaries.

import (
	"io"
	stdnet "net"
	"testing"
	"time"
)

// TestUDPStreamHalfCloseWriteAfterPeerFin: after the peer sends FIN,
// the local side can still write large amounts of data. The peer's read
// side must continue to ACK and send WINDOW_UPDATEs.
func TestUDPStreamHalfCloseWriteAfterPeerFin(t *testing.T) {
	mgr, srv, _, _ := setupDatapath(t)
	defer mgr.Close()
	defer srv.stop()

	st := openTestStream(t, mgr)

	// Simulate peer FIN: server echoes FIN after we half-close.
	// Actually, test the reverse: WE receive FIN first (via onRemoteFin),
	// then we write large data.
	st.onRemoteFin(1) // peer FIN, finalSize=1 (just the 0x00)

	// Verify read side hits EOF.
	if _, err := io.ReadFull(st, make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected EOF after peer FIN, got %v", err)
	}

	// Now write 128KB. The peer (echo server) must still ACK and
	// send WINDOW_UPDATEs, even though it FIN'd its side.
	msg := make([]byte, 128*1024)
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
			t.Fatalf("write after peer FIN failed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("write after peer FIN hung (peer not ACKing/updating window?)")
	}

	// Our FIN should still work after writing.
	if err := st.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite failed: %v", err)
	}
}

// TestUDPStreamRstUnblocksIO: when RST is received, a goroutine blocked in
// Read or Write must return an error immediately, not hang.
func TestUDPStreamRstUnblocksIO(t *testing.T) {
	mgr, srv, _, _ := setupDatapath(t)
	defer mgr.Close()
	defer srv.stop()

	st := openTestStream(t, mgr)

	// Start a blocked Read.
	readDone := make(chan error, 1)
	go func() {
		_, err := st.Read(make([]byte, 1024))
		readDone <- err
	}()
	// Give the Read time to block.
	time.Sleep(200 * time.Millisecond)

	// Simulate receiving RST.
	st.onReset()

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatalf("expected error from Read after RST, got nil")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Read did not unblock after RST")
	}

	// Write after RST must also fail immediately.
	st2 := openTestStream(t, mgr)
	st2.onReset()
	if _, err := st2.Write([]byte("x")); err == nil {
		t.Fatalf("expected error from Write after RST, got nil")
	}
}

// TestUDPBackpressureHysteresis: the 50%/25% thresholds must not jitter.
// When the buffer hovers between the thresholds, WINDOW_UPDATE behavior
// must be stable (no rapid on/off flapping).
func TestUDPBackpressureHysteresis(t *testing.T) {
	mgr, srv, _, _ := setupDatapath(t)
	defer mgr.Close()
	defer srv.stop()

	st := openTestStream(t, mgr)
	// openTestStream consumed offset 0; next expected is 1.

	// Fill buffer to just over 50% (512KB + 1 byte).
	// Use out-of-order chunks so they buffer instead of delivering.
	chunk := make([]byte, 4096)
	base := uint64(1000000)
	target := udpStreamRecvBufMax/2 + 1
	nChunks := uint64((target + 4095) / 4096)
	for i := uint64(0); i < nChunks; i++ {
		st.onStreamData(base+i*4096, chunk)
	}
	st.recvMu.Lock()
	buffered := st.recvBuffered
	st.recvMu.Unlock()
	if buffered < udpStreamRecvBufMax/2 {
		t.Fatalf("failed to fill buffer past 50%%: %d", buffered)
	}

	// Now simulate app reading: call accountRead to trigger the
	// backpressure logic. With buffer >50%, update should be withheld.
	st.flowMu.Lock()
	st.flowRecvOff = udpStreamInitialWindow / 2 // trigger the >= half check
	pendingBefore := st.updatePending
	st.flowMu.Unlock()
	_ = pendingBefore

	// Read 1 byte (via accountRead path) and verify no jitter:
	// multiple small reads near the threshold should not flip
	// updatePending rapidly.
	for i := 0; i < 10; i++ {
		st.accountRead(1)
	}
	st.flowMu.Lock()
	pendingAfter := st.updatePending
	st.flowMu.Unlock()
	// With buffer still >50%, update should remain pending (withheld).
	if !pendingAfter {
		t.Fatalf("updatePending should be true with buffer >50%% full")
	}

	// Drain buffer below 25% by simulating reads.
	// (Directly adjust recvBuffered for test speed.)
	st.recvMu.Lock()
	st.recvBuf = make(map[uint64][]byte)
	st.recvBuffered = udpStreamRecvBufMax/4 - 100
	st.recvMu.Unlock()
	st.accountRead(1)
	st.flowMu.Lock()
	pendingDrained := st.updatePending
	st.flowMu.Unlock()
	if pendingDrained {
		t.Fatalf("updatePending should be false after buffer drained below 25%%")
	}
}

// TestUDPBackpressureSlowReader: if the app reads slowly but steadily,
// WINDOW_UPDATEs must still be sent (not permanently withheld).
func TestUDPBackpressureSlowReader(t *testing.T) {
	mgr, srv, _, _ := setupDatapath(t)
	defer mgr.Close()
	defer srv.stop()

	st := openTestStream(t, mgr)

	// Track WINDOW_UPDATE frames sent.
	var windowUpdates int
	origSend := mgr.onSendFrames
	mgr.onSendFrames = func(frames [][]byte) {
		for _, f := range frames {
			// Frame format: [LEN(2)][TYPE(1)][SID(1)][PAYLOAD]
			if len(f) >= 4 && f[2] == UDPFrameWindowUpdate {
				windowUpdates++
			}
		}
		if origSend != nil {
			origSend(frames)
		}
	}

	// Simulate receiving data and reading slowly.
	// Each accountRead with enough flowRecvOff should trigger an update
	// if the buffer is not full.
	for i := 0; i < 5; i++ {
		// Receive 64KB (in-order, so it goes to recvReady).
		st.onStreamData(uint64(1+i*65536), make([]byte, 65536))
		// Read it all (slowly).
		st.accountRead(65536)
		time.Sleep(10 * time.Millisecond)
	}

	if windowUpdates == 0 {
		t.Fatalf("no WINDOW_UPDATE sent despite steady reading")
	}
	t.Logf("window updates sent: %d", windowUpdates)
}

// TestUDPWindowUpdateLoss: if a WINDOW_UPDATE packet is lost, the peer's
// RTO must retransmit it (it's sent via sendFrames = tracked). The
// sender must not stall permanently.
func TestUDPWindowUpdateLoss(t *testing.T) {
	// This is implicitly covered by TestUDPDataPathWithLoss (5% loss
	// includes WINDOW_UPDATE packets), but we assert explicitly here
	// that the update path uses the tracked sendFrames.
	mgr, srv, _, _ := setupDatapath(t)
	defer mgr.Close()
	defer srv.stop()

	st := openTestStream(t, mgr)

	// Force a WINDOW_UPDATE by advancing flowRecvOff past half the window.
	st.flowMu.Lock()
	st.flowRecvOff = udpStreamInitialWindow // definitely >= half
	st.flowMu.Unlock()
	st.recvMu.Lock()
	st.recvBuffered = 0 // not full, so update should send
	st.recvMu.Unlock()

	// Capture whether sendFrames (tracked) is used for the update.
	usedTracked := false
	origOnSend := mgr.onSendFrames
	mgr.onSendFrames = func(frames [][]byte) {
		for _, f := range frames {
			if len(f) >= 4 && f[2] == UDPFrameWindowUpdate {
				usedTracked = true
			}
		}
		if origOnSend != nil {
			origOnSend(frames)
		}
	}
	st.accountRead(1)

	if !usedTracked {
		t.Fatalf("WINDOW_UPDATE not sent via tracked sendFrames (would not be retransmitted on loss)")
	}
}

var _ = stdnet.IPv4len // keep import if unused in some builds

// TestUDPResetRTOBackoffOnWindowUpdate: RTO backoff inflated while ACKs
// were withheld (receiver buffer full) must be cleared when a WINDOW_UPDATE
// arrives, so retransmission of the dropped data happens promptly instead
// of waiting out the inflated backoff.
func TestUDPResetRTOBackoffOnWindowUpdate(t *testing.T) {
	rel := NewUDPReliability(nil)
	// Simulate an in-flight packet and an inflated backoff.
	rel.PacketSent(1, [][]byte{[]byte("data")}, 100)
	rel.mu.Lock()
	rel.rto = 8 * time.Second // as if backed off 1s -> 2s -> 4s -> 8s
	rel.mu.Unlock()

	if got := rel.RTO(); got != 8*time.Second {
		t.Fatalf("expected inflated RTO 8s, got %v", got)
	}
	rel.ResetRTOBackoff()
	if got := rel.RTO(); got >= 8*time.Second {
		t.Fatalf("RTO backoff not reset after receiver feedback, still %v", got)
	}

	// No in-flight packets: reset must be a no-op (no spurious state).
	rel2 := NewUDPReliability(nil)
	rel2.mu.Lock()
	rel2.rto = 8 * time.Second
	rel2.mu.Unlock()
	rel2.ResetRTOBackoff()
	if got := rel2.RTO(); got != 8*time.Second {
		t.Fatalf("ResetRTOBackoff changed RTO with no in-flight packets: %v", got)
	}
}

// TestUDPWithheldAckRecovery: when a STREAM frame is dropped due to
// receive-buffer overflow, handleFrame returns false so the packet ACK is
// withheld (the peer's RTO will retransmit). After the app drains the
// buffer via Read, the retransmitted frame must be accepted and ACKed
// normally. This is the recovery path for the deferred-ACK mechanism.
func TestUDPWithheldAckRecovery(t *testing.T) {
	mgr, srv, _, _ := setupDatapath(t)
	defer mgr.Close()
	defer srv.stop()

	st := openTestStream(t, mgr)

	// Current receive offset (openTestStream consumed 1 byte of connect code).
	st.recvMu.Lock()
	base := st.recvNext
	st.recvMu.Unlock()

	// Fill the receive buffer to just under the cap with in-order data.
	fillSize := udpStreamRecvBufMax - 1000
	if !st.onStreamData(base, make([]byte, fillSize)) {
		t.Fatalf("initial fill unexpectedly dropped")
	}

	// A further STREAM frame would overflow -> must be DROPPED (false) so
	// the packet ACK is withheld. If it returned true, the packet would be
	// ACKed while the data is gone = permanent loss.
	overflowData := make([]byte, 2000)
	for i := range overflowData {
		overflowData[i] = 0xAB
	}
	payload := append(uint64Bytes(base+uint64(fillSize)), overflowData...)
	f := UDPFrame{Type: UDPFrameStream, SID: st.sid, Payload: payload}
	if mgr.handleFrame(f) {
		t.Fatalf("overflowing STREAM frame accepted; ACK would be sent for dropped data (permanent loss)")
	}

	// Drain the buffer the way an app does (Read accounts internally).
	discard := make([]byte, fillSize)
	if _, err := io.ReadFull(st, discard); err != nil {
		t.Fatalf("drain read failed: %v", err)
	}

	// Re-inject the same frame (as the peer's RTO retransmit would):
	// it must now be accepted.
	if !mgr.handleFrame(f) {
		t.Fatalf("retransmitted STREAM frame dropped after buffer drained (recovery path broken)")
	}

	// The packet carrying it would now be ACKed (recvLoop calls
	// MarkPacketReceived when handleFrame returns true). Verify the
	// marking path records new packets and rejects replays.
	const testPktNum = uint32(424242)
	if isNew, _ := mgr.sess.Rel.PacketReceived(testPktNum); !isNew {
		t.Fatalf("PacketReceived did not record test packet as new")
	}
	if isNew, _ := mgr.sess.Rel.PacketReceived(testPktNum); isNew {
		t.Fatalf("PacketReceived recorded duplicate as new (replay window broken)")
	}

	// The retransmitted data must be readable and intact.
	got := make([]byte, len(overflowData))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatalf("read retransmitted data failed: %v", err)
	}
	for i, b := range got {
		if b != 0xAB {
			t.Fatalf("retransmitted data corrupted at byte %d", i)
		}
	}
}
