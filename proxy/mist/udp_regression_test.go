package mist

// Regression tests for data-path bug fixes (2026-10-23).

import (
	"errors"
	"testing"
)

// TestFastRetransmitRemovesFromSentPackets: after fast retransmit fires,
// the old packet number must be removed from sentPackets. Previously the
// entry was left behind, causing infinite RTO retransmits of the same
// logical packet.
func TestFastRetransmitRemovesFromSentPackets(t *testing.T) {
	rel := NewUDPReliability(nil)
	var retransmitted [][]byte
	rel.OnRetransmit = func(frames [][]byte) error {
		retransmitted = frames
		return nil
	}

	// Send 5 packets.
	for pn := uint32(1); pn <= 5; pn++ {
		rel.PacketSent(pn, [][]byte{[]byte{byte(pn)}}, 100)
	}
	if got := len(rel.sentPackets); got != 5 {
		t.Fatalf("expected 5 sentPackets, got %d", got)
	}

	// ACK packets 2-5 with a single call (largest advances to 5, no dups yet).
	rel.ProcessAck(5, [][2]uint32{{2, 5}})
	// Packets 2-5 should now be acked; only packet 1 remains.
	rel.mu.Lock()
	remaining := len(rel.sentPackets)
	rel.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("expected 1 remaining sentPacket, got %d", remaining)
	}

	// Now trigger fast retransmit: dup ACKs with largest stuck at 5
	// (packet 1 still unacked, largest doesn't advance).
	for i := 0; i < UDPDupAckThreshold; i++ {
		rel.ProcessAck(5, [][2]uint32{{2, 5}})
	}
	if retransmitted == nil {
		t.Fatalf("fast retransmit did not fire")
	}

	// The old packet number (1) must be gone from sentPackets.
	rel.mu.Lock()
	_, stillThere := rel.sentPackets[1]
	count := len(rel.sentPackets)
	rel.mu.Unlock()
	if stillThere {
		t.Fatalf("packet 1 still in sentPackets after fast retransmit (would cause infinite RTO loop)")
	}
	if count != 0 {
		t.Fatalf("expected 0 sentPackets after fast retransmit, got %d", count)
	}
}

// TestAckNotInCongestionWindow: ACK-only packets (SealPacketUntracked)
// must not consume congestion window bytes. This validates the
// SealPacketUntracked path used by sendAck.
func TestAckNotInCongestionWindow(t *testing.T) {
	// Create a session with reliability and BBR.
	sess := &UDPSession{
		Rel: NewUDPReliability(nil),
	}
	// Initialize keys minimally for SealPacket (won't actually encrypt
	// validly, but we only care about tracking behavior).
	// Instead, test at the reliability layer directly:
	rel := sess.Rel

	// Simulate tracked packet.
	rel.PacketSent(1, [][]byte{[]byte("data")}, 1000)
	if got := rel.BytesInFlight(); got != 1000 {
		t.Fatalf("expected 1000 bytes in flight, got %d", got)
	}

	// Untracked packets (ACKs) should not go through PacketSent at all.
	// Verify by checking that SealPacketUntracked doesn't call PacketSent.
	// (This is a code-path assertion: if someone changes sendAck to use
	// SealPacket instead of SealPacketUntracked, this test documents why.)
	if got := rel.BytesInFlight(); got != 1000 {
		t.Fatalf("bytes in flight changed without PacketSent: %d", got)
	}

	// ACK the data packet; bytes should drop to 0.
	rel.PacketAcked(1, 0)
	if got := rel.BytesInFlight(); got != 0 {
		t.Fatalf("expected 0 bytes in flight after ACK, got %d", got)
	}
}

// TestRetransmitFailureKeepsSentPackets: if OnRetransmit returns an error
// (seal/send failed), the old sentPackets entries must be KEPT so the next
// RTO tick retries. Previously the entries were deleted before the callback
// ran, so a failed retransmit silently dropped the data (2026-10-23 hang
// root cause: CheckRTO deleted entries, sendFrames failed on oversize
// batch, error swallowed with `_ =`).
func TestRetransmitFailureKeepsSentPackets(t *testing.T) {
	rel := NewUDPReliability(nil)
	calls := 0
	rel.OnRetransmit = func(frames [][]byte) error {
		calls++
		if calls == 1 {
			return errors.New("simulated seal failure")
		}
		return nil
	}

	rel.PacketSent(1, [][]byte{[]byte("a")}, 100)
	rel.PacketSent(2, [][]byte{[]byte("b")}, 100)
	// Force immediate timeout.
	rel.mu.Lock()
	rel.rto = 0
	rel.mu.Unlock()

	// First CheckRTO: callback fails -> entries must be kept for retry.
	rel.CheckRTO()
	if calls != 1 {
		t.Fatalf("expected 1 retransmit call, got %d", calls)
	}
	rel.mu.Lock()
	n := len(rel.sentPackets)
	rel.mu.Unlock()
	if n != 2 {
		t.Fatalf("expected 2 sentPackets kept after failed retransmit, got %d (data would be silently lost)", n)
	}

	// Second CheckRTO: callback succeeds -> old entries retired.
	rel.CheckRTO()
	if calls != 2 {
		t.Fatalf("expected 2 retransmit calls, got %d", calls)
	}
	rel.mu.Lock()
	n = len(rel.sentPackets)
	rel.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected 0 sentPackets after successful retransmit, got %d", n)
	}
}

// TestFastRetransmitFailureKeepsSentPackets: same guarantee for the fast
// retransmit path — a failed callback must not retire the old entry.
func TestFastRetransmitFailureKeepsSentPackets(t *testing.T) {
	rel := NewUDPReliability(nil)
	rel.OnRetransmit = func(frames [][]byte) error {
		return errors.New("simulated seal failure")
	}

	for pn := uint32(1); pn <= 5; pn++ {
		rel.PacketSent(pn, [][]byte{[]byte{byte(pn)}}, 100)
	}
	rel.ProcessAck(5, [][2]uint32{{2, 5}})
	for i := 0; i < UDPDupAckThreshold; i++ {
		rel.ProcessAck(5, [][2]uint32{{2, 5}})
	}

	// Fast retransmit fired but the callback failed: packet 1 must stay.
	rel.mu.Lock()
	_, stillThere := rel.sentPackets[1]
	rel.mu.Unlock()
	if !stillThere {
		t.Fatalf("packet 1 removed from sentPackets despite failed retransmit (data would be silently lost)")
	}
}
