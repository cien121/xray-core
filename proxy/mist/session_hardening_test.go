package mist

import (
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

// TestJitterDurationBounds verifies the anti-targeting jitter primitive:
// samples must stay inside [base*(1-frac), base*(1+frac)], must actually
// vary (crypto/rand sourced), and the mean must stay near base.
func TestJitterDurationBounds(t *testing.T) {
	const base = 200 * time.Millisecond
	const frac = heartbeatJitterFrac // 0.25
	const n = 500
	lo, hi := 150*time.Millisecond, 250*time.Millisecond
	var sum time.Duration
	first := jitterDuration(base, frac)
	allSame := true
	for i := 0; i < n; i++ {
		d := jitterDuration(base, frac)
		if d < lo || d > hi {
			t.Fatalf("sample %d: %v outside [%v, %v]", i, d, lo, hi)
		}
		if d != first {
			allSame = false
		}
		sum += d
	}
	if allSame {
		t.Fatal("jitter produced identical values across 500 samples")
	}
	mean := sum / n
	if mean < 180*time.Millisecond || mean > 220*time.Millisecond {
		t.Fatalf("mean %v outside ±10%% of %v", mean, base)
	}
	// Degenerate inputs degrade gracefully, never panic.
	if got := jitterDuration(0, frac); got != 0 {
		t.Fatalf("jitterDuration(0) = %v, want 0", got)
	}
	if got := jitterDuration(base, 0); got != base {
		t.Fatalf("jitterDuration(frac=0) = %v, want %v", got, base)
	}
}

// heartbeatTestSession builds a live session over one end of a net.Pipe
// with known keys, so the test peer can speak the real wire protocol.
func heartbeatTestSession(t *testing.T, conn net.Conn, hb time.Duration) (*Session, [32]byte, [32]byte) {
	t.Helper()
	var kC2S, kS2C [32]byte
	if _, err := io.ReadFull(rand.Reader, kC2S[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(rand.Reader, kS2C[:]); err != nil {
		t.Fatal(err)
	}
	sess := newSession(conn, sessionParams{
		hb:      hb,
		shaping: shapingParams{heavyPackets: 0, tailPad: 0},
	})
	sess.kC2S = kC2S
	sess.kS2C = kS2C
	return sess, kC2S, kS2C
}

// TestHeartbeatIntervalJitter runs the real heartbeatLoop against a fake
// server that answers every PING with a PONG, and statistically verifies
// the PING emission intervals are jittered: variance significantly > 0
// and mean within hb±30%.
func TestHeartbeatIntervalJitter(t *testing.T) {
	const hb = 200 * time.Millisecond
	const wantPings = 21 // -> 20 inter-arrival intervals

	c1, c2 := net.Pipe()
	sess, kC2S, kS2C := heartbeatTestSession(t, c1, hb)
	defer sess.close()

	arrivals := make(chan time.Time, wantPings)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer c2.Close()
		for i := 0; i < wantPings; i++ {
			_, pt, err := readRawFrame(c2, kC2S[:], 0, dirC2S, uint32(i))
			if err != nil {
				return
			}
			arrivals <- time.Now()
			if len(pt) < 9 || pt[0] != ctrlPing {
				return
			}
			pong := append([]byte{ctrlPong}, pt[1:9]...)
			frame, err := sealFrame(kS2C[:], 0, dirS2C, uint32(i), 0x00, pong, 0)
			if err != nil {
				return
			}
			if _, err := c2.Write(frame); err != nil {
				return
			}
		}
	}()

	sess.start()

	var ts []time.Time
	timeout := time.After(30 * time.Second)
collect:
	for len(ts) < wantPings {
		select {
		case at := <-arrivals:
			ts = append(ts, at)
		case <-timeout:
			t.Fatalf("timed out waiting for pings: got %d/%d", len(ts), wantPings)
		case <-serverDone:
			// Server exited: drain anything already buffered, then judge.
			for len(arrivals) > 0 {
				ts = append(ts, <-arrivals)
			}
			if len(ts) < wantPings {
				t.Fatalf("server exited early: got %d/%d pings", len(ts), wantPings)
			}
			break collect
		}
	}

	intervals := make([]float64, 0, wantPings-1)
	var sum, min, max float64
	for i := 1; i < len(ts); i++ {
		ms := float64(ts[i].Sub(ts[i-1])) / float64(time.Millisecond)
		intervals = append(intervals, ms)
		sum += ms
		if i == 1 || ms < min {
			min = ms
		}
		if i == 1 || ms > max {
			max = ms
		}
	}
	mean := sum / float64(len(intervals))
	var sq float64
	for _, v := range intervals {
		d := v - mean
		sq += d * d
	}
	variance := sq / float64(len(intervals))

	t.Logf("hb=%v intervals: n=%d mean=%.1fms var=%.1fms^2 min=%.1fms max=%.1fms",
		hb, len(intervals), mean, variance, min, max)

	// Mean must stay within hb±30%: [140ms, 260ms].
	if mean < 140 || mean > 260 {
		t.Fatalf("mean interval %.1fms outside hb±30%% [140, 260]", mean)
	}
	// Variance must be significantly above zero: a fixed 200ms timer
	// would show only scheduling noise (~ms^2); U[150,250]ms has ~833ms^2.
	if variance < 25 {
		t.Fatalf("interval variance %.1fms^2 too small: no detectable jitter", variance)
	}
	// Spread check: 20 samples of U[150,250]ms essentially always span >20ms.
	if max-min < 20 {
		t.Fatalf("interval spread %.1fms too small: looks like a fixed timer", max-min)
	}
}

// TestHeartbeatMissedPongClosesSession verifies the preserved SPEC 10.1
// semantics: with a peer that reads PINGs but never answers, two
// consecutive jittered PONG timeouts must kill the session.
func TestHeartbeatMissedPongClosesSession(t *testing.T) {
	const hb = 200 * time.Millisecond

	c1, c2 := net.Pipe()
	sess, kC2S, _ := heartbeatTestSession(t, c1, hb)
	defer sess.close()
	defer c2.Close()

	// Black-hole peer: keep the connection open and consume PINGs so the
	// read loop stays alive, but never send PONGs.
	go func() {
		for i := 0; i < 8; i++ {
			if _, _, err := readRawFrame(c2, kC2S[:], 0, dirC2S, uint32(i)); err != nil {
				return
			}
		}
	}()

	sess.start()

	select {
	case <-sess.doneCh:
		// expected: dead after 2 consecutive missed PONG windows
	case <-time.After(5 * time.Second):
		t.Fatal("session did not close after consecutive missed PONGs")
	}
}

// TestLightPhasePadRandomized verifies the SPEC appendix B.2 fix at the
// wire level: with tailPad=N, the light-phase PLEN byte must vary in
// [0, N] instead of sitting at the fixed value N.
func TestLightPhasePadRandomized(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	var kC2S [32]byte
	if _, err := io.ReadFull(rand.Reader, kC2S[:]); err != nil {
		t.Fatal(err)
	}
	sess := newSession(c1, sessionParams{
		shaping: shapingParams{heavyPackets: 0, tailPad: 8},
	})
	sess.kC2S = kC2S

	const frames = 40
	go func() {
		for i := 0; i < frames; i++ {
			if err := sess.writeOneFrameLocked(0, uint32(i), 0x00, []byte("ping")); err != nil {
				return
			}
		}
	}()

	seen := make(map[int]bool)
	header := make([]byte, 4)
	for i := 0; i < frames; i++ {
		if _, err := io.ReadFull(c2, header); err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		ln := int(header[0])<<8 | int(header[1])
		padLen := int(header[2])
		if padLen < 0 || padLen > 8 {
			t.Fatalf("frame %d: PLEN %d outside [0, 8]", i, padLen)
		}
		seen[padLen] = true
		// Drain the rest of the frame: (ln-2) bytes after LEN.
		if _, err := io.CopyN(io.Discard, c2, int64(ln-2)); err != nil {
			t.Fatalf("frame %d drain: %v", i, err)
		}
	}
	if len(seen) < 3 {
		t.Fatalf("PLEN took only %d distinct values in %d frames: fixed-size signature",
			len(seen), frames)
	}
	t.Logf("light-phase PLEN distinct values: %d/9 over %d frames", len(seen), frames)
}
