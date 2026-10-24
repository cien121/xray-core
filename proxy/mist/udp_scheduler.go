// Package mist: Mist UDP centralized send scheduler.
//
// All tracked outbound packets go through the scheduler. It enforces:
//   - Congestion window: never send when inflight + pktSize > cwnd.
//   - Packet pacing: token bucket refilled at BBR's pacing rate
//     (or cwnd/SRTT before the first bandwidth sample).
//   - Priority: retransmissions ahead of new data.
//   - Backpressure: Write blocks when the queue is full.
//
// Design (chan, 2026-10-23):
//   - Write() only enqueues frames; it never touches the socket.
//   - A single send loop dequeues when cwnd AND pacing both allow,
//     then seals, sends, and accounts.
//   - SealPacket is package-private; only the scheduler may call it, so a
//     "bypass the gate" call site cannot compile.
//   - Pure ACKs (SealPacketUntracked) stay public and bypass the scheduler:
//     they don't occupy cwnd. Callers should still rate-limit them
//     (the reliability layer already batches ACKs every 10ms/10 packets).
package mist

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Send log (debug): per-packet transmit timestamps for burst analysis.
// ---------------------------------------------------------------------------

// sendLogEntry records one transmitted packet.
type sendLogEntry struct {
	ts         time.Time // transmit time
	size       int       // datagram bytes
	tokens     float64   // token bucket level after deduct
	cwnd       float64   // congestion window at send
	inflight   float64   // bytes in flight at send
	wasRtx     bool      // retransmit (vs new data)
	pacingRate float64   // pacing rate (bytes/sec) at send
	bbrGain    float64   // BBR pacing gain at send
	btlBw      uint64    // BBR bandwidth estimate (bytes/sec) at send
}

// sendLog is a fixed-size ring buffer for transmit events.
// Enable via EnableSendLog(); disabled by default (zero overhead).
type sendLog struct {
	mu      sync.Mutex
	entries []sendLogEntry
	next    int
	count   int
	enabled bool
}

func (l *sendLog) enable(capacity int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = make([]sendLogEntry, capacity)
	l.enabled = true
}

func (l *sendLog) record(e sendLogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.enabled {
		return
	}
	l.entries[l.next] = e
	l.next = (l.next + 1) % len(l.entries)
	if l.count < len(l.entries) {
		l.count++
	}
}

// dump returns entries in chronological order.
func (l *sendLog) dump() []sendLogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.enabled || l.count == 0 {
		return nil
	}
	out := make([]sendLogEntry, 0, l.count)
	start := (l.next - l.count + len(l.entries)) % len(l.entries)
	for i := 0; i < l.count; i++ {
		idx := (start + i) % len(l.entries)
		out = append(out, l.entries[idx])
	}
	return out
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// UDPSchedulerMaxQueue is the max queued packets before Write blocks
	// (backpressure to the stream layer).
	UDPSchedulerMaxQueue = 256
	// UDPSchedulerBucketPackets is the pacing token bucket capacity,
	// in packets. Allows a small burst without per-packet timer overhead.
	UDPSchedulerBucketPackets = 4
	// udpSchedulerMaxDatagram is the assumed max datagram size for the
	// token bucket capacity (matches BBR's maxDatagramSize).
	udpSchedulerMaxDatagram = 1350
)

// udpStrictSizeCheck makes trySend panic (instead of logging) when the
// sealed datagram length differs from the pre-seal estimate.
//
// This is a TEST HOOK (2026-10-23): tests set it to fail fast so a
// wire-format drift is caught at the source. Production leaves it false:
// sealPacket already accounted the ACTUAL datagram length in bytesInFlight
// and BBR (see sealPacket), so the books are correct even when the
// estimate drifts — only the cwnd gate's pre-seal guarantee was
// approximate. Crashing the whole session over a bookkeeping estimate
// would turn a minor accounting skew into a total outage.
var udpStrictSizeCheck = false

// ---------------------------------------------------------------------------
// schedTimer abstracts time.Timer for injectable clocks in tests.
// ---------------------------------------------------------------------------

// schedTimer is the minimal timer interface the send loop needs.
type schedTimer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(d time.Duration) bool
}

// realSchedTimer wraps time.Timer.
type realSchedTimer struct{ t *time.Timer }

func (r *realSchedTimer) C() <-chan time.Time       { return r.t.C }
func (r *realSchedTimer) Stop() bool               { return r.t.Stop() }
func (r *realSchedTimer) Reset(d time.Duration) bool { return r.t.Reset(d) }

// ---------------------------------------------------------------------------
// UDPSendScheduler
// ---------------------------------------------------------------------------

// UDPSendScheduler centralizes outbound transmission for one session
// direction. Create one per direction that sends tracked data.
//
// Typical wiring:
//
//	sched := NewUDPSendScheduler(sess, DirC2S, func(pkt []byte) error {
//	    _, err := conn.WriteToUDP(pkt, peer)
//	    return err
//	})
//	sess.Rel.OnRetransmit = func(frames [][]byte) error { return sched.WriteRetransmitChunked(frames) }
//	sched.Start()
//	defer sched.Stop()
//
//	// Replace: pkt, _ := sess.SealPacket(dir, frames); conn.WriteToUDP(pkt, peer)
//	// With:    sched.Write(frames)
type UDPSendScheduler struct {
	session  *UDPSession
	dir      uint32
	sendFunc func([]byte) error

	mu         sync.Mutex
	notFull    *sync.Cond
	newQueue   [][][]byte // each entry = frames for one packet (FIFO)
	rtxQueue   [][][]byte // retransmit frames (higher priority, FIFO)
	queueLen   int        // total queued packets (new + rtx)
	closed     bool
	running    bool

	// Pacing token bucket (bytes).
	tokens   float64
	capacity float64
	lastFill time.Time

	// Lifecycle.
	stopCh chan struct{}
	wakeCh chan struct{} // buffered(1): signaled on enqueue / state change
	doneCh chan struct{}

	// now is injectable for deterministic tests.
	now func() time.Time
	// newTimer creates timers; injectable for deterministic tests.
	// Defaults to real time.Timer.
	newTimer func(d time.Duration) schedTimer
	// dequeueHook is a test-only hook invoked (synchronously, before seal)
	// with whether the dequeued frames came from the retransmit queue.
	// Nil in production.
	dequeueHook func(wasRetransmit bool)

	// sendLog records per-packet transmit events when enabled.
	// Used for burst analysis on real devices (no root needed).
	slog sendLog
}

// EnableSendLog turns on per-packet transmit logging.
// Capacity is the ring buffer size (e.g. 20000 for a 10MB transfer).
// Disabled by default.
func (s *UDPSendScheduler) EnableSendLog(capacity int) {
	s.slog.enable(capacity)
}

// DumpSendLog returns the recorded transmit events in chronological order.
// Each entry has timestamp, size, token level, cwnd, inflight, and whether
// it was a retransmit. Returns nil if logging was not enabled.
func (s *UDPSendScheduler) DumpSendLog() []sendLogEntry {
	return s.slog.dump()
}

// SendLogEntry is the exported view of a transmit event for analysis tools.
type SendLogEntry struct {
	Ts         time.Time
	Size       int
	Tokens     float64
	Cwnd       float64
	Inflight   float64
	WasRtx     bool
	PacingRate float64
	BBRGain    float64
	BtlBw      uint64
}

// DumpSendLogExported returns the log in an exported struct for cmd/ tools.
func (s *UDPSendScheduler) DumpSendLogExported() []SendLogEntry {
	raw := s.slog.dump()
	out := make([]SendLogEntry, len(raw))
	for i, e := range raw {
		out[i] = SendLogEntry{
			Ts:         e.ts,
			Size:       e.size,
			Tokens:     e.tokens,
			Cwnd:       e.cwnd,
			Inflight:   e.inflight,
			WasRtx:     e.wasRtx,
			PacingRate: e.pacingRate,
			BBRGain:    e.bbrGain,
			BtlBw:      e.btlBw,
		}
	}
	return out
}

// NewUDPSendScheduler creates a scheduler for the given session direction.
// sendFunc transmits a sealed datagram; it must be thread-safe.
func NewUDPSendScheduler(session *UDPSession, dir uint32, sendFunc func([]byte) error) *UDPSendScheduler {
	s := &UDPSendScheduler{
		session:  session,
		dir:      dir,
		sendFunc: sendFunc,
		capacity: float64(UDPSchedulerBucketPackets * udpSchedulerMaxDatagram),
		stopCh:   make(chan struct{}),
		wakeCh:   make(chan struct{}, 1),
		doneCh:   make(chan struct{}),
		now:      time.Now,
		newTimer: func(d time.Duration) schedTimer { return &realSchedTimer{time.NewTimer(d)} },
	}
	s.notFull = sync.NewCond(&s.mu)
	s.tokens = s.capacity // start full: first burst allowed up to bucket
	s.lastFill = s.now()
	return s
}

// Write enqueues frames for sending. It blocks when the queue is full
// (backpressure); the stream layer should treat a blocked Write as "wait
// for flow-control window / cwnd before producing more".
//
// Each call enqueues one packet's worth of frames; the scheduler packs
// exactly what was given (callers must not exceed MaxUDPPlaintext).
func (s *UDPSendScheduler) Write(frames [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.queueLen >= UDPSchedulerMaxQueue && !s.closed {
		s.notFull.Wait()
	}
	if s.closed {
		return errors.New("udp: send scheduler closed")
	}
	s.newQueue = append(s.newQueue, frames)
	s.queueLen++
	s.signalLocked()
	return nil
}

// WriteRetransmit enqueues frames with higher priority than new data.
// It never blocks: retransmissions must not deadlock the RTO path.
// Callers: wire as sess.Rel.OnRetransmit.
func (s *UDPSendScheduler) WriteRetransmit(frames [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.rtxQueue = append(s.rtxQueue, frames)
	s.queueLen++
	s.signalLocked()
}

// WriteRetransmitChunked chunks frames to fit MaxUDPPlaintext per datagram
// and enqueues each chunk via WriteRetransmit. Convenience for wiring
// sess.Rel.OnRetransmit directly:
//
//	sess.Rel.OnRetransmit = func(frames [][]byte) error {
//	    return sched.WriteRetransmitChunked(frames)
//	}
func (s *UDPSendScheduler) WriteRetransmitChunked(frames [][]byte) error {
	var batch [][]byte
	batchSize := 0
	flush := func() {
		if len(batch) > 0 {
			s.WriteRetransmit(batch)
			batch, batchSize = nil, 0
		}
	}
	for _, f := range frames {
		if batchSize+len(f) > MaxUDPPlaintext && len(batch) > 0 {
			flush()
		}
		batch = append(batch, f)
		batchSize += len(f)
	}
	flush()
	return nil
}

// signalLocked wakes the send loop (non-blocking).
func (s *UDPSendScheduler) signalLocked() {
	select {
	case s.wakeCh <- struct{}{}:
	default:
	}
}

// Start begins the send loop. Idempotent.
func (s *UDPSendScheduler) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return
	}
	s.running = true
	go s.loop()
}

// Stop halts the send loop and unblocks Write. Idempotent.
func (s *UDPSendScheduler) Stop() {
	s.mu.Lock()
	if !s.running || s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.stopCh)
	s.notFull.Broadcast()
	s.mu.Unlock()
	<-s.doneCh
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
}

// pacingRateLocked returns the current pacing rate in bytes/sec.
// Uses BBR's pacing rate once a bandwidth sample exists; before that,
// falls back to cwnd/SRTT so the first window is still bounded
// (never infinite).
func (s *UDPSendScheduler) pacingRateLocked() float64 {
	if s.session.BBR != nil {
		if rate := s.session.BBR.PacingRate(); rate > 0 {
			return rate // BBRController.PacingRate is bytes/sec
		}
		// No bandwidth sample yet: cwnd / SRTT.
		cwnd := float64(s.session.BBR.CongestionWindow())
		srtt := s.session.Rel.SRTT()
		if srtt > 0 && cwnd > 0 {
			return cwnd / srtt.Seconds()
		}
	}
	// Absolute fallback: 10 packets per second at max datagram size.
	// Only hit when BBR is absent (tests).
	return float64(10 * udpSchedulerMaxDatagram)
}

// refillLocked adds tokens based on elapsed time.
func (s *UDPSendScheduler) refillLocked() {
	now := s.now()
	elapsed := now.Sub(s.lastFill).Seconds()
	if elapsed <= 0 {
		return
	}
	s.lastFill = now
	s.tokens += s.pacingRateLocked() * elapsed
	if s.tokens > s.capacity {
		s.tokens = s.capacity
	}
}

// cwndAllowsLocked reports whether the congestion window has room for
// a packet of the given size. Uses bytes: inflight + size <= cwnd.
func (s *UDPSendScheduler) cwndAllowsLocked(size int) bool {
	if s.session.BBR == nil || s.session.Rel == nil {
		return true
	}
	return s.session.Rel.BytesInFlight()+size <= s.session.BBR.CongestionWindow()
}

// peekLocked returns the next frames to send (rtx first) without dequeuing.
func (s *UDPSendScheduler) peekLocked() [][]byte {
	if len(s.rtxQueue) > 0 {
		return s.rtxQueue[0]
	}
	if len(s.newQueue) > 0 {
		return s.newQueue[0]
	}
	return nil
}

// dequeueLocked removes and returns the next frames (rtx first).
func (s *UDPSendScheduler) dequeueLocked() [][]byte {
	var frames [][]byte
	if len(s.rtxQueue) > 0 {
		frames = s.rtxQueue[0]
		s.rtxQueue[0] = nil
		s.rtxQueue = s.rtxQueue[1:]
	} else if len(s.newQueue) > 0 {
		frames = s.newQueue[0]
		s.newQueue[0] = nil
		s.newQueue = s.newQueue[1:]
	} else {
		return nil
	}
	s.queueLen--
	s.notFull.Signal() // unblock a waiting Write
	return frames
}

// estimatedSize returns the sealed UDP datagram size for frames.
// Formula: QUICShortHeaderLen (13) + AEAD tag (16) + sum of frame lengths.
//
// This MUST equal len(sealPacket(dir, frames)) exactly. The seal path is:
//   datagram = header(13) + AEAD(plaintext + 16-byte tag)
//   plaintext = concatenation of frames
// so len(datagram) = 13 + 16 + sum(len(f)). Any divergence breaks the
// scheduler's cwnd gate, which checks
//   Rel.BytesInFlight() [actual sealed sizes] + estimatedSize <= cwnd.
// If estimatedSize underestimates, the gate admits a packet that pushes
// actual inflight over cwnd. See TestEstimatedSizeMatchesSeal (property
// test) which asserts estimatedSize(frames) == len(sealed) for randomized
// frame combinations on both the tracked and untracked seal paths.
//
// Unit: UDP datagram size (UDP payload), same as BBR/cwnd accounting;
// excludes IP (20) and UDP (8) headers. See UDPReliability doc.
func estimatedSize(frames [][]byte) int {
	n := QUICShortHeaderLen + 16
	for _, f := range frames {
		n += len(f)
	}
	return n
}

// timeUntilSendLocked returns how long to wait before the next packet
// may go out under pacing. Returns 0 if a packet can go now.
// Caller must hold s.mu.
func (s *UDPSendScheduler) timeUntilSendLocked() time.Duration {
	frames := s.peekLocked()
	if frames == nil {
		return time.Hour // nothing queued; wait for wake
	}
	size := estimatedSize(frames)
	if !s.cwndAllowsLocked(size) {
		// cwnd blocked: wake on ACK/loss (they call Wake), but also
		// poll periodically in case a signal was missed.
		return 10 * time.Millisecond
	}
	s.refillLocked()
	need := float64(size)
	if s.tokens >= need {
		return 0
	}
	rate := s.pacingRateLocked()
	if rate <= 0 {
		return time.Millisecond
	}
	wait := time.Duration((need - s.tokens) / rate * float64(time.Second))
	if wait < time.Millisecond {
		wait = time.Millisecond
	}
	return wait
}

// Wake notifies the send loop that state changed (e.g., ACK arrived,
// cwnd grew). Called by the session when reliability state updates.
func (s *UDPSendScheduler) Wake() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signalLocked()
}

// trySend attempts one packet. Returns true if a packet was sent.
// Must NOT hold s.mu (it takes it internally); seal/send happen outside
// the scheduler lock to avoid lock-order issues with session.mu.
func (s *UDPSendScheduler) trySend() bool {
	// 1. Dequeue under lock (checks cwnd + pacing).
	s.mu.Lock()
	frames := s.peekLocked()
	if frames == nil {
		s.mu.Unlock()
		return false
	}
	size := estimatedSize(frames)
	if !s.cwndAllowsLocked(size) {
		s.mu.Unlock()
		return false
	}
	s.refillLocked()
	if s.tokens < float64(size) {
		s.mu.Unlock()
		return false
	}
	// Commit: dequeue and deduct tokens.
	rtxBefore := len(s.rtxQueue)
	frames = s.dequeueLocked()
	wasRtx := len(s.rtxQueue) < rtxBefore
	s.tokens -= float64(size)
	hook := s.dequeueHook
	s.mu.Unlock()
	if hook != nil {
		hook(wasRtx)
	}

	// 2. Seal (package-private; only the scheduler may call it).
	// sealPacket takes session.mu and rel.mu internally.
	pkt, err := s.session.sealPacket(s.dir, frames, true)
	if err != nil {
		return false
	}

	// 3. Verify the estimate was exact. The cwnd gate admitted this packet
	// on the basis of `size`; if the sealed datagram differs, the gate's
	// guarantee (inflight + size <= cwnd, with inflight in actual sealed
	// bytes) is broken.
	//
	// Test builds (udpStrictSizeCheck=true) panic so a drift is caught at
	// the source instead of surfacing as a mysterious cwnd overrun
	// downstream. (2026-10-23: TestSchedulerBottleneck64Q caught a 63-byte
	// drift here.)
	//
	// Production (udpStrictSizeCheck=false) logs and continues: sealPacket
	// already recorded the ACTUAL len(datagram) in bytesInFlight and BBR,
	// so accounting stays correct; only this one packet may have slightly
	// overshot the pre-seal cwnd estimate. Never crash a live session
	// over a bookkeeping estimate.
	if len(pkt) != size {
		msg := fmt.Sprintf("udp: estimatedSize=%d != sealed len=%d (%d frames)",
			size, len(pkt), len(frames))
		if udpStrictSizeCheck {
			panic(msg)
		}
		log.Printf("ERROR: %s (accounting actual length)", msg)
		// Adjust token accounting for the actual sealed size.
		// Tokens were deducted based on estimate; correct the difference.
		s.mu.Lock()
		if len(pkt) > size {
			s.tokens -= float64(len(pkt) - size)
		} else {
			s.tokens += float64(size - len(pkt))
			if s.tokens > s.capacity {
				s.tokens = s.capacity
			}
		}
		s.mu.Unlock()
	}

	// 4. Transmit.
	if err := s.sendFunc(pkt); err != nil {
		return false
	}
	// Record send log AFTER the actual socket write, so the timestamp
	// reflects when the packet was handed to the OS, not when the token
	// was consumed. (On phones, goroutine scheduling delay between token
	// consume and WriteToUDP can cluster timestamps artificially.)
	s.mu.Lock()
	tokensAfter := s.tokens
	var cwnd, inflight float64
	var bbrGain float64
	var btlBw uint64
	if s.session.BBR != nil {
		cwnd = float64(s.session.BBR.CongestionWindow())
		bbrGain = s.session.BBR.PacingGain()
		btlBw = s.session.BBR.BandwidthEstimate()
	}
	if s.session.Rel != nil {
		inflight = float64(s.session.Rel.BytesInFlight())
	}
	pacingRate := s.pacingRateLocked()
	s.mu.Unlock()
	s.slog.record(sendLogEntry{
		ts:         s.now(),
		size:       len(pkt),
		tokens:     tokensAfter,
		cwnd:       cwnd,
		inflight:   inflight,
		wasRtx:     wasRtx,
		pacingRate: pacingRate,
		bbrGain:    bbrGain,
		btlBw:      btlBw,
	})
	return true
}

// loop is the send loop: pack, pace, and transmit while allowed.
func (s *UDPSendScheduler) loop() {
	defer close(s.doneCh)
	timer := s.newTimer(time.Hour)
	defer timer.Stop()

	for {
		// Drain: send while cwnd + pacing allow.
		for s.trySend() {
		}

		// Compute next wake-up.
		s.mu.Lock()
		delay := s.timeUntilSendLocked()
		// If queue drained, tell BBR we're app-limited so its
		// bandwidth estimate isn't dragged down by idle periods.
		drained := s.queueLen == 0
		s.mu.Unlock()
		if drained && s.session.BBR != nil {
			s.session.BBR.OnAppLimited()
		}

		if !timer.Stop() {
			select {
			case <-timer.C():
			default:
			}
		}
		timer.Reset(delay)

		timerCh := timer.C()
		select {
		case <-s.stopCh:
			return
		case <-s.wakeCh:
			continue
		case <-timerCh:
			continue
		}
	}
}
