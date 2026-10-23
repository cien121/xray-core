// Package mistcore: Mist UDP BBR congestion control.
//
// Wraps the BBR implementation ported from Hy2
// (mistcore/bbr, originally xray-core/transport/internet/hysteria/congestion/bbr).
//
// Design decisions per UDP-DESIGN.md §7 (chan, 2026-10-22):
//   - BBR (not CUBIC/Reno, not Hy2's "Brutal")
//   - Initial window: 10 packets
//   - RTprop window: 10s, BtlBw window: 10 RTT (BBR defaults)
//   - Packet pacing: pacing_rate = BtlBw * gain (user explicitly requested,
//     "reference Hy2's packet sending speed")
package mist

import (
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"

	"github.com/xtls/xray-core/proxy/mist/bbr"
)

// ---------------------------------------------------------------------------
// RTT tracker (implements congestion.RTTStatsProvider for BBR)
// ---------------------------------------------------------------------------

// UDPRTTStats tracks RTT samples using the standard Jacobson/Karels algorithm.
// All newly-acknowledged packets participate in sampling (§11, 2026-10-22:
// with new-packet-number retransmission there is no ambiguity, so excluding
// retransmits would starve BBR of samples under loss).
type UDPRTTStats struct {
	minRTT      time.Duration
	latestRTT   time.Duration
	smoothedRTT time.Duration
	rttVar      time.Duration
	maxAckDelay time.Duration
	hasSample   bool
}

// NewUDPRTTStats creates an RTT tracker with no samples yet.
func NewUDPRTTStats() *UDPRTTStats {
	return &UDPRTTStats{
		maxAckDelay: 25 * time.Millisecond, // QUIC default max_ack_delay
	}
}

// UpdateRTT records a new RTT sample (implements RTTStatsProvider).
func (r *UDPRTTStats) UpdateRTT(sendDelta, ackDelay time.Duration) {
	r.latestRTT = sendDelta
	if ackDelay > r.maxAckDelay {
		ackDelay = r.maxAckDelay
	}
	rttSample := sendDelta
	if rttSample < 0 {
		rttSample = 0
	}
	if !r.hasSample {
		r.minRTT = rttSample
		r.smoothedRTT = rttSample
		r.rttVar = rttSample / 2
		r.hasSample = true
		return
	}
	if rttSample < r.minRTT {
		r.minRTT = rttSample
	}
	// RFC 6298-style update.
	rttVarSample := r.smoothedRTT - rttSample
	if rttVarSample < 0 {
		rttVarSample = -rttVarSample
	}
	r.rttVar = (3*r.rttVar + rttVarSample) / 4
	r.smoothedRTT = (7*r.smoothedRTT + rttSample) / 8
}

// MinRTT returns the minimum observed RTT.
func (r *UDPRTTStats) MinRTT() time.Duration { return r.minRTT }

// LatestRTT returns the most recent RTT sample.
func (r *UDPRTTStats) LatestRTT() time.Duration { return r.latestRTT }

// SmoothedRTT returns the exponentially-weighted moving average RTT.
func (r *UDPRTTStats) SmoothedRTT() time.Duration {
	if !r.hasSample {
		return 100 * time.Millisecond // default before any sample
	}
	return r.smoothedRTT
}

// MeanDeviation returns the mean RTT deviation.
func (r *UDPRTTStats) MeanDeviation() time.Duration { return r.rttVar }

// MaxAckDelay returns the maximum ACK delay.
func (r *UDPRTTStats) MaxAckDelay() time.Duration { return r.maxAckDelay }

// PTO returns the probe timeout (RTO equivalent).
func (r *UDPRTTStats) PTO(includeMaxAckDelay bool) time.Duration {
	pto := r.SmoothedRTT() + 4*r.rttVar
	if includeMaxAckDelay {
		pto += r.maxAckDelay
	}
	if pto < 200*time.Millisecond {
		pto = 200 * time.Millisecond
	}
	return pto
}

// SetInitialRTT sets the initial RTT estimate (implements RTTStatsProvider).
func (r *UDPRTTStats) SetInitialRTT(t time.Duration) {
	if !r.hasSample {
		r.smoothedRTT = t
		r.rttVar = t / 2
		r.minRTT = t
	}
}

// SetMaxAckDelay sets the maximum ACK delay (implements RTTStatsProvider).
func (r *UDPRTTStats) SetMaxAckDelay(mad time.Duration) {
	r.maxAckDelay = mad
}

// ---------------------------------------------------------------------------
// BBR controller wrapper
// ---------------------------------------------------------------------------

// UDPPacingParams holds the pacing state.
type UDPPacingParams struct {
	// nextSendTime is the earliest time the next packet may be sent.
	nextSendTime monotime.Time
}

// BBRController wraps the ported BBR sender with a Mist-friendly API.
// Packet numbers are uint32 (Mist) converted to congestion.PacketNumber (int64).
type BBRController struct {
	sender   *bbr.Sender
	rttStats *UDPRTTStats
	clock    bbr.Clock

	// Pacing state.
	nextSendTime time.Time
}

// NewBBRController creates a BBR controller for a UDP session.
//
// maxDatagramSize: typically 1350 (see §8.4).
// Uses the standard BBR profile (BBRv1-style defaults per §7.2).
func NewBBRController(maxDatagramSize int) *BBRController {
	clk := bbr.DefaultClock{}
	sender := bbr.NewBbrSender(
		clk,
		congestion.ByteCount(maxDatagramSize),
		bbr.ProfileStandard,
	)
	rttStats := NewUDPRTTStats()
	sender.SetRTTStatsProvider(rttStats)
	return &BBRController{
		sender:       sender,
		rttStats:     rttStats,
		clock:        clk,
		nextSendTime: time.Now(),
	}
}

// OnPacketSent notifies BBR that a packet was sent.
func (c *BBRController) OnPacketSent(packetNum uint32, bytes int, bytesInFlight int) {
	c.sender.OnPacketSent(
		c.clock.Now(),
		congestion.ByteCount(bytesInFlight),
		congestion.PacketNumber(packetNum),
		congestion.ByteCount(bytes),
		true, // retransmittable
	)
	// Update pacing: next send time based on pacing rate.
	rate := c.PacingRate() // bytes per second
	if rate > 0 {
		interval := time.Duration(float64(bytes) / float64(rate) * float64(time.Second))
		c.nextSendTime = time.Now().Add(interval)
	}
}

// OnPacketAcked notifies BBR that a packet was acknowledged.
// rtt is the measured RTT for this packet (send time → ack receipt).
// All newly-acknowledged packets participate in RTT sampling (§11).
//
// NOTE: the underlying bbrSender.OnPacketAcked is a no-op; the real logic
// lives in OnCongestionEventEx. We route through it here with a single-packet
// event. bytesInFlight is the POST-ack value from UDPReliability; we add back
// the acked bytes because OnCongestionEventEx expects the PRE-event value
// (it subtracts acked bytes itself).
func (c *BBRController) OnPacketAcked(packetNum uint32, bytes int, bytesInFlight int, rtt time.Duration) {
	// Update RTT stats (all acked packets participate).
	c.rttStats.UpdateRTT(rtt, 0)
	now := c.clock.Now()
	c.sender.OnCongestionEventEx(
		congestion.ByteCount(bytesInFlight+bytes), // pre-event in-flight
		now,
		[]congestion.AckedPacketInfo{
			{
				PacketNumber: congestion.PacketNumber(packetNum),
				BytesAcked:   congestion.ByteCount(bytes),
				ReceivedTime: now,
			},
		},
		nil,
	)
}

// OnPacketLost notifies BBR of packet loss.
// Routes through OnCongestionEventEx (the simple OnPacketLost is a no-op).
// bytesInFlight is the POST-loss value; we add back for the pre-event value.
func (c *BBRController) OnPacketLost(packetNum uint32, bytes int, bytesInFlight int) {
	c.sender.OnCongestionEventEx(
		congestion.ByteCount(bytesInFlight+bytes), // pre-event in-flight
		c.clock.Now(),
		nil,
		[]congestion.LostPacketInfo{
			{
				PacketNumber: congestion.PacketNumber(packetNum),
				BytesLost:    congestion.ByteCount(bytes),
			},
		},
	)
}

// CanSend reports whether BBR allows sending (congestion window check).
func (c *BBRController) CanSend(bytesInFlight int) bool {
	return c.sender.CanSend(congestion.ByteCount(bytesInFlight))
}

// CongestionWindow returns the current congestion window in bytes.
func (c *BBRController) CongestionWindow() int {
	return int(c.sender.GetCongestionWindow())
}

// PacingRate returns the current pacing rate in bytes per second.
func (c *BBRController) PacingRate() float64 {
	// Bandwidth is bytes per second in the bbr package.
	return float64(c.sender.PacingRate())
}

// WaitForPacing blocks until the pacing budget allows sending.
// Returns immediately if pacing allows sending now.
func (c *BBRController) WaitForPacing() {
	now := time.Now()
	if now.Before(c.nextSendTime) {
		time.Sleep(c.nextSendTime.Sub(now))
	}
}

// TimeUntilSend returns how long to wait before sending (for non-blocking use).
func (c *BBRController) TimeUntilSend() time.Duration {
	d := time.Until(c.nextSendTime)
	if d < 0 {
		return 0
	}
	return d
}

// InSlowStart reports whether BBR is in slow start.
func (c *BBRController) InSlowStart() bool {
	return c.sender.InSlowStart()
}

// RTTStats returns the RTT tracker (for RTO calculation).
func (c *BBRController) RTTStats() *UDPRTTStats {
	return c.rttStats
}
