// Package mistcore: Mist UDP packet pacing.
//
// Implements paced sending per UDP-DESIGN.md §7.3 (user explicitly requested:
// "reference Hy2's packet sending speed").
//
// The BBR controller (udp_bbr.go) has built-in pacing via PacingRate().
// This file provides a standalone pacer for use by the reliability layer
// when BBR is not yet active (e.g., before first RTT sample), or for
// testing. The pacer enforces uniform inter-packet gaps:
//
//   interval = packet_size / pacing_rate
//
// rather than bursty sends.
package mist

import (
	"sync"
	"time"
)

// UDPPacer enforces paced packet transmission.
type UDPPacer struct {
	mu sync.Mutex
	// pacingRate is bytes per second.
	pacingRate float64
	// nextSendTime is the earliest time the next packet may go out.
	nextSendTime time.Time
}

// NewUDPPacer creates a pacer with the given initial rate (bytes/sec).
// If rate <= 0, pacing is disabled (sends immediately).
func NewUDPPacer(initialRate float64) *UDPPacer {
	return &UDPPacer{
		pacingRate:   initialRate,
		nextSendTime: time.Now(),
	}
}

// SetRate updates the pacing rate (bytes/sec), typically from BBR.PacingRate().
func (p *UDPPacer) SetRate(bytesPerSec float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pacingRate = bytesPerSec
}

// PacketSent records that a packet of the given size was sent,
// advancing the next allowed send time.
func (p *UDPPacer) PacketSent(size int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pacingRate <= 0 {
		return
	}
	interval := time.Duration(float64(size) / p.pacingRate * float64(time.Second))
	now := time.Now()
	if p.nextSendTime.Before(now) {
		p.nextSendTime = now
	}
	p.nextSendTime = p.nextSendTime.Add(interval)
}

// Delay returns how long to wait before sending the next packet.
// Returns 0 if sending is allowed immediately.
func (p *UDPPacer) Delay() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	d := time.Until(p.nextSendTime)
	if d < 0 {
		return 0
	}
	return d
}

// Wait blocks until pacing allows the next send.
func (p *UDPPacer) Wait() {
	if d := p.Delay(); d > 0 {
		time.Sleep(d)
	}
}
