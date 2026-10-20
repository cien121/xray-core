package mist

import (
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

// serverSession is the server side of one Mist session. It reuses the
// (copied) client Session as the Stream host, with keys and the write
// nonce direction remapped to the server's perspective:
//
//	Session.kC2S   = actual kS2C  (frames the server WRITES)
//	Session.kS2C   = actual kC2S  (frames the server READS)
//	Session.writeDir = dirS2C     (server->client nonce direction word)
//
// The remap is mechanical, not a wire change: the server's read loop
// decrypts with (kS2C field, dirC2S) and Stream.Write encrypts with (kC2S
// field, dirS2C), exactly matching what the client expects. The client's
// readLoop/dispatch cannot be reused (they ignore SYNs, assuming only the
// client initiates streams), so the server runs its own read loop and
// control handler below. The server never opens streams itself (v0.1:
// only the client initiates streams, SPEC 9.1).
type serverSession struct {
	sess    *Session
	handler internet.ConnHandler
}

func newServerSession(conn net.Conn, kC2S, kS2C [32]byte, handler internet.ConnHandler) *serverSession {
	params := sessionParams{
		hb: defaultHeartbeatSec * time.Second,
		shaping: shapingParams{
			heavyPackets: defaultHeavyPackets,
			padMin:       defaultShapingPadMin,
			padMax:       defaultShapingPadMax,
			jitterMaxMs:  defaultShapingJitterMs,
			tailPad:      0,
		},
	}
	s := newSession(conn, params)
	s.kC2S = kS2C // write key: server -> client
	s.kS2C = kC2S // read key:  client -> server
	s.writeDir = dirS2C
	s.epoch = 0
	return &serverSession{sess: s, handler: handler}
}

// readLoop decrypts inbound (C2S) frames and dispatches them per stream.
func (ss *serverSession) readLoop() {
	s := ss.sess
	defer s.close()
	for s.alive() {
		ctr := atomic.AddUint32(&s.s2cCtr, 1) - 1
		sidFlags, pt, err := readRawFrame(s.conn, s.kS2C[:], s.epoch, dirC2S, ctr)
		if err != nil {
			// AEAD failure or IO error: silent close (anti-probing).
			return
		}
		ss.dispatch(sidFlags, pt)
	}
}

// dispatch routes one decrypted frame. A SYN on an unknown stream ID
// accepts a new stream and hands it to the transport handler; FIN/RST are
// passed through to the Stream's close signaling.
func (ss *serverSession) dispatch(sidFlags byte, pt []byte) {
	s := ss.sess
	sid := sidFlags & 0x0F
	flags := sidFlags & 0xF0
	if sid == 0 {
		ss.handleControl(pt)
		return
	}
	s.mu.Lock()
	st := s.streams[sid]
	if st == nil && flags&flagSYN != 0 {
		st = newStream(s, sid)
		s.streams[sid] = st
		s.mu.Unlock()
		sc := &streamConn{s: st, local: s.conn.LocalAddr(), remote: s.conn.RemoteAddr()}
		go ss.handler(sc)
	} else {
		s.mu.Unlock()
	}
	if st == nil {
		return
	}
	if flags&flagRST != 0 {
		st.onReset()
		return
	}
	if len(pt) > 0 {
		select {
		case st.inCh <- pt:
		case <-st.deadCh:
			// Stream was released concurrently; drop the frame instead
			// of stalling the read loop.
		case <-s.doneCh:
			return
		}
	}
	if flags&flagFIN != 0 {
		st.onRemoteFin()
	}
}

// handleControl serves the server side of the control stream (SPEC 9.6).
// The server never initiates PINGs, but it must answer them, otherwise the
// client's heartbeat declares the session dead (SPEC 10.1).
func (ss *serverSession) handleControl(pt []byte) {
	if len(pt) == 0 {
		return
	}
	s := ss.sess
	switch pt[0] {
	case ctrlPing:
		if len(pt) < 9 {
			return
		}
		resp := append([]byte{ctrlPong}, pt[1:9]...)
		_ = s.writeFrame(0x00, resp) // best effort
	case ctrlPong:
		// The server never pings; ignore.
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
