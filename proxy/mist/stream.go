package mist

import (
	"io"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common/errors"
)

// Flow control parameters (SPEC 9.5).
const (
	initStreamWindow      = 256 * 1024 // per-stream initial window
	windowUpdateThreshold = 128 * 1024 // receiver advertises every 128KB consumed
	maxPlainPerFrameBase  = 16366      // 16384 - 2(header tail) - 16(tag); minus padLen per frame
)

// Stream is one multiplexed proxy stream inside a Session (SPEC 9).
// The session read loop is the sole sender to inCh / closer of inCh and
// deadCh, so closing them there is race-free.
type Stream struct {
	id   byte
	sess *Session

	inCh   chan []byte   // inbound frame payloads; closed by read loop on remote FIN
	cur    []byte        // leftover from a partially consumed chunk
	deadCh chan struct{} // closed on RST or session death

	sendWnd int64 // atomic, remaining send window (SPEC 9.5)
	winCh   chan struct{}

	recvSinceUpdate int64 // bytes consumed since last WINDOW_UPDATE

	mu          sync.Mutex
	writeClosed bool // local FIN already sent
	remoteFin   bool // remote FIN received (inCh closed)
	finClosed   bool // inCh already closed
	released    bool
	closeOnce   sync.Once
}

func newStream(sess *Session, id byte) *Stream {
	return &Stream{
		id:      id,
		sess:    sess,
		inCh:    make(chan []byte, 64),
		deadCh:  make(chan struct{}),
		sendWnd: initStreamWindow,
		winCh:   make(chan struct{}, 1),
	}
}

// Read implements io.Reader: byte-stream view of inbound frames.
// Returns io.EOF once the remote FIN is received and buffered data drained.
func (s *Stream) Read(p []byte) (int, error) {
	if len(s.cur) > 0 {
		n := copy(p, s.cur)
		s.cur = s.cur[n:]
		s.sess.accountRx(s, int64(n))
		return n, nil
	}
	select {
	case chunk, ok := <-s.inCh:
		if !ok {
			return 0, io.EOF
		}
		s.cur = chunk
		n := copy(p, s.cur)
		s.cur = s.cur[n:]
		s.sess.accountRx(s, int64(n))
		return n, nil
	case <-s.deadCh:
		return 0, errors.New("mist: stream reset")
	case <-s.sess.doneCh:
		return 0, errors.New("mist: session closed")
	}
}

// ReadDatagram returns the next whole inbound frame payload. Used by the
// UDP bearer stream, where each frame after SYN carries exactly one
// datagram (SPEC 9.4).
func (s *Stream) ReadDatagram() ([]byte, error) {
	select {
	case chunk, ok := <-s.inCh:
		if !ok {
			return nil, io.EOF
		}
		s.sess.accountRx(s, int64(len(chunk)))
		return chunk, nil
	case <-s.deadCh:
		return nil, errors.New("mist: stream reset")
	case <-s.sess.doneCh:
		return nil, errors.New("mist: session closed")
	}
}

// Write implements io.Writer: chunks payload into frames, honoring the
// per-stream send window (SPEC 9.5). Blocks when the window is exhausted
// until a WINDOW_UPDATE arrives.
func (s *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		for atomic.LoadInt64(&s.sendWnd) <= 0 {
			select {
			case <-s.winCh:
			case <-s.deadCh:
				return total, errors.New("mist: stream reset")
			case <-s.sess.doneCh:
				return total, errors.New("mist: session closed")
			}
		}
		w := atomic.LoadInt64(&s.sendWnd)
		n := int64(len(p))
		if n > w {
			n = w
		}
		if n <= 0 {
			continue
		}
		if err := s.sess.writeFrame(s.id, p[:n]); err != nil {
			return total, err
		}
		atomic.AddInt64(&s.sendWnd, -n)
		total += int(n)
		p = p[n:]
	}
	return total, nil
}

// CloseWrite sends FIN (half-close, SPEC 9.3). Idempotent.
func (s *Stream) CloseWrite() error {
	s.mu.Lock()
	if s.writeClosed {
		s.mu.Unlock()
		return nil
	}
	s.writeClosed = true
	s.mu.Unlock()
	// Best effort: a failed FIN just means the session is dying anyway.
	_ = s.sess.writeFrame(s.id|flagFIN, nil)
	return nil
}

// Reset sends RST and releases the stream immediately (SPEC 9.3).
func (s *Stream) Reset() {
	_ = s.sess.writeFrame(s.id|flagRST, nil)
	s.release()
}

// done releases the stream ID. If the stream did not terminate cleanly
// (local FIN sent and remote FIN seen), an RST is sent first so the
// server can drop its state promptly.
func (s *Stream) done() {
	s.mu.Lock()
	clean := s.writeClosed && s.remoteFin
	s.mu.Unlock()
	if !clean {
		_ = s.sess.writeFrame(s.id|flagRST, nil)
	}
	s.release()
}

func (s *Stream) release() {
	s.sess.mu.Lock()
	if !s.released {
		s.released = true
		delete(s.sess.streams, s.id)
	}
	s.sess.mu.Unlock()
	s.closeOnce.Do(func() { close(s.deadCh) })
}

// onRemoteFin is called by the session read loop when a FIN flag arrives.
func (s *Stream) onRemoteFin() {
	s.mu.Lock()
	if s.finClosed {
		s.mu.Unlock()
		return
	}
	s.finClosed = true
	s.remoteFin = true
	s.mu.Unlock()
	// Sole sender is the read loop; no more chunks will arrive after FIN.
	close(s.inCh)
}

// onReset is called by the session read loop when an RST flag arrives.
func (s *Stream) onReset() {
	s.release()
	s.closeOnce.Do(func() { close(s.deadCh) })
}

// addWindow credits the send window (WINDOW_UPDATE, SPEC 9.5).
func (s *Stream) addWindow(inc uint32) {
	if inc == 0 {
		return
	}
	atomic.AddInt64(&s.sendWnd, int64(inc))
	select {
	case s.winCh <- struct{}{}:
	default:
	}
}
