// Package mistcore: Mist UDP frame protocol.
//
// UDP uses whole-packet AEAD (one encryption per UDP datagram), unlike TCP's
// per-frame encryption. Frame headers are NOT visible on the wire.
//
// Frame format (plaintext, after decryption):
//   [LEN(2)][TYPE(1)][SID(1)][PAYLOAD]
//
// UDP datagram:
//   [QUIC short header (13)][AEAD(frame1|frame2|...)]

package mist

import (
	"encoding/binary"
	"errors"
)

// UDP frame types (§4.1).
const (
	UDPFramePadding       = 0x00
	UDPFrameStream        = 0x01
	UDPFrameSyn           = 0x02
	UDPFrameFin           = 0x03
	UDPFrameRst           = 0x04
	UDPFrameAck           = 0x05
	UDPFramePing          = 0x06
	UDPFramePong          = 0x07
	UDPFrameDatagram      = 0x08
	UDPFramePathChallenge = 0x09
	UDPFramePathResponse  = 0x0A
	UDPFrameMigrate       = 0x0B
	UDPFrameMaxStreamData = 0x0C
	UDPFrameWindowUpdate  = 0x0D
)

// UDP limits (§4.1).
const (
	// MaxUDPPlaintext is the max decrypted payload per UDP datagram.
	// 1350 (MTU) - 13 (QUIC header) - 16 (AEAD tag) = 1321, rounded to 1300.
	MaxUDPPlaintext = 1300

	// QUICShortHeaderLen is the fixed short header size.
	QUICShortHeaderLen = 13
)

// UDPFrame is a decoded Mist UDP frame.
type UDPFrame struct {
	Type    byte
	SID     byte
	Payload []byte
}

// EncodeUDPFrame encodes a single frame: [LEN(2)][TYPE(1)][SID(1)][PAYLOAD].
// LEN = 2 + len(PAYLOAD) (bytes after the LEN field itself).
func EncodeUDPFrame(frameType byte, sid byte, payload []byte) []byte {
	// LEN(2) + TYPE(1) + SID(1) + PAYLOAD
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(out[0:], uint16(2+len(payload)))
	out[2] = frameType
	out[3] = sid
	copy(out[4:], payload)
	return out
}

// DecodeUDPFrames decodes concatenated frames from a decrypted payload.
// Returns the list of frames.
func DecodeUDPFrames(plaintext []byte) ([]UDPFrame, error) {
	var frames []UDPFrame
	off := 0
	for off < len(plaintext) {
		if off+4 > len(plaintext) {
			return nil, errors.New("udp: frame header truncated")
		}
		length := int(binary.BigEndian.Uint16(plaintext[off:]))
		frameType := plaintext[off+2]
		sid := plaintext[off+3]
		if length < 2 {
			return nil, errors.New("udp: invalid frame length")
		}
		payloadLen := length - 2
		if off+4+payloadLen > len(plaintext) {
			return nil, errors.New("udp: frame payload truncated")
		}
		frames = append(frames, UDPFrame{
			Type:    frameType,
			SID:     sid,
			Payload: plaintext[off+4 : off+4+payloadLen],
		})
		off += 4 + payloadLen
	}
	return frames, nil
}

// EncodeStreamFrame encodes a STREAM frame: [OFFSET(8)][DATA].
func EncodeStreamFrame(sid byte, offset uint64, data []byte) []byte {
	payload := make([]byte, 8+len(data))
	binary.BigEndian.PutUint64(payload[0:], offset)
	copy(payload[8:], data)
	return EncodeUDPFrame(UDPFrameStream, sid, payload)
}

// EncodeFinFrame encodes a FIN frame: [FINAL_SIZE(8)].
func EncodeFinFrame(sid byte, finalSize uint64) []byte {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload[0:], finalSize)
	return EncodeUDPFrame(UDPFrameFin, sid, payload)
}

// EncodePaddingFrame encodes a PADDING frame with the given total frame size.
// Per §4.1: [LEN(2)][TYPE(1)=0x00][SID(1)][zeros], minimum 4 bytes.
func EncodePaddingFrame(sid byte, totalLen int) []byte {
	if totalLen < 4 {
		totalLen = 4
	}
	payloadLen := totalLen - 4
	payload := make([]byte, payloadLen) // zeros
	return EncodeUDPFrame(UDPFramePadding, sid, payload)
}

// EncodeAckFrame encodes an ACK frame: [LARGEST(4)][RANGE_N(1)][RANGE_1(8)]...
// Each range is [start(4)][end(4)] (closed interval, big-endian).
func EncodeAckFrame(sid byte, largest uint32, ranges [][2]uint32) []byte {
	if len(ranges) > 8 {
		ranges = ranges[:8]
	}
	payload := make([]byte, 4+1+len(ranges)*8)
	binary.BigEndian.PutUint32(payload[0:], largest)
	payload[4] = byte(len(ranges))
	off := 5
	for _, r := range ranges {
		binary.BigEndian.PutUint32(payload[off:], r[0])
		binary.BigEndian.PutUint32(payload[off+4:], r[1])
		off += 8
	}
	return EncodeUDPFrame(UDPFrameAck, sid, payload)
}

// DecodeAckFrame decodes an ACK frame payload.
func DecodeAckFrame(payload []byte) (largest uint32, ranges [][2]uint32, err error) {
	if len(payload) < 5 {
		return 0, nil, errors.New("udp: ack payload too short")
	}
	largest = binary.BigEndian.Uint32(payload[0:])
	n := int(payload[4])
	if len(payload) < 5+n*8 {
		return 0, nil, errors.New("udp: ack ranges truncated")
	}
	for i := 0; i < n; i++ {
		start := binary.BigEndian.Uint32(payload[5+i*8:])
		end := binary.BigEndian.Uint32(payload[5+i*8+4:])
		ranges = append(ranges, [2]uint32{start, end})
	}
	return largest, ranges, nil
}

// BuildShortHeader builds a QUIC short header (13 bytes).
//
// Format (§3.2):
//   [0|1|S|R|R|K|P P][DCID(8)][PacketNum(4)]
//   bit0=0, bit1=1 (short header)
//   S = spin bit (random)
//   K = key phase (0)
//   P P = 0b11 (4-byte packet number)
//
// For Phase 1 simplified: no header protection mask (mask = 0).
// Phase 2 will implement RFC 9001 §5.4.4.
func BuildShortHeader(dcid [8]byte, packetNum uint32, spinBit bool) [13]byte {
	var h [13]byte
	// Byte 0: 0|1|S|0|0|0|1|1
	//   bit0=0, bit1=1, bit2=S, bits 3-4 = R R (0), bit5=K (0), bits 6-7 = P P (0b11)
	h[0] = 0x40 | 0x03 // 0b01000011
	if spinBit {
		h[0] |= 0x20 // set S bit (bit 2)
	}
	copy(h[1:], dcid[:])
	// Packet number (4 bytes, big-endian)
	// Simplified: no mask applied in Phase 1.
	binary.BigEndian.PutUint32(h[9:], packetNum)
	return h
}

// ParseShortHeader parses a QUIC short header.
// Returns dcid, packet number, and spin bit.
// For Phase 1 simplified: no header protection removal.
func ParseShortHeader(header []byte) (dcid [8]byte, packetNum uint32, spinBit bool, err error) {
	if len(header) < QUICShortHeaderLen {
		return dcid, 0, false, errors.New("udp: short header too short")
	}
	// Check bits: bit0=0, bit1=1
	if header[0]&0xC0 != 0x40 {
		return dcid, 0, false, errors.New("udp: not a short header")
	}
	spinBit = header[0]&0x20 != 0
	copy(dcid[:], header[1:9])
	// Simplified: no mask removal in Phase 1.
	packetNum = binary.BigEndian.Uint32(header[9:13])
	return dcid, packetNum, spinBit, nil
}
