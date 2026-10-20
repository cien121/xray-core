package mist

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestDecodeConnectRequest(t *testing.T) {
	ipv4 := net.TCPDestination(net.IPAddress([]byte{1, 2, 3, 4}), 443)
	domain := net.TCPDestination(net.DomainAddress("example.com"), 80)
	ipv6 := net.TCPDestination(net.IPAddress(bytes.Repeat([]byte{0x20, 0x01}, 8)), 8443)

	valid := []struct {
		name string
		raw  []byte
		want net.Destination
	}{
		{"ipv4", []byte{0x01, 1, 2, 3, 4, 0x01, 0xbb}, ipv4},
		{"domain", append(append([]byte{0x03, 11}, "example.com"...), 0x00, 0x50), domain},
		{"ipv6", append(append([]byte{0x04}, bytes.Repeat([]byte{0x20, 0x01}, 8)...), 0x20, 0xfb), ipv6},
	}
	for _, tc := range valid {
		got, err := decodeConnectRequest(bytes.NewReader(tc.raw))
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
			continue
		}
		if got.String() != tc.want.String() {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}

	invalid := []struct {
		name string
		raw  []byte
	}{
		{"empty", []byte{}},
		{"bad atyp", []byte{0x02, 1, 2, 3, 4, 0, 80}},
		{"truncated ipv4", []byte{0x01, 1, 2}},
		{"truncated ipv6", []byte{0x04, 1, 2, 3}},
		{"truncated port", []byte{0x01, 1, 2, 3, 4, 0x01}},
		{"empty domain", []byte{0x03, 0x00, 0x00, 0x50}},
		{"truncated domain", []byte{0x03, 0x05, 'a', 'b'}},
		{"domain missing port", append(append([]byte{0x03, 0x03}, "abc"...), 0x00)},
	}
	for _, tc := range invalid {
		if _, err := decodeConnectRequest(bytes.NewReader(tc.raw)); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}
