package mist

import (
	"strings"
	"testing"
)

// safeTestCodec pretends to be the future Phase 0 QUICInitialCodec:
// production-safe, allowed on any address.
type safeTestCodec struct{ RandomCiphertextCodec }

func (c *safeTestCodec) ProductionSafe() bool { return true }

func TestCheckInitialCodecSafeForAddr(t *testing.T) {
	unsafe := &RandomCiphertextCodec{}
	safe := &safeTestCodec{}

	cases := []struct {
		name    string
		codec   InitialCodec
		addr    string
		wantErr bool
	}{
		// Unsafe codec on private/loopback: allowed.
		{"loopback4", unsafe, "127.0.0.1:1443", false},
		{"loopback6", unsafe, "[::1]:1443", false},
		{"localhost", unsafe, "localhost:1443", false},
		{"rfc1918_10", unsafe, "10.0.0.5:1443", false},
		{"rfc1918_172", unsafe, "172.16.3.9:1443", false},
		{"rfc1918_192", unsafe, "192.168.1.5:1443", false},
		{"bare_loopback", unsafe, "127.0.0.1", false},
		// Unsafe codec on public/unspecified: rejected.
		{"public_v4", unsafe, "148.135.10.19:1443", true},
		{"public_v6", unsafe, "[2607:f130:0:113::31]:1443", true},
		{"public_bare", unsafe, "8.8.8.8", true},
		{"unspecified_v4", unsafe, "0.0.0.0:1443", true},
		{"unspecified_v6", unsafe, "[::]:1443", true},
		{"empty", unsafe, "", true},
		// Safe codec: allowed everywhere.
		{"safe_public", safe, "148.135.10.19:1443", false},
		{"safe_unspecified", safe, "0.0.0.0:1443", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckInitialCodecSafeForAddr(tc.codec, tc.addr)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for addr %q, got nil", tc.addr)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for addr %q: %v", tc.addr, err)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "随机密文 Initial 不能用于真实网络") {
				t.Fatalf("error must state the reason in Chinese, got: %v", err)
			}
		})
	}
}

func TestCodecProductionSafeFailClosed(t *testing.T) {
	// RandomCiphertextCodec: unsafe.
	if CodecProductionSafe(&RandomCiphertextCodec{}) {
		t.Fatal("RandomCiphertextCodec must not be production-safe")
	}
	// Unknown implementation (no ProductionSafe method): unsafe by default.
	if CodecProductionSafe(&opaqueTestCodec{}) {
		t.Fatal("unknown codec implementations must be unsafe by default")
	}
	// Marker implemented: honored.
	if !CodecProductionSafe(&safeTestCodec{}) {
		t.Fatal("ProductionSafe() == true must be honored")
	}
}

// opaqueTestCodec implements InitialCodec without the ProductionSafe marker
// (embeds the interface, so no ProductionSafe method is promoted).
type opaqueTestCodec struct{ InitialCodec }
