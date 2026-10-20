package conf_test

import (
	"encoding/base64"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	misttransport "github.com/xtls/xray-core/transport/internet/mist"
)

func validMistKey(t *testing.T) (cidHex, keyB64 string) {
	t.Helper()
	cidHex = "0123456789abcdef0123456789abcdef" // 16 bytes hex
	keyB64 = base64.StdEncoding.EncodeToString(make([]byte, 32))
	if len(keyB64) == 0 {
		t.Fatal("failed to build test key")
	}
	return cidHex, keyB64
}

func TestMistTransportBuildValid(t *testing.T) {
	cidHex, keyB64 := validMistKey(t)
	c := &MistConfig{
		ClientID:            cidHex,
		AuthKey:             keyB64,
		HeartbeatInterval:   30,
		ShapingHeavyPackets: 32,
		Accounts: map[string]string{
			"abcdef0123456789abcdef0123456789": keyB64,
		},
	}
	msg, err := c.Build()
	if err != nil {
		t.Fatalf("Build() returned unexpected error: %v", err)
	}
	cfg, ok := msg.(*misttransport.Config)
	if !ok {
		t.Fatalf("Build() returned %T, want *misttransport.Config", msg)
	}
	if got := cfg.GetClientId(); got != cidHex {
		t.Errorf("ClientId = %q, want %q", got, cidHex)
	}
	if got := cfg.GetAuthKey(); got != keyB64 {
		t.Errorf("AuthKey mismatch")
	}
	if got := cfg.GetHeartbeatInterval(); got != 30 {
		t.Errorf("HeartbeatInterval = %d, want 30", got)
	}
	if got := cfg.GetShapingHeavyPackets(); got != 32 {
		t.Errorf("ShapingHeavyPackets = %d, want 32", got)
	}
	if got := len(cfg.GetAccounts()); got != 1 {
		t.Fatalf("Accounts len = %d, want 1", got)
	}
	if got := cfg.GetAccounts()[0].GetClientId(); got != "abcdef0123456789abcdef0123456789" {
		t.Errorf("Accounts[0].ClientId = %q", got)
	}
}

func TestMistTransportBuildInvalidClientID(t *testing.T) {
	_, keyB64 := validMistKey(t)
	for _, bad := range []string{
		"",                              // missing
		"deadbeef",                      // only 4 bytes
		strings.Repeat("zz", 16),        // not hex
		strings.Repeat("ab", 17),        // 17 bytes
		"0123456789abcdef0123456789abc", // 15 bytes
	} {
		c := &MistConfig{ClientID: bad, AuthKey: keyB64}
		if _, err := c.Build(); err == nil {
			t.Errorf("Build() with clientId %q: expected error, got nil", bad)
		}
	}
}

func TestMistTransportBuildInvalidAuthKey(t *testing.T) {
	cidHex, _ := validMistKey(t)
	for _, bad := range []string{
		"",
		"not-base64!!!",
		base64.StdEncoding.EncodeToString(make([]byte, 31)), // 31 bytes
		base64.StdEncoding.EncodeToString(make([]byte, 33)), // 33 bytes
	} {
		c := &MistConfig{ClientID: cidHex, AuthKey: bad}
		if _, err := c.Build(); err == nil {
			t.Errorf("Build() with bad authKey: expected error, got nil")
		}
	}
}

func TestMistTransportBuildInvalidAccount(t *testing.T) {
	cidHex, keyB64 := validMistKey(t)
	c := &MistConfig{
		ClientID: cidHex,
		AuthKey:  keyB64,
		Accounts: map[string]string{
			"short": keyB64, // invalid clientId hex length
		},
	}
	if _, err := c.Build(); err == nil {
		t.Error("Build() with invalid account entry: expected error, got nil")
	}
}
