package conf

import (
	"encoding/base64"
	"encoding/hex"
	"maps"
	"slices"

	"github.com/xtls/xray-core/common/errors"
	misttransport "github.com/xtls/xray-core/transport/internet/mist"
	"google.golang.org/protobuf/proto"
)

// MistConfig is the JSON configuration for the Mist transport settings
// (streamSettings.mistSettings), shared by the inbound (server side, which
// reads Accounts) and outbound (client side) transports.
//   - clientId: 16 bytes, hex-encoded
//   - authKey:  32 bytes, base64(std)-encoded
//   - accounts: map from clientId hex to authKey base64(std) (server side)
type MistConfig struct {
	ClientID            string            `json:"clientId"`
	AuthKey             string            `json:"authKey"`
	HeartbeatInterval   uint32            `json:"heartbeatInterval"`
	ShapingHeavyPackets uint32            `json:"shapingHeavyPackets"`
	Accounts            map[string]string `json:"accounts"`
}

func checkMistCredential(cidHex, keyB64 string) error {
	if cidHex == "" {
		return errors.New(`mist: "clientId" is not set`)
	}
	if keyB64 == "" {
		return errors.New(`mist: "authKey" is not set`)
	}
	if cid, err := hex.DecodeString(cidHex); err != nil || len(cid) != 16 {
		return errors.New(`mist: "clientId" must be 16 bytes hex-encoded`)
	}
	if ak, err := base64.StdEncoding.DecodeString(keyB64); err != nil || len(ak) != 32 {
		return errors.New(`mist: "authKey" must be 32 bytes base64(std)-encoded`)
	}
	return nil
}

func (c *MistConfig) Build() (proto.Message, error) {
	if err := checkMistCredential(c.ClientID, c.AuthKey); err != nil {
		return nil, err
	}
	config := &misttransport.Config{
		ClientId:            c.ClientID,
		AuthKey:             c.AuthKey,
		HeartbeatInterval:   c.HeartbeatInterval,
		ShapingHeavyPackets: c.ShapingHeavyPackets,
	}
	// Sorted for deterministic config output.
	for _, cidHex := range slices.Sorted(maps.Keys(c.Accounts)) {
		if err := checkMistCredential(cidHex, c.Accounts[cidHex]); err != nil {
			return nil, errors.New(`mist: accounts entry "`, cidHex, `": `).Base(err)
		}
		config.Accounts = append(config.Accounts, &misttransport.Account{
			ClientId: cidHex,
			AuthKey:  c.Accounts[cidHex],
		})
	}
	return config, nil
}
