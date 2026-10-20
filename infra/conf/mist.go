package conf

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/mist"
	"google.golang.org/protobuf/proto"
)

// MistClientConfig is the JSON configuration for the Mist outbound.
//   - clientId: 16 bytes, hex-encoded (the CID in SPEC 6.2, sent in clear)
//   - authKey:  32 bytes K_auth, base64(std)-encoded
type MistClientConfig struct {
	Address             *Address `json:"address"`
	Port                uint16   `json:"port"`
	ClientID            string   `json:"clientId"`
	AuthKey             string   `json:"authKey"`
	HeartbeatInterval   uint32   `json:"heartbeatInterval"`
	ShapingHeavyPackets uint32   `json:"shapingHeavyPackets"`
}

func (c *MistClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, errors.New(`mist: "address" is not set`)
	}
	if c.ClientID == "" {
		return nil, errors.New(`mist: "clientId" is not set`)
	}
	if c.AuthKey == "" {
		return nil, errors.New(`mist: "authKey" is not set`)
	}
	if cid, err := hex.DecodeString(c.ClientID); err != nil || len(cid) != 16 {
		return nil, errors.New(`mist: "clientId" must be 16 bytes hex-encoded`)
	}
	if ak, err := base64.StdEncoding.DecodeString(c.AuthKey); err != nil || len(ak) != 32 {
		return nil, errors.New(`mist: "authKey" must be 32 bytes base64(std)-encoded`)
	}
	return &mist.ClientConfig{
		Address:             c.Address.String(),
		Port:                uint32(c.Port),
		ClientId:            c.ClientID,
		AuthKey:             c.AuthKey,
		HeartbeatInterval:   c.HeartbeatInterval,
		ShapingHeavyPackets: c.ShapingHeavyPackets,
	}, nil
}
