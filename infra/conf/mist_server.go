package conf

import (
	mistproxy "github.com/xtls/xray-core/proxy/mist"
	"google.golang.org/protobuf/proto"
)

// MistServerConfig is the JSON configuration for the Mist inbound.
// The ServerConfig proto message is empty: inbound parameters (accounts,
// heartbeat, shaping) arrive through streamSettings' mistSettings at the
// transport layer.
type MistServerConfig struct{}

func (c *MistServerConfig) Build() (proto.Message, error) {
	return &mistproxy.ServerConfig{}, nil
}
