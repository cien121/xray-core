package mist

import (
	"context"
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}

// Server is the Mist inbound handler. The transport layer (hub) calls
// Process once per accepted stream, with the Mist CONNECT request payload
// ([ATYP][ADDR][PORT], the SYN payload per SPEC 9.2) as the first bytes on
// the stream. This handler decodes the request and hands the stream to the
// router; all Mist framing/TLS/auth is owned by the transport layer.
type Server struct{}

// NewServer creates a new Mist inbound Server. The ServerConfig message is
// empty: inbound parameters (accounts, heartbeat, shaping) arrive through
// streamSettings' mistSettings at the transport layer.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	return &Server{}, nil
}

// decodeConnectRequest parses one CONNECT request from r:
// [ATYP][ADDR][PORT(2,BE)] (SPEC 9.2). ATYP 0x01=IPv4(4 bytes),
// 0x04=IPv6(16 bytes), 0x03=domain(1 byte length + name). Every length is
// validated strictly: overlong or truncated input returns an error.
func decodeConnectRequest(r io.Reader) (net.Destination, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return net.Destination{}, errors.New("mist: failed to read connect request atyp").Base(err)
	}

	var address net.Address
	switch atyp[0] {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return net.Destination{}, errors.New("mist: truncated ipv4 address in connect request").Base(err)
		}
		address = net.IPAddress(ip[:])
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return net.Destination{}, errors.New("mist: truncated ipv6 address in connect request").Base(err)
		}
		address = net.IPAddress(ip[:])
	case 0x03: // Domain
		var dlen [1]byte
		if _, err := io.ReadFull(r, dlen[:]); err != nil {
			return net.Destination{}, errors.New("mist: truncated domain length in connect request").Base(err)
		}
		if dlen[0] == 0 {
			return net.Destination{}, errors.New("mist: empty domain in connect request")
		}
		// dlen is one byte: at most 255 bytes, no overlong read possible.
		domain := make([]byte, dlen[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return net.Destination{}, errors.New("mist: truncated domain in connect request").Base(err)
		}
		address = net.DomainAddress(string(domain))
	default:
		return net.Destination{}, errors.New("mist: unsupported atyp in connect request: ", atyp[0])
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(r, portBytes[:]); err != nil {
		return net.Destination{}, errors.New("mist: truncated port in connect request").Base(err)
	}

	dest := net.TCPDestination(address, net.Port(binary.BigEndian.Uint16(portBytes[:])))
	if !dest.IsValid() {
		return net.Destination{}, errors.New("mist: invalid destination in connect request")
	}
	return dest, nil
}

// Network implements proxy.Inbound: v0.1 only supports TCP CONNECT streams.
func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// Process handles one inbound Mist stream: decode the CONNECT request,
// dispatch it through the router, then shuttle bytes in both directions.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// v0.1: the inbound side only supports TCP CONNECT streams; there is no
	// UDP relay on inbound yet.
	if network != net.Network_TCP {
		return errors.New("mist: udp relay is not supported on inbound (v0.1)")
	}

	dest, err := decodeConnectRequest(conn)
	if err != nil {
		return err
	}
	errors.LogInfo(ctx, "mist: tunneling request to ", dest)

	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		// SPEC 9.2: report the failure in-band so the client's ReadFull
		// for the result code terminates instead of hanging.
		_, _ = conn.Write([]byte{codeNetUnreachable})
		return errors.New("mist: failed to dispatch request").Base(err)
	}
	// SPEC 9.2: 1-byte CONNECT result. The existing outbound (client.go
	// processTCP) blocks on ReadFull for exactly this byte before piping.
	if _, err := conn.Write([]byte{codeSuccess}); err != nil {
		return errors.New("mist: failed to write connect result").Base(err)
	}

	// Reverse of client.go processTCP: conn is the Mist stream (client side),
	// link bridges to the outbound chain.
	requestDone := func() error {
		return buf.Copy(buf.NewReader(conn), link.Writer)
	}
	responseDone := func() error {
		return buf.Copy(link.Reader, buf.NewWriter(conn))
	}
	responseDoneAndCloseWriter := task.OnSuccess(responseDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDone, responseDoneAndCloseWriter); err != nil {
		return errors.New("mist: connection ends").Base(err)
	}
	return nil
}
