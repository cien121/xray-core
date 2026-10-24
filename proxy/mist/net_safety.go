// Network safety gate: single choke point for all UDP dial/listen.
//
// Background: the Phase 1 random-ciphertext Initial is a DPI fingerprint.
// It must never run on a public network, even by accident. The gate lives
// here in mistcore (not in each cmd/ entry point) so a new entry point
// (e.g. the xray-core fork client) cannot bypass it by forgetting to call
// the check. This is the same lesson as the send scheduler: checks in
// cmd/ get skipped; checks in the library constructor cannot.
//
// Two constructors are the only supported paths:
//   - ResolvePeerAddrSafe: client side. Resolves a "host:port" peer address,
//     runs the safety gate on EVERY resolved IP, and returns a *net.UDPAddr
//     built from a checked IP literal. The caller must use the returned
//     address directly; it must not re-resolve the hostname (TOCTOU).
//   - ListenUDPSafe: server side. Checks the listen address and binds.
//
// Fail-closed: unresolvable hostnames, unspecified addresses, unknown
// address types, and any check failure are all denied.
package mist

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// cgnatV4 is 100.64.0.0/10 (RFC 6598, carrier-grade NAT). It is not RFC 1918
// private. Default policy: deny. If a deployment needs it, add an explicit
// allowlist entry; do not widen IsPrivateOrLoopbackIP.
var cgnatV4 = net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.CIDRMask(10, 32)}

// normalizeIPForCheck maps an IP to the form the policy checks.
// IPv4-mapped IPv6 (::ffff:a.b.c.d) is reduced to its IPv4 form first,
// otherwise a public IPv4 would look like a (non-private) IPv6 address and
// the policy wording gets confusing. Returns nil for unparseable input.
func normalizeIPForCheck(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// ipAllowedByPolicy reports whether ip may be used with a non-production-safe
// codec. Allowed: loopback, RFC 1918 private, IPv6 ULA/link-local.
// Denied: everything else, including 100.64.0.0/10 (CGNAT), unspecified,
// multicast, and unparseable input. Fail-closed.
func ipAllowedByPolicy(ip net.IP) bool {
	ip = normalizeIPForCheck(ip)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if cgnatV4.Contains(ip) {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// resolveAllIPs resolves host to every IP address, without dialing.
// "localhost" maps to 127.0.0.1. IP literals (with optional zone) parse
// directly. Other names go through the resolver with a timeout; resolution
// failure returns an error (fail-closed, not an empty list).
func resolveAllIPs(ctx context.Context, host string) ([]net.IP, error) {
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}
	if strings.EqualFold(host, "localhost") {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	if i := strings.LastIndex(host, "%"); i >= 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", host)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// checkCodecForIPs runs the safety gate for codec against every IP.
// If the codec is production-safe, any address is allowed.
// Otherwise every IP must pass ipAllowedByPolicy; the first failure denies
// the whole address. Returns the first allowed IP for dialing.
func checkCodecForIPs(codec InitialCodec, addrForMsg string, ips []net.IP) (net.IP, error) {
	if CodecProductionSafe(codec) {
		if len(ips) == 0 {
			return nil, fmt.Errorf("mist: no addresses for %q", addrForMsg)
		}
		return ips[0], nil
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("mist: 随机密文 Initial 不能用于真实网络 (addr=%q): 无可用地址，fail closed", addrForMsg)
	}
	for _, ip := range ips {
		norm := normalizeIPForCheck(ip)
		if norm == nil || norm.IsUnspecified() {
			return nil, fmt.Errorf("mist: 随机密文 Initial 不能用于真实网络 (codec=%T, addr=%q): "+
				"监听/目标地址未指定或不可解析，fail closed；内测请显式绑定 127.0.0.1 或内网地址", codec, addrForMsg)
		}
		if !ipAllowedByPolicy(ip) {
			return nil, fmt.Errorf("mist: 随机密文 Initial 不能用于真实网络 (codec=%T, addr=%q, ip=%s): "+
				"随机密文 Initial 是可识别的指纹，仅限内网/回环测试；公网请等待 Phase 0 真 QUIC Initial", codec, addrForMsg, norm.String())
		}
	}
	return normalizeIPForCheck(ips[0]), nil
}

// splitHostPort extracts host and port from "host:port", "[v6]:port", or a
// bare host (port defaults to ""). It never resolves.
func splitHostPort(addr string) (host, port string) {
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(h, "[]"), p
	}
	return strings.Trim(addr, "[]"), ""
}

// ResolvePeerAddrSafe is the client-side choke point. It resolves addr,
// runs the safety gate on every resolved IP, and returns a *net.UDPAddr
// built from a checked IP literal plus the original port.
//
// The caller MUST use the returned address for dialing/sending and MUST NOT
// re-resolve the hostname: the IP was checked, a fresh resolution could
// return a different (unchecked) address (TOCTOU).
func ResolvePeerAddrSafe(ctx context.Context, addr string, codec InitialCodec) (*net.UDPAddr, error) {
	host, port := splitHostPort(addr)
	if host == "" {
		return nil, fmt.Errorf("mist: 随机密文 Initial 不能用于真实网络 (addr=%q): 目标地址为空，fail closed", addr)
	}
	ips, err := resolveAllIPs(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("mist: 随机密文 Initial 不能用于真实网络 (addr=%q): %v，fail closed", addr, err)
	}
	checked, err := checkCodecForIPs(codec, addr, ips)
	if err != nil {
		return nil, err
	}
	p := 0
	if port != "" {
		var pi int
		if _, err := fmt.Sscanf(port, "%d", &pi); err != nil || pi < 0 || pi > 65535 {
			return nil, fmt.Errorf("mist: invalid port %q in %q", port, addr)
		}
		p = pi
	}
	return &net.UDPAddr{IP: checked, Port: p}, nil
}

// ListenUDPSafe is the server-side choke point. It checks the listen address
// with the same policy as the client side and binds. Unspecified listen
// addresses (0.0.0.0, ::, empty host) are denied: they bind all interfaces,
// including public ones.
func ListenUDPSafe(ctx context.Context, addr string, codec InitialCodec) (*net.UDPConn, error) {
	host, port := splitHostPort(addr)
	if host == "" {
		return nil, fmt.Errorf("mist: 随机密文 Initial 不能用于真实网络 (addr=%q): "+
			"监听地址未指定，fail closed；内测请显式绑定 127.0.0.1 或内网地址", addr)
	}
	ips, err := resolveAllIPs(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("mist: 随机密文 Initial 不能用于真实网络 (addr=%q): %v，fail closed", addr, err)
	}
	checked, err := checkCodecForIPs(codec, addr, ips)
	if err != nil {
		return nil, err
	}
	p := 0
	if port != "" {
		var pi int
		if _, err := fmt.Sscanf(port, "%d", &pi); err != nil || pi < 0 || pi > 65535 {
			return nil, fmt.Errorf("mist: invalid port %q in %q", port, addr)
		}
		p = pi
	}
	bindAddr := &net.UDPAddr{IP: checked, Port: p}
	conn, err := net.ListenUDP("udp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("mist: listen %s: %w", bindAddr.String(), err)
	}
	// Enlarge receive buffer for burst tolerance (cellular can deliver
	// 100+ packets at once, ~150KB). The system cap net.core.rmem_max
	// must be >= this value, otherwise the kernel silently truncates.
	// 4MB is well under the typical 16MB max.
	const rcvBufSize = 4 * 1024 * 1024
	if err := conn.SetReadBuffer(rcvBufSize); err != nil {
		conn.Close()
		return nil, fmt.Errorf("mist: set read buffer %d: %w", rcvBufSize, err)
	}
	return conn, nil
}

// resolveWithTimeout is a small helper for callers that need a context.
func resolveWithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}
