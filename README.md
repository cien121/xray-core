# ArasClient Core — Xray-core

Fork of [XTLS/Xray-core](https://github.com/XTLS/Xray-core) v26.9.1 used as the core engine of [ArasClient](https://github.com/ArasTey/ArasClient).

## What's added on top of upstream

| Feature | Description |
|---|---|
| **AnyTLS** | Full outbound protocol: TLS session multiplexing with padding, UDP over TCP (UoT), built from the [sing-anytls](https://github.com/anytls/sing-anytls) reference implementation |
| **AmneziaWG 3.1** | WireGuard outbound now runs on [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) **v3.1** — junk packet params `Jc / Jmin / Jmax / S1 / S2 / H1–H4` supported at device level (UAPI-correct order) |
| **`allowInsecure` restored** | Legacy `allowInsecure: true` maps to the new `insecure_skip_verify` field instead of being rejected |
| **H3/H4 headers fixed** | Cookie (H3) and transport (H4) packet headers were mislabeled/missing — all four now emitted |
| **Mist (雾)** | Self-developed proxy protocol: true TLS 1.3 + uTLS Chrome fingerprint, XChaCha20-Poly1305, multiplexing, traffic shaping. See [Mist Protocol](#mist-protocol) below |


## Mist Protocol

**Mist (雾)** is a self-developed proxy protocol focused on high disguise, anti-blocking, high speed, and stability.

### Features
- True TLS 1.3 with real domain certificates + uTLS Chrome fingerprint camouflage
- XChaCha20-Poly1305 encryption
- Multiplexing over single connection
- Traffic shaping (heavy for first 32 packets, light after)
- Heartbeat + session resume
- SNI-based coexistence with Reality/xhttp on same port

### Building with Mist

```bash
# Clone the mist branch
git clone -b mist https://github.com/cien121/xray-core.git
cd xray-core

# Build (requires Go 1.27+)
go build -o xray ./main
```

### Client Configuration (Outbound)

```json
{
  "outbounds": [{
    "protocol": "mist",
    "settings": {
      "servers": [{
        "address": "mist.example.com",
        "port": 443,
        "clientId": "your-16-byte-hex-client-id",
        "authKey": "your-32-byte-base64-auth-key"
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "tls",
      "tlsSettings": {
        "serverName": "mist.example.com",
        "fingerprint": "hellochrome_155"
      }
    }
  }]
}
```

### As Transport (VLESS over Mist)

Mist can also be used as a transport for VLESS:

```json
{
  "inbounds": [{
    "protocol": "vless",
    "settings": { "clients": [{"id": "your-uuid"}] },
    "streamSettings": {
      "network": "mist",
      "security": "tls",
      "tlsSettings": {
        "certificates": [{
          "certificateFile": "/path/to/fullchain.pem",
          "keyFile": "/path/to/privkey.pem"
        }]
      },
      "mistSettings": {
        "accounts": {
          "client-id-hex": "auth-key-base64"
        }
      }
    }
  }]
}
```

### Server

The reference server implementation is **mist-server** (Go), which handles:
- TLS termination with SNI-based routing
- Mist protocol authentication and multiplexing
- Decoy website for non-Mist visitors

See the [SPEC](https://github.com/cien121/weave/blob/main/docs/mist-spec.md) for the full protocol definition.

### Performance

In real-world evening peak tests (230ms RTT):
- Native Mist: 90+ Mbps (vs xhttp 40 Mbps on same network)
- VLESS over Mist: 26 Mbps

---

## How ArasClient uses it

The [AndroidLibXrayLite](https://github.com/ArasTey/AndroidLibXrayLite) gomobile bindings compile this fork into `aras-core.aar`. AmneziaWG profiles additionally run through a **standalone awg-go tunnel** (the same architecture as the AmneziaVPN client) — see `AwgTurnOn` in the bindings.

## Consumed by

`AndroidLibXrayLite/go.mod`:
```
replace github.com/xtls/xray-core        => github.com/ArasTey/xray-core main
replace github.com/patterniha/xray-core  => github.com/ArasTey/xray-core main
```

## Protocol notes

- `anytls://` links: password auth (SHA-256 frame), session reuse, padding scheme negotiation, UDP via UDP-over-TCP
- `awg://` links and `.conf` files: junk params pass through unchanged; configs without them get AmneziaWG's standard defaults
