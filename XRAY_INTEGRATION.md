# Mist 出站 — Xray 集成文档（Weave App 用）

Mist v0.1 已作为 Xray 原生出站协议实现（`proxy/mist`，client only）。
TLS（含 uTLS Chrome 指纹）**由 Xray 传输层完成**：`streamSettings` 里配
`security: tls` + `fingerprint: chrome` 即可，本协议只在 TLS 之上跑 Mist 帧。
线协议规约见 `~/workspace/mist-protocol/SPEC.md`。

## settings 字段说明

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `address` | string | 是 | Mist 服务端域名（443 端口上的雾域名，如 `www.example-blog.com`）。建议与 `streamSettings.tlsSettings.serverName` 一致 |
| `port` | number | 否 | 默认 443 |
| `clientId` | string | 是 | 16 字节 CID 的 **hex 编码**（32 个 hex 字符），AUTH 报文明文传输，服务端用它查 K_auth |
| `authKey` | string | 是 | 32 字节 K_auth 的 **base64(std) 编码**（44 字符，带 `=` 补齐），长效认证密钥，妥善保管 |
| `heartbeatInterval` | number | 否 | 心跳秒数，默认 30（服务端 AUTH_OK 下发的 HB 在 10–120 范围内会覆盖此值） |
| `shapingHeavyPackets` | number | 否 | 重整形包数，默认 32（前 N 个发出帧随机填充 64–512 字节、0–15ms 抖动、不规则分片；之后零开销）。填 0 会被视为未设置而用默认值 32 |

编码格式注意：`clientId` 必须是 hex（不是 base64），`authKey` 必须是标准 base64
（不是 base64url、不是 hex）。格式错误会在配置加载时直接报错。

## streamSettings（固定写法）

```json
"streamSettings": {
  "network": "tcp",
  "security": "tls",
  "tlsSettings": {
    "serverName": "www.example-blog.com",
    "fingerprint": "chrome",
    "alpn": ["h2", "http/1.1"],
    "allowInsecure": false
  }
}
```

- `fingerprint` 建议填 `hellochrome_155`（显式锁定 Chrome 155 指纹，不随 uTLS 的 auto 升级而漂移；填 `chrome` 则为 auto，同样可用）。uTLS 已随 mist 分支升到 Chrome 155 时代（见 PR XTLS/Xray-core#7135 的 cherry-pick）。
- `serverName` 填雾域名；必须是真实解析到服务端的域名、真实有效证书。
- `allowInsecure` 必须 false（规约要求客户端校验证书链）。

## 完整出站 JSON 示例（可直接用）

```json
{
  "tag": "mist-out",
  "protocol": "mist",
  "settings": {
    "address": "www.example-blog.com",
    "port": 443,
    "clientId": "00112233445566778899aabbccddeeff",
    "authKey": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
    "heartbeatInterval": 30,
    "shapingHeavyPackets": 32
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "serverName": "www.example-blog.com",
      "fingerprint": "hellochrome_155",
      "alpn": ["h2", "http/1.1"],
      "allowInsecure": false
    }
  }
}
```

> 示例中的 `clientId`/`authKey` 是占位值，请替换为服务端下发的真实凭据。

## 行为说明（Weave 侧需要知道的）

- **多路复用**：一个出站配置对应一个 Mist 会话池（最多 4 条 TLS 会话，每会话 15 条流）；
  Weave 的多条连接会自动复用到同一会话上，不用每个节点建多份配置。
- **TCP**：CONNECT 建流，服务端回 CODE=0x00 即通；失败时 Xray 日志会写明原因
  （network unreachable / connection refused / timed out / unsupported address）。
- **UDP**：按规约 9.4 经 TCP 承载流做 UDP 中继（DNS 可用）；无连接语义，
  代理结束后承载流直接 RST。
- **断线**：心跳连续 2 周期无 PONG 判死，自动先试 RESUME（1-RTT 迁移，换网不断流），
  失败回退完整 AUTH。认证失败（clientId/authKey 错）会在 Xray 日志里明确报错，
  不会静默。
- **日志**：debug 日志不输出密钥与 CID，可放心开 `loglevel: debug` 排查。
