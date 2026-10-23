// Package bbr: exported alias for Mist UDP integration.
//
// The underlying BBR implementation is ported from Hy2
// (xray-core/transport/internet/hysteria/congestion/bbr).
// bbrSender is unexported there; this alias makes it usable from mistcore.
package bbr

// Sender is the BBR congestion controller (alias for bbrSender).
type Sender = bbrSender
