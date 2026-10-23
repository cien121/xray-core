//go:build !mist_unsafe_initial

// Inert RandomCiphertextCodec stub — RELEASE / DEFAULT BUILDS.
//
// This file is compiled when the `mist_unsafe_initial` build tag is NOT set
// (i.e. every normal and release build). The type exists so all referencing
// code compiles unchanged, but every encode/decode method fails: a binary
// built without the tag is physically incapable of emitting or parsing a
// random-ciphertext Initial packet.
//
// Lab/internal testing must build with `-tags mist_unsafe_initial`, which
// selects initial_codec_unsafe.go instead.
package mist

import "errors"

// errCodecDisabled is returned by every RandomCiphertextCodec method in
// builds without the mist_unsafe_initial tag.
var errCodecDisabled = errors.New("mist: 随机密文 Initial 在此构建中被禁用（构建时未指定 mist_unsafe_initial 标签）: " +
	"内测构建请加 -tags mist_unsafe_initial；公网部署请等待 Phase 0 真 QUIC Initial (QUICInitialCodec)")

// RandomCiphertextCodec is the Phase 1 simplified Initial codec.
// In this build it is an inert stub: all methods return errCodecDisabled.
type RandomCiphertextCodec struct{}

// SealInitial is disabled in builds without mist_unsafe_initial.
func (c *RandomCiphertextCodec) SealInitial(authPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32) ([]byte, error) {
	return nil, errCodecDisabled
}

// OpenInitial is disabled in builds without mist_unsafe_initial.
func (c *RandomCiphertextCodec) OpenInitial(packet []byte) ([]byte, [8]byte, [8]byte, uint32, error) {
	return nil, [8]byte{}, [8]byte{}, 0, errCodecDisabled
}

// SealInitialResponse is disabled in builds without mist_unsafe_initial.
func (c *RandomCiphertextCodec) SealInitialResponse(authOKPayload []byte, dcid [8]byte, scid [8]byte, packetNum uint32) ([]byte, error) {
	return nil, errCodecDisabled
}

// OpenInitialResponse is disabled in builds without mist_unsafe_initial.
func (c *RandomCiphertextCodec) OpenInitialResponse(packet []byte) ([]byte, [8]byte, [8]byte, uint32, error) {
	return nil, [8]byte{}, [8]byte{}, 0, errCodecDisabled
}
