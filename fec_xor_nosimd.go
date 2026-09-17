//go:build !(amd64 && fec_simd)

package quic

// fecXORScaledImpl is the portable GF(2^8) multiply-accumulate. It is used by
// default builds and by platforms without an optional SIMD implementation.
func fecXORScaledImpl(dst, src []byte, coefficient byte) {
	fecXORScaledTable(dst, src, coefficient)
}

// initFECSIMDTables is a no-op without the fec_simd build tag.
func initFECSIMDTables() {}
