//go:build arm64 && fec_simd

package quic

// The NEON implementation is opt-in (build tag fec_simd) together with the amd64 one;
// see section 4.5 of the QUICX FEC report for why it is not the default. AArch64
// mandates Advanced SIMD, so unlike the amd64 path there is no CPU feature check: the
// VTBL path is always available on arm64.

// fecMulLo[c][i] = c*i and fecMulHi[c][i] = c*(i<<4) over GF(2^8), indexed by VTBL.
var (
	fecMulLo [256][16]byte
	fecMulHi [256][16]byte
)

func initFECSIMDTables() {
	for c := 0; c < 256; c++ {
		table := &gfMulTable[c]
		for i := 0; i < 16; i++ {
			fecMulLo[c][i] = table[i]
			fecMulHi[c][i] = table[i<<4]
		}
	}
}

func fecXORScaledImpl(dst, src []byte, coefficient byte) {
	fecXORScaledNEON(dst, src, coefficient)
}

//go:noescape
func fecXORScaledNEON(dst, src []byte, coefficient byte)
