//go:build amd64 && fec_simd

package quic

import "golang.org/x/sys/cpu"

// The PSHUFB split-table SIMD implementation is opt-in (build tag fec_simd)
// because the technique is covered by third-party patent claims; see section 4.5
// of the QUICX FEC report. Default builds only use fecXORScaledTable.
var fecHasSSSE3 = cpu.X86.HasSSSE3

// fecMulLo[c][i] = c*i and fecMulHi[c][i] = c*(i<<4) over GF(2^8). The two 16 byte
// rows per coefficient let one PSHUFB multiply 16 bytes at once:
//
//	c*x = fecMulLo[c][x&0x0f] ^ fecMulHi[c][x>>4]
var (
	fecMulLo [256][16]byte
	fecMulHi [256][16]byte
)

func initFECSIMDTables() {
	if !fecHasSSSE3 {
		return
	}
	for c := 0; c < 256; c++ {
		table := &gfMulTable[c]
		for i := 0; i < 16; i++ {
			fecMulLo[c][i] = table[i]
			fecMulHi[c][i] = table[i<<4]
		}
	}
}

func fecXORScaledImpl(dst, src []byte, coefficient byte) {
	if fecHasSSSE3 {
		fecXORScaledSSSE3(dst, src, coefficient)
		return
	}
	fecXORScaledTable(dst, src, coefficient)
}

//go:noescape
func fecXORScaledSSSE3(dst, src []byte, coefficient byte)
