//go:build arm64 && fec_simd

#include "textflag.h"

// func fecXORScaledNEON(dst, src []byte, coefficient byte)
//
// dst ^= coefficient * src over GF(2^8), 16 bytes per iteration, using the NEON VTBL
// split-table technique from fecMulLo/fecMulHi. The trailing bytes go through the
// full 256 byte gfMulTable row. The caller guarantees len(dst) >= len(src) and
// 0 < coefficient < 256.
TEXT ·fecXORScaledNEON(SB), NOSPLIT, $0-49
	MOVD dst_base+0(FP), R0
	MOVD src_base+24(FP), R1
	MOVD src_len+32(FP), R2
	MOVD coefficient+48(FP), R3
	AND  $255, R3, R3

	MOVD R2, R4
	LSR  $4, R4, R4  // number of 16 byte blocks
	AND  $15, R2, R2 // trailing bytes

	// R5/R6 point at the low/high nibble table row of the coefficient
	LSL  $4, R3, R7
	MOVD $·fecMulLo(SB), R5
	ADD  R7, R5, R5
	MOVD $·fecMulHi(SB), R6
	ADD  R7, R6, R6
	VLD1 (R5), [V6.B16]
	VLD1 (R6), [V5.B16]
	CBZ  R4, tail

loop:
	VLD1  (R1), [V0.B16]
	VSHL  $4, V0.B16, V1.B16
	VUSHR $4, V1.B16, V1.B16 // low nibbles
	VUSHR $4, V0.B16, V2.B16 // high nibbles
	VTBL  V1.B16, [V6.B16], V3.B16
	VTBL  V2.B16, [V5.B16], V4.B16
	VEOR  V3.B16, V4.B16, V4.B16
	VLD1  (R0), [V0.B16]
	VEOR  V0.B16, V4.B16, V4.B16
	VST1  [V4.B16], (R0)
	ADD   $16, R1, R1
	ADD   $16, R0, R0
	SUB   $1, R4, R4
	CBNZ  R4, loop

tail:
	CBZ R2, done
	// Scalar tail through the full 256 byte row of gfMulTable.
	LSL  $8, R3, R7
	MOVD $·gfMulTable(SB), R5
	ADD  R7, R5, R5

tailloop:
	MOVBU (R1), R6
	MOVBU (R5)(R6), R7
	MOVBU (R0), R8
	EOR   R7, R8, R8
	MOVB  R8, (R0)
	ADD   $1, R1, R1
	ADD   $1, R0, R0
	SUB   $1, R2, R2
	CBNZ  R2, tailloop

done:
	RET
