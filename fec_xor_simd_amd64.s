//go:build amd64 && fec_simd

#include "textflag.h"

// func fecXORScaledSSSE3(dst, src []byte, coefficient byte)
//
// dst ^= coefficient * src over GF(2^8), 16 bytes per iteration, using the SSSE3
// PSHUFB split-table technique from fecMulLo/fecMulHi. The trailing bytes go
// through the full 256 byte gfMulTable row. The caller guarantees
// len(dst) >= len(src) and 0 < coefficient < 256.
TEXT ·fecXORScaledSSSE3(SB), NOSPLIT, $0-56
	MOVQ dst_base+0(FP), DI
	MOVQ src_base+24(FP), SI
	MOVQ src_len+32(FP), CX

	// X15 = 16 x 0x0f, the nibble mask
	MOVQ $0x0f0f0f0f0f0f0f0f, BX
	MOVQ BX, X15
	PUNPCKLQDQ X15, X15

	// R8/R9 point at the low/high nibble table row of the coefficient
	MOVBLZX coefficient+48(FP), AX
	SHLQ $4, AX
	LEAQ ·fecMulLo(SB), R8
	ADDQ AX, R8
	LEAQ ·fecMulHi(SB), R9
	ADDQ AX, R9
	MOVOU (R8), X6
	MOVOU (R9), X5

	MOVQ CX, R11
	SHRQ $4, R11 // number of 16 byte blocks
	ANDQ $15, CX // trailing bytes
	XORQ R10, R10
	TESTQ R11, R11
	JZ tail

loop:
	MOVOU (SI)(R10*1), X0
	MOVO X0, X1
	PAND X15, X0 // low nibbles
	PSRLW $4, X1
	PAND X15, X1 // high nibbles
	MOVO X6, X2
	PSHUFB X0, X2 // X2 = c * (x & 0x0f)
	MOVO X5, X3
	PSHUFB X1, X3 // X3 = c * ((x >> 4) << 4)
	PXOR X3, X2
	MOVOU (DI)(R10*1), X4
	PXOR X2, X4
	MOVOU X4, (DI)(R10*1)
	ADDQ $16, R10
	DECQ R11
	JNZ loop

tail:
	TESTQ CX, CX
	JZ done

	// Scalar tail through the full 256 byte row of gfMulTable.
	MOVBLZX coefficient+48(FP), AX
	SHLQ $8, AX
	LEAQ ·gfMulTable(SB), R8
	ADDQ AX, R8

tailloop:
	MOVBLZX (SI)(R10*1), AX
	MOVBLZX (R8)(AX*1), AX
	MOVBLZX (DI)(R10*1), BX
	XORL BX, AX
	MOVB AX, (DI)(R10*1)
	INCQ R10
	DECQ CX
	JNZ tailloop

done:
	RET
