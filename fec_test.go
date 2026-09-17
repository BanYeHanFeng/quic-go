package quic

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/wire"
)

func randomPacket(t *testing.T, length int) []byte {
	t.Helper()
	data := make([]byte, length)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestFECDefaultsUseTheHighLossKnee(t *testing.T) {
	config := FECConfig{}.withDefaults()
	if config.MaxOverheadPercent != 30 {
		t.Fatalf("default max overhead is %d, expected 30", config.MaxOverheadPercent)
	}
	if config.MaxGroupSize != wire.MaxFECWindowSize {
		t.Fatalf("default window is %d, expected %d", config.MaxGroupSize, wire.MaxFECWindowSize)
	}
}

func TestFECLossTracker(t *testing.T) {
	var tracker fecLossTracker
	// the first packet initializes the tracker
	for pn := protocol.PacketNumber(0); pn < 20; pn++ {
		tracker.record(pn)
	}
	if tracker.lost != 0 {
		t.Fatalf("counted %d losses on a lossless stream", tracker.lost)
	}
	if tracker.received != 20 {
		t.Fatalf("expected 20 received packets, got %d", tracker.received)
	}
	// lose packets 20-24, receive 25 onwards
	for pn := protocol.PacketNumber(25); pn < 45; pn++ {
		tracker.record(pn)
	}
	if tracker.lost != 5 {
		t.Fatalf("expected 5 losses, got %d", tracker.lost)
	}
	// packets that arrive late (within the reorder window) don't count as lost
	var reordered fecLossTracker
	for pn := protocol.PacketNumber(0); pn < 10; pn++ {
		if pn == 5 {
			continue
		}
		reordered.record(pn)
	}
	reordered.record(5)
	if reordered.lost != 0 {
		t.Fatalf("counted a reordered packet as lost (%d)", reordered.lost)
	}
	// ... and a presumed loss is undone when the packet shows up very late
	var late fecLossTracker
	for pn := protocol.PacketNumber(0); pn < 30; pn++ {
		if pn == 10 {
			continue
		}
		late.record(pn)
	}
	if late.lost != 1 {
		t.Fatalf("expected 1 presumed loss, got %d", late.lost)
	}
	late.record(10)
	if late.lost != 0 {
		t.Fatalf("expected the presumed loss to be undone, got %d", late.lost)
	}
}

func TestFECDecaysWithoutFeedback(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10, MaxGroupSize: 16, MaxParityRows: 1}
	state := newFECWindowState(config)
	now := monotime.Now()
	// the first report only establishes the baseline of the cumulative counters
	state.encoder.onFeedback(&wire.FECFeedbackFrame{ReceivedPackets: 100, LostPackets: 20}, now)
	now = now.Add(200 * time.Millisecond)
	state.encoder.onFeedback(&wire.FECFeedbackFrame{ReceivedPackets: 200, LostPackets: 40}, now)
	if !state.encoder.protecting() {
		t.Fatal("FEC didn't engage on a lossy path")
	}
	// the peer stops reporting: the loss estimate has to decay, and FEC to disengage
	for range 40 {
		now = now.Add(100 * time.Millisecond)
		state.encoder.tick(now)
	}
	if state.encoder.protecting() {
		t.Fatalf("FEC stayed engaged without fresh loss reports (loss rate %v)", state.encoder.lossEWMA)
	}
	if stats := state.stats(); stats.WindowSize != 0 {
		t.Fatalf("the statistics still report an active window: %+v", stats)
	}
}

func TestGF256Multiplication(t *testing.T) {
	for a := range 256 {
		for b := range 256 {
			product := gfMul(byte(a), byte(b))
			if a == 0 || b == 0 {
				if product != 0 {
					t.Fatalf("%d * %d = %d, expected 0", a, b, product)
				}
				continue
			}
			if gfMul(product, gfInv(byte(a))) != byte(b) {
				t.Fatalf("division of %d * %d by %d doesn't yield %d", a, b, a, b)
			}
		}
	}
}

// fecSolve solves the linear system matrix * X = rhs over GF(2^8) in place.
// On success, rhs holds the solution.
//
// It is not used by the connection: the decoder of the window scheme reduces its
// equations incrementally (fecWindowDecoder.pump). The test that asserts the MDS
// property of the Cauchy coefficients uses it to invert arbitrary submatrices.
func fecSolve(matrix [][]byte, rhs [][]byte) bool {
	size := len(matrix)
	for col := range size {
		pivot := -1
		for row := col; row < size; row++ {
			if matrix[row][col] != 0 {
				pivot = row
				break
			}
		}
		if pivot < 0 {
			return false
		}
		if pivot != col {
			matrix[pivot], matrix[col] = matrix[col], matrix[pivot]
			rhs[pivot], rhs[col] = rhs[col], rhs[pivot]
		}
		if factor := matrix[col][col]; factor != 1 {
			inverse := gfInv(factor)
			for j := col; j < size; j++ {
				matrix[col][j] = gfMul(matrix[col][j], inverse)
			}
			fecScaleSlice(rhs[col], inverse)
		}
		for row := range size {
			if row == col {
				continue
			}
			factor := matrix[row][col]
			if factor == 0 {
				continue
			}
			for j := col; j < size; j++ {
				matrix[row][j] ^= gfMul(factor, matrix[col][j])
			}
			fecXORScaled(rhs[row], rhs[col], factor)
		}
	}
	return true
}

// fecScaleSlice multiplies a byte slice in place.
func fecScaleSlice(data []byte, factor byte) {
	if factor == 1 {
		return
	}
	for i, b := range data {
		data[i] = gfMul(factor, b)
	}
}

// gfMulLogExp is the pre-table implementation of gfMul. It is only used as the
// reference for the equivalence tests and as the "before" side of the FEC benchmark;
// production code goes through gfMulTable.
func gfMulLogExp(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func fecXORScaledLogExp(dst, src []byte, coefficient byte) {
	if coefficient == 0 {
		return
	}
	for i, b := range src {
		dst[i] ^= gfMulLogExp(coefficient, b)
	}
}

func TestGF256TableMatchesLogExp(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if got, want := gfMul(byte(a), byte(b)), gfMulLogExp(byte(a), byte(b)); got != want {
				t.Fatalf("%d * %d = %d, want %d", a, b, got, want)
			}
		}
	}
}

// TestFECXORScaledMatchesLogExp asserts that the table-driven hot path produces
// byte-identical results to the log/exp implementation it replaced, for every
// coefficient and a range of lengths. dst is deliberately longer than src: the
// trailing bytes must stay untouched (zero-extension of the parity symbol).
func TestFECXORScaledMatchesLogExp(t *testing.T) {
	next := func(state *uint32) byte {
		*state = *state*1664525 + 1013904223
		return byte(*state >> 24)
	}
	for _, length := range []int{0, 1, 2, 3, 7, 16, 63, 64, 255, 256, 1200, 8192} {
		state := uint32(42)
		src := make([]byte, length)
		for i := range src {
			src[i] = next(&state)
		}
		for coefficient := 0; coefficient < 256; coefficient++ {
			dstTable := make([]byte, length+13)
			dstLogExp := make([]byte, length+13)
			for i := range dstTable {
				b := next(&state)
				dstTable[i] = b
				dstLogExp[i] = b
			}
			fecXORScaled(dstTable, src, byte(coefficient))
			fecXORScaledLogExp(dstLogExp, src, byte(coefficient))
			for i := range dstTable {
				if dstTable[i] != dstLogExp[i] {
					t.Fatalf("coefficient %d, length %d: byte %d = %d, want %d", coefficient, length, i, dstTable[i], dstLogExp[i])
				}
			}
		}
	}
}

// benchmarkFECRepairRow mirrors the cost of one repair row: all members multiplied
// by the same row coefficient, exactly as fecWindowEncoder.buildRow does it.
func benchmarkFECRepairRow(b *testing.B, xorScaled func(dst, src []byte, coefficient byte), lengths []int, maxLen int) {
	total := 0
	for _, length := range lengths {
		total += length
	}
	src := make([]byte, total)
	for i := range src {
		src[i] = byte(i*7 + 13)
	}
	dst := make([]byte, maxLen)
	b.SetBytes(int64(total))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		coefficient := byte(i%255 + 1)
		offset := 0
		for _, length := range lengths {
			xorScaled(dst, src[offset:offset+length], coefficient)
			offset += length
		}
	}
}

func uniformRowLengths() []int {
	lengths := make([]int, 128)
	for i := range lengths {
		lengths[i] = 1200
	}
	return lengths
}

// BenchmarkFECRepairRowMixedTableOnly is the adversarial variable-length row from
// the FEC report: 127 members of 60 bytes and one of 1400 bytes. The work must scale
// with the sum of the member lengths (fecXORScaled only iterates len(src)), not with
// members times the longest member: if the latter were true, MB/s would collapse by
// roughly 17x compared to the uniform row.
func BenchmarkFECRepairRowMixedTableOnly(b *testing.B) {
	lengths := make([]int, 128)
	for i := range lengths {
		lengths[i] = 60
	}
	lengths[0] = 1400
	benchmarkFECRepairRow(b, fecXORScaledTable, lengths, 1400)
}

func BenchmarkFECRepairRowLogExp(b *testing.B) {
	benchmarkFECRepairRow(b, fecXORScaledLogExp, uniformRowLengths(), 1200)
}

func BenchmarkFECRepairRowTableOnly(b *testing.B) {
	benchmarkFECRepairRow(b, fecXORScaledTable, uniformRowLengths(), 1200)
}

func BenchmarkFECRepairRowProduction(b *testing.B) {
	benchmarkFECRepairRow(b, fecXORScaled, uniformRowLengths(), 1200)
}
