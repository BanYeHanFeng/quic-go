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
