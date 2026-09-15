package quic

import (
	"bytes"
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

// buildFECGroup feeds packets into the encoder and returns the parity frames.
func buildFECGroup(t *testing.T, state *fecState, groupSize, rows int, packetCount int) ([]*wire.FECRepairFrame, map[protocol.PacketNumber][]byte) {
	t.Helper()
	state.encoder.groupSize = groupSize
	state.encoder.rows = rows
	state.targetGroupSize.Store(int64(groupSize))
	state.parityRows.Store(int64(rows))
	now := monotime.Now()
	packets := make(map[protocol.PacketNumber][]byte, packetCount)
	for i := range packetCount {
		pn := protocol.PacketNumber(100 + i)
		data := randomPacket(t, 20+i*37)
		packets[pn] = data
		state.encoder.addPacket(pn, data, 1452, now)
	}
	frames := make([]*wire.FECRepairFrame, 0, rows)
	for range rows {
		frame := state.encoder.pendingRepair(now, 1452)
		if frame == nil {
			t.Fatalf("expected %d parity frames, got %d", rows, len(frames))
		}
		frames = append(frames, frame)
	}
	if frame := state.encoder.pendingRepair(now, 1452); frame != nil {
		t.Fatal("unexpected extra parity frame")
	}
	return frames, packets
}

func TestFECRecoversSingleLoss(t *testing.T) {
	config := FECConfig{MaxGroupSize: 16, MinGroupSize: 2, MaxOverheadPercent: 50, MaxParityRows: 1}
	for _, groupSize := range []int{2, 3, 8, 16} {
		sender := newFECState(config)
		frames, packets := buildFECGroup(t, sender, groupSize, 1, groupSize)
		for lostPacket := range packets {
			receiver := newFECState(config)
			for pn, data := range packets {
				if pn == lostPacket {
					continue
				}
				receiver.decoder.recordPacket(pn, data, protocol.KeyPhaseZero)
			}
			recovered := receiver.decoder.handleRepair(frames[0], monotime.Now())
			if len(recovered) != 1 {
				t.Fatalf("group size %d: expected 1 recovered packet, got %d", groupSize, len(recovered))
			}
			if recovered[0].packetNumber != lostPacket {
				t.Fatalf("group size %d: recovered the wrong packet: %d", groupSize, recovered[0].packetNumber)
			}
			if !bytes.Equal(recovered[0].data, packets[lostPacket]) {
				t.Fatalf("group size %d: recovered data doesn't match", groupSize)
			}
		}
	}
}

func TestFECRecoversTwoLosses(t *testing.T) {
	config := FECConfig{MaxGroupSize: 16, MinGroupSize: 2, MaxOverheadPercent: 100, MaxParityRows: 2}
	sender := newFECState(config)
	frames, packets := buildFECGroup(t, sender, 8, 2, 8)
	if len(frames) != 2 {
		t.Fatalf("expected 2 parity frames, got %d", len(frames))
	}
	packetNumbers := make([]protocol.PacketNumber, 0, len(packets))
	for pn := range packets {
		packetNumbers = append(packetNumbers, pn)
	}
	// lose two packets: the first and the last one of the group
	lost := map[protocol.PacketNumber]bool{packetNumbers[0]: true, packetNumbers[len(packetNumbers)-1]: true}
	receiver := newFECState(config)
	for pn, data := range packets {
		if lost[pn] {
			continue
		}
		receiver.decoder.recordPacket(pn, data, protocol.KeyPhaseZero)
	}
	// the first parity row arrives: not enough to repair two losses
	if recovered := receiver.decoder.handleRepair(frames[0], monotime.Now()); len(recovered) != 0 {
		t.Fatalf("expected no recovery with a single parity row, got %d packets", len(recovered))
	}
	recovered := receiver.decoder.handleRepair(frames[1], monotime.Now())
	if len(recovered) != 2 {
		t.Fatalf("expected 2 recovered packets, got %d", len(recovered))
	}
	for _, packet := range recovered {
		if !lost[packet.packetNumber] {
			t.Fatalf("recovered an unexpected packet: %d", packet.packetNumber)
		}
		if !bytes.Equal(packet.data, packets[packet.packetNumber]) {
			t.Fatalf("recovered data of packet %d doesn't match", packet.packetNumber)
		}
	}
}

func TestFECRecoversWithUnequalPacketSizes(t *testing.T) {
	config := FECConfig{MaxGroupSize: 8, MinGroupSize: 2, MaxOverheadPercent: 50, MaxParityRows: 1}
	sender := newFECState(config)
	sender.encoder.groupSize = 4
	sender.encoder.rows = 1
	now := monotime.Now()
	packets := map[protocol.PacketNumber][]byte{
		10: randomPacket(t, 1400),
		11: randomPacket(t, 17),
		12: randomPacket(t, 900),
		13: randomPacket(t, 1),
	}
	for pn := protocol.PacketNumber(10); pn <= 13; pn++ {
		sender.encoder.addPacket(pn, packets[pn], 1452, now)
	}
	frame := sender.encoder.pendingRepair(now, 1452)
	if frame == nil {
		t.Fatal("expected a parity frame")
	}
	for lostPacket := range packets {
		receiver := newFECState(config)
		for pn, data := range packets {
			if pn == lostPacket {
				continue
			}
			receiver.decoder.recordPacket(pn, data, protocol.KeyPhaseZero)
		}
		recovered := receiver.decoder.handleRepair(frame, monotime.Now())
		if len(recovered) != 1 {
			t.Fatalf("expected 1 recovered packet, got %d", len(recovered))
		}
		if !bytes.Equal(recovered[0].data, packets[lostPacket]) {
			t.Fatalf("recovered data of packet %d doesn't match (%d vs %d bytes)", lostPacket, len(recovered[0].data), len(packets[lostPacket]))
		}
	}
}

func TestFECNothingToRecover(t *testing.T) {
	config := FECConfig{MaxGroupSize: 8, MinGroupSize: 2, MaxOverheadPercent: 50, MaxParityRows: 1}
	sender := newFECState(config)
	frames, packets := buildFECGroup(t, sender, 4, 1, 4)
	receiver := newFECState(config)
	for pn, data := range packets {
		receiver.decoder.recordPacket(pn, data, protocol.KeyPhaseZero)
	}
	if recovered := receiver.decoder.handleRepair(frames[0], monotime.Now()); len(recovered) != 0 {
		t.Fatalf("expected no recovery, got %d packets", len(recovered))
	}
}

func TestFECUnrecoverableLossIsCounted(t *testing.T) {
	config := FECConfig{MaxGroupSize: 8, MinGroupSize: 2, MaxOverheadPercent: 50, MaxParityRows: 1}
	sender := newFECState(config)
	frames, packets := buildFECGroup(t, sender, 4, 1, 4)
	receiver := newFECState(config)
	var received int
	for pn, data := range packets {
		// lose two packets: XOR parity can only repair one
		if received < 2 {
			receiver.decoder.recordPacket(pn, data, protocol.KeyPhaseZero)
			received++
		}
	}
	if recovered := receiver.decoder.handleRepair(frames[0], monotime.Now()); len(recovered) != 0 {
		t.Fatalf("expected no recovery, got %d packets", len(recovered))
	}
	if stats := receiver.stats(); stats.FailedPackets != 2 {
		t.Fatalf("expected 2 failed packets, got %d", stats.FailedPackets)
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

func TestFECIdleWithoutLoss(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10, MaxGroupSize: 16, MinGroupSize: 2, MaxParityRows: 1}
	state := newFECState(config)
	now := monotime.Now()
	// no loss at all: FEC must stay idle
	for range 20 {
		now = now.Add(100 * time.Millisecond)
		state.encoder.tick(now)
	}
	if state.encoder.protecting() {
		t.Fatalf("FEC engaged on a lossless path (group size %d)", state.encoder.groupSize)
	}
	if state.encoder.pendingRepair(now, 1400) != nil {
		t.Fatal("parity frame emitted on a lossless path")
	}
	stats := state.stats()
	if stats.GroupSize != 0 || stats.ParityPacketsSent != 0 {
		t.Fatalf("unexpected stats on a lossless path: %+v", stats)
	}
}

func TestFECEngagesOnLoss(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10, MaxGroupSize: 16, MinGroupSize: 2, MaxParityRows: 1}
	for _, lossPercent := range []uint64{2, 5, 20, 50} {
		state := newFECState(config)
		now := monotime.Now()
		feedback := &wire.FECFeedbackFrame{}
		for range 20 {
			now = now.Add(100 * time.Millisecond)
			feedback.ReceivedPackets += 100 - lossPercent
			feedback.LostPackets += lossPercent
			state.encoder.onFeedback(feedback, now)
		}
		if !state.encoder.protecting() {
			t.Fatalf("FEC didn't engage at %d%% loss", lossPercent)
		}
		stats := state.stats()
		if stats.SendOverhead > 0.10+1e-9 {
			t.Fatalf("overhead %v exceeds the configured cap of 10%% at %d%% loss", stats.SendOverhead, lossPercent)
		}
	}
}

func TestFECDisengagesAgain(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10, MaxGroupSize: 16, MinGroupSize: 2, MaxParityRows: 1}
	state := newFECState(config)
	now := monotime.Now()
	feedback := &wire.FECFeedbackFrame{}
	for range 10 {
		now = now.Add(100 * time.Millisecond)
		feedback.ReceivedPackets += 90
		feedback.LostPackets += 10
		state.encoder.onFeedback(feedback, now)
	}
	if !state.encoder.protecting() {
		t.Fatal("FEC didn't engage on a lossy path")
	}
	// the path recovers: no new losses are reported
	for range 40 {
		now = now.Add(100 * time.Millisecond)
		feedback.ReceivedPackets += 100
		state.encoder.onFeedback(feedback, now)
	}
	if state.encoder.protecting() {
		t.Fatalf("FEC stayed engaged on a recovered path (group size %d, loss rate %v)", state.encoder.groupSize, state.encoder.lossEWMA)
	}
}

func TestFECDecaysWithoutFeedback(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10, MaxGroupSize: 16, MinGroupSize: 2, MaxParityRows: 1}
	state := newFECState(config)
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
}

func TestFECReserveCoversRepairFrame(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10, MaxGroupSize: 16, MinGroupSize: 2, MaxParityRows: 1}
	state := newFECState(config)
	frames, packets := buildFECGroup(t, state, config.MaxGroupSize, 1, config.MaxGroupSize)
	reserve := state.encoder.reserve()
	headerLength := frames[0].Length(protocol.Version1) - protocol.ByteCount(len(frames[0].Parity))
	if headerLength > reserve {
		t.Fatalf("repair frame header is larger (%d) than the reserved space (%d)", headerLength, reserve)
	}
	if len(packets) != config.MaxGroupSize {
		t.Fatal("unexpected number of protected packets")
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
