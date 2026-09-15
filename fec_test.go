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
	now := monotime.Now()
	packets := make(map[protocol.PacketNumber][]byte, packetCount)
	for i := range packetCount {
		pn := protocol.PacketNumber(100 + i)
		data := randomPacket(t, 20+i*37)
		packets[pn] = data
		state.encoder.addPacket(pn, data, 1400, now)
	}
	frames := make([]*wire.FECRepairFrame, 0, rows)
	for range rows {
		frame := state.encoder.pendingRepair(now, 1400)
		if frame == nil {
			t.Fatalf("expected %d parity frames, got %d", rows, len(frames))
		}
		frames = append(frames, frame)
	}
	if frame := state.encoder.pendingRepair(now, 1400); frame != nil {
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
		sender.encoder.addPacket(pn, packets[pn], 1400, now)
	}
	frame := sender.encoder.pendingRepair(now, 1400)
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

func TestFECIdleWithoutLoss(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10, MaxGroupSize: 16, MinGroupSize: 2, MaxParityRows: 1}
	state := newFECState(config)
	now := monotime.Now()
	// no loss at all: FEC must stay idle
	for i := range 20 {
		now = now.Add(100 * time.Millisecond)
		state.encoder.evaluate(now, uint64(100*(i+1)), 0, true)
	}
	if state.encoder.protecting() {
		t.Fatalf("FEC engaged on a lossless path (group size %d)", state.encoder.groupSize)
	}
	if state.encoder.pendingRepair(now, 1400) != nil {
		t.Fatal("parity frame emitted on a lossless path")
	}
	stats := state.statsForTest()
	if stats.GroupSize != 0 || stats.ParityPacketsSent != 0 {
		t.Fatalf("unexpected stats on a lossless path: %+v", stats)
	}
}

func TestFECEngagesOnLoss(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10, MaxGroupSize: 16, MinGroupSize: 2, MaxParityRows: 1}
	state := newFECState(config)
	now := monotime.Now()
	var sent, lost uint64
	// 5% loss
	for range 20 {
		now = now.Add(100 * time.Millisecond)
		sent += 100
		lost += 5
		state.encoder.evaluate(now, sent, lost, true)
	}
	if !state.encoder.protecting() {
		t.Fatal("FEC didn't engage on a lossy path")
	}
	stats := state.statsForTest()
	if stats.SendOverhead > 0.10+1e-9 {
		t.Fatalf("overhead %v exceeds the configured cap of 10%%", stats.SendOverhead)
	}
	// 20% loss must not exceed the cap either
	state = newFECState(config)
	now = monotime.Now()
	sent, lost = 0, 0
	for range 20 {
		now = now.Add(100 * time.Millisecond)
		sent += 100
		lost += 20
		state.encoder.evaluate(now, sent, lost, true)
	}
	if !state.encoder.protecting() {
		t.Fatal("FEC didn't engage on a very lossy path")
	}
	stats = state.statsForTest()
	if stats.SendOverhead > 0.10+1e-9 {
		t.Fatalf("overhead %v exceeds the configured cap of 10%% at 20%% loss", stats.SendOverhead)
	}
}

func TestFECDisengagesAgain(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10, MaxGroupSize: 16, MinGroupSize: 2, MaxParityRows: 1}
	state := newFECState(config)
	now := monotime.Now()
	var sent, lost uint64
	for range 10 {
		now = now.Add(100 * time.Millisecond)
		sent += 100
		lost += 10
		state.encoder.evaluate(now, sent, lost, true)
	}
	if !state.encoder.protecting() {
		t.Fatal("FEC didn't engage on a lossy path")
	}
	// the path recovers: the loss counter doesn't grow anymore
	for range 40 {
		now = now.Add(100 * time.Millisecond)
		sent += 100
		state.encoder.evaluate(now, sent, lost, true)
	}
	if state.encoder.protecting() {
		t.Fatalf("FEC stayed engaged on a recovered path (group size %d, loss rate %v)", state.encoder.groupSize, state.encoder.lossEWMA)
	}
}

func TestFECPeerFeedbackKeepsFECEngaged(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10, MaxGroupSize: 16, MinGroupSize: 2, MaxParityRows: 1}
	state := newFECState(config)
	now := monotime.Now()
	// The sender itself sees no loss (FEC repairs everything), the peer reports 5% loss.
	feedback := &wire.FECFeedbackFrame{ProtectedPackets: 100, RecoveredPackets: 5, ParityPackets: 10}
	state.encoder.onFeedback(feedback, 100, 0, now)
	for i := range 10 {
		now = now.Add(100 * time.Millisecond)
		feedback.ProtectedPackets += 100
		feedback.RecoveredPackets += 5
		feedback.ParityPackets += 10
		state.encoder.onFeedback(feedback, uint64(100*(i+2)), 0, now)
	}
	if !state.encoder.protecting() {
		t.Fatal("FEC disengaged although the peer reports loss")
	}
	// The peer stops reporting loss: FEC has to disengage.
	for i := range 40 {
		now = now.Add(100 * time.Millisecond)
		feedback.ProtectedPackets += 100
		feedback.ParityPackets += 10
		state.encoder.onFeedback(feedback, uint64(2000+i*100), 0, now)
	}
	if state.encoder.protecting() {
		t.Fatalf("FEC stayed engaged although the peer reports no loss (loss rate %v)", state.encoder.lossEWMA)
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

// statsForTest returns the FECStats of the state, as seen by the application.
func (s *fecState) statsForTest() FECStats {
	return s.stats()
}
