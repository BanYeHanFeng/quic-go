package quic

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/wire"
)

// windowTestSender feeds packets into a sliding window encoder and collects the repair
// rows it emits, in the order they would be sent.
type windowTestSender struct {
	state *fecWindowState
	now   monotime.Time
}

func newWindowTestSender(config FECConfig, rate float64) *windowTestSender {
	state := newFECWindowState(config)
	// The adaptive controller is tested separately: a fixed rate makes the rows a test
	// expects deterministic.
	state.encoder.setRate(rate)
	return &windowTestSender{state: state, now: monotime.Now()}
}

func (s *windowTestSender) send(t *testing.T, pn protocol.PacketNumber, data []byte) []*wire.FECWindowRepairFrame {
	t.Helper()
	s.state.encoder.addPacket(pn, data, 1452, s.now, true)
	var rows []*wire.FECWindowRepairFrame
	for {
		frame := s.state.encoder.pendingFrame(s.now, 1452)
		if frame == nil {
			return rows
		}
		row, ok := frame.(*wire.FECWindowRepairFrame)
		if !ok {
			t.Fatalf("unexpected FEC frame type %T", frame)
		}
		s.state.frameSent(frame, protocol.Version1)
		rows = append(rows, row)
	}
}

// requireFECWindowRecovered checks that the decoder reconstructed exactly the expected
// packets, with the bytes they were sent with.
func requireFECWindowRecovered(t *testing.T, packets map[protocol.PacketNumber][]byte, recovered []fecRecoveredPacket, want []protocol.PacketNumber) {
	t.Helper()
	got := make(map[protocol.PacketNumber][]byte, len(recovered))
	for _, packet := range recovered {
		got[packet.packetNumber] = packet.data
	}
	for _, pn := range want {
		data, ok := got[pn]
		if !ok {
			t.Fatalf("packet %d was not reconstructed (reconstructed: %v)", pn, got)
		}
		if !bytes.Equal(data, packets[pn]) {
			t.Fatalf("packet %d was reconstructed incorrectly: %d bytes instead of %d", pn, len(data), len(packets[pn]))
		}
	}
}

// windowTestTransfer runs the whole chain: it sends count packets of varying sizes
// through the encoder, drops the packets in lost, and returns everything the decoder
// reconstructed. Packets and repair rows are handed to the decoder in the order they
// would arrive on the wire.
func windowTestTransfer(t *testing.T, config FECConfig, rate float64, count int, lost map[protocol.PacketNumber]bool) (map[protocol.PacketNumber][]byte, []fecRecoveredPacket, *fecWindowState) {
	t.Helper()
	sender := newWindowTestSender(config, rate)
	receiver := newFECWindowState(config)
	packets := make(map[protocol.PacketNumber][]byte, count)
	var recovered []fecRecoveredPacket
	rows := 0
	for i := 0; i < count; i++ {
		pn := protocol.PacketNumber(1000 + i)
		// Varying sizes: the lengths are part of the code, not part of the header.
		data := randomPacket(t, 900+(i%7)*40)
		packets[pn] = data
		emitted := sender.send(t, pn, data)
		if !lost[pn] {
			recovered = append(recovered, receiver.decoder.recordPacket(pn, data, protocol.KeyPhaseZero)...)
		}
		for _, row := range emitted {
			rows++
			recovered = append(recovered, receiver.decoder.handleRepair(row, sender.now)...)
		}
	}
	if rows == 0 {
		t.Fatal("no repair row was emitted")
	}
	return packets, recovered, receiver
}

func TestFECRecoversSingleLoss(t *testing.T) {
	for _, packetCount := range []int{8, 40, 200} {
		config := FECConfig{MaxGroupSize: 32, MaxOverheadPercent: 100, MaxParityRows: 2}
		lost := map[protocol.PacketNumber]bool{1007: true}
		packets, recovered, _ := windowTestTransfer(t, config, 0.5, packetCount, lost)
		requireFECWindowRecovered(t, packets, recovered, []protocol.PacketNumber{1007})
	}
}

// TestFECReportsRecoveredPackets verifies that recovered packets are queued as an
// FEC_RECOVERED frame when the option is on, including the wire length the sender
// needs to report the loss to its congestion controller.
func TestFECReportsRecoveredPackets(t *testing.T) {
	config := FECConfig{MaxGroupSize: 32, MaxOverheadPercent: 100, MaxParityRows: 2, RecoveredPacketFeedback: true}
	lost := map[protocol.PacketNumber]bool{1007: true}
	packets, recovered, receiver := windowTestTransfer(t, config, 0.5, 40, lost)
	requireFECWindowRecovered(t, packets, recovered, []protocol.PacketNumber{1007})
	if stats := receiver.stats(); stats.RecoveredPacketsReported != 1 {
		t.Fatalf("recovered packets reported = %d, want 1: %+v", stats.RecoveredPacketsReported, stats)
	}
	pending := receiver.pendingFrame(monotime.Now(), 1452)
	frame, ok := pending.(*wire.FECRecoveredFrame)
	if !ok {
		t.Fatalf("expected a recovered frame, got %T", pending)
	}
	if len(frame.Packets) != 1 || frame.Packets[0].PacketNumber != 1007 {
		t.Fatalf("unexpected recovered packets: %+v", frame.Packets)
	}
	if frame.Packets[0].Length != protocol.ByteCount(len(packets[1007])) {
		t.Fatalf("recovered length = %d, want %d", frame.Packets[0].Length, len(packets[1007]))
	}
	if next := receiver.pendingFrame(monotime.Now(), 1452); next != nil {
		if _, ok := next.(*wire.FECRecoveredFrame); ok {
			t.Fatal("the recovered report was not consumed")
		}
	}
}

// TestFECDoesNotReportRecoveredPacketsByDefault guards the default: without the
// option no recovered frame is generated.
func TestFECDoesNotReportRecoveredPacketsByDefault(t *testing.T) {
	config := FECConfig{MaxGroupSize: 32, MaxOverheadPercent: 100, MaxParityRows: 2}
	packets, recovered, receiver := windowTestTransfer(t, config, 0.5, 40, map[protocol.PacketNumber]bool{1007: true})
	requireFECWindowRecovered(t, packets, recovered, []protocol.PacketNumber{1007})
	if stats := receiver.stats(); stats.RecoveredPacketsReported != 0 {
		t.Fatalf("recovered packets were reported without the option: %+v", stats)
	}
	if frame, ok := receiver.pendingFrame(monotime.Now(), 1452).(*wire.FECRecoveredFrame); ok {
		t.Fatalf("unexpected recovered frame: %+v", frame)
	}
}

func TestFECRecoversBurstLosses(t *testing.T) {
	// A burst of four consecutive packets. The rows that cover the burst are
	// independent of each other - each of them protects the whole window - so the
	// whole burst is reconstructed.
	config := FECConfig{MaxGroupSize: 32, MaxOverheadPercent: 100, MaxParityRows: 2}
	lost := map[protocol.PacketNumber]bool{1005: true, 1006: true, 1007: true, 1008: true}
	packets, recovered, _ := windowTestTransfer(t, config, 0.5, 120, lost)
	requireFECWindowRecovered(t, packets, recovered, []protocol.PacketNumber{1005, 1006, 1007, 1008})
}

func TestFECNothingToRecover(t *testing.T) {
	config := FECConfig{MaxGroupSize: 32, MaxOverheadPercent: 100, MaxParityRows: 2}
	_, recovered, receiver := windowTestTransfer(t, config, 0.5, 60, nil)
	if len(recovered) != 0 {
		t.Fatalf("packets were reconstructed although nothing was lost: %v", recovered)
	}
	if stats := receiver.stats(); stats.RecoveredPackets != 0 {
		t.Fatalf("unexpected recovery statistics: %+v", stats)
	}
}

// TestFECLatePacketCompletesEquation verifies the on-the-fly part of the decoder:
// an equation that two lost packets leave underdetermined is solved as soon as one of
// them arrives late.
func TestFECLatePacketCompletesEquation(t *testing.T) {
	config := FECConfig{MaxGroupSize: 16, MaxOverheadPercent: 100, MaxParityRows: 2}
	sender := newWindowTestSender(config, 0.25)
	packets := make(map[protocol.PacketNumber][]byte)
	var rows []*wire.FECWindowRepairFrame
	for i := 0; i < 4; i++ {
		pn := protocol.PacketNumber(2000 + i)
		packets[pn] = randomPacket(t, 1000)
		rows = append(rows, sender.send(t, pn, packets[pn])...)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one repair row for four packets at 25%% redundancy, got %d", len(rows))
	}
	receiver := newFECWindowState(config)
	recovered := receiver.decoder.recordPacket(2000, packets[2000], protocol.KeyPhaseZero)
	recovered = append(recovered, receiver.decoder.recordPacket(2003, packets[2003], protocol.KeyPhaseZero)...)
	if len(recovered) != 0 {
		t.Fatalf("packets were reconstructed without any repair row: %v", recovered)
	}
	if recovered = receiver.decoder.handleRepair(rows[0], sender.now); len(recovered) != 0 {
		t.Fatalf("one row reconstructed two unknown packets: %v", recovered)
	}
	// The late packet makes the equation solvable for the other lost packet.
	recovered = receiver.decoder.recordPacket(2001, packets[2001], protocol.KeyPhaseZero)
	requireFECWindowRecovered(t, packets, recovered, []protocol.PacketNumber{2002})
}

func TestFECIdleWithoutLoss(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10}
	state := newFECWindowState(config)
	now := monotime.Now()
	for i := 0; i < 500; i++ {
		state.encoder.addPacket(protocol.PacketNumber(1+i), randomPacket(t, 1200), 1452, now, true)
	}
	if state.encoder.protecting() {
		t.Fatal("FEC engaged on a path without a loss report")
	}
	if frame := state.encoder.pendingFrame(now.Add(time.Second), 1452); frame != nil {
		t.Fatal("a repair row was sent on a path without a loss report")
	}
	if stats := state.stats(); stats.ParityPacketsSent != 0 || stats.ParityBytesSent != 0 {
		t.Fatalf("unexpected parity traffic on a lossless path: %+v", stats)
	}
}

// TestFECIgnoresAcknowledgementOnlyPackets verifies that the window doesn't
// spend its budget on packets that carry nothing but acknowledgements: they protect
// nothing, and they would make every row as long as the data packets next to them.
func TestFECIgnoresAcknowledgementOnlyPackets(t *testing.T) {
	config := FECConfig{MaxGroupSize: 32, MaxOverheadPercent: 100}
	state := newFECWindowState(config)
	state.encoder.setRate(0.5)
	now := monotime.Now()
	for i := 0; i < 20; i++ {
		state.encoder.addPacket(protocol.PacketNumber(1+i), randomPacket(t, 1200), 1452, now, true)
		state.encoder.addPacket(protocol.PacketNumber(1000+i), randomPacket(t, 35), 1452, now, false)
	}
	for _, member := range state.encoder.members {
		if len(member.data) < 1200 {
			t.Fatalf("an acknowledgement packet of %d bytes ended up in the window", len(member.data))
		}
	}
	if stats := state.stats(); stats.ProtectedBytesSent != 20*1200 {
		t.Fatalf("the acknowledged packets were counted against the overhead budget: %+v", stats)
	}
	if stats := state.stats(); stats.ProtectedPacketsSent != 20 {
		t.Fatalf("unexpected number of protected packets: %+v", stats)
	}
}

func TestFECEngagesAndDisengages(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10}
	state := newFECWindowState(config)
	now := monotime.Now()
	state.encoder.onFeedback(&wire.FECFeedbackFrame{ReceivedPackets: 100, LostPackets: 5}, now)
	if !state.encoder.protecting() {
		t.Fatal("FEC did not engage on a 5% loss report")
	}
	if rate := state.encoder.rate; rate <= 0 || rate > 0.1 {
		t.Fatalf("unexpected redundancy %v", rate)
	}
	if stats := state.stats(); stats.WindowSize == 0 {
		t.Fatal("the statistics don't report the active window")
	}
	if !state.encoder.flushDeadline().IsZero() {
		t.Fatal("an empty window has a flush deadline")
	}
	for i := 0; i < 20; i++ {
		now = now.Add(fecEvaluationInterval)
		state.encoder.tick(now)
	}
	if state.encoder.protecting() {
		t.Fatalf("FEC stayed engaged without fresh loss reports (rate %v)", state.encoder.rate)
	}
	if stats := state.stats(); stats.WindowSize != 0 {
		t.Fatalf("the statistics still report an active window: %+v", stats)
	}
}

func TestFECOverheadStaysWithinCap(t *testing.T) {
	for _, lossPercent := range []uint64{1, 2, 10, 25} {
		config := FECConfig{MaxOverheadPercent: 10, MaxGroupSize: 32, MaxParityRows: 2}
		state := newFECWindowState(config)
		now := monotime.Now()
		var received, lost uint64
		for i := 0; i < 4000; i++ {
			state.encoder.addPacket(protocol.PacketNumber(1+i), randomPacket(t, 1200), 1452, now, true)
			for {
				frame := state.encoder.pendingFrame(now, 1452)
				if frame == nil {
					break
				}
				state.frameSent(frame, protocol.Version1)
			}
			// The peer reports every 50 packets, like a real feedback frame.
			if i%50 == 49 {
				received += 50
				lost = received * lossPercent / 100
				state.encoder.onFeedback(&wire.FECFeedbackFrame{ReceivedPackets: received, LostPackets: lost}, now)
			}
		}
		stats := state.stats()
		if stats.ParityPacketsSent == 0 {
			t.Fatalf("%d%% loss: no repair row was ever sent", lossPercent)
		}
		if stats.MeasuredOverhead > float64(config.MaxOverheadPercent)/100+1e-9 {
			t.Fatalf("%d%% loss: measured overhead %v exceeds the %d%% cap (%d parity bytes / %d protected bytes)",
				lossPercent, stats.MeasuredOverhead, config.MaxOverheadPercent, stats.ParityBytesSent, stats.ProtectedBytesSent)
		}
	}
}

func TestFECProtectsTheIdleTail(t *testing.T) {
	config := FECConfig{MaxGroupSize: 16, MaxOverheadPercent: 100, MaxParityRows: 2, FlushDelay: 2 * time.Millisecond}
	sender := newWindowTestSender(config, 0.05)
	var rows []*wire.FECWindowRepairFrame
	for i := 0; i < 3; i++ {
		rows = append(rows, sender.send(t, protocol.PacketNumber(1+i), randomPacket(t, 1200))...)
	}
	if len(rows) != 0 {
		t.Fatalf("repair rows were sent before the flush delay: %d", len(rows))
	}
	deadline := sender.state.encoder.flushDeadline()
	if deadline.IsZero() {
		t.Fatal("a pending window has no flush deadline")
	}
	frame := sender.state.encoder.pendingFrame(deadline, 1452)
	if frame == nil {
		t.Fatal("the idle tail was not protected")
	}
	row, ok := frame.(*wire.FECWindowRepairFrame)
	if !ok {
		t.Fatalf("unexpected FEC frame type %T", frame)
	}
	if len(row.PacketNumbers) != 3 {
		t.Fatalf("the tail row covers %d packets, expected 3", len(row.PacketNumbers))
	}
}

// TestFECTailFlushFollowsTargetRate pins the behaviour of a flow that goes idle after
// every packet: the idle flush has to be paid for out of the row credit like any other
// row, so the parity follows the configured rate instead of being limited only by the
// overhead byte cap.
func TestFECTailFlushFollowsTargetRate(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 30, MaxGroupSize: 128, MaxParityRows: 2, FlushDelay: 2 * time.Millisecond}
	const (
		packetCount = 600
		packetSize  = 1000
		// Far above the flush delay: every packet is an isolated tail.
		packetGap = 100 * time.Millisecond
	)
	sender := newWindowTestSender(config, 0.05)
	for i := 0; i < packetCount; i++ {
		data := randomPacket(t, packetSize)
		sender.state.encoder.addPacket(protocol.PacketNumber(1000+i), data, 1452, sender.now, true)
		for {
			frame := sender.state.encoder.pendingFrame(sender.now, 1452)
			if frame == nil {
				break
			}
			sender.state.frameSent(frame, protocol.Version1)
		}
		sender.now = sender.now.Add(packetGap)
		for {
			frame := sender.state.encoder.pendingFrame(sender.now, 1452)
			if frame == nil {
				break
			}
			sender.state.frameSent(frame, protocol.Version1)
		}
	}
	stats := sender.state.stats()
	if stats.ParityPacketsSent == 0 {
		t.Fatal("no tail row was sent")
	}
	// 5% of 600 packets is 30 rows; the debt allows only a couple of rows more while
	// it is repaid, so the byte cap must not be what limits this flow.
	if stats.MeasuredOverhead > 0.08 {
		t.Fatalf("intermittent flow measured overhead %v, expected the target rate, not the overhead cap: %+v",
			stats.MeasuredOverhead, stats)
	}
}

func TestFECReserveCoversRepairFrame(t *testing.T) {
	config := FECConfig{MaxGroupSize: wire.MaxFECWindowSize, MaxOverheadPercent: 100, MaxParityRows: 2}
	sender := newWindowTestSender(config, 1)
	maxPacketSize := protocol.ByteCount(1452)
	protectedLimit := maxPacketSize - sender.state.encoder.reserve() - fecMaxPacketOverhead
	if protectedLimit <= 0 {
		t.Fatal("the reserve doesn't leave any room for a protected packet")
	}
	var largest *wire.FECWindowRepairFrame
	for i := 0; i < 3*wire.MaxFECWindowSize; i++ {
		for _, row := range sender.send(t, protocol.PacketNumber(1+i), randomPacket(t, int(protectedLimit))) {
			if largest == nil || len(row.PacketNumbers) > len(largest.PacketNumbers) {
				largest = row
			}
		}
	}
	if largest == nil {
		t.Fatal("no repair row was sent")
	}
	if len(largest.PacketNumbers) != wire.MaxFECWindowSize {
		t.Fatalf("the largest row covers %d packets, expected a full window of %d", len(largest.PacketNumbers), wire.MaxFECWindowSize)
	}
	if length := largest.Length(protocol.Version1) + fecMaxPacketOverhead; length > maxPacketSize {
		t.Fatalf("a repair row of %d bytes doesn't fit into a %d byte datagram", length, maxPacketSize)
	}
}

// TestFECDropsRowsItCannotEvaluate verifies that a repair row which protects
// packets that were received and then left the decoder's cache is dropped instead of
// being turned into an equation that can never be solved. Without the check, every such
// row would also report the packets it can't evaluate as missing.
func TestFECDropsRowsItCannotEvaluate(t *testing.T) {
	config := FECConfig{MaxGroupSize: 8, MaxOverheadPercent: 100, MaxParityRows: 1}
	sender := newWindowTestSender(config, 1)
	receiver := newFECWindowState(config)
	var early []*wire.FECWindowRepairFrame
	for i := 0; i < 200; i++ {
		pn := protocol.PacketNumber(1000 + i)
		data := randomPacket(t, 600)
		rows := sender.send(t, pn, data)
		if i < 20 {
			early = append(early, rows...)
		}
		receiver.decoder.recordPacket(pn, data, protocol.KeyPhaseZero)
	}
	if len(early) == 0 {
		t.Fatal("no repair row was emitted early in the transfer")
	}
	var recovered int
	for _, row := range early {
		recovered += len(receiver.decoder.handleRepair(row, sender.now))
	}
	if recovered != 0 {
		t.Fatalf("rows over packets that left the cache reconstructed %d packets", recovered)
	}
	if len(receiver.decoder.missing) != 0 {
		t.Fatalf("rows over packets that left the cache were kept as equations over %d missing packets", len(receiver.decoder.missing))
	}
}

// TestFECRateKeepsRowBasesDistinct verifies that the redundancy stays low enough
// for a window larger than the number of row bases: two rows that share a member must
// never use the same base, otherwise they are not linearly independent.
func TestFECRateKeepsRowBasesDistinct(t *testing.T) {
	for _, windowSize := range []int{16, 64, 128} {
		config := FECConfig{MaxGroupSize: windowSize, MaxOverheadPercent: 100}
		state := newFECWindowState(config)
		now := monotime.Now()
		state.encoder.onFeedback(&wire.FECFeedbackFrame{ReceivedPackets: 1000, LostPackets: 500}, now)
		coverage := state.encoder.rate * float64(windowSize)
		if coverage > float64(fecWindowCauchyRows) {
			t.Fatalf("window %d: a packet is covered by %v rows, but only %d row bases exist", windowSize, coverage, fecWindowCauchyRows)
		}
	}
}

// TestFECCoefficientsAreMDS checks the property the sliding window code relies
// on: any three rows reconstruct any three members of the window, whatever their
// positions. It is the Cauchy determinant formula, checked on a few row and member
// combinations instead of being taken on faith.
func TestFECCoefficientsAreMDS(t *testing.T) {
	members := []int{0, 1, 2, 5, 9, 17, 33, 64, 90, 127}
	rowSets := [][3]uint64{{0, 1, 2}, {3, 17, 40}, {7, 8, 9}, {13, 29, 61}, {64, 65, 66}}
	for _, rowSet := range rowSets {
		for i := 0; i < len(members); i++ {
			for j := i + 1; j < len(members); j++ {
				for k := j + 1; k < len(members); k++ {
					matrix := make([][]byte, 3)
					rhs := make([][]byte, 3)
					for r, row := range rowSet {
						matrix[r] = []byte{
							fecWindowCoefficient(row, members[i]),
							fecWindowCoefficient(row, members[j]),
							fecWindowCoefficient(row, members[k]),
						}
						rhs[r] = []byte{1, 2, 3}
					}
					if !fecSolve(matrix, rhs) {
						t.Fatalf("singular submatrix for the rows %v and the members %v", rowSet, []int{members[i], members[j], members[k]})
					}
				}
			}
		}
	}
}

// TestFECHoldsTheLossPeakOfABurst pins the behaviour a burst of losses depends on: the
// peer reports the burst once, the reports after it are clean, and the sender has to
// keep spending rows at the redundancy of the burst for long enough to reconstruct it.
// The redundancy has to follow the peak of the burst, not the smoothed estimate, which
// only ramps up over several reports and decays again while the packets of the burst
// are still inside the window.
func TestFECHoldsTheLossPeakOfABurst(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10, MaxGroupSize: 64, MaxParityRows: 1}
	state := newFECWindowState(config)
	now := monotime.Now()
	// the first report only establishes the baseline of the cumulative counters
	state.encoder.onFeedback(&wire.FECFeedbackFrame{ReceivedPackets: 100, LostPackets: 0}, now)
	if state.encoder.protecting() {
		t.Fatalf("a lossless report engaged FEC: %v", state.encoder.rate)
	}

	// One report of a burst: 40 of 80 packets lost. The redundancy has to engage right
	// away, from the peak of the burst, instead of waiting for the smoothed estimate to
	// ramp up while the burst is already leaving the window.
	now = now.Add(20 * time.Millisecond)
	state.encoder.onFeedback(&wire.FECFeedbackFrame{ReceivedPackets: 140, LostPackets: 40}, now)
	if !state.encoder.protecting() {
		t.Fatalf("the burst did not engage FEC (smoothed loss %v, rate %v)",
			state.encoder.lossEWMA, state.encoder.rate)
	}
	if state.encoder.rate < 0.09 {
		t.Fatalf("the redundancy stayed at the smoothed estimate instead of the peak: %v", state.encoder.rate)
	}

	// The reports that follow the burst are clean. The redundancy of the burst has to
	// stay for the whole hold, so that the rows the burst needs can still be spent while
	// its packets are inside the window.
	for i := uint64(1); i <= 6; i++ {
		now = now.Add(20 * time.Millisecond)
		state.encoder.onFeedback(&wire.FECFeedbackFrame{ReceivedPackets: 140 + 10*i, LostPackets: 40}, now)
		if !state.encoder.protecting() {
			t.Fatalf("FEC disengaged %d reports after the burst (smoothed loss %v, rate %v)",
				i, state.encoder.lossEWMA, state.encoder.rate)
		}
		if state.encoder.rate < 0.09 {
			t.Fatalf("the redundancy decayed to %v within %d reports of the burst",
				state.encoder.rate, i)
		}
	}
	if state.windowSize.Load() == 0 {
		t.Fatal("the statistics report no active window while the burst is held")
	}

	// Once the hold is over and the peer stopped reporting, the estimate has to decay
	// as it did before, and FEC to disengage.
	for range 40 {
		now = now.Add(100 * time.Millisecond)
		state.encoder.tick(now)
	}
	if state.encoder.protecting() {
		t.Fatalf("FEC stayed engaged after the hold and without fresh reports (loss rate %v)",
			state.lossRate())
	}
	if rate := state.encoder.rate; rate != 0 {
		t.Fatalf("the redundancy outlived its hold: %v", rate)
	}
	if state.windowSize.Load() != 0 {
		t.Fatal("the statistics still report an active window after the hold")
	}
}

// TestFECDoesNotReadATinyReportAsLoss pins the failure a 20ms report interval causes on a
// slow connection: a report that covers one packet reads as 0% when the packet arrived
// and as 100% when it was lost, so a single lost packet used to pin the redundancy at the
// overhead cap for as long as the peer kept reporting. The reports are accumulated into a
// sample that is large enough to measure the path instead.
func TestFECDoesNotReadATinyReportAsLoss(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 20, MaxGroupSize: 64}
	state := newFECWindowState(config)
	now := monotime.Now()
	var received, lost uint64
	for i := 0; i < 16; i++ {
		now = now.Add(fecFeedbackInterval)
		// 16 reports of one packet each, one of which carries a loss: the sample the
		// reports accumulate into is 16 packets, so the loss rate is 1/16 = 6.25%.
		if i == 15 {
			lost++
		} else {
			received++
		}
		state.encoder.onFeedback(&wire.FECFeedbackFrame{ReceivedPackets: received, LostPackets: lost}, now)
	}
	if loss := state.encoder.peerLoss; loss < 0.02 || loss > 0.15 {
		t.Fatalf("a single lost packet was measured as %v loss", loss)
	}
	if rate := state.encoder.rate; rate <= 0 || rate > 0.15 {
		t.Fatalf("the redundancy followed a one packet report instead of the sample: %v", rate)
	}
}

// TestFECReleasesTheLossPeakWhileReportsKeepComing pins the other half of the same bug:
// the hold of a burst runs from the sample that measured it, so the clean reports that
// follow it must not keep the redundancy of the burst alive. Without that, the highest
// rate a noisy sample ever produced stayed in force for as long as the peer reported,
// which is the whole life of an active connection: a clean path paid the overhead cap
// forever.
func TestFECReleasesTheLossPeakWhileReportsKeepComing(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 20, MaxGroupSize: 64, MaxParityRows: 1}
	state := newFECWindowState(config)
	now := monotime.Now()
	// the first report establishes the baseline of the cumulative counters
	state.encoder.onFeedback(&wire.FECFeedbackFrame{ReceivedPackets: 100, LostPackets: 0}, now)
	// one report of a burst: 40 of 80 packets lost
	now = now.Add(fecFeedbackInterval)
	state.encoder.onFeedback(&wire.FECFeedbackFrame{ReceivedPackets: 140, LostPackets: 40}, now)
	if !state.encoder.protecting() {
		t.Fatal("the burst did not engage FEC")
	}
	// The path is clean again, and it keeps reporting. The hold is measured from the
	// burst, so the redundancy has to be gone after it.
	received := uint64(140)
	for i := 0; i < 150; i++ {
		now = now.Add(fecFeedbackInterval)
		received += 64
		state.encoder.onFeedback(&wire.FECFeedbackFrame{ReceivedPackets: received, LostPackets: 40}, now)
	}
	if state.encoder.protecting() {
		t.Fatalf("the redundancy of a burst outlived its hold (loss rate %v, rate %v)",
			state.lossRate(), state.encoder.rate)
	}
}

// TestFECHoldCoversTheWindowSpan checks that the hold of a burst follows how fast the
// window is filled: a slow connection needs the redundancy for the time its window spans,
// bounded so that a single burst cannot keep the overhead on for minutes.
func TestFECHoldCoversTheWindowSpan(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 20, MaxGroupSize: 64, MaxParityRows: 1}
	state := newFECWindowState(config)
	now := monotime.Now()
	if hold := state.encoder.holdDuration(); hold != fecWindowLossPeakHold {
		t.Fatalf("an encoder that never sent a packet holds a peak for %v", hold)
	}
	state.encoder.setRate(0.1)
	for i := 0; i < 40; i++ {
		now = now.Add(100 * time.Millisecond)
		state.encoder.addPacket(protocol.PacketNumber(1+i), randomPacket(t, 1200), 1452, now, true)
	}
	// 64 packets at 100ms per packet span 6.4 seconds: more than the lower bound of the
	// hold, and bounded by its maximum.
	if hold := state.encoder.holdDuration(); hold != fecWindowLossPeakHoldMax {
		t.Fatalf("the hold does not follow the packet rate: %v", hold)
	}
}

// TestFECBaselineRedundancyWithoutLoss verifies that a configured baseline keeps repair
// rows flowing on a path that never reports a loss, within the overhead cap, and that it
// stays engaged when the peer's reports stop: that is the "the first row must not wait
// for feedback" property of the baseline.
func TestFECBaselineRedundancyWithoutLoss(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10, MaxGroupSize: 32, MaxParityRows: 1, BaselineRedundancyPercent: 3}
	state := newFECWindowState(config)
	if !state.encoder.protecting() {
		t.Fatal("the configured baseline didn't engage before the first packet")
	}
	if rate := state.encoder.rate; rate <= 0 || rate > 0.031 {
		t.Fatalf("unexpected baseline redundancy %v", rate)
	}
	now := monotime.Now()
	var rows int
	for i := 0; i < 2000; i++ {
		state.encoder.addPacket(protocol.PacketNumber(1+i), randomPacket(t, 1200), 1452, now, true)
		for {
			frame := state.encoder.pendingFrame(now, 1452)
			if frame == nil {
				break
			}
			state.frameSent(frame, protocol.Version1)
			rows++
		}
		now = now.Add(time.Millisecond)
	}
	if rows == 0 {
		t.Fatal("the baseline sent no repair row on a clean path")
	}
	if stats := state.stats(); stats.MeasuredOverhead > 0.10+1e-9 {
		t.Fatalf("baseline overhead %v exceeds the 10%% cap: %+v", stats.MeasuredOverhead, stats)
	}
	// The baseline is not driven by feedback: it survives a peer that goes quiet.
	for i := 0; i < 20; i++ {
		now = now.Add(fecEvaluationInterval)
		state.encoder.tick(now)
	}
	if !state.encoder.protecting() {
		t.Fatal("the baseline decayed after the feedback stream stopped")
	}
}

// TestFECBaselineIsClampedByOverheadCap verifies that a baseline larger than the overhead
// cap is clamped by the same byte budget as the reactive scheme.
func TestFECBaselineIsClampedByOverheadCap(t *testing.T) {
	config := FECConfig{MaxOverheadPercent: 10, MaxGroupSize: 32, MaxParityRows: 1, BaselineRedundancyPercent: 90}
	state := newFECWindowState(config)
	if rate := state.encoder.rate; rate <= 0 || rate > 0.0951 {
		t.Fatalf("baseline rate %v is not clamped to the 10%% cap", rate)
	}
	now := monotime.Now()
	var rows int
	for i := 0; i < 4000; i++ {
		state.encoder.addPacket(protocol.PacketNumber(1+i), randomPacket(t, 1200), 1452, now, true)
		for {
			frame := state.encoder.pendingFrame(now, 1452)
			if frame == nil {
				break
			}
			state.frameSent(frame, protocol.Version1)
			rows++
		}
		now = now.Add(time.Millisecond)
	}
	if rows == 0 {
		t.Fatal("no repair row was sent")
	}
	stats := state.stats()
	if stats.MeasuredOverhead > 0.10+1e-9 {
		t.Fatalf("measured overhead %v exceeds the 10%% cap: %+v", stats.MeasuredOverhead, stats)
	}
}

// recordingLogger captures the lines the FEC decoder logs, for the tests that assert a
// stalled peer is made visible.
type recordingLogger struct {
	lines []string
}

func (l *recordingLogger) SetLogLevel(utils.LogLevel)     {}
func (l *recordingLogger) SetLogTimeFormat(string)        {}
func (l *recordingLogger) WithPrefix(string) utils.Logger { return l }
func (l *recordingLogger) Debug() bool                    { return true }
func (l *recordingLogger) Errorf(string, ...any)          {}
func (l *recordingLogger) Infof(format string, args ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}
func (l *recordingLogger) Debugf(string, ...any) {}

// TestFECSkipReasons verifies that the two skip causes are counted separately: the byte
// budget refusing a row, and a row that can't be built to fit a datagram.
func TestFECSkipReasons(t *testing.T) {
	now := monotime.Now()

	// A 1% cap can never pay for a 1200 byte parity row out of 1200 byte packets. Fill
	// the window at a tiny rate first, so every refused row has a full window and the
	// first-packet "window too small" case can't pollute the counters.
	state := newFECWindowState(FECConfig{MaxOverheadPercent: 1, MaxGroupSize: 32})
	state.encoder.setRate(0.001)
	for i := 0; i < 10; i++ {
		state.encoder.addPacket(protocol.PacketNumber(1+i), randomPacket(t, 1200), 1452, now, true)
	}
	state.encoder.setRate(1)
	for i := 0; i < 50; i++ {
		state.encoder.addPacket(protocol.PacketNumber(11+i), randomPacket(t, 1200), 1452, now, true)
	}
	stats := state.stats()
	if stats.SkippedRowsBudget == 0 {
		t.Fatalf("budget skips were not counted: %+v", stats)
	}
	if stats.SkippedRowsUnbuildable != 0 {
		t.Fatalf("budget skips were miscounted as unbuildable: %+v", stats)
	}

	// A full-size packet plus the repair header doesn't fit into the same datagram.
	// Fill the window first again, then pre-pay the row so only the size check fails.
	state = newFECWindowState(FECConfig{MaxOverheadPercent: 100, MaxGroupSize: 32})
	state.encoder.setRate(0.001)
	for i := 0; i < 4; i++ {
		state.encoder.addPacket(protocol.PacketNumber(1+i), randomPacket(t, 1452), 1452, now, true)
	}
	state.encoder.setRate(1)
	state.encoder.credit = 1 << 20 // pre-pay the row so the budget check passes
	state.encoder.addPacket(9, randomPacket(t, 1452), 1452, now, true)
	stats = state.stats()
	if stats.SkippedRowsUnbuildable == 0 {
		t.Fatalf("unbuildable rows were not counted: %+v", stats)
	}
	if stats.SkippedRowsBudget != 0 {
		t.Fatalf("unbuildable rows were miscounted as budget: %+v", stats)
	}
}

// TestFECMissingGauge verifies that the missing-packets gauge follows the protected
// packets the endpoint hasn't seen, and drops as they arrive or expire. The repair row
// comes from the real encoder, so its length parity is consistent: an artificial frame
// with zero length parity would let the decoder "solve" a garbage packet as soon as
// one of the unknowns arrives.
func TestFECMissingGauge(t *testing.T) {
	config := FECConfig{MaxGroupSize: 8, MaxOverheadPercent: 100, MaxParityRows: 1}
	sender := newWindowTestSender(config, 1)
	packets := make(map[protocol.PacketNumber][]byte)
	var row *wire.FECWindowRepairFrame
	for i := 0; i < 3; i++ {
		pn := protocol.PacketNumber(1 + i)
		packets[pn] = randomPacket(t, 300)
		for _, r := range sender.send(t, pn, packets[pn]) {
			if len(r.PacketNumbers) == 3 {
				row = r
			}
		}
	}
	if row == nil {
		t.Fatal("no repair row covering all three packets")
	}
	receiver := newFECWindowState(config)
	now := monotime.Now()
	receiver.decoder.handleRepair(row, now)
	if got := receiver.stats().MissingPackets; got != 3 {
		t.Fatalf("missing gauge = %d after a row over three unseen packets, want 3", got)
	}
	// With two unknowns left the equation still can't be solved, so the gauge only
	// drops by the packet that actually arrived.
	receiver.decoder.recordPacket(1, packets[1], protocol.KeyPhaseZero)
	if got := receiver.stats().MissingPackets; got != 2 {
		t.Fatalf("missing gauge = %d after packet 1 arrived, want 2 (map=%v)", got, receiver.decoder.missing)
	}
	receiver.decoder.expireMissing(now.Add(fecWindowMissingTimeout))
	if got := receiver.stats().MissingPackets; got != 0 {
		t.Fatalf("missing gauge = %d after the missing packets expired, want 0", got)
	}
}

// TestFECStalledMissingIsLogged verifies that the decoder logs once when protected
// packets expire while no repair row has arrived for a whole missing timeout.
func TestFECStalledMissingIsLogged(t *testing.T) {
	logger := &recordingLogger{}
	state := newFECWindowStateWithLogger(FECConfig{MaxGroupSize: 8, MaxOverheadPercent: 100, MaxParityRows: 1}, logger)
	now := monotime.Now()
	state.decoder.handleRepair(&wire.FECWindowRepairFrame{
		Row:               0,
		FirstPacketNumber: 1,
		Span:              2,
		PacketNumbers:     []protocol.PacketNumber{1, 2},
		ParityLength:      128,
		Parity:            make([]byte, 128),
	}, now)
	state.decoder.expireMissing(now.Add(fecWindowMissingTimeout))
	if len(logger.lines) != 1 {
		t.Fatalf("expected one stall log line, got %v", logger.lines)
	}
	if !strings.Contains(logger.lines[0], "expired unrecovered") {
		t.Fatalf("unexpected stall log line: %q", logger.lines[0])
	}
	// The log is rate limited: a second expiry inside the interval stays quiet.
	state.decoder.handleRepair(&wire.FECWindowRepairFrame{
		Row:               1,
		FirstPacketNumber: 3,
		Span:              2,
		PacketNumbers:     []protocol.PacketNumber{3, 4},
		ParityLength:      128,
		Parity:            make([]byte, 128),
	}, now.Add(100*time.Millisecond))
	state.decoder.expireMissing(now.Add(2 * fecWindowMissingTimeout))
	if len(logger.lines) != 1 {
		t.Fatalf("the stall log was not rate limited: %v", logger.lines)
	}
}

// TestFECDuplicateRowDropped verifies that a repair row whose equation is already
// pending is counted and dropped instead of adding a duplicate equation.
func TestFECDuplicateRowDropped(t *testing.T) {
	state := newFECWindowState(FECConfig{MaxGroupSize: 8, MaxOverheadPercent: 100, MaxParityRows: 1})
	now := monotime.Now()
	frame := &wire.FECWindowRepairFrame{
		Row:               3,
		FirstPacketNumber: 1,
		Span:              2,
		PacketNumbers:     []protocol.PacketNumber{1, 2},
		ParityLength:      128,
		Parity:            make([]byte, 128),
	}
	state.decoder.handleRepair(frame, now)
	if len(state.decoder.pending) != 1 {
		t.Fatalf("expected one pending equation, got %d", len(state.decoder.pending))
	}
	state.decoder.handleRepair(frame, now.Add(time.Millisecond))
	if got := state.stats().DuplicateRows; got != 1 {
		t.Fatalf("duplicate rows = %d, want 1", got)
	}
	if len(state.decoder.pending) != 1 {
		t.Fatalf("the duplicate equation was added: %d pending", len(state.decoder.pending))
	}
}

// TestFECCoverageRowsStayWithinRowBases asserts the invariant updateRedundancyFor
// relies on: a packet is covered by at most fecWindowMaxCoverageRows rows, so their row
// bases can all be distinct.
func TestFECCoverageRowsStayWithinRowBases(t *testing.T) {
	for _, percent := range []int{1, 10, 20, 100} {
		for _, window := range []int{2, 4, 16, 64, wire.MaxFECWindowSize} {
			state := newFECWindowState(FECConfig{MaxOverheadPercent: percent, MaxGroupSize: window})
			state.encoder.updateRedundancyFor(1) // a loss report of 100%
			coverage := float64(state.encoder.windowSize) * state.encoder.rate
			if coverage > float64(fecWindowMaxCoverageRows)+1e-9 {
				t.Fatalf("%d%% cap, window %d: %v rows cover one packet, more than the %d row bases",
					percent, window, coverage, fecWindowMaxCoverageRows)
			}
		}
	}
}
