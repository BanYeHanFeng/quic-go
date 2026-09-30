package ackhandler

import (
	"slices"
	"testing"
	"time"

	congestionExt "github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/internal/congestion"
	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/wire"
)

type recordingSender struct {
	congestion.SendAlgorithm
	sent, acked, lost, spurious int
	lastCongestionPN            protocol.PacketNumber
	blocked, pacing             bool
}

func (c *recordingSender) CanSend(n protocol.ByteCount) bool {
	return !c.blocked && c.SendAlgorithm.CanSend(n)
}

func (c *recordingSender) HasPacingBudget(t monotime.Time) bool {
	return !c.pacing && c.SendAlgorithm.HasPacingBudget(t)
}

func (c *recordingSender) OnPacketSent(t monotime.Time, pn protocol.PacketNumber, size protocol.ByteCount, ack bool) {
	c.sent++
	c.SendAlgorithm.OnPacketSent(t, pn, size, ack)
}

func (c *recordingSender) OnPacketAcked(pn protocol.PacketNumber, flight protocol.ByteCount) {
	c.acked++
	c.SendAlgorithm.OnPacketAcked(pn, flight)
}

func (c *recordingSender) OnCongestionEvent(pn protocol.PacketNumber) {
	c.lost++
	c.lastCongestionPN = pn
	c.SendAlgorithm.OnCongestionEvent(pn)
}

func (c *recordingSender) OnSpuriousLoss(pn protocol.PacketNumber) {
	c.spurious++
	c.SendAlgorithm.OnSpuriousLoss(pn)
}

func newBypassHandler(t *testing.T, enableECN bool) (*sentPacketHandler, *recordingSender) {
	t.Helper()
	rtt := &utils.RTTStats{}
	rtt.SetInitialRTT(20 * time.Millisecond)
	h := NewSentPacketHandler(0, 1280, rtt, &utils.ConnectionStats{}, true, enableECN, nil, protocol.PerspectiveClient, false, nil, utils.DefaultLogger).(*sentPacketHandler)
	h.handshakeConfirmed = true
	h.peerCompletedAddressValidation = true
	h.initialPackets = nil
	h.handshakePackets = nil
	cc := &recordingSender{SendAlgorithm: h.congestion}
	h.congestion = cc
	return h, cc
}

func sendBypassTestPacket(h *sentPacketHandler, now monotime.Time, bypass bool) protocol.PacketNumber {
	pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
	ecn := h.ECNMode(!bypass)
	h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.DatagramFrame{Data: make([]byte, 100)}}}, protocol.Encryption1RTT, ecn, 120, false, false, bypass)
	return pn
}

func ackBypassTestPacket(t *testing.T, h *sentPacketHandler, pn protocol.PacketNumber, now monotime.Time) {
	t.Helper()
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: pn, Largest: pn}}}, protocol.Encryption1RTT, now)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDatagramCongestionAccounting(t *testing.T) {
	h, cc := newBypassHandler(t, false)
	now := monotime.Now()
	normal := sendBypassTestPacket(h, now, false)
	bypass := sendBypassTestPacket(h, now, true)
	if h.bytesInFlight != 120 || cc.sent != 1 || h.appDataPackets.numOutstanding != 2 {
		t.Fatalf("flight=%d sent=%d outstanding=%d", h.bytesInFlight, cc.sent, h.appDataPackets.numOutstanding)
	}
	ackBypassTestPacket(t, h, bypass, now.Add(time.Millisecond))
	if h.bytesInFlight != 120 || cc.acked != 0 || cc.lost != 0 || h.appDataPackets.numOutstanding != 1 {
		t.Fatalf("bypass ACK accounting: flight=%d acked=%d lost=%d outstanding=%d", h.bytesInFlight, cc.acked, cc.lost, h.appDataPackets.numOutstanding)
	}
	ackBypassTestPacket(t, h, normal, now.Add(2*time.Millisecond))
	if h.bytesInFlight != 0 || cc.acked != 1 || h.appDataPackets.numOutstanding != 0 {
		t.Fatalf("controlled ACK accounting: flight=%d acked=%d outstanding=%d", h.bytesInFlight, cc.acked, h.appDataPackets.numOutstanding)
	}
	ackBypassTestPacket(t, h, bypass, now.Add(3*time.Millisecond)) // duplicate ACK
	if cc.acked != 1 || h.appDataPackets.numOutstanding != 0 {
		t.Fatal("duplicate ACK changed controller or outstanding count")
	}
}

func TestDatagramLossRetainsRecovery(t *testing.T) {
	h, cc := newBypassHandler(t, false)
	now := monotime.Now()
	sendBypassTestPacket(h, now, true)
	if h.GetLossDetectionTimeout().IsZero() {
		t.Fatal("DATAGRAM-only traffic has no recovery timer")
	}
	ptoTime := h.GetLossDetectionTimeout()
	if err := h.OnLossDetectionTimeout(ptoTime); err != nil {
		t.Fatal(err)
	}
	if h.numProbesToSend == 0 {
		t.Fatal("PTO did not request an ACK-eliciting probe")
	}
	if !h.QueueProbePacket(protocol.PacketNumberSpaceAppData, ptoTime) {
		t.Fatal("lost datagram not retired")
	}
	if h.hist.HasOutstandingPackets() || h.appDataPackets.numOutstanding != 0 || cc.sent != 0 || cc.lost != 0 {
		t.Fatalf("bypass probe state: hasOutstanding=%v numOutstanding=%d sent=%d lost=%d", h.hist.HasOutstandingPackets(), h.appDataPackets.numOutstanding, cc.sent, cc.lost)
	}
	h.numProbesToSend = 0
	pn := sendBypassTestPacket(h, now.Add(time.Second), true)
	ackBypassTestPacket(t, h, pn, now.Add(time.Second+time.Millisecond))
	if h.bytesInFlight != 0 || h.appDataPackets.numOutstanding != 0 || cc.acked != 0 {
		t.Fatal("bypass recovery accounting")
	}
}

func TestDatagramLossDoesNotReduceWindow(t *testing.T) {
	h, cc := newBypassHandler(t, false)
	now := monotime.Now()
	lostBypass := sendBypassTestPacket(h, now, true)
	pn := sendBypassTestPacket(h, now.Add(time.Millisecond), true)
	ackBypassTestPacket(t, h, pn, now.Add(time.Second))
	if cc.sent != 0 || cc.acked != 0 || cc.lost != 0 || h.bytesInFlight != 0 {
		t.Fatal("bypass loss reached congestion controller")
	}
	if err := h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()); err != nil {
		t.Fatal(err)
	}
	if h.hist.HasOutstandingPackets() || h.appDataPackets.numOutstanding != 0 {
		t.Fatal("lost DATAGRAM not removed")
	}
	if h.connStats.PacketsLost.Load() != 1 || h.connStats.BytesLost.Load() != 120 {
		t.Fatalf("lost stats: packets=%d bytes=%d", h.connStats.PacketsLost.Load(), h.connStats.BytesLost.Load())
	}
	// A late ACK for the declared-lost bypass packet rolls back stats and
	// relaxes reordering thresholds, without reporting a spurious loss to Reno.
	_, err := h.ReceivedAck(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: lostBypass, Largest: pn}}}, protocol.Encryption1RTT, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if cc.spurious != 0 {
		t.Fatalf("bypass spurious loss reported to controller: %d", cc.spurious)
	}
	if !h.packetThresholdDisabled {
		t.Fatal("spurious bypass loss did not relax packet threshold")
	}
	if h.connStats.PacketsLost.Load() != 0 || h.connStats.BytesLost.Load() != 0 {
		t.Fatalf("spurious loss did not roll back stats: packets=%d bytes=%d", h.connStats.PacketsLost.Load(), h.connStats.BytesLost.Load())
	}
}

func TestDatagramBypassLimits(t *testing.T) {
	h, cc := newBypassHandler(t, false)
	now := monotime.Now()
	cc.blocked = true
	if h.SendMode(now) != SendAck || !h.CanSendUncongestedDatagram() {
		t.Fatal("cwnd blocks bypass")
	}
	cc.blocked = false
	cc.pacing = true
	if h.SendMode(now) != SendPacingLimited || !h.CanSendUncongestedDatagram() {
		t.Fatal("pacing blocks bypass")
	}
	h.peerAddressValidated = false
	if h.CanSendUncongestedDatagram() {
		t.Fatal("anti-amplification bypassed")
	}
	h.peerAddressValidated = true
	h.hist.packets = make([]*packet, protocol.MaxOutstandingSentPackets-64)
	if h.CanSendUncongestedDatagram() {
		t.Fatal("resource limit bypassed")
	}
}

type injectedExtendedSender struct {
	sent, acked, lost, delivered, lostSamples, neutered int
	lastLeastUnacked                                    congestionExt.PacketNumber
}

func (*injectedExtendedSender) SetRTTStatsProvider(congestionExt.RTTStatsProvider) {}
func (*injectedExtendedSender) TimeUntilSend(congestionExt.ByteCount) monotime.Time {
	return 0
}
func (*injectedExtendedSender) HasPacingBudget(monotime.Time) bool { return true }
func (c *injectedExtendedSender) OnPacketSent(monotime.Time, congestionExt.ByteCount, congestionExt.PacketNumber, congestionExt.ByteCount, bool) {
	c.sent++
}
func (*injectedExtendedSender) CanSend(congestionExt.ByteCount) bool { return true }
func (*injectedExtendedSender) MaybeExitSlowStart()                  {}
func (c *injectedExtendedSender) OnPacketAcked(congestionExt.PacketNumber, congestionExt.ByteCount, congestionExt.ByteCount, monotime.Time) {
	c.acked++
}
func (c *injectedExtendedSender) OnCongestionEvent(congestionExt.PacketNumber, congestionExt.ByteCount, congestionExt.ByteCount) {
	c.lost++
}
func (*injectedExtendedSender) OnRetransmissionTimeout(bool)               {}
func (*injectedExtendedSender) SetMaxDatagramSize(congestionExt.ByteCount) {}
func (*injectedExtendedSender) InSlowStart() bool                          { return false }
func (*injectedExtendedSender) InRecovery() bool                           { return false }
func (*injectedExtendedSender) GetCongestionWindow() congestionExt.ByteCount {
	return 1 << 20
}
func (c *injectedExtendedSender) OnCongestionEventEx(_ congestionExt.ByteCount, _ monotime.Time, acked []congestionExt.AckedPacketInfo, lost []congestionExt.LostPacketInfo) {
	c.delivered += len(acked)
	c.lostSamples += len(lost)
}
func (c *injectedExtendedSender) OnPacketNeutered(congestionExt.PacketNumber) { c.neutered++ }
func (c *injectedExtendedSender) OnPacketsLost(leastUnacked congestionExt.PacketNumber) {
	c.lastLeastUnacked = leastUnacked
}
func (*injectedExtendedSender) OnAppLimited(congestionExt.ByteCount) {}

func TestDatagramBypassExtendedSampler(t *testing.T) {
	h, _ := newBypassHandler(t, false)
	cc := &injectedExtendedSender{}
	h.SetCongestionControl(cc)
	now := monotime.Now()
	sendBypassTestPacket(h, now, true)
	pn := sendBypassTestPacket(h, now, true)
	ackBypassTestPacket(t, h, pn, now.Add(time.Millisecond))
	if err := h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()); err != nil {
		t.Fatal(err)
	}
	if cc.delivered != 0 || cc.lostSamples != 0 || cc.sent != 0 || cc.acked != 0 || cc.lost != 0 {
		t.Fatalf("exempt data reached bandwidth sampler: %+v", *cc)
	}
	// Keep an unacked bypass packet in history before a normal packet to ensure
	// notifyLeastUnacked and MigratedPath neuterPacket skip bypass packets.
	bypassPending := sendBypassTestPacket(h, now.Add(time.Second), true)
	normal := sendBypassTestPacket(h, now.Add(time.Second), false)
	ackBypassTestPacket(t, h, normal, now.Add(time.Second+time.Millisecond))
	if cc.delivered != 1 || cc.sent != 1 || cc.acked != 1 {
		t.Fatalf("controlled sample missing: %+v", *cc)
	}
	if cc.lastLeastUnacked <= congestionExt.PacketNumber(bypassPending) {
		t.Fatalf("leastUnacked=%d included bypass packet %d", cc.lastLeastUnacked, bypassPending)
	}
	h.MigratedPath(now.Add(2*time.Second), 1280)
	if cc.neutered != 0 {
		t.Fatalf("bypass packet neutered in injected controller: %d", cc.neutered)
	}
}

func ackRangesFor(pns ...protocol.PacketNumber) []wire.AckRange {
	sorted := slices.Clone(pns)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	var ranges []wire.AckRange
	for i := len(sorted) - 1; i >= 0; i-- {
		pn := sorted[i]
		if len(ranges) > 0 && pn+1 == ranges[len(ranges)-1].Smallest {
			ranges[len(ranges)-1].Smallest = pn
		} else {
			ranges = append(ranges, wire.AckRange{Smallest: pn, Largest: pn})
		}
	}
	return ranges
}

func TestDatagramBypassInterleavedECN(t *testing.T) {
	t.Run("testing-and-capable-ack", func(t *testing.T) {
		h, cc := newBypassHandler(t, true)
		tracker := h.ecnTracker.(*ecnTracker)
		now := monotime.Now()

		// Normal ECT(0) -> bypass Not-ECT -> normal ECT(0) during ECN testing.
		p0 := sendBypassTestPacket(h, now, false)
		p1 := sendBypassTestPacket(h, now, true)
		p2 := sendBypassTestPacket(h, now, false)
		if tracker.numSentECT0 != 2 || tracker.numSentTesting != 2 {
			t.Fatalf("unexpected testing counts: ect0=%d testing=%d", tracker.numSentECT0, tracker.numSentTesting)
		}
		_, err := h.ReceivedAck(&wire.AckFrame{
			AckRanges: ackRangesFor(p0, p1, p2),
			ECT0:      2,
		}, protocol.Encryption1RTT, now.Add(time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		if tracker.state != ecnStateCapable {
			t.Fatalf("ECN validation failed on interleaved testing ACK: state=%d", tracker.state)
		}

		// Normal ECT(0) -> bypass Not-ECT -> normal ECT(0) once ECN is capable,
		// with one CE mark reported on the controlled packets.
		p3 := sendBypassTestPacket(h, now.Add(2*time.Millisecond), false)
		p4 := sendBypassTestPacket(h, now.Add(2*time.Millisecond), true)
		p5 := sendBypassTestPacket(h, now.Add(2*time.Millisecond), false)
		_, err = h.ReceivedAck(&wire.AckFrame{
			AckRanges: ackRangesFor(p3, p4, p5),
			ECT0:      3,
			ECNCE:     1,
		}, protocol.Encryption1RTT, now.Add(3*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		if tracker.state != ecnStateCapable {
			t.Fatalf("ECN failed on interleaved capable ACK: state=%d", tracker.state)
		}
		if cc.lost != 1 || cc.lastCongestionPN != p5 {
			t.Fatalf("ECN CE congestion event: lost=%d pn=%d want=%d", cc.lost, cc.lastCongestionPN, p5)
		}

		// ACKing a bypass packet alone with unchanged ECN counts must not fail ECN.
		p6 := sendBypassTestPacket(h, now.Add(4*time.Millisecond), true)
		_, err = h.ReceivedAck(&wire.AckFrame{
			AckRanges: ackRangesFor(p6),
			ECT0:      3,
			ECNCE:     1,
		}, protocol.Encryption1RTT, now.Add(5*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		if tracker.state != ecnStateCapable || cc.lost != 1 {
			t.Fatalf("bypass-only ACK altered ECN state=%d or congestion lost=%d", tracker.state, cc.lost)
		}
	})

	t.Run("testing-loss-and-probe", func(t *testing.T) {
		h, _ := newBypassHandler(t, true)
		tracker := h.ecnTracker.(*ecnTracker)
		now := monotime.Now()

		// Send 10 normal testing packets interleaved with 2 bypass packets.
		// Keep the 10th normal packet sent later so time-threshold loss only
		// declares the first 9 normal packets + 2 bypass packets lost.
		for i := range numECNTestingPackets - 1 {
			if i == 1 || i == 3 {
				sendBypassTestPacket(h, now, true)
			}
			sendBypassTestPacket(h, now, false)
		}
		lastNormalTime := now.Add(time.Second)
		lastNormal := sendBypassTestPacket(h, lastNormalTime, false)
		if tracker.state != ecnStateUnknown || tracker.numSentTesting != numECNTestingPackets {
			t.Fatalf("expected unknown state after 10 testing packets: state=%d sent=%d", tracker.state, tracker.numSentTesting)
		}
		// Acknowledge a later bypass packet so detectLostPackets declares the
		// earlier 9 normal testing packets and 2 bypass packets lost via time
		// threshold while leaving lastNormal in flight.
		ackTrigger := sendBypassTestPacket(h, lastNormalTime, true)
		_, err := h.ReceivedAck(&wire.AckFrame{
			AckRanges: []wire.AckRange{{Smallest: ackTrigger, Largest: ackTrigger}},
			ECT0:      0,
		}, protocol.Encryption1RTT, lastNormalTime.Add(time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		if tracker.numLostTesting != numECNTestingPackets-1 {
			t.Fatalf("numLostTesting=%d, want %d", tracker.numLostTesting, numECNTestingPackets-1)
		}
		if tracker.state != ecnStateUnknown {
			t.Fatalf("ECN failed prematurely on lost bypass packets: state=%d", tracker.state)
		}
		// Acknowledging the surviving 10th testing packet confirms ECN capability.
		pFinal := sendBypassTestPacket(h, lastNormalTime.Add(2*time.Millisecond), false)
		_, err = h.ReceivedAck(&wire.AckFrame{
			AckRanges: ackRangesFor(lastNormal, pFinal),
			ECT0:      1,
		}, protocol.Encryption1RTT, lastNormalTime.Add(3*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		if tracker.state != ecnStateCapable {
			t.Fatalf("ECN failed to become capable after surviving testing packet ACK: state=%d", tracker.state)
		}

		// QueueProbePacket retiring a bypass packet inside the testing window
		// must not increment numLostTesting.
		h2, _ := newBypassHandler(t, true)
		tracker2 := h2.ecnTracker.(*ecnTracker)
		sendBypassTestPacket(h2, now, false) // normal testing packet #1
		sendBypassTestPacket(h2, now, true)  // interleaved bypass packet
		sendBypassTestPacket(h2, now, false) // normal testing packet #2
		if !h2.QueueProbePacket(protocol.PacketNumberSpaceAppData, now) {
			t.Fatal("expected normal testing packet to be queued for probe")
		}
		if tracker2.numLostTesting != 1 {
			t.Fatalf("numLostTesting after normal probe=%d, want 1", tracker2.numLostTesting)
		}
		if !h2.QueueProbePacket(protocol.PacketNumberSpaceAppData, now) {
			t.Fatal("expected bypass packet to be retired by probe")
		}
		if tracker2.numLostTesting != 1 {
			t.Fatalf("numLostTesting after bypass probe=%d, want 1", tracker2.numLostTesting)
		}
	})

	t.Run("reordered-ce-before-bypass-ack", func(t *testing.T) {
		for _, injected := range []bool{false, true} {
			name := "native"
			if injected {
				name = "injected"
			}
			t.Run(name, func(t *testing.T) {
				h, nativeCC := newBypassHandler(t, true)
				tracker := h.ecnTracker.(*ecnTracker)
				var extCC *injectedExtendedSender
				if injected {
					extCC = &injectedExtendedSender{}
					h.SetCongestionControl(extCC)
				}
				now := monotime.Now()

				// Confirm ECN capability first with a normal packet.
				pInit := sendBypassTestPacket(h, now, false)
				_, err := h.ReceivedAck(&wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: pInit, Largest: pInit}},
					ECT0:      1,
				}, protocol.Encryption1RTT, now.Add(time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				if tracker.state != ecnStateCapable {
					t.Fatalf("expected capable ECN state, got %d", tracker.state)
				}

				// Send normal ECT(0) packet pN followed by bypass Not-ECT pN1.
				pN := sendBypassTestPacket(h, now.Add(2*time.Millisecond), false)
				pN1 := sendBypassTestPacket(h, now.Add(2*time.Millisecond), true)

				// Peer receives pN1 first (advancing largestAcked to pN1) with no CE yet.
				_, err = h.ReceivedAck(&wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: pN1, Largest: pN1}},
					ECT0:      1,
				}, protocol.Encryption1RTT, now.Add(3*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}

				// Peer then receives CE-marked pN; largestAcked stays pN1 so ECN
				// tracker does not consume CE=1 yet.
				_, err = h.ReceivedAck(&wire.AckFrame{
					AckRanges: ackRangesFor(pN, pN1),
					ECT0:      1,
					ECNCE:     1,
				}, protocol.Encryption1RTT, now.Add(4*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}

				// Next ACK acknowledges only a new bypass packet pN2, advancing
				// largestAcked and committing the cumulative CE=1 delta.
				pN2 := sendBypassTestPacket(h, now.Add(5*time.Millisecond), true)
				_, err = h.ReceivedAck(&wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: pN2, Largest: pN2}},
					ECT0:      1,
					ECNCE:     1,
				}, protocol.Encryption1RTT, now.Add(6*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}

				if injected {
					if extCC.lost != 1 {
						t.Fatalf("injected CC lost=%d, want 1", extCC.lost)
					}
				} else {
					if nativeCC.lost != 1 || nativeCC.lastCongestionPN != pN {
						t.Fatalf("native CC lost=%d pn=%d, want lost=1 pn=%d", nativeCC.lost, nativeCC.lastCongestionPN, pN)
					}
				}

				// A subsequent bypass-only ACK with unchanged CE count must not notify again.
				pN3 := sendBypassTestPacket(h, now.Add(7*time.Millisecond), true)
				_, err = h.ReceivedAck(&wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: pN3, Largest: pN3}},
					ECT0:      1,
					ECNCE:     1,
				}, protocol.Encryption1RTT, now.Add(8*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				if injected && extCC.lost != 1 {
					t.Fatalf("injected CC notified twice: lost=%d", extCC.lost)
				}
				if !injected && nativeCC.lost != 1 {
					t.Fatalf("native CC notified twice: lost=%d", nativeCC.lost)
				}
			})
		}
	})

	t.Run("spurious-loss-ce-before-bypass-ack", func(t *testing.T) {
		for _, injected := range []bool{false, true} {
			name := "native"
			if injected {
				name = "injected"
			}
			t.Run(name, func(t *testing.T) {
				h, nativeCC := newBypassHandler(t, true)
				tracker := h.ecnTracker.(*ecnTracker)
				var extCC *injectedExtendedSender
				if injected {
					extCC = &injectedExtendedSender{}
					h.SetCongestionControl(extCC)
				}
				now := monotime.Now()

				// Confirm ECN capability first.
				pInit := sendBypassTestPacket(h, now, false)
				_, err := h.ReceivedAck(&wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: pInit, Largest: pInit}},
					ECT0:      1,
				}, protocol.Encryption1RTT, now.Add(time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				if tracker.state != ecnStateCapable {
					t.Fatalf("expected capable ECN state, got %d", tracker.state)
				}
				initialCwnd := nativeCC.GetCongestionWindow()

				// Send normal ECT(0) packet pN followed by 3 bypass packets so
				// ACKing the 3rd bypass packet declares pN lost by packet threshold.
				pN := sendBypassTestPacket(h, now.Add(2*time.Millisecond), false)
				_ = sendBypassTestPacket(h, now.Add(2*time.Millisecond), true)
				_ = sendBypassTestPacket(h, now.Add(2*time.Millisecond), true)
				pB3 := sendBypassTestPacket(h, now.Add(2*time.Millisecond), true)

				_, err = h.ReceivedAck(&wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: pB3, Largest: pB3}},
					ECT0:      1,
				}, protocol.Encryption1RTT, now.Add(3*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				if injected {
					if extCC.lost != 1 {
						t.Fatalf("expected initial loss on injected CC, got %d", extCC.lost)
					}
				} else {
					if nativeCC.lost != 1 || nativeCC.GetCongestionWindow() >= initialCwnd {
						t.Fatalf("expected initial Reno cutback: lost=%d cwnd=%d initial=%d", nativeCC.lost, nativeCC.GetCongestionWindow(), initialCwnd)
					}
				}

				// pN arrives late with CE=1; largestAcked does not advance, so pN is
				// processed as a spurious loss (Reno restores cwnd) and ECN CE is deferred.
				_, err = h.ReceivedAck(&wire.AckFrame{
					AckRanges: ackRangesFor(pN, pB3),
					ECT0:      1,
					ECNCE:     1,
				}, protocol.Encryption1RTT, now.Add(4*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				if !injected && (nativeCC.spurious != 1 || nativeCC.GetCongestionWindow() != initialCwnd) {
					t.Fatalf("expected Reno spurious-loss undo: spurious=%d cwnd=%d initial=%d", nativeCC.spurious, nativeCC.GetCongestionWindow(), initialCwnd)
				}

				// Next bypass-only ACK advances largestAcked and commits CE=1; both
				// controllers must still receive the CE congestion event for pN.
				pB4 := sendBypassTestPacket(h, now.Add(5*time.Millisecond), true)
				_, err = h.ReceivedAck(&wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: pB4, Largest: pB4}},
					ECT0:      1,
					ECNCE:     1,
				}, protocol.Encryption1RTT, now.Add(6*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				if injected {
					if extCC.lost != 2 {
						t.Fatalf("injected CC missed CE after spurious loss: lost=%d, want 2", extCC.lost)
					}
				} else {
					if nativeCC.lost != 2 || nativeCC.lastCongestionPN != pN || nativeCC.GetCongestionWindow() >= initialCwnd {
						t.Fatalf("native CC missed CE after spurious loss: lost=%d pn=%d cwnd=%d initial=%d", nativeCC.lost, nativeCC.lastCongestionPN, nativeCC.GetCongestionWindow(), initialCwnd)
					}
				}

				// Subsequent bypass-only ACK with unchanged CE count must not notify again.
				pB5 := sendBypassTestPacket(h, now.Add(7*time.Millisecond), true)
				_, err = h.ReceivedAck(&wire.AckFrame{
					AckRanges: []wire.AckRange{{Smallest: pB5, Largest: pB5}},
					ECT0:      1,
					ECNCE:     1,
				}, protocol.Encryption1RTT, now.Add(8*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				if injected && extCC.lost != 2 {
					t.Fatalf("injected CC notified twice after spurious loss: lost=%d", extCC.lost)
				}
				if !injected && nativeCC.lost != 2 {
					t.Fatalf("native CC notified twice after spurious loss: lost=%d", nativeCC.lost)
				}
			})
		}
	})

	t.Run("pto-retired-ce-with-bypass-ack", func(t *testing.T) {
		for _, injected := range []bool{false, true} {
			name := "native"
			if injected {
				name = "injected"
			}
			t.Run(name, func(t *testing.T) {
				h, nativeCC := newBypassHandler(t, true)
				tracker := h.ecnTracker.(*ecnTracker)
				var extCC *injectedExtendedSender
				if injected {
					extCC = &injectedExtendedSender{}
					h.SetCongestionControl(extCC)
				}
				now := monotime.Now()

				// Confirm ECN capability with a realistic 1ms RTT and 25ms max_ack_delay,
				// where 1-RTT PTO(true) (~27ms) exceeds 3*PTO(false) (~6ms).
				h.rttStats.SetMaxAckDelay(25 * time.Millisecond)
				h.handshakeConfirmed = true
				pInit := sendBypassTestPacket(h, now, false)
				_, err := h.ReceivedAck(&wire.AckFrame{
					AckRanges: ackRangesFor(pInit),
					ECT0:      1,
				}, protocol.Encryption1RTT, now.Add(time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				if tracker.state != ecnStateCapable {
					t.Fatalf("expected capable ECN state, got %d", tracker.state)
				}
				initialCwnd := nativeCC.GetCongestionWindow()

				// Send two controlled packets and fire the real 1-RTT PTO timer.
				// Retire the first packet immediately on PTO (probe #1), then simulate
				// a delayed second probe retirement (+90ms, exceeding 3*PTO(true) from
				// the PTO trigger time) when the send queue drains later.
				sendTime := now.Add(2 * time.Millisecond)
				_ = sendBypassTestPacket(h, sendTime, false)
				pN := sendBypassTestPacket(h, sendTime, false)
				ptoTime := h.GetLossDetectionTimeout()
				if ptoTime.IsZero() || ptoTime.Sub(sendTime) < 25*time.Millisecond {
					t.Fatalf("expected 1-RTT PTO >= 25ms after sendTime, got %v", ptoTime.Sub(sendTime))
				}
				if err := h.OnLossDetectionTimeout(ptoTime); err != nil {
					t.Fatal(err)
				}
				if !h.QueueProbePacket(protocol.PacketNumberSpaceAppData, ptoTime) {
					t.Fatal("expected first controlled packet to be retired for probe #1")
				}
				delayedRetireTime := ptoTime.Add(90 * time.Millisecond)
				if !h.QueueProbePacket(protocol.PacketNumberSpaceAppData, delayedRetireTime) {
					t.Fatal("expected second controlled packet to be retired for delayed probe #2")
				}
				if injected && extCC.lost != 0 {
					t.Fatalf("PTO probe unexpectedly reported congestion loss to injected CC: lost=%d", extCC.lost)
				}
				if !injected && (nativeCC.lost != 0 || nativeCC.GetCongestionWindow() != initialCwnd) {
					t.Fatalf("PTO probe unexpectedly reported congestion loss to native CC: lost=%d cwnd=%d initial=%d", nativeCC.lost, nativeCC.GetCongestionWindow(), initialCwnd)
				}

				// Send probe #2 at delayedRetireTime and receive a probe-only ACK first;
				// this must NOT prematurely prune pN's ECN attribution even though
				// delayedRetireTime - ptoTime (90ms) > 3*PTO(true) (~82.5ms).
				pProbe := sendBypassTestPacket(h, delayedRetireTime, false)
				_, err = h.ReceivedAck(&wire.AckFrame{
					AckRanges: ackRangesFor(pProbe),
					ECT0:      2,
				}, protocol.Encryption1RTT, delayedRetireTime.Add(time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				if injected && extCC.lost != 0 {
					t.Fatalf("probe-only ACK unexpectedly reported congestion to injected CC: lost=%d", extCC.lost)
				}
				if !injected && nativeCC.lost != 0 {
					t.Fatalf("probe-only ACK unexpectedly reported congestion to native CC: lost=%d", nativeCC.lost)
				}

				// Send a bypass packet pB1; peer ACKs both pN (CE-marked) and pB1,
				// advancing largestAcked and committing CE=1 while only pB1 remains in history.
				pB1 := sendBypassTestPacket(h, delayedRetireTime.Add(2*time.Millisecond), true)
				_, err = h.ReceivedAck(&wire.AckFrame{
					AckRanges: ackRangesFor(pN, pB1),
					ECT0:      2,
					ECNCE:     1,
				}, protocol.Encryption1RTT, delayedRetireTime.Add(3*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				if injected {
					if extCC.lost != 1 {
						t.Fatalf("injected CC missed CE for PTO-retired packet: lost=%d, want 1", extCC.lost)
					}
				} else {
					if nativeCC.lost != 1 || nativeCC.lastCongestionPN != pN || nativeCC.GetCongestionWindow() >= initialCwnd {
						t.Fatalf("native CC missed CE for PTO-retired packet: lost=%d pn=%d cwnd=%d initial=%d", nativeCC.lost, nativeCC.lastCongestionPN, nativeCC.GetCongestionWindow(), initialCwnd)
					}
				}

				// A subsequent bypass-only ACK with unchanged CE count must not notify again.
				pB2 := sendBypassTestPacket(h, delayedRetireTime.Add(4*time.Millisecond), true)
				_, err = h.ReceivedAck(&wire.AckFrame{
					AckRanges: ackRangesFor(pB2),
					ECT0:      2,
					ECNCE:     1,
				}, protocol.Encryption1RTT, delayedRetireTime.Add(5*time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
				if injected && extCC.lost != 1 {
					t.Fatalf("injected CC notified twice after PTO CE: lost=%d", extCC.lost)
				}
				if !injected && nativeCC.lost != 1 {
					t.Fatalf("native CC notified twice after PTO CE: lost=%d", nativeCC.lost)
				}
			})
		}
	})
}
