package ackhandler

import (
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
	congestion.SendAlgorithmWithDebugInfos
	sent, acked, lost int
	blocked, pacing   bool
}

func (c *recordingSender) CanSend(n protocol.ByteCount) bool {
	return !c.blocked && c.SendAlgorithmWithDebugInfos.CanSend(n)
}

func (c *recordingSender) HasPacingBudget(t monotime.Time) bool {
	return !c.pacing && c.SendAlgorithmWithDebugInfos.HasPacingBudget(t)
}

func (c *recordingSender) OnPacketSent(t monotime.Time, n protocol.ByteCount, pn protocol.PacketNumber, size protocol.ByteCount, ack bool) {
	c.sent++
	c.SendAlgorithmWithDebugInfos.OnPacketSent(t, n, pn, size, ack)
}

func (c *recordingSender) OnPacketAcked(pn protocol.PacketNumber, size, flight protocol.ByteCount, t monotime.Time) {
	c.acked++
	c.SendAlgorithmWithDebugInfos.OnPacketAcked(pn, size, flight, t)
}

func (c *recordingSender) OnCongestionEvent(pn protocol.PacketNumber, size, flight protocol.ByteCount) {
	c.lost++
	c.SendAlgorithmWithDebugInfos.OnCongestionEvent(pn, size, flight)
}

func newBypassHandler(t *testing.T) (*sentPacketHandler, *recordingSender) {
	t.Helper()
	rtt := &utils.RTTStats{}
	rtt.SetInitialRTT(20 * time.Millisecond)
	h := NewSentPacketHandler(0, 1280, rtt, &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, false, true, nil, utils.DefaultLogger).(*sentPacketHandler)
	h.handshakeConfirmed = true
	h.peerCompletedAddressValidation = true
	h.initialPackets = nil
	h.handshakePackets = nil
	cc := &recordingSender{SendAlgorithmWithDebugInfos: h.congestion.SendAlgorithmWithDebugInfos}
	h.congestion.SendAlgorithmWithDebugInfos = cc
	return h, cc
}

func sendBypassTestPacket(h *sentPacketHandler, now monotime.Time, bypass bool) protocol.PacketNumber {
	pn := h.PopPacketNumber(protocol.Encryption1RTT)
	h.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.DatagramFrame{Data: make([]byte, 100)}}}, protocol.Encryption1RTT, protocol.ECNNon, 120, false, false, bypass)
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
	h, cc := newBypassHandler(t)
	now := monotime.Now()
	normal := sendBypassTestPacket(h, now, false)
	bypass := sendBypassTestPacket(h, now, true)
	if h.bytesInFlight != 120 || cc.sent != 1 {
		t.Fatalf("flight=%d sent=%d", h.bytesInFlight, cc.sent)
	}
	ackBypassTestPacket(t, h, bypass, now.Add(time.Millisecond))
	if h.bytesInFlight != 120 || cc.acked != 0 || cc.lost != 0 {
		t.Fatal("bypass ACK reached congestion controller")
	}
	ackBypassTestPacket(t, h, normal, now.Add(2*time.Millisecond))
	if h.bytesInFlight != 0 || cc.acked != 1 {
		t.Fatal("controlled ACK not accounted")
	}
	ackBypassTestPacket(t, h, bypass, now.Add(3*time.Millisecond)) // duplicate ACK
	if cc.acked != 1 {
		t.Fatal("duplicate ACK changed controller")
	}
}

func TestDatagramLossRetainsRecovery(t *testing.T) {
	h, cc := newBypassHandler(t)
	now := monotime.Now()
	sendBypassTestPacket(h, now, true)
	if h.GetLossDetectionTimeout().IsZero() {
		t.Fatal("DATAGRAM-only traffic has no recovery timer")
	}
	if err := h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()); err != nil {
		t.Fatal(err)
	}
	if h.numProbesToSend == 0 {
		t.Fatal("PTO did not request an ACK-eliciting probe")
	}
	if !h.QueueProbePacket(protocol.Encryption1RTT) {
		t.Fatal("lost datagram not retired")
	}
	if h.appDataPackets.history.HasOutstandingPackets() || cc.sent != 0 || cc.lost != 0 {
		t.Fatal("bypass packet changed controller or remained outstanding")
	}
	h.numProbesToSend = 0
	pn := sendBypassTestPacket(h, now.Add(time.Second), true)
	ackBypassTestPacket(t, h, pn, now.Add(time.Second+time.Millisecond))
	if h.bytesInFlight != 0 || cc.acked != 0 {
		t.Fatal("bypass recovery accounting")
	}
}

func TestDatagramLossDoesNotReduceWindow(t *testing.T) {
	h, cc := newBypassHandler(t)
	now := monotime.Now()
	sendBypassTestPacket(h, now, true)
	pn := sendBypassTestPacket(h, now.Add(time.Millisecond), true)
	ackBypassTestPacket(t, h, pn, now.Add(time.Second))
	if cc.sent != 0 || cc.acked != 0 || cc.lost != 0 || h.bytesInFlight != 0 {
		t.Fatal("bypass loss reached congestion controller")
	}
	if err := h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()); err != nil {
		t.Fatal(err)
	}
	if h.appDataPackets.history.HasOutstandingPackets() {
		t.Fatal("lost DATAGRAM not removed")
	}
}

func TestDatagramBypassLimits(t *testing.T) {
	h, cc := newBypassHandler(t)
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
	h.appDataPackets.history.packets = make([]*packet, protocol.MaxOutstandingSentPackets-64)
	if h.CanSendUncongestedDatagram() {
		t.Fatal("resource limit bypassed")
	}
}

func TestNativeAlgorithmSurvivesMigration(t *testing.T) {
	for _, reno := range []bool{false, true} {
		h, _ := newBypassHandler(t)
		h.useReno = reno
		now := monotime.Now()
		h.MigratedPath(now, 1400)
		cc := h.getCongestionControl()
		reference := congestion.NewCubicSender(congestion.DefaultClock{}, h.rttStats, &utils.ConnectionStats{}, 1400, reno, nil)
		cc.OnPacketSent(now, 0, 1, 1400, true)
		reference.OnPacketSent(now, 0, 1, 1400, true)
		cc.OnCongestionEvent(1, 1400, cc.GetCongestionWindow())
		reference.OnCongestionEvent(1, 1400, reference.GetCongestionWindow())
		for pn := protocol.PacketNumber(2); pn < 500; pn++ {
			now = now.Add(time.Millisecond)
			cwnd := cc.GetCongestionWindow()
			cc.OnPacketSent(now, cwnd, pn, 1400, true)
			reference.OnPacketSent(now, cwnd, pn, 1400, true)
			cc.OnPacketAcked(pn, 1400, cwnd, now)
			reference.OnPacketAcked(pn, 1400, cwnd, now)
			if cc.GetCongestionWindow() != reference.GetCongestionWindow() {
				t.Fatalf("reno=%v migration selected wrong controller", reno)
			}
		}
	}
}

type extendedRecordingSender struct {
	*recordingSender
	delivered, lostSamples int
}

func (c *extendedRecordingSender) OnCongestionEventEx(_ protocol.ByteCount, _ monotime.Time, acked []congestionExt.AckedPacketInfo, lost []congestionExt.LostPacketInfo) {
	c.delivered += len(acked)
	c.lostSamples += len(lost)
}
func (*extendedRecordingSender) OnPacketNeutered(protocol.PacketNumber) {}
func (*extendedRecordingSender) OnPacketsLost(protocol.PacketNumber)    {}
func (*extendedRecordingSender) OnAppLimited(protocol.ByteCount)        {}
func TestDatagramBypassExtendedSampler(t *testing.T) {
	h, base := newBypassHandler(t)
	cc := &extendedRecordingSender{recordingSender: base}
	h.congestion = congestionControl{SendAlgorithmWithDebugInfos: cc, extended: cc, injected: true}
	now := monotime.Now()
	sendBypassTestPacket(h, now, true)
	pn := sendBypassTestPacket(h, now, true)
	ackBypassTestPacket(t, h, pn, now.Add(time.Millisecond))
	if err := h.OnLossDetectionTimeout(h.GetLossDetectionTimeout()); err != nil {
		t.Fatal(err)
	}
	if cc.delivered != 0 || cc.lostSamples != 0 || cc.sent != 0 || cc.lost != 0 {
		t.Fatal("exempt data reached bandwidth sampler")
	}
	normal := sendBypassTestPacket(h, now.Add(time.Second), false)
	ackBypassTestPacket(t, h, normal, now.Add(time.Second+time.Millisecond))
	if cc.delivered != 1 || cc.sent != 1 {
		t.Fatal("controlled sample missing")
	}
}
