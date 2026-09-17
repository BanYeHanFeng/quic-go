package ackhandler

import (
	"testing"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/wire"
)

// TestFECRecoveredPacketsCutCongestionWindow verifies that the built-in congestion
// controller treats FEC-recovered packets as the loss of the path. The packets were
// already acknowledged, so nothing is retransmitted here; the window is what reacts.
func TestFECRecoveredPacketsCutCongestionWindow(t *testing.T) {
	rttStats := utils.NewRTTStats()
	connStats := &utils.ConnectionStats{}
	handler := NewSentPacketHandler(0, 1200, rttStats, connStats, false, false, nil, protocol.PerspectiveClient, true, nil, utils.DefaultLogger).(*sentPacketHandler)
	cc := handler.getCongestionControl()
	before := cc.GetCongestionWindow()
	handler.OnFECRecoveredPackets([]wire.FECRecoveredPacket{{PacketNumber: 7, Length: 1200}}, monotime.Now())
	if after := cc.GetCongestionWindow(); after >= before {
		t.Fatalf("congestion window did not react to a FEC-recovered loss: %d -> %d", before, after)
	}
	if lost := connStats.BytesLost.Load(); lost != 1200 {
		t.Fatalf("BytesLost = %d, want 1200", lost)
	}
	// An empty report must not touch the controller.
	before = cc.GetCongestionWindow()
	handler.OnFECRecoveredPackets(nil, monotime.Now())
	if after := cc.GetCongestionWindow(); after != before {
		t.Fatalf("an empty report changed the congestion window: %d -> %d", before, after)
	}
}
