package ackhandler

import (
	"testing"

	"github.com/sagernet/quic-go/internal/monotime"
)

func trackedPacket() *packet {
	return &packet{SendTime: monotime.Now(), Frames: []Frame{{}}}
}

// TestSentPacketHistoryOutstandingPackets covers the packet numbers reported
// when a PTO expires: only packets which are actually outstanding (lost
// packets are removed from the history) and not ACK-only may be listed, since
// the list is what makes a loss that was never declared visible.
func TestSentPacketHistoryOutstandingPackets(t *testing.T) {
	history := newSentPacketHistory(true)
	history.SentPacket(0, trackedPacket())
	history.SentPacket(1, trackedPacket())
	// An ACK-only packet is not outstanding: its loss triggers no
	// retransmission and no congestion event.
	history.SentPacket(2, &packet{SendTime: monotime.Now()})

	packets := history.OutstandingPackets()
	if len(packets) != 2 || packets[0] != 0 || packets[1] != 1 {
		t.Fatalf("outstanding packets %v, want [0 1]", packets)
	}

	history.DeclareLost(0)
	packets = history.OutstandingPackets()
	if len(packets) != 1 || packets[0] != 1 {
		t.Fatalf("outstanding packets %v after declaring 0 lost, want [1]", packets)
	}

	history.Remove(1)
	if packets = history.OutstandingPackets(); len(packets) != 0 {
		t.Fatalf("outstanding packets %v after removing 1, want none", packets)
	}
}
