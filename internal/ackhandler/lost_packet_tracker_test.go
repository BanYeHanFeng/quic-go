package ackhandler

import (
	"testing"
	"time"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/qlog"
)

// TestLostPacketTrackerKeepsTrigger covers the data a spurious loss needs to be
// attributed: reporting that the detector was wrong is not enough, the trace
// has to say which detector it was.
func TestLostPacketTrackerKeepsTrigger(t *testing.T) {
	tracker := newLostPacketTracker(64)
	now := monotime.Now()
	tracker.Add(4, now, qlog.PacketLossTimeThreshold)
	tracker.Add(5, now.Add(time.Millisecond), qlog.PacketLossReorderingThreshold)

	triggers := make(map[protocol.PacketNumber]qlog.PacketLossReason)
	for pn, lost := range tracker.All() {
		triggers[pn] = lost.Trigger
		if lost.PacketNumber != pn {
			t.Fatalf("tracker reported packet %d under packet number %d", lost.PacketNumber, pn)
		}
	}
	if triggers[4] != qlog.PacketLossTimeThreshold {
		t.Errorf("packet 4 has trigger %q, want %q", triggers[4], qlog.PacketLossTimeThreshold)
	}
	if triggers[5] != qlog.PacketLossReorderingThreshold {
		t.Errorf("packet 5 has trigger %q, want %q", triggers[5], qlog.PacketLossReorderingThreshold)
	}
}

// TestLostPacketTrackerDropsOldestPackets keeps the bounded history honest: the
// tracker only remembers the most recent losses, so a test which relies on the
// oldest one surviving would be wrong.
func TestLostPacketTrackerDropsOldestPackets(t *testing.T) {
	tracker := newLostPacketTracker(2)
	now := monotime.Now()
	tracker.Add(1, now, qlog.PacketLossTimeThreshold)
	tracker.Add(2, now, qlog.PacketLossTimeThreshold)
	tracker.Add(3, now, qlog.PacketLossReorderingThreshold)

	var packetNumbers []protocol.PacketNumber
	for pn := range tracker.All() {
		packetNumbers = append(packetNumbers, pn)
	}
	if len(packetNumbers) != 2 || packetNumbers[0] != 2 || packetNumbers[1] != 3 {
		t.Fatalf("tracker kept packets %v, want [2 3]", packetNumbers)
	}
}
