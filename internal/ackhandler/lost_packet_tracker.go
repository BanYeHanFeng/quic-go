package ackhandler

import (
	"iter"
	"slices"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/qlog"
)

type lostPacket struct {
	PacketNumber protocol.PacketNumber
	SendTime     monotime.Time
	// Trigger is the loss detection which declared this packet lost. It is
	// kept with the packet so a spurious loss can be attributed to the
	// detector which produced it, not just counted.
	Trigger qlog.PacketLossReason
}

type lostPacketTracker struct {
	maxLength   int
	lostPackets []lostPacket
}

func newLostPacketTracker(maxLength int) *lostPacketTracker {
	return &lostPacketTracker{
		maxLength: maxLength,
		// Preallocate a small slice only.
		// Hopefully we won't lose many packets.
		lostPackets: make([]lostPacket, 0, 4),
	}
}

func (t *lostPacketTracker) Add(p protocol.PacketNumber, sendTime monotime.Time, trigger qlog.PacketLossReason) {
	if len(t.lostPackets) == t.maxLength {
		t.lostPackets = t.lostPackets[1:]
	}
	t.lostPackets = append(t.lostPackets, lostPacket{
		PacketNumber: p,
		SendTime:     sendTime,
		Trigger:      trigger,
	})
}

// Delete deletes a packet from the lost packet tracker.
// This function is not optimized for performance if many packets are lost,
// but it is only used when a spurious loss is detected, which is rare.
func (t *lostPacketTracker) Delete(pn protocol.PacketNumber) {
	t.lostPackets = slices.DeleteFunc(t.lostPackets, func(p lostPacket) bool {
		return p.PacketNumber == pn
	})
}

func (t *lostPacketTracker) All() iter.Seq2[protocol.PacketNumber, lostPacket] {
	return func(yield func(protocol.PacketNumber, lostPacket) bool) {
		for _, p := range t.lostPackets {
			if !yield(p.PacketNumber, p) {
				return
			}
		}
	}
}

func (t *lostPacketTracker) DeleteBefore(ti monotime.Time) {
	if len(t.lostPackets) == 0 {
		return
	}
	if !t.lostPackets[0].SendTime.Before(ti) {
		return
	}
	var idx int
	for ; idx < len(t.lostPackets); idx++ {
		if !t.lostPackets[idx].SendTime.Before(ti) {
			break
		}
	}
	t.lostPackets = slices.Delete(t.lostPackets, 0, idx)
}
