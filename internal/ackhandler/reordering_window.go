package ackhandler

import (
	"time"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
)

const (
	// maxReorderingWindow bounds the adaptive packet threshold. The reordering a
	// mobile path shows has a long tail (the measurements this adapts to reach
	// 60 packets), but an ACK which was itself lost makes a spurious loss report
	// an arbitrarily large distance, and a threshold that large would move all
	// loss detection onto the time threshold.
	maxReorderingWindow = 64
	// reorderingWindowDecay is how long a raised threshold survives without new
	// evidence. The excess over packetThreshold halves every interval, so a
	// window raised by a one-off event (a handover, say) returns to the RFC 9002
	// value within a few minutes instead of lasting for the whole connection.
	reorderingWindowDecay = 5 * time.Minute
)

// reorderingWindow is the packet threshold used by packet threshold loss
// detection, adapted to the reordering the path actually shows.
//
// RFC 9002 fixes the packet threshold at 3, which assumes that a packet is lost
// once three later packets have been acknowledged. A path which reorders more
// than that turns such a declaration into a false positive: the packet was only
// late, but it has already spent a retransmission and has been reported to the
// congestion controller as lost. Measurements on a phone <-> VPS QUICX tunnel
// found reordering of 5 to 50 packets and spurious loss rates of up to 98.8%
// for this detector.
//
// A spurious loss is the only direct evidence a sender has about how far a path
// reorders, so the window is raised to one more than the largest reordering a
// spurious loss proves. A larger threshold is never wrong in the sense of
// declaring a late packet lost; it only delays the detection of packets which
// are really gone, and those are still caught by the time threshold.
type reorderingWindow struct {
	// threshold is the packet threshold currently in use.
	threshold protocol.PacketNumber
	// decayedAt is when the excess over packetThreshold was last halved. It also
	// keeps the zero value meaningful: it is only set once the window is raised.
	decayedAt monotime.Time
}

func newReorderingWindow() reorderingWindow {
	return reorderingWindow{threshold: packetThreshold}
}

// Threshold returns the packet threshold to use at now, applying the decay of
// the excess over packetThreshold. It reports whether the decay changed the
// threshold, which is what the qlog trace records.
func (w *reorderingWindow) Threshold(now monotime.Time) (protocol.PacketNumber, bool) {
	if w.threshold <= packetThreshold || w.decayedAt.IsZero() {
		return w.threshold, false
	}
	steps := int(now.Sub(w.decayedAt) / reorderingWindowDecay)
	if steps <= 0 {
		return w.threshold, false
	}
	excess := w.threshold - packetThreshold
	for i := 0; i < steps && excess > 0; i++ {
		excess /= 2
	}
	w.threshold = packetThreshold + excess
	w.decayedAt = now
	return w.threshold, true
}

// Observe feeds the reordering distance of a spurious loss back into the
// window. The packet would not have been declared lost if the threshold had
// been larger than the distance, hence the +1. It returns the resulting
// threshold and reports whether it changed.
func (w *reorderingWindow) Observe(now monotime.Time, observed protocol.PacketNumber) (protocol.PacketNumber, bool) {
	current, _ := w.Threshold(now)
	wanted := min(observed+1, protocol.PacketNumber(maxReorderingWindow))
	if wanted <= current {
		return current, false
	}
	w.threshold = wanted
	w.decayedAt = now
	return wanted, true
}
