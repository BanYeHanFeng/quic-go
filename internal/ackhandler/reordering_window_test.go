package ackhandler

import (
	"testing"
	"time"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
)

// TestReorderingWindowStartsAtPacketThreshold keeps the adaptive window
// compatible with RFC 9002 until the path gives a reason to leave it.
func TestReorderingWindowStartsAtPacketThreshold(t *testing.T) {
	window := newReorderingWindow()
	threshold, changed := window.Threshold(monotime.Now())
	if threshold != packetThreshold {
		t.Fatalf("initial threshold is %d, want %d", threshold, packetThreshold)
	}
	if changed {
		t.Fatal("the initial threshold reported a change")
	}
}

// TestReorderingWindowIgnoresSmallReordering covers the observations which say
// nothing about the threshold: only a reordering which reaches it does, and
// reaching it is exactly what made the packet look lost.
func TestReorderingWindowIgnoresSmallReordering(t *testing.T) {
	window := newReorderingWindow()
	now := monotime.Now()
	for _, observed := range []protocol.PacketNumber{0, 1, packetThreshold - 2, packetThreshold - 1} {
		threshold, changed := window.Observe(now, observed)
		if changed || threshold != packetThreshold {
			t.Fatalf("reordering of %d changed the threshold to %d (changed=%t), want %d unchanged",
				observed, threshold, changed, packetThreshold)
		}
	}
	// A packet overtaken by exactly packetThreshold packets was declared lost by
	// the current threshold, so the window has to move past that distance.
	if threshold, changed := window.Observe(now, packetThreshold); !changed || threshold != packetThreshold+1 {
		t.Fatalf("reordering of %d changed the threshold to %d (changed=%t), want %d",
			packetThreshold, threshold, changed, packetThreshold+1)
	}
}

// TestReorderingWindowRaisesAndKeepsTheMaximum checks the feedback path itself:
// a spurious loss raises the threshold just above what it observed, and later
// weaker evidence does not lower it again.
func TestReorderingWindowRaisesAndKeepsTheMaximum(t *testing.T) {
	window := newReorderingWindow()
	now := monotime.Now()
	threshold, changed := window.Observe(now, 7)
	if !changed || threshold != 8 {
		t.Fatalf("reordering of 7 raised the threshold to %d (changed=%t), want 8", threshold, changed)
	}
	if threshold, changed = window.Observe(now, 4); changed || threshold != 8 {
		t.Fatalf("reordering of 4 lowered the threshold to %d (changed=%t), want 8 unchanged", threshold, changed)
	}
	if threshold, changed = window.Threshold(now); changed || threshold != 8 {
		t.Fatalf("the threshold decayed early to %d (changed=%t), want 8 unchanged", threshold, changed)
	}
}

// TestReorderingWindowIsCapped keeps a single outlying observation (an ACK
// which was itself lost reports a huge reordering distance) from moving all
// loss detection onto the time threshold.
func TestReorderingWindowIsCapped(t *testing.T) {
	window := newReorderingWindow()
	threshold, changed := window.Observe(monotime.Now(), 100000)
	if !changed || threshold != maxReorderingWindow {
		t.Fatalf("a huge reordering raised the threshold to %d (changed=%t), want %d", threshold, changed, maxReorderingWindow)
	}
}

// TestReorderingWindowDecays proves the window is forgotten again: the excess
// over the RFC threshold halves every interval without new evidence.
func TestReorderingWindowDecays(t *testing.T) {
	window := newReorderingWindow()
	now := monotime.Now()
	if threshold, changed := window.Observe(now, 35); !changed || threshold != 36 {
		t.Fatalf("reordering of 35 raised the threshold to %d, want 36", threshold)
	}
	if threshold, changed := window.Threshold(now.Add(reorderingWindowDecay - time.Millisecond)); changed || threshold != 36 {
		t.Fatalf("the threshold decayed to %d before the interval elapsed (changed=%t), want 36", threshold, changed)
	}
	for _, test := range []struct {
		intervals int
		want      protocol.PacketNumber
	}{
		{1, 19},
		{2, 11},
		{3, 7},
		{4, 5},
		{5, 4},
		{6, packetThreshold},
	} {
		threshold, changed := window.Threshold(now.Add(time.Duration(test.intervals) * reorderingWindowDecay))
		if threshold != test.want {
			t.Fatalf("after %d intervals the threshold is %d, want %d", test.intervals, threshold, test.want)
		}
		if !changed {
			t.Fatalf("after %d intervals the threshold did not report a change", test.intervals)
		}
	}
}
