package ackhandler

import (
	"testing"
	"time"

	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
)

func newLossDelayTestHandler(rtt time.Duration, peerMaxAckDelay time.Duration) *sentPacketHandler {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(rtt, 0)
	rttStats.SetMaxAckDelay(peerMaxAckDelay)
	return &sentPacketHandler{rttStats: rttStats}
}

// TestPacketLossDelayAddsPeerMaxAckDelay pins the fix for the time-threshold
// spurious losses: the RTT samples are corrected for the peer's ACK delay, so
// the loss delay has to carry it, or the sender declares a packet lost while
// its ACK is still waiting at the peer.
func TestPacketLossDelayAddsPeerMaxAckDelay(t *testing.T) {
	const rtt = 50 * time.Millisecond
	base := time.Duration(timeThreshold * float64(rtt))

	handler := newLossDelayTestHandler(rtt, 0)
	if got := handler.packetLossDelay(protocol.Encryption1RTT); got != base {
		t.Fatalf("loss delay without a peer max_ack_delay is %s, want %s", got, base)
	}

	const maxAckDelay = 26 * time.Millisecond
	handler = newLossDelayTestHandler(rtt, maxAckDelay)
	if got := handler.packetLossDelay(protocol.Encryption1RTT); got != base+maxAckDelay {
		t.Fatalf("loss delay with a peer max_ack_delay is %s, want %s", got, base+maxAckDelay)
	}
}

// TestPacketLossDelayIgnoresMaxAckDelayBefore1RTT keeps the handshake on the
// RFC 9002 timing: the ACK Delay field is only meaningful in 1-RTT, and a
// receiver must not delay the ACKs of Initial or Handshake packets.
func TestPacketLossDelayIgnoresMaxAckDelayBefore1RTT(t *testing.T) {
	const rtt = 50 * time.Millisecond
	want := time.Duration(timeThreshold * float64(rtt))
	handler := newLossDelayTestHandler(rtt, 26*time.Millisecond)
	for _, encLevel := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake} {
		if got := handler.packetLossDelay(encLevel); got != want {
			t.Fatalf("loss delay at encryption level %d is %s, want %s", encLevel, got, want)
		}
	}
}

// TestPacketLossDelayClampsPeerMaxAckDelayToRTT bounds the addition: a peer may
// advertise a max_ack_delay of up to 2^14 ms, and loss detection must not be
// moved that far out by it.
func TestPacketLossDelayClampsPeerMaxAckDelayToRTT(t *testing.T) {
	const rtt = 50 * time.Millisecond
	handler := newLossDelayTestHandler(rtt, 5*time.Second)
	want := time.Duration(timeThreshold*float64(rtt)) + rtt
	if got := handler.packetLossDelay(protocol.Encryption1RTT); got != want {
		t.Fatalf("clamped loss delay is %s, want %s", got, want)
	}
}

// TestPacketLossDelayKeepsTimerGranularity keeps the floor for a path whose RTT
// is below the timer granularity.
func TestPacketLossDelayKeepsTimerGranularity(t *testing.T) {
	handler := newLossDelayTestHandler(100*time.Microsecond, 0)
	if got := handler.packetLossDelay(protocol.Encryption1RTT); got != protocol.TimerGranularity {
		t.Fatalf("loss delay on a sub-granularity RTT is %s, want %s", got, protocol.TimerGranularity)
	}
}
