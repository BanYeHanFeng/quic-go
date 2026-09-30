package congestion

import (
	"testing"
	"time"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
)

func TestNativePacerUsesInitialPacketSize(t *testing.T) {
	for _, size := range []protocol.ByteCount{1200, 1280, 1400} {
		rtt := &utils.RTTStats{}
		rtt.SetInitialRTT(time.Second)
		c := NewCubicSender(DefaultClock{}, rtt, &utils.ConnectionStats{}, size, true, nil)
		now := monotime.Now()
		for i := range maxBurstSizePackets {
			if !c.HasPacingBudget(now) {
				t.Fatalf("size=%d exhausted pacing budget at packet %d", size, i)
			}
			c.OnPacketSent(now, 0, protocol.PacketNumber(i), size, true)
		}
		if c.HasPacingBudget(now) {
			t.Fatalf("size=%d initial burst exceeds %d packets", size, maxBurstSizePackets)
		}
	}
}
