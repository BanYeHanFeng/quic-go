package qlog

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/qlogwriter"
	"github.com/sagernet/quic-go/qlogwriter/jsontext"
)

func encodeEvent(t *testing.T, event qlogwriter.Event) string {
	t.Helper()
	var buffer bytes.Buffer
	if err := event.Encode(jsontext.NewEncoder(&buffer), time.Now()); err != nil {
		t.Fatalf("encoding %s failed: %v", event.Name(), err)
	}
	return buffer.String()
}

// TestPacketLostEncodesAckEliciting covers the field which keeps the two lost
// packet populations apart. The trace is read as JSON by the analysis, so the
// field has to be there for both values, not only for the interesting one.
func TestPacketLostEncodesAckEliciting(t *testing.T) {
	for _, ackEliciting := range []bool{true, false} {
		encoded := encodeEvent(t, PacketLost{
			Header:       PacketHeader{PacketType: PacketType1RTT, PacketNumber: 7},
			Trigger:      PacketLossTimeThreshold,
			AckEliciting: ackEliciting,
		})
		want := `"ack_eliciting":` + strconv.FormatBool(ackEliciting)
		if !strings.Contains(encoded, want) {
			t.Errorf("packet_lost %s does not contain %s", encoded, want)
		}
		if !strings.Contains(encoded, `"trigger":"time_threshold"`) {
			t.Errorf("packet_lost %s lost its trigger", encoded)
		}
	}
}

// TestLossTimerUpdatedEncodesOutstandingPackets covers the packet numbers of a
// PTO expiry: they are what makes a loss which was never declared visible, so
// the array has to be encoded exactly when it is known.
func TestLossTimerUpdatedEncodesOutstandingPackets(t *testing.T) {
	encoded := encodeEvent(t, LossTimerUpdated{
		Type:               LossTimerUpdateTypeExpired,
		TimerType:          TimerTypePTO,
		EncLevel:           protocol.Encryption1RTT,
		OutstandingPackets: []protocol.PacketNumber{3, 4},
	})
	if !strings.Contains(encoded, `"outstanding_packets":[3,4]`) {
		t.Errorf("loss_timer_updated %s does not report the outstanding packets", encoded)
	}

	// A timer which expires in loss-time mode declares those packets lost
	// right away, and then carries no list.
	encoded = encodeEvent(t, LossTimerUpdated{
		Type:      LossTimerUpdateTypeExpired,
		TimerType: TimerTypeACK,
		EncLevel:  protocol.Encryption1RTT,
	})
	if strings.Contains(encoded, `"outstanding_packets"`) {
		t.Errorf("loss_timer_updated %s reports outstanding packets it does not have", encoded)
	}
}
