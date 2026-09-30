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

// TestSpuriousLossEncodesTrigger covers the attribution of a spurious loss. A
// spurious loss recorded without the detector that produced it only says that
// detection was wrong, so the field must not silently disappear.
func TestSpuriousLossEncodesTrigger(t *testing.T) {
	encoded := encodeEvent(t, SpuriousLoss{
		PacketNumber:     9,
		PacketReordering: 4,
		TimeReordering:   12 * time.Millisecond,
		Trigger:          PacketLossReorderingThreshold,
	})
	if !strings.Contains(encoded, `"trigger":"reordering_threshold"`) {
		t.Errorf("spurious_loss %s does not report its trigger", encoded)
	}

	// A loss recorded before this field existed has no trigger, and the event
	// has to stay valid (and unchanged) in that case.
	encoded = encodeEvent(t, SpuriousLoss{PacketNumber: 9})
	if strings.Contains(encoded, `"trigger"`) {
		t.Errorf("spurious_loss %s reports a trigger it does not have", encoded)
	}
}

// TestReorderingWindowUpdatedEncodesThreshold covers the event which makes an
// adapted packet threshold visible. Without it, the only trace of the adaptation
// is that losses stop being reported, which is indistinguishable from a path
// that stopped losing packets.
func TestReorderingWindowUpdatedEncodesThreshold(t *testing.T) {
	encoded := encodeEvent(t, ReorderingWindowUpdated{
		PacketThreshold:    9,
		ObservedReordering: 8,
	})
	if !strings.Contains(encoded, `"packet_threshold":9`) {
		t.Errorf("reordering_window_updated %s does not report the threshold", encoded)
	}
	if !strings.Contains(encoded, `"observed_reordering":8`) {
		t.Errorf("reordering_window_updated %s does not report the observation", encoded)
	}

	// A decay has no observation to report, and readers have to be able to rely
	// on the field being present.
	encoded = encodeEvent(t, ReorderingWindowUpdated{PacketThreshold: 6})
	if !strings.Contains(encoded, `"observed_reordering":0`) {
		t.Errorf("reordering_window_updated %s does not report a zero observation", encoded)
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

// TestLossTimerCancelledEncodesAttribution covers the cancellation of a timer.
// A cancelled timer has no time and no outstanding packets, so its timer type
// and packet number space are the only thing which says what was cancelled:
// without them a PTO cancellation is indistinguishable from the cancellation of
// a loss-time timer.
func TestLossTimerCancelledEncodesAttribution(t *testing.T) {
	encoded := encodeEvent(t, LossTimerUpdated{
		Type:      LossTimerUpdateTypeCancelled,
		TimerType: TimerTypePTO,
		EncLevel:  protocol.EncryptionHandshake,
	})
	if !strings.Contains(encoded, `"event_type":"cancelled"`) {
		t.Errorf("loss_timer_updated %s does not report the cancellation", encoded)
	}
	if !strings.Contains(encoded, `"timer_type":"pto"`) {
		t.Errorf("loss_timer_updated %s does not report which timer was cancelled", encoded)
	}
	if !strings.Contains(encoded, `"packet_number_space":"handshake"`) {
		t.Errorf("loss_timer_updated %s does not report the packet number space of the cancelled timer", encoded)
	}
	// The fields are omitted instead of encoded empty when the timer did not
	// know them: an empty attribution is what made the field useless.
	encoded = encodeEvent(t, LossTimerUpdated{Type: LossTimerUpdateTypeCancelled})
	if strings.Contains(encoded, `"timer_type"`) || strings.Contains(encoded, `"packet_number_space"`) {
		t.Errorf("loss_timer_updated %s invents an attribution it does not have", encoded)
	}
}
