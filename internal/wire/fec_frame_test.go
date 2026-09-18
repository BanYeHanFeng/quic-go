package wire

import (
	"bytes"
	"testing"

	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/quicvarint"
)

func TestFECFeedbackFrameRoundTrip(t *testing.T) {
	frame := &FECFeedbackFrame{
		ReceivedPackets:  1234,
		LostPackets:      17,
		RecoveredPackets: 12,
		FailedPackets:    3,
		ParityPackets:    99,
	}
	data, err := frame.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Length(protocol.Version1) != protocol.ByteCount(len(data)) {
		t.Fatalf("length mismatch: %d vs %d", frame.Length(protocol.Version1), len(data))
	}
	parsed, n, err := parseFECFeedbackFrame(data[1:], protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data)-1 {
		t.Fatalf("expected to consume %d bytes, consumed %d", len(data)-1, n)
	}
	if *parsed != *frame {
		t.Fatalf("unexpected frame: %+v", parsed)
	}
}

func TestFECFrameTypesAccepted(t *testing.T) {
	parser := NewFrameParser(false, false, false)
	for _, frameType := range []FrameType{FrameTypeFECFeedback, FrameTypeFECFeedbackV2, FrameTypeFECWindowRepair, FrameTypeFECWindowRepairMulti, FrameTypeFECRecovered} {
		typ, _, err := parser.ParseType([]byte{byte(frameType)}, protocol.Encryption1RTT)
		if err != nil {
			t.Fatalf("frame type %#x rejected at 1-RTT: %v", frameType, err)
		}
		if typ != frameType {
			t.Fatalf("unexpected frame type: %#x", typ)
		}
		if _, _, err := parser.ParseType([]byte{byte(frameType)}, protocol.Encryption0RTT); err == nil {
			t.Fatalf("frame type %#x accepted at 0-RTT", frameType)
		}
	}
}

func TestFECWindowRepairFrameRoundTrip(t *testing.T) {
	for _, memberCount := range []int{2, 3, 8, 64, MaxFECWindowSize} {
		frame := &FECWindowRepairFrame{
			Row:               1234,
			FirstPacketNumber: 5000,
			// The members sit on every other packet number, so the bitmap has to skip
			// the packet numbers the parity packets spent.
			Span:         uint64(2*memberCount - 1),
			ParityLength: 1200,
			LengthParity: [2]byte{0x12, 0x34},
			Parity:       bytes.Repeat([]byte{0x5a}, 1200),
		}
		for i := 0; i < memberCount; i++ {
			frame.PacketNumbers = append(frame.PacketNumbers, protocol.PacketNumber(5000+i*2))
		}
		data, err := frame.Append(nil, protocol.Version1)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Length(protocol.Version1) != protocol.ByteCount(len(data)) {
			t.Fatalf("%d members: length mismatch: %d vs %d", memberCount, frame.Length(protocol.Version1), len(data))
		}
		parsed, n, err := parseFECWindowRepairFrame(data[1:], protocol.Version1)
		if err != nil {
			t.Fatalf("%d members: %v", memberCount, err)
		}
		if n != len(data)-1 {
			t.Fatalf("%d members: expected to consume %d bytes, consumed %d", memberCount, len(data)-1, n)
		}
		if parsed.Row != frame.Row || parsed.FirstPacketNumber != frame.FirstPacketNumber || parsed.Span != frame.Span {
			t.Fatalf("unexpected row/first/span: %+v", parsed)
		}
		if parsed.ParityLength != frame.ParityLength || parsed.LengthParity != frame.LengthParity {
			t.Fatalf("unexpected parity length / length parity: %+v", parsed)
		}
		if len(parsed.PacketNumbers) != len(frame.PacketNumbers) {
			t.Fatalf("unexpected packet numbers: %v", parsed.PacketNumbers)
		}
		for i := range frame.PacketNumbers {
			if parsed.PacketNumbers[i] != frame.PacketNumbers[i] {
				t.Fatalf("unexpected packet number at index %d: %d", i, parsed.PacketNumbers[i])
			}
		}
		if !bytes.Equal(parsed.Parity, frame.Parity) {
			t.Fatal("parity mismatch")
		}
		reencoded, err := parsed.Append(nil, protocol.Version1)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(reencoded, data) {
			t.Fatalf("%d members: re-encoded frame differs", memberCount)
		}
	}
}

func TestFECWindowRepairFrameTruncated(t *testing.T) {
	frame := &FECWindowRepairFrame{
		Row:               3,
		FirstPacketNumber: 100,
		Span:              9,
		PacketNumbers:     []protocol.PacketNumber{100, 101, 103, 108},
		ParityLength:      64,
		LengthParity:      [2]byte{1, 2},
		Parity:            bytes.Repeat([]byte{0x7f}, 64),
	}
	data, err := frame.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(data)-1; i++ {
		if _, _, err := parseFECWindowRepairFrame(data[1:i], protocol.Version1); err == nil {
			t.Fatalf("expected an error for a frame truncated to %d bytes", i)
		}
	}
}

func TestFECWindowRepairFrameInvalid(t *testing.T) {
	valid := &FECWindowRepairFrame{
		Row:               0,
		FirstPacketNumber: 10,
		Span:              5,
		PacketNumbers:     []protocol.PacketNumber{10, 12, 14},
		ParityLength:      22,
		LengthParity:      [2]byte{3, 4},
		Parity:            bytes.Repeat([]byte{0x11}, 22),
	}
	data, err := valid.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseFECWindowRepairFrame(data[1:], protocol.Version1); err != nil {
		t.Fatal(err)
	}
	// a span the bitmap can't describe
	invalid := *valid
	invalid.Span = MaxFECWindowSpan + 1
	invalidData, err := invalid.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseFECWindowRepairFrame(invalidData[1:], protocol.Version1); err == nil {
		t.Fatal("expected an error for a span that is too large")
	}
	// the member count doesn't match the bitmap
	malformed := []byte{
		byte(FrameTypeFECWindowRepair),
		0,          // row
		10,         // first packet number
		5,          // span
		0b00010101, // bitmap: the packet numbers 10, 12 and 14
		2,          // member count: wrong, the bitmap has three bits set
		22,         // parity length
		3, 4,       // length parity
	}
	malformed = append(malformed, bytes.Repeat([]byte{0x11}, 22)...)
	if _, _, err := parseFECWindowRepairFrame(malformed[1:], protocol.Version1); err == nil {
		t.Fatal("expected an error for a bitmap that doesn't match the member count")
	}
	// a single protected packet is invalid
	invalid = *valid
	invalid.PacketNumbers = []protocol.PacketNumber{10}
	invalidData, err = invalid.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseFECWindowRepairFrame(invalidData[1:], protocol.Version1); err == nil {
		t.Fatal("expected an error for a single protected packet")
	}
}

func TestFECRecoveredFrameRoundTrip(t *testing.T) {
	for _, packets := range [][]FECRecoveredPacket{
		nil,
		{{PacketNumber: 42, Length: 1200}},
		{
			{PacketNumber: 100, Length: 1200},
			{PacketNumber: 102, Length: 60},
			{PacketNumber: 200, Length: 33},
			{PacketNumber: 1000, Length: 1452},
		},
	} {
		frame := &FECRecoveredFrame{Packets: packets}
		data, err := frame.Append(nil, protocol.Version1)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Length(protocol.Version1) != protocol.ByteCount(len(data)) {
			t.Fatalf("%d packets: length mismatch: %d vs %d", len(packets), frame.Length(protocol.Version1), len(data))
		}
		parsed, n, err := parseFECRecoveredFrame(data[1:], protocol.Version1)
		if err != nil {
			t.Fatalf("%d packets: %v", len(packets), err)
		}
		if n != len(data)-1 {
			t.Fatalf("%d packets: expected to consume %d bytes, consumed %d", len(packets), len(data)-1, n)
		}
		if len(parsed.Packets) != len(packets) {
			t.Fatalf("%d packets: parsed %d", len(packets), len(parsed.Packets))
		}
		for i, packet := range packets {
			if parsed.Packets[i] != packet {
				t.Fatalf("%d packets: packet %d = %+v, want %+v", len(packets), i, parsed.Packets[i], packet)
			}
		}
	}
}

func TestFECRecoveredFrameRejectsInvalid(t *testing.T) {
	// count larger than the bound
	data := quicvarint.Append(nil, uint64(maxFECRecoveredFramePackets+1))
	if _, _, err := parseFECRecoveredFrame(data, protocol.Version1); err == nil {
		t.Fatal("an oversized recovered frame was accepted")
	}
	// non-increasing packet numbers
	frame := &FECRecoveredFrame{Packets: []FECRecoveredPacket{
		{PacketNumber: 10, Length: 100},
		{PacketNumber: 10, Length: 100},
	}}
	data, err := frame.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseFECRecoveredFrame(data[1:], protocol.Version1); err == nil {
		t.Fatal("a duplicate recovered packet number was accepted")
	}
	// zero wire length
	frame = &FECRecoveredFrame{Packets: []FECRecoveredPacket{{PacketNumber: 7, Length: 0}}}
	data, err = frame.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseFECRecoveredFrame(data[1:], protocol.Version1); err == nil {
		t.Fatal("a zero length recovered packet was accepted")
	}
}

func TestFECFeedbackV2RoundTrip(t *testing.T) {
frame := &FECFeedbackV2Frame{
ReceivedPackets:  1234,
LostPackets:      17,
RecoveredPackets: 12,
FailedPackets:    3,
ParityPackets:    99,
MissingRanges: []FECFeedbackV2Range{
{FirstPacketNumber: 100, Count: 1},
{FirstPacketNumber: 104, Count: 8},
{FirstPacketNumber: 130, Count: 3},
},
}
data, err := frame.Append(nil, protocol.Version1)
if err != nil {
t.Fatal(err)
}
if frame.Length(protocol.Version1) != protocol.ByteCount(len(data)) {
t.Fatalf("length mismatch: %d vs %d", frame.Length(protocol.Version1), len(data))
}
parsed, n, err := parseFECFeedbackV2Frame(data[1:], protocol.Version1)
if err != nil {
t.Fatal(err)
}
if n != len(data)-1 {
t.Fatalf("expected to consume %d bytes, consumed %d", len(data)-1, n)
}
if parsed.ReceivedPackets != frame.ReceivedPackets ||
parsed.LostPackets != frame.LostPackets ||
parsed.RecoveredPackets != frame.RecoveredPackets ||
parsed.FailedPackets != frame.FailedPackets ||
parsed.ParityPackets != frame.ParityPackets ||
len(parsed.MissingRanges) != len(frame.MissingRanges) {
t.Fatalf("unexpected frame: %+v", parsed)
}
for i := range frame.MissingRanges {
if parsed.MissingRanges[i] != frame.MissingRanges[i] {
t.Fatalf("unexpected range at index %d: %+v", i, parsed.MissingRanges[i])
}
}
reencoded, err := parsed.Append(nil, protocol.Version1)
if err != nil {
t.Fatal(err)
}
if !bytes.Equal(reencoded, data) {
t.Fatal("re-encoded frame differs")
}
}

func TestFECFeedbackV2TruncatedAndMalformed(t *testing.T) {
if _, _, err := parseFECFeedbackV2Frame(nil, protocol.Version1); err == nil {
t.Fatal("expected an error for an empty frame")
}
valid := &FECFeedbackV2Frame{
ReceivedPackets:  1,
MissingRanges:    []FECFeedbackV2Range{{FirstPacketNumber: 7, Count: 3}, {FirstPacketNumber: 12, Count: 1}},
}
data, err := valid.Append(nil, protocol.Version1)
if err != nil {
t.Fatal(err)
}
for i := 1; i < len(data); i++ {
if _, _, err := parseFECFeedbackV2Frame(data[1:i], protocol.Version1); err == nil {
t.Fatalf("truncated frame at %d bytes accepted", i)
}
}
invalid := []FECFeedbackV2Frame{
{MissingRanges: []FECFeedbackV2Range{{FirstPacketNumber: 5, Count: 0}}},
{MissingRanges: []FECFeedbackV2Range{{FirstPacketNumber: 5, Count: 1}, {FirstPacketNumber: 5, Count: 1}}},
{MissingRanges: []FECFeedbackV2Range{{FirstPacketNumber: 5, Count: 2}, {FirstPacketNumber: 4, Count: 1}}},
}
for _, frame := range invalid {
data, err := frame.Append(nil, protocol.Version1)
if err != nil {
t.Fatal(err)
}
if _, _, err := parseFECFeedbackV2Frame(data[1:], protocol.Version1); err == nil {
t.Fatalf("invalid frame accepted: %+v", frame)
}
}
// A range that would cross the maximum packet number is rejected before it can be
// turned into a packet number.
overflow := quicvarint.Append(nil, 0)
overflow = quicvarint.Append(overflow, 0)
overflow = quicvarint.Append(overflow, 0)
overflow = quicvarint.Append(overflow, 0)
overflow = quicvarint.Append(overflow, 0)
overflow = quicvarint.Append(overflow, 1)
overflow = quicvarint.Append(overflow, maxFECPacketNumber)
overflow = quicvarint.Append(overflow, 2)
if _, _, err := parseFECFeedbackV2Frame(overflow, protocol.Version1); err == nil {
t.Fatal("overflowing missing range accepted")
}
}

func TestFECFeedbackV2TooManyRanges(t *testing.T) {
ranges := make([]FECFeedbackV2Range, MaxFECFeedbackV2Ranges+1)
for i := range ranges {
ranges[i] = FECFeedbackV2Range{FirstPacketNumber: protocol.PacketNumber(i * 10), Count: 1}
}
frame := &FECFeedbackV2Frame{MissingRanges: ranges}
data, err := frame.Append(nil, protocol.Version1)
if err != nil {
t.Fatal(err)
}
if _, _, err := parseFECFeedbackV2Frame(data[1:], protocol.Version1); err == nil {
t.Fatal("expected an error for too many missing ranges")
}
}

func TestFECFeedbackV2FitsIntoAckOnlyPacket(t *testing.T) {
frame := &FECFeedbackV2Frame{
ReceivedPackets:  maxFECPacketNumber,
LostPackets:      maxFECPacketNumber,
RecoveredPackets: maxFECPacketNumber,
FailedPackets:    maxFECPacketNumber,
ParityPackets:    maxFECPacketNumber,
}
for i := 0; i < MaxFECFeedbackV2Ranges; i++ {
frame.MissingRanges = append(frame.MissingRanges, FECFeedbackV2Range{
FirstPacketNumber: protocol.PacketNumber(i * 17),
Count:             MaxFECFeedbackV2MissingPackets / MaxFECFeedbackV2Ranges,
})
}
if length := frame.Length(protocol.Version1); length > 512 {
t.Fatalf("FEC_FEEDBACK_V2 with %d ranges is %d bytes, too large for an ACK-only packet", len(frame.MissingRanges), length)
}
}

func TestFECMultiWindowRepairFrameRoundTrip(t *testing.T) {
for _, memberCount := range []int{2, 8, 64} {
frame := &FECMultiWindowRepairFrame{
WindowID: 3,
FECWindowRepairFrame: FECWindowRepairFrame{
Row:               77,
FirstPacketNumber: 9000,
Span:              uint64(2*memberCount - 1),
ParityLength:      1200,
LengthParity:      [2]byte{0xab, 0xcd},
Parity:            bytes.Repeat([]byte{0x3c}, 1200),
},
}
for i := 0; i < memberCount; i++ {
frame.PacketNumbers = append(frame.PacketNumbers, protocol.PacketNumber(9000+i*2))
}
data, err := frame.Append(nil, protocol.Version1)
if err != nil {
t.Fatal(err)
}
if frame.Length(protocol.Version1) != protocol.ByteCount(len(data)) {
t.Fatalf("%d members: length mismatch: %d vs %d", memberCount, frame.Length(protocol.Version1), len(data))
}
if data[0] != byte(FrameTypeFECWindowRepairMulti) {
t.Fatalf("unexpected frame type: %#x", data[0])
}
parsed, n, err := parseFECMultiWindowRepairFrame(data[1:], protocol.Version1)
if err != nil {
t.Fatalf("%d members: %v", memberCount, err)
}
if n != len(data)-1 {
t.Fatalf("%d members: expected to consume %d bytes, consumed %d", memberCount, len(data)-1, n)
}
if parsed.WindowID != frame.WindowID || parsed.Row != frame.Row ||
parsed.FirstPacketNumber != frame.FirstPacketNumber || parsed.Span != frame.Span ||
parsed.ParityLength != frame.ParityLength || parsed.LengthParity != frame.LengthParity {
t.Fatalf("unexpected parsed frame: %+v", parsed)
}
if len(parsed.PacketNumbers) != len(frame.PacketNumbers) {
t.Fatalf("unexpected packet numbers: %v", parsed.PacketNumbers)
}
for i := range frame.PacketNumbers {
if parsed.PacketNumbers[i] != frame.PacketNumbers[i] {
t.Fatalf("unexpected packet number at index %d: %d", i, parsed.PacketNumbers[i])
}
}
if !bytes.Equal(parsed.Parity, frame.Parity) {
t.Fatal("parity mismatch")
}
reencoded, err := parsed.Append(nil, protocol.Version1)
if err != nil {
t.Fatal(err)
}
if !bytes.Equal(reencoded, data) {
t.Fatalf("%d members: re-encoded frame differs", memberCount)
}
}
}
