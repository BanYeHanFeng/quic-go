package wire

import (
	"bytes"
	"testing"

	"github.com/sagernet/quic-go/internal/protocol"
)

func TestFECRepairFrameRoundTrip(t *testing.T) {
	frame := &FECRepairFrame{
		Group:             12,
		Row:               0,
		RowCount:          1,
		PacketCount:       3,
		FirstPacketNumber: 42,
		PacketNumbers:     []protocol.PacketNumber{42, 43, 45},
		Lengths:           []protocol.ByteCount{100, 120, 90},
		Parity:            bytes.Repeat([]byte{0xab}, 120),
	}
	data, err := frame.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Length(protocol.Version1) != protocol.ByteCount(len(data)) {
		t.Fatalf("length mismatch: %d vs %d", frame.Length(protocol.Version1), len(data))
	}
	parsed, n, err := parseFECRepairFrame(data[1:], protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data)-1 {
		t.Fatalf("expected to consume %d bytes, consumed %d", len(data)-1, n)
	}
	if parsed.Group != frame.Group || parsed.Row != frame.Row || parsed.RowCount != frame.RowCount {
		t.Fatalf("unexpected group/row: %+v", parsed)
	}
	if parsed.PacketCount != frame.PacketCount || parsed.FirstPacketNumber != frame.FirstPacketNumber {
		t.Fatalf("unexpected packet count / first packet number: %+v", parsed)
	}
	if len(parsed.PacketNumbers) != len(frame.PacketNumbers) {
		t.Fatalf("unexpected packet numbers: %v", parsed.PacketNumbers)
	}
	for i := range frame.PacketNumbers {
		if parsed.PacketNumbers[i] != frame.PacketNumbers[i] {
			t.Fatalf("unexpected packet number at index %d: %d", i, parsed.PacketNumbers[i])
		}
	}
	for i := range frame.Lengths {
		if parsed.Lengths[i] != frame.Lengths[i] {
			t.Fatalf("unexpected length at index %d: %d", i, parsed.Lengths[i])
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
		t.Fatal("re-encoding mismatch")
	}
}

func TestFECRepairFrameTruncated(t *testing.T) {
	frame := &FECRepairFrame{
		Group:             1,
		Row:               0,
		RowCount:          1,
		PacketCount:       2,
		FirstPacketNumber: 10,
		PacketNumbers:     []protocol.PacketNumber{10, 11},
		Lengths:           []protocol.ByteCount{50, 60},
		Parity:            bytes.Repeat([]byte{1}, 60),
	}
	data, err := frame.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(data); i++ {
		if _, _, err := parseFECRepairFrame(data[1:i], protocol.Version1); err == nil {
			t.Fatalf("expected an error for a truncated frame of %d bytes", i)
		}
	}
}

func TestFECRepairFrameInvalid(t *testing.T) {
	valid := &FECRepairFrame{
		Group:             1,
		Row:               0,
		RowCount:          1,
		PacketCount:       2,
		FirstPacketNumber: 10,
		PacketNumbers:     []protocol.PacketNumber{10, 11},
		Lengths:           []protocol.ByteCount{50, 60},
		Parity:            bytes.Repeat([]byte{1}, 60),
	}
	data, err := valid.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	// parity length doesn't match the longest protected packet
	invalid := *valid
	invalid.Parity = bytes.Repeat([]byte{1}, 59)
	invalidData, err := invalid.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseFECRepairFrame(invalidData[1:], protocol.Version1); err == nil {
		t.Fatal("expected an error for a mismatching parity length")
	}
	// a single protected packet is invalid
	invalid = *valid
	invalid.PacketCount = 1
	invalid.PacketNumbers = []protocol.PacketNumber{10}
	invalid.Lengths = []protocol.ByteCount{50}
	invalidData, err = invalid.Append(nil, protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parseFECRepairFrame(invalidData[1:], protocol.Version1); err == nil {
		t.Fatal("expected an error for a single protected packet")
	}
	if len(data) == 0 {
		t.Fatal("unreachable")
	}
}

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
	for _, frameType := range []FrameType{FrameTypeFECRepair, FrameTypeFECFeedback, FrameTypeFECWindowRepair} {
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
