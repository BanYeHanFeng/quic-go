package wire

import (
	"errors"
	"io"

	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/quicvarint"
)

// Frame types of the fork-private packet level FEC extension.
//
// These frame types are not registered with IANA. They are only ever sent after
// both endpoints enabled packet level FEC out of band (for sing-box QUICX: in the
// protocol handshake). A receiver that didn't enable FEC ignores them instead of
// closing the connection, so enabling FEC on one side only degrades to "no
// protection" instead of breaking the connection.
const (
	FrameTypeFECRepair   FrameType = 0x32
	FrameTypeFECFeedback FrameType = 0x33
)

// MaxFECGroupSize is the maximum number of packets protected by one FEC group.
const MaxFECGroupSize = 64

// maxFECProtectedPacketLength is the maximum wire length of a protected packet that
// can be described by a FEC repair frame (2 byte varints for the length list).
const maxFECProtectedPacketLength = 16383

// IsFECFrameType says if this is a packet level FEC frame.
func (t FrameType) IsFECFrameType() bool {
	return t == FrameTypeFECRepair || t == FrameTypeFECFeedback
}

// A FECRepairFrame carries one parity row over a group of QUIC packets.
//
// The protected packets are zero-extended to the parity length (the length of the
// longest protected packet) and combined with the coefficients of the row. Row 0
// uses all-ones coefficients, i.e. a plain XOR of the protected packets, which is
// the cheapest and most common case. Row r > 0 uses the coefficients (r+1)^j in
// GF(2^8), so that any `rows` lost packets of the group can be reconstructed from
// `rows` parity rows (Vandermonde / MDS construction).
//
// Wire format (all integers are QUIC varints):
//
//	0x32 | group | row | row count | count | first packet number | parity length
//	     | count-1 packet number deltas | count packet lengths | parity
type FECRepairFrame struct {
	// Group is a sender side counter identifying the FEC group.
	Group uint64
	// Row is the index of the parity row, starting at 0.
	Row uint8
	// RowCount is the total number of parity rows sent for this group.
	RowCount uint8
	// PacketCount is the number of protected packets, at least 2.
	PacketCount uint64
	// FirstPacketNumber is the packet number of the first protected packet.
	FirstPacketNumber protocol.PacketNumber
	// PacketNumbers are the protected packet numbers, in increasing order.
	PacketNumbers []protocol.PacketNumber
	// Lengths are the wire lengths of the protected packets, in the same order.
	Lengths []protocol.ByteCount
	// Parity is the parity row. Its length equals the maximum of Lengths.
	Parity []byte
}

func parseFECRepairFrame(b []byte, _ protocol.Version) (*FECRepairFrame, int, error) {
	startLen := len(b)
	f := &FECRepairFrame{}
	var (
		l   int
		err error
	)
	if f.Group, l, err = quicvarint.Parse(b); err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	row, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	if row > 255 {
		return nil, 0, errors.New("invalid FEC parity row")
	}
	f.Row = uint8(row)
	b = b[l:]
	rowCount, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	if rowCount == 0 || rowCount > 4 || row > rowCount-1 {
		return nil, 0, errors.New("invalid FEC parity row count")
	}
	f.RowCount = uint8(rowCount)
	b = b[l:]
	if f.PacketCount, l, err = quicvarint.Parse(b); err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	if f.PacketCount < 2 || f.PacketCount > MaxFECGroupSize {
		return nil, 0, errors.New("invalid number of protected packets")
	}
	b = b[l:]
	first, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	f.FirstPacketNumber = protocol.PacketNumber(first)
	b = b[l:]
	parityLen, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	if parityLen == 0 || parityLen > maxFECProtectedPacketLength {
		return nil, 0, errors.New("invalid FEC parity length")
	}
	b = b[l:]

	f.PacketNumbers = make([]protocol.PacketNumber, f.PacketCount)
	f.PacketNumbers[0] = f.FirstPacketNumber
	for i := uint64(1); i < f.PacketCount; i++ {
		delta, l, err := quicvarint.Parse(b)
		if err != nil {
			return nil, 0, replaceUnexpectedEOF(err)
		}
		if delta == 0 {
			return nil, 0, errors.New("invalid FEC packet number delta")
		}
		f.PacketNumbers[i] = f.PacketNumbers[i-1] + protocol.PacketNumber(delta)
		b = b[l:]
	}

	f.Lengths = make([]protocol.ByteCount, f.PacketCount)
	var maxLength protocol.ByteCount
	for i := range f.Lengths {
		length, l, err := quicvarint.Parse(b)
		if err != nil {
			return nil, 0, replaceUnexpectedEOF(err)
		}
		if length == 0 || length > maxFECProtectedPacketLength {
			return nil, 0, errors.New("invalid FEC protected packet length")
		}
		f.Lengths[i] = protocol.ByteCount(length)
		maxLength = max(maxLength, protocol.ByteCount(length))
		b = b[l:]
	}
	if protocol.ByteCount(parityLen) != maxLength {
		return nil, 0, errors.New("FEC parity length doesn't match the longest protected packet")
	}
	if uint64(len(b)) < parityLen {
		return nil, 0, io.EOF
	}
	f.Parity = make([]byte, parityLen)
	copy(f.Parity, b[:parityLen])
	b = b[parityLen:]

	return f, startLen - len(b), nil
}

func (f *FECRepairFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypeFECRepair))
	b = quicvarint.Append(b, f.Group)
	b = quicvarint.Append(b, uint64(f.Row))
	b = quicvarint.Append(b, uint64(f.RowCount))
	b = quicvarint.Append(b, f.PacketCount)
	b = quicvarint.Append(b, uint64(f.FirstPacketNumber))
	b = quicvarint.Append(b, uint64(len(f.Parity)))
	for i := 1; i < len(f.PacketNumbers); i++ {
		b = quicvarint.Append(b, uint64(f.PacketNumbers[i]-f.PacketNumbers[i-1]))
	}
	for _, length := range f.Lengths {
		b = quicvarint.Append(b, uint64(length))
	}
	b = append(b, f.Parity...)
	return b, nil
}

func (f *FECRepairFrame) Length(_ protocol.Version) protocol.ByteCount {
	length := protocol.ByteCount(quicvarint.Len(uint64(FrameTypeFECRepair)))
	length += protocol.ByteCount(quicvarint.Len(f.Group))
	length += protocol.ByteCount(quicvarint.Len(uint64(f.Row)))
	length += protocol.ByteCount(quicvarint.Len(uint64(f.RowCount)))
	length += protocol.ByteCount(quicvarint.Len(f.PacketCount))
	length += protocol.ByteCount(quicvarint.Len(uint64(f.FirstPacketNumber)))
	length += protocol.ByteCount(quicvarint.Len(uint64(len(f.Parity))))
	for i := 1; i < len(f.PacketNumbers); i++ {
		length += protocol.ByteCount(quicvarint.Len(uint64(f.PacketNumbers[i] - f.PacketNumbers[i-1])))
	}
	for _, l := range f.Lengths {
		length += protocol.ByteCount(quicvarint.Len(uint64(l)))
	}
	length += protocol.ByteCount(len(f.Parity))
	return length
}

// A FECFeedbackFrame reports the receiver's view of the FEC protected packet stream
// back to the sender, so that the sender can adapt the amount of redundancy to the
// loss rate actually observed on the path. All counters are cumulative; the sender
// only looks at the deltas, which makes the feedback robust against lost feedback
// packets.
//
// Wire format:
//
//	0x33 | protected packets | recovered packets | failed packets | parity packets
type FECFeedbackFrame struct {
	// ProtectedPackets is the number of protected packets that were part of a group
	// for which a parity row was received.
	ProtectedPackets uint64
	// RecoveredPackets is the number of packets that were reconstructed from parity.
	RecoveredPackets uint64
	// FailedPackets is the number of protected packets that were still missing after
	// all parity rows of their group had been processed.
	FailedPackets uint64
	// ParityPackets is the number of received FEC repair frames.
	ParityPackets uint64
}

func parseFECFeedbackFrame(b []byte, _ protocol.Version) (*FECFeedbackFrame, int, error) {
	startLen := len(b)
	f := &FECFeedbackFrame{}
	fields := []*uint64{&f.ProtectedPackets, &f.RecoveredPackets, &f.FailedPackets, &f.ParityPackets}
	for _, field := range fields {
		value, l, err := quicvarint.Parse(b)
		if err != nil {
			return nil, 0, replaceUnexpectedEOF(err)
		}
		*field = value
		b = b[l:]
	}
	return f, startLen - len(b), nil
}

func (f *FECFeedbackFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypeFECFeedback))
	b = quicvarint.Append(b, f.ProtectedPackets)
	b = quicvarint.Append(b, f.RecoveredPackets)
	b = quicvarint.Append(b, f.FailedPackets)
	b = quicvarint.Append(b, f.ParityPackets)
	return b, nil
}

func (f *FECFeedbackFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(
		quicvarint.Len(uint64(FrameTypeFECFeedback)) +
			quicvarint.Len(f.ProtectedPackets) +
			quicvarint.Len(f.RecoveredPackets) +
			quicvarint.Len(f.FailedPackets) +
			quicvarint.Len(f.ParityPackets),
	)
}
