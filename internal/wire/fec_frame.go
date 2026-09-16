package wire

import (
	"errors"
	"io"

	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/quicvarint"
)

// Frame types of the fork-private packet level FEC extension.
//
// These frame types are not registered with IANA. They are only ever sent after both
// endpoints enabled packet level FEC out of band (for sing-box QUICX: in the protocol
// handshake). A receiver that didn't enable FEC ignores them instead of closing the
// connection, so enabling FEC on one side only degrades to "no protection" instead of
// breaking the connection.
//
// 0x32 used to be the repair frame of the group based block scheme, which this fork no
// longer implements. It is not reused.
const (
	FrameTypeFECFeedback     FrameType = 0x33
	FrameTypeFECWindowRepair FrameType = 0x34
)

// MaxFECWindowSize is the maximum number of packets a sliding window repair row
// protects. A sliding window row is superseded by the rows that follow it, so a large
// window costs memory but not recovery latency.
const MaxFECWindowSize = 128

// MaxFECWindowSpan is the maximum packet number distance the membership bitmap of a
// sliding window repair row can describe. The bitmap costs one bit per packet number
// of the span, so the span is what bounds the frame header.
const MaxFECWindowSpan = 512

// maxFECProtectedPacketLength is the maximum wire length of a protected packet that
// can be described by a FEC repair frame.
const maxFECProtectedPacketLength = 16383

// IsFECFrameType says if this is a packet level FEC frame.
func (t FrameType) IsFECFrameType() bool {
	return t == FrameTypeFECWindowRepair || t == FrameTypeFECFeedback
}

// A FECWindowRepairFrame carries one repair row of the sliding window
// (convolutional) FEC scheme.
//
// A row protects the *current* window of the sender: the packets it names are a
// snapshot of the packets that were protected when the row was generated. Successive
// rows protect overlapping windows, so a lost packet is covered by every row generated
// while it stays in the window. That is what makes the scheme recover from bursts,
// without the all-or-nothing behaviour of a block code.
//
// The protected packets are zero-extended to the parity length (the length of the
// longest protected packet) and combined with the coefficients of the row. The
// coefficients form a Cauchy matrix over GF(2^8): the coefficient of the member at
// position p of the row with number r is 1 / (x[r] + y[p]), with the row bases x and
// the position bases y taken from two disjoint sets. Every square submatrix of a
// Cauchy matrix is invertible, so any n rows reconstruct any n missing members of the
// window, whatever their positions.
//
// The member list is a bitmap instead of a packet number list: the packets of a window
// are nearly consecutive packet numbers - the packet numbers spent on parity packets
// simply stay clear - so the bitmap costs one bit per packet number of the span. The
// wire lengths of the members are not listed either: their GF(2^8) combination is sent
// (two bytes), and a recovered length is computed exactly like a recovered packet.
//
// Wire format (all integers are QUIC varints unless noted otherwise):
//
//	0x34 | row | first packet number | span | bitmap | member count | parity length
//	     | length parity (2 bytes) | parity
type FECWindowRepairFrame struct {
	// Row is the repair row number, a sender side counter that also selects the
	// coefficients of the row. Two rows with row numbers that are congruent modulo the
	// number of row bases share their coefficients, so the redundancy is bounded to
	// keep two rows that cover the same packet linearly independent.
	Row uint64
	// FirstPacketNumber is the smallest packet number covered by the bitmap.
	FirstPacketNumber protocol.PacketNumber
	// Span is the number of packet numbers the bitmap describes.
	Span uint64
	// PacketNumbers are the protected packet numbers, in increasing order. They are
	// the set bits of the bitmap.
	PacketNumbers []protocol.PacketNumber
	// ParityLength is the length of the parity payload, i.e. the length of the longest
	// protected packet.
	ParityLength protocol.ByteCount
	// LengthParity is the GF(2^8) combination of the wire lengths of the protected
	// packets: [0] combines the high bytes, [1] the low bytes.
	LengthParity [2]byte
	// Parity is the parity payload.
	Parity []byte
}

func parseFECWindowRepairFrame(b []byte, _ protocol.Version) (*FECWindowRepairFrame, int, error) {
	startLen := len(b)
	f := &FECWindowRepairFrame{}
	var (
		l   int
		err error
	)
	if f.Row, l, err = quicvarint.Parse(b); err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	first, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	f.FirstPacketNumber = protocol.PacketNumber(first)
	b = b[l:]
	if f.Span, l, err = quicvarint.Parse(b); err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	if f.Span < 2 || f.Span > MaxFECWindowSpan {
		return nil, 0, errors.New("invalid FEC window span")
	}
	b = b[l:]
	bitmapLen := int((f.Span + 7) / 8)
	if len(b) < bitmapLen {
		return nil, 0, io.EOF
	}
	bitmap := b[:bitmapLen]
	b = b[bitmapLen:]
	memberCount, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	if memberCount < 2 || memberCount > MaxFECWindowSize {
		return nil, 0, errors.New("invalid FEC window member count")
	}
	b = b[l:]
	parityLen, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	if parityLen == 0 || parityLen > maxFECProtectedPacketLength {
		return nil, 0, errors.New("invalid FEC window parity length")
	}
	b = b[l:]
	if len(b) < 2 {
		return nil, 0, io.EOF
	}
	f.LengthParity = [2]byte{b[0], b[1]}
	b = b[2:]
	f.PacketNumbers = make([]protocol.PacketNumber, 0, memberCount)
	for i := uint64(0); i < f.Span; i++ {
		if bitmap[i/8]&(1<<(i%8)) != 0 {
			f.PacketNumbers = append(f.PacketNumbers, f.FirstPacketNumber+protocol.PacketNumber(i))
		}
	}
	if uint64(len(f.PacketNumbers)) != memberCount {
		return nil, 0, errors.New("FEC window bitmap doesn't match the member count")
	}
	if uint64(len(b)) < parityLen {
		return nil, 0, io.EOF
	}
	f.ParityLength = protocol.ByteCount(parityLen)
	f.Parity = make([]byte, parityLen)
	copy(f.Parity, b[:parityLen])
	b = b[parityLen:]

	return f, startLen - len(b), nil
}

func (f *FECWindowRepairFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypeFECWindowRepair))
	b = quicvarint.Append(b, f.Row)
	b = quicvarint.Append(b, uint64(f.FirstPacketNumber))
	b = quicvarint.Append(b, f.Span)
	bitmap := make([]byte, (f.Span+7)/8)
	for _, pn := range f.PacketNumbers {
		offset := uint64(pn - f.FirstPacketNumber)
		bitmap[offset/8] |= 1 << (offset % 8)
	}
	b = append(b, bitmap...)
	b = quicvarint.Append(b, uint64(len(f.PacketNumbers)))
	b = quicvarint.Append(b, uint64(len(f.Parity)))
	b = append(b, f.LengthParity[0], f.LengthParity[1])
	b = append(b, f.Parity...)
	return b, nil
}

func (f *FECWindowRepairFrame) Length(_ protocol.Version) protocol.ByteCount {
	length := protocol.ByteCount(quicvarint.Len(uint64(FrameTypeFECWindowRepair)))
	length += protocol.ByteCount(quicvarint.Len(f.Row))
	length += protocol.ByteCount(quicvarint.Len(uint64(f.FirstPacketNumber)))
	length += protocol.ByteCount(quicvarint.Len(f.Span))
	length += protocol.ByteCount((f.Span + 7) / 8)
	length += protocol.ByteCount(quicvarint.Len(uint64(len(f.PacketNumbers))))
	length += protocol.ByteCount(quicvarint.Len(uint64(len(f.Parity))))
	length += 2
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
//	0x33 | received packets | lost packets | recovered packets | failed packets | parity packets
type FECFeedbackFrame struct {
	// ReceivedPackets is the number of 1-RTT packets received by the peer.
	ReceivedPackets uint64
	// LostPackets is the number of packet numbers the peer never received (gaps in
	// the packet number sequence). This is the loss rate of the path, independent of
	// whether the packets were protected by FEC.
	LostPackets uint64
	// RecoveredPackets is the number of packets that were reconstructed from parity.
	RecoveredPackets uint64
	// FailedPackets is the number of protected packets the decoder gave up on: they
	// stayed missing for longer than the decoder waits for a repair row.
	FailedPackets uint64
	// ParityPackets is the number of received FEC repair frames.
	ParityPackets uint64
}

func parseFECFeedbackFrame(b []byte, _ protocol.Version) (*FECFeedbackFrame, int, error) {
	startLen := len(b)
	f := &FECFeedbackFrame{}
	fields := []*uint64{&f.ReceivedPackets, &f.LostPackets, &f.RecoveredPackets, &f.FailedPackets, &f.ParityPackets}
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
	b = quicvarint.Append(b, f.ReceivedPackets)
	b = quicvarint.Append(b, f.LostPackets)
	b = quicvarint.Append(b, f.RecoveredPackets)
	b = quicvarint.Append(b, f.FailedPackets)
	b = quicvarint.Append(b, f.ParityPackets)
	return b, nil
}

func (f *FECFeedbackFrame) Length(_ protocol.Version) protocol.ByteCount {
	return protocol.ByteCount(
		quicvarint.Len(uint64(FrameTypeFECFeedback)) +
			quicvarint.Len(f.ReceivedPackets) +
			quicvarint.Len(f.LostPackets) +
			quicvarint.Len(f.RecoveredPackets) +
			quicvarint.Len(f.FailedPackets) +
			quicvarint.Len(f.ParityPackets),
	)
}
