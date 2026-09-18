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
	// FrameTypeFECRecovered reports packets that were reconstructed by FEC back to the
	// sender. 0x35 is not reused: it was taken by the experimental streaming scheme.
	FrameTypeFECRecovered FrameType = 0x36
	// FrameTypeFECFeedbackV2 carries the counters of FEC_FEEDBACK plus the precise
	// ranges of protected packets that are still missing at the receiver. A sender
	// uses the ranges to schedule repair rows only for packets that are still inside
	// its window, instead of estimating from the cumulative loss delta.
	FrameTypeFECFeedbackV2 FrameType = 0x37
	// FrameTypeFECWindowRepairMulti is the multi-window variant of
	// FEC_WINDOW_REPAIR. It carries the same repair row plus the sub-window it
	// belongs to, so a connection can run k independent Cauchy windows without
	// changing the shape of one row.
	FrameTypeFECWindowRepairMulti FrameType = 0x38
)

// maxFECRecoveredFramePackets bounds the packets one recovered frame may report. It
// keeps a malformed peer from allocating an unbounded slice while parsing.
const maxFECRecoveredFramePackets = 256

// MaxFECFeedbackV2Ranges bounds the number of missing packet ranges one
// FEC_FEEDBACK_V2 frame carries. A frame has to fit into an ACK-only short packet,
// and the receiver truncates the list rather than building a frame that can't be
// sent.
const MaxFECFeedbackV2Ranges = 32

// MaxFECFeedbackV2MissingPackets bounds the number of packet numbers one
// FEC_FEEDBACK_V2 frame describes. The bound applies to the parsed frame as well, so
// a malformed peer can not make the receiver allocate an unbounded range list.
const MaxFECFeedbackV2MissingPackets = 128

// MaxFECMultiWindowCount bounds the sub-windows one multi-window encoder uses. The
// effective window and the per-connection memory both grow with the count, so it is
// a protocol-level bound rather than a tunable that can grow without limit.
const MaxFECMultiWindowCount = 4

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

// maxFECPacketNumber is the largest packet number QUIC varints can encode. It keeps
// FEC_FEEDBACK_V2 ranges from overflowing protocol.PacketNumber on malformed input.
const maxFECPacketNumber = 1<<62 - 1

// IsFECFrameType says if this is a packet level FEC frame.
func (t FrameType) IsFECFrameType() bool {
	return t == FrameTypeFECWindowRepair || t == FrameTypeFECFeedback || t == FrameTypeFECRecovered || t == FrameTypeFECFeedbackV2 || t == FrameTypeFECWindowRepairMulti
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
// the position bases y partitioning the 255 non-zero elements of the field. Every
// square submatrix of a Cauchy matrix is invertible, so any n rows reconstruct any n
// missing members of one window, whatever their positions.
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

// A FECMultiWindowRepairFrame carries one repair row of one sub-window of the
// multi-window scheme. Its body is identical to FECWindowRepairFrame; WindowID says
// which sub-window the member packet numbers belong to. The packet number itself
// encodes the assignment (packet number % window count), so the receiver can route a
// row without a separate field on every protected packet.
//
// Wire format:
//
//	0x38 | window id | row | first packet number | span | bitmap | member count
//	     | parity length | length parity (2 bytes) | parity
type FECMultiWindowRepairFrame struct {
	WindowID uint64
	FECWindowRepairFrame
}

func parseFECMultiWindowRepairFrame(b []byte, v protocol.Version) (*FECMultiWindowRepairFrame, int, error) {
	startLen := len(b)
	windowID, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	body, n, err := parseFECWindowRepairFrame(b, v)
	if err != nil {
		return nil, 0, err
	}
	f := &FECMultiWindowRepairFrame{WindowID: windowID}
	f.FECWindowRepairFrame = *body
	return f, startLen - len(b) + n, nil
}

func (f *FECMultiWindowRepairFrame) Append(b []byte, v protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypeFECWindowRepairMulti))
	b = quicvarint.Append(b, f.WindowID)
	body, err := f.FECWindowRepairFrame.Append(nil, v)
	if err != nil {
		return nil, err
	}
	// The embedded body frame prepends its own 0x34 frame type. Skip it: the multi
	// frame already announced the frame type and the sub-window, and the body follows
	// immediately after the window id.
	if len(body) == 0 {
		return b, nil
	}
	b = append(b, body[1:]...)
	return b, nil
}

func (f *FECMultiWindowRepairFrame) Length(v protocol.Version) protocol.ByteCount {
	bodyLength := f.FECWindowRepairFrame.Length(v) - protocol.ByteCount(quicvarint.Len(uint64(FrameTypeFECWindowRepair)))
	return protocol.ByteCount(quicvarint.Len(uint64(FrameTypeFECWindowRepairMulti)) + quicvarint.Len(f.WindowID)) + bodyLength
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
	// LostPackets is the receiver's cumulative loss evidence: packet numbers that were
	// presumed lost from gaps in the packet number sequence, or that a repair row revealed
	// as missing protected packets. The two detections are deduplicated, so this is still
	// a count of distinct lost packet numbers, independent of whether they were protected
	// by FEC. A monotonic value also survives one lost feedback packet without resetting
	// the sender's view to an older baseline.
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

// A FECFeedbackV2Range describes a span of packet numbers that are still missing at
// the receiver. Count is the length of the span, not the number of gaps inside it:
// a range produced by merging two gaps at most three packet numbers apart counts the
// packet numbers between them as well. The sender only uses ranges to test whether
// the packets are still in its window, so the span representation is sufficient.
type FECFeedbackV2Range struct {
	// FirstPacketNumber is the first packet number of the range.
	FirstPacketNumber protocol.PacketNumber
	// Count is the number of consecutive packet numbers the range describes.
	Count uint64
}

// A FECFeedbackV2Frame extends FEC_FEEDBACK with the receiver's current missing
// packet ranges. The cumulative counters keep the same semantics as FEC_FEEDBACK, so
// a sender can share its loss estimator between the two frame types. The ranges are
// only a snapshot: feedback packets can be lost, and the next snapshot re-sends the
// ranges of the packets that are still missing.
//
// Wire format (all integers are QUIC varints):
//
//	0x37 | received | lost evidence | recovered | failed | parity received | count |
//	(first packet number, count) * count
//
// Ranges are sorted by packet number and do not overlap. A receiver only reports
// packet numbers that a repair row announced as protected; unannounced gaps in the
// packet number sequence are carried by the cumulative lost evidence counter but are
// not necessarily FEC repairable.
type FECFeedbackV2Frame struct {
	// ReceivedPackets, LostPackets, RecoveredPackets, FailedPackets and ParityPackets
	// carry the same cumulative counters as FECFeedbackFrame. LostPackets is still the
	// receiver's cumulative deduplicated loss evidence, not the number of packets that
	// are currently missing.
	ReceivedPackets  uint64
	LostPackets      uint64
	RecoveredPackets uint64
	FailedPackets    uint64
	ParityPackets    uint64
	// MissingRanges is the current snapshot of protected packet numbers the receiver
	// has neither seen nor reconstructed. It is empty when there is nothing missing, or
	// when the receiver chose to suppress an unchanged snapshot.
	MissingRanges []FECFeedbackV2Range
}

// MissingPackets returns the number of packet numbers the frame ranges describe.
func (f *FECFeedbackV2Frame) MissingPackets() uint64 {
	var count uint64
	for _, r := range f.MissingRanges {
		count += r.Count
	}
	return count
}

func parseFECFeedbackV2Frame(b []byte, _ protocol.Version) (*FECFeedbackV2Frame, int, error) {
	startLen := len(b)
	f := &FECFeedbackV2Frame{}
	fields := []*uint64{&f.ReceivedPackets, &f.LostPackets, &f.RecoveredPackets, &f.FailedPackets, &f.ParityPackets}
	for _, field := range fields {
		value, l, err := quicvarint.Parse(b)
		if err != nil {
			return nil, 0, replaceUnexpectedEOF(err)
		}
		*field = value
		b = b[l:]
	}
	rangeCount, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	if rangeCount > MaxFECFeedbackV2Ranges {
		return nil, 0, errors.New("FEC feedback v2 carries too many missing ranges")
	}
	if rangeCount > 0 {
		f.MissingRanges = make([]FECFeedbackV2Range, 0, rangeCount)
	}
	var (
		totalMissing uint64
		previousEnd  uint64
	)
	for i := uint64(0); i < rangeCount; i++ {
		first, l, err := quicvarint.Parse(b)
		if err != nil {
			return nil, 0, replaceUnexpectedEOF(err)
		}
		b = b[l:]
		count, l, err := quicvarint.Parse(b)
		if err != nil {
			return nil, 0, replaceUnexpectedEOF(err)
		}
		b = b[l:]
		if count == 0 {
			return nil, 0, errors.New("FEC feedback v2 contains an empty missing range")
		}
		// Packet numbers are QUIC varints, i.e. non-negative integers below 2^62.
		// Reject a range that would step over that bound before it is converted into
		// a signed protocol.PacketNumber.
		if first > maxFECPacketNumber || count-1 > maxFECPacketNumber-first {
			return nil, 0, errors.New("FEC feedback v2 missing range overflows")
		}
		if i > 0 && first <= previousEnd {
			return nil, 0, errors.New("FEC feedback v2 missing ranges are not increasing")
		}
		previousEnd = first + count - 1
		totalMissing += count
		if totalMissing > MaxFECFeedbackV2MissingPackets {
			return nil, 0, errors.New("FEC feedback v2 reports too many missing packets")
		}
		f.MissingRanges = append(f.MissingRanges, FECFeedbackV2Range{
			FirstPacketNumber: protocol.PacketNumber(first),
			Count:             count,
		})
	}
	return f, startLen - len(b), nil
}

func (f *FECFeedbackV2Frame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypeFECFeedbackV2))
	b = quicvarint.Append(b, f.ReceivedPackets)
	b = quicvarint.Append(b, f.LostPackets)
	b = quicvarint.Append(b, f.RecoveredPackets)
	b = quicvarint.Append(b, f.FailedPackets)
	b = quicvarint.Append(b, f.ParityPackets)
	b = quicvarint.Append(b, uint64(len(f.MissingRanges)))
	for _, r := range f.MissingRanges {
		b = quicvarint.Append(b, uint64(r.FirstPacketNumber))
		b = quicvarint.Append(b, r.Count)
	}
	return b, nil
}

func (f *FECFeedbackV2Frame) Length(_ protocol.Version) protocol.ByteCount {
	length := protocol.ByteCount(
		quicvarint.Len(uint64(FrameTypeFECFeedbackV2)) +
			quicvarint.Len(f.ReceivedPackets) +
			quicvarint.Len(f.LostPackets) +
			quicvarint.Len(f.RecoveredPackets) +
			quicvarint.Len(f.FailedPackets) +
			quicvarint.Len(f.ParityPackets) +
			quicvarint.Len(uint64(len(f.MissingRanges))),
	)
	for _, r := range f.MissingRanges {
		length += protocol.ByteCount(quicvarint.Len(uint64(r.FirstPacketNumber)) + quicvarint.Len(r.Count))
	}
	return length
}

// A FECRecoveredPacket is one packet the receiver reconstructed from a repair row.
type FECRecoveredPacket struct {
	PacketNumber protocol.PacketNumber
	// Length is the wire length of the reconstructed packet. The sender needs it to
	// report the packet as lost to the congestion controller: the packet was already
	// acknowledged, so it has left the sender's packet history and its length is not
	// available there anymore.
	Length protocol.ByteCount
}

// A FECRecoveredFrame reports packets that the receiver reconstructed with FEC back
// to the sender. The packets were acknowledged on arrival (as recovered packets are
// ACKed like packets that arrived on the wire), so the sender doesn't need to
// retransmit them; it reports them as lost to the congestion controller instead, so
// that FEC doesn't hide the congestion signal (RFC 9265, with the exception for a
// path that is known to be lossy). The frame only carries data for a receiver that
// enabled the option, and a sender that doesn't understand it ignores it.
//
// Wire format (all integers are QUIC varints):
//
//	0x36 | count | first packet number | (pn delta, wire length) * count
//
// Packets are sorted by packet number, so the first packet's delta is zero.
type FECRecoveredFrame struct {
	Packets []FECRecoveredPacket
}

func parseFECRecoveredFrame(b []byte, _ protocol.Version) (*FECRecoveredFrame, int, error) {
	startLen := len(b)
	count, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	if count > maxFECRecoveredFramePackets {
		return nil, 0, errors.New("recovered frame reports too many packets")
	}
	f := &FECRecoveredFrame{}
	if count == 0 {
		return f, startLen - len(b), nil
	}
	first, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	f.Packets = make([]FECRecoveredPacket, 0, count)
	previous := first
	for i := uint64(0); i < count; i++ {
		delta, l, err := quicvarint.Parse(b)
		if err != nil {
			return nil, 0, replaceUnexpectedEOF(err)
		}
		b = b[l:]
		length, l, err := quicvarint.Parse(b)
		if err != nil {
			return nil, 0, replaceUnexpectedEOF(err)
		}
		b = b[l:]
		if i > 0 && delta == 0 {
			return nil, 0, errors.New("recovered frame packet numbers are not increasing")
		}
		packetNumber := first + delta
		if packetNumber < previous {
			return nil, 0, errors.New("recovered frame packet numbers overflow")
		}
		previous = packetNumber
		if length == 0 || protocol.ByteCount(length) > maxFECProtectedPacketLength {
			return nil, 0, errors.New("recovered frame has an invalid packet length")
		}
		f.Packets = append(f.Packets, FECRecoveredPacket{PacketNumber: protocol.PacketNumber(packetNumber), Length: protocol.ByteCount(length)})
	}
	return f, startLen - len(b), nil
}

func (f *FECRecoveredFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypeFECRecovered))
	b = quicvarint.Append(b, uint64(len(f.Packets)))
	if len(f.Packets) == 0 {
		return b, nil
	}
	first := f.Packets[0].PacketNumber
	b = quicvarint.Append(b, uint64(first))
	for _, packet := range f.Packets {
		b = quicvarint.Append(b, uint64(packet.PacketNumber-first))
		b = quicvarint.Append(b, uint64(packet.Length))
	}
	return b, nil
}

func (f *FECRecoveredFrame) Length(_ protocol.Version) protocol.ByteCount {
	length := protocol.ByteCount(quicvarint.Len(uint64(FrameTypeFECRecovered)) + quicvarint.Len(uint64(len(f.Packets))))
	if len(f.Packets) == 0 {
		return length
	}
	first := f.Packets[0].PacketNumber
	length += protocol.ByteCount(quicvarint.Len(uint64(first)))
	for _, packet := range f.Packets {
		length += protocol.ByteCount(quicvarint.Len(uint64(packet.PacketNumber-first)) + quicvarint.Len(uint64(packet.Length)))
	}
	return length
}
