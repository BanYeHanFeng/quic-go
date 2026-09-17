package quic

import (
	"errors"
	"time"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/wire"
)

// Packet level forward error correction (FEC).
//
// This is a fork-private extension of quic-go, used by sing-box QUICX to survive
// packet loss on lossy paths without forcing the congestion controller to ignore
// loss (the approach used by Hysteria's "brutal" congestion control).
//
// The sliding window scheme (fec_window.go) is the only scheme this fork implements.
// It protects the packets the sender most recently wrote to the wire: one repair row
// covers the current window, and successive rows protect overlapping windows, so a
// lost packet is covered by every row emitted while it stays in the window. The
// receiver caches the bytes of recently received packets and reconstructs the missing
// members of a row from it; the reconstructed packets are fed back into the regular
// packet processing path and acknowledged like packets that arrived on the wire, so
// the congestion controller never sees the loss.
//
// Bandwidth is only spent when the path actually loses packets: the receiver reports
// the loss it observes (including packets that FEC had to repair) in FEC_FEEDBACK
// frames, and the sender adapts the redundancy to the measured loss rate, capped by
// FECConfig.MaxOverheadPercent. With no loss, no parity packets are sent at all.
//
// Acknowledging recovered packets needs one explicit justification: RFC 9265 says a
// packet recovered by FEC must be treated as lost for congestion control, but it
// excepts "a path that is known to be lossy", which is the path this fork is built
// for. The exception only holds while the loss really is a property of the path and
// not congestion caused by the redundancy itself, so FECStats reports the connection's
// RTT inflation alongside the FEC counters: a rising RTT means the redundancy should
// be reduced, not increased.

const (
	defaultFECMaxOverheadPercent = 20
	defaultFECMaxParityRows      = 2
	defaultFECFlushDelay         = 2 * time.Millisecond

	// fecMinLossRate is the loss rate above which FEC engages. Below this threshold
	// the connection is treated as lossless, and no redundancy is sent at all.
	fecMinLossRate = 0.002
	// fecLossSafetyFactor is applied to the measured loss rate when computing the
	// amount of redundancy: protecting against 1.5x the observed loss.
	fecLossSafetyFactor = 1.5
	fecLossEWMAAlpha    = 0.3

	// fecFeedbackInterval is the minimum interval between two FEC_FEEDBACK frames.
	fecFeedbackInterval = 20 * time.Millisecond
	// fecEvaluationInterval is how often the sender re-evaluates the loss rate.
	fecEvaluationInterval = 30 * time.Millisecond
	// fecPeerLossValidity is how long a loss report from the peer is considered
	// current. The loss rate of the path is measured by the receiver, so a report
	// that stopped arriving means the path has to be re-measured from scratch.
	fecPeerLossValidity = 150 * time.Millisecond
	// fecReorderWindow is the number of packets a packet may be late before the
	// receiver counts it as lost.
	fecReorderWindow = 8
	// fecMaxTrackerJump is the maximum packet number jump the loss tracker accounts
	// for. A larger jump resets the tracker (packets can only be authenticated, so
	// this only guards against a misbehaving peer).
	fecMaxTrackerJump = 4096

	// fecMaxPacketOverhead bounds the space a parity packet spends besides its repair
	// frame: a short header (up to 1 + 20 byte connection ID + 4 byte packet number)
	// plus the AEAD tag (up to 16 bytes). The encoder has to keep this much room in a
	// datagram when it decides how large a protected packet may be and whether a
	// parity frame fits. A frame that fits by its own length alone is dropped when it
	// is packed, and the repair silently never happens - which is exactly what a
	// saturated sender (a bulk transfer filling every packet to the limit) used to
	// hit.
	fecMaxPacketOverhead = 1 + 20 + 4 + 16
)

// FECConfig configures packet level forward error correction for a connection.
//
// The zero value is a valid configuration: MaxOverheadPercent defaults to 20,
// MaxGroupSize (the number of packets one window protects) to 128, MaxParityRows (the
// number of repair rows an idle sender emits for the tail of its window) to 2, and
// FlushDelay to 2ms.
type FECConfig struct {
	// MaxOverheadPercent caps the parity traffic as a percentage of the protected
	// traffic. It bounds the bandwidth FEC is allowed to spend, no matter how high
	// the measured loss rate is. The cap is enforced on the bytes actually sent: the
	// sender grants every protected packet a byte budget of MaxOverheadPercent of its
	// size and refuses a repair row the budget doesn't cover. Defaults to 20.
	MaxOverheadPercent int
	// MaxGroupSize is the number of packets one window protects. Larger windows
	// tolerate longer bursts, at the price of memory: the sender holds the bytes of
	// every window member, and the receiver caches roughly two windows of packets.
	// Defaults to 128.
	MaxGroupSize int
	// MaxParityRows is the number of repair rows an idle sender emits for the tail of
	// its window. The packets sent last are covered by fewer rows than the ones in the
	// middle, so a connection that stops sending would leave them unprotected
	// otherwise. Defaults to 2.
	MaxParityRows int
	// BaselineRedundancyPercent keeps a small fixed redundancy on the wire even while
	// the path looks lossless. A purely reactive sender only starts protecting after
	// the peer reports the first loss, which costs roughly 0.5*RTT plus the feedback
	// interval; on a high-RTT or low-rate path the first burst can already be gone from
	// the window by then. The baseline is subject to MaxOverheadPercent like any other
	// redundancy. Defaults to 0: a clean path then spends no byte on FEC at all.
	BaselineRedundancyPercent int
	// RecoveredPacketFeedback reports packets the decoder reconstructed with FEC back to
	// the sender (FEC_RECOVERED), so that the sender can tell its congestion controller
	// about the loss without retransmitting the packet. This keeps FEC from hiding the
	// congestion signal (RFC 9265, with the exception for a path that is known to be
	// lossy). It is off by default: it requires both ends to understand the frame, and
	// enabling it deliberately makes the connection react to the losses FEC repairs.
	RecoveredPacketFeedback bool
	// FlushDelay is how long the sender waits after the last packet before it emits
	// the repair rows for the tail of the window. Defaults to 2ms.
	FlushDelay time.Duration
}

func (c FECConfig) withDefaults() FECConfig {
	if c.MaxOverheadPercent <= 0 {
		c.MaxOverheadPercent = defaultFECMaxOverheadPercent
	}
	if c.MaxOverheadPercent > 100 {
		c.MaxOverheadPercent = 100
	}
	if c.MaxGroupSize <= 0 {
		c.MaxGroupSize = defaultFECWindowSize
	}
	if c.MaxGroupSize > wire.MaxFECWindowSize {
		c.MaxGroupSize = wire.MaxFECWindowSize
	}
	if c.MaxParityRows <= 0 {
		c.MaxParityRows = defaultFECMaxParityRows
	}
	if c.MaxParityRows > fecWindowMaxFlushRows {
		c.MaxParityRows = fecWindowMaxFlushRows
	}
	if c.FlushDelay <= 0 {
		c.FlushDelay = defaultFECFlushDelay
	}
	if c.BaselineRedundancyPercent < 0 {
		c.BaselineRedundancyPercent = 0
	}
	if c.BaselineRedundancyPercent > 100 {
		c.BaselineRedundancyPercent = 100
	}
	return c
}

// FECStats reports the state of the packet level FEC of a connection.
type FECStats struct {
	Enabled bool
	// WindowSize is the number of packets the current window protects. It is 0 while
	// FEC is idle, i.e. while the path looks lossless.
	WindowSize int
	LossRate   float64 // smoothed loss rate observed by the peer on the path we send on
	// RedundancyRate is the parity/protected ratio the sender aims for at the current
	// loss rate, before the overhead cap is applied. It is a configuration value
	// derived from the peer's reports, not a measurement.
	RedundancyRate float64
	// MeasuredOverhead is the parity bytes actually sent divided by the bytes they
	// protect. MaxOverheadPercent bounds this over the whole connection, so the value
	// reported for a statistics window is already guaranteed to be within the cap.
	MeasuredOverhead float64

	ProtectedPacketsSent uint64
	// ProtectedBytesSent is the number of bytes FEC handed to the encoder and granted
	// a parity budget. It is the denominator of MeasuredOverhead.
	ProtectedBytesSent uint64
	ParityPacketsSent  uint64
	ParityBytesSent    uint64
	// SkippedRows is the number of repair rows that were not sent because the byte
	// budget the overhead cap granted didn't cover them. A value that keeps growing
	// means the cap - not the measured loss rate - is limiting FEC on this connection.
	SkippedRows uint64
	// SkippedRowsBudget is the part of SkippedRows that the byte budget refused. A
	// value that keeps growing means MaxOverheadPercent, not the loss estimate, is what
	// limits FEC on this connection.
	SkippedRowsBudget uint64
	// SkippedRowsUnbuildable is the part of SkippedRows that were neither refused by the
	// budget nor sent: the window couldn't be described, or the repair row would not
	// fit into a datagram.
	SkippedRowsUnbuildable uint64
	// DroppedFrames is the number of repair frames that were discarded because the send
	// queue stayed busy for too long. It should stay at zero; a growing value means the
	// sender never gets a chance to send parity, so FEC is not protecting anything on
	// that connection.
	DroppedFrames uint64

	// The remaining counters describe the direction we receive on: they are produced
	// by the decoder and are independent of LossRate, which the peer measures on the
	// direction we send on.
	ProtectedPacketsReceived uint64
	RecoveredPackets         uint64
	FailedPackets            uint64
	ParityPacketsReceived    uint64
	// MissingPackets is the number of packets the peer announced as protected that this
	// endpoint has neither received nor reconstructed, and that haven't expired yet. It
	// is a gauge: MissingPackets > 0 while ParityPacketsReceived stopped growing is the
	// signature of a peer that went idle after announcing the packets it protects.
	MissingPackets uint64
	// DuplicateRows is the number of repair rows dropped because an equation with the
	// same row number was already pending. Re-adding it can't add rank, only work.
	DuplicateRows uint64
	// RecoveredPacketsReported is the number of locally recovered packets that were
	// queued into FEC_RECOVERED frames for the peer (only with RecoveredPacketFeedback).
	RecoveredPacketsReported uint64
	// RecoveredPacketsReceived is the number of packets the peer reported as recovered
	// and that were handed to the congestion controller.
	RecoveredPacketsReceived uint64

	// SmoothedRTT, MinRTT and RTTInflation are the connection's RTT estimates at the
	// time the statistics were read. While FEC is recovering packets, RTTInflation
	// (smoothed RTT above the connection minimum) is the queueing delay the connection
	// sees: if it grows, the loss is likely congestion and the right reaction is to
	// reduce redundancy rather than add more. These are zero while FEC is disabled.
	SmoothedRTT  time.Duration
	MinRTT       time.Duration
	RTTInflation time.Duration
}

// EnableFEC enables packet level forward error correction for this connection.
//
// Both peers need to enable FEC, otherwise one side sends repair frames the other
// side never asked for. Enablement is not negotiated by quic-go itself (QUICX
// negotiates it in its own handshake), so that no additional transport parameter shows
// up in the ClientHello and the HTTP/3 fingerprint is preserved. FEC frames of a peer
// that enabled FEC earlier are ignored, so enabling FEC on one side only does not
// break the connection.
func (c *Conn) EnableFEC(config FECConfig) error {
	select {
	case <-c.handshakeCompleteChan:
	default:
		return &FECError{Message: "FEC can only be enabled after the handshake completed"}
	}
	state := newFECWindowStateWithLogger(config, c.logger)
	c.fecState.Store(state)
	c.scheduleSending()
	return nil
}

// DisableFEC disables packet level FEC for this connection. Packets that are already
// in flight may still be repaired by the peer.
func (c *Conn) DisableFEC() {
	c.fecState.Store(nil)
}

// FECStats returns the current FEC statistics of the connection.
func (c *Conn) FECStats() FECStats {
	state := c.loadFEC()
	if state == nil {
		return FECStats{}
	}
	stats := state.stats()
	// RTTStats stores its estimates in atomics, so reading them from a statistics
	// caller on another goroutine is safe.
	stats.SmoothedRTT = c.rttStats.SmoothedRTT()
	stats.MinRTT = c.rttStats.MinRTT()
	stats.RTTInflation = stats.SmoothedRTT - stats.MinRTT
	if stats.RTTInflation < 0 {
		stats.RTTInflation = 0
	}
	return stats
}

// loadFEC returns the FEC state of the connection, or nil while FEC is disabled.
func (c *Conn) loadFEC() *fecWindowState {
	return c.fecState.Load()
}

// FECError is returned when FEC can't be enabled.
type FECError struct{ Message string }

func (e *FECError) Error() string { return "quic: " + e.Message }

// errFECFrameTooLarge is returned when a FEC frame doesn't fit into a packet.
// The frame is then dropped instead of closing the connection.
var errFECFrameTooLarge = errors.New("FEC frame too large")

// dataPacketSizeLimit returns the maximum size of a packet that may be protected by
// FEC. A parity frame is at most as long as the longest protected packet plus the
// header that describes the code, so protected packets have to leave room for it.
func (c *Conn) dataPacketSizeLimit() protocol.ByteCount {
	maxPacketSize := c.maxPacketSize()
	state := c.loadFEC()
	if state == nil || !state.protecting() {
		return maxPacketSize
	}
	// The parity packet carries the longest protected packet plus the frame header, and
	// spends a short header and an AEAD tag on top of the datagram. All three have to be
	// kept free, otherwise the parity frame is dropped when it is packed.
	reserve := state.reserve() + fecMaxPacketOverhead
	if reserve >= maxPacketSize {
		return maxPacketSize
	}
	return maxPacketSize - reserve
}

// fecRecordSentPacket hands a packet that was just written to the wire to the FEC
// encoder, and lets the encoder re-evaluate the loss rate.
func (c *Conn) fecRecordSentPacket(pn protocol.PacketNumber, data []byte, maxPacketSize protocol.ByteCount, now monotime.Time, carriesData bool) {
	state := c.loadFEC()
	if state == nil {
		return
	}
	state.tick(now)
	state.addPacket(pn, data, maxPacketSize, now, carriesData)
}

// fecProtectsPacket says whether a packet carries application data, and is therefore
// worth protecting. A packet that only acknowledges packets, or that only updates flow
// control state, carries information the peer can reconstruct from its own state:
// spending parity on it protects nothing.
func fecProtectsPacket(p shortHeaderPacket) bool {
	if len(p.StreamFrames) > 0 {
		return true
	}
	for _, frame := range p.Frames {
		if _, ok := frame.Frame.(*wire.DatagramFrame); ok {
			return true
		}
	}
	return false
}

// fecRecordReceivedPacket caches a received packet for FEC recovery. A packet that
// arrives late can make a packet that was lost before it recoverable, so the packets
// the cache reconstructs are handed to the connection right away.
func (c *Conn) fecRecordReceivedPacket(pn protocol.PacketNumber, data []byte, keyPhase protocol.KeyPhaseBit, rcvTime monotime.Time) {
	state := c.loadFEC()
	if state == nil {
		return
	}
	c.handleRecoveredFECPackets(state.recordPacket(pn, data, keyPhase), rcvTime)
}

// handleFECFrame processes an incoming FEC frame: a sliding window repair frame, or a
// feedback frame of the peer. All FEC frames are ignored while FEC is disabled locally.
func (c *Conn) handleFECFrame(frame wire.Frame, rcvTime monotime.Time) error {
	state := c.loadFEC()
	if state == nil {
		// FEC wasn't enabled (locally): ignore the parity packet. This happens when
		// the peer enabled FEC before we did, or when one side is misconfigured.
		return nil
	}
	c.handleRecoveredFECPackets(state.handleFrame(frame, rcvTime), rcvTime)
	return nil
}

// handleFECRecoveredFrame processes a report of packets the peer reconstructed with
// FEC. The packets were acknowledged like packets that arrived on the wire, so they
// are not retransmitted; their loss is reported to the congestion controller instead,
// so that FEC doesn't hide the congestion signal (RFC 9265, with the exception for a
// path that is known to be lossy).
func (c *Conn) handleFECRecoveredFrame(frame *wire.FECRecoveredFrame, rcvTime monotime.Time) error {
	state := c.loadFEC()
	if state == nil {
		// FEC wasn't enabled (locally): ignore the report. This happens when one side is
		// misconfigured, like with the other FEC frames.
		return nil
	}
	if len(frame.Packets) == 0 {
		return nil
	}
	state.recoveredReceived.Add(uint64(len(frame.Packets)))
	c.sentPacketHandler.OnFECRecoveredPackets(frame.Packets, rcvTime)
	return nil
}

// handleRecoveredFECPackets feeds packets that FEC reconstructed into the regular
// packet processing path. They are acknowledged like packets that arrived on the wire,
// so the congestion controller doesn't see the loss as a retransmission.
func (c *Conn) handleRecoveredFECPackets(recovered []fecRecoveredPacket, rcvTime monotime.Time) {
	for _, packet := range recovered {
		buffer := getPacketBuffer()
		buffer.Data = append(buffer.Data, packet.data...)
		c.handlePacket(receivedPacket{
			buffer:     buffer,
			data:       buffer.Data,
			rcvTime:    rcvTime,
			remoteAddr: c.conn.RemoteAddr(),
			ecn:        protocol.ECNNon,
		})
	}
}

// fecFlushDeadline returns the time at which an idle sender protects the packets it is
// still holding, or a zero time if there is nothing to protect.
func (c *Conn) fecFlushDeadline() monotime.Time {
	state := c.loadFEC()
	if state == nil {
		return 0
	}
	return state.flushDeadline()
}

// maybeSendFECPackets sends at most one pending FEC packet (a repair packet or a
// feedback frame). It reports whether a packet was sent.
func (c *Conn) maybeSendFECPackets(now monotime.Time) (bool, error) {
	state := c.loadFEC()
	if state == nil {
		return false, nil
	}
	// The send queue is bounded. FEC packets are only enqueued when the caller is
	// guaranteed to have left room for them (sendQueue.Send panics when it's full).
	if c.sendQueue.WouldBlock() {
		return false, nil
	}
	if frame := state.pendingFrame(now, c.maxPacketSize()); frame != nil {
		if err := c.sendFECFrame(state, frame, now); err != nil {
			return false, err
		}
		if state.hasPending() {
			c.scheduleSending()
		}
		return true, nil
	}
	return false, nil
}

func (c *Conn) sendFECFrame(state *fecWindowState, frame wire.Frame, now monotime.Time) error {
	ecn := c.sentPacketHandler.ECNMode(true)
	packet, buf, err := c.packer.PackFECPacket(frame, c.maxPacketSize(), now, c.version)
	if err != nil {
		if err == errNothingToPack || err == errFECFrameTooLarge {
			// The frame was already taken off the encoder's queue, so this is a lost
			// repair. The encoder sizes its frames to fit, so this shouldn't happen to
			// them - but a feedback frame can be larger than expected, and a path MTU
			// that shrank between building and packing a row makes it reachable for
			// repair frames as well. It is counted rather than dropped silently.
			state.frameDropped()
			c.logger.Debugf("dropping FEC frame that doesn't fit into a datagram: %s", err)
			return nil
		}
		return err
	}
	c.logShortHeaderPacket(packet, ecn, buf.Len())
	c.registerPackedShortHeaderPacket(packet, ecn, now)
	c.sendQueue.Send(buf, 0, ecn)
	state.frameSent(frame, c.version)
	return nil
}

// GF(2^8) arithmetic, with the AES/Rijndael polynomial x^8 + x^4 + x^3 + x + 1.
var (
	gfExp      [512]byte
	gfLog      [256]byte
	gfMulTable [256][256]byte
)

func init() {
	x := 1
	for i := range 255 {
		gfExp[i] = byte(x)
		gfLog[byte(x)] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	for i := 255; i < len(gfExp); i++ {
		gfExp[i] = gfExp[i-255]
	}
	// Multiplying by a fixed coefficient is the hot path of FEC encoding and
	// decoding: every protected byte is multiplied by the coefficient of its row.
	// A per-coefficient 256 byte lookup table turns that into a single branch-free
	// array read, instead of looking up two logarithms and adding them for every
	// byte in fecXORScaled. The table costs 64 KiB of per-process read-mostly data.
	for a := 1; a < 256; a++ {
		for b := 1; b < 256; b++ {
			gfMulTable[a][b] = gfExp[int(gfLog[a])+int(gfLog[b])]
		}
	}
	initFECSIMDTables()
}

func gfMul(a, b byte) byte {
	return gfMulTable[a][b]
}

func gfInv(a byte) byte {
	return gfExp[255-int(gfLog[a])]
}

// fecXORScaled computes dst ^= coefficient * src. src may be shorter than dst, which
// realizes the zero-extension to the parity length. Only len(src) bytes are visited:
// the cost of a variable-length row scales with the sum of the member lengths, not
// with the longest member times the number of members.
func fecXORScaled(dst, src []byte, coefficient byte) {
	if coefficient == 0 {
		return
	}
	if coefficient == 1 {
		for i, b := range src {
			dst[i] ^= b
		}
		return
	}
	fecXORScaledImpl(dst, src, coefficient)
}

// fecXORScaledTable is the portable implementation: every byte is multiplied
// through the per-coefficient 256 byte row of gfMulTable. It is also the fallback
// of the optional SIMD build (see fec_xor_simd_amd64.go).
func fecXORScaledTable(dst, src []byte, coefficient byte) {
	table := &gfMulTable[coefficient]
	dst = dst[:len(src)]
	for i, b := range src {
		dst[i] ^= table[b]
	}
}

// fecRecoveredPacket is a packet that was reconstructed from parity.
type fecRecoveredPacket struct {
	packetNumber protocol.PacketNumber
	data         []byte
}

// fecLossTracker measures the loss rate of the path by looking at the gaps in the
// received 1-RTT packet numbers. A packet number is only counted as lost once it is
// fecReorderWindow packets behind the largest received packet number, so that packets
// that were merely reordered are not counted as lost.
type fecLossTracker struct {
	initialized  bool
	largest      protocol.PacketNumber
	watermark    protocol.PacketNumber
	seen         map[protocol.PacketNumber]struct{}
	presumedLost map[protocol.PacketNumber]struct{}
	received     uint64
	lost         uint64
}

func (t *fecLossTracker) record(pn protocol.PacketNumber) {
	t.received++
	if !t.initialized {
		t.initialized = true
		t.largest = pn
		t.watermark = pn - 1
		t.seen = map[protocol.PacketNumber]struct{}{pn: {}}
		t.presumedLost = make(map[protocol.PacketNumber]struct{})
		return
	}
	if pn > t.largest {
		t.largest = pn
	}
	if pn <= t.watermark {
		// A packet that arrived late: undo the "presumed lost" if we counted one.
		if _, ok := t.presumedLost[pn]; ok {
			delete(t.presumedLost, pn)
			if t.lost > 0 {
				t.lost--
			}
		}
		return
	}
	t.seen[pn] = struct{}{}
	newWatermark := t.largest - fecReorderWindow
	if newWatermark <= t.watermark {
		return
	}
	if newWatermark-t.watermark > fecMaxTrackerJump {
		// Don't account for absurd jumps (this can only be caused by a misbehaving
		// peer): start over.
		t.initialized = false
		t.record(pn)
		return
	}
	for pn := t.watermark + 1; pn <= newWatermark; pn++ {
		if _, ok := t.seen[pn]; ok {
			delete(t.seen, pn)
			continue
		}
		t.lost++
		t.presumedLost[pn] = struct{}{}
	}
	t.watermark = newWatermark
	for pn := range t.presumedLost {
		if pn < t.watermark-4*fecReorderWindow {
			delete(t.presumedLost, pn)
		}
	}
}
