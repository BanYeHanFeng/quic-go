package quic

import (
	"errors"
	"math"
	"sync/atomic"
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
// The sender groups outgoing 1-RTT packets into FEC groups. Once a group is closed
// (either because it reached the target group size, or because the sender went idle),
// the sender emits one parity row per group: a FEC_REPAIR frame carrying the wire
// bytes of the group XORed together (row 0), or a GF(2^8) Vandermonde combination
// (row > 0). The receiver caches recently received packet bytes; when a parity row
// arrives, it reconstructs the missing packets of the group and feeds them into the
// regular packet processing path. Recovered packets are acknowledged like packets
// that arrived on the wire, so the congestion controller never sees the loss.
//
// Bandwidth is only spent when the path actually loses packets: the receiver reports
// the loss it observes (including packets that FEC had to repair) in FEC_FEEDBACK
// frames, and the sender adapts the group size to the measured loss rate, capped by
// FECConfig.MaxOverheadPercent. With no loss, no parity packets are sent at all.

const (
	defaultFECMaxGroupSize       = 32
	defaultFECMinGroupSize       = 2
	defaultFECMaxOverheadPercent = 10
	defaultFECMaxParityRows      = 2
	defaultFECFlushDelay         = 2 * time.Millisecond

	// fecMinLossRate is the loss rate above which FEC engages. Below this threshold
	// the connection is treated as lossless, and no redundancy is sent at all.
	fecMinLossRate = 0.002
	// fecLossSafetyFactor is applied to the measured loss rate when computing the
	// amount of redundancy: protecting against 1.5x the observed loss.
	fecLossSafetyFactor = 1.5
	fecLossEWMAAlpha    = 0.3
	// fecLengthEWMAAlpha is the weight of the newest packet when tracking the average
	// protected packet size, which the group size calculation uses to keep the
	// per-group FEC_REPAIR header inside the overhead cap.
	fecLengthEWMAAlpha = 0.2
	// fecHighLossThreshold is the loss rate above which a second parity row is used
	// (if allowed by the configuration), which makes the group survive two losses.
	fecHighLossThreshold = 0.12
	// fecDoubleRowThreshold is the redundancy (loss rate times safety factor) above
	// which a single parity row is no longer considered sufficient, even when the
	// measured loss rate itself is still below fecHighLossThreshold.
	fecDoubleRowThreshold = 0.25

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

	fecMaxPendingGroups = 8
	fecCacheSlack       = 16
	// fecMaxPacketOverhead bounds the space a parity packet spends besides its FEC_REPAIR
	// frame: a short header (up to 1 + 20 byte connection ID + 4 byte packet number) plus
	// the AEAD tag (up to 16 bytes). The encoder has to keep this much room in a datagram
	// when it decides how large a protected packet may be and whether a parity frame
	// fits. A frame that fits by its own length alone is dropped when it is packed, and
	// the repair silently never happens - which is exactly what a saturated sender (a
	// bulk transfer filling every packet to the limit) used to hit.
	fecMaxPacketOverhead = 1 + 20 + 4 + 16
	// fecMaxReadyFrames bounds the parity frames waiting to be sent. Parity is only
	// enqueued when the send queue has room, so a sender that saturates its own send
	// queue can fall behind. Parity for a group older than the receiver's pending group
	// window can't be repaired from anymore, so the oldest frames are dropped instead of
	// being held in memory.
	fecMaxReadyFrames = 2 * fecMaxPendingGroups
	// fecMaxPacketDelta is the maximum packet number distance inside one FEC group.
	// Keeping it below 64 guarantees that packet number deltas fit into 1 byte varints.
	fecMaxPacketDelta = 63
)

// FECConfig configures packet level forward error correction for a connection.
// The zero value is a valid configuration: the block scheme (Scheme FECSchemeBlock)
// with MaxOverheadPercent defaulting to 10%, MaxGroupSize to 32, MinGroupSize to 2 and
// MaxParityRows to 2 (Reed-Solomon parity over GF(2^8), which survives two losses per
// group). With Scheme FECSchemeWindow the same fields configure the sliding window
// scheme: MaxGroupSize is the number of packets in the window (default 64) and
// MaxParityRows is the number of repair rows an idle sender emits for the tail
// (default 2).
type FECConfig struct {
	// Scheme selects the FEC scheme. Defaults to FECSchemeBlock. Both endpoints have to
	// use the same scheme; QUICX negotiates it during its handshake.
	Scheme FECScheme
	// MaxOverheadPercent caps the parity traffic as a percentage of the protected
	// traffic. It bounds the bandwidth FEC is allowed to spend, no matter how high
	// the measured loss rate is. The cap is enforced on the bytes actually sent: a
	// group is left unprotected when its parity packets would push the connection
	// over the cap. Defaults to 10.
	MaxOverheadPercent int
	// MaxGroupSize is the maximum number of packets protected by one FEC group.
	// Larger groups reduce the relative overhead, but increase the time until a
	// lost packet can be repaired. It has to be large enough to fit MaxParityRows
	// within MaxOverheadPercent, otherwise the second parity row can't be used.
	// Defaults to 32.
	MaxGroupSize int
	// MinGroupSize is the smallest group the sender is willing to protect. Partial
	// groups smaller than this are not protected. Defaults to 2.
	MinGroupSize int
	// MaxParityRows is the maximum number of parity rows sent per group. With 1 row
	// a group survives a single loss (XOR parity, "RAID 5" style), with 2 rows it
	// survives two losses ("RAID 6" style, Reed-Solomon over GF(2^8)). Defaults to 2.
	MaxParityRows int
	// FlushDelay is how long the sender keeps a partial group open while the
	// connection is idle, before protecting it. Defaults to 2ms.
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
		if c.Scheme == FECSchemeWindow {
			c.MaxGroupSize = defaultFECWindowSize
		} else {
			c.MaxGroupSize = defaultFECMaxGroupSize
		}
	}
	if c.MaxGroupSize > wire.MaxFECGroupSize && c.Scheme != FECSchemeWindow {
		c.MaxGroupSize = wire.MaxFECGroupSize
	}
	if c.MaxGroupSize > wire.MaxFECWindowSize {
		c.MaxGroupSize = wire.MaxFECWindowSize
	}
	if c.MinGroupSize <= 0 {
		c.MinGroupSize = defaultFECMinGroupSize
	}
	if c.MinGroupSize > c.MaxGroupSize {
		c.MinGroupSize = c.MaxGroupSize
	}
	if c.MaxParityRows <= 0 {
		c.MaxParityRows = defaultFECMaxParityRows
	}
	if c.MaxParityRows > 4 {
		c.MaxParityRows = 4
	}
	if c.FlushDelay <= 0 {
		c.FlushDelay = defaultFECFlushDelay
	}
	return c
}

// FECScheme selects the packet level FEC scheme of a connection.
type FECScheme uint8

const (
	// FECSchemeBlock is the group based scheme: the sender closes a group of packets
	// and protects it with a fixed number of parity rows. It is the original scheme,
	// and the one used when the peer only supports it.
	FECSchemeBlock FECScheme = iota
	// FECSchemeWindow is the sliding window (convolutional) scheme: every repair row
	// protects the sender's current window of packets, so a lost packet is covered by
	// every row generated while it stays in the window instead of by the fixed number
	// of rows of one group.
	FECSchemeWindow
)

// fecScheme is the connection facing part of a packet level FEC implementation. The
// block scheme (fecState) and the sliding window scheme (fecWindowState) implement it;
// the connection hooks only talk to this interface, so both schemes share the send
// path, the packet cache and the statistics plumbing.
type fecScheme interface {
	// stats returns a snapshot of the scheme's statistics.
	stats() FECStats
	// protecting says whether outgoing packets are currently protected. When it is
	// false no parity is sent, and protected packets don't have to leave room for one.
	protecting() bool
	// reserve is the number of bytes a parity frame needs in a datagram on top of the
	// protected packet (the frame header in the worst case).
	reserve() protocol.ByteCount
	// tick re-evaluates the amount of redundancy to send.
	tick(now monotime.Time)
	// addPacket hands a packet that was just written to the wire to the encoder.
	// carriesData says whether the packet carries application data: a packet that only
	// acknowledges packets is not worth protecting, and the schemes are free to ignore
	// it.
	addPacket(pn protocol.PacketNumber, data []byte, maxPacketSize protocol.ByteCount, now monotime.Time, carriesData bool)
	// recordPacket caches a received packet so that it can be used to reconstruct a lost
	// packet of the same code. It returns the packets that this packet made recoverable.
	recordPacket(pn protocol.PacketNumber, data []byte, keyPhase protocol.KeyPhaseBit) []fecRecoveredPacket
	// handleFrame processes an incoming FEC frame and returns the packets that were
	// reconstructed from it.
	handleFrame(frame wire.Frame, now monotime.Time) []fecRecoveredPacket
	// pendingFrame returns the next frame to send: a parity frame, or a feedback frame
	// for the peer. It returns nil when there is nothing to send.
	pendingFrame(now monotime.Time, maxPacketSize protocol.ByteCount) wire.Frame
	// hasPending says whether another frame is already waiting to be sent.
	hasPending() bool
	// frameSent accounts a frame that was handed to the send queue.
	frameSent(frame wire.Frame, v protocol.Version)
	// frameDropped accounts a frame that couldn't be sent at all.
	frameDropped()
	// flushDeadline is the time at which an idle sender protects the packets that are
	// still pending, or a zero time if there is nothing to protect.
	flushDeadline() monotime.Time
}

// FECStats reports the state of the packet level FEC of a connection.
type FECStats struct {
	Enabled bool
	Scheme  FECScheme
	// GroupSize is the current target group size of the block scheme, or the window
	// size of the sliding window scheme. It is 0 while FEC is idle.
	GroupSize int
	// ParityRows is the number of parity rows per group (block scheme). The sliding
	// window scheme doesn't use it.
	ParityRows int
	LossRate   float64 // smoothed loss rate observed by the peer on the path we send on
	// ConfiguredOverhead is the parity/protected ratio the current group size and
	// parity row count aim for. It is a configuration value, not a measurement.
	ConfiguredOverhead float64
	// MeasuredOverhead is the parity bytes actually sent divided by the bytes they
	// protect. MaxOverheadPercent bounds this value *per group*, so it bounds every
	// aggregation of it as well: what the statistics line reports for a window is
	// already guaranteed to be within the cap.
	MeasuredOverhead float64

	ProtectedPacketsSent uint64
	// ProtectedBytesSent is the number of bytes that were placed in a group that was
	// actually protected by at least one parity packet.
	ProtectedBytesSent uint64
	// ConsideredBytesSent is the number of bytes that were placed in any group FEC
	// closed. It includes the groups that were skipped to stay within the overhead cap,
	// which is what makes SkippedGroups interpretable.
	ConsideredBytesSent uint64
	ParityPacketsSent   uint64
	ParityBytesSent     uint64
	// SkippedGroups is the number of groups that were left unprotected because their
	// parity packets would have exceeded MaxOverheadPercent.
	SkippedGroups uint64
	// DroppedFrames is the number of parity frames that were discarded because the send
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
}

// fecState holds the FEC state of a connection. The encoder is only accessed from
// the connection's send path, the decoder only from its receive path - both run on
// the connection's run loop goroutine. The statistics are accessed from other
// goroutines (FECStats), and are therefore atomic.
type fecState struct {
	config  FECConfig
	encoder *fecEncoder
	decoder *fecDecoder

	lossBits atomic.Uint64 // math.Float64bits of the smoothed loss rate

	// mirror of the encoder's current configuration, for FECStats. The encoder
	// itself is only accessed from the connection's run loop goroutine.
	targetGroupSize atomic.Int64
	parityRows      atomic.Int64

	protectedSent  atomic.Uint64
	protectedBytes atomic.Uint64
	paritySent     atomic.Uint64
	parityBytes    atomic.Uint64
	// consideredBytes is the number of protected bytes FEC has evaluated so far. It
	// is the denominator of MeasuredOverhead and therefore of the overhead cap: it
	// includes the groups that were left unprotected because their parity would have
	// exceeded the cap.
	consideredBytes atomic.Uint64
	skippedGroups   atomic.Uint64
	// droppedFrames counts parity frames that had to be thrown away because the send
	// queue stayed busy longer than fecMaxReadyFrames allows.
	droppedFrames atomic.Uint64

	protectedRecv atomic.Uint64
	recoveredRecv atomic.Uint64
	failedRecv    atomic.Uint64
	parityRecv    atomic.Uint64
}

func newFECState(config FECConfig) *fecState {
	config = config.withDefaults()
	state := &fecState{config: config}
	state.encoder = &fecEncoder{
		state:       state,
		config:      config,
		overheadCap: float64(config.MaxOverheadPercent) / 100,
	}
	state.decoder = &fecDecoder{state: state, config: config}
	state.parityRows.Store(1)
	return state
}

func (s *fecState) setLossRate(loss float64) {
	s.lossBits.Store(math.Float64bits(loss))
}

func (s *fecState) lossRate() float64 {
	return math.Float64frombits(s.lossBits.Load())
}

// EnableFEC enables packet level forward error correction for this connection. The
// scheme is selected by config.Scheme.
//
// Both peers need to enable FEC, and they need to use the same scheme. Enablement is
// not negotiated by quic-go itself (QUICX negotiates it in its own handshake), so that
// no additional transport parameter shows up in the ClientHello and the HTTP/3
// fingerprint is preserved. FEC frames of a peer that enabled FEC earlier are ignored,
// so enabling FEC on one side only does not break the connection.
func (c *Conn) EnableFEC(config FECConfig) error {
	select {
	case <-c.handshakeCompleteChan:
	default:
		return &FECError{Message: "FEC can only be enabled after the handshake completed"}
	}
	var scheme fecScheme
	switch config.Scheme {
	case FECSchemeWindow:
		scheme = newFECWindowState(config)
	default:
		config.Scheme = FECSchemeBlock
		scheme = newFECState(config)
	}
	c.fecState.Store(&scheme)
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
	scheme := c.loadFEC()
	if scheme == nil {
		return FECStats{}
	}
	return scheme.stats()
}

// loadFEC returns the FEC scheme of the connection, or nil while FEC is disabled.
func (c *Conn) loadFEC() fecScheme {
	if scheme := c.fecState.Load(); scheme != nil {
		return *scheme
	}
	return nil
}

func (s *fecState) stats() FECStats {
	groupSize := int(s.targetGroupSize.Load())
	rows := int(s.parityRows.Load())
	protectedBytes := s.protectedBytes.Load()
	parityBytes := s.parityBytes.Load()
	consideredBytes := s.consideredBytes.Load()
	stats := FECStats{
		Enabled:                  true,
		Scheme:                   FECSchemeBlock,
		GroupSize:                groupSize,
		ParityRows:               rows,
		LossRate:                 s.lossRate(),
		ProtectedPacketsSent:     s.protectedSent.Load(),
		ProtectedBytesSent:       protectedBytes,
		ConsideredBytesSent:      consideredBytes,
		ParityPacketsSent:        s.paritySent.Load(),
		ParityBytesSent:          parityBytes,
		SkippedGroups:            s.skippedGroups.Load(),
		DroppedFrames:            s.droppedFrames.Load(),
		ProtectedPacketsReceived: s.protectedRecv.Load(),
		RecoveredPackets:         s.recoveredRecv.Load(),
		FailedPackets:            s.failedRecv.Load(),
		ParityPacketsReceived:    s.parityRecv.Load(),
	}
	if groupSize > 0 && rows > 0 {
		stats.ConfiguredOverhead = float64(rows) / float64(groupSize)
	}
	if protectedBytes > 0 {
		stats.MeasuredOverhead = float64(parityBytes) / float64(protectedBytes)
	}
	return stats
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
	scheme := c.loadFEC()
	if scheme == nil || !scheme.protecting() {
		return maxPacketSize
	}
	// The parity packet carries the longest protected packet plus the frame header, and
	// spends a short header and an AEAD tag on top of the datagram. All three have to be
	// kept free, otherwise the parity frame is dropped when it is packed.
	reserve := scheme.reserve() + fecMaxPacketOverhead
	if reserve >= maxPacketSize {
		return maxPacketSize
	}
	return maxPacketSize - reserve
}

// fecRecordSentPacket hands a packet that was just written to the wire to the FEC
// encoder, and lets the encoder re-evaluate the loss rate.
func (c *Conn) fecRecordSentPacket(pn protocol.PacketNumber, data []byte, maxPacketSize protocol.ByteCount, now monotime.Time, carriesData bool) {
	scheme := c.loadFEC()
	if scheme == nil {
		return
	}
	scheme.tick(now)
	scheme.addPacket(pn, data, maxPacketSize, now, carriesData)
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
	scheme := c.loadFEC()
	if scheme == nil {
		return
	}
	c.handleRecoveredFECPackets(scheme.recordPacket(pn, data, keyPhase), rcvTime)
}

// handleFECFrame processes an incoming FEC frame: a repair frame of the scheme that is
// enabled for this connection, or a feedback frame of the peer. Frames of the other
// scheme, and all FEC frames while FEC is disabled locally, are ignored.
func (c *Conn) handleFECFrame(frame wire.Frame, rcvTime monotime.Time) error {
	scheme := c.loadFEC()
	if scheme == nil {
		// FEC wasn't enabled (locally): ignore the parity packet. This happens when
		// the peer enabled FEC before we did, or when one side is misconfigured.
		return nil
	}
	c.handleRecoveredFECPackets(scheme.handleFrame(frame, rcvTime), rcvTime)
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
	scheme := c.loadFEC()
	if scheme == nil {
		return 0
	}
	return scheme.flushDeadline()
}

// maybeSendFECPackets sends at most one pending FEC packet (a parity packet or a
// feedback frame). It reports whether a packet was sent.
func (c *Conn) maybeSendFECPackets(now monotime.Time) (bool, error) {
	scheme := c.loadFEC()
	if scheme == nil {
		return false, nil
	}
	// The send queue is bounded. FEC packets are only enqueued when the caller is
	// guaranteed to have left room for them (sendQueue.Send panics when it's full).
	if c.sendQueue.WouldBlock() {
		return false, nil
	}
	if frame := scheme.pendingFrame(now, c.maxPacketSize()); frame != nil {
		if err := c.sendFECFrame(scheme, frame, now); err != nil {
			return false, err
		}
		if scheme.hasPending() {
			c.scheduleSending()
		}
		return true, nil
	}
	return false, nil
}

func (c *Conn) sendFECFrame(scheme fecScheme, frame wire.Frame, now monotime.Time) error {
	ecn := c.sentPacketHandler.ECNMode(true)
	packet, buf, err := c.packer.PackFECPacket(frame, c.maxPacketSize(), now, c.version)
	if err != nil {
		if err == errNothingToPack || err == errFECFrameTooLarge {
			// The frame was already taken off the encoder's queue, so this is a lost
			// repair. The encoder sizes its frames to fit, so this shouldn't happen to
			// them - but a feedback frame can be larger than expected, and a path MTU
			// that shrank between building and packing a row makes it reachable for
			// repair frames as well. It is counted rather than dropped silently.
			scheme.frameDropped()
			c.logger.Debugf("dropping FEC frame that doesn't fit into a datagram: %s", err)
			return nil
		}
		return err
	}
	c.logShortHeaderPacket(packet, ecn, buf.Len())
	c.registerPackedShortHeaderPacket(packet, ecn, now)
	c.sendQueue.Send(buf, 0, ecn)
	scheme.frameSent(frame, c.version)
	return nil
}

// The block scheme implements the fecScheme interface. The scheme's state and its
// encoder and decoder are only accessed from the connection's run loop goroutine.
func (s *fecState) protecting() bool { return s.encoder.protecting() }

func (s *fecState) reserve() protocol.ByteCount { return s.encoder.reserve() }

func (s *fecState) tick(now monotime.Time) { s.encoder.tick(now) }

func (s *fecState) addPacket(pn protocol.PacketNumber, data []byte, maxPacketSize protocol.ByteCount, now monotime.Time, _ bool) {
	s.encoder.addPacket(pn, data, maxPacketSize, now)
}

func (s *fecState) recordPacket(pn protocol.PacketNumber, data []byte, keyPhase protocol.KeyPhaseBit) []fecRecoveredPacket {
	s.decoder.recordPacket(pn, data, keyPhase)
	return nil
}

func (s *fecState) handleFrame(frame wire.Frame, now monotime.Time) []fecRecoveredPacket {
	switch f := frame.(type) {
	case *wire.FECRepairFrame:
		return s.decoder.handleRepair(f, now)
	case *wire.FECFeedbackFrame:
		s.encoder.onFeedback(f, now)
	}
	return nil
}

func (s *fecState) pendingFrame(now monotime.Time, maxPacketSize protocol.ByteCount) wire.Frame {
	if frame := s.encoder.pendingRepair(now, maxPacketSize); frame != nil {
		return frame
	}
	if frame := s.decoder.pendingFeedback(now); frame != nil {
		return frame
	}
	return nil
}

func (s *fecState) hasPending() bool { return s.encoder.hasPendingRepair() }

func (s *fecState) frameSent(frame wire.Frame, v protocol.Version) {
	if repair, ok := frame.(*wire.FECRepairFrame); ok {
		s.paritySent.Add(1)
		s.parityBytes.Add(uint64(repair.Length(v)))
	}
}

func (s *fecState) flushDeadline() monotime.Time { return s.encoder.flushDeadline() }

func (s *fecState) frameDropped() { s.droppedFrames.Add(1) }

// fecGroup is an FEC group that is currently being filled.
type fecGroup struct {
	id            uint64
	started       monotime.Time
	packetNumbers []protocol.PacketNumber
	lengths       []protocol.ByteCount
	maxLength     protocol.ByteCount
	maxPacketSize protocol.ByteCount // MTU at the time the group was opened
	// parity holds one accumulator per parity row. A member that is shorter than the
	// longest member of the group simply doesn't contribute to the tail, which is
	// exactly the zero-extension the receiver assumes.
	parity [][]byte
}

func (g *fecGroup) addPacket(pn protocol.PacketNumber, data []byte) {
	// Grow the accumulators first: a member that is longer than all previous members
	// extends the parity (this is the zero-extension the receiver assumes).
	if protocol.ByteCount(len(data)) > g.maxLength {
		g.maxLength = protocol.ByteCount(len(data))
		for row := range g.parity {
			accumulator := g.parity[row]
			if len(accumulator) < len(data) {
				g.parity[row] = append(accumulator, make([]byte, len(data)-len(accumulator))...)
			}
		}
	}
	for row := range g.parity {
		coefficient := fecCoefficient(row, len(g.packetNumbers))
		accumulator := g.parity[row]
		if coefficient == 1 {
			for i, b := range data {
				accumulator[i] ^= b
			}
			continue
		}
		for i, b := range data {
			accumulator[i] ^= gfMul(coefficient, b)
		}
	}
	g.packetNumbers = append(g.packetNumbers, pn)
	g.lengths = append(g.lengths, protocol.ByteCount(len(data)))
}

type fecEncoder struct {
	state  *fecState
	config FECConfig

	groupSize int // current target group size, 0 while FEC is idle
	rows      int // number of parity rows per group

	nextGroup uint64
	group     *fecGroup
	ready     []*wire.FECRepairFrame

	// overheadCap is MaxOverheadPercent as a fraction. A group is only protected when
	// its parity packets fit into this share of its own bytes.
	overheadCap float64
	// averageLength is an EWMA of the size of the packets that were protected most
	// recently. It lets the group size calculation account for the per-group frame
	// header, which is a fixed cost that would otherwise push a group that is
	// exactly at the cap over it.
	averageLength float64

	lossEWMA float64

	lastEvaluation monotime.Time

	feedbackSeen bool
	fbReceived   uint64
	fbLost       uint64
	fbRecovered  uint64
	fbFailed     uint64

	peerLoss     float64
	peerLossTime monotime.Time
}

// protecting says whether the encoder currently protects outgoing packets.
func (e *fecEncoder) protecting() bool {
	return e.groupSize >= e.config.MinGroupSize
}

// reserve is the number of bytes a FEC_REPAIR frame needs in the worst case for the
// configured maximum group size. Protected packets have to stay below maxPacketSize
// minus this reserve, so that the parity packet fits into a QUIC datagram.
func (e *fecEncoder) reserve() protocol.ByteCount {
	groupSize := protocol.ByteCount(e.config.MaxGroupSize)
	// frame type, group, row, row count, count, first packet number, parity length
	reserve := protocol.ByteCount(1 + 4 + 1 + 1 + 2 + 4 + 2)
	// packet number deltas: 1 byte varints (enforced by fecMaxPacketDelta)
	reserve += groupSize - 1
	// packet lengths: 2 byte varints (packets are smaller than 16384 bytes)
	reserve += groupSize * 2
	// slack for varints that may need one byte more than estimated
	reserve += 2
	return reserve
}

func (e *fecEncoder) flushDelay() time.Duration {
	return e.config.FlushDelay
}

func (e *fecEncoder) flushDeadline() monotime.Time {
	if e.group == nil {
		return 0
	}
	return e.group.started.Add(e.config.FlushDelay)
}

func (e *fecEncoder) hasPendingRepair() bool {
	return len(e.ready) > 0
}

// addPacket adds a packet that was just sent to the current FEC group.
// maxPacketSize is the maximum size of a QUIC packet (the MTU), not the (smaller)
// size limit that applies to FEC protected packets.
func (e *fecEncoder) addPacket(pn protocol.PacketNumber, data []byte, maxPacketSize protocol.ByteCount, now monotime.Time) {
	if !e.protecting() || len(data) == 0 {
		return
	}
	if protocol.ByteCount(len(data)) > maxPacketSize {
		// A packet that doesn't even fit into a datagram (shouldn't happen).
		e.closeGroup(e.group, maxPacketSize)
		e.group = nil
		return
	}
	if group := e.group; group != nil {
		if len(group.packetNumbers) >= e.groupSize ||
			pn-group.packetNumbers[len(group.packetNumbers)-1] > fecMaxPacketDelta {
			e.closeGroup(group, maxPacketSize)
			e.group = nil
		}
	}
	if e.group == nil {
		if e.rows < 1 {
			e.rows = 1
		}
		e.group = &fecGroup{
			id:            e.nextGroup,
			started:       now,
			maxPacketSize: maxPacketSize,
			parity:        make([][]byte, e.rows),
		}
		e.nextGroup++
		for row := range e.group.parity {
			e.group.parity[row] = make([]byte, 0, maxPacketSize)
		}
	}
	e.group.addPacket(pn, data)
	e.averageLength = fecLengthEWMAAlpha*float64(len(data)) + (1-fecLengthEWMAAlpha)*e.averageLength
	if len(e.group.packetNumbers) >= e.groupSize {
		// The group is complete: protect it right away.
		e.closeGroup(e.group, maxPacketSize)
		e.group = nil
	}
}

// closeGroup turns a group into FEC_REPAIR frames and queues them for sending.
//
// A group is only protected when its parity packets fit into MaxOverheadPercent of the
// group's own bytes, and into a datagram. Otherwise it is left unprotected: sending
// parity for it would break the bandwidth bound the configuration promises. Leaving a
// group unprotected is always safe - the packets are simply not recoverable by FEC,
// exactly as they would be with a smaller group or a larger FlushDelay.
//
// The check is per group rather than on a running budget on purpose. A group that
// cannot pay for its own parity - a burst tail of two packets, or packets so small that
// the FEC_REPAIR header dominates - is not worth protecting at any point, and letting
// credit accumulated earlier pay for it only spends the budget on repairs that are
// unlikely to succeed. Because every group stays within the cap, so does every
// aggregation of them, which is what makes the value in the statistics line verifiable.
func (e *fecEncoder) closeGroup(group *fecGroup, maxPacketSize protocol.ByteCount) {
	if group == nil || len(group.packetNumbers) < e.config.MinGroupSize {
		return
	}
	headerReserve := e.repairHeaderReserve(len(group.packetNumbers))
	if group.maxLength+headerReserve+fecMaxPacketOverhead > maxPacketSize {
		// The parity packet wouldn't fit into a datagram, short header and AEAD tag
		// included. Skip this group instead of queueing a frame that has to be dropped
		// again when it is packed.
		return
	}
	var protectedBytes int
	for _, length := range group.lengths {
		protectedBytes += int(length)
	}
	e.state.consideredBytes.Add(uint64(protectedBytes))
	parityBytes := (int(group.maxLength) + int(headerReserve)) * len(group.parity)
	if float64(parityBytes) > float64(protectedBytes)*e.overheadCap {
		e.state.skippedGroups.Add(1)
		return
	}
	for row := range group.parity {
		frame := &wire.FECRepairFrame{
			Group:             group.id,
			Row:               uint8(row),
			RowCount:          uint8(len(group.parity)),
			PacketCount:       uint64(len(group.packetNumbers)),
			FirstPacketNumber: group.packetNumbers[0],
			PacketNumbers:     group.packetNumbers,
			Lengths:           group.lengths,
			Parity:            group.parity[row],
		}
		e.ready = append(e.ready, frame)
	}
	if len(e.ready) > fecMaxReadyFrames {
		// The send queue stayed busy for long enough that parity frames piled up. Parity
		// older than the receiver's pending group window can't be repaired from anymore,
		// so drop the oldest instead of growing without bound.
		dropped := len(e.ready) - fecMaxReadyFrames
		e.ready = append(e.ready[:0], e.ready[dropped:]...)
		e.state.droppedFrames.Add(uint64(dropped))
	}
	e.state.protectedSent.Add(uint64(len(group.packetNumbers)))
	e.state.protectedBytes.Add(uint64(protectedBytes))
}

func (e *fecEncoder) repairHeaderReserve(groupSize int) protocol.ByteCount {
	if groupSize < 1 {
		return 0
	}
	return protocol.ByteCount(1+4+1+1+2+4+2) +
		protocol.ByteCount(groupSize-1) +
		protocol.ByteCount(groupSize*2) +
		2
}

// pendingRepair returns the next parity frame to send, if any. A partial group is
// closed (and protected) if it has been idle for longer than the flush delay.
func (e *fecEncoder) pendingRepair(now monotime.Time, maxPacketSize protocol.ByteCount) *wire.FECRepairFrame {
	if len(e.ready) > 0 {
		frame := e.ready[0]
		e.ready = e.ready[1:]
		return frame
	}
	if group := e.group; group != nil && !now.Before(group.started.Add(e.config.FlushDelay)) {
		e.closeGroup(group, maxPacketSize)
		e.group = nil
		if len(e.ready) > 0 {
			frame := e.ready[0]
			e.ready = e.ready[1:]
			return frame
		}
	}
	return nil
}

// tick re-evaluates the loss rate. The loss rate of the path is measured by the peer
// (it sees the gaps in the packet number sequence), so the loss rate decays towards
// zero if the peer's reports stop arriving.
func (e *fecEncoder) tick(now monotime.Time) {
	if !e.lastEvaluation.IsZero() && now.Sub(e.lastEvaluation) < fecEvaluationInterval {
		return
	}
	e.lastEvaluation = now
	var sample float64
	if !e.peerLossTime.IsZero() && now.Sub(e.peerLossTime) < fecPeerLossValidity {
		sample = e.peerLoss
	}
	e.updateLoss(sample)
}

// onFeedback processes a loss report of the peer. The counters are cumulative, so a
// lost feedback packet degrades nothing but the freshness of the report.
func (e *fecEncoder) onFeedback(feedback *wire.FECFeedbackFrame, now monotime.Time) {
	var deltaReceived, deltaLost uint64
	if !e.feedbackSeen {
		// The first report already carries the counters observed since the connection
		// was established, so it can be used right away.
		deltaReceived = feedback.ReceivedPackets
		deltaLost = feedback.LostPackets
	} else if feedback.ReceivedPackets >= e.fbReceived && feedback.LostPackets >= e.fbLost {
		deltaReceived = feedback.ReceivedPackets - e.fbReceived
		deltaLost = feedback.LostPackets - e.fbLost
	}
	if deltaReceived+deltaLost > 0 {
		lost := deltaLost
		if lost > deltaReceived+deltaLost {
			lost = deltaReceived + deltaLost
		}
		e.peerLoss = float64(lost) / float64(deltaReceived+deltaLost)
		e.peerLossTime = now
	}
	e.fbReceived = feedback.ReceivedPackets
	e.fbLost = feedback.LostPackets
	e.fbRecovered = feedback.RecoveredPackets
	e.fbFailed = feedback.FailedPackets
	e.feedbackSeen = true
	e.lastEvaluation = now
	e.updateLoss(e.peerLoss)
}

func (e *fecEncoder) updateLoss(sample float64) {
	if sample < 0 {
		sample = 0
	}
	e.lossEWMA = fecLossEWMAAlpha*sample + (1-fecLossEWMAAlpha)*e.lossEWMA
	e.state.setLossRate(e.lossEWMA)
	e.updateRedundancy()
}

// estimatedOverhead is the byte ratio of parity traffic to protected traffic a group
// of the given size and parity row count is expected to cost, including the
// FEC_REPAIR frame header. It falls back to the pure packet ratio while the average
// protected packet size is still unknown.
func (e *fecEncoder) estimatedOverhead(rows, groupSize int) float64 {
	if groupSize <= 0 {
		return 1
	}
	if e.averageLength <= 0 {
		return float64(rows) / float64(groupSize)
	}
	headerBytes := float64(e.repairHeaderReserve(groupSize))
	parityBytes := (e.averageLength + headerBytes) * float64(rows)
	protectedBytes := e.averageLength * float64(groupSize)
	return parityBytes / protectedBytes
}

func (e *fecEncoder) updateRedundancy() {
	overheadCap := float64(e.config.MaxOverheadPercent) / 100
	if e.lossEWMA < fecMinLossRate {
		// The path looks lossless: don't spend a single byte on redundancy.
		e.groupSize = 0
		e.rows = 1
		e.state.targetGroupSize.Store(0)
		e.state.parityRows.Store(1)
		return
	}
	// required is the redundancy the measured loss rate asks for, before it is capped
	// by the bandwidth budget. The rows decision is based on the uncapped value:
	// capping it first would make the double row branch unreachable at low caps.
	required := e.lossEWMA * fecLossSafetyFactor
	rows := 1
	if e.config.MaxParityRows > 1 &&
		(e.lossEWMA >= fecHighLossThreshold || required >= fecDoubleRowThreshold) &&
		// Two parity rows only fit into the overhead cap if the maximum group size is
		// large enough to pay for them.
		e.estimatedOverhead(2, e.config.MaxGroupSize) <= overheadCap {
		rows = 2
	}
	target := required
	if target > overheadCap {
		target = overheadCap
	}
	groupSize := int(math.Round(float64(rows) / target))
	if groupSize < e.config.MinGroupSize {
		groupSize = e.config.MinGroupSize
	}
	if groupSize > e.config.MaxGroupSize {
		groupSize = e.config.MaxGroupSize
	}
	// Never exceed the configured overhead cap. The estimate includes the FEC_REPAIR
	// frame header, so that a group which is exactly at the cap still has room for it
	// and isn't rejected by the per group check in closeGroup.
	for groupSize < e.config.MaxGroupSize && e.estimatedOverhead(rows, groupSize) > overheadCap {
		groupSize++
	}
	e.rows = rows
	e.groupSize = groupSize
	e.state.targetGroupSize.Store(int64(groupSize))
	e.state.parityRows.Store(int64(rows))
}

// GF(2^8) arithmetic, with the AES/Rijndael polynomial x^8 + x^4 + x^3 + x + 1.
var (
	gfExp [512]byte
	gfLog [256]byte
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
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfInv(a byte) byte {
	return gfExp[255-int(gfLog[a])]
}

// fecCoefficient returns the coefficient of the member at index member of a group for
// the parity row row. The coefficient matrix is a Vandermonde matrix over GF(2^8) with
// distinct bases: row 0 uses the base 1 (all coefficients are 1, i.e. a plain XOR of
// the protected packets), row 1 uses the base 2, row 2 the base 3, and so on. A
// Vandermonde matrix is MDS: any square submatrix is invertible, so any `rows` losses
// in a group can be reconstructed from `rows` parity rows.
func fecCoefficient(row, member int) byte {
	if row == 0 {
		return 1
	}
	return gfExp[(int(gfLog[byte(row+1)])*member)%255]
}

// fecXORScaled computes dst ^= coefficient * src. src may be shorter than dst, which
// realizes the zero-extension to the parity length.
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
	for i, b := range src {
		dst[i] ^= gfMul(coefficient, b)
	}
}

// fecScaleSlice multiplies a byte slice in place.
func fecScaleSlice(data []byte, factor byte) {
	if factor == 1 {
		return
	}
	for i, b := range data {
		data[i] = gfMul(factor, b)
	}
}

// fecRecoveredPacket is a packet that was reconstructed from parity.
type fecRecoveredPacket struct {
	packetNumber protocol.PacketNumber
	data         []byte
}

type fecPendingGroup struct {
	rows []*wire.FECRepairFrame
}

type fecDecoder struct {
	state  *fecState
	config FECConfig

	cache        map[protocol.PacketNumber][]byte
	order        []protocol.PacketNumber
	keyPhase     protocol.KeyPhaseBit
	haveKeyPhase bool

	pending      map[uint64]*fecPendingGroup
	pendingOrder []uint64

	// tracker measures the packet loss rate of the path, independently of whether
	// packets are FEC protected. This is what makes the sender engage FEC.
	tracker fecLossTracker

	feedbackTime     monotime.Time
	reportedReceived uint64
	reportedLost     uint64
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

func (d *fecDecoder) cacheSize() int {
	size := d.config.MaxGroupSize*2 + fecCacheSlack
	if size < 16 {
		size = 16
	}
	return size
}

func (d *fecDecoder) reset() {
	d.cache = nil
	d.order = nil
	d.pending = nil
	d.pendingOrder = nil
}

func (d *fecDecoder) recordPacket(pn protocol.PacketNumber, data []byte, keyPhase protocol.KeyPhaseBit) {
	d.tracker.record(pn)
	if d.haveKeyPhase && keyPhase != d.keyPhase {
		// Packets of the previous key phase can't be decrypted anymore.
		d.reset()
	}
	d.keyPhase = keyPhase
	d.haveKeyPhase = true
	if d.cache == nil {
		d.cache = make(map[protocol.PacketNumber][]byte)
	}
	if _, ok := d.cache[pn]; ok {
		return
	}
	buffer := make([]byte, len(data))
	copy(buffer, data)
	d.cache[pn] = buffer
	d.order = append(d.order, pn)
	for len(d.order) > d.cacheSize() {
		evicted := d.order[0]
		d.order = d.order[1:]
		delete(d.cache, evicted)
	}
}

// handleRepair processes an incoming parity row, reconstructing the packets of the
// group that are missing. Packets that are still in flight may be "recovered" as
// well; the duplicate that arrives later is dropped by the regular duplicate
// detection of the connection.
func (d *fecDecoder) handleRepair(frame *wire.FECRepairFrame, now monotime.Time) []fecRecoveredPacket {
	d.state.parityRecv.Add(1)
	if d.pending == nil {
		d.pending = make(map[uint64]*fecPendingGroup)
	}
	group, ok := d.pending[frame.Group]
	if !ok {
		group = &fecPendingGroup{}
		d.pending[frame.Group] = group
		d.pendingOrder = append(d.pendingOrder, frame.Group)
		d.state.protectedRecv.Add(frame.PacketCount)
		for len(d.pendingOrder) > fecMaxPendingGroups {
			evicted := d.pendingOrder[0]
			d.pendingOrder = d.pendingOrder[1:]
			delete(d.pending, evicted)
		}
	}
	group.rows = append(group.rows, frame)

	var missing []int
	if d.cache != nil {
		for i, pn := range frame.PacketNumbers {
			if _, ok := d.cache[pn]; !ok {
				missing = append(missing, i)
			}
		}
	} else {
		missing = make([]int, len(frame.PacketNumbers))
		for i := range missing {
			missing[i] = i
		}
	}
	if len(missing) == 0 {
		delete(d.pending, frame.Group)
		return nil
	}
	rows := d.pendingRows(group, frame)
	if len(rows) < len(missing) && len(rows) < int(frame.RowCount) {
		// More parity rows of this group may still arrive.
		return nil
	}
	if len(rows) < len(missing) {
		d.state.failedRecv.Add(uint64(len(missing)))
		delete(d.pending, frame.Group)
		return nil
	}
	recovered := fecRecover(rows, frame, missing, d.cache)
	if len(recovered) != len(missing) {
		d.state.failedRecv.Add(uint64(len(missing)))
	} else {
		d.state.recoveredRecv.Add(uint64(len(recovered)))
	}
	delete(d.pending, frame.Group)
	return recovered
}

// pendingRows returns the parity rows of the group, highest row first.
func (d *fecDecoder) pendingRows(group *fecPendingGroup, frame *wire.FECRepairFrame) []*wire.FECRepairFrame {
	rows := make([]*wire.FECRepairFrame, 0, len(group.rows))
	for i := len(group.rows) - 1; i >= 0; i-- {
		rows = append(rows, group.rows[i])
	}
	return rows
}

// fecRecover reconstructs the missing packets of a group.
func fecRecover(rows []*wire.FECRepairFrame, frame *wire.FECRepairFrame, missing []int, cache map[protocol.PacketNumber][]byte) []fecRecoveredPacket {
	count := int(frame.PacketCount)
	parityLength := len(frame.Parity)
	// Build the right hand sides: the parity rows with the contributions of all
	// received packets of the group removed.
	rhs := make([][]byte, len(missing))
	for i := range rhs {
		rhs[i] = make([]byte, parityLength)
	}
	used := rows[:len(missing)]
	for rowIndex, row := range used {
		copy(rhs[rowIndex], row.Parity)
		for member := 0; member < count; member++ {
			if isMissing(missing, member) {
				continue
			}
			data, ok := cache[frame.PacketNumbers[member]]
			if !ok {
				continue
			}
			fecXORScaled(rhs[rowIndex], data, fecCoefficient(int(row.Row), member))
		}
	}
	// Build the coefficient matrix and solve it with Gauss-Jordan elimination.
	matrix := make([][]byte, len(missing))
	for i := range matrix {
		matrix[i] = make([]byte, len(missing))
		for j := range matrix[i] {
			matrix[i][j] = fecCoefficient(int(used[i].Row), missing[j])
		}
	}
	if !fecSolve(matrix, rhs) {
		return nil
	}
	recovered := make([]fecRecoveredPacket, 0, len(missing))
	for i, member := range missing {
		length := frame.Lengths[member]
		if protocol.ByteCount(len(rhs[i])) < length {
			return nil
		}
		data := make([]byte, length)
		copy(data, rhs[i][:length])
		recovered = append(recovered, fecRecoveredPacket{
			packetNumber: frame.PacketNumbers[member],
			data:         data,
		})
	}
	return recovered
}

func isMissing(missing []int, member int) bool {
	for _, m := range missing {
		if m == member {
			return true
		}
	}
	return false
}

// fecSolve solves the linear system matrix * X = rhs over GF(2^8) in place.
// On success, rhs holds the solution.
func fecSolve(matrix [][]byte, rhs [][]byte) bool {
	size := len(matrix)
	for col := range size {
		pivot := -1
		for row := col; row < size; row++ {
			if matrix[row][col] != 0 {
				pivot = row
				break
			}
		}
		if pivot < 0 {
			return false
		}
		if pivot != col {
			matrix[pivot], matrix[col] = matrix[col], matrix[pivot]
			rhs[pivot], rhs[col] = rhs[col], rhs[pivot]
		}
		if factor := matrix[col][col]; factor != 1 {
			inverse := gfInv(factor)
			for j := col; j < size; j++ {
				matrix[col][j] = gfMul(matrix[col][j], inverse)
			}
			fecScaleSlice(rhs[col], inverse)
		}
		for row := range size {
			if row == col {
				continue
			}
			factor := matrix[row][col]
			if factor == 0 {
				continue
			}
			for j := col; j < size; j++ {
				matrix[row][j] ^= gfMul(factor, matrix[col][j])
			}
			fecXORScaled(rhs[row], rhs[col], factor)
		}
	}
	return true
}

// pendingFeedback returns a feedback frame if a new loss report is due. The loss rate
// of the path is measured locally (packet number gaps), so reports are sent even
// while FEC is idle: they are what makes the sender engage FEC in the first place.
func (d *fecDecoder) pendingFeedback(now monotime.Time) *wire.FECFeedbackFrame {
	if !d.tracker.initialized {
		return nil
	}
	if !d.feedbackTime.IsZero() && now.Sub(d.feedbackTime) < fecFeedbackInterval {
		return nil
	}
	if d.tracker.received == d.reportedReceived && d.tracker.lost == d.reportedLost {
		return nil
	}
	d.feedbackTime = now
	d.reportedReceived = d.tracker.received
	d.reportedLost = d.tracker.lost
	return &wire.FECFeedbackFrame{
		ReceivedPackets:  d.tracker.received,
		LostPackets:      d.tracker.lost,
		RecoveredPackets: d.state.recoveredRecv.Load(),
		FailedPackets:    d.state.failedRecv.Load(),
		ParityPackets:    d.state.parityRecv.Load(),
	}
}
