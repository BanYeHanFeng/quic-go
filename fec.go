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
	defaultFECMaxGroupSize       = 16
	defaultFECMinGroupSize       = 2
	defaultFECMaxOverheadPercent = 10
	defaultFECMaxParityRows      = 1
	defaultFECFlushDelay         = 2 * time.Millisecond

	// fecMinLossRate is the loss rate above which FEC engages. Below this threshold
	// the connection is treated as lossless, and no redundancy is sent at all.
	fecMinLossRate = 0.002
	// fecLossSafetyFactor is applied to the measured loss rate when computing the
	// amount of redundancy: protecting against 1.5x the observed loss.
	fecLossSafetyFactor = 1.5
	fecLossEWMAAlpha    = 0.3
	// fecHighLossThreshold is the loss rate above which a second parity row is used
	// (if allowed by the configuration), which makes the group survive two losses.
	fecHighLossThreshold = 0.12

	fecFeedbackMinProtected = 8
	fecFeedbackInterval     = 50 * time.Millisecond
	// fecEvaluationInterval is how often the sender re-evaluates the loss rate.
	fecEvaluationInterval = 30 * time.Millisecond
	// fecPeerLossValidity is how long a loss report from the peer is considered
	// current. While FEC is repairing packets, the sender itself sees no loss at all,
	// so the report of the peer is what keeps FEC engaged.
	fecPeerLossValidity = 150 * time.Millisecond

	fecMaxPendingGroups = 8
	fecCacheSlack       = 16
	// fecMaxPacketDelta is the maximum packet number distance inside one FEC group.
	// Keeping it below 64 guarantees that packet number deltas fit into 1 byte varints.
	fecMaxPacketDelta = 63
)

// FECConfig configures packet level forward error correction for a connection.
// The zero value is a valid configuration: MaxOverheadPercent defaults to 10%,
// MaxGroupSize to 16, MinGroupSize to 2 and MaxParityRows to 1 (plain XOR parity).
type FECConfig struct {
	// MaxOverheadPercent caps the parity traffic as a percentage of the protected
	// traffic. It bounds the bandwidth FEC is allowed to spend, no matter how high
	// the measured loss rate is. Defaults to 10.
	MaxOverheadPercent int
	// MaxGroupSize is the maximum number of packets protected by one FEC group.
	// Larger groups reduce the relative overhead, but increase the time until a
	// lost packet can be repaired. Defaults to 16.
	MaxGroupSize int
	// MinGroupSize is the smallest group the sender is willing to protect. Partial
	// groups smaller than this are not protected. Defaults to 2.
	MinGroupSize int
	// MaxParityRows is the maximum number of parity rows sent per group. With 1 row
	// a group survives a single loss (XOR parity, "RAID 5" style), with 2 rows it
	// survives two losses ("RAID 6" style, Reed-Solomon over GF(2^8)). Defaults to 1.
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
		c.MaxGroupSize = defaultFECMaxGroupSize
	}
	if c.MaxGroupSize > wire.MaxFECGroupSize {
		c.MaxGroupSize = wire.MaxFECGroupSize
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

// FECStats reports the state of the packet level FEC of a connection.
type FECStats struct {
	Enabled      bool
	GroupSize    int     // current target group size, 0 if FEC is currently idle
	ParityRows   int     // number of parity rows per group
	LossRate     float64 // smoothed loss rate observed on the path
	SendOverhead float64 // parity bytes / protected bytes, as currently configured

	ProtectedPacketsSent     uint64
	ParityPacketsSent        uint64
	ParityBytesSent          uint64
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

	protectedSent atomic.Uint64
	paritySent    atomic.Uint64
	parityBytes   atomic.Uint64

	protectedRecv atomic.Uint64
	recoveredRecv atomic.Uint64
	failedRecv    atomic.Uint64
	parityRecv    atomic.Uint64
}

func newFECState(config FECConfig) *fecState {
	config = config.withDefaults()
	state := &fecState{config: config}
	state.encoder = &fecEncoder{state: state, config: config}
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

// EnableFEC enables packet level forward error correction for this connection.
//
// Both peers need to enable FEC. Enablement is not negotiated by quic-go itself
// (QUICX negotiates it in its own handshake), so that no additional transport
// parameter shows up in the ClientHello and the HTTP/3 fingerprint is preserved.
// FEC_FEEDBACK and FEC_REPAIR frames of a peer that enabled FEC earlier are ignored,
// so enabling FEC on one side only does not break the connection.
func (c *Conn) EnableFEC(config FECConfig) error {
	select {
	case <-c.handshakeCompleteChan:
	default:
		return &FECError{Message: "FEC can only be enabled after the handshake completed"}
	}
	c.fecState.Store(newFECState(config))
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
	state := c.fecState.Load()
	if state == nil {
		return FECStats{}
	}
	return state.stats()
}

func (s *fecState) stats() FECStats {
	groupSize := int(s.targetGroupSize.Load())
	rows := int(s.parityRows.Load())
	stats := FECStats{
		Enabled:                  true,
		GroupSize:                groupSize,
		ParityRows:               rows,
		LossRate:                 s.lossRate(),
		ProtectedPacketsSent:     s.protectedSent.Load(),
		ParityPacketsSent:        s.paritySent.Load(),
		ParityBytesSent:          s.parityBytes.Load(),
		ProtectedPacketsReceived: s.protectedRecv.Load(),
		RecoveredPackets:         s.recoveredRecv.Load(),
		FailedPackets:            s.failedRecv.Load(),
		ParityPacketsReceived:    s.parityRecv.Load(),
	}
	if groupSize > 0 && rows > 0 {
		stats.SendOverhead = float64(rows) / float64(groupSize)
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
// FEC. FEC_REPAIR frames are at most as long as the longest protected packet plus the
// header that describes the group, so protected packets have to leave room for it.
func (c *Conn) dataPacketSizeLimit() protocol.ByteCount {
	maxPacketSize := c.maxPacketSize()
	state := c.fecState.Load()
	if state == nil || !state.encoder.protecting() {
		return maxPacketSize
	}
	reserve := state.encoder.reserve()
	if reserve >= maxPacketSize {
		return maxPacketSize
	}
	return maxPacketSize - reserve
}

// fecRecordSentPacket hands a packet that was just written to the wire to the FEC
// encoder, and lets the encoder re-evaluate the loss rate. The evaluation has to
// happen even while FEC is idle: the sender's own loss counters are what engages
// FEC in the first place. (While FEC is repairing, those counters stay quiet - then
// the peer's feedback keeps it engaged.)
func (c *Conn) fecRecordSentPacket(pn protocol.PacketNumber, data []byte, maxPacketSize protocol.ByteCount, now monotime.Time) {
	state := c.fecState.Load()
	if state == nil {
		return
	}
	state.encoder.evaluate(now, c.connStats.PacketsSent.Load(), c.connStats.PacketsLost.Load(), false)
	if !state.encoder.protecting() {
		return
	}
	state.encoder.addPacket(pn, data, maxPacketSize, now)
}

// fecRecordReceivedPacket caches a received packet for FEC recovery.
func (c *Conn) fecRecordReceivedPacket(pn protocol.PacketNumber, data []byte, keyPhase protocol.KeyPhaseBit) {
	state := c.fecState.Load()
	if state == nil {
		return
	}
	state.decoder.recordPacket(pn, data, keyPhase)
}

func (c *Conn) handleFECRepairFrame(frame *wire.FECRepairFrame, rcvTime monotime.Time) error {
	state := c.fecState.Load()
	if state == nil {
		// FEC wasn't enabled (locally): ignore the parity packet. This happens when
		// the peer enabled FEC before we did, or when one side is misconfigured.
		return nil
	}
	for _, recovered := range state.decoder.handleRepair(frame, rcvTime) {
		buffer := getPacketBuffer()
		buffer.Data = append(buffer.Data, recovered.data...)
		c.handlePacket(receivedPacket{
			buffer:     buffer,
			data:       buffer.Data,
			rcvTime:    rcvTime,
			remoteAddr: c.conn.RemoteAddr(),
			ecn:        protocol.ECNNon,
		})
	}
	return nil
}

func (c *Conn) handleFECFeedbackFrame(frame *wire.FECFeedbackFrame, rcvTime monotime.Time) {
	state := c.fecState.Load()
	if state == nil {
		return
	}
	state.encoder.onFeedback(frame, c.connStats.PacketsSent.Load(), c.connStats.PacketsLost.Load(), rcvTime)
}

// fecFlushDeadline returns the time at which an open (partial) FEC group should be
// protected, or a zero time if no group is open.
func (c *Conn) fecFlushDeadline() monotime.Time {
	state := c.fecState.Load()
	if state == nil {
		return 0
	}
	return state.encoder.flushDeadline()
}

// maybeSendFECPackets sends at most one pending FEC packet (a parity packet or a
// feedback frame). It reports whether a packet was sent.
func (c *Conn) maybeSendFECPackets(now monotime.Time) (bool, error) {
	state := c.fecState.Load()
	if state == nil {
		return false, nil
	}
	if frame := state.encoder.pendingRepair(now, c.maxPacketSize()); frame != nil {
		if err := c.sendFECFrame(state, frame, now); err != nil {
			return false, err
		}
		if state.encoder.hasPendingRepair() {
			c.scheduleSending()
		}
		return true, nil
	}
	if frame := state.decoder.pendingFeedback(now); frame != nil {
		if err := c.sendFECFrame(state, frame, now); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func (c *Conn) sendFECFrame(state *fecState, frame wire.Frame, now monotime.Time) error {
	ecn := c.sentPacketHandler.ECNMode(true)
	packet, buf, err := c.packer.PackFECPacket(frame, c.maxPacketSize(), now, c.version)
	if err != nil {
		if err == errNothingToPack || err == errFECFrameTooLarge {
			return nil
		}
		return err
	}
	c.logShortHeaderPacket(packet, ecn, buf.Len())
	c.registerPackedShortHeaderPacket(packet, ecn, now)
	c.sendQueue.Send(buf, 0, ecn)
	if repair, ok := frame.(*wire.FECRepairFrame); ok {
		state.paritySent.Add(1)
		state.parityBytes.Add(uint64(repair.Length(c.version)))
	}
	return nil
}

// fecGroup is an FEC group that is currently being filled.
type fecGroup struct {
	id            uint64
	started       monotime.Time
	packetNumbers []protocol.PacketNumber
	lengths       []protocol.ByteCount
	maxLength     protocol.ByteCount
	maxPacketSize protocol.ByteCount
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

	lossEWMA float64

	lastEvaluation  monotime.Time
	lastSentPackets uint64
	lastLostPackets uint64

	feedbackSeen bool
	fbProtected  uint64
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
func (e *fecEncoder) addPacket(pn protocol.PacketNumber, data []byte, maxPacketSize protocol.ByteCount, now monotime.Time) {
	if !e.protecting() || len(data) == 0 {
		return
	}
	if protocol.ByteCount(len(data)) > maxPacketSize {
		// Too large to be protected (this can happen when the packet size limit
		// changed while the group was open). Start a new group instead of producing
		// a parity packet that doesn't fit into a datagram.
		e.closeGroup(e.group, maxPacketSize)
		e.group = nil
		return
	}
	if group := e.group; group != nil {
		if len(group.packetNumbers) >= e.groupSize ||
			pn-group.packetNumbers[len(group.packetNumbers)-1] > fecMaxPacketDelta ||
			group.maxPacketSize != maxPacketSize {
			e.closeGroup(group, group.maxPacketSize)
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
	if len(e.group.packetNumbers) >= e.groupSize {
		// The group is complete: protect it right away.
		e.closeGroup(e.group, e.group.maxPacketSize)
		e.group = nil
	}
}

// closeGroup turns a group into FEC_REPAIR frames and queues them for sending.
func (e *fecEncoder) closeGroup(group *fecGroup, maxPacketSize protocol.ByteCount) {
	if group == nil || len(group.packetNumbers) < e.config.MinGroupSize {
		return
	}
	headerReserve := e.repairHeaderReserve(len(group.packetNumbers))
	if group.maxLength+headerReserve > maxPacketSize {
		// The parity packet wouldn't fit into a datagram. Skip this group instead of
		// sending a packet that can't be transmitted.
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
	e.state.protectedSent.Add(uint64(len(group.packetNumbers)))
}

func (e *fecEncoder) repairHeaderReserve(groupSize int) protocol.ByteCount {
	if groupSize < 1 {
		return 0
	}
	return protocol.ByteCount(1 + 4 + 1 + 1 + 2 + 4 + 2) +
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
		e.closeGroup(group, group.maxPacketSize)
		e.group = nil
		if len(e.ready) > 0 {
			frame := e.ready[0]
			e.ready = e.ready[1:]
			return frame
		}
	}
	return nil
}

// flush forces the current group to be protected, e.g. when the connection goes idle.
func (e *fecEncoder) flush() {
	if e.group == nil {
		return
	}
	group := e.group
	e.group = nil
	e.closeGroup(group, group.maxPacketSize)
}

// evaluate updates the smoothed loss rate and recomputes the redundancy.
//
// The loss rate is the maximum of
//   - the loss the sender itself observed (packets that were never acknowledged, i.e.
//     packets that FEC failed to repair), and
//   - the loss reported by the peer, which includes packets that FEC did repair.
//
// The second component is what keeps FEC engaged while it is working; the first one
// is what engages FEC in the first place (while FEC is idle, the peer sees no
// protected packets, and therefore has nothing to report).
func (e *fecEncoder) evaluate(now monotime.Time, sentPackets, lostPackets uint64, force bool) {
	if !force && !e.lastEvaluation.IsZero() && now.Sub(e.lastEvaluation) < fecEvaluationInterval {
		return
	}
	var selfLoss float64
	if sentPackets > e.lastSentPackets {
		deltaSent := sentPackets - e.lastSentPackets
		deltaLost := uint64(0)
		if lostPackets > e.lastLostPackets {
			deltaLost = lostPackets - e.lastLostPackets
		}
		if deltaLost > deltaSent {
			deltaLost = deltaSent
		}
		selfLoss = float64(deltaLost) / float64(deltaSent)
	}
	e.lastSentPackets = sentPackets
	e.lastLostPackets = lostPackets
	e.lastEvaluation = now

	var peerLoss float64
	if !e.peerLossTime.IsZero() && now.Sub(e.peerLossTime) < fecPeerLossValidity {
		peerLoss = e.peerLoss
	}
	sample := max(selfLoss, peerLoss)
	if sample > 0 || e.lossEWMA > 0 {
		e.lossEWMA = fecLossEWMAAlpha*sample + (1-fecLossEWMAAlpha)*e.lossEWMA
	}
	e.state.setLossRate(e.lossEWMA)
	e.updateRedundancy()
}

func (e *fecEncoder) onFeedback(feedback *wire.FECFeedbackFrame, sentPackets, lostPackets uint64, now monotime.Time) {
	if e.feedbackSeen && feedback.ProtectedPackets >= e.fbProtected {
		if deltaProtected := feedback.ProtectedPackets - e.fbProtected; deltaProtected > 0 {
			deltaRecovered := uint64(0)
			if feedback.RecoveredPackets > e.fbRecovered {
				deltaRecovered = feedback.RecoveredPackets - e.fbRecovered
			}
			deltaFailed := uint64(0)
			if feedback.FailedPackets > e.fbFailed {
				deltaFailed = feedback.FailedPackets - e.fbFailed
			}
			lost := deltaRecovered + deltaFailed
			if lost > deltaProtected {
				lost = deltaProtected
			}
			e.peerLoss = float64(lost) / float64(deltaProtected)
			e.peerLossTime = now
		}
	}
	e.fbProtected = feedback.ProtectedPackets
	e.fbRecovered = feedback.RecoveredPackets
	e.fbFailed = feedback.FailedPackets
	e.feedbackSeen = true
	e.evaluate(now, sentPackets, lostPackets, true)
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
	target := e.lossEWMA * fecLossSafetyFactor
	if target > overheadCap {
		target = overheadCap
	}
	rows := 1
	if e.lossEWMA >= fecHighLossThreshold || target > 0.25 {
		if e.config.MaxParityRows > 1 && float64(2)/float64(e.config.MaxGroupSize) <= overheadCap {
			rows = 2
			target = e.lossEWMA * fecLossSafetyFactor
			if target > overheadCap {
				target = overheadCap
			}
		}
	}
	groupSize := int(math.Round(float64(rows) / target))
	if groupSize < e.config.MinGroupSize {
		groupSize = e.config.MinGroupSize
	}
	if groupSize > e.config.MaxGroupSize {
		groupSize = e.config.MaxGroupSize
	}
	// Never exceed the configured overhead cap.
	for groupSize < e.config.MaxGroupSize && float64(rows)/float64(groupSize) > overheadCap {
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

	feedbackPending   bool
	feedbackProtected uint64
	feedbackTime      monotime.Time
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
		d.feedbackProtected += frame.PacketCount
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
		d.maybeQueueFeedback(now)
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
		d.maybeQueueFeedback(now)
		return nil
	}
	recovered := fecRecover(rows, frame, missing, d.cache)
	if len(recovered) != len(missing) {
		d.state.failedRecv.Add(uint64(len(missing)))
	} else {
		d.state.recoveredRecv.Add(uint64(len(recovered)))
	}
	delete(d.pending, frame.Group)
	d.maybeQueueFeedback(now)
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

func (d *fecDecoder) maybeQueueFeedback(now monotime.Time) {
	if d.feedbackPending {
		return
	}
	if d.feedbackProtected < fecFeedbackMinProtected {
		return
	}
	if !d.feedbackTime.IsZero() && now.Sub(d.feedbackTime) < fecFeedbackInterval {
		return
	}
	d.feedbackPending = true
}

func (d *fecDecoder) pendingFeedback(now monotime.Time) *wire.FECFeedbackFrame {
	if !d.feedbackPending {
		return nil
	}
	d.feedbackPending = false
	d.feedbackProtected = 0
	d.feedbackTime = now
	return &wire.FECFeedbackFrame{
		ProtectedPackets: d.state.protectedRecv.Load(),
		RecoveredPackets: d.state.recoveredRecv.Load(),
		FailedPackets:    d.state.failedRecv.Load(),
		ParityPackets:    d.state.parityRecv.Load(),
	}
}
