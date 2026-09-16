package quic

import (
	"math"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/wire"
)

// Sliding window (convolutional) packet level forward error correction.
//
// This is the packet level FEC scheme of the fork, used by sing-box QUICX. It
// replaced the group based block scheme the fork used to have, which had two
// structural weaknesses on the paths QUICX is used on:
//
//   - All or nothing per group. The sender protected a closed group of k packets with
//     a fixed number of parity rows m. A group that lost more than m packets was not
//     partly repaired, it was not repaired at all: every missing packet of the group
//     fell back to a retransmission. Mobile paths lose packets in bursts, so the
//     number of unrecoverable packets stayed high even though most groups only lost
//     one or two packets.
//   - Cost of the group tail. A group was only worth protecting when its parity fit
//     into the overhead cap. The last packets before an idle period, and the packets of
//     a low rate flow, ended up in small groups that could not pay for their own
//     parity, so they were skipped - on a path that is losing packets exactly at those
//     moments.
//
// The sliding window scheme replaces the group with a window of the most recent
// packets and emits one repair row for it at the configured redundancy. Successive
// rows protect overlapping windows, so every packet is covered by many rows instead of
// m: a packet that leaves the window has been covered by window*redundancy rows, which
// makes a burst of losses recoverable row by row, and a row that cannot be used is
// superseded by the next one instead of leaving the packet unprotected.
//
// The decoder keeps the equations of the rows it received. A row that reduces to a
// single unknown (either directly, or after the packets that arrived late were
// substituted, or after another row eliminated one of its unknowns) reconstructs that
// packet immediately; the packet is then treated like a packet that arrived on the
// wire, so later rows use it as a known symbol. This is the same "on the fly" decoding
// that RFC 9407 (Tetrys) describes for an elastic encoding window, with the window
// here being a fixed number of the most recently sent packets.
//
// Coefficients. A repair row combines the packets of its window with the coefficients
// of a Cauchy matrix: coefficient(row, position) = 1 / (x[row] + y[position]), with the
// row bases x and the position bases y taken from two disjoint halves of the nonzero
// elements of GF(2^8). Every square submatrix of a Cauchy matrix is invertible, so any
// `n` rows reconstruct any `n` members of the window - the code is MDS for every loss
// pattern, not only for the patterns that keep the message symbols contiguous.

const (
	// defaultFECWindowSize is the number of packets one window protects, unless the
	// configuration asks for another size. A window row is superseded by the rows that
	// follow it, so a large window trades memory for burst tolerance, not recovery
	// latency.
	//
	// It is the largest window the wire format has, because the window size is what
	// bounds the burst a reactive scheme can repair at all. The sender can only start
	// repairing after the peer reported the loss, and every row it then spends costs
	// 1/rate packets of the window's lifetime, so the longest burst a window can
	// reconstruct is about
	//
	//	window * cap / (1 + cap)
	//
	// packets: about 5.8 at the default 10% cap with a 64 packet window, about 11.6 at
	// 128. Mobile paths lose in bursts of that order, and a burst longer than the
	// window can reconstruct is not partly repaired - the packets that fall out of the
	// window before a row covers them are lost to a retransmission. The larger window
	// also halves the repair frame header each protected packet pays for, because a row
	// is as long as the longest packet of its window either way.
	defaultFECWindowSize = 128
	// fecWindowMaxFlushRows bounds the number of rows an idle sender emits for the tail
	// of its window.
	fecWindowMaxFlushRows = 2
	// fecWindowMinMembers is the smallest window the sender protects. A row over a
	// single packet would just duplicate it.
	fecWindowMinMembers = 2
	// fecWindowMaxReadyFrames bounds the repair frames waiting to be sent. The send
	// queue is bounded, so a saturated sender can fall behind; a row for a window that
	// has already left the receiver can't repair anything, so the oldest ones are
	// dropped instead of being held in memory.
	fecWindowMaxReadyFrames = 8
	// fecWindowMaxPendingRows bounds the equations the decoder keeps. A row whose
	// unknowns never become solvable is useless, and the rows are superseded by the
	// rows that follow them. It also bounds the work of one decoding pass, which is
	// quadratic in the number of rows.
	fecWindowMaxPendingRows = 16
	// fecWindowCreditLimit bounds the parity bytes the sender may spend out of the
	// credit it accumulated while the path looked lossless. The long term overhead
	// stays within the cap because the credit accrues at the cap; the limit only keeps
	// a long clean period from paying for one large burst later.
	fecWindowCreditLimit = 32 * 1024
	// fecWindowRateMargin leaves a little room between the redundancy the overhead cap
	// allows and the redundancy the sender aims for, so that a row is never refused
	// because of rounding.
	fecWindowRateMargin = 0.95
	// fecWindowLossPeakHold is how long the highest loss rate of a burst keeps driving
	// the redundancy after it was reported. A mobile path loses packets in short
	// bursts: the peer reports one high loss rate for the burst, and the reports that
	// follow are clean again. Without the hold the loss estimate decays within a few
	// evaluation intervals - the example below - and the sender stops spending rows
	// while the packets of the burst are still inside the window, which is exactly when
	// they could still be reconstructed.
	//
	//	15% reported -> 4.5% after 30ms -> 1.4% after 60ms -> 0.4% after 90ms
	//
	// A row repairs one packet, so a burst costs one row per packet it lost, and a row
	// is only emitted every 1/rate protected packets. The hold therefore has to last
	// for the packets those rows are paid out of, which is what makes it a second
	// rather than a few evaluation intervals: a burst of ten packets needs about 106
	// protected packets at the 10% cap, and a path that carries 150 packets per second
	// needs about 700ms for them. Holding longer costs nothing on a clean path - the
	// rate the redundancy follows decays with the reports, and the byte credit stops
	// the spend - while ending the hold early gives up on part of the burst, because
	// the rows that were never emitted cannot repair anything later.
	fecWindowLossPeakHold = time.Second
	// fecWindowLengthEWMAAlpha is the weight of the newest packet when tracking the
	// average protected packet size, which the redundancy calculation uses to keep the
	// frame header inside the overhead cap.
	fecWindowLengthEWMAAlpha = 0.2
	// fecWindowMissingTimeout is how long a packet the peer protects may stay missing
	// before the decoder gives up on it and counts it as unrecoverable.
	fecWindowMissingTimeout = time.Second
	// fecWindowCacheSlack is the number of packets the decoder caches on top of two
	// windows: rows can only reference packets that are still in the sender's window,
	// but packets arrive out of order.
	fecWindowCacheSlack = 32
	// fecWindowCauchyRows is the number of distinct row bases of the Cauchy matrix. Two
	// rows that are this many rows apart use the same base; they never share a member
	// unless the redundancy is far above the configured cap.
	fecWindowCauchyRows = 64
	// fecWindowFrameBaseBytes is the part of a window repair frame that doesn't depend
	// on the window: frame type, row, first packet number, span, member count, parity
	// length and the length parity.
	fecWindowFrameBaseBytes = 1 + 4 + 8 + 4 + 2 + 2 + 2
)

// fecWindowCoefficient returns the coefficient of the member at the given position of
// the window for the repair row with the given number.
//
// The coefficients form a Cauchy matrix over GF(2^8): 1/(x + y), with the row base x
// taken from alpha^0..alpha^63 and the position base y from alpha^64..alpha^191. The
// two sets are disjoint, so no denominator is zero, and Cauchy's determinant formula
// (all x distinct, all y distinct, no x equal to a y) says that every square submatrix
// of the matrix is invertible. That is what makes the code MDS: any n rows recover any
// n lost members of the window, whatever their positions.
func fecWindowCoefficient(row uint64, position int) byte {
	x := gfExp[int(row%fecWindowCauchyRows)]
	y := gfExp[fecWindowCauchyRows+position]
	return gfInv(x ^ y)
}

// fecWindowFrameBytes is the size of a window repair frame over a window whose member
// packet numbers span span packet numbers, excluding the parity payload.
func fecWindowFrameBytes(span uint64) protocol.ByteCount {
	// One byte of slack for each varint that can grow by a byte.
	return fecWindowFrameBaseBytes + protocol.ByteCount((span+7)/8) + 4
}

// fecWindowState holds the sliding window FEC state of a connection: the encoder on
// the send path, the decoder on the receive path. Both are only accessed from the
// connection's run loop goroutine. The statistics are read from other goroutines
// (FECStats), and are therefore atomic.
type fecWindowState struct {
	config  FECConfig
	encoder *fecWindowEncoder
	decoder *fecWindowDecoder

	lossBits   atomic.Uint64 // math.Float64bits of the smoothed loss rate
	windowSize atomic.Int64  // configured window size while FEC is active, 0 while idle

	protectedSent  atomic.Uint64
	protectedBytes atomic.Uint64
	paritySent     atomic.Uint64
	parityBytes    atomic.Uint64
	skippedRows    atomic.Uint64
	droppedFrames  atomic.Uint64

	protectedRecv atomic.Uint64
	recoveredRecv atomic.Uint64
	failedRecv    atomic.Uint64
	parityRecv    atomic.Uint64
}

func newFECWindowState(config FECConfig) *fecWindowState {
	config = config.withDefaults()
	state := &fecWindowState{config: config}
	state.encoder = newFECWindowEncoder(state, config)
	state.decoder = newFECWindowDecoder(state, config)
	return state
}

func (s *fecWindowState) setLossRate(loss float64) {
	s.lossBits.Store(math.Float64bits(loss))
}

func (s *fecWindowState) lossRate() float64 {
	return math.Float64frombits(s.lossBits.Load())
}

func (s *fecWindowState) stats() FECStats {
	rate := math.Float64frombits(s.encoder.rateBits.Load())
	protectedBytes := s.protectedBytes.Load()
	parityBytes := s.parityBytes.Load()
	stats := FECStats{
		Enabled:                  true,
		WindowSize:               int(s.windowSize.Load()),
		LossRate:                 s.lossRate(),
		RedundancyRate:           rate,
		ProtectedPacketsSent:     s.protectedSent.Load(),
		ProtectedBytesSent:       protectedBytes,
		ParityPacketsSent:        s.paritySent.Load(),
		ParityBytesSent:          parityBytes,
		SkippedRows:              s.skippedRows.Load(),
		DroppedFrames:            s.droppedFrames.Load(),
		ProtectedPacketsReceived: s.protectedRecv.Load(),
		RecoveredPackets:         s.recoveredRecv.Load(),
		FailedPackets:            s.failedRecv.Load(),
		ParityPacketsReceived:    s.parityRecv.Load(),
	}
	if protectedBytes > 0 {
		stats.MeasuredOverhead = float64(parityBytes) / float64(protectedBytes)
	}
	return stats
}

func (s *fecWindowState) protecting() bool { return s.encoder.protecting() }

func (s *fecWindowState) reserve() protocol.ByteCount { return s.encoder.reserve() }

func (s *fecWindowState) tick(now monotime.Time) { s.encoder.tick(now) }

func (s *fecWindowState) addPacket(pn protocol.PacketNumber, data []byte, maxPacketSize protocol.ByteCount, now monotime.Time, carriesData bool) {
	s.encoder.addPacket(pn, data, maxPacketSize, now, carriesData)
}

func (s *fecWindowState) recordPacket(pn protocol.PacketNumber, data []byte, keyPhase protocol.KeyPhaseBit) []fecRecoveredPacket {
	return s.decoder.recordPacket(pn, data, keyPhase)
}

func (s *fecWindowState) handleFrame(frame wire.Frame, now monotime.Time) []fecRecoveredPacket {
	switch f := frame.(type) {
	case *wire.FECWindowRepairFrame:
		return s.decoder.handleRepair(f, now)
	case *wire.FECFeedbackFrame:
		s.encoder.onFeedback(f, now)
	}
	return nil
}

func (s *fecWindowState) pendingFrame(now monotime.Time, maxPacketSize protocol.ByteCount) wire.Frame {
	if frame := s.encoder.pendingFrame(now, maxPacketSize); frame != nil {
		return frame
	}
	if frame := s.decoder.pendingFeedback(now); frame != nil {
		return frame
	}
	return nil
}

func (s *fecWindowState) hasPending() bool { return s.encoder.hasPending() }

func (s *fecWindowState) frameSent(frame wire.Frame, v protocol.Version) {
	if repair, ok := frame.(*wire.FECWindowRepairFrame); ok {
		s.paritySent.Add(1)
		s.parityBytes.Add(uint64(repair.Length(v)))
	}
}

func (s *fecWindowState) flushDeadline() monotime.Time { return s.encoder.flushDeadline() }

func (s *fecWindowState) frameDropped() { s.droppedFrames.Add(1) }

// fecWindowMember is a packet that is currently protected: the bytes of the packet as
// they were written to the wire, so that a parity row can be computed from them later.
type fecWindowMember struct {
	packetNumber protocol.PacketNumber
	data         []byte
}

type fecWindowEncoder struct {
	state  *fecWindowState
	config FECConfig

	windowSize  int
	maxSpan     uint64
	flushRows   int
	overheadCap float64

	members []fecWindowMember

	rowSeq uint64
	ready  []*wire.FECWindowRepairFrame

	// rowCredit is the number of rows that are due, in rows: it accrues at the target
	// redundancy and is spent one row at a time. credit is the byte budget, in bytes:
	// it accrues at the overhead cap for every packet FEC sees and is spent on the
	// rows that are actually sent, which is what bounds the measured overhead.
	rowCredit float64
	credit    float64

	rate          float64
	rateBits      atomic.Uint64
	lossEWMA      float64
	averageLength float64

	lastAdd      monotime.Time
	rowsSinceAdd int
	// tailFlushed says that the tail of the current window was already offered to the
	// byte budget. A flush the budget refused must not be retried on every send loop
	// iteration; the next packet resets it.
	tailFlushed bool

	lastEvaluation monotime.Time
	feedbackSeen   bool
	fbReceived     uint64
	fbLost         uint64
	peerLoss       float64
	peerLossTime   monotime.Time
	// lossPeak is the highest loss rate the peer reported within the last
	// fecWindowLossPeakHold, and lossPeakTime is when it was reported. It holds the
	// redundancy of a burst after the burst is over, instead of letting the loss
	// estimate decay away while the packets of the burst are still recoverable.
	lossPeak     float64
	lossPeakTime monotime.Time
}

func newFECWindowEncoder(state *fecWindowState, config FECConfig) *fecWindowEncoder {
	windowSize := config.MaxGroupSize
	if windowSize > wire.MaxFECWindowSize {
		windowSize = wire.MaxFECWindowSize
	}
	if windowSize < fecWindowMinMembers {
		windowSize = fecWindowMinMembers
	}
	maxSpan := uint64(2*windowSize + 8)
	if maxSpan > wire.MaxFECWindowSpan {
		maxSpan = wire.MaxFECWindowSpan
	}
	flushRows := config.MaxParityRows
	if flushRows > fecWindowMaxFlushRows {
		flushRows = fecWindowMaxFlushRows
	}
	if flushRows < 1 {
		flushRows = 1
	}
	return &fecWindowEncoder{
		state:       state,
		config:      config,
		windowSize:  windowSize,
		maxSpan:     maxSpan,
		flushRows:   flushRows,
		overheadCap: float64(config.MaxOverheadPercent) / 100,
	}
}

// protecting says whether the encoder currently spends bandwidth on repair rows. A
// window with no measured loss doesn't send anything at all, and the packets don't
// have to leave room for a frame that is never sent.
func (e *fecWindowEncoder) protecting() bool { return e.rate > 0 }

// reserve is the number of bytes a repair row needs on top of the packet it protects,
// for the largest window this encoder can describe. Protected packets have to stay
// below maxPacketSize minus this reserve, so that a row always fits into a datagram.
func (e *fecWindowEncoder) reserve() protocol.ByteCount {
	return fecWindowFrameBytes(e.maxSpan)
}

func (e *fecWindowEncoder) hasPending() bool { return len(e.ready) > 0 }

func (e *fecWindowEncoder) flushDeadline() monotime.Time {
	if e.tailFlushed || !e.protecting() || e.rowsSinceAdd > 0 || e.lastAdd.IsZero() || len(e.members) < fecWindowMinMembers {
		return 0
	}
	return e.lastAdd.Add(e.config.FlushDelay)
}

// tick re-evaluates the loss rate. The loss rate of the path is measured by the peer
// (it sees the gaps in the packet number sequence), so the loss rate decays towards
// zero if the peer's reports stop arriving, and the redundancy of a burst is held for
// fecWindowLossPeakHold after the burst.
func (e *fecWindowEncoder) tick(now monotime.Time) {
	if !e.lastEvaluation.IsZero() && now.Sub(e.lastEvaluation) < fecEvaluationInterval {
		return
	}
	e.lastEvaluation = now
	e.evaluateLoss(now)
}

// evaluateLoss re-evaluates the loss rate of the path from the freshest report the
// peer sent, and drives the redundancy from it.
//
// The redundancy is computed from the highest rate the peer reported within the last
// fecWindowLossPeakHold, not from the smoothed estimate. Two effects make the smoothed
// estimate the wrong input for a reactive scheme on a bursty path:
//
//   - It only moves a fraction of the way to a sample, so a burst reported at L drives
//     the redundancy as if the path lost 0.3*L, while reconstructing the burst needs a
//     row per lost packet. Under half of what the burst costs can never repair it.
//   - The burst is over before the sender could spend the rows, and the reports that
//     follow it are clean, so the estimate is back near zero while the packets of the
//     burst are still inside the window.
//
// The peak of the burst is held for fecWindowLossPeakHold instead, and the redundancy
// follows the peak. The smoothed rate is still reported as the current estimate of the
// path.
//
// A report that is not fresh is treated as no loss at all: the loss rate of the path is
// measured by the peer, so a report that stopped arriving has to be re-measured from
// scratch instead of holding the sender at the redundancy of a path that may be gone.
func (e *fecWindowEncoder) evaluateLoss(now monotime.Time) {
	var lossRate float64
	if !e.peerLossTime.IsZero() && now.Sub(e.peerLossTime) < fecPeerLossValidity {
		lossRate = e.peerLoss
		if e.lossPeak > lossRate && now.Sub(e.lossPeakTime) < fecWindowLossPeakHold {
			lossRate = e.lossPeak
		}
	} else {
		e.lossPeak = 0
	}
	e.lossEWMA = fecLossEWMAAlpha*lossRate + (1-fecLossEWMAAlpha)*e.lossEWMA
	e.state.setLossRate(e.lossEWMA)
	e.updateRedundancyFor(lossRate)
}

// onFeedback processes a loss report of the peer. The counters are cumulative, so a
// lost feedback packet degrades nothing but the freshness of the report.
func (e *fecWindowEncoder) onFeedback(feedback *wire.FECFeedbackFrame, now monotime.Time) {
	var deltaReceived, deltaLost uint64
	if !e.feedbackSeen {
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
		// Only a higher rate raises the peak, but every fresh report moves its
		// deadline: the hold has to survive the clean reports that follow a burst,
		// otherwise a single clean report would drop the redundancy while the packets
		// of the burst are still inside the window. A path that keeps losing raises the
		// peak, and a path that keeps reporting clean holds the burst for the full
		// duration.
		if e.peerLoss > e.lossPeak {
			e.lossPeak = e.peerLoss
		}
		e.lossPeakTime = now
	}
	e.fbReceived = feedback.ReceivedPackets
	e.fbLost = feedback.LostPackets
	e.feedbackSeen = true
	e.lastEvaluation = now
	e.evaluateLoss(now)
}

// updateLoss applies a loss rate sample to the smoothed estimate of the path and
// re-derives the redundancy from it. The encoder itself drives the redundancy from the
// held peak of a burst rather than from the smoothed rate (see evaluateLoss); this is
// the entry point for callers that only have the smoothed rate.
func (e *fecWindowEncoder) updateLoss(sample float64) {
	if sample < 0 {
		sample = 0
	}
	e.lossEWMA = fecLossEWMAAlpha*sample + (1-fecLossEWMAAlpha)*e.lossEWMA
	e.state.setLossRate(e.lossEWMA)
	e.updateRedundancy()
}

// updateRedundancy re-derives the redundancy from the smoothed loss rate.
func (e *fecWindowEncoder) updateRedundancy() {
	e.updateRedundancyFor(e.lossEWMA)
}

// updateRedundancyFor computes the number of repair rows to send per protected packet
// for a loss rate. It is capped by the configured overhead: when the estimated byte
// cost of a row would push the parity traffic over the cap, the rate is reduced until
// it fits.
func (e *fecWindowEncoder) updateRedundancyFor(lossRate float64) {
	if lossRate < fecMinLossRate {
		// The path looks lossless: don't spend a single byte on redundancy.
		e.setRate(0)
		return
	}
	required := lossRate * fecLossSafetyFactor
	maxRate := e.overheadCap
	if e.averageLength > 0 {
		// A row costs the longest packet of its window plus the frame header, so a row
		// per `1/rate` packets costs rate*(1 + header/length) of the protected traffic.
		maxRate = e.overheadCap * e.averageLength / (e.averageLength + float64(e.reserve()))
	}
	maxRate *= fecWindowRateMargin
	if maxRate > 1 {
		maxRate = 1
	}
	// Two rows whose numbers are congruent modulo fecWindowCauchyRows use the same row
	// base, and a repair row is only invertible against rows with a different base. A
	// packet is covered by about window*rate consecutive rows, so keeping that product
	// below fecWindowCauchyRows guarantees that two rows that share a member always
	// have different bases.
	if sameBase := float64(fecWindowCauchyRows) / float64(e.windowSize); maxRate > sameBase {
		maxRate = sameBase
	}
	rate := math.Min(required, maxRate)
	if rate < 0 {
		rate = 0
	}
	e.setRate(rate)
}

func (e *fecWindowEncoder) setRate(rate float64) {
	e.rate = rate
	e.rateBits.Store(math.Float64bits(rate))
	if rate > 0 {
		e.state.windowSize.Store(int64(e.windowSize))
	} else {
		e.state.windowSize.Store(0)
	}
}

// addPacket adds a packet that was just sent to the window, and emits the repair rows
// that are due. maxPacketSize is the maximum size of a QUIC packet (the MTU), not the
// (smaller) size limit that applies to FEC protected packets.
func (e *fecWindowEncoder) addPacket(pn protocol.PacketNumber, data []byte, maxPacketSize protocol.ByteCount, now monotime.Time, carriesData bool) {
	if len(data) == 0 || protocol.ByteCount(len(data)) > maxPacketSize {
		return
	}
	if !carriesData {
		// A packet that only acknowledges packets or updates flow control state carries
		// information the peer can reconstruct from its own state: spending parity on it
		// protects nothing. It would also be expensive, because the parity symbol of a
		// window is as long as the longest packet in it, and a stream of short
		// acknowledgement packets next to full data packets would make every row as long
		// as a data packet while paying for it out of the bytes of both.
		return
	}
	// Every protected packet adds to the budget of the overhead cap, whether or not a
	// row is sent for it: that is what makes the measured overhead comparable to the
	// cap.
	e.state.protectedSent.Add(1)
	e.state.protectedBytes.Add(uint64(len(data)))
	e.credit = math.Min(e.credit+e.overheadCap*float64(len(data)), fecWindowCreditLimit)
	if !e.protecting() {
		return
	}
	packet := make([]byte, len(data))
	copy(packet, data)
	e.members = append(e.members, fecWindowMember{packetNumber: pn, data: packet})
	e.averageLength = fecWindowLengthEWMAAlpha*float64(len(data)) + (1-fecWindowLengthEWMAAlpha)*e.averageLength
	e.evict(pn)
	e.lastAdd = now
	e.rowsSinceAdd = 0
	e.tailFlushed = false
	e.rowCredit += e.rate
	for e.rowCredit >= 1 {
		if !e.emitRow(maxPacketSize) {
			e.rowCredit = 0
			break
		}
		e.rowCredit--
	}
}

// evict drops the packets that left the window: the ones that don't fit into the
// window any more, and the ones whose packet number is more than maxSpan behind the
// newest member - a repair row couldn't describe a window that wide. The second rule
// is what keeps the window useful when only some of the packets carry data: a sender
// that spends most of its packet numbers on acknowledgements would otherwise fill the
// window with packets the peer already has (or that the decoder no longer caches).
func (e *fecWindowEncoder) evict(newest protocol.PacketNumber) {
	for len(e.members) > 0 {
		if len(e.members) <= e.windowSize && uint64(newest-e.members[0].packetNumber) < e.maxSpan {
			return
		}
		// Clear the slot before it is resliced away, so that the packet it points to can
		// be collected while the array is still in use.
		e.members[0] = fecWindowMember{}
		e.members = e.members[1:]
	}
}

// emitRow builds one repair row for the current window and queues it for sending. It
// returns false when the row can't be built or can't be paid for out of the byte
// budget, in which case the caller drops the row credit instead of saving it up.
func (e *fecWindowEncoder) emitRow(maxPacketSize protocol.ByteCount) bool {
	// The parity pass is the expensive part of a row. Refuse a row the byte budget
	// can't pay for before computing it; the exact check below still runs on the frame
	// that is actually built.
	if length := e.estimatedRowLength(); length > 0 && float64(length) > e.credit {
		e.state.skippedRows.Add(1)
		return false
	}
	frame := e.buildRow(maxPacketSize)
	if frame == nil {
		e.state.skippedRows.Add(1)
		return false
	}
	length := float64(frame.Length(protocol.Version1))
	if length > e.credit {
		e.state.skippedRows.Add(1)
		return false
	}
	e.credit -= length
	e.rowSeq++
	e.ready = append(e.ready, frame)
	e.rowsSinceAdd++
	if len(e.ready) > fecWindowMaxReadyFrames {
		// The send queue stayed busy long enough that rows piled up. A row for a window
		// that has already left the receiver can't repair anything, so drop the oldest.
		dropped := len(e.ready) - fecWindowMaxReadyFrames
		e.ready = append(e.ready[:0], e.ready[dropped:]...)
		e.state.droppedFrames.Add(uint64(dropped))
	}
	return true
}

// estimatedRowLength is a lower bound for the size of the next repair row: the header
// that describes the current window plus its longest member. It is computed without any
// GF arithmetic, so a row the byte budget can't pay for is refused before its parity is
// computed.
func (e *fecWindowEncoder) estimatedRowLength() protocol.ByteCount {
	if len(e.members) < fecWindowMinMembers {
		return 0
	}
	span := uint64(e.members[len(e.members)-1].packetNumber-e.members[0].packetNumber) + 1
	if span > e.maxSpan {
		span = e.maxSpan
	}
	var maxLength protocol.ByteCount
	for _, member := range e.members {
		if length := protocol.ByteCount(len(member.data)); length > maxLength {
			maxLength = length
		}
	}
	return maxLength + fecWindowFrameBytes(span)
}

// buildRow computes one parity row over the current window. It returns nil when the
// window is too small, when its packet number span doesn't fit into the membership
// bitmap, or when the row wouldn't fit into a datagram.
func (e *fecWindowEncoder) buildRow(maxPacketSize protocol.ByteCount) *wire.FECWindowRepairFrame {
	if len(e.members) < fecWindowMinMembers {
		return nil
	}
	members := e.members
	first := members[0].packetNumber
	last := members[len(members)-1].packetNumber
	// The window covers consecutive packet numbers, with the packet numbers spent on
	// parity packets left clear. A span the bitmap can't describe is out of the
	// question: the oldest members are dropped instead.
	for uint64(last-first)+1 > e.maxSpan {
		members = members[1:]
		if len(members) < fecWindowMinMembers {
			return nil
		}
		first = members[0].packetNumber
	}
	frame := &wire.FECWindowRepairFrame{
		Row:               e.rowSeq,
		FirstPacketNumber: first,
		Span:              uint64(last-first) + 1,
		PacketNumbers:     make([]protocol.PacketNumber, len(members)),
		ParityLength:      0,
	}
	var parityLength protocol.ByteCount
	for i, member := range members {
		frame.PacketNumbers[i] = member.packetNumber
		if length := protocol.ByteCount(len(member.data)); length > parityLength {
			parityLength = length
		}
	}
	frame.ParityLength = parityLength
	frame.Parity = make([]byte, parityLength)
	if frame.Length(protocol.Version1)+fecMaxPacketOverhead > maxPacketSize {
		// The parity packet would be larger than a datagram. This happens when the
		// window holds a packet that was sent before FEC engaged, when packets were
		// still sized without a repair frame in mind.
		return nil
	}
	for position, member := range members {
		coefficient := fecWindowCoefficient(frame.Row, position)
		fecXORScaled(frame.Parity, member.data, coefficient)
		length := uint16(len(member.data))
		frame.LengthParity[0] ^= gfMul(coefficient, byte(length>>8))
		frame.LengthParity[1] ^= gfMul(coefficient, byte(length))
	}
	return frame
}

// pendingFrame returns the next repair row to send. When the sender went idle with a
// non-empty window, the rows for the tail of the window are built here: the packets
// sent last are covered by fewer rows than the ones in the middle, and a connection
// that stops sending would otherwise leave them unprotected.
func (e *fecWindowEncoder) pendingFrame(now monotime.Time, maxPacketSize protocol.ByteCount) wire.Frame {
	if len(e.ready) > 0 {
		frame := e.ready[0]
		e.ready = e.ready[1:]
		return frame
	}
	if !e.protecting() || len(e.members) < fecWindowMinMembers {
		return nil
	}
	if e.tailFlushed || e.rowsSinceAdd > 0 || e.lastAdd.IsZero() || now.Before(e.lastAdd.Add(e.config.FlushDelay)) {
		return nil
	}
	// The tail is offered to the byte budget once per packet: a flush the budget refused
	// must not be retried on every iteration of the send loop.
	e.tailFlushed = true
	for i := 0; i < e.flushRows; i++ {
		if !e.emitRow(maxPacketSize) {
			break
		}
	}
	if len(e.ready) > 0 {
		frame := e.ready[0]
		e.ready = e.ready[1:]
		return frame
	}
	return nil
}

// fecWindowPendingRow is one equation of the decoder: the parity row with the
// contributions of all members that are already known removed. What is left is a
// linear combination of the missing packets.
type fecWindowPendingRow struct {
	pivot  protocol.PacketNumber
	coeffs map[protocol.PacketNumber]byte
	rhs    []byte
	lenRHS [2]byte
}

func (r *fecWindowPendingRow) updatePivot() {
	first := true
	for pn := range r.coeffs {
		if first || pn < r.pivot {
			r.pivot = pn
			first = false
		}
	}
}

type fecWindowDecoder struct {
	state      *fecWindowState
	config     FECConfig
	windowSize int
	cacheSize  int
	// maxMissing bounds the packet numbers the decoder tracks as missing, which only
	// feed the statistics.
	maxMissing int

	cache        map[protocol.PacketNumber][]byte
	order        []protocol.PacketNumber
	keyPhase     protocol.KeyPhaseBit
	haveKeyPhase bool

	// protected remembers which packets the peer announced as protected, so that the
	// statistics count every packet once instead of once per row that covers it.
	protected      map[protocol.PacketNumber]struct{}
	protectedOrder []protocol.PacketNumber

	// missing is the set of packets the peer protects that this endpoint has not seen
	// (and FEC has not reconstructed) yet. Entries that stay missing for longer than
	// fecWindowMissingTimeout are given up on and counted as unrecoverable.
	missing map[protocol.PacketNumber]monotime.Time

	// staleBefore is the highest packet number that left the cache (or that belongs to
	// a key phase whose keys are gone). A repair row that references a packet below it
	// that is no longer cached can't be evaluated - the contribution of a packet the
	// decoder doesn't have is unknown - so the row is dropped instead of turning into
	// an equation that can never be solved.
	staleBefore protocol.PacketNumber

	pending []*fecWindowPendingRow

	// tracker measures the packet loss rate of the path, independently of whether
	// packets are FEC protected. This is what makes the sender engage FEC.
	tracker fecLossTracker

	feedbackTime     monotime.Time
	reportedReceived uint64
	reportedLost     uint64
}

func newFECWindowDecoder(state *fecWindowState, config FECConfig) *fecWindowDecoder {
	windowSize := config.MaxGroupSize
	if windowSize > wire.MaxFECWindowSize {
		windowSize = wire.MaxFECWindowSize
	}
	if windowSize < fecWindowMinMembers {
		windowSize = fecWindowMinMembers
	}
	return &fecWindowDecoder{
		state:      state,
		config:     config,
		windowSize: windowSize,
		cacheSize:  2*windowSize + fecWindowCacheSlack,
		maxMissing: 4 * (2*windowSize + fecWindowCacheSlack),
	}
}

func (d *fecWindowDecoder) reset() {
	d.cache = nil
	d.order = nil
	d.protected = nil
	d.protectedOrder = nil
	d.missing = nil
	d.pending = nil
}

// recordPacket caches a received packet and lets the pending equations use it: a packet
// that arrives late can make an equation solvable immediately, without waiting for the
// next repair row.
func (d *fecWindowDecoder) recordPacket(pn protocol.PacketNumber, data []byte, keyPhase protocol.KeyPhaseBit) []fecRecoveredPacket {
	d.tracker.record(pn)
	if d.haveKeyPhase && keyPhase != d.keyPhase {
		// Packets of the previous key phase can't be decrypted anymore: everything the
		// decoder holds is stale, and so is everything it might still reconstruct from
		// the rows that protect the packets of that phase.
		d.staleBefore = d.tracker.largest
		d.reset()
	}
	d.keyPhase = keyPhase
	d.haveKeyPhase = true
	d.cachePacket(pn, data)
	d.noteKnown(pn, data)
	return d.pump()
}

func (d *fecWindowDecoder) cachePacket(pn protocol.PacketNumber, data []byte) {
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
	for len(d.order) > d.cacheSize {
		evicted := d.order[0]
		d.order = d.order[1:]
		delete(d.cache, evicted)
		if evicted > d.staleBefore {
			d.staleBefore = evicted
		}
	}
	delete(d.missing, pn)
}

// noteKnown removes a packet from the pending equations: its contribution to the parity
// is known, so it is subtracted from the right hand sides.
func (d *fecWindowDecoder) noteKnown(pn protocol.PacketNumber, data []byte) {
	length := uint16(len(data))
	for _, row := range d.pending {
		coefficient, ok := row.coeffs[pn]
		if !ok {
			continue
		}
		if len(data) > len(row.rhs) {
			// A packet is never longer than the parity symbol of a row that protects it.
			// Growing the symbol keeps the arithmetic of a row that was built from a
			// frame this decoder accepted consistent instead of panicking.
			row.rhs = append(row.rhs, make([]byte, len(data)-len(row.rhs))...)
		}
		delete(row.coeffs, pn)
		fecXORScaled(row.rhs, data, coefficient)
		row.lenRHS[0] ^= gfMul(coefficient, byte(length>>8))
		row.lenRHS[1] ^= gfMul(coefficient, byte(length))
		row.updatePivot()
	}
}

func (d *fecWindowDecoder) markProtected(pn protocol.PacketNumber) {
	if d.protected == nil {
		d.protected = make(map[protocol.PacketNumber]struct{})
	}
	if _, ok := d.protected[pn]; ok {
		return
	}
	d.protected[pn] = struct{}{}
	d.protectedOrder = append(d.protectedOrder, pn)
	d.state.protectedRecv.Add(1)
	for len(d.protectedOrder) > d.cacheSize {
		evicted := d.protectedOrder[0]
		d.protectedOrder = d.protectedOrder[1:]
		delete(d.protected, evicted)
	}
}

func (d *fecWindowDecoder) expireMissing(now monotime.Time) {
	for pn, first := range d.missing {
		if now.Sub(first) >= fecWindowMissingTimeout {
			delete(d.missing, pn)
			d.state.failedRecv.Add(1)
		}
	}
}

// handleRepair processes an incoming repair row. The packets of the row that are still
// missing become the unknowns of a new equation; if the equation - together with the
// ones before it - determines a packet, the packet is reconstructed and returned, so
// that the connection can process it like a packet that arrived on the wire.
func (d *fecWindowDecoder) handleRepair(frame *wire.FECWindowRepairFrame, now monotime.Time) []fecRecoveredPacket {
	d.state.parityRecv.Add(1)
	missing := make([]int, 0, len(frame.PacketNumbers))
	trackMissing := func(pn protocol.PacketNumber) {
		// The set only feeds the statistics; the equation is built from the cache
		// contents. It is bounded so that a peer can't make the decoder hold an
		// unbounded number of packet numbers.
		if len(d.missing) >= d.maxMissing {
			return
		}
		if _, ok := d.missing[pn]; ok {
			return
		}
		if d.missing == nil {
			d.missing = make(map[protocol.PacketNumber]monotime.Time)
		}
		d.missing[pn] = now
	}
	for position, pn := range frame.PacketNumbers {
		d.markProtected(pn)
		if _, ok := d.cache[pn]; ok {
			continue
		}
		if pn <= d.staleBefore {
			// The packet was received and then left the cache, or it belongs to a key
			// phase whose keys are gone. The row can't be evaluated without it, and the
			// packet itself is not something FEC can still reconstruct, so the row is
			// dropped instead of becoming an equation that can never be solved.
			return nil
		}
		trackMissing(pn)
		missing = append(missing, position)
	}
	if len(missing) == 0 {
		return nil
	}
	row := d.buildRow(frame, missing)
	if row == nil {
		return nil
	}
	d.pending = append(d.pending, row)
	d.dropPending()
	return d.pump()
}

// buildRow turns a repair row into an equation over the packets that are missing. The
// contributions of the packets that are already known - and of their lengths - are
// subtracted from the parity.
func (d *fecWindowDecoder) buildRow(frame *wire.FECWindowRepairFrame, missing []int) *fecWindowPendingRow {
	isMissing := make(map[int]struct{}, len(missing))
	for _, position := range missing {
		isMissing[position] = struct{}{}
	}
	rhs := make([]byte, frame.ParityLength)
	copy(rhs, frame.Parity)
	row := &fecWindowPendingRow{
		coeffs: make(map[protocol.PacketNumber]byte, len(missing)),
		rhs:    rhs,
		lenRHS: frame.LengthParity,
	}
	for position, pn := range frame.PacketNumbers {
		coefficient := fecWindowCoefficient(frame.Row, position)
		if _, ok := isMissing[position]; ok {
			row.coeffs[pn] = coefficient
			continue
		}
		data, ok := d.cache[pn]
		if !ok {
			// Neither cached nor missing: the packet was evicted from the cache, so this
			// equation can't be evaluated.
			return nil
		}
		if len(data) > len(row.rhs) {
			// A protected packet can't be longer than the parity symbol of its own row.
			// A frame that says otherwise is inconsistent: don't build an equation from
			// it instead of recovering packets from it.
			return nil
		}
		fecXORScaled(row.rhs, data, coefficient)
		length := uint16(len(data))
		row.lenRHS[0] ^= gfMul(coefficient, byte(length>>8))
		row.lenRHS[1] ^= gfMul(coefficient, byte(length))
	}
	if len(row.coeffs) == 0 {
		return nil
	}
	row.updatePivot()
	return row
}

func (d *fecWindowDecoder) dropPending() {
	for len(d.pending) > fecWindowMaxPendingRows {
		d.pending = d.pending[1:]
	}
}

// pump solves the pending equations until nothing changes: a row that lost all its
// unknowns is dropped, a row with a single unknown reconstructs its packet (which is
// then substituted into the other rows), and two rows that are reduced to the same
// pivot are combined.
func (d *fecWindowDecoder) pump() []fecRecoveredPacket {
	var recovered []fecRecoveredPacket
	for {
		changed := false
		for i := 0; i < len(d.pending); i++ {
			row := d.pending[i]
			if len(row.coeffs) < 2 {
				d.pending = append(d.pending[:i], d.pending[i+1:]...)
				i--
				changed = true
				if len(row.coeffs) == 0 {
					continue
				}
				if packet, ok := d.solve(row); ok {
					recovered = append(recovered, packet)
					d.cachePacket(packet.packetNumber, packet.data)
					d.noteKnown(packet.packetNumber, packet.data)
				}
				continue
			}
			if d.mergePivot(i) {
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return recovered
}

// mergePivot combines a row with another row that has the same pivot, eliminating that
// unknown from one of them.
func (d *fecWindowDecoder) mergePivot(index int) bool {
	row := d.pending[index]
	for j, other := range d.pending {
		if j == index || other.pivot != row.pivot || len(other.coeffs) == 0 {
			continue
		}
		pivot := row.pivot
		factor := gfMul(row.coeffs[pivot], gfInv(other.coeffs[other.pivot]))
		if len(other.rhs) > len(row.rhs) {
			// Two rows of overlapping windows can have parity symbols of different
			// lengths: a symbol is as long as the longest packet its row protects.
			// Combining them works on the longer symbol, with the shorter one
			// zero-extended - which is exactly what the encoder did.
			row.rhs = append(row.rhs, make([]byte, len(other.rhs)-len(row.rhs))...)
		}
		fecXORScaled(row.rhs, other.rhs, factor)
		row.lenRHS[0] ^= gfMul(factor, other.lenRHS[0])
		row.lenRHS[1] ^= gfMul(factor, other.lenRHS[1])
		for pn, coefficient := range other.coeffs {
			if pn == pivot {
				delete(row.coeffs, pn)
				continue
			}
			if combined := row.coeffs[pn] ^ gfMul(factor, coefficient); combined != 0 {
				row.coeffs[pn] = combined
			} else {
				delete(row.coeffs, pn)
			}
		}
		row.updatePivot()
		return true
	}
	return false
}

// solve reconstructs the single remaining unknown of an equation, including its wire
// length, which is encoded in the same linear combination as the packet itself.
func (d *fecWindowDecoder) solve(row *fecWindowPendingRow) (fecRecoveredPacket, bool) {
	var (
		packetNumber protocol.PacketNumber
		coefficient  byte
	)
	for pn, c := range row.coeffs {
		packetNumber, coefficient = pn, c
		break
	}
	inverse := gfInv(coefficient)
	length := uint16(gfMul(row.lenRHS[0], inverse))<<8 | uint16(gfMul(row.lenRHS[1], inverse))
	if length == 0 || protocol.ByteCount(length) > protocol.ByteCount(len(row.rhs)) {
		// The length doesn't fit the parity symbol: the equation can't describe a packet.
		d.state.failedRecv.Add(1)
		return fecRecoveredPacket{}, false
	}
	data := make([]byte, length)
	for i := range data {
		data[i] = gfMul(row.rhs[i], inverse)
	}
	d.state.recoveredRecv.Add(1)
	return fecRecoveredPacket{packetNumber: packetNumber, data: data}, true
}

// pendingFeedback returns a feedback frame if a new loss report is due. The loss rate
// of the path is measured locally (packet number gaps), so reports are sent even while
// FEC is idle: they are what makes the sender engage FEC in the first place.
func (d *fecWindowDecoder) pendingFeedback(now monotime.Time) *wire.FECFeedbackFrame {
	if !d.tracker.initialized {
		return nil
	}
	if !d.feedbackTime.IsZero() && now.Sub(d.feedbackTime) < fecFeedbackInterval {
		return nil
	}
	// Expiring the missing packets is rate limited with the reports: the decoder is
	// asked for feedback on every send loop iteration, and the set can hold hundreds of
	// packet numbers.
	d.expireMissing(now)
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
