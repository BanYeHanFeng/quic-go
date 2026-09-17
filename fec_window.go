package quic

import (
	"math"
	"slices"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
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
	// packets: about 10.7 at the default 20% cap with a 64 packet window, about 21.3 at
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
	// fecWindowLossPeakHold is how long the highest loss rate measured of a burst keeps
	// driving the redundancy after it was measured. A mobile path loses packets in short
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
	// for the packets those rows are paid out of: a burst of ten packets needs about
	// 55 protected packets at the 20% cap, and a path that carries 150 packets per
	// second needs about 700ms for them. The hold runs from the sample that measured
	// the peak, never from the last report, and it is capped by
	// fecWindowLossPeakHoldMax: the redundancy of a burst may outlive the burst, but a
	// clean path has to get its bytes back.
	fecWindowLossPeakHold = time.Second
	// fecWindowLossPeakHoldMax bounds the hold when the window spans a lot of time: a
	// slow connection fills the window over several seconds, so its bursts need the
	// redundancy for longer than fecWindowLossPeakHold. Holding it for minutes would
	// turn a single burst into permanent overhead.
	fecWindowLossPeakHoldMax = 3 * time.Second
	// fecWindowAddIntervalMax bounds the packet interval the hold is estimated from: a
	// gap in the traffic is not the rate the window is being filled at.
	fecWindowAddIntervalMax = 250 * time.Millisecond
	// fecLossSampleMinPackets is how many packets a loss report has to cover before it
	// is accepted as a measurement of the path. The peer reports every
	// fecFeedbackInterval (20ms); on a connection that carries a few packets per second
	// one report covers one or two packets, and a single lost packet among them would
	// otherwise read as 50% or 100% loss and pin the redundancy at the overhead cap for
	// as long as the connection is active. Sixteen packets is small enough that a fast
	// connection reaches it in its first reports, and large enough that one lost packet
	// in the sample reads as its real share (6.25%) instead of as half the path.
	fecLossSampleMinPackets = 16
	// fecLossSampleMinLostPackets makes a pending sample a measurement as soon as it
	// holds this many lost packets, however small it still is: a burst that already
	// cost this many packets is not an artefact of the report size, and its packets
	// leave the window while the sample is still filling up, so waiting for the rest of
	// the sample would mean giving up on the burst. A single lost packet - the case
	// that pinned the redundancy in production - is far below this.
	fecLossSampleMinLostPackets = 8
	// fecLossSampleMinDelayPackets and fecLossSampleMaxDelay bound the other side of the
	// same trade-off: once a pending sample is this old it is accepted even when it is
	// smaller than fecLossSampleMinPackets, so that a path carrying only a few packets
	// per second still gets a measurement instead of none.
	fecLossSampleMinDelayPackets = 8
	fecLossSampleMaxDelay        = 500 * time.Millisecond
	// fecWindowLengthEWMAAlpha is the weight of the newest packet when tracking the
	// average protected packet size, which the redundancy calculation uses to keep the
	// frame header inside the overhead cap.
	fecWindowLengthEWMAAlpha = 0.2
	// fecWindowMissingTimeout is how long a packet the peer protects may stay missing
	// before the decoder gives up on it and counts it as unrecoverable.
	fecWindowMissingTimeout = time.Second
	// fecWindowStallWarnInterval rate limits the log line that makes a stalled sender
	// visible: packets expiring unrecovered while no repair row has arrived for a whole
	// missing timeout mean the peer stopped protecting this direction.
	fecWindowStallWarnInterval = 10 * time.Second
	// fecWindowMaxRecoveredPending bounds the recovered packets the decoder queues for
	// reporting to the peer; the oldest is dropped when the peer doesn't drain them.
	fecWindowMaxRecoveredPending = 256
	// fecWindowMaxRecoveredFramePackets bounds the packets one recovered frame carries,
	// so that a report still fits into a datagram.
	fecWindowMaxRecoveredFramePackets = 64
	// fecWindowCacheSlack is the number of packets the decoder caches on top of two
	// windows: rows can only reference packets that are still in the sender's window,
	// but packets arrive out of order.
	fecWindowCacheSlack = 32
	// fecWindowCauchyRows is the number of distinct row bases of the Cauchy matrix. Two
	// rows that are this many rows apart use the same base; they never share a member
	// unless the redundancy is far above the configured cap.
	fecWindowCauchyRows = 64
	// fecWindowMaxCoverageRows is the largest number of rows a single packet may be
	// covered by. updateRedundancyFor derives its rate cap from it: a packet is covered
	// by about window*rate consecutive rows, and it can only be recovered while those
	// rows have distinct row bases, of which there are fecWindowCauchyRows. Naming the
	// condition explicitly keeps the rate limit from silently turning into a guess.
	fecWindowMaxCoverageRows = fecWindowCauchyRows
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
	logger  utils.Logger

	lossBits   atomic.Uint64 // math.Float64bits of the smoothed loss rate
	windowSize atomic.Int64  // configured window size while FEC is active, 0 while idle

	protectedSent  atomic.Uint64
	protectedBytes atomic.Uint64
	paritySent     atomic.Uint64
	parityBytes    atomic.Uint64
	skippedRows    atomic.Uint64
	droppedFrames  atomic.Uint64

	skippedRowsBudget      atomic.Uint64
	skippedRowsUnbuildable atomic.Uint64

	protectedRecv atomic.Uint64
	recoveredRecv atomic.Uint64
	failedRecv    atomic.Uint64
	parityRecv    atomic.Uint64
	missingGauge  atomic.Uint64
	duplicateRows atomic.Uint64

	recoveredReported atomic.Uint64
	recoveredReceived atomic.Uint64
}

func newFECWindowState(config FECConfig) *fecWindowState {
	return newFECWindowStateWithLogger(config, nil)
}

// newFECWindowStateWithLogger is newFECWindowState plus the connection logger: the
// decoder uses it to make a stalled peer visible (missing packets that expire while no
// repair row arrives). A nil logger disables those logs.
func newFECWindowStateWithLogger(config FECConfig, logger utils.Logger) *fecWindowState {
	config = config.withDefaults()
	state := &fecWindowState{config: config, logger: logger}
	state.encoder = newFECWindowEncoder(state, config)
	state.decoder = newFECWindowDecoder(state, config)
	// Install the baseline immediately, before the first packet: waiting for the first
	// periodic evaluation would leave the opening burst of the connection unprotected.
	if state.encoder.baselineRate > 0 {
		state.encoder.updateRedundancyFor(0)
	}
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
		SkippedRowsBudget:        s.skippedRowsBudget.Load(),
		SkippedRowsUnbuildable:   s.skippedRowsUnbuildable.Load(),
		DroppedFrames:            s.droppedFrames.Load(),
		ProtectedPacketsReceived: s.protectedRecv.Load(),
		RecoveredPackets:         s.recoveredRecv.Load(),
		FailedPackets:            s.failedRecv.Load(),
		ParityPacketsReceived:    s.parityRecv.Load(),
		MissingPackets:           s.missingGauge.Load(),
		DuplicateRows:            s.duplicateRows.Load(),
		RecoveredPacketsReported: s.recoveredReported.Load(),
		RecoveredPacketsReceived: s.recoveredReceived.Load(),
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
	// Recovered packet reports go first: they tell the peer about losses it has already
	// repaired, and delaying them delays the congestion controller's view of the path.
	if frame := s.decoder.pendingRecoveredFrame(maxPacketSize); frame != nil {
		return frame
	}
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
	baselineRate  float64
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
	// fbTime is when the peer last sent a report, whether the report was large enough
	// to be a sample or not. It says whether the path is still being measured; the
	// samples themselves only arrive every few hundred milliseconds (see
	// accumulateLossSample), so tying the validity of the estimate to them would drop
	// the loss rate of a path that is reporting perfectly well.
	fbTime monotime.Time
	// peerLoss is the last sample that was large enough to measure the path (see
	// accumulateLossSample).
	peerLoss float64
	// sampleReceived/sampleLost accumulate the reports that are too small to measure
	// the path on their own, and sampleStart is when the pending sample began.
	// fecFeedbackInterval is 20ms, so on a connection that carries a few packets per
	// second a report covers one or two packets and a single lost packet among them
	// reads as 50% or 100% loss. Accumulating until the sample covers
	// fecLossSampleMinPackets keeps the redundancy driven by the path instead of by the
	// size of the reports.
	sampleReceived uint64
	sampleLost     uint64
	sampleStart    monotime.Time
	// lossPeak is the highest loss rate measured within holdDuration() of its report,
	// and lossPeakTime is when that sample was measured. It holds the redundancy of a
	// burst after the burst is over, instead of letting the loss estimate decay away
	// while the packets of the burst are still recoverable. Only a new peak moves the
	// deadline: a report that is merely clean must not extend the hold, otherwise the
	// highest sample a noisy link ever produces keeps the redundancy pinned for as long
	// as reports keep arriving, which is the whole life of an active connection.
	lossPeak     float64
	lossPeakTime monotime.Time
	// averageInterval is the average time between two protected packets. It says how
	// long the packets of a burst stay inside the window, which is how long a burst has
	// to keep driving the redundancy on a slow connection.
	averageInterval float64
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
		state:        state,
		config:       config,
		windowSize:   windowSize,
		maxSpan:      maxSpan,
		flushRows:    flushRows,
		overheadCap:  float64(config.MaxOverheadPercent) / 100,
		baselineRate: float64(config.BaselineRedundancyPercent) / 100,
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
// holdDuration after the burst.
func (e *fecWindowEncoder) tick(now monotime.Time) {
	if !e.lastEvaluation.IsZero() && now.Sub(e.lastEvaluation) < fecEvaluationInterval {
		return
	}
	e.lastEvaluation = now
	e.evaluateLoss(now)
}

// evaluateLoss re-evaluates the loss rate of the path from the last sample that was
// large enough to measure it, and drives the redundancy from it.
//
// The redundancy is computed from the highest rate measured within holdDuration(), not
// from the smoothed estimate. Two effects make the smoothed estimate the wrong input for
// a reactive scheme on a bursty path:
//
//   - It only moves a fraction of the way to a sample, so a burst measured at L drives
//     the redundancy as if the path lost 0.3*L, while reconstructing the burst needs a
//     row per lost packet. Under half of what the burst costs can never repair it.
//   - The burst is over before the sender could spend the rows, and the reports that
//     follow it are clean, so the estimate is back near zero while the packets of the
//     burst are still inside the window.
//
// The peak of the burst drives the redundancy for holdDuration() instead. The hold runs
// from the sample that measured the peak and is never extended by the reports that follow
// it - only a new peak moves the deadline - so a path that stops losing gets its bytes
// back once the hold is over. The smoothed rate is still reported as the current estimate
// of the path.
//
// A report stream that stopped is treated as no loss at all: the loss rate of the path is
// measured by the peer, so a report stream that stopped has to be re-measured from
// scratch instead of holding the sender at the redundancy of a path that may be gone.
func (e *fecWindowEncoder) evaluateLoss(now monotime.Time) {
	var lossRate float64
	if !e.fbTime.IsZero() && now.Sub(e.fbTime) < fecPeerLossValidity {
		lossRate = e.peerLoss
		if !e.lossPeakTime.IsZero() {
			if now.Sub(e.lossPeakTime) < e.holdDuration() {
				if e.lossPeak > lossRate {
					lossRate = e.lossPeak
				}
			} else {
				// The burst had its rows. Forget the peak, so that the estimate of a
				// clean path can go back to zero and a later burst can set a new one.
				e.lossPeak = 0
				e.lossPeakTime = 0
			}
		}
	} else {
		e.lossPeak = 0
		e.lossPeakTime = 0
	}
	e.lossEWMA = fecLossEWMAAlpha*lossRate + (1-fecLossEWMAAlpha)*e.lossEWMA
	e.state.setLossRate(e.lossEWMA)
	e.updateRedundancyFor(lossRate)
}

// holdDuration is how long the peak of a burst keeps driving the redundancy: long enough
// for the rows the burst needs to be paid out of the packets whose window still holds the
// burst. That is fecWindowLossPeakHold on a connection that fills the window quickly, and
// the window's span in time on a slow one, bounded by fecWindowLossPeakHoldMax.
func (e *fecWindowEncoder) holdDuration() time.Duration {
	hold := fecWindowLossPeakHold
	if e.averageInterval > 0 {
		if span := time.Duration(float64(e.windowSize) * e.averageInterval); span > hold {
			hold = span
		}
	}
	if hold > fecWindowLossPeakHoldMax {
		hold = fecWindowLossPeakHoldMax
	}
	return hold
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
	e.fbReceived = feedback.ReceivedPackets
	e.fbLost = feedback.LostPackets
	e.feedbackSeen = true
	e.fbTime = now
	e.accumulateLossSample(deltaReceived, deltaLost, now)
	e.lastEvaluation = now
	e.evaluateLoss(now)
}

// accumulateLossSample adds the packets of one report to the pending sample and accepts
// the sample as a measurement of the path once it is large enough to be one: it covers
// fecLossSampleMinPackets packets, or it already holds fecLossSampleMinLostPackets lost
// packets, or it has been pending for fecLossSampleMaxDelay and covers
// fecLossSampleMinDelayPackets of them. Only an accepted sample updates the loss rate and
// can raise the peak; the reports in between are the sample.
func (e *fecWindowEncoder) accumulateLossSample(received, lost uint64, now monotime.Time) {
	if received == 0 && lost == 0 {
		return
	}
	if e.sampleReceived == 0 && e.sampleLost == 0 {
		e.sampleStart = now
	}
	e.sampleReceived += received
	e.sampleLost += lost
	total := e.sampleReceived + e.sampleLost
	if total < fecLossSampleMinPackets && e.sampleLost < fecLossSampleMinLostPackets &&
		(now.Sub(e.sampleStart) < fecLossSampleMaxDelay || total < fecLossSampleMinDelayPackets) {
		return
	}
	lost = e.sampleLost
	if lost > total {
		lost = total
	}
	e.peerLoss = float64(lost) / float64(total)
	e.sampleReceived = 0
	e.sampleLost = 0
	e.sampleStart = 0
	// Only a higher rate raises the peak, and the hold of the peak runs from here: the
	// reports that follow a burst, clean or not, must not keep it alive past its hold.
	if e.peerLoss > e.lossPeak {
		e.lossPeak = e.peerLoss
		e.lossPeakTime = now
	}
}

// updateRedundancyFor computes the number of repair rows to send per protected packet
// for a loss rate. It is capped by the configured overhead: when the estimated byte
// cost of a row would push the parity traffic over the cap, the rate is reduced until
// it fits.
func (e *fecWindowEncoder) updateRedundancyFor(lossRate float64) {
	// The baseline keeps FEC engaged while the path looks lossless. It is what lets a
	// row cover the first loss before the peer's feedback could have reported it; the
	// overhead cap bounds what that costs on a clean path.
	required := e.baselineRate
	if lossRate >= fecMinLossRate {
		if reactive := lossRate * fecLossSafetyFactor; reactive > required {
			required = reactive
		}
	}
	if required <= 0 {
		// The path looks lossless and no baseline was configured: don't spend a single
		// byte on redundancy.
		e.setRate(0)
		return
	}
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
	// at or below fecWindowMaxCoverageRows guarantees that two rows that share a member
	// always have different bases.
	if baseLimit := float64(fecWindowMaxCoverageRows) / float64(e.windowSize); maxRate > baseLimit {
		maxRate = baseLimit
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
	// Track how fast the window is being filled: holdDuration uses it to keep the
	// redundancy of a burst for as long as the packets of the burst stay in the window.
	// A traffic gap is not a packet interval, so it is bounded.
	if !e.lastAdd.IsZero() {
		interval := float64(now.Sub(e.lastAdd))
		if interval > float64(fecWindowAddIntervalMax) {
			interval = float64(fecWindowAddIntervalMax)
		}
		if interval > 0 {
			if e.averageInterval == 0 {
				e.averageInterval = interval
			} else {
				e.averageInterval = fecWindowLengthEWMAAlpha*interval + (1-fecWindowLengthEWMAAlpha)*e.averageInterval
			}
		}
	}
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
		e.state.skippedRowsBudget.Add(1)
		return false
	}
	frame := e.buildRow(maxPacketSize)
	if frame == nil {
		e.state.skippedRows.Add(1)
		e.state.skippedRowsUnbuildable.Add(1)
		return false
	}
	length := float64(frame.Length(protocol.Version1))
	if length > e.credit {
		e.state.skippedRows.Add(1)
		e.state.skippedRowsBudget.Add(1)
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
	row    uint64
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

	// lastParity is when the last repair row arrived, and lastStallWarn rate limits the
	// "missing packets expired while no repair row arrives" log line.
	lastParity    monotime.Time
	lastStallWarn monotime.Time

	// pendingRecovered holds recovered packets that still have to be reported to the
	// peer with FEC_RECOVERED, in recovery order.
	pendingRecovered []wire.FECRecoveredPacket
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
	d.state.missingGauge.Store(0)
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
	if _, ok := d.missing[pn]; ok {
		delete(d.missing, pn)
		d.syncMissingGauge()
	}
}

// syncMissingGauge publishes the size of the missing set, which is only updated from
// the connection's run loop, for FECStats readers on other goroutines.
func (d *fecWindowDecoder) syncMissingGauge() {
	d.state.missingGauge.Store(uint64(len(d.missing)))
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
	expired := 0
	for pn, first := range d.missing {
		if now.Sub(first) >= fecWindowMissingTimeout {
			delete(d.missing, pn)
			d.state.failedRecv.Add(1)
			expired++
		}
	}
	if expired == 0 {
		return
	}
	d.syncMissingGauge()
	// Packets expiring while no repair row has arrived for a whole missing timeout are
	// the signature of a peer that went idle (or was never protecting this direction)
	// after announcing the packets: exactly the windows that dominate the unrecoverable
	// counters in the field. Log them instead of leaving the counters to speak for
	// themselves. The log is rate limited, and a nil logger (tests, embedders that
	// don't set one) disables it.
	if d.state.logger == nil || now.Sub(d.lastStallWarn) < fecWindowStallWarnInterval {
		return
	}
	if !d.lastParity.IsZero() && now.Sub(d.lastParity) < fecWindowMissingTimeout {
		return
	}
	d.lastStallWarn = now
	lastParity := "never"
	if !d.lastParity.IsZero() {
		lastParity = now.Sub(d.lastParity).String()
	}
	d.state.logger.Infof("FEC: %d protected packets expired unrecovered; last repair row %s ago (recovered=%d, failed=%d, still missing=%d)",
		expired, lastParity, d.state.recoveredRecv.Load(), d.state.failedRecv.Load(), len(d.missing))
}

// handleRepair processes an incoming repair row. The packets of the row that are still
// missing become the unknowns of a new equation; if the equation - together with the
// ones before it - determines a packet, the packet is reconstructed and returned, so
// that the connection can process it like a packet that arrived on the wire.
func (d *fecWindowDecoder) handleRepair(frame *wire.FECWindowRepairFrame, now monotime.Time) []fecRecoveredPacket {
	d.state.parityRecv.Add(1)
	d.lastParity = now
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
		d.syncMissingGauge()
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
	for _, pending := range d.pending {
		if pending.row == frame.Row {
			// The same equation twice can't add rank, only work. Count it so that a
			// misbehaving or replaying peer is visible instead of silently filling the
			// pending set.
			d.state.duplicateRows.Add(1)
			return nil
		}
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
		row:    frame.Row,
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
					d.queueRecoveredReport(packet)
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

// queueRecoveredReport remembers a recovered packet for the FEC_RECOVERED frame that
// tells the sender about it. It is only called when RecoveredPacketFeedback is on.
func (d *fecWindowDecoder) queueRecoveredReport(packet fecRecoveredPacket) {
	if !d.config.RecoveredPacketFeedback {
		return
	}
	if len(d.pendingRecovered) >= fecWindowMaxRecoveredPending {
		// The peer is not draining the reports. Keep the newest packets, which are the
		// ones the congestion controller can still act on.
		d.pendingRecovered = d.pendingRecovered[1:]
	}
	d.pendingRecovered = append(d.pendingRecovered, wire.FECRecoveredPacket{
		PacketNumber: packet.packetNumber,
		Length:       protocol.ByteCount(len(packet.data)),
	})
	d.state.recoveredReported.Add(1)
}

// pendingRecoveredFrame returns the next FEC_RECOVERED frame, or nil when there is
// nothing to report. The frame is built from the oldest queued recoveries, sorted by
// packet number and bounded so that it fits into a datagram.
func (d *fecWindowDecoder) pendingRecoveredFrame(maxPacketSize protocol.ByteCount) *wire.FECRecoveredFrame {
	if len(d.pendingRecovered) == 0 {
		return nil
	}
	count := min(len(d.pendingRecovered), fecWindowMaxRecoveredFramePackets)
	for count > 0 {
		frame := &wire.FECRecoveredFrame{Packets: append([]wire.FECRecoveredPacket(nil), d.pendingRecovered[:count]...)}
		slices.SortFunc(frame.Packets, func(a, b wire.FECRecoveredPacket) int {
			switch {
			case a.PacketNumber < b.PacketNumber:
				return -1
			case a.PacketNumber > b.PacketNumber:
				return 1
			default:
				return 0
			}
		})
		if frame.Length(protocol.Version1)+fecMaxPacketOverhead <= maxPacketSize {
			d.pendingRecovered = d.pendingRecovered[count:]
			return frame
		}
		count--
	}
	return nil
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
