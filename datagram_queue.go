package quic

import (
	"context"
	"sync"

	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/utils/ringbuffer"
	"github.com/sagernet/quic-go/internal/wire"
)

const (
	maxDatagramSendQueueLen = 32
	maxDatagramRcvQueueLen  = 128
)

// DatagramBufferOwner returns a DATAGRAM payload to whoever allocated it.
// It is the counterpart of SendDatagramOwned / ReceiveDatagramOwned: whoever
// allocates a payload is asked to release it once the frame carrying it is gone.
type DatagramBufferOwner = wire.DatagramBufferOwner

func releaseDatagramBuffer(owner DatagramBufferOwner) {
	if owner != nil {
		owner.ReleaseDatagramBuffer()
	}
}

type datagramQueue struct {
	sendMx    sync.Mutex
	sendQueue ringbuffer.RingBuffer[*wire.DatagramFrame]
	sent      chan struct{} // used to notify Add that a datagram was dequeued

	rcvMx    sync.Mutex
	rcvQueue ringbuffer.RingBuffer[*wire.DatagramFrame]
	rcvd     chan struct{} // used to notify Receive that a new datagram was received

	closeErr error
	closed   chan struct{}

	hasData func()

	logger utils.Logger
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	return &datagramQueue{
		hasData: hasData,
		rcvd:    make(chan struct{}, 1),
		sent:    make(chan struct{}, 1),
		closed:  make(chan struct{}),
		logger:  logger,
	}
}

// Add queues a new DATAGRAM frame for sending.
// Up to 32 DATAGRAM frames will be queued.
// Once that limit is reached, Add blocks until the queue size has reduced.
// The queue takes ownership of the frame: its payload is released once the frame
// was sent out or discarded.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	h.sendMx.Lock()

	for {
		select {
		case <-h.closed:
			h.sendMx.Unlock()
			f.ReleaseDatagram()
			return h.closeErr
		default:
		}
		if h.sendQueue.Len() < maxDatagramSendQueueLen {
			h.sendQueue.PushBack(f)
			h.sendMx.Unlock()
			h.hasData()
			return nil
		}
		select {
		case <-h.sent: // drain the queue so we don't loop immediately
		default:
		}
		h.sendMx.Unlock()
		select {
		case <-h.closed:
			f.ReleaseDatagram()
			return h.closeErr
		case <-h.sent:
		}
		h.sendMx.Lock()
	}
}

// Peek gets the next DATAGRAM frame for sending.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	if h.sendQueue.Empty() {
		return nil
	}
	return h.sendQueue.PeekFront()
}

func (h *datagramQueue) Pop() {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	_ = h.sendQueue.PopFront()
	select {
	case h.sent <- struct{}{}:
	default:
	}
}

// Discard drops the frame at the head of the send queue without sending it.
func (h *datagramQueue) Discard() {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	if !h.sendQueue.Empty() {
		h.sendQueue.PopFront().ReleaseDatagram()
	}
	select {
	case h.sent <- struct{}{}:
	default:
	}
}

// HandleDatagramFrame handles a received DATAGRAM frame.
// The queue takes ownership of the frame: its payload has to be released by the
// receiver of the frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	var queued bool
	h.rcvMx.Lock()
	if h.rcvQueue.Len() < maxDatagramRcvQueueLen {
		h.rcvQueue.PushBack(f)
		queued = true
		select {
		case h.rcvd <- struct{}{}:
		default:
		}
	}
	h.rcvMx.Unlock()
	if !queued {
		if h.logger.Debug() {
			h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
		}
		f.ReleaseDatagram()
	}
}

// Receive gets a received DATAGRAM frame. The caller takes ownership of the
// frame and has to release its payload.
func (h *datagramQueue) Receive(ctx context.Context) (*wire.DatagramFrame, error) {
	for {
		h.rcvMx.Lock()
		if !h.rcvQueue.Empty() {
			f := h.rcvQueue.PopFront()
			h.rcvMx.Unlock()
			return f, nil
		}
		h.rcvMx.Unlock()
		select {
		case <-h.rcvd:
			continue
		case <-h.closed:
			return nil, h.closeErr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.closeErr = e
	close(h.closed)
	// Payloads of frames that will never be sent or received are returned to
	// their owners, otherwise a closing connection would leak them until the next
	// garbage collection.
	h.sendMx.Lock()
	for !h.sendQueue.Empty() {
		h.sendQueue.PopFront().ReleaseDatagram()
	}
	h.sendMx.Unlock()
	h.rcvMx.Lock()
	for !h.rcvQueue.Empty() {
		h.rcvQueue.PopFront().ReleaseDatagram()
	}
	h.rcvMx.Unlock()
}
