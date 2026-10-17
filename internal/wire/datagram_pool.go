package wire

import "sync"

// A DatagramBufferOwner hands a DATAGRAM payload back to whoever allocated it.
//
// DATAGRAM frames are the only frames whose payload is not consumed by the
// QUIC stack itself: it is handed to the application (receive side) or taken
// over from the application (send side). Both sides forward packets at a rate
// where one allocation per datagram dominates the allocation profile, so
// payloads are recycled instead of allocated, and the owner is what returns
// them.
type DatagramBufferOwner interface {
	ReleaseDatagramBuffer()
}

// DATAGRAM payloads are pooled in power-of-two size classes between 64 bytes and
// 64 KiB, which covers every datagram that fits into a QUIC packet as well as
// the largest payload MaxDatagramSize allows.
const (
	datagramPoolMinShift = 6  // 64 B
	datagramPoolMaxShift = 16 // 64 KiB
	datagramPoolClasses  = datagramPoolMaxShift - datagramPoolMinShift + 1
)

// datagramPayload is a pooled payload buffer of one size class. It is both the
// buffer and the handle that returns it: the frame holds the handle, and
// releasing the frame puts the buffer back into its class pool.
type datagramPayload struct {
	data []byte
}

var datagramPayloadPools [datagramPoolClasses]sync.Pool

func (p *datagramPayload) ReleaseDatagramBuffer() {
	size := cap(p.data)
	if size < 1<<datagramPoolMinShift || size > 1<<datagramPoolMaxShift {
		return
	}
	shift := datagramPoolMinShift
	for 1<<shift < size {
		shift++
	}
	p.data = p.data[:size]
	datagramPayloadPools[shift-datagramPoolMinShift].Put(p)
}

// getDatagramPayload returns a payload buffer of the requested size together with
// its owner. The caller owns the returned buffer and must call
// ReleaseDatagramBuffer on the owner once the payload is no longer referenced.
// Sizes above 64 KiB are allocated, since they cannot be sent in a QUIC datagram
// and are only reachable through a peer that ignores the frame size limit.
func getDatagramPayload(size int) ([]byte, DatagramBufferOwner) {
	if size <= 0 {
		return nil, nil
	}
	if size > 1<<datagramPoolMaxShift {
		return make([]byte, size), nil
	}
	shift := datagramPoolMinShift
	for 1<<shift < size {
		shift++
	}
	pool := &datagramPayloadPools[shift-datagramPoolMinShift]
	payload, ok := pool.Get().(*datagramPayload)
	if !ok {
		payload = &datagramPayload{data: make([]byte, 1<<shift)}
	}
	return payload.data[:size], payload
}
