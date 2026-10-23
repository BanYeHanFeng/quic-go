package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/quicvarint"
)

func newPendingDatagramTestPair(t *testing.T, handler http.Handler) (*ClientConn, *RawServerConn, *quic.Conn, *quic.Conn) {
	t.Helper()
	cert := httptest.NewTLSServer(nil)
	serverTLS := cert.TLS.Clone()
	cert.Close()
	serverTLS.NextProtos = []string{NextProtoH3}

	ln, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientQ, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{NextProtoH3}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clientQ.CloseWithError(0, "") })
	serverQ, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { serverQ.CloseWithError(0, "") })

	srv := newRawServerConn(serverQ, true, 0, nil, nil, context.Background(), handler, 1<<20)
	if _, err := srv.openControlStream(&settingsFrame{
		Datagram:            true,
		ExtendedConnect:     true,
		MaxFieldSectionSize: 1 << 20,
	}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			str, err := serverQ.AcceptUniStream(context.Background())
			if err != nil {
				return
			}
			go srv.HandleUnidirectionalStream(str)
		}
	}()

	tr := &Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		EnableDatagrams: true,
	}
	t.Cleanup(func() { tr.Close() })
	cc := tr.NewClientConn(clientQ)

	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal("client did not receive server SETTINGS")
	}
	select {
	case <-srv.rawConn.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal("server did not receive client SETTINGS")
	}
	return cc, srv, clientQ, serverQ
}

func waitPendingCount(t *testing.T, rc *rawConn, id quic.StreamID, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rc.streamMx.Lock()
		var got int
		if p := rc.pendingDatagrams[id]; p != nil {
			got = len(p.queue)
		}
		rc.streamMx.Unlock()
		if got >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d pending datagrams on stream %d", want, id)
}

func TestPendingDatagramsExtendedConnectHandoff(t *testing.T) {
	gotCh := make(chan [][]byte, 1)
	errCh := make(chan error, 1)
	cc, srv, _, serverQ := newPendingDatagramTestPair(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		str := w.(HTTPStreamer).HTTPStream()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		var got [][]byte
		for range 4 {
			d, err := str.ReceiveDatagram(ctx)
			if err != nil {
				errCh <- err
				return
			}
			got = append(got, d)
		}
		gotCh <- got
		errCh <- nil
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reqStr, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodConnect, "https://localhost/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Proto = "connect-udp"
	if err := reqStr.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}

	// Send early datagrams before the server accepts and tracks the request stream.
	early := []string{"early-1", "early-2", "early-3"}
	for _, msg := range early {
		if err := reqStr.SendDatagram([]byte(msg)); err != nil {
			t.Fatal(err)
		}
	}
	waitPendingCount(t, srv.rawConn, reqStr.StreamID(), len(early))

	// Now accept and track the stream on the server.
	serverStr, err := serverQ.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go srv.HandleRequestStream(serverStr)

	resp, err := reqStr.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if err := reqStr.SendDatagram([]byte("late-4")); err != nil {
		t.Fatal(err)
	}

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	got := <-gotCh
	want := []string{"early-1", "early-2", "early-3", "late-4"}
	if len(got) != len(want) {
		t.Fatalf("got %d datagrams, want %d", len(got), len(want))
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Fatalf("datagram[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestPendingDatagramsRejectedForNonExtendedConnect(t *testing.T) {
	handlerCalled := make(chan struct{}, 1)
	cc, srv, clientQ, serverQ := newPendingDatagramTestPair(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case handlerCalled <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reqStr, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://localhost/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := reqStr.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}

	// Send an early HTTP datagram for this ordinary GET request before server TrackStream.
	raw := quicvarint.Append(nil, uint64(reqStr.StreamID()/4))
	raw = append(raw, []byte("forbidden-early")...)
	if err := clientQ.SendDatagram(raw); err != nil {
		t.Fatal(err)
	}
	waitPendingCount(t, srv.rawConn, reqStr.StreamID(), 1)

	serverStr, err := serverQ.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go srv.HandleRequestStream(serverStr)

	_, err = reqStr.ReadResponse()
	if err == nil {
		t.Fatal("expected ordinary GET request with early datagram to be aborted")
	}
	var h3Err *Error
	if !errors.As(err, &h3Err) || h3Err.ErrorCode != ErrCodeDatagramError {
		t.Fatalf("got error %v, want H3_DATAGRAM_ERROR", err)
	}
}

func TestPendingDatagramsClientDropsUntrackedAndCapsExpire(t *testing.T) {
	cc, srv, _, serverQ := newPendingDatagramTestPair(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	// Client must not buffer datagrams for untracked streams.
	if cc.rawConn.bufferPendingDatagrams {
		t.Fatal("client unexpectedly enabled pending datagram buffering")
	}
	raw := quicvarint.Append(nil, uint64(40/4))
	raw = append(raw, []byte("unknown-stream")...)
	if err := serverQ.SendDatagram(raw); err != nil {
		t.Fatal(err)
	}
	// Send a known datagram or wait briefly and ensure client pending map stays empty.
	time.Sleep(20 * time.Millisecond)
	cc.rawConn.streamMx.Lock()
	clientPending := len(cc.rawConn.pendingDatagrams)
	cc.rawConn.streamMx.Unlock()
	if clientPending != 0 {
		t.Fatalf("client buffered %d untracked streams", clientPending)
	}

	// Verify 16-stream cap, 32-datagram cap, expiration eviction, and TrackStream expiration drop.
	rc := srv.rawConn
	rc.streamMx.Lock()
	for i := range maxPendingDatagramStreams {
		id := quic.StreamID(4 * (100 + i))
		for j := range streamDatagramQueueLen + 5 {
			rc.bufferPendingDatagramLocked(id, []byte(fmt.Sprintf("%d-%d", i, j)))
		}
	}
	// 17th stream must be dropped while all 16 are unexpired.
	overflowID := quic.StreamID(4 * (100 + maxPendingDatagramStreams))
	rc.bufferPendingDatagramLocked(overflowID, []byte("overflow"))
	if len(rc.pendingDatagrams) != maxPendingDatagramStreams {
		rc.streamMx.Unlock()
		t.Fatalf("pending stream count=%d, want %d", len(rc.pendingDatagrams), maxPendingDatagramStreams)
	}
	if _, ok := rc.pendingDatagrams[overflowID]; ok {
		rc.streamMx.Unlock()
		t.Fatal("overflow stream was buffered past limit")
	}
	firstID := quic.StreamID(4 * 100)
	if got := len(rc.pendingDatagrams[firstID].queue); got != streamDatagramQueueLen {
		rc.streamMx.Unlock()
		t.Fatalf("per-stream queue=%d, want %d", got, streamDatagramQueueLen)
	}
	if !bytes.Equal(rc.pendingDatagrams[firstID].queue[0], []byte("0-0")) ||
		!bytes.Equal(rc.pendingDatagrams[firstID].queue[streamDatagramQueueLen-1], []byte(fmt.Sprintf("0-%d", streamDatagramQueueLen-1))) {
		rc.streamMx.Unlock()
		t.Fatal("per-stream pending datagram FIFO order violated")
	}

	// Expire one entry; buffering overflowID must evict it and accept overflowID.
	rc.pendingDatagrams[firstID].deadline = time.Now().Add(-time.Second)
	rc.bufferPendingDatagramLocked(overflowID, []byte("accepted-after-expiry"))
	if _, ok := rc.pendingDatagrams[firstID]; ok {
		rc.streamMx.Unlock()
		t.Fatal("expired pending stream was not evicted")
	}
	if p := rc.pendingDatagrams[overflowID]; p == nil || len(p.queue) != 1 || string(p.queue[0]) != "accepted-after-expiry" {
		rc.streamMx.Unlock()
		t.Fatal("new stream not buffered after evicting expired stream")
	}
	rc.streamMx.Unlock()

	// TrackStream must drop expired pending datagrams instead of handing them over.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientStr, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Trigger stream creation on wire.
	if err := clientStr.SendRequestHeader(mustConnectRequest(t)); err != nil {
		t.Fatal(err)
	}
	srvStr, err := serverQ.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rc.streamMx.Lock()
	rc.pendingDatagrams[srvStr.StreamID()] = &pendingDatagrams{
		deadline: time.Now().Add(-time.Second),
		queue:    [][]byte{[]byte("stale")},
	}
	rc.streamMx.Unlock()
	tracked := rc.TrackStream(srvStr)
	tracked.mx.Lock()
	staleLen := len(tracked.queue)
	tracked.mx.Unlock()
	if staleLen != 0 {
		t.Fatalf("TrackStream handed over %d expired datagrams", staleLen)
	}
}

func mustConnectRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodConnect, "https://localhost/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Proto = "connect-udp"
	return req
}
