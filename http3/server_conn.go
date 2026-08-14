package http3

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/qpack"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/qlogwriter"
)

// RawServerConn is an HTTP/3 server connection.
// It can be used for advanced use cases where the application wants to manage the QUIC connection lifecycle.
type RawServerConn struct {
	rawConn rawConn

	idleTimeout time.Duration
	idleTimer   *time.Timer

	serverContext  context.Context
	requestHandler http.Handler
	maxHeaderBytes int

	decoder *qpack.Decoder

	qlogger qlogwriter.Recorder
	logger  *slog.Logger

	controlStream    *quic.SendStream
	draining         atomic.Bool
	gracefullyClosed chan struct{}
	graceCloseOnce   sync.Once
}

func newRawServerConn(
	conn *quic.Conn,
	enableDatagrams bool,
	idleTimeout time.Duration,
	qlogger qlogwriter.Recorder,
	logger *slog.Logger,
	serverContext context.Context,
	requestHandler http.Handler,
	maxHeaderBytes int,
) *RawServerConn {
	c := &RawServerConn{
		idleTimeout:      idleTimeout,
		serverContext:    serverContext,
		requestHandler:   requestHandler,
		maxHeaderBytes:   maxHeaderBytes,
		decoder:          qpack.NewDecoder(),
		qlogger:          qlogger,
		logger:           logger,
		gracefullyClosed: make(chan struct{}),
	}
	c.rawConn = *newRawConn(conn, enableDatagrams, c.onStreamsEmpty, nil, qlogger, logger)
	if idleTimeout > 0 {
		c.idleTimer = time.AfterFunc(idleTimeout, func() {
			conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeNoError), "idle timeout")
		})
	}
	return c
}

func (c *RawServerConn) onStreamsEmpty() {
	if c.idleTimeout > 0 {
		c.idleTimer.Reset(c.idleTimeout)
	}
}

// CloseWithError closes the connection with the given error code and message.
func (c *RawServerConn) CloseWithError(code quic.ApplicationErrorCode, msg string) error {
	if c.idleTimer != nil {
		c.idleTimer.Stop()
	}
	return c.rawConn.CloseWithError(code, msg)
}

// HandleRequestStream handles an HTTP/3 request on a bidirectional request stream.
// The stream can either be obtained by calling AcceptStream on the underlying QUIC connection,
// or (internally) by using the server's stream accept loop.
func (c *RawServerConn) HandleRequestStream(str *quic.Stream) {
	hstr := c.rawConn.TrackStream(str)
	c.handleRequestStream(hstr)
}

func (c *RawServerConn) requestMaxHeaderBytes() int {
	if c.maxHeaderBytes <= 0 {
		return http.DefaultMaxHeaderBytes
	}
	return c.maxHeaderBytes
}

func (c *RawServerConn) openControlStream(settings *settingsFrame) (*quic.SendStream, error) {
	return c.rawConn.openControlStream(settings)
}

// SetControlStream records the already-open control stream so that the
// connection can later send a GOAWAY frame for graceful shutdown.
func (c *RawServerConn) SetControlStream(str *quic.SendStream) {
	c.controlStream = str
}

// Draining reports whether graceful shutdown has been initiated.
func (c *RawServerConn) Draining() bool {
	return c.draining.Load()
}

// RejectRequestStream resets a newly-arrived request stream once the
// connection is draining: after a GOAWAY frame, a conforming client must not
// send new requests, and any that race with the GOAWAY are rejected.
func (c *RawServerConn) RejectRequestStream(str *quic.Stream) {
	str.CancelRead(quic.StreamErrorCode(ErrCodeRequestRejected))
	str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestRejected))
}

// GracefulShutdown initiates an RFC 9114 graceful shutdown of this HTTP/3
// connection: it sends a GOAWAY frame, rejects requests that arrive after the
// GOAWAY, and closes the QUIC connection with H3_NO_ERROR once the last
// tracked stream has finished. The returned channel is closed when the
// underlying connection has been closed.
func (c *RawServerConn) GracefulShutdown() <-chan struct{} {
	c.graceCloseOnce.Do(func() {
		c.draining.Store(true)
		nextStreamID := c.rawConn.nextStreamID()
		if c.controlStream != nil {
			// Sending might block if the peer has not granted enough flow
			// control credit; the write is guaranteed to return once the
			// connection is closed, so a separate goroutine is required.
			go func() {
				_, _ = c.controlStream.Write((&goAwayFrame{StreamID: nextStreamID}).Append(nil))
			}()
		}
		go c.drainAndClose()
	})
	return c.gracefullyClosed
}

func (c *RawServerConn) drainAndClose() {
	defer close(c.gracefullyClosed)
	// Stop the idle timer: once we have asked the peer to close, the idle
	// timeout must not race with the graceful shutdown.
	if c.idleTimer != nil {
		c.idleTimer.Stop()
	}
	// If no request stream is active, close right away; otherwise block until
	// every stream tracked by the HTTP/3 layer has completed.
	if !c.rawConn.hasActiveStreams() {
		_ = c.CloseWithError(quic.ApplicationErrorCode(ErrCodeNoError), "")
		return
	}
	<-c.rawConn.streamsGone()
	_ = c.CloseWithError(quic.ApplicationErrorCode(ErrCodeNoError), "")
}

func (c *RawServerConn) handleRequestStream(str *stateTrackingStream) {
	if c.idleTimeout > 0 {
		// This only applies if the stream is the first active stream,
		// but it's ok to stop a stopped timer.
		c.idleTimer.Stop()
	}

	conn := &c.rawConn
	qlogger := c.qlogger
	decoder := c.decoder
	connCtx := c.serverContext
	maxHeaderBytes := c.requestMaxHeaderBytes()

	fp := &frameParser{closeConn: conn.CloseWithError, r: str, streamID: str.StreamID()}
	frame, err := fp.ParseNext(qlogger)
	if err != nil {
		str.CancelRead(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		return
	}
	hf, ok := frame.(*headersFrame)
	if !ok {
		conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "expected first frame to be a HEADERS frame")
		return
	}
	if hf.Length > uint64(maxHeaderBytes) {
		maybeQlogInvalidHeadersFrame(qlogger, str.StreamID(), hf.Length)
		// stop the client from sending more data
		str.CancelRead(quic.StreamErrorCode(ErrCodeExcessiveLoad))
		// send a 431 Response (Request Header Fields Too Large)
		c.rejectWithHeaderFieldsTooLarge(str)
		return
	}
	headerBlock := make([]byte, hf.Length)
	if _, err := io.ReadFull(str, headerBlock); err != nil {
		maybeQlogInvalidHeadersFrame(qlogger, str.StreamID(), hf.Length)
		str.CancelRead(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestIncomplete))
		return
	}
	decodeFn := decoder.Decode(headerBlock)
	var hfs []qpack.HeaderField
	if qlogger != nil {
		hfs = make([]qpack.HeaderField, 0, 16)
	}
	req, err := requestFromHeaders(decodeFn, maxHeaderBytes, &hfs)
	if qlogger != nil {
		qlogParsedHeadersFrame(qlogger, str.StreamID(), hf, hfs)
	}
	if err != nil {
		if errors.Is(err, errHeaderTooLarge) {
			// stop the client from sending more data
			str.CancelRead(quic.StreamErrorCode(ErrCodeExcessiveLoad))
			// send a 431 Response (Request Header Fields Too Large)
			c.rejectWithHeaderFieldsTooLarge(str)
			return
		}

		errCode := ErrCodeMessageError
		var qpackErr *qpackError
		if errors.As(err, &qpackErr) {
			errCode = ErrCodeQPACKDecompressionFailed
		}
		str.CancelRead(quic.StreamErrorCode(errCode))
		str.CancelWrite(quic.StreamErrorCode(errCode))
		return
	}

	connState := conn.ConnectionState().TLS
	req.TLS = &connState
	req.RemoteAddr = conn.RemoteAddr().String()

	// Check that the client doesn't send more data in DATA frames than indicated by the Content-Length header (if set).
	// See section 4.1.2 of RFC 9114.
	contentLength := int64(-1)
	if _, ok := req.Header["Content-Length"]; ok && req.ContentLength >= 0 {
		contentLength = req.ContentLength
	}
	hstr := newStream(str, conn, nil, func(r io.Reader, hf *headersFrame) error {
		trailers, err := decodeTrailers(r, hf, maxHeaderBytes, decoder, qlogger, str.StreamID())
		if err != nil {
			return err
		}
		req.Trailer = trailers
		return nil
	}, qlogger)
	body := newRequestBody(hstr, contentLength, connCtx, conn.ReceivedSettings(), conn.Settings)
	req.Body = body

	if c.logger != nil {
		c.logger.Debug("handling request", "method", req.Method, "host", req.Host, "uri", req.RequestURI)
	}

	ctx, cancel := context.WithCancel(connCtx)
	req = req.WithContext(ctx)
	context.AfterFunc(str.Context(), cancel)

	r := newResponseWriter(hstr, conn, req.Method == http.MethodHead, c.logger)
	handler := c.requestHandler
	if handler == nil {
		handler = http.DefaultServeMux
	}

	// It's the client's responsibility to decide which requests are eligible for 0-RTT.
	var panicked bool
	func() {
		defer func() {
			if p := recover(); p != nil {
				panicked = true
				if p == http.ErrAbortHandler {
					return
				}
				// Copied from net/http/server.go
				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				logger := c.logger
				if logger == nil {
					logger = slog.Default()
				}
				logger.Error("http3: panic serving", "arg", p, "trace", string(buf))
			}
		}()
		handler.ServeHTTP(r, req)
	}()

	if r.wasStreamHijacked() {
		return
	}

	// abort the stream when there is a panic
	if panicked {
		str.CancelRead(quic.StreamErrorCode(ErrCodeInternalError))
		str.CancelWrite(quic.StreamErrorCode(ErrCodeInternalError))
		return
	}

	// response not written to the client yet, set Content-Length
	if !r.headerWritten {
		if _, haveCL := r.header["Content-Length"]; !haveCL {
			r.header.Set("Content-Length", strconv.FormatInt(r.numWritten, 10))
		}
	}
	r.Flush()
	r.flushTrailers()

	// If the EOF was read by the handler, CancelRead() is a no-op.
	str.CancelRead(quic.StreamErrorCode(ErrCodeNoError))
	str.Close()
}

func (c *RawServerConn) rejectWithHeaderFieldsTooLarge(str *stateTrackingStream) {
	hstr := newStream(str, &c.rawConn, nil, nil, c.qlogger)
	defer hstr.Close()
	r := newResponseWriter(hstr, &c.rawConn, false, c.logger)
	r.WriteHeader(http.StatusRequestHeaderFieldsTooLarge)
	r.Flush()
}

// HandleUnidirectionalStream handles an incoming unidirectional stream.
func (c *RawServerConn) HandleUnidirectionalStream(str *quic.ReceiveStream) {
	c.rawConn.handleUnidirectionalStream(str, true)
}
