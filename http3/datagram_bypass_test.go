package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
)

func TestHTTP3SendDatagramWithoutCongestionControl(t *testing.T) {
	cert := httptest.NewTLSServer(nil)
	serverTLS := cert.TLS.Clone()
	cert.Close()
	serverTLS.NextProtos = []string{NextProtoH3}

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	serverDone := make(chan error, 1)
	received := make(chan []byte, 1)
	server := &Server{
		TLSConfig:       serverTLS,
		EnableDatagrams: true,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			str := w.(HTTPStreamer).HTTPStream()
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			data, err := str.ReceiveDatagram(ctx)
			if err != nil {
				serverDone <- err
				return
			}
			received <- data
			serverDone <- str.SendDatagramWithoutCongestionControl([]byte("server-bypass-reply"))
		}),
	}
	defer server.Close()
	go func() {
		_ = server.Serve(udpConn)
	}()

	tr := &Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		EnableDatagrams: true,
	}
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qconn, err := quic.DialAddr(ctx, udpConn.LocalAddr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{NextProtoH3}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer qconn.CloseWithError(0, "")

	cc := tr.NewClientConn(qconn)
	reqStr, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodConnect, "https://localhost/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Proto = "connect-ip"
	if err := reqStr.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	resp, err := reqStr.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}

	payload := []byte("client-bypass-datagram")
	if err := reqStr.SendDatagramWithoutCongestionControl(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if !bytes.Equal(got, payload) {
			t.Fatalf("server got %q, want %q", got, payload)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for server to receive bypass datagram")
	}
	reply, err := reqStr.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(reply) != "server-bypass-reply" {
		t.Fatalf("client got %q", reply)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}

	// Closing the stream must reject subsequent bypass datagrams via context.Cause.
	reqStr.CancelWrite(0)
	if err := reqStr.SendDatagramWithoutCongestionControl(payload); err == nil {
		t.Fatal("expected error after CancelWrite")
	}
}
