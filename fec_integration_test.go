package quic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// lossyPacketConn is a net.PacketConn that drops every n-th packet. Loss can be
// enabled and disabled while the connection is running.
type lossyPacketConn struct {
	net.PacketConn
	dropEvery atomic.Int64
	counter   atomic.Int64
}

func (c *lossyPacketConn) shouldDrop() bool {
	every := c.dropEvery.Load()
	if every <= 0 {
		return false
	}
	return c.counter.Add(1)%every == 0
}

func (c *lossyPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if c.shouldDrop() {
			continue
		}
		return n, addr, nil
	}
}

func (c *lossyPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.shouldDrop() {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

type fecTestPair struct {
	clientConn      *Conn
	serverConn      *Conn
	clientTransport *Transport
	serverTransport *Transport
	listener        *Listener
	clientLossy     *lossyPacketConn
	serverLossy     *lossyPacketConn
}

func (p *fecTestPair) Close() {
	if p.clientConn != nil {
		_ = p.clientConn.CloseWithError(0, "")
	}
	if p.serverConn != nil {
		_ = p.serverConn.CloseWithError(0, "")
	}
	if p.listener != nil {
		_ = p.listener.Close()
	}
	if p.clientTransport != nil {
		_ = p.clientTransport.Close()
	}
	if p.serverTransport != nil {
		_ = p.serverTransport.Close()
	}
}

func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"fec-test"}}
	clientTLS := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"fec-test"}}
	return serverTLS, clientTLS
}

func newFECTestPair(t *testing.T) *fecTestPair {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	serverLossy := &lossyPacketConn{PacketConn: serverUDP}
	serverTransport := &Transport{Conn: serverLossy}
	listener, err := serverTransport.Listen(serverTLS, &Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	acceptCh := make(chan *Conn, 1)
	acceptErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			acceptErrCh <- err
			return
		}
		acceptCh <- conn
	}()

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	clientLossy := &lossyPacketConn{PacketConn: clientUDP}
	clientTransport := &Transport{Conn: clientLossy}
	clientConn, err := clientTransport.Dial(ctx, serverUDP.LocalAddr(), clientTLS, &Config{})
	if err != nil {
		t.Fatal(err)
	}
	pair := &fecTestPair{
		clientConn:      clientConn,
		clientTransport: clientTransport,
		serverTransport: serverTransport,
		listener:        listener,
		clientLossy:     clientLossy,
		serverLossy:     serverLossy,
	}
	var serverConn *Conn
	select {
	case serverConn = <-acceptCh:
	case err := <-acceptErrCh:
		pair.Close()
		t.Fatal(err)
	case <-ctx.Done():
		pair.Close()
		t.Fatal("timeout accepting the QUIC connection")
	}
	pair.serverConn = serverConn
	return pair
}

func enableFEC(t *testing.T, conn *Conn, name string) {
	t.Helper()
	if err := conn.EnableFEC(FECConfig{MaxOverheadPercent: 25, MaxGroupSize: 8, MinGroupSize: 2, MaxParityRows: 1}); err != nil {
		t.Fatalf("enabling FEC on the %s failed: %v", name, err)
	}
}

// transfer sends the payload over a new stream and returns the bytes received by the peer.
func transfer(t *testing.T, client *Conn, server *Conn, payload []byte) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	stream, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	receivedCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		serverStream, err := server.AcceptStream(ctx)
		if err != nil {
			errCh <- err
			return
		}
		data, err := io.ReadAll(serverStream)
		if err != nil {
			errCh <- err
			return
		}
		receivedCh <- data
	}()
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case data := <-receivedCh:
		return data
	case err := <-errCh:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for the payload")
	}
	return nil
}

// TestFECCleanPathSendsNoParity verifies that FEC doesn't spend any bandwidth when
// the path doesn't lose packets: redundancy is adaptive, not fixed.
func TestFECCleanPathSendsNoParity(t *testing.T) {
	pair := newFECTestPair(t)
	defer pair.Close()
	<-pair.clientConn.HandshakeComplete()
	enableFEC(t, pair.clientConn, "client")
	enableFEC(t, pair.serverConn, "server")

	payload := randomPacket(t, 256*1024)
	received := transfer(t, pair.clientConn, pair.serverConn, payload)
	if !bytes.Equal(received, payload) {
		t.Fatal("payload mismatch")
	}
	stats := pair.clientConn.FECStats()
	if stats.ParityPacketsSent != 0 {
		t.Fatalf("FEC sent %d parity packets (%d bytes) on a lossless path", stats.ParityPacketsSent, stats.ParityBytesSent)
	}
	if stats.GroupSize != 0 {
		t.Fatalf("FEC is active on a lossless path (group size %d)", stats.GroupSize)
	}
}

// TestFECRecoversLostPackets verifies that packets lost on the wire are reconstructed
// from the parity packets, i.e. that the receiver never has to wait for a
// retransmission (and the congestion controller never sees the loss).
func TestFECRecoversLostPackets(t *testing.T) {
	pair := newFECTestPair(t)
	defer pair.Close()
	<-pair.clientConn.HandshakeComplete()
	enableFEC(t, pair.clientConn, "client")
	enableFEC(t, pair.serverConn, "server")

	// Drop every 4th packet in both directions.
	pair.clientLossy.dropEvery.Store(4)
	pair.serverLossy.dropEvery.Store(4)

	payload := randomPacket(t, 512*1024)
	received := transfer(t, pair.clientConn, pair.serverConn, payload)
	if !bytes.Equal(received, payload) {
		t.Fatalf("payload mismatch: got %d bytes, expected %d", len(received), len(payload))
	}
	stats := pair.serverConn.FECStats()
	if stats.ParityPacketsReceived == 0 {
		t.Fatal("the receiver didn't see any parity packets")
	}
	if stats.RecoveredPackets == 0 {
		t.Fatalf("no packet was reconstructed from parity: %+v", stats)
	}
}
