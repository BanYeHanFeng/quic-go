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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// lossyPacketConn is a net.PacketConn that drops every n-th packet, and can drop bursts
// of consecutive packets instead. Loss can be enabled and disabled while the connection
// is running.
type lossyPacketConn struct {
	net.PacketConn
	dropEvery atomic.Int64
	// burstLength and burstPeriod drop the first burstLength packets of every
	// burstPeriod packets, which is the loss pattern of a mobile link: losses arrive in
	// bursts instead of being spread evenly.
	burstLength atomic.Int64
	burstPeriod atomic.Int64
	counter     atomic.Int64
}

func (c *lossyPacketConn) shouldDrop() bool {
	count := c.counter.Add(1)
	if burstLength, burstPeriod := c.burstLength.Load(), c.burstPeriod.Load(); burstLength > 0 && burstPeriod > 0 {
		if (count-1)%burstPeriod < burstLength {
			return true
		}
	}
	every := c.dropEvery.Load()
	if every <= 0 {
		return false
	}
	return count%every == 0
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
	testConfig := &Config{
		MaxIdleTimeout:  2 * time.Minute,
		KeepAlivePeriod: 5 * time.Second,
	}
	listener, err := serverTransport.Listen(serverTLS, testConfig)
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
	clientConn, err := clientTransport.Dial(ctx, serverUDP.LocalAddr(), clientTLS, testConfig)
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

// fecTestOverheadCap is the overhead cap both endpoints are configured with in the
// integration tests. It is checked against the measured overhead at the end of a
// transfer, which is the strongest form of the bandwidth bound: real packets, real
// parity frames, the real send path.
const fecTestOverheadCap = 25

// enableFEC turns on packet level FEC with the configuration QUICX uses by default,
// on both endpoints of the pair.
func enableFEC(t *testing.T, conn *Conn, name string) {
	t.Helper()
	if err := conn.EnableFEC(FECConfig{MaxOverheadPercent: fecTestOverheadCap, MaxGroupSize: 32, MaxParityRows: 2}); err != nil {
		t.Fatalf("enabling FEC on the %s failed: %v", name, err)
	}
}

// requireOverheadWithinCap fails when an endpoint spent more parity traffic than the
// configured share of the traffic FEC protected.
func requireOverheadWithinCap(t *testing.T, name string, stats FECStats) {
	t.Helper()
	if stats.MeasuredOverhead > float64(fecTestOverheadCap)/100+1e-9 {
		t.Fatalf("%s measured overhead %v exceeds the %d%% cap (%d parity bytes / %d protected bytes)",
			name, stats.MeasuredOverhead, fecTestOverheadCap, stats.ParityBytesSent, stats.ProtectedBytesSent)
	}
}

// transfer sends the payload over a new stream and returns the bytes received by the peer.
func transfer(t *testing.T, client *Conn, server *Conn, payload []byte) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	progressCtx, stopProgress := context.WithCancel(ctx)
	defer stopProgress()
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-progressCtx.Done():
				return
			case <-ticker.C:
				t.Logf("still transferring: client %+v, client FEC %+v, server FEC %+v",
					client.ConnectionStats(), client.FECStats(), server.FECStats())
			}
		}
	}()
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
		t.Fatalf("the peer failed to read the payload: %v (client %+v, client FEC %+v, server FEC %+v)",
			err, client.ConnectionStats(), client.FECStats(), server.FECStats())
	case <-ctx.Done():
		t.Fatalf("timeout waiting for the payload (client %+v, client FEC %+v, server FEC %+v)",
			client.ConnectionStats(), client.FECStats(), server.FECStats())
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
	if stats.WindowSize != 0 {
		t.Fatalf("FEC is active on a lossless path (window size %d)", stats.WindowSize)
	}
}

// TestFECRecoversLostPackets verifies that packets lost on the wire are reconstructed
// from the repair rows, i.e. that the receiver never has to wait for a retransmission
// (and the congestion controller never sees the loss).
func TestFECRecoversLostPackets(t *testing.T) {
	pair := newFECTestPair(t)
	defer pair.Close()
	<-pair.clientConn.HandshakeComplete()
	enableFEC(t, pair.clientConn, "client")
	enableFEC(t, pair.serverConn, "server")

	// Drop every 16th packet in both directions (about 12% when both drop points are
	// counted): the redundancy the loss rate asks for fits into the 25% cap, so the
	// window is expected to reconstruct the losses.
	pair.clientLossy.dropEvery.Store(16)
	pair.serverLossy.dropEvery.Store(16)

	payload := randomPacket(t, 4*1024*1024)
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
	requireOverheadWithinCap(t, "client", pair.clientConn.FECStats())
	requireOverheadWithinCap(t, "server", stats)
}

// gsoTestPair sets up a client and a server on real UDP sockets (which enables GSO on
// Linux), with a userspace UDP relay in between that drops every n-th packet in both
// directions. Unlike lossyPacketConn (which hides the socket optimizations from
// quic-go), this exercises the GSO send path together with FEC.
type gsoTestPair struct {
	clientConn      *Conn
	serverConn      *Conn
	clientTransport *Transport
	serverTransport *Transport
	listener        *Listener
	relay           *udpDropRelay
}

func (p *gsoTestPair) Close() {
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
	if p.relay != nil {
		p.relay.Close()
	}
}

// udpDropRelay forwards UDP packets between a client and a server, dropping every
// dropEvery-th packet (in both directions).
type udpDropRelay struct {
	conn      *net.UDPConn
	upstream  *net.UDPAddr
	dropEvery int64
	counter   atomic.Int64
	client    atomic.Pointer[net.UDPAddr]
	closeOnce sync.Once
}

func newUDPDropRelay(upstream *net.UDPAddr, dropEvery int64) (*udpDropRelay, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	relay := &udpDropRelay{conn: conn, upstream: upstream, dropEvery: dropEvery}
	go relay.run()
	return relay, nil
}

func (r *udpDropRelay) Addr() net.Addr { return r.conn.LocalAddr() }

func (r *udpDropRelay) Close() {
	r.closeOnce.Do(func() { _ = r.conn.Close() })
}

func (r *udpDropRelay) run() {
	buffer := make([]byte, 65535)
	for {
		n, addr, err := r.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if r.counter.Add(1)%r.dropEvery == 0 {
			continue
		}
		if addr.Port == r.upstream.Port && addr.IP.Equal(r.upstream.IP) {
			// downstream: server -> client
			if client := r.client.Load(); client != nil {
				_, _ = r.conn.WriteToUDP(buffer[:n], client)
			}
			continue
		}
		// upstream: client -> server
		r.client.Store(addr)
		_, _ = r.conn.WriteToUDP(buffer[:n], r.upstream)
	}
}

func newGSOTestPair(t *testing.T, dropEvery int64) *gsoTestPair {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	testConfig := &Config{
		MaxIdleTimeout:  2 * time.Minute,
		KeepAlivePeriod: 5 * time.Second,
	}
	serverTransport := &Transport{Conn: serverUDP}
	listener, err := serverTransport.Listen(serverTLS, testConfig)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := newUDPDropRelay(serverUDP.LocalAddr().(*net.UDPAddr), dropEvery)
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
	clientTransport := &Transport{Conn: clientUDP}
	clientConn, err := clientTransport.Dial(ctx, relay.Addr(), clientTLS, testConfig)
	if err != nil {
		t.Fatal(err)
	}
	pair := &gsoTestPair{
		clientConn:      clientConn,
		clientTransport: clientTransport,
		serverTransport: serverTransport,
		listener:        listener,
		relay:           relay,
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

// TestFECRecoversLostPacketsGSO runs the lossy transfer on real UDP sockets: on Linux
// quic-go sends batches of packets with GSO there, a code path that a wrapped
// (non OOB capable) packet connection doesn't exercise.
//
// Note that a userspace relay sees a GSO batch as one coalesced datagram (loopback
// GRO), so a drop takes out a whole burst of packets at once. Real networks drop
// individual packets, so this test verifies that FEC packets flow through the GSO send
// path and that the transfer survives; the actual repair is covered by
// TestFECRecoversLostPackets (and by the relay-free clean path test).
func TestFECRecoversLostPacketsGSO(t *testing.T) {
	pair := newGSOTestPair(t, 8)
	defer pair.Close()
	<-pair.clientConn.HandshakeComplete()
	enableFEC(t, pair.clientConn, "client")
	enableFEC(t, pair.serverConn, "server")

	payload := randomPacket(t, 4*1024*1024)
	received := transfer(t, pair.clientConn, pair.serverConn, payload)
	if !bytes.Equal(received, payload) {
		t.Fatalf("payload mismatch: got %d bytes, expected %d", len(received), len(payload))
	}
	clientStats := pair.clientConn.FECStats()
	serverStats := pair.serverConn.FECStats()
	if clientStats.ParityPacketsSent == 0 {
		t.Fatalf("no parity packet was sent over the GSO path: %+v", clientStats)
	}
	if serverStats.ParityPacketsReceived == 0 {
		t.Fatalf("no parity packet arrived over the GSO path: %+v", serverStats)
	}
	requireOverheadWithinCap(t, "client (GSO)", clientStats)
	requireOverheadWithinCap(t, "server (GSO)", serverStats)
}

// TestFECSurvivesLostPacketsAboveTheCap keeps the heavier loss rate of the block
// scheme's regression test: every 8th packet is dropped on both sides, which is about
// 23% in each direction once both drop points are counted. That is beyond the
// redundancy the 25% cap allows, so the window cannot reconstruct most of it - a
// quarter of the packets of every window are missing, and a packet is covered by fewer
// rows than that while it stays in the window. QUIC retransmission carries the
// transfer; what has to hold is that FEC doesn't spend more than the cap and that the
// connection survives the loss.
func TestFECSurvivesLostPacketsAboveTheCap(t *testing.T) {
	pair := newFECTestPair(t)
	defer pair.Close()
	<-pair.clientConn.HandshakeComplete()
	enableFEC(t, pair.clientConn, "client")
	enableFEC(t, pair.serverConn, "server")

	pair.clientLossy.dropEvery.Store(8)
	pair.serverLossy.dropEvery.Store(8)

	payload := randomPacket(t, 4*1024*1024)
	received := transfer(t, pair.clientConn, pair.serverConn, payload)
	if !bytes.Equal(received, payload) {
		t.Fatalf("payload mismatch: got %d bytes, expected %d", len(received), len(payload))
	}
	stats := pair.serverConn.FECStats()
	if stats.ParityPacketsReceived == 0 {
		t.Fatal("the receiver didn't see any repair row")
	}
	if stats.WindowSize == 0 {
		t.Fatalf("FEC didn't engage on a 23%% loss path: %+v", stats)
	}
	requireOverheadWithinCap(t, "client", pair.clientConn.FECStats())
	requireOverheadWithinCap(t, "server", stats)
}

// TestFECRecoversBurstLossesPath drops bursts of consecutive packets on the path: the
// whole burst lands in the same window, and the rows that cover it reconstruct all of
// it. A block code could only repair a burst as long as the number of parity rows of
// one group.
func TestFECRecoversBurstLossesPath(t *testing.T) {
	pair := newFECTestPair(t)
	defer pair.Close()
	<-pair.clientConn.HandshakeComplete()
	enableFEC(t, pair.clientConn, "client")
	enableFEC(t, pair.serverConn, "server")

	// Three consecutive packets every 32 packets: about 9% loss, all of it in bursts.
	// The redundancy the loss rate asks for gives the window enough rows over a burst
	// to reconstruct all of it.
	pair.clientLossy.burstLength.Store(3)
	pair.clientLossy.burstPeriod.Store(32)
	pair.serverLossy.burstLength.Store(3)
	pair.serverLossy.burstPeriod.Store(32)

	payload := randomPacket(t, 4*1024*1024)
	received := transfer(t, pair.clientConn, pair.serverConn, payload)
	if !bytes.Equal(received, payload) {
		t.Fatalf("payload mismatch: got %d bytes, expected %d", len(received), len(payload))
	}
	stats := pair.serverConn.FECStats()
	if stats.RecoveredPackets == 0 {
		t.Fatalf("no packet was reconstructed from a burst: %+v", stats)
	}
	requireOverheadWithinCap(t, "client", pair.clientConn.FECStats())
	requireOverheadWithinCap(t, "server", stats)
}
