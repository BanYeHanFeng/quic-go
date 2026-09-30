package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
)

type gatedCongestion struct {
	allow           atomic.Bool
	pacing          bool
	sent            atomic.Int64
	acked           chan struct{}
	blockedObserved chan struct{}
}

func (*gatedCongestion) SetRTTStatsProvider(congestion.RTTStatsProvider) {}
func (c *gatedCongestion) TimeUntilSend(congestion.ByteCount) monotime.Time {
	if c.allow.Load() {
		return 0
	}
	return monotime.Now().Add(time.Hour)
}

func (c *gatedCongestion) observeBlocked() {
	if c.blockedObserved != nil {
		select {
		case c.blockedObserved <- struct{}{}:
		default:
		}
	}
}

func (c *gatedCongestion) HasPacingBudget(monotime.Time) bool {
	allowed := !c.pacing || c.allow.Load()
	if !allowed {
		c.observeBlocked()
	}
	return allowed
}

func (c *gatedCongestion) CanSend(congestion.ByteCount) bool {
	allowed := c.pacing || c.allow.Load()
	if !allowed {
		c.observeBlocked()
	}
	return allowed
}

func (c *gatedCongestion) OnPacketSent(_ monotime.Time, _ congestion.ByteCount, _ congestion.PacketNumber, _ congestion.ByteCount, eliciting bool) {
	if eliciting {
		c.sent.Add(1)
	}
}
func (*gatedCongestion) MaybeExitSlowStart() {}
func (c *gatedCongestion) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
	if c.acked != nil {
		select {
		case c.acked <- struct{}{}:
		default:
		}
	}
}

func (*gatedCongestion) OnCongestionEvent(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount) {
}
func (*gatedCongestion) OnRetransmissionTimeout(bool)              {}
func (*gatedCongestion) SetMaxDatagramSize(congestion.ByteCount)   {}
func (*gatedCongestion) InSlowStart() bool                         { return false }
func (*gatedCongestion) InRecovery() bool                          { return false }
func (*gatedCongestion) GetCongestionWindow() congestion.ByteCount { return 1 << 20 }

func bypassTestPair(t *testing.T, disableGSO bool) (*Conn, *Conn) {
	t.Helper()
	cert := httptest.NewTLSServer(nil)
	serverTLS := cert.TLS.Clone()
	cert.Close()
	serverTLS.NextProtos = []string{"bypass-test"}
	listener, err := ListenAddr("127.0.0.1:0", serverTLS, &Config{EnableDatagrams: true, DisableGSO: disableGSO, DisablePathMTUDiscovery: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := DialAddr(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: serverTLS.NextProtos}, &Config{EnableDatagrams: true, DisableGSO: disableGSO, DisablePathMTUDiscovery: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.CloseWithError(0, "") })
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.CloseWithError(0, "") })
	// Exchange application traffic in both directions before blocking the sender.
	if err := server.SendDatagram([]byte("ready")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReceiveDatagram(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.SendDatagram([]byte("ready")); err != nil {
		t.Fatal(err)
	}
	if _, err := server.ReceiveDatagram(ctx); err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestDatagramBypassesBlockedSender(t *testing.T) {
	for _, disableGSO := range []bool{true, false} {
		for _, pacing := range []bool{false, true} {
			name := "cwnd"
			if pacing {
				name = "pacing"
			}
			if disableGSO {
				name += "/no-gso"
			} else {
				name += "/gso"
			}
			t.Run(name, func(t *testing.T) {
				client, server := bypassTestPair(t, disableGSO)
				cc := &gatedCongestion{pacing: pacing, acked: make(chan struct{}, 1), blockedObserved: make(chan struct{}, 1)}
				cc.allow.Store(true)
				client.SetCongestionControl(cc)
				settleCtx, settleCancel := context.WithTimeout(context.Background(), time.Second)
				defer settleCancel()
				if err := client.SendDatagram([]byte("settle")); err != nil {
					t.Fatal(err)
				}
				if _, err := server.ReceiveDatagram(settleCtx); err != nil {
					t.Fatal(err)
				}
				select {
				case <-cc.acked:
				case <-settleCtx.Done():
					t.Fatal("sender failed to settle")
				}
				cc.allow.Store(false)
				client.scheduleSending()
				// Wait for the send loop to observe the gate before enqueueing data;
				// replacing a controller doesn't cancel a packet already being packed.
				select {
				case <-cc.blockedObserved:
				case <-settleCtx.Done():
					t.Fatal("sender did not observe gate")
				}
				cc.sent.Store(0)
				normal := []byte("controlled DATAGRAM")
				if err := client.SendDatagram(normal); err != nil {
					t.Fatal(err)
				}
				stream, err := client.OpenUniStream()
				if err != nil {
					t.Fatal(err)
				}
				written := make(chan error, 1)
				go func() {
					_, err := stream.Write([]byte("controlled STREAM"))
					if err == nil {
						err = stream.Close()
					}
					written <- err
				}()
				// Include full-sized packets so Linux can exercise GSO batching.
				payload := bytes.Repeat([]byte{0x45}, int(client.maxPayloadSizeEstimate.Load()))
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				for range 40 {
					if err := client.SendDatagramWithoutCongestionControl(payload); err != nil {
						t.Fatal(err)
					}
					got, err := server.ReceiveDatagram(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, payload) {
						t.Fatal("controlled datagram escaped congestion control")
					}
				}
				// Keep this negative check below the normal PTO: PTO probes are
				// allowed to carry reliable data even when cwnd is exhausted.
				readCtx, readCancel := context.WithTimeout(ctx, 2*time.Millisecond)
				_, err = server.AcceptUniStream(readCtx)
				readCancel()
				if err == nil {
					t.Fatal("STREAM escaped congestion control")
				}
				if cc.sent.Load() != 0 {
					t.Fatalf("bypass packets reached controller: %d", cc.sent.Load())
				}
				cc.allow.Store(true)
				client.scheduleSending()
				got, err := server.ReceiveDatagram(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, normal) {
					t.Fatal("normal datagram lost")
				}
				incoming, err := server.AcceptUniStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				got, err = io.ReadAll(incoming)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != "controlled STREAM" {
					t.Fatal("normal stream lost")
				}
				if err := <-written; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestUncongestedQueueClose(t *testing.T) {
	client, server := bypassTestPair(t, true)
	server.CloseWithError(0, "")
	select {
	case <-client.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("peer close not observed")
	}
	if err := client.SendDatagramWithoutCongestionControl(bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("enqueue after close succeeded")
	}
}

func TestNativeCongestionConfig(t *testing.T) {
	for _, algorithm := range []CongestionControlAlgorithm{CongestionControlNewReno, CongestionControlCubic} {
		c := &Config{CongestionControl: algorithm}
		if err := validateConfig(c); err != nil {
			t.Fatal(err)
		}
		if populateConfig(c.Clone()).CongestionControl != algorithm {
			t.Fatal("algorithm lost during config copy")
		}
	}
	if err := validateConfig(&Config{CongestionControl: 255}); err == nil {
		t.Fatal("invalid algorithm accepted")
	}
}
