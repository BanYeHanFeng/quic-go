package quic

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/quic-go/internal/utils"
)

type gsoTestRawConn struct {
	rawConn
	caps connCapabilities
}

func (c *gsoTestRawConn) capabilities() connCapabilities { return c.caps }
func (*gsoTestRawConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }

func TestDisableGSOPerConnection(t *testing.T) {
	raw := &gsoTestRawConn{caps: connCapabilities{GSO: true, ECN: true, DF: true}}
	allowed := newSendConn(raw, &net.UDPAddr{}, packetInfo{}, utils.DefaultLogger, false)
	disabled := newSendConn(raw, &net.UDPAddr{}, packetInfo{}, utils.DefaultLogger, true)
	if caps := disabled.capabilities(); caps.GSO || !caps.ECN || !caps.DF {
		t.Fatalf("only GSO should be disabled: %+v", caps)
	}
	if !allowed.capabilities().GSO || !raw.capabilities().GSO {
		t.Fatal("disabling one connection affected the shared socket")
	}
	allowed.gotGSOError = true
	if allowed.capabilities().GSO {
		t.Fatal("GSO error fallback was overridden")
	}
	raw.caps.GSO = false
	allowed.gotGSOError = false
	if allowed.capabilities().GSO {
		t.Fatal("configuration enabled GSO on a socket without the capability")
	}
}

func TestDisableGSOConfig(t *testing.T) {
	config := &Config{DisableGSO: true}
	if !populateConfig(config).DisableGSO || !config.Clone().DisableGSO {
		t.Fatal("configuration copy lost DisableGSO")
	}
	if populateConfig(nil).DisableGSO {
		t.Fatal("GSO must remain automatic by default")
	}
}

func TestDisableGSOEnvironment(t *testing.T) {
	t.Setenv("QUIC_GO_DISABLE_GSO", "true")
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	raw, err := wrapConn(socket)
	if err != nil {
		t.Fatal(err)
	}
	conn := newSendConn(raw, &net.UDPAddr{}, packetInfo{}, utils.DefaultLogger, false)
	if conn.capabilities().GSO {
		t.Fatal("connection configuration overrode the environment prohibition")
	}
}

func TestGSOSharedTransport(t *testing.T) {
	t.Setenv("QUIC_GO_DISABLE_GSO", "false")
	serverTLS, clientTLS := gsoTestTLS(t)
	serverSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverSocket.Close()
	serverTransport := &Transport{Conn: serverSocket}
	defer serverTransport.Close()
	listener, err := serverTransport.Listen(serverTLS, &Config{
		DisableGSO:         true,
		GetConfigForClient: func(*ClientInfo) (*Config, error) { return &Config{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	clientSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientSocket.Close()
	clientTransport := &Transport{Conn: clientSocket}
	defer clientTransport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for index, disable := range []bool{true, false, true} {
		client, err := clientTransport.Dial(ctx, listener.Addr(), clientTLS, &Config{DisableGSO: disable})
		if err != nil {
			t.Fatal(err)
		}
		defer client.CloseWithError(0, "")
		server, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer server.CloseWithError(0, "")
		want := clientTransport.conn.capabilities().GSO && !disable
		if got := client.ConnectionState().GSO; got != want {
			t.Fatalf("disable=%v: client GSO=%v, want %v", disable, got, want)
		}
		if server.ConnectionState().GSO {
			t.Fatal("GetConfigForClient overrode listener prohibition")
		}
		if index == 0 {
			// Moving to a fresh, GSO-capable socket must retain the connection policy.
			migratedSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer migratedSocket.Close()
			migratedTransport := &Transport{Conn: migratedSocket}
			defer migratedTransport.Close()
			path, err := client.AddPath(migratedTransport)
			if err != nil {
				t.Fatal(err)
			}
			if err = path.Probe(ctx); err != nil {
				t.Fatal(err)
			}
			if err = path.Switch(); err != nil {
				t.Fatal(err)
			}
		}
		payload := bytes.Repeat([]byte("gso"), 32768)
		stream, err := client.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = stream.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err = stream.Close(); err != nil {
			t.Fatal(err)
		}
		received, err := server.AcceptStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		received.SetReadDeadline(time.Now().Add(5 * time.Second))
		data, err := io.ReadAll(received)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, payload) {
			t.Fatal("payload changed")
		}
		if disable && client.ConnectionState().GSO {
			t.Fatal("path migration lost GSO policy")
		}
	}
}

func gsoTestTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, NextProtos: []string{"gso-test"}},
		&tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"gso-test"}}
}
