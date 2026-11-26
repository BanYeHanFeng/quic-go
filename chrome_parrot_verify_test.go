package quic_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
)

const (
	chromeTrustAnchorsExt uint16 = 0xca34
	badCertificateCode           = quic.TransportErrorCode(0x100 + 42)
)

type clientHelloObservation struct {
	serverName string
	extensions []uint16
}

func newVerifyTestCert(t *testing.T, dnsNames []string, ips []net.IP) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	return tls.Certificate{
		Certificate: [][]byte{leafDER, rootDER},
		PrivateKey:  leafKey,
		Leaf:        leafCert,
	}, pool
}

func startChromeParrotTestServer(t *testing.T, cert tls.Certificate) (net.Addr, <-chan clientHelloObservation, <-chan context.Context) {
	t.Helper()

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	helloCh := make(chan clientHelloObservation, 4)
	connCtxCh := make(chan context.Context, 4)

	tr := &quic.Transport{
		Conn: udpConn,
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			select {
			case connCtxCh <- ctx:
			default:
			}
			return ctx, nil
		},
	}
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case helloCh <- clientHelloObservation{
				serverName: chi.ServerName,
				extensions: slices.Clone(chi.Extensions),
			}:
			default:
			}
			return nil, nil
		},
	}
	ln, err := tr.Listen(serverTLS, &quic.Config{HandshakeIdleTimeout: 5 * time.Second})
	if err != nil {
		tr.Close()
		udpConn.Close()
		t.Fatal(err)
	}

	acceptCtx, cancelAccept := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := ln.Accept(acceptCtx)
			if err != nil {
				return
			}
			wg.Go(func() {
				<-acceptCtx.Done()
				_ = conn.CloseWithError(0, "")
			})
		}
	})
	t.Cleanup(func() {
		cancelAccept()
		_ = ln.Close()
		_ = tr.Close()
		_ = udpConn.Close()
		wg.Wait()
	})
	return udpConn.LocalAddr(), helloCh, connCtxCh
}

func dialChromeParrot(t *testing.T, addr net.Addr, tlsConf *tls.Config) (*quic.Conn, error) {
	t.Helper()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: udpConn}
	t.Cleanup(func() {
		_ = tr.Close()
		_ = udpConn.Close()
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, addr, tlsConf, &quic.Config{
		ChromeParrot:         true,
		HandshakeIdleTimeout: 5 * time.Second,
	})
	if err == nil {
		t.Cleanup(func() {
			_ = conn.CloseWithError(0, "")
		})
	}
	return conn, err
}

func readClientHello(t *testing.T, ch <-chan clientHelloObservation) clientHelloObservation {
	t.Helper()
	select {
	case hello := <-ch:
		return hello
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ClientHello")
		return clientHelloObservation{}
	}
}

func readServerConnCtx(t *testing.T, ch <-chan context.Context) context.Context {
	t.Helper()
	select {
	case ctx := <-ch:
		return ctx
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server ConnContext")
		return nil
	}
}

func TestChromeParrotVerifyConnection(t *testing.T) {
	cert, roots := newVerifyTestCert(t, []string{"cert.example"}, nil)

	t.Run("trusted DNS verifies and translates state", func(t *testing.T) {
		addr, helloCh, _ := startChromeParrotTestServer(t, cert)

		var callbackState tls.ConnectionState
		var called bool
		conn, err := dialChromeParrot(t, addr, &tls.Config{
			ServerName: "cert.example",
			RootCAs:    roots,
			NextProtos: []string{"h3"},
			VerifyConnection: func(state tls.ConnectionState) error {
				called = true
				callbackState = state
				return nil
			},
		})
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		if !called {
			t.Fatal("VerifyConnection was not called")
		}

		hello := readClientHello(t, helloCh)
		if hello.serverName != "cert.example" {
			t.Fatalf("server observed SNI %q, want %q", hello.serverName, "cert.example")
		}
		if !slices.Contains(hello.extensions, chromeTrustAnchorsExt) {
			t.Fatalf("ChromeParrot trust_anchors extension %#x missing from %v", chromeTrustAnchorsExt, hello.extensions)
		}

		if callbackState.HandshakeComplete {
			t.Fatal("callback HandshakeComplete = true, want false")
		}
		if callbackState.Version != tls.VersionTLS13 {
			t.Fatalf("callback Version = %#x, want TLS 1.3", callbackState.Version)
		}
		if callbackState.ServerName != "cert.example" || callbackState.NegotiatedProtocol != "h3" {
			t.Fatalf("callback ServerName=%q ALPN=%q", callbackState.ServerName, callbackState.NegotiatedProtocol)
		}
		if callbackState.CurveID == 0 {
			t.Fatal("callback CurveID = 0, want non-zero key exchange group")
		}
		if len(callbackState.PeerCertificates) == 0 || !callbackState.PeerCertificates[0].Equal(cert.Leaf) {
			t.Fatal("callback PeerCertificates did not contain expected leaf")
		}
		if len(callbackState.VerifiedChains) == 0 {
			t.Fatal("callback VerifiedChains is empty for trusted certificate")
		}

		finalTLS := conn.ConnectionState().TLS
		if !finalTLS.HandshakeComplete {
			t.Fatal("final ConnectionState HandshakeComplete = false, want true")
		}
		if finalTLS.ServerName != callbackState.ServerName ||
			finalTLS.NegotiatedProtocol != callbackState.NegotiatedProtocol ||
			finalTLS.CipherSuite != callbackState.CipherSuite ||
			finalTLS.CurveID != callbackState.CurveID ||
			len(finalTLS.PeerCertificates) != len(callbackState.PeerCertificates) ||
			!finalTLS.PeerCertificates[0].Equal(callbackState.PeerCertificates[0]) {
			t.Fatalf("final TLS state %+v diverged from callback state %+v", finalTLS, callbackState)
		}
	})

	t.Run("builtin verification failure skips callbacks", func(t *testing.T) {
		addr, helloCh, _ := startChromeParrotTestServer(t, cert)

		var peerCalled, connCalled bool
		_, err := dialChromeParrot(t, addr, &tls.Config{
			ServerName: "wrong.example",
			RootCAs:    roots,
			NextProtos: []string{"h3"},
			VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
				peerCalled = true
				return nil
			},
			VerifyConnection: func(tls.ConnectionState) error {
				connCalled = true
				return nil
			},
		})
		var hostErr x509.HostnameError
		if !errors.As(err, &hostErr) {
			t.Fatalf("expected hostname verification error, got %v", err)
		}
		_ = readClientHello(t, helloCh)
		if peerCalled || connCalled {
			t.Fatalf("callbacks should not run after builtin verification fails: peer=%v conn=%v", peerCalled, connCalled)
		}
	})

	t.Run("VerifyPeerCertificate runs before VerifyConnection", func(t *testing.T) {
		addr, _, _ := startChromeParrotTestServer(t, cert)

		var order []string
		var peerLeaf, connLeaf *x509.Certificate
		_, err := dialChromeParrot(t, addr, &tls.Config{
			ServerName: "cert.example",
			RootCAs:    roots,
			NextProtos: []string{"h3"},
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				order = append(order, "peer")
				parsed, parseErr := x509.ParseCertificate(rawCerts[0])
				if parseErr != nil {
					return parseErr
				}
				peerLeaf = parsed
				return nil
			},
			VerifyConnection: func(state tls.ConnectionState) error {
				order = append(order, "conn")
				connLeaf = state.PeerCertificates[0]
				return nil
			},
		})
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		if !slices.Equal(order, []string{"peer", "conn"}) {
			t.Fatalf("callback order = %v, want [peer conn]", order)
		}
		if peerLeaf == nil || connLeaf == nil || !peerLeaf.Equal(connLeaf) {
			t.Fatal("peer and connection callbacks observed different leaf certificates")
		}
	})

	t.Run("VerifyPeerCertificate failure stops VerifyConnection", func(t *testing.T) {
		addr, _, _ := startChromeParrotTestServer(t, cert)

		peerErr := errors.New("peer callback rejected")
		var connCalled bool
		_, err := dialChromeParrot(t, addr, &tls.Config{
			ServerName: "cert.example",
			RootCAs:    roots,
			NextProtos: []string{"h3"},
			VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
				return peerErr
			},
			VerifyConnection: func(tls.ConnectionState) error {
				connCalled = true
				return nil
			},
		})
		if !errors.Is(err, peerErr) {
			t.Fatalf("dial error = %v, want sentinel %v", err, peerErr)
		}
		if connCalled {
			t.Fatal("VerifyConnection ran after VerifyPeerCertificate failed")
		}
	})

	t.Run("VerifyConnection rejection preserves sentinel and sends bad_certificate alert", func(t *testing.T) {
		addr, _, connCtxCh := startChromeParrotTestServer(t, cert)

		verifyErr := errors.New("custom connection verification failed")
		_, err := dialChromeParrot(t, addr, &tls.Config{
			ServerName: "cert.example",
			RootCAs:    roots,
			NextProtos: []string{"h3"},
			VerifyConnection: func(tls.ConnectionState) error {
				return verifyErr
			},
		})
		if !errors.Is(err, verifyErr) {
			t.Fatalf("dial error = %v, want sentinel %v", err, verifyErr)
		}
		var trErr *quic.TransportError
		if !errors.As(err, &trErr) || trErr.ErrorCode != badCertificateCode {
			t.Fatalf("client TransportError = %v (code %#x), want %#x", trErr, func() quic.TransportErrorCode {
				if trErr == nil {
					return 0
				}
				return trErr.ErrorCode
			}(), badCertificateCode)
		}

		select {
		case srvConnCtx := <-connCtxCh:
			select {
			case <-srvConnCtx.Done():
				cause := context.Cause(srvConnCtx)
				var srvTrErr *quic.TransportError
				if !errors.As(cause, &srvTrErr) || !srvTrErr.Remote || srvTrErr.ErrorCode != badCertificateCode {
					t.Fatalf("server close cause = %v (remote=%v code=%#x), want remote %#x", cause,
						srvTrErr != nil && srvTrErr.Remote,
						func() quic.TransportErrorCode {
							if srvTrErr == nil {
								return 0
							}
							return srvTrErr.ErrorCode
						}(), badCertificateCode)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for server connection context cancellation")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for server ConnContext")
		}
	})

	t.Run("empty SNI with InsecureSkipVerify accepts and rejects via VerifyConnection", func(t *testing.T) {
		addr, helloCh, connCtxCh := startChromeParrotTestServer(t, cert)

		var gotState tls.ConnectionState
		_, err := dialChromeParrot(t, addr, &tls.Config{
			ServerName:         "",
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
			VerifyConnection: func(state tls.ConnectionState) error {
				gotState = state
				return nil
			},
		})
		if err != nil {
			t.Fatalf("empty SNI accept failed: %v", err)
		}
		hello := readClientHello(t, helloCh)
		_ = readServerConnCtx(t, connCtxCh)
		if hello.serverName != "" {
			t.Fatalf("server observed SNI %q, want empty", hello.serverName)
		}
		if slices.Contains(hello.extensions, 0) {
			t.Fatalf("SNI extension (0) should be omitted for empty ServerName: %v", hello.extensions)
		}
		if !slices.Contains(hello.extensions, chromeTrustAnchorsExt) {
			t.Fatalf("ChromeParrot trust_anchors extension missing from %v", hello.extensions)
		}
		if gotState.ServerName != "" || gotState.VerifiedChains != nil || len(gotState.PeerCertificates) == 0 || !gotState.PeerCertificates[0].Equal(cert.Leaf) {
			t.Fatalf("unexpected empty-SNI callback state: %+v", gotState)
		}

		rejectErr := errors.New("empty sni verify failed")
		_, err = dialChromeParrot(t, addr, &tls.Config{
			ServerName:         "",
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
			VerifyConnection: func(tls.ConnectionState) error {
				return rejectErr
			},
		})
		if !errors.Is(err, rejectErr) {
			t.Fatalf("empty SNI reject error = %v, want %v", err, rejectErr)
		}
		var trErr *quic.TransportError
		if !errors.As(err, &trErr) || trErr.ErrorCode != badCertificateCode {
			t.Fatalf("empty SNI reject TransportError = %v, want code %#x", trErr, badCertificateCode)
		}
		hello = readClientHello(t, helloCh)
		if hello.serverName != "" || slices.Contains(hello.extensions, 0) {
			t.Fatalf("empty SNI reject sent unexpected SNI %q extensions %v", hello.serverName, hello.extensions)
		}
		srvConnCtx := readServerConnCtx(t, connCtxCh)
		select {
		case <-srvConnCtx.Done():
			var srvTrErr *quic.TransportError
			if cause := context.Cause(srvConnCtx); !errors.As(cause, &srvTrErr) || !srvTrErr.Remote || srvTrErr.ErrorCode != badCertificateCode {
				t.Fatalf("empty SNI server close cause = %v, want remote %#x", cause, badCertificateCode)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for empty SNI server rejection close")
		}
	})
}
