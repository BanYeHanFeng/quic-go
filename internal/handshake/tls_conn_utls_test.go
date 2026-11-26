package handshake

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"testing"

	utls "github.com/metacubex/utls"
)

func TestUTLSConnectionStateToStd(t *testing.T) {
	leaf := &x509.Certificate{Raw: []byte("leaf")}
	issuer := &x509.Certificate{Raw: []byte("issuer")}
	in := utls.ConnectionState{
		Version:                     utls.VersionTLS13,
		HandshakeComplete:           true,
		DidResume:                   true,
		CipherSuite:                 utls.TLS_AES_128_GCM_SHA256,
		CurveID:                     utls.X25519MLKEM768,
		NegotiatedProtocol:          "h3",
		NegotiatedProtocolIsMutual:  false,
		ServerName:                  "cert.example",
		PeerCertificates:            []*x509.Certificate{leaf, issuer},
		VerifiedChains:              [][]*x509.Certificate{{leaf, issuer}},
		SignedCertificateTimestamps: [][]byte{{1, 2}, {3, 4}},
		OCSPResponse:                []byte{5, 6, 7},
		TLSUnique:                   []byte{8, 9},
		ECHAccepted:                 true,
		HelloRetryRequest:           true,
	}

	got := connectionStateToStd(in)
	if got.Version != tls.VersionTLS13 {
		t.Fatalf("Version = %#x, want %#x", got.Version, tls.VersionTLS13)
	}
	if !got.HandshakeComplete || !got.DidResume {
		t.Fatalf("HandshakeComplete=%v DidResume=%v, want true/true", got.HandshakeComplete, got.DidResume)
	}
	if got.CipherSuite != tls.TLS_AES_128_GCM_SHA256 {
		t.Fatalf("CipherSuite = %#x, want %#x", got.CipherSuite, tls.TLS_AES_128_GCM_SHA256)
	}
	if got.CurveID != tls.CurveID(utls.X25519MLKEM768) {
		t.Fatalf("CurveID = %#x, want %#x", got.CurveID, utls.X25519MLKEM768)
	}
	if got.NegotiatedProtocol != "h3" {
		t.Fatalf("NegotiatedProtocol = %q, want %q", got.NegotiatedProtocol, "h3")
	}
	if got.NegotiatedProtocolIsMutual {
		t.Fatal("NegotiatedProtocolIsMutual = true, want false")
	}
	if got.ServerName != "cert.example" {
		t.Fatalf("ServerName = %q, want %q", got.ServerName, "cert.example")
	}
	if !slices.Equal(got.PeerCertificates, in.PeerCertificates) {
		t.Fatal("PeerCertificates mismatch")
	}
	if len(got.VerifiedChains) != 1 || !slices.Equal(got.VerifiedChains[0], in.VerifiedChains[0]) {
		t.Fatal("VerifiedChains mismatch")
	}
	if len(got.SignedCertificateTimestamps) != 2 ||
		!bytes.Equal(got.SignedCertificateTimestamps[0], []byte{1, 2}) ||
		!bytes.Equal(got.SignedCertificateTimestamps[1], []byte{3, 4}) {
		t.Fatal("SignedCertificateTimestamps mismatch")
	}
	if !bytes.Equal(got.OCSPResponse, in.OCSPResponse) {
		t.Fatal("OCSPResponse mismatch")
	}
	if !bytes.Equal(got.TLSUnique, in.TLSUnique) {
		t.Fatal("TLSUnique mismatch")
	}
	if !got.ECHAccepted {
		t.Fatal("ECHAccepted = false, want true")
	}
	if !got.HelloRetryRequest {
		t.Fatal("HelloRetryRequest = false, want true")
	}

	nilChains := connectionStateToStd(utls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
	})
	if nilChains.VerifiedChains != nil {
		t.Fatalf("VerifiedChains = %v, want nil", nilChains.VerifiedChains)
	}
}

func TestUTLSConfigFromStdVerifyConnection(t *testing.T) {
	uc, err := utlsConfigFromStd(&tls.Config{ServerName: "cert.example"})
	if err != nil {
		t.Fatalf("utlsConfigFromStd returned error: %v", err)
	}
	if uc.VerifyConnection != nil {
		t.Fatal("expected nil VerifyConnection when source callback is nil")
	}

	sentinel := errors.New("verify rejected")
	var gotState tls.ConnectionState
	uc, err = utlsConfigFromStd(&tls.Config{
		VerifyConnection: func(state tls.ConnectionState) error {
			gotState = state
			return sentinel
		},
	})
	if err != nil {
		t.Fatalf("utlsConfigFromStd with VerifyConnection returned error: %v", err)
	}
	if uc.VerifyConnection == nil {
		t.Fatal("expected non-nil VerifyConnection")
	}
	leaf := &x509.Certificate{Raw: []byte("leaf")}
	err = uc.VerifyConnection(utls.ConnectionState{
		Version:          utls.VersionTLS13,
		ServerName:       "cert.example",
		PeerCertificates: []*x509.Certificate{leaf},
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("VerifyConnection error = %v, want %v", err, sentinel)
	}
	if gotState.ServerName != "cert.example" || len(gotState.PeerCertificates) != 1 || gotState.PeerCertificates[0] != leaf {
		t.Fatalf("translated state mismatch: %+v", gotState)
	}
}

func TestWrapUTLSError(t *testing.T) {
	if err := wrapUTLSError(nil); err != nil {
		t.Fatalf("wrapUTLSError(nil) = %v, want nil", err)
	}
	plain := errors.New("plain error")
	if err := wrapUTLSError(plain); err != plain {
		t.Fatalf("wrapUTLSError(plain) = %v, want %v", err, plain)
	}

	sentinel := errors.New("verify failed")
	orig := fmt.Errorf("%w%.0w", sentinel, utls.AlertError(42))
	wrapped := wrapUTLSError(orig)
	if !errors.Is(wrapped, sentinel) {
		t.Fatalf("wrapped error lost sentinel: %v", wrapped)
	}
	var stdAlert tls.AlertError
	if !errors.As(wrapped, &stdAlert) || stdAlert != tls.AlertError(42) {
		t.Fatalf("wrapped error alert = %v, want %v", stdAlert, tls.AlertError(42))
	}
	if wrapped.Error() != orig.Error() {
		t.Fatalf("wrapped error text = %q, want %q", wrapped.Error(), orig.Error())
	}
}
