package handshake

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	utls "github.com/metacubex/utls"
	"github.com/sagernet/quic-go/quicvarint"
)

// utlsQUICConn adapts uTLS's UQUICConn to the tlsQUICConn interface, translating
// its QUIC event and connection-state types back into the crypto/tls
// equivalents. uTLS is a fork of crypto/tls, so the translation is mechanical.
type utlsQUICConn struct {
	conn *utls.UQUICConn
	// spec is retained because the transport parameters have to be written into
	// the ClientHello extension rather than handed to uTLS directly; see
	// SetTransportParameters.
	spec *utls.ClientHelloSpec
}

var _ tlsQUICConn = (*utlsQUICConn)(nil)

// newUTLSQUICClient creates a QUIC-TLS client emitting the parroted ClientHello.
//
// Session resumption and 0-RTT are disabled: crypto/tls and uTLS each have their
// own SessionState with unexported internals, so a uTLS session cannot be
// converted into the *tls.SessionState the resumption path expects. The events
// are turned off at the source rather than half-supported.
func newUTLSQUICClient(tlsConf *tls.Config) (*utlsQUICConn, error) {
	uConf, err := utlsConfigFromStd(tlsConf)
	if err != nil {
		return nil, err
	}
	spec := chromeQUICClientHelloSpec(tlsConf.NextProtos)

	conn := utls.UQUICClient(&utls.QUICConfig{TLSConfig: uConf}, utls.HelloCustom)
	if err := conn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("applying Chrome ClientHello spec: %w", err)
	}
	return &utlsQUICConn{conn: conn, spec: spec}, nil
}

// utlsConfigFromStd converts a crypto/tls client config into the uTLS
// equivalent.
//
// uTLS ships no converter, so this copies field by field. Unsupported fields
// are rejected rather than silently omitted so security-sensitive behavior is
// never weakened. VerifyConnection is bridged by translating the uTLS
// ConnectionState into crypto/tls.ConnectionState (excluding unexported
// exporter hooks and uTLS-only fields).
func utlsConfigFromStd(c *tls.Config) (*utls.Config, error) {
	if c == nil {
		return &utls.Config{MinVersion: utls.VersionTLS13}, nil
	}
	if c.EncryptedClientHelloRejectionVerify != nil {
		// Takes a crypto/tls ConnectionState, which uTLS will never produce.
		return nil, errors.New("quic: tls.Config.EncryptedClientHelloRejectionVerify is not supported with ChromeParrot")
	}
	if c.GetConfigForClient != nil || c.GetCertificate != nil {
		return nil, errors.New("quic: server-side tls.Config fields are not supported with ChromeParrot")
	}

	uc := &utls.Config{
		Rand:                  c.Rand,
		Time:                  c.Time,
		RootCAs:               c.RootCAs,
		NextProtos:            c.NextProtos,
		ServerName:            c.ServerName,
		InsecureSkipVerify:    c.InsecureSkipVerify,
		VerifyPeerCertificate: c.VerifyPeerCertificate,
		KeyLogWriter:          c.KeyLogWriter,
		// TLS 1.3 only, which QUIC requires regardless.
		MinVersion: utls.VersionTLS13,
		MaxVersion: utls.VersionTLS13,
		// Resumption is off; see newUTLSQUICClient.
		SessionTicketsDisabled: true,
	}
	for i := range c.Certificates {
		uc.Certificates = append(uc.Certificates, utlsCertificateFromStd(&c.Certificates[i]))
	}

	if c.GetClientCertificate != nil {
		get := c.GetClientCertificate
		uc.GetClientCertificate = func(cri *utls.CertificateRequestInfo) (*utls.Certificate, error) {
			cert, err := get(&tls.CertificateRequestInfo{
				AcceptableCAs:    cri.AcceptableCAs,
				SignatureSchemes: signatureSchemesToStd(cri.SignatureSchemes),
				Version:          cri.Version,
			})
			if err != nil {
				return nil, err
			}
			if cert == nil {
				return &utls.Certificate{}, nil
			}
			uCert := utlsCertificateFromStd(cert)
			return &uCert, nil
		}
	}

	if c.VerifyConnection != nil {
		verify := c.VerifyConnection
		uc.VerifyConnection = func(state utls.ConnectionState) error {
			return verify(connectionStateToStd(state))
		}
	}

	// GREASE ECH is covered by the ClientHello spec; a caller-supplied config list
	// takes precedence.
	if len(c.EncryptedClientHelloConfigList) > 0 {
		uc.EncryptedClientHelloConfigList = c.EncryptedClientHelloConfigList
	}
	return uc, nil
}

func utlsCertificateFromStd(cert *tls.Certificate) utls.Certificate {
	uCert := utls.Certificate{
		Certificate:                 cert.Certificate,
		PrivateKey:                  cert.PrivateKey,
		OCSPStaple:                  cert.OCSPStaple,
		SignedCertificateTimestamps: cert.SignedCertificateTimestamps,
		Leaf:                        cert.Leaf,
	}
	for _, scheme := range cert.SupportedSignatureAlgorithms {
		uCert.SupportedSignatureAlgorithms = append(uCert.SupportedSignatureAlgorithms, utls.SignatureScheme(scheme))
	}
	return uCert
}

func signatureSchemesToStd(in []utls.SignatureScheme) []tls.SignatureScheme {
	out := make([]tls.SignatureScheme, len(in))
	for i, s := range in {
		out[i] = tls.SignatureScheme(s)
	}
	return out
}

// wrapUTLSError attaches an equivalent crypto/tls.AlertError when uTLS wraps a
// utls.AlertError, so handshake.wrapError maps it to a QUIC CRYPTO_ERROR
// instead of INTERNAL_ERROR while preserving the original error chain.
func wrapUTLSError(err error) error {
	if err == nil {
		return nil
	}
	var alertErr utls.AlertError
	if errors.As(err, &alertErr) {
		return fmt.Errorf("%w%.0w", err, tls.AlertError(alertErr))
	}
	return err
}

func (c *utlsQUICConn) Start(ctx context.Context) error { return wrapUTLSError(c.conn.Start(ctx)) }
func (c *utlsQUICConn) Close() error                    { return wrapUTLSError(c.conn.Close()) }

func (c *utlsQUICConn) HandleData(level tls.QUICEncryptionLevel, data []byte) error {
	return wrapUTLSError(c.conn.HandleData(utlsEncryptionLevel(level), data))
}

// SetTransportParameters installs quic-go's marshalled transport parameters into
// the ClientHello.
//
// uTLS's own SetTransportParameters does not reach the ClientHello when a preset
// is in use, so the bytes must be written into the spec's
// quic_transport_parameters extension. uTLS models that extension as (id, value)
// pairs and marshals it itself, so the blob is split back into pairs here.
// Splitting rather than re-deriving preserves our per-connection ordering.
func (c *utlsQUICConn) SetTransportParameters(params []byte) {
	// Still call through so uTLS's internal copy stays consistent.
	c.conn.SetTransportParameters(params)

	tps, err := splitTransportParameters(params)
	if err != nil {
		// Our own marshaller produced these, so this is unreachable short of a bug.
		panic(fmt.Sprintf("handshake BUG: cannot split marshalled transport parameters: %s", err))
	}
	for _, ext := range c.spec.Extensions {
		if qtp, ok := ext.(*utls.QUICTransportParametersExtension); ok {
			qtp.TransportParameters = tps
			return
		}
	}
	panic("handshake BUG: Chrome ClientHello spec has no quic_transport_parameters extension")
}

// splitTransportParameters parses a marshalled transport parameter blob back into
// individual (id, value) pairs, preserving order.
func splitTransportParameters(b []byte) (utls.TransportParameters, error) {
	var tps utls.TransportParameters
	for len(b) > 0 {
		id, n, err := quicvarint.Parse(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		l, n, err := quicvarint.Parse(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		if uint64(len(b)) < l {
			return nil, fmt.Errorf("transport parameter 0x%x truncated: want %d bytes, have %d", id, l, len(b))
		}
		val := make([]byte, l)
		copy(val, b[:l])
		b = b[l:]
		tps = append(tps, &utls.FakeQUICTransportParameter{Id: id, Val: val})
	}
	return tps, nil
}

func (c *utlsQUICConn) NextEvent() tls.QUICEvent {
	ev := c.conn.NextEvent()
	out := tls.QUICEvent{
		Level: stdEncryptionLevel(ev.Level),
		Data:  ev.Data,
		Suite: ev.Suite,
	}
	switch ev.Kind {
	case utls.QUICNoEvent:
		out.Kind = tls.QUICNoEvent
	case utls.QUICSetReadSecret:
		out.Kind = tls.QUICSetReadSecret
	case utls.QUICSetWriteSecret:
		out.Kind = tls.QUICSetWriteSecret
	case utls.QUICWriteData:
		out.Kind = tls.QUICWriteData
	case utls.QUICTransportParameters:
		out.Kind = tls.QUICTransportParameters
	case utls.QUICTransportParametersRequired:
		out.Kind = tls.QUICTransportParametersRequired
	case utls.QUICRejectedEarlyData:
		out.Kind = tls.QUICRejectedEarlyData
	case utls.QUICHandshakeDone:
		out.Kind = tls.QUICHandshakeDone
	default:
		// QUICStoreSession and QUICResumeSession carry a *utls.SessionState that
		// cannot be converted. They only fire when EnableSessionEvents is set,
		// which newUTLSQUICClient never does, so reaching this is a bug.
		panic(fmt.Sprintf("handshake BUG: unexpected uTLS QUIC event kind %d", ev.Kind))
	}
	return out
}

func (c *utlsQUICConn) SendSessionTicket(tls.QUICSessionTicketOptions) error {
	return errors.New("quic: SendSessionTicket is server-only and unsupported with ChromeParrot")
}

func (c *utlsQUICConn) StoreSession(*tls.SessionState) error {
	return errors.New("quic: session resumption is unsupported with ChromeParrot")
}

// connectionStateToStd translates uTLS connection state to crypto/tls.
// ExportKeyingMaterial cannot be used on the returned value because crypto/tls
// stores the exporter callback in an unexported field; uTLS-only fields
// (PeerApplicationSettings, JLS) have no crypto/tls counterpart.
func connectionStateToStd(s utls.ConnectionState) tls.ConnectionState {
	return tls.ConnectionState{
		Version:                     s.Version,
		HandshakeComplete:           s.HandshakeComplete,
		DidResume:                   s.DidResume,
		CipherSuite:                 s.CipherSuite,
		CurveID:                     tls.CurveID(s.CurveID),
		NegotiatedProtocol:          s.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  s.NegotiatedProtocolIsMutual,
		ServerName:                  s.ServerName,
		PeerCertificates:            s.PeerCertificates,
		VerifiedChains:              s.VerifiedChains,
		SignedCertificateTimestamps: s.SignedCertificateTimestamps,
		OCSPResponse:                s.OCSPResponse,
		TLSUnique:                   s.TLSUnique,
		ECHAccepted:                 s.ECHAccepted,
		HelloRetryRequest:           s.HelloRetryRequest,
	}
}

func (c *utlsQUICConn) ConnectionState() tls.ConnectionState {
	return connectionStateToStd(c.conn.ConnectionState())
}

func utlsEncryptionLevel(l tls.QUICEncryptionLevel) utls.QUICEncryptionLevel {
	switch l {
	case tls.QUICEncryptionLevelInitial:
		return utls.QUICEncryptionLevelInitial
	case tls.QUICEncryptionLevelEarly:
		return utls.QUICEncryptionLevelEarly
	case tls.QUICEncryptionLevelHandshake:
		return utls.QUICEncryptionLevelHandshake
	case tls.QUICEncryptionLevelApplication:
		return utls.QUICEncryptionLevelApplication
	default:
		panic(fmt.Sprintf("handshake BUG: unknown encryption level %d", l))
	}
}

func stdEncryptionLevel(l utls.QUICEncryptionLevel) tls.QUICEncryptionLevel {
	switch l {
	case utls.QUICEncryptionLevelInitial:
		return tls.QUICEncryptionLevelInitial
	case utls.QUICEncryptionLevelEarly:
		return tls.QUICEncryptionLevelEarly
	case utls.QUICEncryptionLevelHandshake:
		return tls.QUICEncryptionLevelHandshake
	case utls.QUICEncryptionLevelApplication:
		return tls.QUICEncryptionLevelApplication
	default:
		panic(fmt.Sprintf("handshake BUG: unknown uTLS encryption level %d", l))
	}
}
