package quic

import (
	"fmt"
	"testing"

	"github.com/sagernet/quic-go/internal/ackhandler"
	"github.com/sagernet/quic-go/internal/handshake"
	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/udp"
	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/wire"
)

type bypassSealer struct{}

func (bypassSealer) Seal(dst, src []byte, _ protocol.PacketNumber, _ []byte) []byte {
	return append(append(dst, src...), make([]byte, 16)...)
}
func (bypassSealer) EncryptHeader([]byte, *byte, []byte) {}
func (bypassSealer) Overhead() int                       { return 16 }
func (bypassSealer) KeyPhase() protocol.KeyPhaseBit      { return 0 }

type bypassCrypto struct{ sealingManager }

func (bypassCrypto) Get1RTTSealer() (handshake.ShortHeaderSealer, error) { return bypassSealer{}, nil }

type bypassCapture struct {
	sender
	wouldBlockAfter int
	sizes           []int
	segments        []uint16
	ecn             []protocol.ECN
}

func (s *bypassCapture) WouldBlock() bool {
	return s.wouldBlockAfter > 0 && len(s.sizes) >= s.wouldBlockAfter
}

func (s *bypassCapture) Send(buf *udp.PacketBuffer, segment uint16, ecn protocol.ECN) {
	s.sizes = append(s.sizes, len(buf.Data))
	s.segments = append(s.segments, segment)
	s.ecn = append(s.ecn, ecn)
	buf.Release()
}

type checkingBypassPacker struct {
	*packetPacker
	t *testing.T
}

func (p *checkingBypassPacker) AppendUncongestedDatagramPacket(buf *udp.PacketBuffer, q *datagramQueue, max protocol.ByteCount, v protocol.Version) (shortHeaderPacket, error) {
	packet, err := p.packetPacker.AppendUncongestedDatagramPacket(buf, q, max, v)
	if err == nil {
		if !packet.BypassCongestionControl || packet.Ack != nil || len(packet.StreamFrames) != 0 || len(packet.Frames) != 1 {
			p.t.Fatal("bypass packet mixed with controlled frames")
		}
		if _, ok := packet.Frames[0].Frame.(*wire.DatagramFrame); !ok {
			p.t.Fatal("non-DATAGRAM frame exempted")
		}
	}
	return packet, err
}

func TestDatagramBypassPackingAndGSO(t *testing.T) {
	for _, gso := range []bool{false, true} {
		for _, enableECN := range []bool{false, true} {
			t.Run(fmt.Sprintf("gso=%v/ecn=%v", gso, enableECN), func(t *testing.T) {
				now := monotime.Now()
				h := ackhandler.NewSentPacketHandler(0, 1200, &utils.RTTStats{}, &utils.ConnectionStats{}, true, enableECN, nil, protocol.PerspectiveServer, false, nil, utils.DefaultLogger)
				h.DropPackets(protocol.EncryptionInitial, now)
				h.DropPackets(protocol.EncryptionHandshake, now)
				queue := newDatagramQueue(func() {}, utils.DefaultLogger, nil)
				// A pending oversized datagram is discarded after a PMTU decrease. Valid
				// full-sized and short datagrams following it must still make progress.
				maxPayload := protocol.ByteCount(1200) - wire.ShortHeaderLen(protocol.ZeroLengthConnectionID, protocol.PacketNumberLen2) - 16
				frame := &wire.DatagramFrame{DataLenPresent: true}
				fullSize := frame.MaxDataLen(maxPayload, protocol.Version1)
				for _, size := range []int{2000, int(fullSize), int(fullSize), 100} {
					if err := queue.Add(&wire.DatagramFrame{DataLenPresent: true, Data: make([]byte, size)}); err != nil {
						t.Fatal(err)
					}
				}
				packer := &checkingBypassPacker{t: t, packetPacker: &packetPacker{
					pnManager:            h,
					cryptoSetup:          bypassCrypto{},
					getDestConnID:        func() protocol.ConnectionID { return protocol.ZeroLengthConnectionID },
					maxDatagramFrameSize: 1200,
					// Normal ACK/framer/retransmission sources are nil: touching them is a bug.
				}}
				captured := &bypassCapture{}
				conn := &Conn{
					config:                   &Config{InitialPacketSize: 1200},
					handshakeConfirmed:       true,
					conn:                     newSendConn(&gsoTestRawConn{caps: udp.Capabilities{GSO: gso, ECN: enableECN}}, nil, udp.PacketInfo{}, utils.DefaultLogger, false),
					sentPacketHandler:        h,
					uncongestedDatagramQueue: queue,
					packer:                   packer,
					sendQueue:                captured,
					logger:                   utils.DefaultLogger,
					connIDManager:            &connIDManager{},
					version:                  protocol.Version1,
					sendingScheduled:         make(chan struct{}, 1),
				}
				if err := conn.sendUncongestedDatagrams(now); err != nil {
					t.Fatal(err)
				}
				if queue.Peek() != nil {
					t.Fatal("queue failed to drain")
				}
				expectedWrites := 3
				if gso {
					expectedWrites = 1
				}
				if len(captured.sizes) != expectedWrites {
					t.Fatalf("gso=%v writes=%v", gso, captured.sizes)
				}
				expectedECN := protocol.ECNUnsupported
				if enableECN {
					expectedECN = protocol.ECNNon
				}
				for i, ecn := range captured.ecn {
					if ecn != expectedECN {
						t.Fatalf("got ECN %s, want %s", ecn, expectedECN)
					}
					expectedSegment := uint16(0)
					if gso {
						expectedSegment = 1200
					}
					if captured.segments[i] != expectedSegment {
						t.Fatalf("got GSO segment %d, want %d", captured.segments[i], expectedSegment)
					}
				}
			})
		}
	}
}

func TestDatagramBypassSendQueueBackpressureAndPeerLimit(t *testing.T) {
	now := monotime.Now()
	h := ackhandler.NewSentPacketHandler(0, 1200, &utils.RTTStats{}, &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveServer, false, nil, utils.DefaultLogger)
	h.DropPackets(protocol.EncryptionInitial, now)
	h.DropPackets(protocol.EncryptionHandshake, now)
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, nil)
	// First frame exceeds peer maxDatagramFrameSize (200) and must be dropped;
	// the following two frames fit and trigger sendQueue backpressure after the first write.
	for _, size := range []int{300, 100, 100} {
		if err := queue.Add(&wire.DatagramFrame{DataLenPresent: true, Data: make([]byte, size)}); err != nil {
			t.Fatal(err)
		}
	}
	packer := &checkingBypassPacker{t: t, packetPacker: &packetPacker{
		pnManager:            h,
		cryptoSetup:          bypassCrypto{},
		getDestConnID:        func() protocol.ConnectionID { return protocol.ZeroLengthConnectionID },
		maxDatagramFrameSize: 200,
	}}
	captured := &bypassCapture{wouldBlockAfter: 1}
	conn := &Conn{
		config:                   &Config{InitialPacketSize: 1200},
		handshakeConfirmed:       true,
		conn:                     newSendConn(&gsoTestRawConn{}, nil, udp.PacketInfo{}, utils.DefaultLogger, false),
		sentPacketHandler:        h,
		uncongestedDatagramQueue: queue,
		packer:                   packer,
		sendQueue:                captured,
		logger:                   utils.DefaultLogger,
		connIDManager:            &connIDManager{},
		version:                  protocol.Version1,
		sendingScheduled:         make(chan struct{}, 1),
	}
	if err := conn.sendUncongestedDatagrams(now); err != nil {
		t.Fatal(err)
	}
	if len(captured.sizes) != 1 {
		t.Fatalf("expected 1 write before backpressure, got %d", len(captured.sizes))
	}
	if queue.Peek() == nil {
		t.Fatal("expected remaining datagram after backpressure")
	}
	if conn.pacingDeadline != deadlineSendImmediately {
		t.Fatalf("backpressure did not schedule immediate retry: pacingDeadline=%v", conn.pacingDeadline)
	}
}

func TestDatagramBypassFixedMTUBoundaryOmitsLength(t *testing.T) {
	now := monotime.Now()
	dcid := protocol.ParseConnectionID(make([]byte, 16))
	h := ackhandler.NewSentPacketHandler(0, 1200, &utils.RTTStats{}, &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveClient, false, nil, utils.DefaultLogger)
	h.DropPackets(protocol.EncryptionInitial, now)
	h.DropPackets(protocol.EncryptionHandshake, now)
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, nil)
	packer := &checkingBypassPacker{t: t, packetPacker: &packetPacker{
		pnManager:            h,
		cryptoSetup:          bypassCrypto{},
		getDestConnID:        func() protocol.ConnectionID { return dcid },
		maxDatagramFrameSize: 1200,
	}}
	captured := &bypassCapture{}
	conn := &Conn{
		config:                   &Config{InitialPacketSize: 1200},
		handshakeConfirmed:       true,
		conn:                     newSendConn(&gsoTestRawConn{}, nil, udp.PacketInfo{}, utils.DefaultLogger, false),
		sentPacketHandler:        h,
		uncongestedDatagramQueue: queue,
		packer:                   packer,
		sendQueue:                captured,
		logger:                   utils.DefaultLogger,
		connIDManager:            &connIDManager{},
		version:                  protocol.Version1,
		sendingScheduled:         make(chan struct{}, 1),
	}
	conn.peerParams.Store(&wire.TransportParameters{MaxDatagramFrameSize: 1200})
	conn.maxPayloadSizeEstimate.Store(uint32(estimateMaxPayloadSize(1200)))

	// With MTU 1200, 16-byte DCID, 2-byte PN and 16-byte AEAD tag:
	// short header (19) + tag (16) = 35 -> maxPayload = 1165.
	// Public SendDatagramWithoutCongestionControl accepts 1163 bytes (1200 - 37),
	// which is 1166 bytes with length field (1201 wire bytes > 1200) and 1164 bytes
	// without length field (1199 wire bytes <= 1200).
	if err := conn.SendDatagramWithoutCongestionControl(make([]byte, 1163)); err != nil {
		t.Fatalf("public enqueue failed at fixed MTU boundary: %v", err)
	}
	if err := conn.sendUncongestedDatagrams(now); err != nil {
		t.Fatal(err)
	}
	if len(captured.sizes) != 1 {
		t.Fatalf("expected boundary datagram to be sent without length field, got %d writes", len(captured.sizes))
	}
	if captured.sizes[0] != 1199 {
		t.Fatalf("wire size=%d, want 1199", captured.sizes[0])
	}
}
