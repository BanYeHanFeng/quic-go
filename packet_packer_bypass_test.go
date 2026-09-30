package quic

import (
	"testing"

	"github.com/sagernet/quic-go/internal/ackhandler"
	"github.com/sagernet/quic-go/internal/handshake"
	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
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
	sizes    []int
	segments []uint16
	ecn      []protocol.ECN
}

func (s *bypassCapture) WouldBlock() bool { return false }
func (s *bypassCapture) Send(buf *packetBuffer, segment uint16, ecn protocol.ECN) {
	s.sizes = append(s.sizes, len(buf.Data))
	s.segments = append(s.segments, segment)
	s.ecn = append(s.ecn, ecn)
	buf.Release()
}

type checkingBypassPacker struct {
	*packetPacker
	t *testing.T
}

func (p *checkingBypassPacker) AppendUncongestedDatagramPacket(buf *packetBuffer, q *datagramQueue, max protocol.ByteCount, v protocol.Version) (shortHeaderPacket, error) {
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
		now := monotime.Now()
		h := ackhandler.NewSentPacketHandler(0, 1200, &utils.RTTStats{}, &utils.ConnectionStats{}, true, false, nil, protocol.PerspectiveServer, false, true, nil, utils.DefaultLogger)
		h.DropPackets(protocol.EncryptionInitial, now)
		h.DropPackets(protocol.EncryptionHandshake, now)
		queue := newDatagramQueue(func() {}, utils.DefaultLogger)
		// A pending oversized datagram is discarded after a PMTU decrease. Valid
		// full-sized and short datagrams following it must still make progress.
		maxPayload := protocol.ByteCount(1200) - wire.ShortHeaderLen(protocol.ConnectionID{}, protocol.PacketNumberLen2) - 16
		frame := &wire.DatagramFrame{DataLenPresent: true}
		fullSize := frame.MaxDataLen(maxPayload, protocol.Version1)
		for _, size := range []int{2000, int(fullSize), int(fullSize), 100} {
			if err := queue.Add(&wire.DatagramFrame{DataLenPresent: true, Data: make([]byte, size)}); err != nil {
				t.Fatal(err)
			}
		}
		packer := &checkingBypassPacker{t: t, packetPacker: &packetPacker{
			pnManager: h, cryptoSetup: bypassCrypto{}, getDestConnID: func() protocol.ConnectionID { return protocol.ConnectionID{} },
			// Normal ACK/framer/retransmission sources are nil: touching them is a bug.
		}}
		captured := &bypassCapture{}
		conn := &Conn{
			handshakeConfirmed: true, conn: newSendConn(&gsoTestRawConn{caps: connCapabilities{GSO: gso}}, nil, packetInfo{}, utils.DefaultLogger, false),
			sentPacketHandler: h, uncongestedDatagramQueue: queue, packer: packer, sendQueue: captured, logger: utils.DefaultLogger,
			connIDManager: &connIDManager{}, version: protocol.Version1, sendingScheduled: make(chan struct{}, 1),
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
		for i, ecn := range captured.ecn {
			if ecn != protocol.ECNNon {
				t.Fatal("bypass packet is ECN-capable")
			}
			expectedSegment := uint16(0)
			if gso {
				expectedSegment = 1200
			}
			if captured.segments[i] != expectedSegment {
				t.Fatal("wrong GSO segmentation")
			}
		}
	}
}
