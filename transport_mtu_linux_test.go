//go:build linux

package quic

import (
	"bytes"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

type mtuErrorTestConn struct {
	rawConn
	reads int
}

func (c *mtuErrorTestConn) ReadPacket() (receivedPacket, error) {
	c.reads++
	switch c.reads {
	case 1:
		return receivedPacket{}, &net.OpError{
			Op: "read", Net: "udp",
			Err: os.NewSyscallError("recvmsg", unix.EMSGSIZE),
		}
	case 2:
		// An empty datagram is ignored, but proves the read loop resumed.
		return receivedPacket{}, nil
	default:
		return receivedPacket{}, net.ErrClosed
	}
}

func TestTransportContinuesAfterReceiveMTUError(t *testing.T) {
	conn := &mtuErrorTestConn{}
	transport := &Transport{}
	transport.listen(conn)
	if conn.reads != 3 {
		t.Fatalf("transport stopped after %d reads; expected it to survive EMSGSIZE", conn.reads)
	}
	if !errors.Is(transport.closeErr, net.ErrClosed) || errors.Is(transport.closeErr, unix.EMSGSIZE) {
		t.Fatalf("unexpected transport close error: %v", transport.closeErr)
	}
}

type mtuErrorBatchConn struct {
	batchConn
	reads int
}

func (c *mtuErrorBatchConn) ReadBatch(messages []ipv4.Message, flags int) (int, error) {
	c.reads++
	if c.reads == 2 {
		return 0, os.NewSyscallError("recvmsg", unix.EMSGSIZE)
	}
	return c.batchConn.ReadBatch(messages, flags)
}

func TestConnectedUDPReadsFreshBatchAfterMTUError(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := wrapNetConn(client)
	if err != nil {
		t.Fatal(err)
	}
	conn, ok := raw.(*oobConn)
	if !ok {
		t.Fatal("connected UDP socket did not use the optimized receive path")
	}
	reader := &mtuErrorBatchConn{batchConn: conn.batchConn}
	conn.batchConn = reader
	for index, payload := range [][]byte{[]byte("before MTU error"), []byte("after MTU error: fresh packet")} {
		if index == 1 {
			if _, err := conn.ReadPacket(); !errors.Is(err, unix.EMSGSIZE) {
				t.Fatalf("expected injected MTU error, got %v", err)
			}
		}
		if _, err := server.WriteToUDP(payload, client.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
		packet, err := conn.ReadPacket()
		if err != nil {
			t.Fatal(err)
		}
		matches := bytes.Equal(packet.data, payload)
		packet.buffer.Release()
		if !matches {
			t.Fatalf("read stale batch data after %d batch reads", reader.reads)
		}
	}
}
