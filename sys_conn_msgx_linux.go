//go:build linux && !386 && !arm && !mips && !mipsle && !s390x

package quic

import (
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// mmsghdr mirrors struct mmsghdr from linux/socket.h.
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
}

// mmsgReader reads a batch of datagrams with a single recvmmsg call.
//
// The alternative, x/net's ReadBatch, is a recvmmsg as well, but it parses the
// source address of every single datagram into a fresh *net.UDPAddr with a fresh
// net.IP, whether or not anyone is going to look at it. On a connected socket the
// source address is fixed and already known, so it is not requested at all here;
// on an unconnected socket the address is still parsed, but into a single
// allocation instead of two.
type mmsgReader struct {
	rawConn   syscall.RawConn
	connected bool

	hdrs  []mmsghdr
	iovs  []unix.Iovec
	names []unix.RawSockaddrInet6
}

func newBatchReader(rawConn syscall.RawConn, connected bool) batchConn {
	return &mmsgReader{
		rawConn:   rawConn,
		connected: connected,
		hdrs:      make([]mmsghdr, batchSize),
		iovs:      make([]unix.Iovec, batchSize),
		names:     make([]unix.RawSockaddrInet6, batchSize),
	}
}

func (r *mmsgReader) ReadBatch(ms []ipv4.Message, _ int) (int, error) {
	count := min(len(ms), len(r.hdrs))
	if count == 0 {
		return 0, nil
	}
	for i := range count {
		buffer := ms[i].Buffers[0]
		r.iovs[i] = unix.Iovec{Base: &buffer[0]}
		r.iovs[i].SetLen(len(buffer))
		r.hdrs[i] = mmsghdr{}
		r.hdrs[i].Hdr.Iov = &r.iovs[i]
		r.hdrs[i].Hdr.Iovlen = 1
		if !r.connected {
			r.hdrs[i].Hdr.Name = (*byte)(unsafe.Pointer(&r.names[i]))
			r.hdrs[i].Hdr.Namelen = unix.SizeofSockaddrInet6
		}
		if oob := ms[i].OOB; len(oob) > 0 {
			r.hdrs[i].Hdr.Control = &oob[0]
			r.hdrs[i].Hdr.Controllen = uint64(len(oob))
		}
	}
	var (
		n     uintptr
		errno syscall.Errno
	)
	// The socket is in non-blocking mode, so recvmmsg reports a missing datagram
	// with EAGAIN and the runtime waits for readability before calling us again.
	err := r.rawConn.Read(func(fd uintptr) bool {
		for {
			n, _, errno = syscall.Syscall6(unix.SYS_RECVMMSG, fd,
				uintptr(unsafe.Pointer(&r.hdrs[0])), uintptr(count), 0, 0, 0)
			if errno == unix.EINTR {
				continue
			}
			return errno != unix.EAGAIN
		}
	})
	if err != nil {
		return 0, err
	}
	if errno != 0 {
		return 0, os.NewSyscallError("recvmmsg", errno)
	}
	if n == 0 {
		return 0, io.EOF
	}
	numMsgs := int(n)
	for i := range numMsgs {
		ms[i].N = int(r.hdrs[i].Len)
		ms[i].NN = int(r.hdrs[i].Hdr.Controllen)
		ms[i].Flags = int(r.hdrs[i].Hdr.Flags)
		if r.connected {
			ms[i].Addr = nil
			continue
		}
		ms[i].Addr = udpAddrFromRawSockaddr(&r.names[i])
	}
	return numMsgs, nil
}

// udpAddr is a net.UDPAddr with the IP storage inlined, so that parsing a source
// address costs one allocation instead of one for the address and one for the IP.
type udpAddr struct {
	addr net.UDPAddr
	ip   [16]byte
}

func udpAddrFromRawSockaddr(name *unix.RawSockaddrInet6) *net.UDPAddr {
	parsed := new(udpAddr)
	if name.Family == unix.AF_INET {
		name4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(name))
		copy(parsed.ip[:4], name4.Addr[:])
		parsed.addr.IP = parsed.ip[:4]
		parsed.addr.Port = portFromRawSockaddr(&name4.Port)
		return &parsed.addr
	}
	copy(parsed.ip[:], name.Addr[:])
	parsed.addr.IP = parsed.ip[:16]
	parsed.addr.Port = portFromRawSockaddr(&name.Port)
	if name.Scope_id != 0 {
		parsed.addr.Zone = interfaceZone(name.Scope_id)
	}
	return &parsed.addr
}

func portFromRawSockaddr(port *uint16) int {
	portBytes := (*[2]byte)(unsafe.Pointer(port))
	return int(portBytes[0])<<8 | int(portBytes[1])
}

var interfaceZones sync.Map // uint32 -> string

func interfaceZone(index uint32) string {
	if index == 0 {
		return ""
	}
	cached, loaded := interfaceZones.Load(index)
	if loaded {
		return cached.(string)
	}
	zone := strconv.FormatUint(uint64(index), 10)
	iface, err := net.InterfaceByIndex(int(index))
	if err == nil {
		zone = iface.Name
	}
	interfaceZones.Store(index, zone)
	return zone
}

func newSegmentWriter(syscall.RawConn) segmentWriter { return nil }
