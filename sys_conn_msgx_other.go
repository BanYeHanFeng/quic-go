//go:build freebsd || (linux && (386 || arm || mips || mipsle || s390x))

package quic

import "syscall"

// newBatchReader returns nil on platforms without a batched receive: x/net's
// ReadBatch is used instead.
func newBatchReader(syscall.RawConn, bool) batchConn { return nil }

func newSegmentWriter(syscall.RawConn) segmentWriter { return nil }
