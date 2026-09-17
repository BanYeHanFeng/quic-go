//go:build amd64 && fec_simd

package quic

import "testing"

// TestFECSIMDAvailable reports whether the CI runner actually exercised the
// assembly path. The equivalence tests cover both paths; this log makes the
// fallback visible in the run when a runner lacks SSSE3.
func TestFECSIMDAvailable(t *testing.T) {
	t.Logf("SSSE3 available: %v", fecHasSSSE3)
}
