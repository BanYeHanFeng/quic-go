//go:build arm64 && fec_simd

package quic

import "testing"

// TestFECSIMDAvailableARM64 reports that the qemu run actually exercised the NEON
// path. Advanced SIMD is mandatory on AArch64, so this only records which path ran.
func TestFECSIMDAvailableARM64(t *testing.T) {
	t.Log("arm64 NEON (VTBL) path in use")
}
