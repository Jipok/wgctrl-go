//go:build linux
// +build linux

package wglinux

import (
	"strings"
	"testing"
	"time"

	"github.com/Jipok/wgctrl-go/wgtypes"
)

// TestAmneziaKeepaliveEncoding locks in the AmneziaWG 3.x wire format of the
// persistent keepalive attribute. It is not a widened scalar but a packed u16
// range (lo | hi<<16); sending a bare value makes the kernel and the official
// tools read back the pair (0, seconds) instead of the intended interval.
func TestAmneziaKeepaliveEncoding(t *testing.T) {
	ka := 25 * time.Second
	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: wgtypes.Key{}, PersistentKeepaliveInterval: &ka}},
	}

	b, err := configAttrs("wg0", cfg, 1)
	if err != nil {
		t.Fatalf("version 1: %v", err)
	}
	if !strings.Contains(string(b), string([]byte{25, 0})) {
		t.Fatalf("version 1 should encode a plain uint16 25, got %x", b)
	}

	b, err = configAttrs("wg0", cfg, 3)
	if err != nil {
		t.Fatalf("version 3: %v", err)
	}
	// 25 packed as (lo=25, hi=25) is 0x00190019 in little endian.
	if !strings.Contains(string(b), string([]byte{0x19, 0x00, 0x19, 0x00})) {
		t.Fatalf("version 3 should encode the packed range 25|25<<16, got %x", b)
	}
}

// TestAmneziaHeaderProtectionValidation ensures an unusable padding is rejected
// in userspace with a clear message instead of the kernel's bare -EINVAL.
func TestAmneziaHeaderProtectionValidation(t *testing.T) {
	key := [32]byte{}
	s1 := headerProtectionNonceSize - 1

	_, err := configAttrs("wg0", wgtypes.Config{HeaderProtectionKey: &key, S1: &s1}, 3)
	if err == nil || !strings.Contains(err.Error(), "S1 must be at least") {
		t.Fatalf("want a clear S1 validation error, got %v", err)
	}

	// A valid padding must not be rejected.
	ok := headerProtectionNonceSize
	if _, err := configAttrs("wg0", wgtypes.Config{HeaderProtectionKey: &key, S1: &ok}, 3); err != nil {
		t.Fatalf("valid padding rejected: %v", err)
	}
}
