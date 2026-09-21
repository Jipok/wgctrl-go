//go:build linux
// +build linux

package wglinux

import (
	"strings"
	"testing"
	"time"

	"github.com/Jipok/wgctrl-go/internal/wgtest"
	"github.com/Jipok/wgctrl-go/wgtypes"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// amneziawg-dkms v3.0 (genl family version 3) wire-format changes:
// WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL is a u32 (u16 in mainline WireGuard
// and amneziawg-dkms v1.x), WGDEVICE_A_H1..H4 are u64 values (strings before).
// These tests cover both directions: parsing device dumps from either module
// generation, and encoding config attributes at the right width for the
// family version the kernel reported.

// peerWithKeepalive builds a single-peer device message whose keepalive
// attribute carries the given raw payload.
func peerWithKeepalive(t *testing.T, keepalive []byte) genetlink.Message {
	t.Helper()
	key := wgtest.MustPublicKey()

	return genetlink.Message{
		Data: m([]netlink.Attribute{
			{
				Type: unix.WGDEVICE_A_IFNAME,
				Data: nlenc.Bytes("wg0"),
			},
			{
				Type: unix.WGDEVICE_A_PEERS,
				Data: m(netlink.Attribute{
					Type: 0,
					Data: m([]netlink.Attribute{
						{
							Type: unix.WGPEER_A_PUBLIC_KEY,
							Data: key[:],
						},
						{
							Type: unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
							Data: keepalive,
						},
					}...),
				}),
			},
		}...),
	}
}

func Test_parseDeviceKeepaliveWidths(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    time.Duration
	}{
		{
			name:    "u16 mainline and dkms v1.x",
			payload: nlenc.Uint16Bytes(10),
			want:    10 * time.Second,
		},
		{
			// dkms v3: a packed u16 range hi<<16|lo; the fixed range 25..25.
			name:    "u32 dkms v3 fixed range",
			payload: nlenc.Uint32Bytes(25<<16 | 25),
			want:    25 * time.Second,
		},
		{
			// A real range (set by awg-tools) reports its lower bound.
			name:    "u32 dkms v3 range 20..30",
			payload: nlenc.Uint32Bytes(30<<16 | 20),
			want:    20 * time.Second,
		},
		{
			name:    "u32 dkms v3 disabled",
			payload: nlenc.Uint32Bytes(0),
			want:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := parseDevice([]genetlink.Message{peerWithKeepalive(t, tt.payload)})
			if err != nil {
				t.Fatalf("parseDevice: %v", err)
			}
			if len(d.Peers) != 1 {
				t.Fatalf("got %d peers, want 1", len(d.Peers))
			}
			if got := d.Peers[0].PersistentKeepaliveInterval; got != tt.want {
				t.Fatalf("keepalive = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseDeviceKeepaliveBadLength(t *testing.T) {
	_, err := parseDevice([]genetlink.Message{peerWithKeepalive(t, []byte{1, 2, 3})})
	if err == nil {
		t.Fatal("parseDevice accepted a 3-byte keepalive attribute")
	}
	if !strings.Contains(err.Error(), "keepalive") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// firstPeerAttrs decodes configAttrs output down to the first peer's raw
// attributes, keyed by attribute type.
func firstPeerAttrs(t *testing.T, b []byte) map[uint16][]byte {
	t.Helper()
	attrs := deviceAttrs(t, b)
	peers, ok := attrs[unix.WGDEVICE_A_PEERS]
	if !ok {
		t.Fatal("no WGDEVICE_A_PEERS attribute encoded")
	}

	arr, err := netlink.UnmarshalAttributes(peers)
	if err != nil {
		t.Fatalf("unmarshal peers array: %v", err)
	}
	if len(arr) == 0 {
		t.Fatal("empty peers array")
	}

	peer, err := netlink.UnmarshalAttributes(arr[0].Data)
	if err != nil {
		t.Fatalf("unmarshal first peer: %v", err)
	}
	out := make(map[uint16][]byte, len(peer))
	for _, a := range peer {
		out[a.Type&0x3fff] = a.Data
	}
	return out
}

// deviceAttrs decodes configAttrs output into device-level raw attributes,
// keyed by attribute type with the NLA_F_NESTED/NLA_F_NET_BYTEORDER flag bits
// masked off (UnmarshalAttributes keeps them in Type).
func deviceAttrs(t *testing.T, b []byte) map[uint16][]byte {
	t.Helper()
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		t.Fatalf("unmarshal device attributes: %v", err)
	}
	out := make(map[uint16][]byte, len(attrs))
	for _, a := range attrs {
		out[a.Type&0x3fff] = a.Data
	}
	return out
}

func Test_configAttrsKeepaliveWidthByFamilyVersion(t *testing.T) {
	dur := 10 * time.Second
	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   wgtest.MustPublicKey(),
			PersistentKeepaliveInterval: &dur,
		}},
	}

	tests := []struct {
		name    string
		version uint8
		wantLen int
	}{
		{name: "mainline v1", version: 1, wantLen: 2},
		{name: "amnezia dkms v1.x (genl 2)", version: 2, wantLen: 2},
		{name: "amnezia dkms v3.0 (genl 3)", version: genlVersionAWG3, wantLen: 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := configAttrs("wg0", cfg, tt.version)
			if err != nil {
				t.Fatalf("configAttrs: %v", err)
			}
			ka, ok := firstPeerAttrs(t, b)[unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]
			if !ok {
				t.Fatal("no keepalive attribute encoded")
			}
			if len(ka) != tt.wantLen {
				t.Fatalf("keepalive attribute length = %d, want %d", len(ka), tt.wantLen)
			}
			// v3 takes a packed u16 range (hi<<16|lo): a bare 10 would be the
			// inverted range 10..0, from which the module picks a garbage delay.
			if tt.wantLen == 4 {
				if v := nlenc.Uint32(ka); v != 10<<16|10 {
					t.Fatalf("keepalive = %#x, want the fixed range 10..10 (%#x)", v, 10<<16|10)
				}
			} else if v := nlenc.Uint16(ka); v != 10 {
				t.Fatalf("keepalive = %d, want 10", v)
			}
		})
	}
}

func Test_configAttrsKeepaliveV3Bounds(t *testing.T) {
	encode := func(d time.Duration) ([]byte, error) {
		return configAttrs("wg0", wgtypes.Config{Peers: []wgtypes.PeerConfig{{
			PublicKey:                   wgtest.MustPublicKey(),
			PersistentKeepaliveInterval: &d,
		}}}, genlVersionAWG3)
	}

	// 0 disables keepalive and must stay 0 (the module tests the whole range
	// for zero).
	b, err := encode(0)
	if err != nil {
		t.Fatalf("configAttrs(0): %v", err)
	}
	if v := nlenc.Uint32(firstPeerAttrs(t, b)[unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]); v != 0 {
		t.Fatalf("disabled keepalive = %#x, want 0", v)
	}

	// Each bound is a u16: more than 65535s can't be represented.
	if _, err := encode(70000 * time.Second); err == nil {
		t.Fatal("configAttrs accepted a keepalive interval over 65535s")
	}
}

func Test_configAttrsMagicHeadersByFamilyVersion(t *testing.T) {
	// dkms v3 stores a magic header as a u32_range_t: a u64 holding hi<<32|lo
	// (src/type.h). A single value N is the range N..N — NOT a bare N, which
	// would be the inverted range N..0 that matches no incoming packet.
	tests := []struct {
		name   string
		header string
		wantV3 uint64
	}{
		{name: "single value", header: "123456", wantV3: 123456<<32 | 123456},
		{name: "range", header: "523920657-651671620", wantV3: 651671620<<32 | 523920657},
		{name: "range with spaces", header: " 5 - 4294967295 ", wantV3: 4294967295<<32 | 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := wgtypes.Config{H1: &tt.header}

			// genl 2 (dkms v1.x): the string goes on the wire untouched.
			b, err := configAttrs("wg0", cfg, 2)
			if err != nil {
				t.Fatalf("configAttrs(v2): %v", err)
			}
			got, ok := deviceAttrs(t, b)[WGDEVICE_A_H1]
			if !ok {
				t.Fatal("v2: no H1 attribute encoded")
			}
			if s := nlenc.String(got); s != tt.header {
				t.Fatalf("v2: H1 = %q, want %q", s, tt.header)
			}

			// genl 3 (dkms v3): packed u64 range.
			b, err = configAttrs("wg0", cfg, genlVersionAWG3)
			if err != nil {
				t.Fatalf("configAttrs(v3): %v", err)
			}
			got, ok = deviceAttrs(t, b)[WGDEVICE_A_H1]
			if !ok {
				t.Fatal("v3: no H1 attribute encoded")
			}
			if len(got) != 8 {
				t.Fatalf("v3: H1 attribute length = %d, want 8", len(got))
			}
			if v := nlenc.Uint64(got); v != tt.wantV3 {
				t.Fatalf("v3: H1 = %#x, want %#x (hi<<32|lo)", v, tt.wantV3)
			}
		})
	}
}

// All four headers land on their own attribute, each packed independently.
func Test_configAttrsMagicHeadersV3AllFour(t *testing.T) {
	h1, h2, h3, h4 := "100-199", "200-299", "300", "400-499"
	b, err := configAttrs("wg0", wgtypes.Config{H1: &h1, H2: &h2, H3: &h3, H4: &h4}, genlVersionAWG3)
	if err != nil {
		t.Fatalf("configAttrs: %v", err)
	}
	attrs := deviceAttrs(t, b)
	for typ, want := range map[uint16]uint64{
		WGDEVICE_A_H1: 199<<32 | 100,
		WGDEVICE_A_H2: 299<<32 | 200,
		WGDEVICE_A_H3: 300<<32 | 300,
		WGDEVICE_A_H4: 499<<32 | 400,
	} {
		if v := nlenc.Uint64(attrs[typ]); v != want {
			t.Errorf("attribute %d = %#x, want %#x", typ, v, want)
		}
	}
}

func Test_configAttrsMagicHeaderInvalidOnV3(t *testing.T) {
	for _, header := range []string{"", "abc", "10-", "-10", "20-10", "4294967296", "1-4294967296", "1-2-3"} {
		h := header
		_, err := configAttrs("wg0", wgtypes.Config{H2: &h}, genlVersionAWG3)
		if err == nil {
			t.Errorf("configAttrs(v3) accepted magic header %q", header)
			continue
		}
		// The error names the header by its config name, not its attribute number.
		if !strings.Contains(err.Error(), "H2") {
			t.Errorf("%q: error %q doesn't name H2", header, err)
		}
	}
}
