//go:build linux
// +build linux

package wglinux

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/Jipok/wgctrl-go/wgtypes"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// AmneziaWG Netlink attribute constants.
// Derived from amneziawg-linux-kernel-module/src/uapi/wireguard.h
const (
	WGDEVICE_A_JC   = 9
	WGDEVICE_A_JMIN = 10
	WGDEVICE_A_JMAX = 11
	WGDEVICE_A_S1   = 12
	WGDEVICE_A_S2   = 13
	WGDEVICE_A_H1   = 14
	WGDEVICE_A_H2   = 15
	WGDEVICE_A_H3   = 16
	WGDEVICE_A_H4   = 17
	// WGDEVICE_A_PEER = 18
	WGDEVICE_A_S3 = 19
	WGDEVICE_A_S4 = 20
	WGDEVICE_A_I1 = 21
	WGDEVICE_A_I2 = 22
	WGDEVICE_A_I3 = 23
	WGDEVICE_A_I4 = 24
	WGDEVICE_A_I5 = 25
)

// genlVersionAWG3 is the generic netlink family version amneziawg-dkms v3.x
// reports (WG_GENL_VERSION; mainline WireGuard reports 1, amneziawg-dkms v1.x
// reports 2). v3.0 moved two attributes to packed integer RANGES (see the
// module's src/type.h), and its nla_policy rejects the old widths, so writes
// must match the family version the kernel reported:
//
//   - WGDEVICE_A_H1..H4: a u32_range_t, i.e. a u64 holding `hi<<32 | lo`
//     (NUL-terminated "lo-hi" strings before). A single magic header N is the
//     range N..N. The module checks incoming headers with lo <= h <= hi and
//     picks outgoing ones uniformly in [lo, hi].
//   - WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: a u16_range_t, i.e. a u32
//     holding `hi<<16 | lo` seconds (a plain u16 before); the module picks each
//     keepalive delay uniformly in [lo, hi]. 0 still disables it.
//
// Writing a bare value N into either — hi = 0 — is NOT "just N": it's the
// inverted range N..0, which matches no incoming header and makes the module's
// get_random_u32_inclusive(lo, hi) wrap around to an arbitrary value.
const genlVersionAWG3 = 3

// awg3MagicHeader packs a magic header — a single value "N" or an AmneziaWG
// 2.0 range "lo-hi", both u32 — into amneziawg-dkms v3's u32_range_t wire
// form (`hi<<32 | lo`).
func awg3MagicHeader(s string) (uint64, error) {
	loStr, hiStr, isRange := strings.Cut(strings.TrimSpace(s), "-")
	if !isRange {
		hiStr = loStr
	}
	lo, err := strconv.ParseUint(strings.TrimSpace(loStr), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%q is not a u32 value or a lo-hi range of u32 values", s)
	}
	hi, err := strconv.ParseUint(strings.TrimSpace(hiStr), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%q is not a u32 value or a lo-hi range of u32 values", s)
	}
	if lo > hi {
		return 0, fmt.Errorf("range %q is inverted (lo > hi)", s)
	}
	return hi<<32 | lo, nil
}

// awg3KeepaliveRange packs a keepalive interval into amneziawg-dkms v3's
// u16_range_t wire form (`hi<<16 | lo`) as the fixed range secs..secs.
func awg3KeepaliveRange(d time.Duration) (uint32, error) {
	secs := int64(d / time.Second)
	if secs < 0 || secs > math.MaxUint16 {
		return 0, fmt.Errorf("wglinux: persistent keepalive interval %s is out of range (0-%ds)", d, math.MaxUint16)
	}
	return uint32(secs)<<16 | uint32(secs), nil
}

// configAttrs creates the required encoded netlink attributes to configure
// the device specified by name using the non-nil fields in cfg. genlVersion
// is the generic netlink family version reported by the kernel for the target
// family; attribute widths that changed in amneziawg-dkms v3.0 are keyed off
// it (see genlVersionAWG3).
func configAttrs(name string, cfg wgtypes.Config, genlVersion uint8) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.WGDEVICE_A_IFNAME, name)

	if cfg.PrivateKey != nil {
		ae.Bytes(unix.WGDEVICE_A_PRIVATE_KEY, (*cfg.PrivateKey)[:])
	}

	if cfg.ListenPort != nil {
		ae.Uint16(unix.WGDEVICE_A_LISTEN_PORT, uint16(*cfg.ListenPort))
	}

	if cfg.FirewallMark != nil {
		ae.Uint32(unix.WGDEVICE_A_FWMARK, uint32(*cfg.FirewallMark))
	}

	if cfg.ReplacePeers {
		ae.Uint32(unix.WGDEVICE_A_FLAGS, unix.WGDEVICE_F_REPLACE_PEERS)
	}

	// -------------------------------------------------------------------------
	// AmneziaWG specific attributes encoding.
	// We check if the fields are present in the config (not nil) and encode them.
	// -------------------------------------------------------------------------

	// Uint16 parameters
	if cfg.Jc != nil {
		ae.Uint16(WGDEVICE_A_JC, uint16(*cfg.Jc))
	}
	if cfg.Jmin != nil {
		ae.Uint16(WGDEVICE_A_JMIN, uint16(*cfg.Jmin))
	}
	if cfg.Jmax != nil {
		ae.Uint16(WGDEVICE_A_JMAX, uint16(*cfg.Jmax))
	}

	if cfg.S1 != nil {
		ae.Uint16(WGDEVICE_A_S1, uint16(*cfg.S1))
	}
	if cfg.S2 != nil {
		ae.Uint16(WGDEVICE_A_S2, uint16(*cfg.S2))
	}
	if cfg.S3 != nil {
		ae.Uint16(WGDEVICE_A_S3, uint16(*cfg.S3))
	}
	if cfg.S4 != nil {
		ae.Uint16(WGDEVICE_A_S4, uint16(*cfg.S4))
	}

	// Magic Headers: a single value or an AmneziaWG 2.0 range like
	// "123456-123999". Up to amneziawg-dkms v1.x that string goes on the wire
	// as is (NUL-terminated); v3 takes it packed into a u64 (awg3MagicHeader).
	for _, h := range []struct {
		typ uint16
		val *string
	}{
		{WGDEVICE_A_H1, cfg.H1},
		{WGDEVICE_A_H2, cfg.H2},
		{WGDEVICE_A_H3, cfg.H3},
		{WGDEVICE_A_H4, cfg.H4},
	} {
		if h.val == nil {
			continue
		}
		if genlVersion >= genlVersionAWG3 {
			v, err := awg3MagicHeader(*h.val)
			if err != nil {
				return nil, fmt.Errorf("wglinux: magic header H%d: %w", h.typ-WGDEVICE_A_H1+1, err)
			}
			ae.Uint64(h.typ, v)
		} else {
			ae.String(h.typ, *h.val)
		}
	}

	// String parameters (Custom Packets)
	if cfg.I1 != nil {
		ae.String(WGDEVICE_A_I1, *cfg.I1)
	}
	if cfg.I2 != nil {
		ae.String(WGDEVICE_A_I2, *cfg.I2)
	}
	if cfg.I3 != nil {
		ae.String(WGDEVICE_A_I3, *cfg.I3)
	}
	if cfg.I4 != nil {
		ae.String(WGDEVICE_A_I4, *cfg.I4)
	}
	if cfg.I5 != nil {
		ae.String(WGDEVICE_A_I5, *cfg.I5)
	}
	// -------------------------------------------------------------------------

	// Only apply peer attributes if necessary.
	if len(cfg.Peers) > 0 {
		ae.Nested(unix.WGDEVICE_A_PEERS, func(nae *netlink.AttributeEncoder) error {
			// Netlink arrays use type as an array index.
			for i, p := range cfg.Peers {
				nae.Nested(uint16(i), encodePeer(p, genlVersion))
			}

			return nil
		})
	}

	return ae.Encode()
}

// ipBatchChunk is a tunable allowed IP batch limit per peer.
//
// Because we don't necessarily know how much space a given peer will occupy,
// we play it safe and use a reasonably small value.  Note that this constant
// is used both in this package and tests, so be aware when making changes.
const ipBatchChunk = 256

// peerBatchChunk specifies the number of peers that can appear in a
// configuration before we start splitting it into chunks.
const peerBatchChunk = 32

// shouldBatch determines if a configuration is sufficiently complex that it
// should be split into batches.
func shouldBatch(cfg wgtypes.Config) bool {
	if len(cfg.Peers) > peerBatchChunk {
		return true
	}

	var ips int
	for _, p := range cfg.Peers {
		ips += len(p.AllowedIPs)
	}

	return ips > ipBatchChunk
}

// buildBatches produces a batch of configs from a single config, if needed.
func buildBatches(cfg wgtypes.Config) []wgtypes.Config {
	// Is this a small configuration; no need to batch?
	if !shouldBatch(cfg) {
		return []wgtypes.Config{cfg}
	}

	// Use most fields of cfg for our "base" configuration, and only differ
	// peers in each batch.
	base := cfg
	base.Peers = nil

	// Track the known peers so that peer IPs are not replaced if a single
	// peer has its allowed IPs split into multiple batches.
	knownPeers := make(map[wgtypes.Key]struct{})

	batches := make([]wgtypes.Config, 0)
	for _, p := range cfg.Peers {
		batch := base

		// Iterate until no more allowed IPs.
		var done bool
		for !done {
			var tmp []net.IPNet
			if len(p.AllowedIPs) < ipBatchChunk {
				// IPs all fit within a batch; we are done.
				tmp = make([]net.IPNet, len(p.AllowedIPs))
				copy(tmp, p.AllowedIPs)
				done = true
			} else {
				// IPs are larger than a single batch, copy a batch out and
				// advance the cursor.
				tmp = make([]net.IPNet, ipBatchChunk)
				copy(tmp, p.AllowedIPs[:ipBatchChunk])

				p.AllowedIPs = p.AllowedIPs[ipBatchChunk:]

				if len(p.AllowedIPs) == 0 {
					// IPs ended on a batch boundary; no more IPs left so end
					// iteration after this loop.
					done = true
				}
			}

			pcfg := wgtypes.PeerConfig{
				// PublicKey denotes the peer and must be present.
				PublicKey: p.PublicKey,

				// Apply the update only flag to every chunk to ensure
				// consistency between batches when the kernel module processes
				// them.
				UpdateOnly: p.UpdateOnly,

				// It'd be a bit weird to have a remove peer message with many
				// IPs, but just in case, add this to every peer's message.
				Remove: p.Remove,

				// The IPs for this chunk.
				AllowedIPs: tmp,
			}

			// Only pass certain fields on the first occurrence of a peer, so
			// that subsequent IPs won't be wiped out and space isn't wasted.
			if _, ok := knownPeers[p.PublicKey]; !ok {
				knownPeers[p.PublicKey] = struct{}{}

				pcfg.PresharedKey = p.PresharedKey
				pcfg.Endpoint = p.Endpoint
				pcfg.PersistentKeepaliveInterval = p.PersistentKeepaliveInterval

				// Important: do not move or appending peers won't work.
				pcfg.ReplaceAllowedIPs = p.ReplaceAllowedIPs
			}

			// Add a peer configuration to this batch and keep going.
			batch.Peers = []wgtypes.PeerConfig{pcfg}
			batches = append(batches, batch)
		}
	}

	// Do not allow peer replacement beyond the first message in a batch,
	// so we don't overwrite our previous batch work.
	for i := range batches {
		if i > 0 {
			batches[i].ReplacePeers = false
		}
	}

	return batches
}

// encodePeer returns a function to encode PeerConfig nested attributes.
// genlVersion selects the persistent keepalive attribute width (u32 for
// amneziawg-dkms v3.0, u16 before — see genlVersionAWG3).
func encodePeer(p wgtypes.PeerConfig, genlVersion uint8) func(ae *netlink.AttributeEncoder) error {
	return func(ae *netlink.AttributeEncoder) error {
		ae.Bytes(unix.WGPEER_A_PUBLIC_KEY, p.PublicKey[:])

		// Flags are stored in a single attribute.
		var flags uint32
		if p.Remove {
			flags |= unix.WGPEER_F_REMOVE_ME
		}
		if p.ReplaceAllowedIPs {
			flags |= unix.WGPEER_F_REPLACE_ALLOWEDIPS
		}
		if p.UpdateOnly {
			flags |= unix.WGPEER_F_UPDATE_ONLY
		}
		if flags != 0 {
			ae.Uint32(unix.WGPEER_A_FLAGS, flags)
		}

		if p.PresharedKey != nil {
			ae.Bytes(unix.WGPEER_A_PRESHARED_KEY, (*p.PresharedKey)[:])
		}

		if p.Endpoint != nil {
			ae.Do(unix.WGPEER_A_ENDPOINT, encodeSockaddr(*p.Endpoint))
		}

		if p.PersistentKeepaliveInterval != nil {
			// amneziawg-dkms v3's nla_policy declares this NLA_U32 (a packed
			// u16 range, see genlVersionAWG3) and rejects the mainline u16
			// width, and vice versa — match the encoding to the family
			// version the kernel reported.
			if genlVersion >= genlVersionAWG3 {
				v, err := awg3KeepaliveRange(*p.PersistentKeepaliveInterval)
				if err != nil {
					return err
				}
				ae.Uint32(unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, v)
			} else {
				ae.Uint16(unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, uint16(p.PersistentKeepaliveInterval.Seconds()))
			}
		}

		// Only apply allowed IPs if necessary.
		if len(p.AllowedIPs) > 0 {
			ae.Nested(unix.WGPEER_A_ALLOWEDIPS, encodeAllowedIPs(p.AllowedIPs))
		}

		return nil
	}
}

// encodeSockaddr returns a function which encodes a net.UDPAddr as raw
// sockaddr_in or sockaddr_in6 bytes.
func encodeSockaddr(endpoint net.UDPAddr) func() ([]byte, error) {
	return func() ([]byte, error) {
		if !isValidIP(endpoint.IP) {
			return nil, fmt.Errorf("wglinux: invalid endpoint IP: %s", endpoint.IP.String())
		}

		// Is this an IPv6 address?
		if isIPv6(endpoint.IP) {
			var addr [16]byte
			copy(addr[:], endpoint.IP.To16())

			sa := unix.RawSockaddrInet6{
				Family: unix.AF_INET6,
				Port:   sockaddrPort(endpoint.Port),
				Addr:   addr,
			}

			return (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&sa)))[:], nil
		}

		// IPv4 address handling.
		var addr [4]byte
		copy(addr[:], endpoint.IP.To4())

		sa := unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Port:   sockaddrPort(endpoint.Port),
			Addr:   addr,
		}

		return (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&sa)))[:], nil
	}
}

// encodeAllowedIPs returns a function to encode allowed IP nested attributes.
func encodeAllowedIPs(ipns []net.IPNet) func(ae *netlink.AttributeEncoder) error {
	return func(ae *netlink.AttributeEncoder) error {
		for i, ipn := range ipns {
			if !isValidIP(ipn.IP) {
				return fmt.Errorf("wglinux: invalid allowed IP: %s", ipn.IP.String())
			}

			family := uint16(unix.AF_INET6)
			if !isIPv6(ipn.IP) {
				// Make sure address is 4 bytes if IPv4.
				family = unix.AF_INET
				ipn.IP = ipn.IP.To4()
			}

			// Netlink arrays use type as an array index.
			ae.Nested(uint16(i), func(nae *netlink.AttributeEncoder) error {
				nae.Uint16(unix.WGALLOWEDIP_A_FAMILY, family)
				nae.Bytes(unix.WGALLOWEDIP_A_IPADDR, ipn.IP)

				ones, _ := ipn.Mask.Size()
				nae.Uint8(unix.WGALLOWEDIP_A_CIDR_MASK, uint8(ones))
				return nil
			})
		}

		return nil
	}
}

// isValidIP determines if IP is a valid IPv4 or IPv6 address.
func isValidIP(ip net.IP) bool {
	return ip.To16() != nil
}

// isIPv6 determines if IP is a valid IPv6 address.
func isIPv6(ip net.IP) bool {
	return isValidIP(ip) && ip.To4() == nil
}

// sockaddrPort interprets port as a big endian uint16 for use passing sockaddr
// structures to the kernel.
func sockaddrPort(port int) uint16 {
	return binary.BigEndian.Uint16(nlenc.Uint16Bytes(uint16(port)))
}
