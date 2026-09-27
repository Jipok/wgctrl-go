//go:build linux
// +build linux

package wglinux

import (
	"encoding/binary"
	"fmt"
	"net"
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

	// AmneziaWG 3.0 attributes.
	WGDEVICE_A_HEADER_PROTECTION_KEY    = 26
	WGDEVICE_A_CONTENT_PADDING_ADDITION = 27
	WGDEVICE_A_REKEY_AFTER_TIME         = 28
	WGDEVICE_A_REKEY_TIMEOUT            = 29
	WGDEVICE_A_REJECT_AFTER_TIME        = 30
	WGDEVICE_A_KEEPALIVE_TIMEOUT        = 31
	WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS   = 32

	// AmneziaWG 3.1 attributes.
	WGDEVICE_A_RANDOM_TRAILERS = 33
	WGDEVICE_A_DISABLE_COOKIES = 34
)

// packU16Range converts a range into AmneziaWG's packed u16 representation
// (lo | hi<<16). It is used both for the device timing ranges and for the
// peer persistent keepalive interval.
func packU16Range(r wgtypes.UintRange) uint32 {
	return uint32(r.Hi)<<16 | uint32(r.Lo)
}

// packRange converts a uint32 range into AmneziaWG's on-the-wire u64
// representation: the low bound in the low word, the high bound in the high
// word.
func packRange(lo, hi uint32) uint64 {
	return uint64(hi)<<32 | uint64(lo)
}

// configAttrs creates the required encoded netlink attributes to configure
// the device specified by name using the non-nil fields in cfg. The version
// is the generic netlink version reported by the target family; it selects
// between the incompatible AmneziaWG wire formats (see WG_GENL_VERSION).
func configAttrs(name string, cfg wgtypes.Config, version uint8) ([]byte, error) {
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

	// S3/S4 and I1-I5 only exist from 2.0 onwards.
	if version >= 2 {
		if cfg.S3 != nil {
			ae.Uint16(WGDEVICE_A_S3, uint16(*cfg.S3))
		}
		if cfg.S4 != nil {
			ae.Uint16(WGDEVICE_A_S4, uint16(*cfg.S4))
		}
	}

	// Magic Headers. The encoding changed twice:
	//   1.5: a plain uint32 (static header, no ranges)
	//   2.0: a string, "lo-hi"
	//   3.0: a packed uint64 (lo | hi<<32)
	for i, h := range []*string{cfg.H1, cfg.H2, cfg.H3, cfg.H4} {
		if h == nil {
			continue
		}

		attr := uint16(WGDEVICE_A_H1 + i)
		r, err := wgtypes.ParseUintRange(*h)
		if err != nil {
			return nil, err
		}

		switch {
		case version < 2:
			ae.Uint32(attr, r.Lo)
		case version < 3:
			ae.String(attr, r.String())
		default:
			ae.Uint64(attr, packRange(r.Lo, r.Hi))
		}
	}

	// String parameters (Custom Packets), available from 2.0 onwards.
	if version >= 2 {
		for i, s := range []*string{cfg.I1, cfg.I2, cfg.I3, cfg.I4, cfg.I5} {
			if s != nil {
				ae.String(uint16(WGDEVICE_A_I1+i), *s)
			}
		}
	}

	// AmneziaWG 3.0+ device parameters.
	if version >= 3 {
		if key := cfg.HeaderProtectionKey; key != nil {
			// The kernel rejects header protection unless every padding can
			// hold the embedded nonce, and only says -EINVAL when it does.
			// Checking here turns that into an actionable message.
			for _, p := range []struct {
				name string
				val  *int
			}{{"S1", cfg.S1}, {"S2", cfg.S2}, {"S3", cfg.S3}, {"S4", cfg.S4}} {
				if p.val != nil && *p.val < headerProtectionNonceSize {
					return nil, fmt.Errorf("wglinux: %s must be at least %d when HeaderProtectionKey is set, got %d", p.name, headerProtectionNonceSize, *p.val)
				}
			}
			ae.Bytes(WGDEVICE_A_HEADER_PROTECTION_KEY, key[:])
		}

		for _, r := range []struct {
			attr uint16
			val  *wgtypes.UintRange
		}{
			{WGDEVICE_A_CONTENT_PADDING_ADDITION, cfg.ContentPaddingAddition},
			{WGDEVICE_A_REKEY_AFTER_TIME, cfg.RekeyAfterTime},
			{WGDEVICE_A_REKEY_TIMEOUT, cfg.RekeyTimeout},
			{WGDEVICE_A_REJECT_AFTER_TIME, cfg.RejectAfterTime},
			{WGDEVICE_A_KEEPALIVE_TIMEOUT, cfg.KeepaliveTimeout},
			{WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS, cfg.MaxHandshakeAttempts},
		} {
			// Timings use a 16-bit range packed into a uint32 (hi<<16 | lo).
			if r.val != nil {
				ae.Uint32(r.attr, packU16Range(*r.val))
			}
		}

		// AmneziaWG 3.1 booleans.
		if cfg.RandomTrailers != nil {
			ae.Uint8(WGDEVICE_A_RANDOM_TRAILERS, boolToU8(*cfg.RandomTrailers))
		}
		if cfg.DisableCookies != nil {
			ae.Uint8(WGDEVICE_A_DISABLE_COOKIES, boolToU8(*cfg.DisableCookies))
		}
	}
	// -------------------------------------------------------------------------

	// Only apply peer attributes if necessary.
	if len(cfg.Peers) > 0 {
		ae.Nested(unix.WGDEVICE_A_PEERS, func(nae *netlink.AttributeEncoder) error {
			// Netlink arrays use type as an array index.
			for i, p := range cfg.Peers {
				nae.Nested(uint16(i), encodePeer(p, version))
			}

			return nil
		})
	}

	return ae.Encode()
}

// headerProtectionNonceSize is the nonce size embedded in every packet when
// header protection is enabled; every padding has to be at least this large.
const headerProtectionNonceSize = 12

// boolToU8 encodes a bool as the uint8 the kernel's NLA_U8 booleans expect.
func boolToU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
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
func encodePeer(p wgtypes.PeerConfig, version uint8) func(ae *netlink.AttributeEncoder) error {
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
			// The attribute changed shape in AmneziaWG 3.0: it is no longer a
			// plain number but a packed u16 range (lo | hi<<16), so sending a
			// bare value would be read back as the pair (0, seconds). Pack it
			// as (seconds, seconds) to express a fixed interval, matching what
			// the official awg tools send.
			if version < 3 {
				ae.Uint16(unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, uint16(p.PersistentKeepaliveInterval.Seconds()))
			} else {
				n := uint16(p.PersistentKeepaliveInterval.Seconds())
				ae.Uint32(unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, packU16Range(wgtypes.UintRange{Lo: uint32(n), Hi: uint32(n)}))
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
