//go:build linux
// +build linux

package wglinux

import (
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/Jipok/wgctrl-go/wgtypes"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// parseDevice parses a Device from a slice of generic netlink messages,
// automatically merging peer lists from subsequent messages into the Device
// from the first message. version is the generic netlink family version, used
// to pick the right width for fields AmneziaWG has changed.
func parseDevice(msgs []genetlink.Message, version uint8) (*wgtypes.Device, error) {
	var first wgtypes.Device
	knownPeers := make(map[wgtypes.Key]int)

	for i, m := range msgs {
		d, err := parseDeviceLoop(m, version)
		if err != nil {
			return nil, err
		}

		if i == 0 {
			// First message contains our target device.
			first = *d

			// Gather the known peers so that we can merge
			// them later if needed
			for i := range first.Peers {
				knownPeers[first.Peers[i].PublicKey] = i
			}

			continue
		}

		// Any subsequent messages have their peer contents merged into the
		// first "target" message.
		mergeDevices(&first, d, knownPeers)
	}

	return &first, nil
}

// parseDeviceLoop parses a Device from a single generic netlink message.
func parseDeviceLoop(m genetlink.Message, version uint8) (*wgtypes.Device, error) {
	ad, err := netlink.NewAttributeDecoder(m.Data)
	if err != nil {
		return nil, err
	}

	d := wgtypes.Device{Type: wgtypes.LinuxKernel}
	for ad.Next() {
		switch ad.Type() {
		case unix.WGDEVICE_A_IFINDEX:
			// Ignored; interface index isn't exposed at all in the userspace
			// configuration protocol, and name is more friendly anyway.
		case unix.WGDEVICE_A_IFNAME:
			d.Name = ad.String()
		case unix.WGDEVICE_A_PRIVATE_KEY:
			ad.Do(parseKey(&d.PrivateKey))
		case unix.WGDEVICE_A_PUBLIC_KEY:
			ad.Do(parseKey(&d.PublicKey))
		case unix.WGDEVICE_A_LISTEN_PORT:
			d.ListenPort = int(ad.Uint16())
		case unix.WGDEVICE_A_FWMARK:
			d.FirewallMark = int(ad.Uint32())
		case WGDEVICE_A_JC:
			d.Jc = int(ad.Uint16())
		case WGDEVICE_A_JMIN:
			d.Jmin = int(ad.Uint16())
		case WGDEVICE_A_JMAX:
			d.Jmax = int(ad.Uint16())
		case WGDEVICE_A_S1:
			d.S1 = int(ad.Uint16())
		case WGDEVICE_A_S2:
			d.S2 = int(ad.Uint16())
		case WGDEVICE_A_S3:
			d.S3 = int(ad.Uint16())
		case WGDEVICE_A_S4:
			d.S4 = int(ad.Uint16())
		case WGDEVICE_A_H1, WGDEVICE_A_H2, WGDEVICE_A_H3, WGDEVICE_A_H4:
			// Same three-way split as on the encoding side.
			switch {
			case version < 2:
				v := ad.Uint32()
				setHeader(&d, ad.Type(), wgtypes.UintRange{Lo: v, Hi: v})
			case version < 3:
				r, err := wgtypes.ParseUintRange(ad.String())
				if err != nil {
					return nil, err
				}
				setHeader(&d, ad.Type(), r)
			default:
				v := ad.Uint64()
				setHeader(&d, ad.Type(), wgtypes.UintRange{Lo: uint32(v), Hi: uint32(v >> 32)})
			}
		case WGDEVICE_A_I1, WGDEVICE_A_I2, WGDEVICE_A_I3, WGDEVICE_A_I4, WGDEVICE_A_I5:
			setCustomPacket(&d, ad.Type(), ad.String())
		case WGDEVICE_A_HEADER_PROTECTION_KEY:
			if b := ad.Bytes(); len(b) == 32 {
				key := [32]byte(b)
				d.HeaderProtectionKey = &key
			}
		case WGDEVICE_A_CONTENT_PADDING_ADDITION:
			d.ContentPaddingAddition = unpackTiming(ad.Uint32())
		case WGDEVICE_A_REKEY_AFTER_TIME:
			d.RekeyAfterTime = unpackTiming(ad.Uint32())
		case WGDEVICE_A_REKEY_TIMEOUT:
			d.RekeyTimeout = unpackTiming(ad.Uint32())
		case WGDEVICE_A_REJECT_AFTER_TIME:
			d.RejectAfterTime = unpackTiming(ad.Uint32())
		case WGDEVICE_A_KEEPALIVE_TIMEOUT:
			d.KeepaliveTimeout = unpackTiming(ad.Uint32())
		case WGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS:
			d.MaxHandshakeAttempts = unpackTiming(ad.Uint32())
		case WGDEVICE_A_RANDOM_TRAILERS:
			d.RandomTrailers = ad.Uint8() != 0
			d.SawRandomTrailers = true
		case WGDEVICE_A_DISABLE_COOKIES:
			d.DisableCookies = ad.Uint8() != 0
		case unix.WGDEVICE_A_PEERS:
			// Netlink array of peers.
			//
			// Errors while parsing are propagated up to top-level ad.Err check.
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				// Initialize to the number of peers in this decoder and begin
				// handling nested Peer attributes.
				d.Peers = make([]wgtypes.Peer, 0, nad.Len())
				for nad.Next() {
					nad.Nested(func(nnad *netlink.AttributeDecoder) error {
						d.Peers = append(d.Peers, parsePeer(nnad, version))
						return nil
					})
				}

				return nil
			})
		}
	}

	if err := ad.Err(); err != nil {
		return nil, err
	}

	return &d, nil
}

// setHeader stores a parsed magic header range into its Device field.
func setHeader(d *wgtypes.Device, attr uint16, r wgtypes.UintRange) {
	switch attr {
	case WGDEVICE_A_H1:
		d.H1 = r
	case WGDEVICE_A_H2:
		d.H2 = r
	case WGDEVICE_A_H3:
		d.H3 = r
	case WGDEVICE_A_H4:
		d.H4 = r
	}
}

// setCustomPacket stores a parsed custom packet signature into its Device field.
func setCustomPacket(d *wgtypes.Device, attr uint16, spec string) {
	switch attr {
	case WGDEVICE_A_I1:
		d.I1 = spec
	case WGDEVICE_A_I2:
		d.I2 = spec
	case WGDEVICE_A_I3:
		d.I3 = spec
	case WGDEVICE_A_I4:
		d.I4 = spec
	case WGDEVICE_A_I5:
		d.I5 = spec
	}
}

// unpackTiming reverses the uint16 range packing used by the 3.0 timing
// parameters, which store a low bound in the low word and a high bound in the
// high word.
func unpackTiming(v uint32) *wgtypes.UintRange {
	return &wgtypes.UintRange{Lo: v & 0xffff, Hi: v >> 16}
}

// parseAllowedIPs parses a wgtypes.Peer from a netlink attribute payload.
func parsePeer(ad *netlink.AttributeDecoder, version uint8) wgtypes.Peer {
	var p wgtypes.Peer
	for ad.Next() {
		switch ad.Type() {
		case unix.WGPEER_A_PUBLIC_KEY:
			ad.Do(parseKey(&p.PublicKey))
		case unix.WGPEER_A_PRESHARED_KEY:
			ad.Do(parseKey(&p.PresharedKey))
		case unix.WGPEER_A_ENDPOINT:
			p.Endpoint = &net.UDPAddr{}
			ad.Do(parseSockaddr(p.Endpoint))
		case unix.WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL:
			// A plain uint16 before AmneziaWG 3.0, a packed u16 range
			// (lo | hi<<16) from 3.0 on. Unpack the low bound, which is the
			// value the interval is actually picked from.
			if version < 3 {
				p.PersistentKeepaliveInterval = time.Duration(ad.Uint16()) * time.Second
			} else {
				p.PersistentKeepaliveInterval = time.Duration(uint16(ad.Uint32())) * time.Second
			}
		case unix.WGPEER_A_LAST_HANDSHAKE_TIME:
			ad.Do(parseTimespec(&p.LastHandshakeTime))
		case unix.WGPEER_A_RX_BYTES:
			p.ReceiveBytes = int64(ad.Uint64())
		case unix.WGPEER_A_TX_BYTES:
			p.TransmitBytes = int64(ad.Uint64())
		case unix.WGPEER_A_ALLOWEDIPS:
			ad.Nested(parseAllowedIPs(&p.AllowedIPs))
		case unix.WGPEER_A_PROTOCOL_VERSION:
			p.ProtocolVersion = int(ad.Uint32())
		}
	}

	return p
}

// parseAllowedIPs parses a slice of net.IPNet from a netlink attribute payload.
func parseAllowedIPs(ipns *[]net.IPNet) func(ad *netlink.AttributeDecoder) error {
	return func(ad *netlink.AttributeDecoder) error {
		// Initialize to the number of allowed IPs and begin iterating through
		// the netlink array to decode each one.
		*ipns = make([]net.IPNet, 0, ad.Len())
		for ad.Next() {
			// Allowed IP nested attributes.
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				var (
					ipn    net.IPNet
					mask   int
					family int
				)

				for nad.Next() {
					switch nad.Type() {
					case unix.WGALLOWEDIP_A_IPADDR:
						nad.Do(parseAddr(&ipn.IP))
					case unix.WGALLOWEDIP_A_CIDR_MASK:
						mask = int(nad.Uint8())
					case unix.WGALLOWEDIP_A_FAMILY:
						family = int(nad.Uint16())
					}
				}

				if err := nad.Err(); err != nil {
					return err
				}

				// The address family determines the correct number of bits in
				// the mask.
				switch family {
				case unix.AF_INET:
					ipn.Mask = net.CIDRMask(mask, 32)
				case unix.AF_INET6:
					ipn.Mask = net.CIDRMask(mask, 128)
				}

				*ipns = append(*ipns, ipn)
				return nil
			})
		}

		return nil
	}
}

// parseKey parses a wgtypes.Key from a byte slice.
func parseKey(key *wgtypes.Key) func(b []byte) error {
	return func(b []byte) error {
		k, err := wgtypes.NewKey(b)
		if err != nil {
			return err
		}

		*key = k
		return nil
	}
}

// parseAddr parses a net.IP from raw in_addr or in6_addr struct bytes.
func parseAddr(ip *net.IP) func(b []byte) error {
	return func(b []byte) error {
		switch len(b) {
		case net.IPv4len, net.IPv6len:
			// Okay to convert directly to net.IP; memory layout is identical.
			*ip = make(net.IP, len(b))
			copy(*ip, b)
			return nil
		default:
			return fmt.Errorf("wglinux: unexpected IP address size: %d", len(b))
		}
	}
}

// parseSockaddr parses a *net.UDPAddr from raw sockaddr_in or sockaddr_in6 bytes.
func parseSockaddr(endpoint *net.UDPAddr) func(b []byte) error {
	return func(b []byte) error {
		switch len(b) {
		case unix.SizeofSockaddrInet4:
			// IPv4 address parsing.
			sa := *(*unix.RawSockaddrInet4)(unsafe.Pointer(&b[0]))

			*endpoint = net.UDPAddr{
				IP:   net.IP(sa.Addr[:]).To4(),
				Port: int(sockaddrPort(int(sa.Port))),
			}

			return nil
		case unix.SizeofSockaddrInet6:
			// IPv6 address parsing.
			sa := *(*unix.RawSockaddrInet6)(unsafe.Pointer(&b[0]))

			*endpoint = net.UDPAddr{
				IP:   net.IP(sa.Addr[:]),
				Port: int(sockaddrPort(int(sa.Port))),
			}

			return nil
		default:
			return fmt.Errorf("wglinux: unexpected sockaddr size: %d", len(b))
		}
	}
}

// timespec32 is a unix.Timespec with 32-bit integers.
type timespec32 struct {
	Sec  int32
	Nsec int32
}

// timespec64 is a unix.Timespec with 64-bit integers.
type timespec64 struct {
	Sec  int64
	Nsec int64
}

const (
	sizeofTimespec32 = int(unsafe.Sizeof(timespec32{}))
	sizeofTimespec64 = int(unsafe.Sizeof(timespec64{}))
)

// parseTimespec parses a time.Time from raw timespec bytes.
func parseTimespec(t *time.Time) func(b []byte) error {
	return func(b []byte) error {
		// It would appear that WireGuard can return a __kernel_timespec which
		// uses 64-bit integers, even on 32-bit platforms. Clarification of this
		// behavior is being sought in:
		// https://lists.zx2c4.com/pipermail/wireguard/2019-April/004088.html.
		//
		// In the mean time, be liberal and accept 32-bit and 64-bit variants.
		var sec, nsec int64

		switch len(b) {
		case sizeofTimespec32:
			ts := *(*timespec32)(unsafe.Pointer(&b[0]))

			sec = int64(ts.Sec)
			nsec = int64(ts.Nsec)
		case sizeofTimespec64:
			ts := *(*timespec64)(unsafe.Pointer(&b[0]))

			sec = ts.Sec
			nsec = ts.Nsec
		default:
			return fmt.Errorf("wglinux: unexpected timespec size: %d bytes, expected 8 or 16 bytes", len(b))
		}

		// Only set fields if UNIX timestamp value is greater than 0, so the
		// caller will see a zero-value time.Time otherwise.
		if sec > 0 || nsec > 0 {
			*t = time.Unix(sec, nsec)
		}

		return nil
	}
}

// mergeDevices merges Peer information from d into target.  mergeDevices is
// used to deal with multiple incoming netlink messages for the same device.
func mergeDevices(target, d *wgtypes.Device, knownPeers map[wgtypes.Key]int) {
	for i := range d.Peers {
		// Peer is already known, append to it's allowed IP networks
		if peerIndex, ok := knownPeers[d.Peers[i].PublicKey]; ok {
			target.Peers[peerIndex].AllowedIPs = append(target.Peers[peerIndex].AllowedIPs, d.Peers[i].AllowedIPs...)
		} else { // New peer, add it to the target peers.
			target.Peers = append(target.Peers, d.Peers[i])
			knownPeers[d.Peers[i].PublicKey] = len(target.Peers) - 1
		}
	}
}
