//go:build linux
// +build linux

package wglinux

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/Jipok/wgctrl-go/internal/wginternal"
	"github.com/Jipok/wgctrl-go/wgtypes"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

// Constants for AmneziaWG identification
const (
	amneziaGenlName = "amneziawg"
	amneziaKind     = "amneziawg"
)

var _ wginternal.Client = &Client{}

// A Client provides access to Linux WireGuard netlink information.
type Client struct {
	c *genetlink.Conn

	// Store pointers to families so we can distinguish if they are loaded.
	// These structs contain the Name, ID, and Version required for requests.
	wgFamily      *genetlink.Family
	amneziaFamily *genetlink.Family

	interfaces func() ([]string, error)
}

// New creates a new Client and returns whether or not the generic netlink
// interface is available.
func New() (*Client, bool, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, false, err
	}

	// Best effort version of netlink.Config.Strict due to CentOS 7.
	for _, o := range []netlink.ConnOption{
		netlink.ExtendedAcknowledge,
		netlink.GetStrictCheck,
	} {
		_ = c.SetOption(o, true)
	}

	return initClient(c)
}

// initClient is the internal Client constructor used in some tests.
func initClient(c *genetlink.Conn) (*Client, bool, error) {
	// Try to locate the standard WireGuard family.
	wg, errWg := c.GetFamily(unix.WG_GENL_NAME)

	// Try to locate the AmneziaWG family.
	// Using a pointer to distinguish between "not found" and "found".
	var amnezia *genetlink.Family
	if af, err := c.GetFamily(amneziaGenlName); err == nil {
		amnezia = &af
	}

	// If neither family is found, return the error from the standard WG lookup.
	if errWg != nil && amnezia == nil {
		_ = c.Close()

		// If WG is missing but we had a specific Netlink error (not just NotExist), return it.
		if !errors.Is(errWg, os.ErrNotExist) {
			return nil, false, errWg
		}
		// If both are strictly missing (NotExist), return false with no error (not supported).
		return nil, false, nil
	}

	// Make a pointer for standard WG if it was found.
	var wgPtr *genetlink.Family
	if errWg == nil {
		wgPtr = &wg
	}

	return &Client{
		c:             c,
		wgFamily:      wgPtr,
		amneziaFamily: amnezia,
		interfaces:    rtnlInterfaces,
	}, true, nil
}

// Close implements wginternal.Client.
func (c *Client) Close() error {
	return c.c.Close()
}

// Devices implements wginternal.Client.
func (c *Client) Devices() ([]*wgtypes.Device, error) {
	// By default, rtnetlink is used to fetch a list of all interfaces and then
	// filter that list to only find WireGuard/AmneziaWG interfaces.
	//
	// The remainder of this function assumes that any returned device from this
	// function is a valid WireGuard device.
	ifis, err := c.interfaces()
	if err != nil {
		return nil, err
	}

	ds := make([]*wgtypes.Device, 0, len(ifis))
	for _, ifi := range ifis {
		d, err := c.Device(ifi)
		if err != nil {
			return nil, err
		}

		ds = append(ds, d)
	}

	return ds, nil
}

// Device implements wginternal.Client.
func (c *Client) Device(name string) (*wgtypes.Device, error) {
	if name == "" {
		return nil, os.ErrNotExist
	}

	// Determine which family owns this device.
	family, err := c.getDeviceFamily(name)
	if err != nil {
		return nil, err
	}

	// Now fetch the data using the correct family ID and Version.
	return c.getDeviceInternal(name, *family)
}

// ConfigureDevice implements wginternal.Client.
func (c *Client) ConfigureDevice(name string, cfg wgtypes.Config) error {
	family, err := c.getDeviceFamily(name)
	if err != nil {
		return err
	}

	batches := buildBatches(cfg)
	if len(batches) == 0 {
		return nil
	}

	for _, batch := range batches {
		attrs, err := configAttrs(name, batch, family.Version)
		if err != nil {
			return err
		}

		// Proceed with the family determined in the first step.
		if _, err := c.execute(*family, unix.WG_CMD_SET_DEVICE, netlink.Request|netlink.Acknowledge, attrs); err != nil {
			return err
		}
	}

	return nil
}

// getDeviceFamily determines if a device belongs to standard WireGuard or AmneziaWG.
// It prioritizes standard WireGuard.
func (c *Client) getDeviceFamily(name string) (*genetlink.Family, error) {
	// 1. Try Standard WireGuard if loaded.
	if c.wgFamily != nil {
		// We perform a cheap check (GET_DEVICE) to see if the kernel module accepts this interface.
		// We rely on getDeviceInternal to perform the actual Netlink call.
		_, err := c.getDeviceInternal(name, *c.wgFamily)
		if err == nil {
			return c.wgFamily, nil
		}
		// If error is something other than NotExist/OpNotSupported, fail immediately.
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.EOPNOTSUPP) {
			return nil, err
		}
	}

	// 2. Try AmneziaWG if loaded.
	if c.amneziaFamily != nil {
		_, err := c.getDeviceInternal(name, *c.amneziaFamily)
		if err == nil {
			return c.amneziaFamily, nil
		}
		if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.EOPNOTSUPP) {
			return nil, err
		}
	}

	return nil, os.ErrNotExist
}

// getDeviceInternal executes the netlink call to fetch device details for a specific family.
func (c *Client) getDeviceInternal(name string, family genetlink.Family) (*wgtypes.Device, error) {
	b, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: unix.WGDEVICE_A_IFNAME,
		Data: nlenc.Bytes(name),
	}})
	if err != nil {
		return nil, err
	}

	msgs, err := c.execute(family, unix.WG_CMD_GET_DEVICE, netlink.Request|netlink.Dump, b)
	if err != nil {
		return nil, err
	}

	d, err := parseDevice(msgs, family.Version)
	if err != nil {
		return nil, err
	}

	if family.Name == amneziaGenlName {
		d.IsAmnezia = true
		d.AmneziaVersion = amneziaVersion(family.Version)
		// AmneziaWG 3.1 always advertises its random trailers capability,
		// which is how 3.0 and 3.1 are told apart within netlink version 3.
		if d.SawRandomTrailers {
			d.AmneziaVersion = wgtypes.AWG31
		}
	}

	return d, nil
}

// amneziaVersion maps a generic netlink family version to an AmneziaWG
// generation. Version 3 covers both 3.0 and 3.1; those are told apart by
// AmneziaWG 3.1's random trailers attribute, which the kernel always emits.
func amneziaVersion(version uint8) wgtypes.AmneziaVersion {
	switch version {
	case 1:
		return wgtypes.AWG15
	case 2:
		return wgtypes.AWG20
	case 3:
		return wgtypes.AWG30
	default:
		return wgtypes.AWGNone
	}
}

// execute executes a single Netlink request.
// It uses the passed family to determine the Family ID and the Generic Netlink Version.
func (c *Client) execute(family genetlink.Family, command uint8, flags netlink.HeaderFlags, attrb []byte) ([]genetlink.Message, error) {
	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: command,
			Version: family.Version, // Use the version reported by the kernel (e.g. 2 for Amnezia)
		},
		Data: attrb,
	}

	msgs, err := c.c.Execute(msg, family.ID, flags)
	if err == nil {
		return msgs, nil
	}

	oerr, ok := err.(*netlink.OpError)
	if !ok {
		return nil, fmt.Errorf("wglinux: netlink operation returned non-netlink error: %v", err)
	}

	switch oerr.Err {
	case unix.ENODEV, unix.ENOTSUP:
		return nil, os.ErrNotExist
	default:
		return nil, oerr.Err
	}
}

// rtnlInterfaces uses rtnetlink to fetch a list of WireGuard interfaces.
func rtnlInterfaces() ([]string, error) {
	// Use the stdlib's rtnetlink helpers to get ahold of a table of all
	// interfaces, so we can begin filtering it down to just WireGuard devices.
	tab, err := syscall.NetlinkRIB(unix.RTM_GETLINK, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("wglinux: failed to get list of interfaces from rtnetlink: %v", err)
	}

	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, fmt.Errorf("wglinux: failed to parse rtnetlink messages: %v", err)
	}

	return parseRTNLInterfaces(msgs)
}

// parseRTNLInterfaces unpacks rtnetlink messages and returns WireGuard
// interface names.
func parseRTNLInterfaces(msgs []syscall.NetlinkMessage) ([]string, error) {
	var ifis []string
	for _, m := range msgs {
		// Only deal with link messages, and they must have an ifinfomsg
		// structure appear before the attributes.
		if m.Header.Type != unix.RTM_NEWLINK {
			continue
		}

		if len(m.Data) < unix.SizeofIfInfomsg {
			return nil, fmt.Errorf("wglinux: rtnetlink message is too short for ifinfomsg: %d", len(m.Data))
		}

		ad, err := netlink.NewAttributeDecoder(m.Data[syscall.SizeofIfInfomsg:])
		if err != nil {
			return nil, err
		}

		// Determine the interface's name and if it's a WireGuard device.
		var (
			ifi  string
			isWG bool
		)

		for ad.Next() {
			switch ad.Type() {
			case unix.IFLA_IFNAME:
				ifi = ad.String()
			case unix.IFLA_LINKINFO:
				ad.Do(isWGKind(&isWG))
			}
		}

		if err := ad.Err(); err != nil {
			return nil, err
		}

		if isWG {
			// Found one; append it to the list.
			ifis = append(ifis, ifi)
		}
	}

	return ifis, nil
}

// wgKind is the IFLA_INFO_KIND value for WireGuard devices.
const wgKind = "wireguard"

// isWGKind parses netlink attributes to determine if a link is a WireGuard
// or AmneziaWG device.
func isWGKind(ok *bool) func(b []byte) error {
	return func(b []byte) error {
		ad, err := netlink.NewAttributeDecoder(b)
		if err != nil {
			return err
		}

		for ad.Next() {
			if ad.Type() != unix.IFLA_INFO_KIND {
				continue
			}

			s := ad.String()
			// Check for both kinds
			if s == wgKind || s == amneziaKind {
				*ok = true
				return nil
			}
		}

		return ad.Err()
	}
}
