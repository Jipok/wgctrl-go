package wgtypes

import (
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// A DeviceType specifies the underlying implementation of a WireGuard device.
type DeviceType int

// Possible DeviceType values.
const (
	Unknown DeviceType = iota
	LinuxKernel
	OpenBSDKernel
	FreeBSDKernel
	WindowsKernel
	Userspace
)

// String returns the string representation of a DeviceType.
func (dt DeviceType) String() string {
	switch dt {
	case LinuxKernel:
		return "Linux kernel"
	case OpenBSDKernel:
		return "OpenBSD kernel"
	case FreeBSDKernel:
		return "FreeBSD kernel"
	case WindowsKernel:
		return "Windows kernel"
	case Userspace:
		return "userspace"
	default:
		return "unknown"
	}
}

// An AmneziaVersion identifies the AmneziaWG protocol generation of a device.
type AmneziaVersion int

// Possible AmneziaVersion values.
const (
	AWGNone AmneziaVersion = iota // plain WireGuard
	AWG15                         // 1.5: static magic headers
	AWG20                         // 2.0: ranged headers, I1-I5, S3/S4
	AWG30                         // 3.0: header protection, padding/timing ranges
	AWG31                         // 3.1: random trailers, cookie control
)

// amneziaVersionNames maps each generation to its human-readable name.
var amneziaVersionNames = [...]string{
	AWGNone: "none",
	AWG15:   "1.5",
	AWG20:   "2.0",
	AWG30:   "3.0",
	AWG31:   "3.1",
}

// String returns a short name such as "1.5" or "3.1".
func (v AmneziaVersion) String() string {
	if v < AWG15 || v > AWG31 {
		return amneziaVersionNames[AWGNone]
	}
	return amneziaVersionNames[v]
}

// genlVersion maps a generation to the generic netlink version its kernel
// module reports (see WG_GENL_VERSION in the module's uapi header).
func (v AmneziaVersion) genlVersion() uint8 {
	switch v {
	case AWG15:
		return 1
	case AWG20:
		return 2
	case AWG30, AWG31:
		return 3
	}
	return 0
}

// A UintRange is an inclusive [Lo, Hi] range of unsigned values.
// AmneziaWG uses ranges for magic headers and, since 3.0, for content padding
// and protocol timing parameters.
type UintRange struct {
	Lo, Hi uint32
}

// String renders a range in the AmneziaWG configuration format ("lo" or
// "lo-hi").
func (r UintRange) String() string {
	if r.Lo == r.Hi {
		return strconv.FormatUint(uint64(r.Lo), 10)
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// IsZero reports whether the range is unset.
func (r UintRange) IsZero() bool {
	return r.Lo == 0 && r.Hi == 0
}

// ParseUintRange parses an AmneziaWG range in "lo" or "lo-hi" form.
func ParseUintRange(s string) (UintRange, error) {
	loStr, hiStr, isRange := strings.Cut(s, "-")
	lo, err := strconv.ParseUint(loStr, 10, 32)
	if err != nil {
		return UintRange{}, fmt.Errorf("wgtypes: invalid range %q: %v", s, err)
	}

	hi := lo
	if isRange {
		if hi, err = strconv.ParseUint(hiStr, 10, 32); err != nil {
			return UintRange{}, fmt.Errorf("wgtypes: invalid range %q: %v", s, err)
		}
	}
	if hi < lo {
		return UintRange{}, fmt.Errorf("wgtypes: invalid range %q: hi is below lo", s)
	}

	return UintRange{Lo: uint32(lo), Hi: uint32(hi)}, nil
}

// A Device is a WireGuard device.
type Device struct {
	// Name is the name of the device.
	Name string

	// Type specifies the underlying implementation of the device.
	Type DeviceType

	// PrivateKey is the device's private key.
	PrivateKey Key

	// PublicKey is the device's public key, computed from its PrivateKey.
	PublicKey Key

	// ListenPort is the device's network listening port.
	ListenPort int

	// FirewallMark is the device's current firewall mark.
	//
	// The firewall mark can be used in conjunction with firewall software to
	// take action on outgoing WireGuard packets.
	FirewallMark int

	IsAmnezia bool

	// AmneziaVersion is the detected AmneziaWG generation of this device, or
	// AWGNone for a plain WireGuard device.
	AmneziaVersion AmneziaVersion

	// AmneziaWG obfuscation parameters, zero when the device is plain
	// WireGuard or the attribute is absent.
	Jc                     int
	Jmin                   int
	Jmax                   int
	S1, S2, S3, S4         int
	H1, H2, H3, H4         UintRange
	I1, I2, I3, I4, I5     string
	ContentPaddingAddition *UintRange
	RekeyAfterTime         *UintRange
	RekeyTimeout           *UintRange
	RejectAfterTime        *UintRange
	KeepaliveTimeout       *UintRange
	MaxHandshakeAttempts   *UintRange
	RandomTrailers         bool
	DisableCookies         bool

	// SawRandomTrailers reports that the peer implementation advertised the
	// AmneziaWG 3.1 random trailers capability, even when it is disabled.
	SawRandomTrailers bool

	// HeaderProtectionKey is the ChaCha20 key encrypting the magic headers.
	// A nil value means no header protection is configured.
	HeaderProtectionKey *[32]byte

	// Peers is the list of network peers associated with this device.
	Peers []Peer
}

// KeyLen is the expected key length for a WireGuard key.
const KeyLen = 32 // wgh.KeyLen

// A Key is a public, private, or pre-shared secret key.  The Key constructor
// functions in this package can be used to create Keys suitable for each of
// these applications.
type Key [KeyLen]byte

// GenerateKey generates a Key suitable for use as a pre-shared secret key from
// a cryptographically safe source.
//
// The output Key should not be used as a private key; use GeneratePrivateKey
// instead.
func GenerateKey() (Key, error) {
	b := make([]byte, KeyLen)
	if _, err := crand.Read(b); err != nil {
		return Key{}, fmt.Errorf("wgtypes: failed to read random bytes: %v", err)
	}

	return NewKey(b)
}

// GeneratePrivateKey generates a Key suitable for use as a private key from a
// cryptographically safe source.
func GeneratePrivateKey() (Key, error) {
	key, err := GenerateKey()
	if err != nil {
		return Key{}, err
	}

	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64

	return key, nil
}

// NewKey creates a Key from an existing byte slice.  The byte slice must be
// exactly 32 bytes in length.
func NewKey(b []byte) (Key, error) {
	if len(b) != KeyLen {
		return Key{}, fmt.Errorf("wgtypes: incorrect key size: %d", len(b))
	}

	var k Key
	copy(k[:], b)

	return k, nil
}

// ParseKey parses a Key from a base64-encoded string, as produced by the
// Key.String method.
func ParseKey(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("wgtypes: failed to parse base64-encoded key: %v", err)
	}

	return NewKey(b)
}

// PublicKey computes a public key from the private key k.
//
// PublicKey should only be called when k is a private key.
func (k Key) PublicKey() Key {
	var (
		pub  [KeyLen]byte
		priv = [KeyLen]byte(k)
	)

	// ScalarBaseMult uses the correct base value per https://cr.yp.to/ecdh.html,
	// so no need to specify it.
	curve25519.ScalarBaseMult(&pub, &priv)

	return Key(pub)
}

// String returns the base64-encoded string representation of a Key.
//
// ParseKey can be used to produce a new Key from this string.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// A Peer is a WireGuard peer to a Device.
type Peer struct {
	// PublicKey is the public key of a peer, computed from its private key.
	//
	// PublicKey is always present in a Peer.
	PublicKey Key

	// PresharedKey is an optional preshared key which may be used as an
	// additional layer of security for peer communications.
	//
	// A zero-value Key means no preshared key is configured.
	PresharedKey Key

	// Endpoint is the most recent source address used for communication by
	// this Peer.
	Endpoint *net.UDPAddr

	// PersistentKeepaliveInterval specifies how often an "empty" packet is sent
	// to a peer to keep a connection alive.
	//
	// A value of 0 indicates that persistent keepalives are disabled.
	PersistentKeepaliveInterval time.Duration

	// LastHandshakeTime indicates the most recent time a handshake was performed
	// with this peer.
	//
	// A zero-value time.Time indicates that no handshake has taken place with
	// this peer.
	LastHandshakeTime time.Time

	// ReceiveBytes indicates the number of bytes received from this peer.
	ReceiveBytes int64

	// TransmitBytes indicates the number of bytes transmitted to this peer.
	TransmitBytes int64

	// AllowedIPs specifies which IPv4 and IPv6 addresses this peer is allowed
	// to communicate on.
	//
	// 0.0.0.0/0 indicates that all IPv4 addresses are allowed, and ::/0
	// indicates that all IPv6 addresses are allowed.
	AllowedIPs []net.IPNet

	// ProtocolVersion specifies which version of the WireGuard protocol is used
	// for this Peer.
	//
	// A value of 0 indicates that the most recent protocol version will be used.
	ProtocolVersion int
}

// A Config is a WireGuard device configuration.
//
// Because the zero value of some Go types may be significant to WireGuard for
// Config fields, pointer types are used for some of these fields. Only
// pointer fields which are not nil will be applied when configuring a device.
type Config struct {
	// PrivateKey specifies a private key configuration, if not nil.
	//
	// A non-nil, zero-value Key will clear the private key.
	PrivateKey *Key

	// ListenPort specifies a device's listening port, if not nil.
	ListenPort *int

	// FirewallMark specifies a device's firewall mark, if not nil.
	//
	// If non-nil and set to 0, the firewall mark will be cleared.
	FirewallMark *int

	// ReplacePeers specifies if the Peers in this configuration should replace
	// the existing peer list, instead of appending them to the existing list.
	ReplacePeers bool

	// Peers specifies a list of peer configurations to apply to a device.
	Peers []PeerConfig

	// --- AmneziaWG Specific Configuration ---
	// All fields are pointers to handle "optional update" semantics.

	// Junk Packet parameters
	Jc   *int // Count
	Jmin *int // Min size
	Jmax *int // Max size

	// Message Padding parameters (bytes)
	S1 *int // Init
	S2 *int // Response
	S3 *int // Cookie
	S4 *int // Transport

	// Message Magic Headers
	// In AmneziaWG 2.0 these should be ranges (e.g., "123456-123999")
	H1 *string // Init
	H2 *string // Response
	H3 *string // Cookie
	H4 *string // Transport

	// Init Packet Magic / Custom Signature (obfuscation)
	// For client-side explicit setups only.
	I1 *string
	I2 *string
	I3 *string
	I4 *string
	I5 *string

	// --- AmneziaWG 3.0+ Configuration ---

	// HeaderProtectionKey encrypts the magic headers with ChaCha20, if not
	// nil. Requires S1-S4 to be at least 12 bytes (the embedded nonce size).
	HeaderProtectionKey *[32]byte

	// ContentPaddingAddition, if not nil, appends a random number of bytes
	// picked from the range to every transport packet.
	ContentPaddingAddition *UintRange

	// Protocol timings, if not nil. Unlike WireGuard's fixed constants these
	// are picked at random from the given ranges.
	RekeyAfterTime       *UintRange
	RekeyTimeout         *UintRange
	RejectAfterTime      *UintRange
	KeepaliveTimeout     *UintRange
	MaxHandshakeAttempts *UintRange

	// RandomTrailers, if not nil, pads packets with random trailing bytes
	// bounded by the UDP window size. This breaks simple packet-size
	// fingerprinting, but both endpoints must enable it.
	RandomTrailers *bool

	// DisableCookies, if not nil, disables cookie replies and the whole
	// "under load" code path, removing a recognisable response pattern.
	DisableCookies *bool
}

// GenerateAmneziaParams populates the config with obfuscation values for the
// given AmneziaWG generation. Generations below 3.0 receive the classic 2.0
// profile; 3.0 and 3.1 additionally get header protection, content padding
// and timing ranges (3.1 also enables random trailers and cookie control).
func (cfg *Config) GenerateAmneziaParams(ver AmneziaVersion) {
	// Header protection and the 3.x padding rules need at least 12 bytes.
	thirdGen := ver >= AWG30
	// ==========================================
	// 1. PRE-SESSION JUNK PACKETS (Jc, Jmin, Jmax)
	// Doc limits: Jc 0-10, Jmin/Jmax 64-1024 bytes.
	// For 1.5/2.0 we avoid packets smaller than 64 bytes so DPI doesn't flag them
	// as anomalies. 3.x uses the official client's smaller sizes, see below.
	// ==========================================

	// thirdGen is decided below for the padding rules; junk is versioned here.
	// Pre-session junk is sent once before the handshake and never parsed by the
	// receiver, so it only has to look plausible in the channel. AmneziaWG 3.x
	// already spreads sizes through ContentPadding and random trailers, and large
	// junk can exceed the path MTU at exactly the wrong moment, so 3.x keeps the
	// modest sizes the official client uses.
	if ver >= AWG30 {
		cfg.Jc = intPtr(4 + rand.IntN(3)) // 4 to 6 packets
		cfg.Jmin = intPtr(10)
		cfg.Jmax = intPtr(50)
	} else {
		cfg.Jc = intPtr(3 + rand.IntN(4)) // 3 to 6 packets

		// AWG Go core easily handles up to 1024. We wanna look like UDP app traffic.
		cfg.Jmin = intPtr(64 + rand.IntN(50))              // 64-113 bytes
		cfg.Jmax = intPtr(*cfg.Jmin + 50 + rand.IntN(100)) // Jmin + (50-149 bytes)
	}

	// ==========================================
	// 2. PACKET PADDING (S1, S2, S3, S4)
	// Doc limits: S1-S3: 0-64 bytes. S4: 0-32 bytes.
	// Base standard WG sizes: Init=148, Resp=92, Cookie=64.
	// Random garbage bytes prepended to the START of WireGuard packets.
	// S3/S4 only exist from 2.0 onwards.
	// ==========================================

	// secondGen tells us whether the 2.0-only parameters may be emitted.
	secondGen := ver >= AWG20

	// RandomTrailers (3.1) makes the receiving side accept a packet whenever it
	// is at least as large as the expected type instead of exactly as large, so
	// differing paddings would let one packet type be mistaken for another. The
	// official guidance is therefore to share one padding across all four types,
	// which also makes the uniqueness rules below pointless.
	//
	// The padding is a random prefix, and header protection takes its ChaCha20
	// nonce from that prefix's first 12 bytes. Anything past the nonce is unused
	// filler, so 12 -- the minimum the kernel accepts -- is also the optimum.
	if ver >= AWG31 {
		s := 12
		cfg.S1, cfg.S2, cfg.S3, cfg.S4 = intPtr(s), intPtr(s), intPtr(s), intPtr(s)
	} else {
		for {
			// Strict limits to prevent high overhead while breaking WG signature
			s1 := 15 + rand.IntN(49) // 15-63 bytes
			s2 := 15 + rand.IntN(49) // 15-63 bytes
			s3 := 10 + rand.IntN(54) // 10-63 bytes
			s4 := 1 + rand.IntN(15)  // 1-15 bytes (keep Transport small to save MTU)

			// Header protection embeds a 12-byte nonce into every packet, so
			// every padding has to be at least that large.
			if thirdGen {
				s3 = 12 + rand.IntN(52) // 12-63 bytes
				s4 = 12 + rand.IntN(13) // 12-24 bytes
			}

			// Rule A: All padding values must be unique
			if s1 == s2 || s1 == s3 || s1 == s4 || s2 == s3 || s2 == s4 || s3 == s4 {
				continue
			}

			// Rule B: Total resulting packet sizes must NEVER be equal.
			// NOTE: We do not check S4 against control packets because Transport
			// packets have variable payload sizes. The AWG core handles Transport
			// size alignment dynamically using inner MsgType validation.
			if s1+148 == s2+92 || s3+64 == s1+148 || s3+64 == s2+92 {
				continue
			}

			// Apply values and break the loop
			cfg.S1, cfg.S2 = intPtr(s1), intPtr(s2)
			if secondGen {
				cfg.S3, cfg.S4 = intPtr(s3), intPtr(s4)
			}
			break
		}
	}

	// ==========================================
	// 3. MAGIC HEADERS (H1 - H4)
	// 1.5 uses four independent static headers, while 2.0+ uses ranges.
	// Ranges are generated non-overlapping, then shuffled so that
	// H1 < H2 < H3 < H4 is mathematically destroyed, preventing heuristic
	// DPI signature matching.
	// We keep max value below math.MaxInt32 to prevent integer
	// overflow crashes on legacy C++ clients which parse strings into signed ints.
	// ==========================================

	currentOffset := 150_000_000 + rand.IntN(50_000_000)
	ranges := make([]*string, 4)

	// Step 3.1: Generate strictly increasing non-overlapping ranges
	for i := 0; i < 4; i++ {
		rangeStart := currentOffset
		rangeEnd := rangeStart + 50_000_000 + rand.IntN(100_000_000)
		if !secondGen {
			// Static headers: only the low bound is meaningful.
			rangeEnd = rangeStart
		}
		ranges[i] = strPtr(UintRange{Lo: uint32(rangeStart), Hi: uint32(rangeEnd)}.String())

		// Add a guaranteed gap to prevent overlap
		currentOffset = rangeEnd + 10_000_000 + rand.IntN(20_000_000)
	}

	// Step 3.2: SHUFFLE THE RANGES (The Anti-Heuristic Magic)
	rand.Shuffle(len(ranges), func(i, j int) {
		ranges[i], ranges[j] = ranges[j], ranges[i]
	})

	// Step 3.3: Assign shuffled ranges to packet types
	cfg.H1 = ranges[0] // Handshake Initiation
	cfg.H2 = ranges[1] // Handshake Response
	cfg.H3 = ranges[2] // Cookie Reply
	cfg.H4 = ranges[3] // Transport Data

	// With header protection the message type is encrypted, so custom ranges
	// add nothing to what the cipher already hides. The official guidance is to
	// keep the standard compatibility values in that mode, which also leaves the
	// custom header mechanism effectively disabled.
	if thirdGen {
		cfg.H1, cfg.H2, cfg.H3, cfg.H4 = strPtr("1"), strPtr("2"), strPtr("3"), strPtr("4")
	}

	// Init-packets (I1..I5) are usually for specific protocol emulation (TLS/DTLS).
	// From Doc:
	// If the parameter I1 is missing, the entire chain (I2-I5) is skipped, and AmneziaWG behaves as AmneziaWG 1.0, simplifying compatibility.
	// These only exist from 2.0 onwards.
	if !secondGen {
		return
	}

	i1Length := 15 + rand.IntN(26)
	cfg.I1 = strPtr(fmt.Sprintf("<r %d>", i1Length))

	// Got it from amnezia desktop client. Without it some dpi drops packets
	cfg.I1 = strPtr("<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>")

	if !thirdGen {
		return
	}

	// ==========================================
	// 4. HEADER PROTECTION KEY (AWG 3.0+)
	// A 32-byte shared key which encrypts the four magic headers. S1-S4 are
	// already >= 12 bytes above, as the kernel demands for this feature.
	// ==========================================

	if key, err := GenerateKey(); err == nil {
		k := [32]byte(key)
		cfg.HeaderProtectionKey = &k
	}

	// ==========================================
	// 5. CONTENT PADDING & TIMINGS (AWG 3.0+)
	// Values match the official client's generator. ContentPadding and
	// RandomTrailers both randomise the tail of a transport packet and the
	// kernel applies the former with an else-if, so setting it means trailers
	// only affect handshake packets. Together they spread transport sizes.
	// ==========================================

	cfg.ContentPaddingAddition = &UintRange{Lo: 10, Hi: 100}
	cfg.RekeyAfterTime = &UintRange{Lo: 100, Hi: 120}
	cfg.RekeyTimeout = &UintRange{Lo: 3, Hi: 7}
	cfg.RejectAfterTime = &UintRange{Lo: 150, Hi: 180}
	cfg.KeepaliveTimeout = &UintRange{Lo: 5, Hi: 15}
	cfg.MaxHandshakeAttempts = &UintRange{Lo: 15, Hi: 20}

	// ==========================================
	// 6. RANDOM TRAILERS & COOKIE CONTROL (AWG 3.1)
	// Both endpoints must agree on RandomTrailers for handshakes to be
	// accepted, and amneziawg's own client enables both, so we do too.
	// ==========================================

	if ver >= AWG31 {
		cfg.RandomTrailers = boolPtr(true)
		cfg.DisableCookies = boolPtr(true)
	}
}

// intPtr is a helper to get a pointer to an int generic literal
func intPtr(i int) *int {
	return &i
}

func strPtr(s string) *string {
	return &s
}

// boolPtr is a helper to get a pointer to a bool generic literal
func boolPtr(b bool) *bool {
	return &b
}

// TODO(mdlayher): consider adding ProtocolVersion in PeerConfig.

// A PeerConfig is a WireGuard device peer configuration.
//
// Because the zero value of some Go types may be significant to WireGuard for
// PeerConfig fields, pointer types are used for some of these fields. Only
// pointer fields which are not nil will be applied when configuring a peer.
type PeerConfig struct {
	// PublicKey specifies the public key of this peer.  PublicKey is a
	// mandatory field for all PeerConfigs.
	PublicKey Key

	// Remove specifies if the peer with this public key should be removed
	// from a device's peer list.
	Remove bool

	// UpdateOnly specifies that an operation will only occur on this peer
	// if the peer already exists as part of the interface.
	UpdateOnly bool

	// PresharedKey specifies a peer's preshared key configuration, if not nil.
	//
	// A non-nil, zero-value Key will clear the preshared key.
	PresharedKey *Key

	// Endpoint specifies the endpoint of this peer entry, if not nil.
	Endpoint *net.UDPAddr

	// PersistentKeepaliveInterval specifies the persistent keepalive interval
	// for this peer, if not nil.
	//
	// A non-nil value of 0 will clear the persistent keepalive interval.
	PersistentKeepaliveInterval *time.Duration

	// ReplaceAllowedIPs specifies if the allowed IPs specified in this peer
	// configuration should replace any existing ones, instead of appending them
	// to the allowed IPs list.
	ReplaceAllowedIPs bool

	// AllowedIPs specifies a list of allowed IP addresses in CIDR notation
	// for this peer.
	AllowedIPs []net.IPNet
}
