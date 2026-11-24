package tunnel

// Link budget of the (fictional) tunnel protocol. None of these values is
// known to the analyser in advance; it must derive frame sizes from them.
const (
	linkMTU      = 1420
	ipv4Overhead = 20
	udpOverhead  = 8
	frameHeader  = 4 // 2-byte length, 1-byte type, 1-byte flags
	maxPad       = 64
	minPad       = 8
)

const (
	frameData byte = iota + 1
	frameKeepalive
	frameProbe
)

const (
	probeMagicLen = 6
	probeNonceLen = 12
	probeSize     = probeMagicLen + 2*probeNonceLen + 1<<4
)
