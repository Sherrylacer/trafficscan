package tunnel

import (
	"crypto/cipher"
	"encoding/binary"
	"math/rand"
	"net"
)

// Tunnel frames application data and seals it with an AEAD.
type Tunnel struct {
	conn net.Conn
	aead cipher.AEAD
	sent int
}

// budget is the largest plaintext that keeps one frame inside one link packet.
func (t *Tunnel) budget() int {
	return linkMTU - ipv4Overhead - udpOverhead - frameHeader - t.aead.Overhead()
}

func (t *Tunnel) seal(hdr, payload []byte) []byte {
	return t.aead.Seal(hdr, nil, payload, nil)
}

// Write splits b into frames of at most budget() plaintext bytes.
func (t *Tunnel) Write(b []byte) (int, error) {
	n := 0
	for len(b) > 0 {
		m := len(b)
		if lim := t.budget(); m > lim {
			m = lim
		}
		hdr := make([]byte, frameHeader)
		hdr[2] = frameData
		binary.BigEndian.PutUint16(hdr, uint16(m))
		frame := t.seal(hdr, b[:m])
		if _, err := t.conn.Write(frame); err != nil {
			return n, err
		}
		t.sent++
		n += m
		b = b[m:]
	}
	return n, nil
}

// WriteKeepalive sends a randomly padded keepalive frame.
func (t *Tunnel) WriteKeepalive() error {
	pad := rand.Intn(maxPad) + minPad
	frame := make([]byte, frameHeader+pad)
	frame[2] = frameKeepalive
	_, err := t.conn.Write(frame)
	return err
}

// Prober sends fixed-size reachability probes over UDP.
type Prober struct {
	pc net.PacketConn
}

// SendProbe writes one probe datagram.
func (p *Prober) SendProbe(addr net.Addr) error {
	buf := make([]byte, probeSize)
	buf[0] = frameProbe
	_, err := p.pc.WriteTo(buf, addr)
	return err
}
