// Package radius is the RADIUS side of SpireUEM's network-access connector.
//
// SpireUEM is not a RADIUS server. FreeRADIUS calls SpireUEM over HTTPS (rlm_rest) and this
// package holds what SpireUEM needs on its own: the decision mapping for those calls, the
// rlm_rest JSON parser, and a small RFC 5176 encoder used to push Disconnect-Requests to a
// NAS when a device's posture changes.
//
// The encoder is hand-written (about 200 lines, standard library only) rather than a
// dependency: it needs exactly one packet type, the cryptography is two MD5 and HMAC-MD5
// calls that are specified in the RFCs, and the wire format is checked against FreeRADIUS's
// own radclient in scripts/test_radius.sh. MD5 is mandated by the protocol here; it is not
// a choice of this code.
package radius

import (
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- required by RFC 2865/5176
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// Packet codes (RFC 5176).
const (
	CodeDisconnectRequest byte = 40
	CodeDisconnectACK     byte = 41
	CodeDisconnectNAK     byte = 42
	CodeCoARequest        byte = 43
	CodeCoAACK            byte = 44
	CodeCoANAK            byte = 45
)

// Attribute types used by this package.
const (
	AttrUserName             byte = 1
	AttrNASIPAddress         byte = 4
	AttrCallingStationID     byte = 31
	AttrNASIdentifier        byte = 32
	AttrAcctSessionID        byte = 44
	AttrEventTimestamp       byte = 55
	AttrMessageAuthenticator byte = 80
	AttrErrorCause           byte = 101
)

// ErrorCauseSessionNotFound (RFC 5176 section 3.5, 503) means the NAS no longer has the
// session; for a Disconnect that is the outcome we wanted.
const ErrorCauseSessionNotFound = 503

const (
	headerLen = 20
	maxPacket = 4096
)

// Attr is one RADIUS attribute.
type Attr struct {
	Type  byte
	Value []byte
}

// Packet is a decoded RADIUS packet.
type Packet struct {
	Code          byte
	ID            byte
	Authenticator [16]byte
	Attrs         []Attr
}

// Get returns the first attribute of type t.
func (p *Packet) Get(t byte) ([]byte, bool) {
	for _, a := range p.Attrs {
		if a.Type == t {
			return a.Value, true
		}
	}
	return nil, false
}

// StringAttr builds a string attribute.
func StringAttr(t byte, s string) Attr { return Attr{Type: t, Value: []byte(s)} }

// IPv4Attr builds a 4-byte address attribute.
func IPv4Attr(t byte, ip4 [4]byte) Attr { return Attr{Type: t, Value: ip4[:]} }

// Uint32Attr builds a 4-byte integer attribute.
func Uint32Attr(t byte, v uint32) Attr {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return Attr{Type: t, Value: b}
}

func encodeAttrs(attrs []Attr) ([]byte, error) {
	var out []byte
	for _, a := range attrs {
		if len(a.Value) > 253 {
			return nil, fmt.Errorf("radius: attribute %d is %d bytes (max 253)", a.Type, len(a.Value))
		}
		out = append(out, a.Type, byte(len(a.Value)+2))
		out = append(out, a.Value...)
	}
	return out, nil
}

// EncodeRequest serialises a Disconnect/CoA-Request and signs it per RFC 5176 section 2.3:
// it appends a Message-Authenticator (HMAC-MD5 over the packet with a zero authenticator)
// and then sets the Request Authenticator to MD5(packet with a zero authenticator + secret).
// The returned packet also carries the computed authenticator in p.Authenticator.
func (p *Packet) EncodeRequest(secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("radius: empty shared secret")
	}
	attrs := make([]Attr, 0, len(p.Attrs)+1)
	for _, a := range p.Attrs {
		if a.Type != AttrMessageAuthenticator {
			attrs = append(attrs, a)
		}
	}
	attrs = append(attrs, Attr{Type: AttrMessageAuthenticator, Value: make([]byte, 16)})
	body, err := encodeAttrs(attrs)
	if err != nil {
		return nil, err
	}
	n := headerLen + len(body)
	if n > maxPacket {
		return nil, errors.New("radius: packet too large")
	}
	buf := make([]byte, n)
	buf[0], buf[1] = p.Code, p.ID
	binary.BigEndian.PutUint16(buf[2:4], uint16(n))
	copy(buf[headerLen:], body) // authenticator (buf[4:20]) is zero here

	// Message-Authenticator is the last attribute: its 16 value bytes are the final 16.
	mac := hmac.New(md5.New, secret)
	mac.Write(buf)
	copy(buf[n-16:], mac.Sum(nil))

	sum := md5.New()
	sum.Write(buf)
	sum.Write(secret)
	copy(buf[4:20], sum.Sum(nil))
	copy(p.Authenticator[:], buf[4:20])
	p.Attrs = attrs
	return buf, nil
}

// Decode parses a RADIUS packet, enforcing the length rules of RFC 2865 section 3.
func Decode(b []byte) (*Packet, error) {
	if len(b) < headerLen {
		return nil, errors.New("radius: short packet")
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n < headerLen || n > maxPacket || n > len(b) {
		return nil, errors.New("radius: bad length")
	}
	p := &Packet{Code: b[0], ID: b[1]}
	copy(p.Authenticator[:], b[4:20])
	rest := b[headerLen:n]
	for len(rest) > 0 {
		if len(rest) < 2 || int(rest[1]) < 2 || int(rest[1]) > len(rest) {
			return nil, errors.New("radius: malformed attribute")
		}
		l := int(rest[1])
		p.Attrs = append(p.Attrs, Attr{Type: rest[0], Value: append([]byte(nil), rest[2:l]...)})
		rest = rest[l:]
	}
	return p, nil
}

// VerifyRequest checks the Request Authenticator (and the Message-Authenticator when one is
// present) of a Disconnect/CoA-Request. A NAS (or a test listener) uses it.
func VerifyRequest(raw, secret []byte) error {
	p, err := Decode(raw)
	if err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(raw[2:4]))
	raw = raw[:n]
	zeroed := append([]byte(nil), raw...)
	for i := 4; i < 20; i++ {
		zeroed[i] = 0
	}
	// Message-Authenticator first: it is computed over the packet with the authenticator zero
	// and its own value zero.
	if off, ok := attrOffset(raw, AttrMessageAuthenticator); ok {
		if off+16 > len(raw) {
			return errors.New("radius: bad Message-Authenticator")
		}
		chk := append([]byte(nil), zeroed...)
		for i := 0; i < 16; i++ {
			chk[off+i] = 0
		}
		mac := hmac.New(md5.New, secret)
		mac.Write(chk)
		if subtle.ConstantTimeCompare(mac.Sum(nil), raw[off:off+16]) != 1 {
			return errors.New("radius: Message-Authenticator mismatch")
		}
	}
	sum := md5.New()
	sum.Write(zeroed)
	sum.Write(secret)
	if subtle.ConstantTimeCompare(sum.Sum(nil), p.Authenticator[:]) != 1 {
		return errors.New("radius: Request Authenticator mismatch")
	}
	return nil
}

// attrOffset returns the offset of the VALUE of the first attribute of type t.
func attrOffset(raw []byte, t byte) (int, bool) {
	i := headerLen
	for i+2 <= len(raw) {
		l := int(raw[i+1])
		if l < 2 || i+l > len(raw) {
			return 0, false
		}
		if raw[i] == t {
			return i + 2, true
		}
		i += l
	}
	return 0, false
}

// EncodeResponse builds a signed response (ACK/NAK) to the request whose authenticator is
// reqAuth: Response Authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret).
func EncodeResponse(code, id byte, reqAuth [16]byte, secret []byte, attrs []Attr) ([]byte, error) {
	body, err := encodeAttrs(attrs)
	if err != nil {
		return nil, err
	}
	n := headerLen + len(body)
	buf := make([]byte, n)
	buf[0], buf[1] = code, id
	binary.BigEndian.PutUint16(buf[2:4], uint16(n))
	copy(buf[4:20], reqAuth[:])
	copy(buf[headerLen:], body)
	sum := md5.New()
	sum.Write(buf)
	sum.Write(secret)
	copy(buf[4:20], sum.Sum(nil))
	return buf, nil
}

// VerifyResponse checks a response's authenticator against the request it answers.
func VerifyResponse(raw []byte, reqAuth [16]byte, secret []byte) (*Packet, error) {
	p, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(raw[2:4]))
	chk := append([]byte(nil), raw[:n]...)
	copy(chk[4:20], reqAuth[:])
	sum := md5.New()
	sum.Write(chk)
	sum.Write(secret)
	if subtle.ConstantTimeCompare(sum.Sum(nil), p.Authenticator[:]) != 1 {
		return nil, errors.New("radius: Response Authenticator mismatch")
	}
	return p, nil
}

// NewID returns a random packet identifier.
func NewID() byte {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return b[0]
}
