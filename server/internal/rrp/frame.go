// Package rrp implements the ReverseRay Protocol v1 (RRP/1) frame codec.
//
// Frame layout (big-endian), 12-byte header:
//
//	[u8 version=1][u8 type][u16 flags][u32 stream_id][u32 payload_len]
package rrp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	Version1 = 1

	// Client -> Server.
	TypeHello  = 0x01
	TypeAuth   = 0x03
	TypeOpenOK = 0x17
	TypeStats  = 0x20

	// Server -> Client.
	TypeHelloOK = 0x02
	TypeReady   = 0x04
	TypeOpen    = 0x10

	// Bidirectional.
	TypeData   = 0x11
	TypeClose  = 0x12
	TypeWindow = 0x13
	TypePing   = 0x14
	TypePong   = 0x15
	TypeError  = 0x7F

	// UDP-over-tunnel (v0.7, RFC 1928 UDP ASSOCIATE analog).
	// TypeUdpAssoc: S→C, пустой payload, stream_id = id ассоциации;
	// телефон отвечает OPEN_OK(err_code) через существующий pending-механизм.
	// TypeUdpData: оба направления, payload [u8 atyp][addr][u16 port][data],
	// где S→C несёт адрес назначения, а C→S — фактический источник ответа.
	TypeUdpAssoc = 0x21
	TypeUdpData  = 0x22

	// TypeProbe (v0.7.4): C→S JSON {"target":"host:port","timeout_ms":N};
	// S→C отвечает тем же типом {"ok":true|false,"err":"","proto":"rrp1"}.
	// Клиент использует PROBE для валидации «реального трафика до реальных
	// хостов» перед переключением протокола (валидация → коммит, иначе откат).
	TypeProbe = 0x23

	// Обмен ключами протокола mtproto2 (v0.8, module protocol.mtproto2):
	// происходит ПОСЛЕ приватного хендшейка (TLS+HMAC) и READY. S→C KEY_REQ
	// несёт p/g/g_a (base64 256-байтовые доли), C→S KEY_RESP — g_b.
	// После обмена payload'ы DATA/UDP_DATA уходят в MTProto 2.0-конверте.
	TypeKeyReq  = 0x24
	TypeKeyResp = 0x25
)

const (
	HeaderLen = 12

	// MaxDataPayload limits DATA frames (hardening: per-type frame limits).
	MaxDataPayload = 64 * 1024
	// MaxControlPayload limits every other frame type.
	MaxControlPayload = 4096

	// ATYP values (SOCKS5-compatible).
	ATYPIPv4   = 1
	ATYPDomain = 3
	ATYPIPv6   = 4
)

var (
	ErrBadVersion    = errors.New("rrp: unsupported protocol version")
	ErrFrameTooLarge = errors.New("rrp: frame payload exceeds type limit")
	ErrFrameShort    = errors.New("rrp: truncated frame")
	ErrUnknownType   = errors.New("rrp: unknown frame type")
	ErrProtocolOrder = errors.New("rrp: frame not allowed in current state")
)

// MaxPayloadFor returns the hard payload limit for a frame type.
func MaxPayloadFor(t uint8) int {
	if t == TypeData || t == TypeUdpData {
		return MaxDataPayload
	}
	return MaxControlPayload
}

// Frame is a single RRP/1 frame.
type Frame struct {
	Type     uint8
	Flags    uint16
	StreamID uint32
	Payload  []byte
}

func (f *Frame) String() string {
	return fmt.Sprintf("frame{type=0x%02x flags=0x%04x stream=%d len=%d}",
		f.Type, f.Flags, f.StreamID, len(f.Payload))
}

// ReadFrame reads one frame from r. Payload is freshly allocated.
func ReadFrame(r io.Reader) (*Frame, error) {
	var hdr [HeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != Version1 {
		return nil, ErrBadVersion
	}
	f := &Frame{
		Type:     hdr[1],
		Flags:    binary.BigEndian.Uint16(hdr[2:4]),
		StreamID: binary.BigEndian.Uint32(hdr[4:8]),
	}
	n := binary.BigEndian.Uint32(hdr[8:12])
	if int(n) > MaxPayloadFor(f.Type) {
		return nil, fmt.Errorf("%w: type=0x%02x len=%d", ErrFrameTooLarge, f.Type, n)
	}
	if n > 0 {
		f.Payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFrameShort, err)
		}
	}
	return f, nil
}

// WriteFrame writes one frame to w.
func WriteFrame(w io.Writer, t uint8, flags uint16, streamID uint32, payload []byte) error {
	if len(payload) > MaxPayloadFor(t) {
		return ErrFrameTooLarge
	}
	var hdr [HeaderLen]byte
	hdr[0] = Version1
	hdr[1] = t
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint32(hdr[4:8], streamID)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(payload))) // #nosec G115: вызывающие ограничены лимитами протокола (DATA<=64КБ, control<=4КБ), фаззинг покрывает
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// ---- payload helpers (binary) ----

// EncodeOpen builds an OPEN payload: [u8 atyp][addr][u16 port],
// where domain addresses carry a 1-byte length prefix (SOCKS5 style):
// [3][len][name][port].
func EncodeOpen(atyp byte, addr []byte, port uint16) []byte {
	p := make([]byte, 0, 2+len(addr)+2)
	p = append(p, atyp)
	if atyp == ATYPDomain {
		p = append(p, byte(len(addr))) // #nosec G115: ATYP-domain ограничен 255 байтами
	}
	p = append(p, addr...)
	p = append(p, byte(port>>8), byte(port)) // #nosec G115: порт 1..65535 (u16)
	return p
}

// DecodeOpen parses an OPEN payload.
func DecodeOpen(payload []byte) (atyp byte, addr []byte, port uint16, err error) {
	if len(payload) < 4 {
		return 0, nil, 0, errors.New("rrp: OPEN payload too short")
	}
	atyp = payload[0]
	switch atyp {
	case ATYPIPv4:
		if len(payload) != 1+4+2 {
			return 0, nil, 0, errors.New("rrp: bad IPv4 OPEN")
		}
		addr = payload[1:5]
	case ATYPDomain:
		dl := int(payload[1])
		if len(payload) != 1+1+dl+2 {
			return 0, nil, 0, errors.New("rrp: bad domain OPEN")
		}
		addr = payload[2 : 2+dl]
	case ATYPIPv6:
		if len(payload) != 1+16+2 {
			return 0, nil, 0, errors.New("rrp: bad IPv6 OPEN")
		}
		addr = payload[1:17]
	default:
		return 0, nil, 0, fmt.Errorf("rrp: unknown ATYP %d", atyp)
	}
	port = binary.BigEndian.Uint16(payload[len(payload)-2:])
	return atyp, addr, port, nil
}

// EncodeUdpData builds a UDP_DATA payload: [u8 atyp][addr][u16 port][data],
// domain addresses carry a 1-byte length prefix (SOCKS5 style).
func EncodeUdpData(atyp byte, addr []byte, port uint16, data []byte) []byte {
	p := make([]byte, 0, 2+len(addr)+2+len(data))
	p = append(p, atyp)
	if atyp == ATYPDomain {
		p = append(p, byte(len(addr))) // #nosec G115: ATYP-domain ограничен 255 байтами
	}
	p = append(p, addr...)
	p = append(p, byte(port>>8), byte(port)) // #nosec G115: порт 1..65535 (u16)
	p = append(p, data...)
	return p
}

// DecodeUdpData parses a UDP_DATA payload.
func DecodeUdpData(payload []byte) (atyp byte, addr []byte, port uint16, data []byte, err error) {
	if len(payload) < 4 {
		return 0, nil, 0, nil, errors.New("rrp: UDP_DATA payload too short")
	}
	atyp = payload[0]
	off := 1
	switch atyp {
	case ATYPIPv4:
		off = 1 + 4
	case ATYPDomain:
		if len(payload) < 3 {
			return 0, nil, 0, nil, errors.New("rrp: bad domain UDP_DATA")
		}
		off = 2 + int(payload[1])
	case ATYPIPv6:
		off = 1 + 16
	default:
		return 0, nil, 0, nil, fmt.Errorf("rrp: unknown ATYP %d", atyp)
	}
	if len(payload) < off+2 {
		return 0, nil, 0, nil, errors.New("rrp: UDP_DATA header truncated")
	}
	switch atyp {
	case ATYPIPv4:
		addr = payload[1:5]
	case ATYPDomain:
		addr = payload[2 : 2+int(payload[1])]
	case ATYPIPv6:
		addr = payload[1:17]
	}
	port = binary.BigEndian.Uint16(payload[off : off+2])
	data = payload[off+2:]
	return atyp, addr, port, data, nil
}

// EncodeDomainAddr encodes a hostname as atyp+addr bytes.
func EncodeDomainAddr(host string) (byte, []byte, error) {
	if len(host) == 0 || len(host) > 255 {
		return 0, nil, errors.New("rrp: bad hostname length")
	}
	return ATYPDomain, []byte(host), nil
}

func EncodeClose(errCode uint8) []byte { return []byte{errCode} }

func EncodeOpenOK(errCode uint8) []byte { return []byte{errCode} }

func EncodeWindow(increment uint32) []byte {
	p := make([]byte, 4)
	binary.BigEndian.PutUint32(p, increment)
	return p
}

func DecodeWindow(payload []byte) (uint32, error) {
	if len(payload) != 4 {
		return 0, errors.New("rrp: WINDOW payload must be 4 bytes")
	}
	return binary.BigEndian.Uint32(payload), nil
}

func EncodeError(code uint16, msg string) []byte {
	if len(msg) > 256 {
		msg = msg[:256]
	}
	p := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(p, code)
	copy(p[2:], msg)
	return p
}

func DecodeError(payload []byte) (uint16, string) {
	if len(payload) < 2 {
		return 0, ""
	}
	return binary.BigEndian.Uint16(payload), string(payload[2:])
}

// RandomPingNonce returns a copy of an 8-byte ping nonce.
func PingNonce(payload []byte) []byte {
	if len(payload) != 8 {
		return nil
	}
	return append([]byte(nil), payload...)
}
