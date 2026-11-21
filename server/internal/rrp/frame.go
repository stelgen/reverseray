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

	// Кадр камуфляжа «API Mask» (v0.8.2, module id apimask, bidirectional):
	// payload — JSON-объект, похожий на обмен бизнес-API (см. internal/apimasq).
	// Клиент шлёт NOISE только если сервер в READY заявил features:["apimask"];
	// сервер отвечает NOISE ТОЛЬКО на полученный NOISE — старые версии обеих
	// сторон кадр никогда не видят (нулевая поломка совместимости).
	TypeNoise = 0x26

	// Кадры протокола wireguard (v0.9.5, module protocol.wireguard):
	// payload — НАСТОЯЩИЕ WireGuard-кадры (Noise_IKpsk2) внутри приватного
	// канала. WG_INIT (C→S) — msg1 инициатора (148 Б), WG_RESP (S→C) —
	// msg2 респондера (92 Б). После обмена payload'ы DATA/UDP_DATA —
	// WG transport-пакеты (type=4, ChaCha20-Poly1305, sliding-window).
	TypeWgInit = 0x27
	TypeWgResp = 0x28

	// Управление модулем камуфляжа с клиента (v0.9.5): C→S JSON
	// {"enabled":true|false}. Сервер сохраняет выбор устройства ПЕРМАНЕНТНО
	// (переживает реконнекты и офлайн клиента) и отражает в READY.features
	// следующей сессии: выключенный клиентом apimask не включается обратно.
	TypeCamCtl = 0x2A

	// Кадры протокола bittorrent (v0.10, module protocol.bittorrent):
	// payload — канонные пакеты MSE/PE (Message Stream Encryption) внутри
	// приватного канала. BT_INIT (C→S) = packet1||packet3 (Ya+pad+req1+
	// req2⊕req3+RC4_A(...)), BT_RESP (S→C) = packet4 (RC4_B(VC+select+PadD)).
	// После обмена payload'ы DATA/UDP_DATA — peer-wire piece-сообщения (type 7).
	TypeBtInit = 0x29
	TypeBtResp = 0x2B

	// v1.3.0 «буфер трафика» — резюме стримов при потере связи:
	// RESUME_TOKEN (S→C, сразу после OPEN_OK err=0): 16-байтный токен привязки
	// телефонного сокета. OPEN_RESUME (S→C, после реконнекта): сервер просит
	// телефон ПРИВЯЗАТЬ запаркованный сокет (телефон НЕ закрывал его) к новому
	// стриму; ответ — обычный OPEN_OK (0 = привязано, 5 = сокета больше нет).
	// Оба кадра уходят ТОЛЬКО клиентам с HELLO caps «stream-resume».
	TypeOpenResume  = 0x2D
	TypeResumeToken = 0x2E

	// v1.9.8 Buffer/2 (docs/spec/ack.md) — кумулятивный ACK доставки p→c:
	// payload [u64be offset]. Уходит ТОЛЬКО клиентам с caps+features
	// «stream-ack» (сервер-отправитель ведёт LEDGER по WINDOW от телефона,
	// телефон-отправитель — по этому ACK). C→S TypeAck — нарушение протокола.
	TypeAck = 0x2F
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
	switch t {
	case TypeData, TypeUdpData:
		return MaxDataPayload
	case TypeOpenResume, TypeResumeToken:
		return 16 // ровно токен
	case TypeAck:
		return 8 // ровно u64
	case TypeWgInit:
		return 256 // wg msg1 = 148 Б (запас на будущие WG-форматы)
	case TypeWgResp:
		return 256 // wg msg2 = 92 Б
	case TypeBtInit:
		return 1280 // MSE packet1(96+512) + packet3(40+8+4+2+512+2)
	case TypeBtResp:
		return 640 // MSE packet4 = RC4(8+4+2+512)
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
	var off int // присваивается в каждой ветке switch ниже
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

// ---- Buffer/2 (v1.9.8, docs/spec/ack.md) ----

// EncodeACK — payload TypeAck: кумулятивный offset доставки p→c.
func EncodeACK(offset uint64) []byte {
	p := make([]byte, 8)
	binary.BigEndian.PutUint64(p, offset)
	return p
}

// DecodeACK разбирает payload TypeAck.
func DecodeACK(payload []byte) (uint64, error) {
	if len(payload) != 8 {
		return 0, errors.New("rrp: ACK payload must be 8 bytes")
	}
	return binary.BigEndian.Uint64(payload), nil
}

// EncodeDataOffset — payload DATA в ack-режиме: [u64be offset][chunk].
// Префикс живёт ВНУТРИ крипто-конверта. Лимит: chunk ≤ MaxDataPayload-8.
func EncodeDataOffset(offset uint64, chunk []byte) []byte {
	p := make([]byte, 8+len(chunk))
	binary.BigEndian.PutUint64(p, offset)
	copy(p[8:], chunk)
	return p
}

// SplitDataOffset разбирает payload DATA в ack-режиме.
func SplitDataOffset(payload []byte) (uint64, []byte, error) {
	if len(payload) < 8 {
		return 0, nil, errors.New("rrp: DATA payload shorter than offset prefix")
	}
	return binary.BigEndian.Uint64(payload), payload[8:], nil
}

// EncodeResumedOpenOK — payload OPEN_OK resume-стрима в ack-режиме:
// [u8 err_code=0][u64be K] — K = потреблено телефоном из старого стрима (c→p).
func EncodeResumedOpenOK(errCode uint8, consumed uint64) []byte {
	p := make([]byte, 9)
	p[0] = errCode
	binary.BigEndian.PutUint64(p[1:], consumed)
	return p
}

// DecodeResumedOpenOK разбирает расширенный OPEN_OK (ack-режим, resume).
func DecodeResumedOpenOK(payload []byte) (uint8, uint64, error) {
	if len(payload) != 9 {
		return 0, 0, errors.New("rrp: resumed OPEN_OK payload must be 9 bytes")
	}
	return payload[0], binary.BigEndian.Uint64(payload[1:]), nil
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
