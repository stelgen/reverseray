package rrp

// WebSocket-транспорт RRP/1 (v0.7): тот же TLS-порт 4433, апгрейд до
// RFC 6455 по пути /rrp. Это позволяет держать туннель на портах, где
// инспекторы DPI ожидают HTTP/WebSocket (443/80/CDN-проксирование).
//
// Сервер: после TLS-хендшейка читает первый байт. 'G' (HTTP GET) —
// WS-апгрейд, иначе — сырой RRP/1 (обратная совместимость со старыми
// клиентами). Один порт обслуживает оба транспорта.
//
// Маппинг кадров: одна Write = одно binary-сообщение WebSocket = один
// кадр RRP/1. Read возвращает байты всех binary-сообщений подряд;
// ping/pong/close протокола WS обрабатываются прозрачно.

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	wsGUID         = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	wsPath         = "/rrp"
	wsMaxHeader    = 8 * 1024
	wsMaxMessage   = 1 << 20 // защита от memory-bomb: одно WS-сообщение ≤ 1 МБ
	wsHandshakeTTL = 10 * time.Second
)

var (
	ErrWsHandshake = errors.New("rrp: websocket handshake failed")
	ErrWsProtocol  = errors.New("rrp: websocket protocol violation")
)

// IsWsPeek reports whether the buffered stream starts with an HTTP GET
// (WebSocket upgrade attempt) rather than raw RRP/1 frames.
func IsWsPeek(br *bufio.Reader) bool {
	b, err := br.Peek(1)
	if err != nil || len(b) == 0 {
		return false
	}
	return b[0] == 'G' // 0x47: "GET"
}

// WsHandshakeServer performs the RFC 6455 server handshake over an already
// TLS-established connection and returns a framed binary transport.
func WsHandshakeServer(conn net.Conn, br *bufio.Reader) (*WsConn, error) {
	_ = conn.SetDeadline(time.Now().Add(wsHandshakeTTL))
	req, err := readWsRequest(br)
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
		_ = conn.Close()
		return nil, err
	}
	if !strings.EqualFold(req.upgrade, "websocket") || req.key == "" {
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
		_ = conn.Close()
		return nil, fmt.Errorf("%w: not a websocket upgrade", ErrWsHandshake)
	}
	if req.path != wsPath {
		_, _ = conn.Write([]byte("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n"))
		_ = conn.Close()
		return nil, fmt.Errorf("%w: bad path %q (expected %s)", ErrWsHandshake, req.path, wsPath)
	}
	sum := sha1.Sum([]byte(req.key + wsGUID)) // #nosec G401: SHA1 предписан RFC 6455 для Accept
	accept := base64.StdEncoding.EncodeToString(sum[:])
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &WsConn{r: br, w: conn, c: conn}, nil
}

type wsRequest struct {
	path     string
	upgrade  string
	key      string
	connFlag string
}

func readWsRequest(br *bufio.Reader) (*wsRequest, error) {
	req := &wsRequest{}
	line, err := readHeaderLine(br)
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return nil, fmt.Errorf("%w: bad request line %q", ErrWsHandshake, line)
	}
	req.path = parts[1]
	for {
		h, err := readHeaderLine(br)
		if err != nil {
			return nil, err
		}
		if h == "" {
			break
		}
		name, value, found := strings.Cut(h, ":")
		if !found {
			continue
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		switch strings.ToLower(name) {
		case "upgrade":
			req.upgrade = value
		case "sec-websocket-key":
			req.key = value
		case "connection":
			req.connFlag = value
		}
	}
	if !strings.Contains(strings.ToLower(req.connFlag), "upgrade") {
		return nil, fmt.Errorf("%w: missing Connection: Upgrade", ErrWsHandshake)
	}
	return req, nil
}

func readHeaderLine(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for sb.Len() < wsMaxHeader {
		b, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			return strings.TrimSuffix(sb.String(), "\r"), nil
		}
		sb.WriteByte(b)
	}
	return "", errors.New("rrp: ws request header too large")
}

// WsConn is a server-side RFC 6455 binary transport (unmasked server frames).
type WsConn struct {
	r *bufio.Reader
	w io.Writer
	c io.Closer

	wmu     sync.Mutex
	buf     []byte // pending bytes from ws messages
	scratch []byte
	closed  bool
}

func (c *WsConn) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		if err := c.fill(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *WsConn) fill() error {
	fin, opcode, payload, err := c.readFrame()
	if err != nil {
		return err
	}
	switch opcode {
	case 0x2, 0x0: // binary / continuation
		c.buf = append(c.buf, payload...)
		_ = fin // сообщения до 1 МБ приходят одним фреймом; продолжения копим так же
		return nil
	case 0x9: // ping → pong
		if werr := c.writeFrame(0xA, payload); werr != nil {
			return werr
		}
		return nil
	case 0xA: // pong — игнорируем
		return nil
	case 0x8: // close
		_ = c.writeFrame(0x8, nil)
		return io.EOF
	default:
		return fmt.Errorf("%w: opcode 0x%02x", ErrWsProtocol, opcode)
	}
}

func (c *WsConn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(c.r, hdr[:]); err != nil {
		return
	}
	fin = hdr[0]&0x80 != 0
	opcode = hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	ln := uint64(hdr[1] & 0x7F)
	switch ln {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.r, ext[:]); err != nil {
			return
		}
		ln = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.r, ext[:]); err != nil {
			return
		}
		ln = binary.BigEndian.Uint64(ext[:])
	}
	if ln > wsMaxMessage {
		err = fmt.Errorf("%w: message %d > %d", ErrWsProtocol, ln, wsMaxMessage)
		return
	}
	var maskKey [4]byte
	if masked {
		if _, err = io.ReadFull(c.r, maskKey[:]); err != nil {
			return
		}
	}
	payload = make([]byte, ln)
	if _, err = io.ReadFull(c.r, payload); err != nil {
		return
	}
	if masked { // клиент обязан маскировать; сервер — не обязан, но терпим
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return
}

// Write sends one binary WebSocket message per Write call (RRP frame 1:1).
func (c *WsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return 0, ErrClosed
	}
	if err := c.writeFrame(0x2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *WsConn) writeFrame(opcode byte, payload []byte) error {
	var hdr [10]byte
	hdr[0] = 0x80 | opcode // FIN + opcode, сервер не маскирует
	n := len(payload)
	i := 1
	switch {
	case n < 126:
		hdr[1] = byte(n)
		i = 2
	case n <= 0xFFFF:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		i = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		i = 10
	}
	if _, err := c.w.Write(hdr[:i]); err != nil {
		return err
	}
	if n > 0 {
		_, err := c.w.Write(payload)
		return err
	}
	return nil
}

func (c *WsConn) Close() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	// best-effort close frame
	_ = c.writeFrame(0x8, nil)
	return c.c.Close()
}
