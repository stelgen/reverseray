// Package inbound implements the mixed SOCKS5/HTTP entry listener.
package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/stelgen/reverseray/server/internal/hub"
)

// Dialer abstracts the tunnel hub (implemented by *hub.Hub).
type Dialer interface {
	Dial(ctx context.Context, atyp byte, addr []byte, port uint16, timeout time.Duration) (net.Conn, error)
}

// Inbound is a mixed-protocol proxy listener.
type Inbound struct {
	Dialer    Dialer
	Username  string // optional; both empty = no auth
	Password  string
	Allowlist []*net.IPNet
	Logf      func(format string, args ...any)

	DialTimeout time.Duration
}

// Serve accepts connections until the listener closes.
func (in *Inbound) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !in.allowed(c.RemoteAddr()) {
			_ = c.Close()
			continue
		}
		go in.handle(c)
	}
}

func (in *Inbound) allowed(ra net.Addr) bool {
	if len(in.Allowlist) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(ra.String())
	if err != nil {
		host = ra.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range in.Allowlist {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (in *Inbound) logf(f string, a ...any) {
	if in.Logf != nil {
		in.Logf(f, a...)
	}
}

func (in *Inbound) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReaderSize(c, 16*1024)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	switch first[0] {
	case 0x05:
		in.socks5(c, br)
	default:
		in.http(c, br)
	}
}

// ---- SOCKS5 (RFC 1928) ----

func (in *Inbound) socks5(c net.Conn, br *bufio.Reader) {
	if err := in.socksAuth(c, br); err != nil {
		in.logf("socks auth: %v", err)
		return
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	if head[0] != 0x05 {
		return
	}
	if head[1] != 0x01 { // only CONNECT
		c.Write([]byte{5, 0x07, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	atyp, addr, port, err := readSocksTarget(br, head[3])
	if err != nil {
		c.Write([]byte{5, 0x01, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	dst, err := in.dial(c, atyp, addr, port)
	if err != nil {
		c.Write([]byte{5, socksErr(err), 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer dst.Close()
	// Success reply.
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	relay(c, dst)
}

func (in *Inbound) socksAuth(c net.Conn, br *bufio.Reader) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return fmt.Errorf("bad version %d", head[0])
	}
	n := int(head[1])
	methods := make([]byte, n)
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	hasNoAuth, hasUserPass := false, false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
		}
		if m == 0x02 {
			hasUserPass = true
		}
	}
	wantAuth := in.Username != "" || in.Password != ""
	if wantAuth {
		if !hasUserPass {
			c.Write([]byte{5, 0xFF})
			return errors.New("auth required but not offered")
		}
		c.Write([]byte{5, 0x02})
		ver := make([]byte, 2) // ver, ulen
		if _, err := io.ReadFull(br, ver); err != nil {
			return err
		}
		user := make([]byte, ver[1])
		if _, err := io.ReadFull(br, user); err != nil {
			return err
		}
		pl := make([]byte, 1)
		if _, err := io.ReadFull(br, pl); err != nil {
			return err
		}
		pass := make([]byte, pl[0])
		if _, err := io.ReadFull(br, pass); err != nil {
			return err
		}
		ok := subtleEqual(string(user), in.Username) && subtleEqual(string(pass), in.Password)
		if ok {
			c.Write([]byte{1, 0})
		} else {
			c.Write([]byte{1, 1})
			return errors.New("bad credentials")
		}
		return nil
	}
	if !hasNoAuth {
		c.Write([]byte{5, 0xFF})
		return errors.New("no acceptable auth method")
	}
	c.Write([]byte{5, 0x00})
	return nil
}

func readSocksTarget(br *bufio.Reader, atyp byte) (byte, []byte, uint16, error) {
	switch atyp {
	case 1: // IPv4
		b := make([]byte, 6)
		if _, err := io.ReadFull(br, b); err != nil {
			return 0, nil, 0, err
		}
		return 1, b[:4], uint16(b[4])<<8 | uint16(b[5]), nil
	case 3: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return 0, nil, 0, err
		}
		b := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(br, b); err != nil {
			return 0, nil, 0, err
		}
		return 3, b[:l[0]], uint16(b[l[0]])<<8 | uint16(b[l[0]+1]), nil
	case 4: // IPv6
		b := make([]byte, 18)
		if _, err := io.ReadFull(br, b); err != nil {
			return 0, nil, 0, err
		}
		return 4, b[:16], uint16(b[16])<<8 | uint16(b[17]), nil
	}
	return 0, nil, 0, fmt.Errorf("bad ATYP %d", atyp)
}

// ---- HTTP proxy (CONNECT + absolute-URI) ----

func (in *Inbound) http(c net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if in.Username != "" || in.Password != "" {
		u, p, ok := proxyBasicAuth(req)
		if !ok || !subtleEqual(u, in.Username) || !subtleEqual(p, in.Password) {
			c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"reverseray\"\r\n\r\n"))
			return
		}
	}
	if req.Method == http.MethodConnect {
		host, portS, err := net.SplitHostPort(req.Host)
		if err != nil {
			c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		port, err := strconv.ParseUint(portS, 10, 16)
		if err != nil {
			c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		atyp, addr, aerr := encodeHost(host)
		if aerr != nil {
			c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		dst, derr := in.dial(c, atyp, addr, uint16(port))
		if derr != nil {
			c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer dst.Close()
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		relay(c, dst)
		return
	}
	// Absolute-URI plain proxy (GET/POST ...). One request per connection.
	if req.URL.Host == "" {
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		if req.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	atyp, addr, aerr := encodeHost(host)
	if aerr != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	p64, _ := strconv.ParseUint(port, 10, 16)
	dst, derr := in.dial(c, atyp, addr, uint16(p64))
	if derr != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer dst.Close()
	outReq := req.Clone(context.Background())
	outReq.RequestURI = ""
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Set("Connection", "close")
	if err := outReq.Write(dst); err != nil {
		return
	}
	_ = relayHalf(c, dst)
}

func relayHalf(a, b net.Conn) error {
	done := make(chan error, 2)
	go func() { _, err := io.Copy(b, a); done <- err }()
	go func() { _, err := io.Copy(a, b); done <- err }()
	err1 := <-done
	_ = b.SetDeadline(time.Now())
	_ = a.SetDeadline(time.Now())
	err2 := <-done
	if err1 != nil && err1 != io.EOF {
		return err1
	}
	if err2 != nil && err2 != io.EOF {
		return err2
	}
	return nil
}

func relay(a, b net.Conn) {
	_ = relayHalf(a, b)
}

func (in *Inbound) dial(_ net.Conn, atyp byte, addr []byte, port uint16) (net.Conn, error) {
	return in.Dialer.Dial(context.Background(), atyp, addr, port, in.DialTimeout)
}

func encodeHost(host string) (byte, []byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return 1, v4, nil
		}
		return 4, ip.To16(), nil
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 255 {
		return 0, nil, fmt.Errorf("bad host")
	}
	return 3, []byte(strings.ToLower(host)), nil
}

// proxyBasicAuth parses the Proxy-Authorization header (RFC 7235 proxy variant).
func proxyBasicAuth(r *http.Request) (string, string, bool) {
	h := r.Header.Get("Proxy-Authorization")
	const prefix = "Basic "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", "", false
	}
	dec, err := base64.StdEncoding.DecodeString(h[len(prefix):])
	if err != nil {
		return "", "", false
	}
	i := bytes.IndexByte(dec, ':')
	if i < 0 {
		return "", "", false
	}
	return string(dec[:i]), string(dec[i+1:]), true
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func socksErr(err error) byte {
	switch {
	case errors.Is(err, hub.ErrNoTunnel):
		return 0x01 // general failure (no device online)
	default:
		return 0x04 // host unreachable (phone dial failed)
	}
}
