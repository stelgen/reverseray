// v1.9.0: зона HTTP-прокси (CONNECT + absolute-URI) вынесена из mixed.go (транш-2):
// http-хендлер, Proxy-Authorization (basic), constant-time сравнение.

package inbound

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// ---- HTTP proxy (CONNECT + absolute-URI) ----

func (in *Inbound) http(c net.Conn, br *bufio.Reader) bool {
	req, err := http.ReadRequest(br)
	if err != nil {
		return false
	}
	if in.Username != "" || in.Password != "" {
		u, p, ok := proxyBasicAuth(req)
		if !ok || !subtleEqual(u, in.Username) || !subtleEqual(p, in.Password) {
			_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"reverseray\"\r\n\r\n"))
			return false
		}
	}
	if req.Method == http.MethodConnect {
		host, portS, err := net.SplitHostPort(req.Host)
		if err != nil {
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return false
		}
		port, err := strconv.ParseUint(portS, 10, 16)
		if err != nil {
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return false
		}
		atyp, addr, aerr := encodeHost(host)
		if aerr != nil {
			_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return false
		}
		dst, derr := in.dial(c, atyp, addr, uint16(port))
		if derr != nil {
			_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return false
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		wasParked := in.relayStream(c, dst)
		dst.Close()
		return wasParked
	}
	// Absolute-URI plain proxy (GET/POST ...). One request per connection.
	if req.URL.Host == "" {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return false
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
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return false
	}
	p64, _ := strconv.ParseUint(port, 10, 16)
	dst, derr := in.dial(c, atyp, addr, uint16(p64))
	if derr != nil {
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return false
	}
	defer dst.Close()
	outReq := req.Clone(context.Background())
	outReq.RequestURI = ""
	outReq.Header.Del("Proxy-Authorization")
	outReq.Header.Set("Connection", "close")
	if err := outReq.Write(dst); err != nil {
		return false
	}
	_ = relayHalf(c, dst)
	return false
}

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
	before, after, ok := bytes.Cut(dec, []byte{':'})
	if !ok {
		return "", "", false
	}
	return string(before), string(after), true
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
