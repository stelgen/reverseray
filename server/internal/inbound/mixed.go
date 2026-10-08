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
	"sync"
	"sync/atomic"
	"time"

	"github.com/stelgen/reverseray/server/internal/hub"
	"github.com/stelgen/reverseray/server/internal/rrp"
)

// Dialer abstracts the tunnel hub (implemented by *hub.Hub).
type Dialer interface {
	Dial(ctx context.Context, atyp byte, addr []byte, port uint16, timeout time.Duration) (net.Conn, error)
	// DialUDP открывает UDP-ассоциацию на пуле телефонов (v0.7).
	DialUDP(ctx context.Context, timeout time.Duration) (*rrp.UdpChannel, error)
}

// UdpPacket — алиас пакета туннеля (source: телефон, target: клиент SOCKS).
type UdpPacket = rrp.UdpPacket

// socks request cmd codes (RFC 1928).
const (
	socksCmdConnect = 0x01
	socksCmdUdpAsoc = 0x03
)

// Inbound is a mixed-protocol proxy listener.
type Inbound struct {
	Dialer    Dialer
	Username  string // optional; both empty = no auth
	Password  string
	Allowlist []*net.IPNet
	Logf      func(format string, args ...any)

	DialTimeout time.Duration

	// UDPBindPort — порт UDP-сокета для SOCKS5 UDP ASSOCIATE (RFC 1928).
	// Один общий сокет на listener (клиент шлёт дейтаграммы на BND.PORT).
	// 0 → порт берётся из listen-адреса mixed (1080).
	UDPBindPort int

	udpMu        sync.Mutex
	udpSock      *net.UDPConn
	udpByIP      map[string][]*udpAssoc
	udpByClient  map[string]*udpAssoc
	UdpDatagrams atomic.Uint64
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
	switch head[1] {
	case socksCmdUdpAsoc:
		in.socks5UdpAssociate(c, br, head[3])
		return
	case socksCmdConnect:
	default: // BIND и прочее не поддерживаем
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

// ---- SOCKS5 UDP ASSOCIATE (v0.7) ----
//
// Один общий UDP-сокет на listener (BND.PORT фиксирован → публикуется
// в compose как 1080/udp). Демультиплексирование ассоциаций: по точному
// «ip:port» клиента после пиннинга первым дейтаграммом; до пиннинга —
// по IP (если с этого IP ровно одна активная ассоциация).

type udpAssoc struct {
	ip        string
	dst       atomic.Pointer[net.UDPAddr] // пинится первым дейтаграммом клиента
	relay     *rrp.UdpChannel
	closed    chan struct{}
	closeOnce sync.Once
}

func (a *udpAssoc) isClosed() bool {
	select {
	case <-a.closed:
		return true
	default:
		return false
	}
}

func (in *Inbound) socks5UdpAssociate(c net.Conn, br *bufio.Reader, atyp byte) {
	// DST.ADDR/DST.PORT в запросе — информационные (обычно 0.0.0.0:0), читаем и игнорируем.
	if _, _, _, err := readSocksTarget(br, atyp); err != nil {
		c.Write([]byte{5, 0x01, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	port := in.udpBindPort()
	relay, err := in.Dialer.DialUDP(context.Background(), in.DialTimeout)
	if err != nil {
		c.Write([]byte{5, 0x01, 0, 1, 0, 0, 0, 0, 0, 0}) // general failure
		return
	}
	ip, _, splitErr := net.SplitHostPort(c.RemoteAddr().String())
	if splitErr != nil {
		ip = c.RemoteAddr().String()
	}
	a := &udpAssoc{ip: ip, relay: relay, closed: make(chan struct{})}
	if !in.udpRegister(a) {
		relay.Close()
		c.Write([]byte{5, 0x01, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer c.Close()
	defer func() {
		in.udpUnregister(a)
		relay.Close()
	}()

	// Ответ: BND.ADDR 0.0.0.0 (клиент шлёт на адрес самого прокси), BND.PORT.
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, byte(port >> 8), byte(port)}); err != nil {
		return
	}

	// Телефон → клиент.
	fwdDone := make(chan struct{})
	go func() {
		defer close(fwdDone)
		for pkt := range relay.Recv() {
			dst := a.dst.Load()
			if dst == nil {
				continue
			}
			// Ответ клиенту — формат SOCKS5 UDP: [RSV 2][FRAG 0][atyp][addr][port][data]
			payload := append([]byte{0, 0, 0}, rrp.EncodeUdpData(pkt.Atyp, pkt.Addr, pkt.Port, pkt.Data)...)
			in.udpWithSock(func(sock *net.UDPConn) {
				if sock != nil {
					_, _ = sock.WriteToUDP(payload, dst)
				}
			})
		}
	}()

	// Ассоциация живёт, пока открыто TCP-управляющее соединение (RFC 1928).
	buf := make([]byte, 512)
	for {
		if _, err := c.Read(buf); err != nil {
			break
		}
	}
}

func (in *Inbound) udpBindPort() int {
	if in.UDPBindPort > 0 {
		return in.UDPBindPort
	}
	return 1080
}

// udpRegister добавляет ассоциацию и лениво поднимает общий UDP-сокет.
func (in *Inbound) udpRegister(a *udpAssoc) bool {
	in.udpMu.Lock()
	defer in.udpMu.Unlock()
	if in.udpSock == nil {
		sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: in.udpBindPort()})
		if err != nil {
			return false
		}
		in.udpSock = sock
		in.udpByIP = make(map[string][]*udpAssoc)
		in.udpByClient = make(map[string]*udpAssoc)
		go in.udpReadLoop(sock)
	}
	in.udpByIP[a.ip] = append(in.udpByIP[a.ip], a)
	return true
}

func (in *Inbound) udpUnregister(a *udpAssoc) {
	in.udpMu.Lock()
	defer in.udpMu.Unlock()
	if list, ok := in.udpByIP[a.ip]; ok {
		out := list[:0]
		for _, x := range list {
			if x != a {
				out = append(out, x)
			}
		}
		in.udpByIP[a.ip] = out
		if len(in.udpByIP[a.ip]) == 0 {
			delete(in.udpByIP, a.ip)
		}
	}
	for k, v := range in.udpByClient {
		if v == a {
			delete(in.udpByClient, k)
		}
	}
	a.closeOnce.Do(func() { close(a.closed) })
}

func (in *Inbound) udpWithSock(fn func(*net.UDPConn)) {
	in.udpMu.Lock()
	sock := in.udpSock
	in.udpMu.Unlock()
	fn(sock)
}

func (in *Inbound) udpReadLoop(sock *net.UDPConn) {
	defer sock.Close()
	buf := make([]byte, 65535)
	for {
		n, src, err := sock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 4 || buf[2] != 0 {
			continue // [RSV][RSV][FRAG]: фрагментация не поддерживается
		}
		atyp, addr, port, data, derr := rrp.DecodeUdpData(buf[3:n])
		if derr != nil {
			continue
		}
		in.udpMu.Lock()
		assoc := in.udpRouteLocked(src)
		in.udpMu.Unlock()
		if assoc == nil {
			continue
		}
		if serr := assoc.relay.Send(atyp, addr, port, data); serr == nil {
			in.UdpDatagrams.Add(1)
		}
	}
}

// udpRouteLocked выбирает ассоциацию для дейтаграммы: точный пин «ip:port»,
// иначе — пин первой (единственной) активной ассоциации с этого IP.
// Вызывать под udpMu.
func (in *Inbound) udpRouteLocked(src *net.UDPAddr) *udpAssoc {
	if a, ok := in.udpByClient[src.String()]; ok && !a.isClosed() {
		return a
	}
	var candidates []*udpAssoc
	for _, a := range in.udpByIP[src.IP.String()] {
		if !a.isClosed() {
			candidates = append(candidates, a)
		}
	}
	if len(candidates) != 1 {
		return nil // 0 или >1 ассоциаций с IP — неоднозначно, дропаем
	}
	a := candidates[0]
	a.dst.Store(src)
	in.udpByClient[src.String()] = a
	return a
}
