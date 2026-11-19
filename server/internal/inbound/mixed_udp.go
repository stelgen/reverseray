// mixed_udp.go — зона «SOCKS5 UDP ASSOCIATE» (v0.7) — pure move из mixed.go (v1.8.3, дробление по зонам; поведение не меняется).
package inbound

import (
	"bufio"
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

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
