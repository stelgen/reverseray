// v1.9.0: зона SOCKS5 (RFC 1928) вынесена из mixed.go (транш-2):
// greet/auth (username-password), чтение target, маппинг ошибок.

package inbound

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/stelgen/reverseray/server/internal/hub"
)

// ---- SOCKS5 (RFC 1928) ----

func (in *Inbound) socks5(c net.Conn, br *bufio.Reader) bool {
	if err := in.socksAuth(c, br); err != nil {
		in.logf("socks auth: %v", err)
		return false
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		return false
	}
	if head[0] != 0x05 {
		return false
	}
	switch head[1] {
	case socksCmdUdpAsoc:
		in.socks5UdpAssociate(c, br, head[3])
		return false
	case socksCmdConnect:
	default: // BIND и прочее не поддерживаем
		_, _ = c.Write([]byte{5, 0x07, 0, 1, 0, 0, 0, 0, 0, 0})
		return false
	}
	atyp, addr, port, err := readSocksTarget(br, head[3])
	if err != nil {
		_, _ = c.Write([]byte{5, 0x01, 0, 1, 0, 0, 0, 0, 0, 0})
		return false
	}
	dst, err := in.dial(c, atyp, addr, port)
	if err != nil {
		_, _ = c.Write([]byte{5, socksErr(err), 0, 1, 0, 0, 0, 0, 0, 0})
		return false
	}
	// Success reply.
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	wasParked := in.relayStream(c, dst)
	dst.Close()
	return wasParked
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
			_, _ = c.Write([]byte{5, 0xFF})
			return errors.New("auth required but not offered")
		}
		_, _ = c.Write([]byte{5, 0x02})
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
			_, _ = c.Write([]byte{1, 0})
		} else {
			_, _ = c.Write([]byte{1, 1})
			return errors.New("bad credentials")
		}
		return nil
	}
	if !hasNoAuth {
		_, _ = c.Write([]byte{5, 0xFF})
		return errors.New("no acceptable auth method")
	}
	_, _ = c.Write([]byte{5, 0x00})
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

func socksErr(err error) byte {
	switch {
	case errors.Is(err, hub.ErrNoTunnel):
		return 0x01 // general failure (no device online)
	default:
		return 0x04 // host unreachable (phone dial failed)
	}
}
