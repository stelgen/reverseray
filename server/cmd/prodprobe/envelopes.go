// v1.8.10: зона «конверты» вынесена из main.go (дробление по зонам
// ответственности): pbCrypto-обёртка кадра + WG/BT-клиенты хендшейков +
// DATA-проба (зеркало E2eProbe клиента). Тот же пакет main.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/stelgen/reverseray/server/internal/bt"
	"github.com/stelgen/reverseray/server/internal/rrp"
	"github.com/stelgen/reverseray/server/internal/wg"
)

// pbCrypto — текущая клиентская крипта после свитча: MT-обёртка (wrap) либо
// WG/BT-конверт (seal/open только для payload-кадров DATA/UDP_DATA).
type pbCrypto struct {
	conn net.Conn
	wrap io.ReadWriteCloser
	seal func([]byte) ([]byte, error)
	open func([]byte) ([]byte, error)
}

func (c *pbCrypto) writeFrame(t uint8, streamID uint16, payload []byte) error {
	if c.wrap != nil {
		return rrp.WriteFrame(c.wrap, t, streamID, 0, payload)
	}
	if (t == rrp.TypeData || t == rrp.TypeUdpData) && c.seal != nil && len(payload) > 0 {
		sealed, err := c.seal(payload)
		if err != nil {
			return err
		}
		payload = sealed
	}
	return rrp.WriteFrame(c.conn, t, streamID, 0, payload)
}

func (c *pbCrypto) readFrame() (*rrp.Frame, error) {
	src := io.Reader(c.conn)
	if c.wrap != nil {
		src = c.wrap
	}
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		f, err := rrp.ReadFrame(src)
		if err != nil {
			return nil, err
		}
		// Фон: WINDOW-гранты и echo-CLOSE закрытых стримов — не ответы.
		if f.Type == rrp.TypeWindow || f.Type == rrp.TypeClose {
			continue
		}
		if c.wrap == nil && c.open != nil && (f.Type == rrp.TypeData || f.Type == rrp.TypeUdpData) && len(f.Payload) > 0 {
			plain, oerr := c.open(f.Payload)
			if oerr != nil {
				return nil, fmt.Errorf("open payload: %w", oerr)
			}
			f.Payload = plain
		}
		return f, nil
	}
}

func pbWgClient(conn net.Conn, keyReq []byte, token string) (*wg.Transport, error) {
	var kw struct {
		SPub string `json:"spub"`
	}
	if err := json.Unmarshal(keyReq, &kw); err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(kw.SPub)
	if err != nil || len(raw) != wg.KeySize {
		return nil, fmt.Errorf("bad spub: %v len=%d", err, len(raw))
	}
	var spub [wg.KeySize]byte
	copy(spub[:], raw)
	psk := wg.TokenPSK(token)
	msg1, ch, err := wg.NewClientHandshake(&spub, &psk)
	if err != nil {
		return nil, err
	}
	if err := rrp.WriteFrame(conn, rrp.TypeWgInit, 0, 0, msg1); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var f *rrp.Frame
	for {
		var err error
		f, err = rrp.ReadFrame(conn)
		if err != nil {
			return nil, err
		}
		if f.Type == rrp.TypeClose || f.Type == rrp.TypeWindow {
			continue // эхо-CLOSE/WINDOW чужих стримов — не ответ хендшейка
		}
		break
	}
	if f.Type != rrp.TypeWgResp {
		return nil, fmt.Errorf("ждали WG_RESP, получили 0x%02x", f.Type)
	}
	if err := ch.ConsumeResponse(f.Payload, &psk); err != nil {
		return nil, err
	}
	return wg.NewTransport(true, ch), nil
}

func pbBtClient(conn net.Conn, keyReq []byte, token string) (*bt.Transport, error) {
	var kb struct {
		YB string `json:"yb"`
	}
	if err := json.Unmarshal(keyReq, &kb); err != nil {
		return nil, err
	}
	yb, err := base64.RawURLEncoding.DecodeString(kb.YB)
	if err != nil || len(yb) != bt.KeySize {
		return nil, fmt.Errorf("bad yb: %v len=%d", err, len(yb))
	}
	skey := bt.TokenSKEY(token)
	pkt1, ch, err := bt.NewClientInit(skey, nil)
	if err != nil {
		return nil, err
	}
	pkt3, err := ch.BuildPacket3(yb)
	if err != nil {
		return nil, err
	}
	if err := rrp.WriteFrame(conn, rrp.TypeBtInit, 0, 0, ch.Init(pkt3, pkt1)); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	var f *rrp.Frame
	for {
		var err error
		f, err = rrp.ReadFrame(conn)
		if err != nil {
			return nil, err
		}
		if f.Type == rrp.TypeClose || f.Type == rrp.TypeWindow {
			continue // эхо-CLOSE/WINDOW чужих стримов — не ответ хендшейка
		}
		break
	}
	if f.Type != rrp.TypeBtResp {
		return nil, fmt.Errorf("ждали BT_RESP, получили 0x%02x", f.Type)
	}
	if err := ch.ConsumeResponse(f.Payload); err != nil {
		return nil, err
	}
	return ch.Transport(), nil
}

// pbDataProbe — «данные идут»: OPEN(host:port) → OPEN_OK → DATA(HTTP GET)
// → читаем DATA-ответ (≥1 байт; 204 от connectivitycheck.gstatic.com:80) → CLOSE.
// v1.8.10: проба = HTTP GET к подключ-чеку (та же цель, что E2eProbe клиента).
// Прежний TLS-ClientHello к 1.1.1.1:443 DPI дропал молча (и на egress VM,
// и в песочнице) — инструмент ложно диагностировал «мёртвый payload-путь».
func pbDataProbe(c *pbCrypto, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port := 0
	_, err = fmt.Sscanf(portStr, "%d", &port)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("bad port %q", portStr)
	}
	var atyp byte
	var addr []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			atyp, addr = rrp.ATYPIPv4, v4
		} else {
			atyp, addr = rrp.ATYPIPv6, ip
		}
	} else {
		atyp, addr = rrp.ATYPDomain, []byte(host)
	}
	if err := c.writeFrame(rrp.TypeOpen, 1, rrp.EncodeOpen(atyp, addr, uint16(port))); err != nil {
		return err
	}
	for {
		f, err := c.readFrame()
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}
		if f.Type == rrp.TypeOpenOK {
			if len(f.Payload) > 0 && f.Payload[0] != 0 {
				return fmt.Errorf("сервер отказал в dial %s: %v", target, f.Payload)
			}
			break
		}
	}
	// v1.8.10: HTTP GET к подключ-чеку — DPI-стойкая проба с гарантированным
	// ответом (204): тот же target/запрос, что у E2eProbe клиента (зеркало).
	hello := []byte("GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\nConnection: close\r\n\r\n")
	if err := c.writeFrame(rrp.TypeData, 1, hello); err != nil {
		return err
	}
	for {
		f, err := c.readFrame()
		if err != nil {
			return fmt.Errorf("data read: %w", err)
		}
		if f.Type == rrp.TypeWindow {
			continue
		}
		if f.Type != rrp.TypeData {
			return fmt.Errorf("ждали DATA-ответ, получили 0x%02x", f.Type)
		}
		if len(f.Payload) == 0 {
			return fmt.Errorf("пустой DATA-ответ")
		}
		fmt.Printf("DATA: %d байт от %s через текущий конверт\n", len(f.Payload), target)
		break
	}
	return c.writeFrame(rrp.TypeClose, 1, []byte{0})
}

