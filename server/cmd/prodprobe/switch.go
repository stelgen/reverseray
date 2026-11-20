// v1.8.10: зона «бесшовная смена» вынесена из main.go — цепочка свитчей
// (0x2C) с реальными DATA-пробами после каждого конверта. Тот же пакет main.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/stelgen/reverseray/server/internal/mtproto"
	"github.com/stelgen/reverseray/server/internal/rrp"
)

// runSwitchChain — бесшовная цепочка свитчей против боевого сервера.
func runSwitchChain(conn net.Conn, token string, sid string, targets []string, dataTarget string) error {
	c := &pbCrypto{conn: conn}
	for i, tgt := range targets {
		tgt = strings.TrimSpace(tgt)
		if tgt == "" {
			continue
		}
		nonce := fmt.Sprintf("prodprobe-%d", i+1)
		req, _ := json.Marshal(map[string]string{"proto": tgt, "nonce": nonce})
		if err := c.writeFrame(rrp.TypeProtoSwitch, 0, req); err != nil {
			return fmt.Errorf("switch→%s: write: %w", tgt, err)
		}
		f, err := c.readFrame()
		if err != nil {
			return fmt.Errorf("switch→%s: ack read: %w", tgt, err)
		}
		if f.Type != rrp.TypeProtoSwitch {
			return fmt.Errorf("switch→%s: ждали 0x2C ack, получили 0x%02x", tgt, f.Type)
		}
		var ack struct {
			OK     bool   `json:"ok"`
			Nonce  string `json:"nonce"`
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(f.Payload, &ack)
		if !ack.OK {
			if tgt == rrp.DefaultProtocolID {
				fmt.Printf("SWITCH→%s: отказ сервера (ОЖИДАЕМО, rrp1 бесшовно недостижим): %s\n", tgt, ack.Reason)
				continue
			}
			return fmt.Errorf("switch→%s: отказ: %s", tgt, ack.Reason)
		}
		// Обмен ключами целевого протокола (KEY_REQ → INIT/RESP).
		kf, err := c.readFrame()
		if err != nil {
			return fmt.Errorf("switch→%s: KEY_REQ read: %w", tgt, err)
		}
		if kf.Type != rrp.TypeKeyReq {
			return fmt.Errorf("switch→%s: ждали KEY_REQ, получили 0x%02x", tgt, kf.Type)
		}
		var kind struct {
			Kind string `json:"kind"`
		}
		_ = json.Unmarshal(kf.Payload, &kind)
		switch kind.Kind {
		case "wireguard":
			tr, err := pbWgClient(conn, kf.Payload, token)
			if err != nil {
				return fmt.Errorf("switch→%s: wg: %w", tgt, err)
			}
			c.wrap, c.seal, c.open = nil, tr.Seal, tr.Open
			fmt.Printf("SWITCH→%s: KEY_REQ→WG_INIT→WG_RESP OK (Noise_IKpsk2)\n", tgt)
		case "bittorrent":
			tr, err := pbBtClient(conn, kf.Payload, token)
			if err != nil {
				return fmt.Errorf("switch→%s: bt: %w", tgt, err)
			}
			c.wrap, c.seal, c.open = nil, tr.Seal, tr.Open
			fmt.Printf("SWITCH→%s: KEY_REQ→BT_INIT→BT_RESP OK (MSE/PE)\n", tgt)
		default: // mtproto2: KEY_REQ без kind (p,g,g_a)
			w, err := mtproto.ClientExchange(conn, kf, sid)
			if err != nil {
				return fmt.Errorf("switch→%s: mtproto2: %w", tgt, err)
			}
			c.wrap, c.seal, c.open = w, nil, nil
			fmt.Printf("SWITCH→%s: KEY_REQ→KEY_RESP OK (DH→IGE)\n", tgt)
		}
		// Сессия жива после коммита: PING/PONG (контроль — насквозь).
		pingNonce := []byte("swpong" + nonce)
		if err := c.writeFrame(rrp.TypePing, 0, pingNonce); err != nil {
			return fmt.Errorf("switch→%s: ping: %w", tgt, err)
		}
		pf, err := c.readFrame()
		if err != nil {
			return fmt.Errorf("switch→%s: pong read: %w", tgt, err)
		}
		if pf.Type != rrp.TypePong || !bytes.HasPrefix(pf.Payload, pingNonce) && !bytes.Equal(pf.Payload, pingNonce[:8]) {
			return fmt.Errorf("switch→%s: PONG нет/битый: type=0x%02x", tgt, pf.Type)
		}
		// Данные реально идут в НОВОМ конверте: OPEN → DATA → DATA-ответ.
		if err := pbDataProbe(c, dataTarget); err != nil {
			return fmt.Errorf("switch→%s: DATA-проба: %w", tgt, err)
		}
		fmt.Printf("SWITCH→%s: сессия жива, DATA-проба до %s через новый конверт OK\n", tgt, dataTarget)
	}
	return nil
}
