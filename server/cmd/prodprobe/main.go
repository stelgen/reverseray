// Одноразовая диагностика прода (не коммитится): телефонная роль против
// боевого сервера — TLS+SPKI-pin, HELLO→HELLO_OK→AUTH→READY, PING/PONG,
// PROBE (если телефон подключён — проверит и egress).
//
// v0.9.3: полноценный пр checker всех протоколов:
//
//	-proto mtproto2 — DH-апгрейд после READY (KEY_REQ→KEY_RESP, IGE-конверт),
//	  той же функцией, что и настоящий APK (mtproto.UpgradeClient);
//	-streams N — N параллельных PROBE в одну сессию (многоканальность).
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/stelgen/reverseray/server/internal/bt"
	"github.com/stelgen/reverseray/server/internal/mtproto"
	"github.com/stelgen/reverseray/server/internal/rrp"
	"github.com/stelgen/reverseray/server/internal/wg"
)

func main() {
	link := flag.String("link", os.Getenv("RR_PROBE_LINK"), "rrp://token@host:port/?pin=B64&name=X")
	target := flag.String("target", "1.1.1.1:443", "PROBE-цель (нужен подключённый телефон)")
	proto := flag.String("proto", "", "согласовать протокол сессии: пусто/rrp1 | mtproto2 | wireguard (апгрейд после READY)")
	streams := flag.Int("streams", 1, "параллельных PROBE-запросов (многоканальность)")
	holdSecs := flag.Int("hold", 0, "держать сессию N секунд после проверки (отладка mixed/egress)")
	switchList := flag.String("switch", "", "бесшовная цепочка свитчей 0x2C после согласования: mtproto2,wireguard,bittorrent[,rrp1] — прод-проба ротации")
	flag.Parse()
	if *streams < 1 {
		*streams = 1
	}
	if *streams > 32 {
		*streams = 32
	}

	useMtp := *proto == "mtproto2"
	useWg := *proto == wg.ProtoID
	var token, hostPort, pinB64, name string
	{
		rest := *link
		if i := bytes.Index([]byte(rest), []byte("rrp://")); i >= 0 {
			rest = rest[i+len("rrp://"):]
		}
		// token@host:port/?pin=..&name=..
		var hostPart, query string
		for i := 0; i < len(rest); i++ {
			if rest[i] == '/' {
				hostPart, query = rest[:i], rest[i+1:]
				break
			}
		}
		if hostPart == "" {
			hostPart = rest
		}
		var cred string
		for i := 0; i < len(hostPart); i++ {
			if hostPart[i] == '@' {
				cred, hostPort = hostPart[:i], hostPart[i+1:]
			}
		}
		if q := query; q != "" {
			q = q[1:] // ?pin=..&name=.. -> pin=..&name=..  (query начинается с '?')
			for _, pair := range splitAmp(q) {
				if len(pair) > 4 && pair[:4] == "pin=" {
					pinB64 = pair[4:]
				}
				if len(pair) > 5 && pair[:5] == "name=" {
					name = pair[5:]
				}
			}
		}
		token = cred
	}
	if token == "" || hostPort == "" || pinB64 == "" {
		fmt.Println("ERR: link parse: token/host/pin пусты")
		os.Exit(2)
	}
	if name == "" {
		name = "prodprobe"
	}
	fmt.Printf("target=%s pin=%s device=%s proto=%s streams=%d\n",
		hostPort, pinB64, name, func() string {
			switch {
			case useMtp:
				return "mtproto2"
			case useWg:
				return wg.ProtoID
			default:
				return "rrp1"
			}
		}(), *streams)

	cfg := &tls.Config{
		InsecureSkipVerify: true, // #nosec G402: подлинность проверяет SPKI-pin ниже (prodprobe — диагностический инструмент)
		NextProtos:         []string{"reverseray/1"},
		ServerName:         "reverseray.test",
	}
	want, err := base64.RawURLEncoding.DecodeString(pinB64)
	if err != nil || len(want) != sha256.Size {
		fmt.Println("ERR: bad pin base64:", err)
		os.Exit(2)
	}
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) < 2 {
			return errors.New("expected leaf+CA chain")
		}
		for i, rc := range rawCerts {
			c, err := x509.ParseCertificate(rc)
			if err != nil {
				fmt.Printf("chain[%d]: parse err %v\n", i, err)
				continue
			}
			sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
			fmt.Printf("chain[%d]: subj=%q spki_sha256_std=%s\n", i, c.Subject.CommonName, base64.StdEncoding.EncodeToString(sum[:]))
		}
		leaf, e1 := x509.ParseCertificate(rawCerts[0])
		ca, e2 := x509.ParseCertificate(rawCerts[len(rawCerts)-1])
		if e1 != nil || e2 != nil {
			return errors.New("bad chain parse")
		}
		if err := leaf.CheckSignatureFrom(ca); err != nil {
			return errors.New("leaf not signed by presented CA")
		}
		sum := sha256.Sum256(ca.RawSubjectPublicKeyInfo)
		if !bytes.Equal(sum[:], want) {
			got := base64.RawURLEncoding.EncodeToString(sum[:])
			return fmt.Errorf("CA pin mismatch: real pin=%s", got)
		}
		return nil
	}

	raw, err := net.Dial("tcp", hostPort)
	if err != nil {
		fmt.Println("ERR: tcp dial:", err)
		os.Exit(1)
	}
	defer raw.Close()
	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		fmt.Println("ERR: tls handshake:", err)
		os.Exit(1)
	}
	fmt.Println("TLS: OK (pin совпал), ALPN:", conn.ConnectionState().NegotiatedProtocol)

	hb, _ := json.Marshal(&rrp.Hello{Agent: "prodprobe", Ver: "1.0", Device: name, MaxStreams: 64, Proto: rrp.FlexString(*proto)})
	if err := rrp.WriteFrame(conn, rrp.TypeHello, 0, 0, hb); err != nil {
		fmt.Println("ERR: write HELLO:", err)
		os.Exit(1)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	f, err := rrp.ReadFrame(conn)
	if err != nil {
		fmt.Println("ERR: read HELLO_OK:", err)
		os.Exit(1)
	}
	if f.Type != rrp.TypeHelloOK {
		fmt.Printf("ERR: expected HELLO_OK, got 0x%02x %q\n", f.Type, f.Payload)
		os.Exit(1)
	}
	var hok rrp.HelloOK
	if err := json.Unmarshal(f.Payload, &hok); err != nil {
		fmt.Println("ERR: HELLO_OK json:", err)
		os.Exit(1)
	}
	fmt.Printf("HELLO_OK: sid=%s nonce=%d… proto=%s реестр=%v\n", hok.SessionID, len(hok.Nonce), hok.Proto, hok.Protocols)

	code := rrp.AuthCode(token, hok.Nonce, hok.SessionID)
	ab, _ := json.Marshal(&rrp.Auth{Mode: "token-hmac", HMAC: code})
	if err := rrp.WriteFrame(conn, rrp.TypeAuth, 0, 0, ab); err != nil {
		fmt.Println("ERR: write AUTH:", err)
		os.Exit(1)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	f, err = rrp.ReadFrame(conn)
	if err != nil {
		fmt.Println("ERR: read READY:", err)
		os.Exit(1)
	}
	if f.Type != rrp.TypeReady {
		_, msg := rrp.DecodeError(f.Payload)
		fmt.Printf("ERR: handshake rejected: %s\n", msg)
		os.Exit(1)
	}
	fmt.Println("READY: OK — туннель и AUTH валидны (сервер жив)")

	// v0.9.3: mtproto2 — сервер пришлёт KEY_REQ после READY; выполняем
	// DH-апгрейд той же функцией, что и настоящий APK (mtproto.UpgradeClient):
	// валидируем доли, отвечаем KEY_RESP, поднимаем IGE-конверт.
	probeConn := io.ReadWriteCloser(conn)
	if useMtp {
		wrap, err := mtproto.UpgradeClient(conn, hok.SessionID, nil)
		if err != nil {
			fmt.Println("ERR: mtproto2 DH-апгрейд:", err)
			os.Exit(1)
		}
		fmt.Println("mtproto2: KEY_REQ→KEY_RESP OK — DH-канон принят сервером, IGE-конверт поднят")
		probeConn = wrap
	}
	// v0.9.6: wireguard — WG-хендшейк тем же зеркалом, что и APK (Wg.kt):
	// KEY_REQ(kind=wireguard) → WG_INIT(msg1) → WG_RESP(msg2) → ключи
	// транспортных конвертов. Данные WG-конвертом идут только DATA/UDP_DATA,
	// PING/PROBE — служебные кадры вне конверта у обеих сторон.
	if useWg {
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		f, err = rrp.ReadFrame(conn)
		if err != nil {
			fmt.Println("ERR: read KEY_REQ:", err)
			os.Exit(1)
		}
		if f.Type != rrp.TypeKeyReq {
			fmt.Printf("ERR: ждали KEY_REQ, получили 0x%02x %q\n", f.Type, f.Payload)
			os.Exit(1)
		}
		var req struct {
			Kind string `json:"kind"`
			SPub string `json:"spub"`
		}
		if err := json.Unmarshal(f.Payload, &req); err != nil {
			fmt.Println("ERR: KEY_REQ json:", err)
			os.Exit(1)
		}
		if req.Kind != wg.ProtoID {
			fmt.Printf("ERR: KEY_REQ kind=%q ≠ wireguard\n", req.Kind)
			os.Exit(1)
		}
		spub, err := base64.RawURLEncoding.DecodeString(req.SPub)
		if err != nil || len(spub) != wg.KeySize {
			fmt.Printf("ERR: spub bad: %v len=%d\n", err, len(spub))
			os.Exit(1)
		}
		var serverPub, psk [wg.KeySize]byte
		copy(serverPub[:], spub)
		psk = wg.TokenPSK(token)
		msg1, ch, err := wg.NewClientHandshake(&serverPub, &psk)
		if err != nil {
			fmt.Println("ERR: WG msg1:", err)
			os.Exit(1)
		}
		if err := rrp.WriteFrame(conn, rrp.TypeWgInit, 0, 0, msg1); err != nil {
			fmt.Println("ERR: write WG_INIT:", err)
			os.Exit(1)
		}
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		f, err = rrp.ReadFrame(conn)
		if err != nil {
			fmt.Println("ERR: read WG_RESP:", err)
			os.Exit(1)
		}
		if f.Type != rrp.TypeWgResp {
			fmt.Printf("ERR: ждали WG_RESP, получили 0x%02x %q\n", f.Type, f.Payload)
			os.Exit(1)
		}
		if err := ch.ConsumeResponse(f.Payload, &psk); err != nil {
			fmt.Println("ERR: WG msg2:", err)
			os.Exit(1)
		}
		fmt.Println("wireguard: KEY_REQ→WG_INIT→WG_RESP OK — Noise_IKpsk2 принят сервером, WG-конверты активны")
	}

	// PING/PONG (служебный кадр — вне MTProto-конверта у обеих сторон)
	nonce := []byte("12345678")
	if err := rrp.WriteFrame(probeConn, rrp.TypePing, 0, 0, nonce); err != nil {
		fmt.Println("ERR: write PING:", err)
		os.Exit(1)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err = rrp.ReadFrame(probeConn)
	if err != nil {
		fmt.Println("ERR: read PONG:", err)
		os.Exit(1)
	}
	if f.Type == rrp.TypePong && bytes.Equal(f.Payload, nonce) {
		fmt.Println("PONG: OK")
	} else {
		fmt.Printf("WARN: got 0x%02x вместо PONG\n", f.Type)
	}

	// v1.8.6: прод-проба бесшовной ротации — цепочка 0x2C против боевого
	// сервера: ack → обмен ключами целиком → PING + DATA-проба в новом
	// конверте (ключевой регресс «фолбэк на wireguard» ловится именно тут).
	if *switchList != "" {
		if err := runSwitchChain(conn, token, hok.SessionID, strings.Split(*switchList, ","), *target); err != nil {
			fmt.Println("ERR: switch-chain:", err)
			os.Exit(1)
		}
	}

	// PROBE: валиден только при подключённом телефоне; streams>1 — проверка
	// многоканальности (параллельные запросы в одну сессию).
	pb, _ := json.Marshal(map[string]any{"target": *target, "timeout_ms": 5000})
	type probeRes struct {
		ok  bool
		err string
		ms  int64
	}
	resCh := make(chan probeRes, *streams)
	t0 := time.Now()
	for i := 0; i < *streams; i++ {
		go func() {
			r := probeRes{}
			s := time.Now()
			defer func() {
				r.ms = time.Since(s).Milliseconds()
				resCh <- r
			}()
			if err := rrp.WriteFrame(probeConn, rrp.TypeProbe, 0, 0, pb); err != nil {
				r.err = "write: " + err.Error()
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
			f, err := rrp.ReadFrame(probeConn)
			if err != nil {
				r.err = "read: " + err.Error()
				return
			}
			if f.Type != rrp.TypeProbe {
				r.err = fmt.Sprintf("unexpected frame 0x%02x", f.Type)
				return
			}
			var pr struct {
				Ok  bool   `json:"ok"`
				Err string `json:"err"`
			}
			_ = json.Unmarshal(f.Payload, &pr)
			r.ok, r.err = pr.Ok, pr.Err
		}()
	}
	oks, fails := 0, 0
	sample := ""
	for i := 0; i < *streams; i++ {
		r := <-resCh
		if r.ok {
			oks++
		} else {
			fails++
			if sample == "" {
				sample = r.err
			}
		}
	}
	wall := time.Since(t0).Milliseconds()
	if *holdSecs > 0 {
		fmt.Printf("HOLD: держим сессию %dс (телефон подключён)…\n", *holdSecs)
		time.Sleep(time.Duration(*holdSecs) * time.Second)
	}
	if oks > 0 {
		fmt.Printf("PROBE: OK %d/%d — egress до %s подтверждён (телефон подключён!), wall=%dms\n",
			oks, *streams, *target, wall)
		os.Exit(0)
	}
	// Ни одного успеха: телефон не подключён (ожидаемо без APK) — но если
	// сервер отвечал ok=false по делу, это тоже видно.
	fmt.Printf("PROBE: нет успешных (%d запросов, wall=%dms)", *streams, wall)
	if strings.TrimSpace(sample) != "" {
		fmt.Printf(", пример: %q", sample)
	}
	fmt.Println(" — телефон не подключён или egress недоступен")
	os.Exit(0)
}

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
	f, err := rrp.ReadFrame(conn)
	if err != nil {
		return nil, err
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
	f, err := rrp.ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	if f.Type != rrp.TypeBtResp {
		return nil, fmt.Errorf("ждали BT_RESP, получили 0x%02x", f.Type)
	}
	if err := ch.ConsumeResponse(f.Payload); err != nil {
		return nil, err
	}
	return ch.Transport(), nil
}

// pbDataProbe — «данные идут»: OPEN(host:port) → OPEN_OK → DATA(TLS ClientHello)
// → читаем DATA-ответ (≥1 байт; TLS alert/Handshake от 1.1.1.1:443) → CLOSE.
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
	// TLS 1.0 ClientHello (cipher 0x002f) — TLS-alert/ответ гарантирован.
	hello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x2f, // record: handshake
		0x01, 0x00, 0x00, 0x2b, // ClientHello len=43
		0x03, 0x03, // version TLS1.2
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, // random
		0x00,                   // session id len
		0x00, 0x02, 0x00, 0x2f, // cipher suites
		0x01, 0x00, // compression
	}
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

func splitAmp(s string) []string {
	var out []string
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == '&' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(s[i])
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
