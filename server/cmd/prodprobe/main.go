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

	"github.com/stelgen/reverseray/server/internal/mtproto"
	"github.com/stelgen/reverseray/server/internal/rrp"
)

func main() {
	link := flag.String("link", os.Getenv("RR_PROBE_LINK"), "rrp://token@host:port/?pin=B64&name=X")
	target := flag.String("target", "1.1.1.1:443", "PROBE-цель (нужен подключённый телефон)")
	proto := flag.String("proto", "", "согласовать протокол сессии: пусто/rrp1 | mtproto2 (DH-апгрейд после READY)")
	streams := flag.Int("streams", 1, "параллельных PROBE-запросов (многоканальность)")
	flag.Parse()
	if *streams < 1 {
		*streams = 1
	}
	if *streams > 32 {
		*streams = 32
	}

	useMtp := *proto == "mtproto2"
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
			if useMtp {
				return "mtproto2"
			}
			return "rrp1"
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
