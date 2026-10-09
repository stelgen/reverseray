// Одноразовая диагностика прода (не коммитится): телефонная роль против
// боевого сервера — TLS+SPKI-pin, HELLO→HELLO_OK→AUTH→READY, PING/PONG,
// PROBE (если телефон подключён — проверит и egress).
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
	"net"
	"os"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

func main() {
	link := flag.String("link", os.Getenv("RR_PROBE_LINK"), "rrp://token@host:port/?pin=B64&name=X")
	target := flag.String("target", "1.1.1.1:443", "PROBE-цель (нужен подключённый телефон)")
	flag.Parse()

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
	fmt.Printf("target=%s pin=%s device=%s\n", hostPort, pinB64, name)

	cfg := &tls.Config{
		InsecureSkipVerify: true, // подлинность проверяет SPKI-pin ниже
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

	hb, _ := json.Marshal(&rrp.Hello{Agent: "prodprobe", Ver: "1.0", Device: name, MaxStreams: 64, Proto: rrp.FlexString("rrp1")})
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
	fmt.Printf("HELLO_OK: sid=%s nonce=%d…\n", hok.SessionID, len(hok.Nonce))

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

	// PING/PONG
	nonce := []byte("12345678")
	if err := rrp.WriteFrame(conn, rrp.TypePing, 0, 0, nonce); err != nil {
		fmt.Println("ERR: write PING:", err)
		os.Exit(1)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err = rrp.ReadFrame(conn)
	if err != nil {
		fmt.Println("ERR: read PONG:", err)
		os.Exit(1)
	}
	if f.Type == rrp.TypePong && bytes.Equal(f.Payload, nonce) {
		fmt.Println("PONG: OK")
	} else {
		fmt.Printf("WARN: got 0x%02x вместо PONG\n", f.Type)
	}

	// PROBE: валиден только при подключённом телефоне
	pb, _ := json.Marshal(map[string]any{"target": *target, "timeout_ms": 5000})
	if err := rrp.WriteFrame(conn, rrp.TypeProbe, 0, 0, pb); err != nil {
		fmt.Println("ERR: write PROBE:", err)
		os.Exit(1)
	}
	_ = conn.SetReadDeadline(time.Now().Add(12 * time.Second))
	f, err = rrp.ReadFrame(conn)
	if err != nil {
		fmt.Println("PROBE: нет ответа (телефон не подключён к серверу — ожидаемо, APK пока не может зайти из-за пина)")
		os.Exit(0)
	}
	if f.Type == rrp.TypeProbe { // S→C отвечает тем же типом 0x23
		var pr struct {
			Ok  bool   `json:"ok"`
			Err string `json:"err"`
		}
		_ = json.Unmarshal(f.Payload, &pr)
		if pr.Ok {
			fmt.Printf("PROBE: OK — egress до %s подтверждён (телефон подключён!)\n", *target)
		} else {
			fmt.Printf("PROBE: ok=false err=%q (телефон не в сети?)\n", pr.Err)
		}
	} else {
		fmt.Printf("PROBE: неожиданный кадр 0x%02x\n", f.Type)
	}
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
