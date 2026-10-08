// Command reverseray is the server side of ReverseRay: a SOCKS5/HTTP proxy
// whose egress is a phone connected via the RRP/1 reverse tunnel.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stelgen/reverseray/server/internal/config"
	"github.com/stelgen/reverseray/server/internal/serverapp"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "healthcheck":
		err = cmdHealthcheck(os.Args[2:])
	case "enroll":
		err = cmdEnroll(os.Args[2:])
	case "reset-state":
		err = cmdResetState(os.Args[2:])
	case "version", "--version":
		fmt.Println("reverseray", version)
	case "help", "--help", "-h":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `reverseray — reverse-proxy server (phone = egress node)

Usage:
  reverseray run [-config CONFIG.json]
  reverseray enroll [-state-dir DIR] -name DEVICE -host HOST [-port 443]
  reverseray healthcheck [-url http://127.0.0.1:9090/healthz]
  reverseray version
`)
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config.json")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	app, err := serverapp.New(cfg, log)
	if err != nil {
		return err
	}
	return app.Run(context.Background())
}

func cmdHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:9090/healthz", "admin healthz URL")
	_ = fs.Parse(args)
	return healthzHTTP(*url)
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "server state dir (default from config or /var/lib/reverseray)")
	name := fs.String("name", "", "device name")
	host := fs.String("host", "", "public host or IP (auto-detected if omitted)")
	port := fs.String("port", "4433", "tunnel port (or comma list)")
	_ = fs.Parse(args)
	if *name == "" {
		return fmt.Errorf("enroll: -name is required")
	}
	if *stateDir == "" {
		*stateDir = os.Getenv("RR_STATE_DIR")
	}
	if *stateDir == "" {
		*stateDir = "/var/lib/reverseray"
	}

	// Порядок: -host вручную -> RR_PUBLIC_HOST (домен/DDNS) -> автоопределение IP.
	if *host == "" {
		if env := os.Getenv("RR_PUBLIC_HOST"); env != "" {
			*host = env
		} else if ip, err := detectExternalIP(); err != nil {
			return fmt.Errorf("enroll: не удалось определить внешний IP (%v); задай -host вручную", err)
		} else {
			*host = ip
		}
	}

	// Генерация токена.
	raw := make([]byte, 32)
	if _, err := cryptoRead(raw); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	hashB64 := base64.RawURLEncoding.EncodeToString(sum[:])

	// Токен пишется в tokens.json автоматически. Если запись невозможна
	// (права/RO-файловая система) — НЕ фейлим: печатаем токен и инструкцию.
	writeErr := upsertToken(*stateDir, *name, hashB64)

	pin := ""
	pinPath := filepath.Join(*stateDir, "ca.pem")
	if b, err := os.ReadFile(pinPath); err == nil {
		pin = caPinFromPEM(b)
	}

	if writeErr != nil {
		fmt.Printf("# НЕ удалось записать %s (%v).\n", filepath.Join(*stateDir, "tokens.json"), writeErr)
		fmt.Printf("# Добавь запись в \"devices\" вручную и перечитай токены (SIGHUP):\n")
		inst, _ := json.MarshalIndent(map[string]string{"device": *name, "sha256_b64url": hashB64}, "", "  ")
		fmt.Printf("%s\n\n", inst)
	} else {
		fmt.Printf("Устройство %q добавлено. Сервер подхватит токен автоматически (до 3 с).\n\n", *name)
	}
	fmt.Printf("Конфигурационная строка для приложения:\n\n")
	fmt.Printf("rrp://%s@%s:%s/?pin=%s&name=%s\n\n", token, *host, *port, pin, *name)
	fmt.Printf("Outbound для Xray (вставь в outbounds; для клиентов в ЛОКАЛЬНОЙ сети\n")
	fmt.Printf("подставь LAN-IP хоста вместо %s):\n\n", *host)
	fmt.Printf("{\n  \"tag\": \"reverseray-out\",\n  \"protocol\": \"socks\",\n  \"settings\": { \"servers\": [ { \"address\": \"%s\", \"port\": 1080 } ] }\n}\n\n", *host)
	return nil
}

// detectExternalIP определяет публичный IPv4 через публичные echo-сервисы.
// Используется только командой enroll (админ-действие): в штатной работе
// сервер исходящих соединений не выполняет.
func detectExternalIP() (string, error) {
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://ipecho.net/plain",
	}
	client := &http.Client{Timeout: 4 * time.Second}
	var lastErr error
	for _, svc := range services {
		resp, err := client.Get(svc)
		if err != nil {
			lastErr = err
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		ip := strings.TrimSpace(string(b))
		if net.ParseIP(ip) != nil && ip != "" {
			return ip, nil
		}
		lastErr = fmt.Errorf("%s вернул не IP: %q", svc, ip)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("нет доступных сервисов")
	}
	return "", lastErr
}

// upsertToken добавляет/обновляет устройство в stateDir/tokens.json,
// создавая файл и каталог при необходимости (enroll без ручных шагов).
func upsertToken(stateDir, device, hashB64 string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(stateDir, "tokens.json")
	doc := struct {
		Devices map[string]string `json:"devices"`
	}{Devices: map[string]string{}}
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		if err := json.Unmarshal(b, &doc); err != nil {
			return fmt.Errorf("%s: %v", path, err)
		}
	}
	if doc.Devices == nil {
		doc.Devices = map[string]string{}
	}
	doc.Devices[device] = hashB64
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o600)
}

// cmdResetState очищает состояние устройства (токены), оставляя сервер
// в состоянии «чистый лист» — применяется при повторном деплое новой версии.
// CA-ключ сохраняется по умолчанию (флаг -keep-ca не нужен: ca.pem не трогаем),
// флаг -all удаляет и CA (тогда pin у клиентов изменится).
func cmdResetState(args []string) error {
	fs := flag.NewFlagSet("reset-state", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "server state dir (default from config or /var/lib/reverseray)")
	all := fs.Bool("all", false, "also remove CA (ca.pem) — clients will need re-enrollment")
	_ = fs.Parse(args)
	if *stateDir == "" {
		*stateDir = os.Getenv("RR_STATE_DIR")
	}
	if *stateDir == "" {
		*stateDir = "/var/lib/reverseray"
	}

	removed := 0
	targets := []string{
		filepath.Join(*stateDir, "tokens.json"),
		filepath.Join(*stateDir, "sessions.json"),
	}
	if *all {
		targets = append(targets,
			filepath.Join(*stateDir, "ca.pem"),
			filepath.Join(*stateDir, "ca.key"),
			filepath.Join(*stateDir, "leaf.pem"),
			filepath.Join(*stateDir, "leaf.key"),
		)
	}
	for _, p := range targets {
		if err := os.Remove(p); err == nil {
			removed++
			fmt.Println("removed:", p)
		}
	}
	if removed == 0 {
		fmt.Println("state already clean:", *stateDir)
		return nil
	}
	fmt.Printf("state reset (%d files removed). Запусти enroll заново для каждого устройства.\n", removed)
	return nil
}
