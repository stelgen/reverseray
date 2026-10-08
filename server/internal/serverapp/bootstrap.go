package serverapp

import (
	"context"
	"crypto/rand"
	"log/slog"

	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/stelgen/reverseray/server/internal/config"
	"time"
)

// DetectExternalIP определяет публичный IPv4 через публичные echo-сервисы.
// Используется в админ-операциях (enroll, стартовая подсказка): в штатной
// работе сервер исходящих соединений не выполняет.
func DetectExternalIP(timeout time.Duration) (string, error) {
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://ipecho.net/plain",
	}
	client := &http.Client{Timeout: timeout}
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
		ip := trimSpace(string(b))
		if net.ParseIP(ip) != nil && ip != "" {
			return ip, nil
		}
		lastErr = fmt.Errorf("%s: not an IP (%q)", svc, ip)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no reachable service")
	}
	return "", lastErr
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\r' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// ensureDefaultDevice: если tokens.json отсутствует — сервер сам создаёт
// первое устройство "phone-1" со сгенерированным токеном. Деплой сводится
// к `docker compose up -d`: никакие файлы вручную создавать не нужно.
func ensureDefaultDevice(cfg *config.Config, log *slog.Logger) {
	if _, err := os.Stat(cfg.TokensFile); err == nil {
		return // файл есть — ничего не трогаем
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		log.Warn("bootstrap: cannot generate token", "err", err)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	hashB64 := base64.RawURLEncoding.EncodeToString(sum[:])

	doc := struct {
		Devices map[string]string `json:"devices"`
	}{Devices: map[string]string{"phone-1": hashB64}}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		log.Warn("bootstrap: marshal", "err", err)
		return
	}
	if err := os.WriteFile(cfg.TokensFile, append(out, '\n'), 0o600); err != nil {
		log.Warn("bootstrap: write tokens", "err", err)
		return
	}
	log.Info("bootstrap: created default device", "device", "phone-1")
	log.Info("bootstrap: created default device", "device", "phone-1")
}

// logConnectInfo: асинхронно (не блокируя старт) определяет публичный IP и
// печатает в лог готовую конфигурационную строку для приложения.
func (a *App) logConnectInfo(ctx context.Context) {
	// Приоритет: RR_PUBLIC_HOST (домен/DDNS) -> автоопределённый внешний IP.
	host := a.cfg.PublicHost
	if host == "" {
		ip, err := DetectExternalIP(5 * time.Second)
		if err != nil {
			a.log.Info("connect info: внешний IP не определён автоматически — используйте enroll -host HOST",
				"ca_pin", a.bundle.CAPin, "err", err.Error())
			return
		}
		host = ip
	}
	// Первый токен из хранилища (bootstrap создаёт phone-1; enroll добавляет свои).
	if a.cfg.TokensFile == "" {
		return
	}
	a.log.Info("connect info",
		"ca_pin", a.bundle.CAPin,
		"host", host,
		"tunnel_port", "4433",
		"next_step", "docker compose exec reverseray /reverseray enroll -state-dir /var/lib/reverseray -name DEVICE  ->  печатает полную rrp:// строку для приложения",
	)
	_ = ctx
}
