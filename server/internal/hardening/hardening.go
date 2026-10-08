// Package hardening — WAN-стойкость туннельного порта (v0.8).
//
// Правила канона ReverseRay (README → «Защита при пробросе в WAN»):
//  1. Скрытие сервиса: первый байт соединения — не TLS ClientHello
//     (0x16) и не WS-путь за TLS → соединение НЕ получает НИ ОДНОГО байта
//     ответа: tarpit-задержка (время сканера съедается) и тихое закрытие.
//     Никаких HTTP-страниц, баннеров, версий, RST-диагностики.
//     nmap -sV не получает service data; ответы только для настоящих
//     TLS-клиентов.
//  2. Ноль утечек: единственное, что видит сканер — SYN-ACK от ядра и
//     молчание приложения. Всё остальное (версия, CA-pin, устройство)
//     отдаётся только после успешного TLS + HMAC.
//  3. Дроссель давильни: глобальный и per-IP лимиты параллельных
//     соединений — автоматизированный скан не выест ни память, ни fd.
//
// ICMP-пинги и SYN-сканы отвечаются ядром хоста — на этом уровне приложение
// бессильно; см. SECURITY.md («Уровень хоста»): iptables/ufw-рецепт.
package hardening

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Статистика для /metrics и /status (без IP и содержимого — приватность).
type Stats struct {
	Scans   atomic.Uint64 // соединений классифицировано как скан/мусор
	Dropped atomic.Uint64 // из них tarpit-нуты и тихо закрытые
	Limited atomic.Uint64 // отклонено лимитами параллельности
}

// Gate — точка входа для туннельного listener'а.
type Gate struct {
	Enabled    bool
	Tarpit     time.Duration // пауза перед тихим закрытием сканера
	MaxConns   int           // глобальный лимит параллельных соединений
	PerIPConns int           // per-IP лимит параллельных соединений
	Logf       func(format string, args ...any)

	st    *Stats
	cur   atomic.Int64
	perIP sync.Map // ip -> *atomic.Int64
}

func NewGate(enabled bool, tarpitSec, maxConns, perIPConns int, st *Stats) *Gate {
	// tarpitSec=0 — легальный режим «закрывать сразу» (тесты/чтобы не ломать
	// своей же задержкой легитимные пробники мониторинга).<0 → дефолт.
	if tarpitSec < 0 {
		tarpitSec = 3
	}
	if maxConns <= 0 {
		maxConns = 4096
	}
	if perIPConns <= 0 {
		perIPConns = 32
	}
	if st == nil {
		st = &Stats{}
	}
	return &Gate{
		Enabled:    enabled,
		Tarpit:     time.Duration(tarpitSec) * time.Second,
		MaxConns:   maxConns,
		PerIPConns: perIPConns,
		st:         st,
	}
}

func (g *Gate) Stats() *Stats { return g.st }

// Admit проверяет лимиты параллельности. false — соединение надо закрыть
// сразу (счётчик не занят). true — вызывающий ОБЯЗАН вызвать Release(ip).
func (g *Gate) Admit(ip string) bool {
	if !g.Enabled {
		return true
	}
	if n := g.cur.Add(1); int(n) > g.MaxConns {
		g.cur.Add(-1)
		g.st.Limited.Add(1)
		return false
	}
	c := g.loadCounter(ip)
	if n := c.Add(1); int(n) > g.PerIPConns {
		c.Add(-1)
		g.cur.Add(-1)
		g.st.Limited.Add(1)
		return false
	}
	return true
}

func (g *Gate) Release(ip string) {
	if !g.Enabled {
		return
	}
	g.cur.Add(-1)
	if c, ok := g.perIP.Load(ip); ok {
		c.(*atomic.Int64).Add(-1)
	}
}

func (g *Gate) loadCounter(ip string) *atomic.Int64 {
	if v, ok := g.perIP.Load(ip); ok {
		return v.(*atomic.Int64)
	}
	c := &atomic.Int64{}
	v, loaded := g.perIP.LoadOrStore(ip, c)
	if loaded {
		return v.(*atomic.Int64)
	}
	return c
}

// Classify читает первый байт и решает судьбу соединения:
//
//	ok=true  → TLS-клиент: возвращается conn, воспроизводящий peek-нутый байт;
//	ok=false → сканер/мусор: tarpit и тихое закрытие (НЕТ ответных байтов).
//
// TLS-запись всегда начинается с 0x16 (handshake). Любое другое начало
// (HTTP GET, PROXY-протокол, строки, нули — сигнатуры автоматизированных
// сканеров и пробников бинаря) — мусор: держим паузу и закрываем молча.
func (g *Gate) Classify(conn net.Conn) (net.Conn, bool) {
	if !g.Enabled {
		return conn, true
	}
	br := bufio.NewReaderSize(conn, 512)
	first, err := br.Peek(1)
	if err != nil || len(first) == 0 {
		// сканер закрылся сам (SYN-сканы, port-knockers) — тихо и без метрики скана
		_ = conn.Close()
		return nil, false
	}
	if first[0] == 0x16 { // TLS handshake
		return &peekedConn{Conn: conn, r: br}, true
	}
	// мусор: съедаем время сканера, не отвечаем ничем.
	g.st.Scans.Add(1)
	g.st.Dropped.Add(1)
	g.tarpit(conn)
	return nil, false
}

// tarpit держит соединение открытым, НИЧЕГО не отправляя: типичные
// автоматизированные пробники ждут баннер до своего таймаута.
func (g *Gate) tarpit(conn net.Conn) {
	if g.Logf != nil {
		g.Logf("hardening: non-TLS probe tarpitted %ds", int(g.Tarpit.Seconds()))
	}
	// 64КБ буфера чтения достаточно, чтобы сканер успел выгрузить payload
	// (мы его НЕ читаем — просто держим сокет и буфер приёма не растёт).
	var sink [512]byte
	deadline := time.Now().Add(g.Tarpit)
	_ = conn.SetReadDeadline(deadline)
	for time.Now().Before(deadline) {
		if _, err := conn.Read(sink[:]); err != nil {
			break
		}
	}
	_ = conn.Close()
}

// peekedConn подмешивает уже прочитанный байт обратно в поток — TLS-хендшейк
// должен увидеть полный ClientHello.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// String защищает от паники на nil после tarpit-ветки.
func (c *peekedConn) String() string {
	if c == nil || c.Conn == nil {
		return "<closed>"
	}
	return c.Conn.RemoteAddr().String()
}

// ParseTarpitSec парсит env-значение (мусор → дефолт, никогда не ошибка).
func ParseTarpitSec(raw string) int {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > 60 {
		return 3
	}
	if n == 0 {
		return 0
	}
	return n
}

// ConnLimit — мягкий limiter для inbound-прокси (та же дисциплина).
type ConnLimit struct {
	Max int
	cur atomic.Int64
}

func (l *ConnLimit) Admit() bool {
	if l == nil || l.Max <= 0 {
		return true
	}
	if l.cur.Add(1) > int64(l.Max) {
		l.cur.Add(-1)
		return false
	}
	return true
}

func (l *ConnLimit) Release() {
	if l == nil || l.Max <= 0 {
		return
	}
	l.cur.Add(-1)
}

// Describe — человекочитаемая сводка для лога старта и /status.
func (g *Gate) Describe() string {
	if !g.Enabled {
		return "off"
	}
	return fmt.Sprintf("tarpit=%ds max_conns=%d per_ip=%d", int(g.Tarpit.Seconds()), g.MaxConns, g.PerIPConns)
}
