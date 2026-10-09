package serverapp

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// v0.9.3: многоканальность — канон ROADMAP v1.0 «soak/load», измеримая база
// спидтеста (WORKFLOW v0.9.2, окна 512 КБ→4 МБ).
//
// ОДНА сессия (один туннель телефон↔сервер) обязана корректно мультиплексировать
// N параллельных потоков:
//  1. каждый поток доставляет РОВНО свой объём без подмены (SHA-256 каждого
//     потока сверяется — данные не путаются между стримами);
//  2. ни один поток не убивается анти-абьюзом (close(4) = ошибка копии);
//  3. сессия переживает параллельную нагрузку и закрывается чисто.
//
// Скорость (Mbps) тестируем КАК МЕТРИКУ (t.Logf), но НЕ гейтим абсолютные
// числа и не гейтим строгий speedup: на нагруженном CI-раннере под -race
// контеншн одного writeLoop/TLS-коннекта делает отношение шумным (канон:
// флейк = причина, а не ретраи; спидтест-методика меряет медианой на линке).
// Гейт-минимум: параллельный агрегат не хуже 0.5× одиночного (полный коллапс
// мультиплексирования поймает даже он).
//
// Отсюда же родился дедлок-фикс v0.9.3 (TypeClose: s.mu→st.mu против
// Read: st.mu→s.mu) и канон flow-control (кредит ≤ буферу приёма).

const msBulkSize = 4 << 20 // 4 МБ на поток

// msBulkData: детерминированный поток байт + его SHA-256.
func msBulkData() ([]byte, [sha256.Size]byte) {
	data := make([]byte, msBulkSize)
	var prev byte = 0x5A
	for i := range data {
		prev = prev*31 + byte(i*7)
		data[i] = prev
	}
	return data, sha256.Sum256(data)
}

// msStartBulk поднимает «сайт-зеркало»: на каждое подключение отдаёт
// ровно bulk и закрывает соединение (как HTTP download endpoint).
func msStartBulk(t *testing.T, bulk []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, bytes.NewReader(bulk))
			}(c)
		}
	}()
	return ln.Addr().String()
}

// msFetch: SOCKS5 CONNECT → скачать всё до EOF → вернуть длительность.
// SHA сверяет вызывающая сторона (потокобезопасно, каждый — свой массив).
func msFetch(t *testing.T, mixedAddr, host string, port uint16, deadline time.Duration) time.Duration {
	t.Helper()
	c, err := net.DialTimeout("tcp", mixedAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("socks dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(deadline))
	br := bufio.NewReader(c)
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(br, resp); err != nil || resp[1] != 0 {
		t.Fatalf("socks greeting failed: %v %v", resp, err)
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(br, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("socks connect failed: code=%d", rep[1])
	}
	start := time.Now()
	n, err := io.Copy(io.Discard, br)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("copy: %v (got %d/%d)", err, n, msBulkSize)
	}
	if n != msBulkSize {
		t.Fatalf("short download: %d/%d", n, msBulkSize)
	}
	return elapsed
}

// msFetchSHA: как msFetch, но возвращает скачанное (для SHA-сверки).
func msFetchSHA(t *testing.T, mixedAddr, host string, port uint16, deadline time.Duration) ([]byte, time.Duration) {
	t.Helper()
	c, err := net.DialTimeout("tcp", mixedAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("socks dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(deadline))
	br := bufio.NewReader(c)
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(br, resp); err != nil || resp[1] != 0 {
		t.Fatalf("socks greeting failed: %v %v", resp, err)
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(br, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("socks connect failed: code=%d", rep[1])
	}
	start := time.Now()
	got, err := io.ReadAll(io.LimitReader(br, msBulkSize))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("read: %v (got %d)", err, len(got))
	}
	if len(got) != msBulkSize {
		t.Fatalf("short download: %d/%d", len(got), msBulkSize)
	}
	return got, elapsed
}

func TestMultiStreamThroughput(t *testing.T) {
	app, cfg, token := startTestServer(t)

	bulk, wantSum := msBulkData()
	bulkAddr := msStartBulk(t, bulk)
	bulkHost, bulkPortS, _ := net.SplitHostPort(bulkAddr)
	var bulkPort uint16
	fmt.Sscanf(bulkPortS, "%d", &bulkPort)

	_, _, err := DialPhone(t, cfg.Listen.Tunnels, app.CAPin(), token, "phone-1",
		func(host string, port uint16) (net.Conn, error) {
			return net.Dial("tcp", bulkAddr)
		})
	if err != nil {
		t.Fatalf("phone connect: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // регистрация в хабе

	// Одиночный поток: целостность + базовая скорость (медиана 3 прогонов).
	var singles []float64
	for i := 0; i < 3; i++ {
		got, dur := msFetchSHA(t, cfg.Listen.Mixed, bulkHost, bulkPort, 60*time.Second)
		if sha256.Sum256(got) != wantSum {
			t.Fatalf("single stream payload corrupted (round %d)", i)
		}
		singles = append(singles, float64(msBulkSize)/dur.Seconds())
	}
	single := medianF(singles)

	// 8 параллельных потоков в ОДНУ сессию, каждый — со своей SHA-сверкой.
	const parallelStreams = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	var aggBytes int64
	wall0 := time.Now()
	for i := 0; i < parallelStreams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, _ := msFetchSHA(t, cfg.Listen.Mixed, bulkHost, bulkPort, 90*time.Second)
			if sha256.Sum256(got) != wantSum {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("parallel stream payload corrupted (len=%d)", len(got))
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			aggBytes += int64(len(got))
			mu.Unlock()
		}()
	}
	wg.Wait()
	wall := time.Since(wall0)
	if firstErr != nil {
		t.Fatalf("parallel streams failed: %v", firstErr)
	}
	agg := float64(aggBytes) / wall.Seconds() // честный агрегат: весь объём / стеночное время

	speedup := agg / single
	t.Logf("single=%.1f MB/s, %d×4MB parallel: aggregate=%.1f MB/s (wall=%s), speedup=%.2fx",
		single/(1<<20), parallelStreams, agg/(1<<20), wall.Round(time.Millisecond), speedup)

	// Гейт-минимум: мультиплексирование не коллапсировало. Полная сериализация
	// потоков дала бы ровно ~1×; деградация ниже 0.5× = потеря данных/стримов.
	if agg < 0.5*single {
		t.Fatalf("multi-channel collapsed: aggregate=%.1f MB/s < 0.5×single=%.1f MB/s",
			agg/(1<<20), single/(1<<20))
	}
}

func medianF(xs []float64) float64 {
	for i := 0; i < len(xs); i++ {
		for j := i + 1; j < len(xs); j++ {
			if xs[j] < xs[i] {
				xs[i], xs[j] = xs[j], xs[i]
			}
		}
	}
	return xs[len(xs)/2]
}
