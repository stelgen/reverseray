package rrp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// windowedPhone — фейковый телефон, соблюдающий flow-control: не шлёт DATA
// сверх выданных сервером WINDOW-кредитов (как реальный клиент на семафоре).
// Позволяет детерминированно тестировать BDP-автотюнинг и бюджеты.
//
// Детерминизм для медленных CI-раннеров: все дедлайны 60с, фазы тестов
// разделены синхронизацией по каналам (никаких «поспим и подождём»).
type windowedPhone struct {
	t       *testing.T
	c       net.Conn
	mu      sync.Mutex
	permits int64

	streamID uint32
	dialOK   chan struct{}
	closed   chan struct{}
	once     sync.Once

	sentBytes   int64
	creditBytes int64 // сумма WINDOW-инкрементов от сервера
	growMax     int64 // максимум (credit - sent): прирост сверх отправленного
	killedCode  uint8
}

func newWindowedPhone(t *testing.T, c net.Conn, initialPermits int64) *windowedPhone {
	p := &windowedPhone{
		t:        t,
		c:        c,
		permits:  initialPermits,
		dialOK:   make(chan struct{}, 16), // буфер: рун-цикл телефона никогда не блокируется
		closed:   make(chan struct{}),
		streamID: 0xFFFFFFFF,
	}
	return p
}

func (p *windowedPhone) run() {
	for {
		f, err := ReadFrame(p.c)
		if err != nil {
			p.once.Do(func() { close(p.closed) })
			return
		}
		switch f.Type {
		case TypeOpen:
			p.mu.Lock()
			p.streamID = f.StreamID
			p.mu.Unlock()
			_ = WriteFrame(p.c, TypeOpenOK, 0, f.StreamID, []byte{0})
			select {
			case p.dialOK <- struct{}{}:
			case <-p.closed:
			}
		case TypeWindow:
			inc, err := DecodeWindow(f.Payload)
			if err != nil {
				continue
			}
			p.mu.Lock()
			p.permits += int64(inc)
			p.creditBytes += int64(inc)
			if g := p.creditBytes - p.sentBytes; g > p.growMax {
				p.growMax = g
			}
			p.mu.Unlock()
		case TypePing:
			_ = WriteFrame(p.c, TypePong, 0, 0, f.Payload)
		case TypeClose:
			p.mu.Lock()
			p.killedCode = f.closeCode()
			p.mu.Unlock()
			p.once.Do(func() { close(p.closed) })
			return
		}
	}
}

// sendChunk ждёт кредитов и шлёт один DATA-чанк. false — стрим закрыт/нет кредитов.
func (p *windowedPhone) sendChunk(n int, deadline time.Time) bool {
	for {
		p.mu.Lock()
		if p.permits >= int64(n) {
			p.permits -= int64(n)
			id := p.streamID
			p.sentBytes += int64(n)
			p.mu.Unlock()
			payload := make([]byte, n)
			return WriteFrame(p.c, TypeData, 0, id, payload) == nil
		}
		closed := false
		select {
		case <-p.closed:
			closed = true
		default:
		}
		p.mu.Unlock()
		if closed || !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (p *windowedPhone) stats() (sent, credit, grow int64, killed uint8) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sentBytes, p.creditBytes, p.growMax, p.killedCode
}

func newTestSession(t *testing.T, mutate func(*SessionConfig)) (*Session, *windowedPhone) {
	t.Helper()
	c1, c2 := net.Pipe()
	cfg := DefaultSessionConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	sess := NewSession("s1", "dev", pipeConn{c1}, cfg)
	go sess.Run()
	p := newWindowedPhone(t, c2, cfg.initialGrant())
	go p.run()
	t.Cleanup(func() { _ = sess.Close() })
	return sess, p
}

// waitFor поллит условие до дедлайна (детерминизм против асинхронности pipe:
// sendChunk/WriteFrame возвращаются раньше, чем сессия обработает кадр).
func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	dl := time.Now().Add(d)
	for time.Now().Before(dl) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

func openStream(t *testing.T, sess *Session, p *windowedPhone) net.Conn {
	t.Helper()
	st, err := sess.Open(context.Background(), DialRequest{ATYP: ATYPDomain, Addr: []byte("example.com"), Port: 443})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	select {
	case <-p.dialOK:
	case <-time.After(60 * time.Second):
		t.Fatal("phone did not see OPEN")
	}
	return st
}

// Тест 1: учёт outstand для download-направления сбалансирован и не уходит в минус.
// Регрессия v1.2.0: раньше DATA от телефона не инкрементили outstand,
// а Read декрементил — на живой сессии счётчик уходил в −469 МБ.
func TestOutstandBalancedDownload(t *testing.T) {
	sess, p := newTestSession(t, nil)
	st := openStream(t, sess, p)
	defer st.Close()

	deadline := time.Now().Add(60 * time.Second)
	const chunks, size = 3, 64 * 1024
	for i := 0; i < chunks; i++ {
		if !p.sendChunk(size, deadline) {
			t.Fatalf("phone send %d failed", i)
		}
	}
	// In-flight до чтения: ровно то, что прислал телефон. sendChunk завершается
	// раньше, чем сессия обработает кадр (pipe→handle асинхронны) — поллим.
	if !waitFor(t, 60*time.Second, func() bool { return sess.Outstanding() == chunks*size }) {
		t.Fatalf("outstanding after push = %d, want %d", sess.Outstanding(), chunks*size)
	}
	buf := make([]byte, chunks*size)
	_ = st.SetReadDeadline(time.Now().Add(60 * time.Second))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := sess.Outstanding(); got != 0 {
		t.Fatalf("outstanding after credit = %d, want 0 (учёт не сбалансирован)", got)
	}
}

// drainUntilGrown: фон-потребитель осушает стрим, тест ждёт фактического роста
// гранта сверх стартового окна (детерминированно, по состоянию, не по времени).
func drainUntilGrown(t *testing.T, st net.Conn, sess *Session, p *windowedPhone) {
	t.Helper()
	dl := time.Now().Add(60 * time.Second)
	for time.Now().Before(dl) {
		if !p.sendChunk(64*1024, dl) {
			break
		}
		if sess.WindowGrantTotal() > int64(sess.cfg.initialGrant()) {
			return
		}
	}
	t.Fatalf("autotune не вырос за отведённое время: grant=%d", sess.WindowGrantTotal())
}

// waitPhoneGrow: ждём, пока фейковый телефон фактически ПОЛУЧИТ WINDOW-кредит
// с приростом (серверный грант уже вырос — кадр мог быть ещё в полёте).
func waitPhoneGrow(t *testing.T, p *windowedPhone) {
	t.Helper()
	dl := time.Now().Add(60 * time.Second)
	for time.Now().Before(dl) {
		if _, _, grow, _ := p.stats(); grow > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("телефон не увидел прирост окна (WINDOW-кредит не дошёл)")
}

// Тест 2: BDP-автотюнинг растит окно при быстром потребителе; прирост виден
// телефону (кредиты > отправленного) и вписывается в MaxStreamWin/Budget.
func TestAutotuneGrowsToMax(t *testing.T) {
	sess, p := newTestSession(t, nil)
	st := openStream(t, sess, p)

	// Потребитель-discarder: осушает стрим на протяжении всего теста.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32*1024)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = st.SetReadDeadline(time.Now().Add(60 * time.Second))
			if _, err := st.Read(buf); err != nil {
				return
			}
		}
	}()
	defer func() {
		_ = st.Close() // читатель выйдет по ошибке/закрытию
		<-done
	}()

	drainUntilGrown(t, st, sess, p)
	waitPhoneGrow(t, p)

	_, _, grow, killed := p.stats()
	if killed != 0 {
		t.Fatalf("stream killed code %d — буфер не должен переполняться при честном flow-control", killed)
	}
	if grow <= 0 {
		t.Fatalf("autotune не сработал: кредиты не превысили отправленное (grow=%d)", grow)
	}
	if got := sess.WindowGrantTotal(); got <= int64(sess.cfg.initialGrant()) {
		t.Fatalf("grant не вырос: %d ≤ стартового %d", got, sess.cfg.initialGrant())
	}
	if got := sess.WindowGrantTotal(); got > int64(sess.cfg.MaxStreamWin) {
		t.Fatalf("grant %d превысил MaxStreamWin %d", got, sess.cfg.MaxStreamWin)
	}
	if sess.WindowGrowTotal() == 0 {
		t.Fatal("счётчик windowGrow пуст")
	}
}

// Тест 3: затор потребителя останавливает рост окна и НЕ убивает стрим.
// Полностью синхронный (одна горутина теста): send→read по очереди в фазе
// роста, затем шлём БЕЗ чтения — никакого межгорутинного ожидания, гонок и
// зависаний нет по построению. У rrp-стрима нет реального read-таймаута
// (SetReadDeadline — best-effort пробуждение), поэтому фоновые читатели
// здесь принципиально не используются.
func TestAutotuneStallStopsGrowthNoKill(t *testing.T) {
	sess, p := newTestSession(t, nil)
	st := openStream(t, sess, p)
	defer st.Close()

	floor := int64(sess.cfg.initialGrant())

	// Фаза роста: send→read по очереди; на каждом Read буфер осушен целиком
	// (inLen==0) → autotune выдаёт прирост. Ждём фактического роста гранта.
	dl := time.Now().Add(60 * time.Second)
	chunk := make([]byte, 64*1024)
	for time.Now().Before(dl) {
		if !p.sendChunk(64*1024, dl) {
			t.Fatal("phone send failed в фазе роста")
		}
		if _, err := io.ReadFull(st, chunk); err != nil {
			t.Fatalf("read: %v", err)
		}
		if sess.WindowGrantTotal() > floor {
			break
		}
	}
	g1 := sess.WindowGrantTotal()
	if g1 <= floor {
		t.Fatalf("autotune не вырос: grant=%d", g1)
	}

	// Фаза затора: шлём БЕЗ чтения. Рост обязан остановиться (окно выдаётся
	// только на Read при пустом буфере); стрим обязан выжить — буфер вмещает
	// грант, kill(4) при честном flow-control невозможен.
	for i := 0; i < 40; i++ {
		if !p.sendChunk(64*1024, time.Now().Add(10*time.Second)) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	g2 := sess.WindowGrantTotal()
	if g2 < floor {
		t.Fatalf("grant %d ниже стартового %d", g2, floor)
	}
	if _, _, _, killed := p.stats(); killed != 0 {
		t.Fatalf("стрим убит кодом %d при честном flow-control", killed)
	}
	if g2 > g1 {
		t.Fatalf("окно продолжило расти при заторе: %d → %d", g1, g2)
	}
}

// Тест 4: бюджет устройства снова работает — при переполнении in-flight новые
// стримы отклоняются, после слива — снова открываются.
func TestOpenBudgetBlocksAndRecovers(t *testing.T) {
	sess, p := newTestSession(t, func(c *SessionConfig) { c.Budget = 512 * 1024 })
	st := openStream(t, sess, p)
	defer st.Close()

	deadline := time.Now().Add(60 * time.Second)
	for i := 0; i < 10; i++ {
		if !p.sendChunk(64*1024, deadline) {
			break
		}
	}
	if !waitFor(t, 60*time.Second, func() bool { return sess.Outstanding() >= 512*1024 }) {
		t.Fatalf("outstanding %d — тест expects ≥ Budget", sess.Outstanding())
	}
	_, err := sess.Open(context.Background(), DialRequest{ATYP: ATYPDomain, Addr: []byte("example.com"), Port: 80})
	if err == nil || !strings.Contains(err.Error(), "device window budget exhausted") {
		t.Fatalf("ожидали отказ по бюджету, получили: %v", err)
	}
	// Слив → бюджет освобождается → открытие снова работает.
	if _, _, _, killed := p.stats(); killed != 0 {
		t.Fatalf("стрим убит %d", killed)
	}
	buf := make([]byte, 64*1024)
	dl := time.Now().Add(60 * time.Second)
	for time.Now().Before(dl) {
		if sess.Outstanding() == 0 {
			break
		}
		_ = st.SetReadDeadline(time.Now().Add(60 * time.Second))
		if _, err := st.Read(buf); err != nil {
			break
		}
	}
	if got := sess.Outstanding(); got != 0 {
		t.Fatalf("outstanding %d после слива, want 0", got)
	}
	st2, err := sess.Open(context.Background(), DialRequest{ATYP: ATYPDomain, Addr: []byte("example.com"), Port: 80})
	if err != nil {
		t.Fatalf("open после слива: %v", err)
	}
	_ = st2.Close()
}

// Тест 5: WINDOW от телефона подтверждает upload — outstand возвращается к нулю.
func TestTypeWindowCreditsOutstand(t *testing.T) {
	sess, p := newTestSession(t, nil)
	st := openStream(t, sess, p)
	defer st.Close()

	msg := make([]byte, 100*1024)
	if _, err := st.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Фейковый телефон не отвечает WINDOW → outstand висит как in-flight.
	if got := sess.Outstanding(); got != int64(len(msg)) {
		t.Fatalf("outstanding после записи = %d, want %d", got, len(msg))
	}
	// Телефон подтверждает все байты одним WINDOW.
	id := p.streamID
	inc := make([]byte, 4)
	binary.BigEndian.PutUint32(inc, uint32(len(msg)))
	if err := WriteFrame(p.c, TypeWindow, 0, id, inc); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if sess.Outstanding() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("outstanding не обнулился после WINDOW: %d", sess.Outstanding())
}

// Тест 6: телефон-нарушитель (шлёт без кредитов) убивается по переполнению
// буфера — анти-абьюз сохранён, память защищена.
func TestPushInKillsProtocolViolator(t *testing.T) {
	sess, p := newTestSession(t, nil)
	st := openStream(t, sess, p)
	defer st.Close()

	id := p.streamID
	big := make([]byte, 64*1024)
	// 1МБ буфера + запас: 24 чанка по 64К без чтения.
	for i := 0; i < 24; i++ {
		if err := WriteFrame(p.c, TypeData, 0, id, big); err != nil {
			break
		}
	}
	buf := make([]byte, 1)
	_ = st.SetReadDeadline(time.Now().Add(60 * time.Second))
	_, err := io.ReadFull(st, buf)
	for err == nil {
		_, err = io.ReadFull(st, buf)
	}
	if err == nil || !strings.Contains(err.Error(), "code 4") {
		t.Fatalf("ожидали закрытие code 4 (buffer overflow), получили: %v", err)
	}
	if _, _, _, killed := p.stats(); killed != 4 {
		t.Fatalf("телефон должен был получить CLOSE(4), получил %d", killed)
	}
}

// Тест 7: отказ диала телефона учитывается (openErrs) и виден в акцессоре.
func TestOpenErrorsCounted(t *testing.T) {
	c1, c2 := net.Pipe()
	cfg := DefaultSessionConfig()
	sess := NewSession("s1", "dev", pipeConn{c1}, cfg)
	go sess.Run()
	t.Cleanup(func() { _ = sess.Close() })

	// Телефон отвечает OPEN_OK с кодом ошибки 3 (dial timeout).
	go func() {
		for {
			f, err := ReadFrame(c2)
			if err != nil {
				return
			}
			if f.Type == TypeOpen {
				_ = WriteFrame(c2, TypeOpenOK, 0, f.StreamID, []byte{3})
			}
		}
	}()
	_, err := sess.Open(context.Background(), DialRequest{ATYP: ATYPDomain, Addr: []byte("blocked.example"), Port: 80})
	if err == nil || !errors.Is(err, errOpen(3)) {
		t.Fatalf("ожидали errOpen(3), получили %v", err)
	}
	if got := sess.OpenErrors(); got != 1 {
		t.Fatalf("OpenErrors = %d, want 1", got)
	}
}
