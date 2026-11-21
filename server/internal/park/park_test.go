// Тесты паркинга (v1.9.8 Buffer/2): LEDGER-replay порядок, K-обрезка,
// Delivered-база, идемпотентность Close. Канон — docs/spec/ack.md.
package park

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// fakeStream — минимальный net.Conn с записью Write-порядка и ResumeK
// (расширенный OPEN_OK): park.ReResume пишет досыл и live через st.Write.
type fakeStream struct {
	mu     sync.Mutex
	wrote  [][]byte
	pend   []byte // данные, доступные для Read (эмуляция S→C браузеру)
	notify chan struct{}
	closed chan struct{}
	k      uint64
	hasK   bool
}

func newFakeStream() *fakeStream {
	return &fakeStream{notify: make(chan struct{}, 16), closed: make(chan struct{})}
}

func (f *fakeStream) Write(b []byte) (int, error) {
	f.mu.Lock()
	f.wrote = append(f.wrote, append([]byte(nil), b...))
	f.mu.Unlock()
	return len(b), nil
}

func (f *fakeStream) Read(p []byte) (int, error) {
	for {
		f.mu.Lock()
		if len(f.pend) > 0 {
			n := copy(p, f.pend)
			f.pend = f.pend[n:]
			f.mu.Unlock()
			return n, nil
		}
		f.mu.Unlock()
		select {
		case <-f.notify:
		case <-f.closed:
			return 0, io.EOF
		}
	}
}

func (f *fakeStream) ResumeK() (uint64, bool) { return f.k, f.hasK }

func (f *fakeStream) wroteAll() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []byte
	for _, c := range f.wrote {
		out = append(out, c...)
	}
	return out
}

// --- net.Conn boilerplate (паркинг только пишет и копирует) ---
func (f *fakeStream) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}
func (f *fakeStream) LocalAddr() net.Addr                { return nil }
func (f *fakeStream) RemoteAddr() net.Addr               { return nil }
func (f *fakeStream) SetDeadline(t time.Time) error      { return nil }
func (f *fakeStream) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeStream) SetWriteDeadline(t time.Time) error { return nil }

func newTestParked(t *testing.T, snap rrp.ResumeSnapshot) *Parked {
	t.Helper()
	return New("dev", [16]byte{1}, rrp.DialRequest{}, nil, "test", snap)
}

// KAT со спеки (docs/spec/ack.md; векторы — HEX-байты): LEDGER base=4,
// чанк {0x44,0x55,0x66}, K=5 → досыл {0x55,0x66} ДО буфера FIFO.
func TestParkReplayOrderAndK(t *testing.T) {
	snap := rrp.ResumeSnapshot{Base: 4, Chunks: [][]byte{{0x44, 0x55, 0x66}}, Delivered: 0}
	p := newTestParked(t, snap)
	if p.Delivered() != 0 {
		t.Fatalf("Delivered() = %d, want 0", p.Delivered())
	}
	if !p.Feed([]byte("AA")) { // FIFO до resume
		t.Fatal("Feed before resume failed")
	}
	st := newFakeStream()
	st.k, st.hasK = 5, true
	if err := p.Resume(st); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	got := string(st.wroteAll())
	// Порядок: LEDGER-хвост (после K) затем FIFO-буфер.
	want := "\x55\x66" + "AA"
	if got != want {
		t.Fatalf("stream wrote %q, want %q", got, want)
	}
	// Live после resume: Feed идёт прямо в стрим.
	if !p.Feed([]byte("BB")) || !p.Resumed() {
		t.Fatalf("live feed failed (Feed=%v Resumed=%v)", p.PendingLen(), p.Resumed())
	}
	got = string(st.wroteAll())
	if got != want+"BB" {
		t.Fatalf("live wrote %q, want %q", got, want+"BB")
	}
	p.Close()
}

// K покрывает весь replay → досылать нечего, только буфер.
func TestParkReplayFullyAcked(t *testing.T) {
	snap := rrp.ResumeSnapshot{Base: 0, Chunks: [][]byte{[]byte("abc"), []byte("de")}, Delivered: 9}
	p := newTestParked(t, snap)
	if p.Delivered() != 9 {
		t.Fatalf("Delivered() = %d, want 9", p.Delivered())
	}
	_ = p.Feed([]byte("X"))
	st := newFakeStream()
	st.k, st.hasK = 5, true // "abc"+"de" = 5 байт — всё подтверждено
	if err := p.Resume(st); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if got := string(st.wroteAll()); got != "X" {
		t.Fatalf("stream wrote %q, want %q (replay должен быть срезан K)", got, "X")
	}
	p.Close()
}

// Без snap (Buffer/1 legacy): только FIFO, ResumeK не запрашивается.
func TestParkLegacyNoReplay(t *testing.T) {
	p := newTestParked(t, rrp.ResumeSnapshot{})
	_ = p.Feed([]byte("L1"))
	st := newFakeStream()
	if err := p.Resume(st); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if got := string(st.wroteAll()); got != "L1" {
		t.Fatalf("stream wrote %q, want %q", got, "L1")
	}
	p.Close()
}

// Ошибка записи в стрим при replay: Resume закрывает стрим и паркинг.
func TestParkReplayWriteError(t *testing.T) {
	snap := rrp.ResumeSnapshot{Base: 0, Chunks: [][]byte{[]byte("zz")}, Delivered: 0}
	p := newTestParked(t, snap)
	st := &errStream{fakeStream: *newFakeStream()}
	if err := p.Resume(st); err == nil {
		t.Fatal("Resume должен вернуть ошибку записи replay")
	}
	select {
	case <-p.Done:
	default:
		t.Fatal("паркинг должен быть закрыт после ошибки replay")
	}
}

type errStream struct{ fakeStream }

func (e *errStream) Write(b []byte) (int, error) { return 0, errors.New("boom") }

// Close идемпотентен; Feed на закрытом — false.
func TestParkCloseIdempotent(t *testing.T) {
	p := newTestParked(t, rrp.ResumeSnapshot{})
	p.Close()
	p.Close() // повторный — no-op
	select {
	case <-p.Done:
	default:
		t.Fatal("Done не закрыт")
	}
	if p.Feed([]byte("x")) {
		t.Fatal("Feed на закрытом паркинге должен вернуть false")
	}
	if p.Resumed() {
		t.Fatal("закрытый паркинг не может быть live")
	}
}
