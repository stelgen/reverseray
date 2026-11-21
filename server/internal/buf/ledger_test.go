package buf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Buffer/2 KAT (docs/spec/ack.md): одинаковые векторы с
// android .../RrpAckLedgerKATTest.kt. Меняешь — обновляй ОБЕ стороны.

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func eqSnap(t *testing.T, l *Ledger, wantBase uint64, wantChunks ...string) {
	t.Helper()
	base, chunks := l.Snapshot()
	if base != wantBase {
		t.Fatalf("base = %d, want %d", base, wantBase)
	}
	if len(chunks) != len(wantChunks) {
		t.Fatalf("chunks = %v, want %v", chunks, wantChunks)
	}
	for i, w := range wantChunks {
		if !bytes.Equal(chunks[i], hx(t, w)) {
			t.Fatalf("chunk[%d] = %x, want %s", i, chunks[i], w)
		}
	}
}

// Тест 1: append подрастающие оффсеты + snapshot целиком.
func TestLedgerAppendOffsets(t *testing.T) {
	l := NewLedger()
	if off := l.Append(hx(t, "0011")); off != 0 {
		t.Fatalf("off1 = %d, want 0", off)
	}
	if off := l.Append(hx(t, "2233")); off != 2 {
		t.Fatalf("off2 = %d, want 2", off)
	}
	if off := l.Append(hx(t, "445566")); off != 4 {
		t.Fatalf("off3 = %d, want 4", off)
	}
	eqSnap(t, l, 0, "0011", "2233", "445566")
	if l.End() != 7 {
		t.Fatalf("end = %d, want 7", l.End())
	}
}

// Тест 2: кумулятивное вытеснение (граница внутри чанка).
func TestLedgerEvictToKAT(t *testing.T) {
	l := NewLedger()
	l.Append(hx(t, "0011"))
	l.Append(hx(t, "2233"))
	l.Append(hx(t, "445566"))

	// граница внутри третьего чанка: голова "445566" подрезается до "5566"
	l.EvictTo(5)
	eqSnap(t, l, 5, "5566")

	// всё подтверждено — очередь пуста
	l.EvictTo(7)
	eqSnap(t, l, 7)

	// назад не отматываем
	l.EvictTo(2)
	eqSnap(t, l, 7)

	// append после вытеснения продолжает нумерацию
	if off := l.Append(hx(t, "7788")); off != 7 {
		t.Fatalf("off after evict = %d, want 7", off)
	}
	eqSnap(t, l, 7, "7788")
}

// Тест 3: SetBase — нумерация resume-стрима продолжается со старого K.
func TestLedgerSetBase(t *testing.T) {
	l := NewLedger()
	l.SetBase(42)
	if off := l.Append(hx(t, "aabb")); off != 42 {
		t.Fatalf("off = %d, want 42", off)
	}
	eqSnap(t, l, 42, "aabb")
	// SetBase после Append — no-op
	l.SetBase(0)
	eqSnap(t, l, 42, "aabb")
}

// Тест 4: replay-фильтр RESUME (K-границы) на сцене KAT.
func TestLedgerResumeFilter(t *testing.T) {
	l := NewLedger()
	l.Append(hx(t, "0011"))
	l.Append(hx(t, "2233"))
	l.Append(hx(t, "445566"))

	// K=5: чанки с концом ≤ 5 скипнуты, третий подрезан — досыл "4556".
	if got := l.ReplayFrom(5); len(got) != 1 || !bytes.Equal(got[0], hx(t, "5566")) {
		t.Fatalf("replay(K=5) = %v, want [5566]", got)
	}
	// K=7 — досылать нечего
	if got := l.ReplayFrom(7); len(got) != 0 {
		t.Fatalf("replay(K=7) = %v, want empty", got)
	}
	// K=0 — досыл целиком
	if got := l.ReplayFrom(0); len(got) != 3 {
		t.Fatalf("replay(K=0) = %v, want 3 chunks", got)
	}
}

// Тест 5: параллельный EvictTo/Append/Snapshot — гонок нет, нумерация неединообразна.
func TestLedgerConcurrent(t *testing.T) {
	l := NewLedger()
	done := make(chan struct{})
	for w := 0; w < 4; w++ {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 200; i++ {
				l.Append(bytes.Repeat([]byte{byte(w)}, 16))
				l.EvictTo(l.End() / 2)
				l.Snapshot()
			}
		}(w)
	}
	for w := 0; w < 4; w++ {
		<-done
	}
	if l.Len() > 4*200 {
		t.Fatalf("ledger grew beyond appends: %d", l.Len())
	}
}
