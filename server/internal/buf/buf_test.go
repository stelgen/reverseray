package buf

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// KAT-векторы канона Buffer/1 (docs/spec/buffer.md). Те же hex-константы в
// android/.../core/RrpStreamBufferKATTest.kt. Меняешь канон — обновляй ОБЕ стороны.
var (
	katVecA = []byte{0x61, 0x62, 0x63} // «abc»
	katVecB = []byte{0x64, 0x65}       // «de»
	katVecC = []byte{0x21, 0x22}       // пост-attach чанк
)

func katBig() []byte {
	b := make([]byte, 90*1024)
	for i := range b {
		b[i] = 0x11
	}
	return b
}

func TestKATPushLen(t *testing.T) {
	b := New()
	if !b.Push(katVecA) || !b.Push(katVecB) {
		t.Fatal("push должен быть успешен")
	}
	if got := b.Len(); got != len(katVecA)+len(katVecB) {
		t.Fatalf("len: got=%d want=%d", got, len(katVecA)+len(katVecB))
	}
}

func TestKATAttachOrder(t *testing.T) {
	b := New()
	if !b.Push(katVecA) || !b.Push(katVecB) {
		t.Fatal("push должен быть успешен")
	}
	var out bytes.Buffer
	if err := b.Attach(&out); err != nil {
		t.Fatal(err)
	}
	if want := "abcde"; out.String() != want {
		t.Fatalf("attach order: got=%q want=%q", out.String(), want)
	}
	// живой путь: push уходит в sink, мимо буфера
	if !b.Push(katVecC) {
		t.Fatal("post-attach push")
	}
	if got := b.Len(); got != 0 {
		t.Fatalf("len after live push: got=%d want=0", got)
	}
	if out.String() != "abcde\x21\x22" {
		t.Fatalf("live push: got=%q", out.String())
	}
}

func TestKATOverflowBlocks(t *testing.T) {
	b := New()
	if !b.Push(katBig()) {
		t.Fatal("fill 1 должен быть успешен")
	}
	if !b.Push(katBig()) {
		t.Fatal("fill 2 должен быть успешен")
	}
	if got := b.Len(); got != 2*90*1024 {
		t.Fatalf("len: got=%d", got)
	}
	done := make(chan bool, 1)
	go func() { done <- b.Push(katBig()) }() // 184320+92160 > 262144: блок до Close
	select {
	case ok := <-done:
		t.Fatalf("push при переполнении вернулся слишком рано: ok=%v", ok)
	case <-time.After(200 * time.Millisecond):
	}
	b.Close()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("push после Close: ok=true, ждали false")
		}
	case <-time.After(time.Second):
		t.Fatal("push не разблокирован Close")
	}
}

func TestKATClosedRejects(t *testing.T) {
	b := New()
	b.Close()
	if b.Push(katVecA) {
		t.Fatal("push в закрытый буфер: ждали false")
	}
	if b.Len() != 0 {
		t.Fatal("закрытый буфер не пуст")
	}
}

// Конкурентные производители (MODE_BLOCK): все байты доезжают в sink.
func TestConcurrentPushers(t *testing.T) {
	b := New()
	const producers, rounds = 8, 50
	var wg sync.WaitGroup
	for range producers {
		wg.Go(func() {
			for range rounds {
				if !b.Push([]byte("data")) {
					t.Error("push провален")
					return
				}
			}
		})
	}
	wg.Wait()
	if got := b.Len(); got != producers*rounds*4 {
		t.Fatalf("len: got=%d want=%d", got, producers*rounds*4)
	}
	var out bytes.Buffer
	if err := b.Attach(&out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != producers*rounds*4 {
		t.Fatalf("sink bytes: got=%d want=%d", out.Len(), producers*rounds*4)
	}
}
