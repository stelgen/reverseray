// Package buf — канон базовой буферизации стримов (docs/spec/buffer.md).
// Единое ядро FIFO-буфера: паркинг c→p (park) и будущие применения.
// Реализация-зеркало Kotlin: core/RrpStreamBuffer.kt; KAT обеих сторон
// байт-в-байт по одним векторам. Меняешь канон — обновляй ОБЕ стороны.
package buf

import (
	"errors"
	"io"
	"sync"
)

const (
	// Cap — верхняя граница буфера, байт (256 КиБ; бывший park.PendingCap).
	Cap = 256 * 1024
	// MaxChunk — максимальный чанк одного Push, байт (16 КиБ).
	MaxChunk = 16 * 1024
)

// Buffer — bounded FIFO без дропов: Push копирует чанк; при переполнении
// блокируется (MODE_BLOCK, TCP backpressure) до появления места, Attach или
// Close. После Attach прямые записи уходят в sink, минуя буфер (живой стрим).
type Buffer struct {
	mu     sync.Mutex
	cond   *sync.Cond
	chunks [][]byte
	n      int
	sink   io.Writer
	closed bool
}

// New — пустой буфер с канонной ёмкостью Cap.
func New() *Buffer {
	b := &Buffer{}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// Push добавляет копию чанка (FIFO). Блокируется при переполнении — так
// TCP-давление доходит до производителя, ни один байт не дропается.
// После Attach записи уходят напрямую в sink. false — буфер закрыт или
// запись в sink не удалась.
func (b *Buffer) Push(chunk []byte) bool {
	cp := make([]byte, len(chunk))
	copy(cp, chunk)
	b.mu.Lock()
	defer b.mu.Unlock()
	for !b.closed && b.sink == nil && b.n+len(cp) > Cap {
		b.cond.Wait()
	}
	if b.closed {
		return false
	}
	if b.sink != nil {
		_, err := b.sink.Write(cp)
		return err == nil
	}
	b.chunks = append(b.chunks, cp)
	b.n += len(cp)
	return true
}

// Attach подключает живой sink: досылает FIFO-буфер по порядку, затем все
// последующие Push уходят напрямую в sink. Ошибка записи → буфер закрыт.
func (b *Buffer) Attach(sink io.Writer) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return errors.New("buf: closed")
	}
	for _, c := range b.chunks {
		if _, err := sink.Write(c); err != nil {
			b.chunks = nil
			b.n = 0
			b.sink = sink
			b.mu.Unlock()
			b.Close()
			return err
		}
	}
	b.chunks = nil
	b.n = 0
	b.sink = sink
	b.cond.Broadcast()
	b.mu.Unlock()
	return nil
}

// Len — байтов в буфере (диагностика/телеметрия).
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.n
}

// Live — true после Attach (push уходит в sink, мимо буфера).
func (b *Buffer) Live() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sink != nil
}

// Closed — буфер закрыт.
func (b *Buffer) Closed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// Close будит ждущих производителей и закрывает буфер (идемпотентно).
func (b *Buffer) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	b.chunks = nil
	b.n = 0
	b.cond.Broadcast()
}
