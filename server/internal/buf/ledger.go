// Package buf: Buffer/1 (см. docs/spec/buffer.md) — FIFO-буфер c→p.
// v1.9.8 Buffer/2 (docs/spec/ack.md): Ledger — send-side реестр
// отправленных-и-неподтверждённых чанков с кумулятивным вытеснением.
package buf

import (
	"sync"
)

// Ledger — реестр непонятых байтов (Buffer/2): отправитель кладёт каждый
// отправленный чанк под абсолютным оффсетом; EvictTo выкидывает всё,
// что получатель подтвердил (кумулятивно). При потере транспорта Snapshot
// отдаёт неподтверждённый хвост для досылки (OPEN_RESUME).
//
// Потокобезопасен. Политики:
//   - оффсеты абсолютные (base = подтверждённая граница);
//   - EvictTo(n<base) — no-op (назад не отматываем);
//   - чанки копируются при Append (вызывающий волен переиспользовать буфер).
type Ledger struct {
	mu     sync.Mutex
	base   uint64 // кумулятивно вытеснено (подтверждено получателем)
	chunks [][]byte
}

// NewLedger — пустой Ledger с базой 0.
func NewLedger() *Ledger { return &Ledger{} }

// SetBase — база для resume-стрима: оффсеты продолжают нумерацию старого
// стрима (K из OPEN_OK). Вызывать ДО первого Append (иначе — no-op).
func (l *Ledger) SetBase(off uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.chunks) == 0 {
		l.base = off
	}
}

// Append копирует чанк и возвращает назначенный оффсет.
func (l *Ledger) Append(chunk []byte) uint64 {
	c := make([]byte, len(chunk))
	copy(c, chunk)
	l.mu.Lock()
	defer l.mu.Unlock()
	off := l.base + uint64(l.bytes())
	l.chunks = append(l.chunks, c)
	return off
}

// bytes — суммарный байт-объём очереди (вызывать под l.mu).
func (l *Ledger) bytes() int {
	n := 0
	for _, c := range l.chunks {
		n += len(c)
	}
	return n
}

// EvictTo выкидывает всё до off кумулятивно: чанки с концом ≤ off уходят,
// подрезанный головной чанк укорачивается. base растёт только вперёд.
func (l *Ledger) EvictTo(off uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if off <= l.base {
		return
	}
	keep := 0
	pos := l.base
	for i, c := range l.chunks {
		ce := pos + uint64(len(c))
		switch {
		case ce <= off: // чанк целиком под границей — уходят
			keep = i + 1
		case pos < off: // straddle: голова под границей — подрезаем, дальше стоп
			l.chunks[i] = c[off-pos:]
			keep = i
			pos = off
		default: // чанк после границы — стоп
		}
		if pos >= off {
			break
		}
		pos = ce
	}
	l.chunks = l.chunks[keep:]
	l.base = off
}

// ReplayFrom — досыл для resume: чанки с оффсетов ≥ k, кумулятивно
// отфильтрованные (полностью подтверждённые — скип, straddle — подрезаны).
// Порядок сохранён; очередь не мутируется (Snapshot по значению).
func (l *Ledger) ReplayFrom(k uint64) [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([][]byte, 0, len(l.chunks))
	pos := l.base
	for _, c := range l.chunks {
		ce := pos + uint64(len(c))
		switch {
		case ce <= k: // целиком подтверждено получателем
		case pos >= k: // целиком после границы
			out = append(out, c)
		default: // straddle: голова за границей
			out = append(out, c[k-pos:])
		}
		pos = ce
	}
	return out
}

// ReplayFilter — фильтр досыла при RESUME (docs/spec/ack.md): из списка
// чанков (последовательные оффсеты от base) отбирает хвост с оффсетов ≥ k:
// полностью подтверждённые скипаются, straddle подрезается. Порядок сохранён.
func ReplayFilter(base, k uint64, chunks [][]byte) [][]byte {
	out := make([][]byte, 0, len(chunks))
	pos := base
	for _, c := range chunks {
		ce := pos + uint64(len(c))
		switch {
		case ce <= k: // целиком подтверждено получателем
		case pos >= k: // целиком после границы
			out = append(out, c)
		default: // straddle: голова за границей
			out = append(out, c[k-pos:])
		}
		pos = ce
	}
	return out
}

// Snapshot — копия неподтверждённого хвоста: (base, chunks). Используется
// при паркинге: снятое уходит в park.Parked.replay, Ledger живёт дальше.
func (l *Ledger) Snapshot() (uint64, [][]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([][]byte, len(l.chunks))
	copy(out, l.chunks)
	return l.base, out
}

// End — текущий хвост оффсетов (base + байты очереди).
func (l *Ledger) End() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.base + uint64(l.bytes())
}

// Len — число чанков в очереди (диагностика/тесты).
func (l *Ledger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.chunks)
}
