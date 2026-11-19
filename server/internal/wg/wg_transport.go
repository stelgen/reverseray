// wg_transport.go — зона «Транспорт (канон WG, тип 4)» + replay-window — pure move из wg.go (v1.8.3, дробление по зонам; поведение не меняется).
package wg

import (
	"encoding/binary"
	"fmt"
	"sync"
)

// ---- Транспорт (канон WG, тип 4) ----

// Transport — транспортные конверты WG после хендшейка: [type=4][receiver
// index 4][counter 8 LE][ChaCha20Poly1305(plaintext)]. Анти-реплей —
// sliding window 2048 (канон WG).
type Transport struct {
	mu      sync.Mutex
	SendKey [KeySize]byte
	RecvKey [KeySize]byte
	SendIdx uint32 // наш sender_index (peer ставит его в receiver)
	RecvIdx uint32 // sender_index пира (мы ставим его в receiver)
	sendCtr uint64
	window  *replayWindow
}

// NewTransport строит транспорт из состояния хендшейка.
// initiator=true — сторона клиента (SendKey=t0), false — сервера (SendKey=t1).
func NewTransport(initiator bool, ch *ClientHandshake) *Transport {
	t := &Transport{window: newReplayWindow()}
	if initiator {
		t.SendKey, t.RecvKey = ch.SendKey, ch.RecvKey
		t.SendIdx, t.RecvIdx = ch.Sender, ch.RecvIdx
	} else {
		t.SendKey, t.RecvKey = ch.RecvKey, ch.SendKey
		t.SendIdx, t.RecvIdx = ch.RecvIdx, ch.Sender
	}
	return t
}

func NewTransportServer(sh *ServerHandshake) *Transport {
	t := &Transport{window: newReplayWindow()}
	t.SendKey, t.RecvKey = sh.SendKey, sh.RecvKey
	t.SendIdx, t.RecvIdx = sh.Sender, sh.RecvIdx
	return t
}

// Seal упаковывает открытые данные в WG transport-пакет.
func (t *Transport) Seal(plain []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sendCtr >= MaxCounter {
		return nil, ErrCounter
	}
	ctr := t.sendCtr
	t.sendCtr++
	pkt := make([]byte, 0, MsgDataHeader+len(plain)+MacSize)
	var hdr [MsgDataHeader]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 4)
	binary.LittleEndian.PutUint32(hdr[4:8], t.RecvIdx)
	binary.LittleEndian.PutUint64(hdr[8:16], ctr)
	pkt = append(pkt, hdr[:]...)
	box, err := seal(t.SendKey[:], ctr, nil, plain)
	if err != nil {
		return nil, err
	}
	return append(pkt, box...), nil
}

// Open распаковывает WG transport-пакет (анти-реплей, канон WG).
func (t *Transport) Open(pkt []byte) ([]byte, error) {
	if len(pkt) < MsgDataHeader+MacSize {
		return nil, ErrEnvelope
	}
	if binary.LittleEndian.Uint32(pkt[0:4]) != 4 {
		return nil, fmt.Errorf("%w: type ≠ 4", ErrEnvelope)
	}
	ctr := binary.LittleEndian.Uint64(pkt[8:16])
	if ctr >= MaxCounter {
		return nil, ErrCounter
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.window.check(ctr) {
		return nil, ErrReplay
	}
	plain, err := open(t.RecvKey[:], ctr, nil, pkt[MsgDataHeader:])
	if err != nil {
		t.window.rollback(ctr)
		return nil, fmt.Errorf("%w: AEAD: %v", ErrEnvelope, err)
	}
	return plain, nil
}

// replayWindow — sliding window 2048 (канон WG §5.4.7).
type replayWindow struct {
	bitmap [ReplayWindowSize / 64]uint64
	base   uint64
	max    uint64 // старший принятый
}

func newReplayWindow() *replayWindow { return &replayWindow{max: ^uint64(0)>>1 | 0} }

func (w *replayWindow) check(ctr uint64) bool {
	switch {
	case ctr >= w.base+ReplayWindowSize:
		// сдвиг окна вперёд
		shift := ctr - w.base - ReplayWindowSize + 1
		w.advance(shift)
		w.set(ctr)
		return true
	case ctr >= w.base:
		if w.get(ctr) {
			return false
		}
		w.set(ctr)
		return true
	default:
		return false // позади окна
	}
}

func (w *replayWindow) rollback(ctr uint64) {
	if ctr >= w.base && ctr <= w.max {
		w.clear(ctr)
	}
}

func (w *replayWindow) advance(shift uint64) {
	if shift >= ReplayWindowSize {
		for i := range w.bitmap {
			w.bitmap[i] = 0
		}
		w.base += shift
		return
	}
	wIdx := int(shift / 64)
	bShift := shift % 64
	newBitmap := make([]uint64, len(w.bitmap))
	for i := 0; i < len(w.bitmap); i++ {
		src := i + wIdx
		if src < len(w.bitmap) {
			newBitmap[i] = w.bitmap[src] >> bShift
			if bShift > 0 && src+1 < len(w.bitmap) {
				newBitmap[i] |= w.bitmap[src+1] << (64 - bShift)
			}
		}
	}
	copy(w.bitmap[:], newBitmap)
	w.base += shift
}

func (w *replayWindow) get(ctr uint64) bool {
	bit := ctr - w.base
	return w.bitmap[bit/64]&(1<<(bit%64)) != 0
}

func (w *replayWindow) set(ctr uint64) {
	bit := ctr - w.base
	w.bitmap[bit/64] |= 1 << (bit % 64)
	if ctr > w.max {
		w.max = ctr
	}
}

func (w *replayWindow) clear(ctr uint64) {
	bit := ctr - w.base
	w.bitmap[bit/64] &^= 1 << (bit % 64)
}

// MaxPlainData — максимум открытого чанка WG-конверта.
const MaxPlainData = 65536 - TransportOverhead
