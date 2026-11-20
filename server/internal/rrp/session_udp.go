package rrp

import (
	"context"

	"errors"
	"sync"
)

// ---- UDP (v0.7) ----

// UdpPacket — одна дейтаграмма через туннель. Atyp/Addr/Port:
// S→C — назначение, C→S — фактический источник ответа.
type UdpPacket struct {
	Atyp byte
	Addr []byte
	Port uint16
	Data []byte
}

// UdpChannel — UDP-ассоциация поверх сессии (аналог SOCKS5 UDP ASSOCIATE).
// mu защищает close(incoming) от параллельного push — иначе гонка close/send.
type UdpChannel struct {
	id       uint32
	sess     *Session
	mu       sync.Mutex
	closed   bool
	incoming chan UdpPacket
}

func (c *UdpChannel) push(pkt UdpPacket) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	select {
	case c.incoming <- pkt:
	default:
	}
	c.mu.Unlock()
}

func (c *UdpChannel) closeChan() {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.incoming)
	}
	c.mu.Unlock()
}

// UdpOpen запрашивает у телефона UDP-ассоциацию и ждёт OPEN_OK(err_code).
func (s *Session) UdpOpen(ctx context.Context) (*UdpChannel, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	if len(s.streams)+len(s.udpChans) >= s.cfg.MaxStreams {
		s.mu.Unlock()
		return nil, errors.New("rrp: too many streams (udp assoc)")
	}
	id := s.nextID
	s.nextID += 2
	if s.nextID < 2 {
		s.nextID = 1
	}
	w := &openWait{ch: make(chan error, 1)}
	s.pending[id] = w
	ch := &UdpChannel{id: id, sess: s, incoming: make(chan UdpPacket, 64)}
	s.udpChans[id] = ch
	s.mu.Unlock()

	errc := make(chan error, 1)
	s.outq <- outItem{frame: &Frame{Type: TypeUdpAssoc, StreamID: id}, err: errc}
	if err := <-errc; err != nil {
		s.dropUdp(id)
		return nil, err
	}
	select {
	case err := <-w.ch:
		if err != nil {
			s.dropUdp(id)
			return nil, err
		}
		return ch, nil
	case <-ctx.Done():
		s.dropUdp(id)
		s.writeAsync(&Frame{Type: TypeClose, StreamID: id, Payload: EncodeClose(3)})
		return nil, ctx.Err()
	case <-s.done:
		return nil, ErrClosed
	}
}

func (s *Session) dropUdp(id uint32) {
	s.mu.Lock()
	delete(s.pending, id)
	ch := s.udpChans[id]
	delete(s.udpChans, id)
	s.mu.Unlock()
	if ch != nil {
		ch.closeChan()
	}
}

// routeUdp раздаёт входящие UDP_DATA по ассоциациям; переполнение буфера
// означает потерю дейтаграммы — допустимая семантика UDP.
func (s *Session) routeUdp(f *Frame) {
	atyp, addr, port, data, err := DecodeUdpData(f.Payload)
	if err != nil {
		return
	}
	s.mu.Lock()
	ch := s.udpChans[f.StreamID]
	s.mu.Unlock()
	if ch == nil {
		return // неизвестная ассоциация — дропаем тихо (UDP)
	}
	ch.push(UdpPacket{Atyp: atyp, Addr: append([]byte(nil), addr...), Port: port, Data: data})
}

// Send отправляет дейтаграмму телефону (неблокирующе; при переполнении
// очереди записи дейтаграмма теряется — семантика UDP).
func (c *UdpChannel) Send(atyp byte, addr []byte, port uint16, data []byte) error {
	if port == 53 {
		c.sess.mu.Lock()
		c.sess.dnsHits++ // v0.9.5: счётчик DNS для дашборда
		c.sess.mu.Unlock()
	}
	payload := EncodeUdpData(atyp, addr, port, data)
	if len(payload) > MaxDataPayload {
		return ErrFrameTooLarge
	}
	select {
	case <-c.sess.done:
		return ErrClosed
	default:
	}
	// v1.8.6 ФИКС: как и stream.Write — UDP_DATA обязан ждать коммита
	// смены протокола (паркинг), иначе кадр уходит старым конвертом.
	if !c.sess.parkWait() {
		return ErrClosed
	}
	select {
	case c.sess.outq <- outItem{frame: &Frame{Type: TypeUdpData, StreamID: c.id, Payload: payload}}:
		return nil
	default:
		return ErrUdpBacklog
	}
}

// Recv возвращает канал входящих дейтаграмм (закрывается при закрытии).
func (c *UdpChannel) Recv() <-chan UdpPacket { return c.incoming }

// Close закрывает ассоциацию (посылает CLOSE телефону).
func (c *UdpChannel) Close() {
	c.sess.mu.Lock()
	_, live := c.sess.udpChans[c.id]
	delete(c.sess.udpChans, c.id)
	c.sess.mu.Unlock()
	c.closeChan()
	if live {
		c.sess.writeAsync(&Frame{Type: TypeClose, StreamID: c.id, Payload: EncodeClose(0)})
	}
}
