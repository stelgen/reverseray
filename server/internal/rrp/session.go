package rrp

import (
	"container/list"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SessionConfig tunes a server-side tunnel session.
type SessionConfig struct {
	MaxStreams   int           // max concurrent streams on this tunnel
	StreamWindow uint32        // initial per-stream window (server->phone), bytes
	MaxStreamWin uint32        // max window after WINDOW increments
	Budget       int64         // total outstanding bytes cap on this session
	IdleTimeout  time.Duration // no frames -> close
	PingInterval time.Duration // server-side keepalive
}

func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		MaxStreams:   256,
		StreamWindow: 512 * 1024,
		MaxStreamWin: 4 * 1024 * 1024,
		Budget:       16 * 1024 * 1024,
		IdleTimeout:  180 * time.Second,
		PingInterval: 60 * time.Second,
	}
}

// DialRequest is one egress connect request.
type DialRequest struct {
	ATYP byte
	Addr []byte // IPv4/IPv6 raw or domain bytes
	Port uint16
}

func (d DialRequest) Host() string {
	if d.ATYP == ATYPDomain {
		return string(d.Addr)
	}
	return net.IP(d.Addr).String()
}

func (d DialRequest) String() string { return net.JoinHostPort(d.Host(), fmt.Sprint(d.Port)) }

// Stats is what the phone reports periodically.
type Stats struct {
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
	RTTMs    int64  `json:"rtt_ms"`
}

// Session is a server-side phone tunnel. Safe for concurrent use.
type Session struct {
	ID     string
	Device string

	cfg SessionConfig

	wmu  sync.Mutex
	wc   io.ReadWriteCloser
	outq chan outItem

	mu       sync.Mutex
	cond     *sync.Cond
	streams  map[uint32]*stream
	nextID   uint32
	outstand int64
	pending  map[uint32]*openWait
	closed   bool
	err      error

	rtt    int64 // ms, atomic read via mu
	bin    uint64
	bout   uint64
	pingAt time.Time
	pingCh chan []byte

	stats *list.List // recent Stats reports
	lastS Stats

	done chan struct{}
}

type outItem struct {
	frame *Frame
	err   chan error
}

type openWait struct {
	ch   chan error
	data chan struct{}
}

// ErrClosed is returned by ops after the session ends.
var ErrClosed = errors.New("rrp: session closed")

// NewSession wraps a framed transport. Call Run once.
func NewSession(id, device string, conn io.ReadWriteCloser, cfg SessionConfig) *Session {
	if cfg.MaxStreams <= 0 {
		cfg = DefaultSessionConfig()
	}
	s := &Session{
		ID:      id,
		Device:  device,
		cfg:     cfg,
		wc:      conn,
		outq:    make(chan outItem, 256),
		streams: make(map[uint32]*stream),
		pending: make(map[uint32]*openWait),
		pingCh:  make(chan []byte, 4),
		done:    make(chan struct{}),
	}
	s.cond = sync.NewCond(&s.mu)
	// Random stream ID base avoids cross-session ID confusion after reconnect.
	var nb [4]byte
	_, _ = crand.Read(nb[:])
	s.nextID = binary.BigEndian.Uint32(nb[:])%0xFFFF + 1
	return s
}

// Run pumps frames until the transport or the session dies.
func (s *Session) Run() {
	go s.writeLoop()
	go s.pingLoop()
	defer s.shutdown(errors.New("session ended"))
	for {
		if ds, ok := s.wc.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = ds.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		}
		f, err := ReadFrame(s.wc)
		if err != nil {
			s.shutdown(err)
			return
		}
		if err := s.handle(f); err != nil {
			s.writeAsync(&Frame{Type: TypeError, Payload: EncodeError(1, err.Error())})
			s.shutdown(err)
			return
		}
	}
}

func (s *Session) handle(f *Frame) error {
	switch f.Type {
	case TypeData:
		st := s.getStream(f.StreamID)
		if st == nil {
			// Unknown stream: ignore data, tell peer to stop.
			s.writeAsync(&Frame{Type: TypeClose, StreamID: f.StreamID, Payload: EncodeClose(2)})
			return nil
		}
		if len(f.Payload) > 0 {
			st.pushIn(f.Payload)
		}
		return nil
	case TypeOpenOK:
		s.mu.Lock()
		w := s.pending[f.StreamID]
		code := uint8(0)
		if len(f.Payload) == 1 {
			code = f.Payload[0]
		}
		if w != nil {
			delete(s.pending, f.StreamID)
		}
		s.mu.Unlock()
		if w != nil {
			w.ch <- openResultErr(code)
		}
		return nil
	case TypeClose:
		s.mu.Lock()
		st := s.streams[f.StreamID]
		if st != nil {
			st.markClosed(f.closeCode())
		}
		w := s.pending[f.StreamID]
		if w != nil {
			delete(s.pending, f.StreamID)
		}
		s.mu.Unlock()
		if st == nil && w != nil {
			w.ch <- openResultErr(1)
		}
		return nil
	case TypeWindow:
		inc, err := DecodeWindow(f.Payload)
		if err != nil {
			return err
		}
		s.mu.Lock()
		st := s.streams[f.StreamID]
		s.mu.Unlock()
		if st != nil {
			st.refill(inc)
		}
		return nil
	case TypePing:
		s.writeAsync(&Frame{Type: TypePong, Payload: f.Payload})
		return nil
	case TypePong:
		s.mu.Lock()
		if !s.pingAt.IsZero() {
			s.rtt = time.Since(s.pingAt).Milliseconds()
			s.pingAt = time.Time{}
		}
		s.mu.Unlock()
		select {
		case s.pingCh <- f.Payload:
		default:
		}
		return nil
	case TypeStats:
		var st Stats
		if err := json.Unmarshal(f.Payload, &st); err != nil {
			return fmt.Errorf("bad STATS: %w", err)
		}
		s.mu.Lock()
		s.lastS = st
		s.stats = listPush(s.stats, st)
		s.mu.Unlock()
		return nil
	case TypeHello, TypeAuth, TypeHelloOK, TypeReady, TypeOpen:
		return ErrProtocolOrder
	case TypeError:
		errCode, msg := DecodeError(f.Payload)
		return fmt.Errorf("peer error %d: %s", errCode, msg)
	default:
		return ErrUnknownType
	}
}

// ---- outbound (server -> phone) ----

func (s *Session) writeAsync(f *Frame) {
	select {
	case <-s.done:
		return
	default:
	}
	select {
	case s.outq <- outItem{frame: f}:
	case <-time.After(10 * time.Second):
		go s.shutdown(errors.New("writer backlog"))
	case <-s.done:
	}
}

func (s *Session) writeLoop() {
	for {
		select {
		case it := <-s.outq:
			err := WriteFrame(s.wc, it.frame.Type, it.frame.Flags, it.frame.StreamID, it.frame.Payload)
			if it.err != nil {
				it.err <- err
			}
			if err != nil {
				s.shutdown(err)
				return
			}
		case <-s.done:
			return
		}
	}
}

func (s *Session) pingLoop() {
	t := time.NewTicker(s.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			nonce := make([]byte, 8)
			_, _ = crand.Read(nonce)
			s.mu.Lock()
			s.pingAt = time.Now()
			s.mu.Unlock()
			s.writeAsync(&Frame{Type: TypePing, Payload: nonce})
		case <-s.done:
			return
		}
	}
}

// Open asks the phone to connect to dst and returns the stream.
func (s *Session) Open(ctx context.Context, d DialRequest) (net.Conn, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	if len(s.streams) >= s.cfg.MaxStreams {
		s.mu.Unlock()
		return nil, errors.New("rrp: too many streams")
	}
	if s.outstand >= s.cfg.Budget {
		s.mu.Unlock()
		return nil, errors.New("rrp: device window budget exhausted")
	}
	id := s.nextID
	s.nextID += 2 // odd ids are server-originated
	if s.nextID < 2 {
		s.nextID = 1
	}
	w := &openWait{ch: make(chan error, 1)}
	s.pending[id] = w
	st := newStream(s, id, d)
	s.streams[id] = st
	s.mu.Unlock()

	payload := EncodeOpen(d.ATYP, d.Addr, d.Port)
	errc := make(chan error, 1)
	s.outq <- outItem{frame: &Frame{Type: TypeOpen, StreamID: id, Payload: payload}, err: errc}
	if err := <-errc; err != nil {
		s.dropStream(id)
		return nil, err
	}

	select {
	case err := <-w.ch:
		if err != nil {
			s.dropStream(id)
			return nil, err
		}
		return st, nil
	case <-ctx.Done():
		s.dropStream(id)
		s.writeAsync(&Frame{Type: TypeClose, StreamID: id, Payload: EncodeClose(3)})
		return nil, ctx.Err()
	case <-s.done:
		return nil, ErrClosed
	}
}

func (s *Session) dropStream(id uint32) {
	s.mu.Lock()
	delete(s.pending, id)
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *Session) getStream(id uint32) *stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *Session) shutdown(err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	if s.err == nil {
		s.err = err
	}
	ids := make([]uint32, 0, len(s.streams))
	for id := range s.streams {
		ids = append(ids, id)
	}
	for _, id := range ids {
		s.streams[id].markClosed(1)
		delete(s.streams, id)
	}
	for id, w := range s.pending {
		w.ch <- ErrClosed
		delete(s.pending, id)
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	close(s.done)
	_ = s.wc.Close()
}

// Close terminates the session.
func (s *Session) Close() error {
	s.shutdown(nil)
	return nil
}

// Done fires when the session is over.
func (s *Session) Done() <-chan struct{} { return s.done }

// Outstanding returns bytes sent to the phone not yet windowed back.
func (s *Session) Outstanding() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.outstand
}

// RTT returns the last measured round-trip in ms.
func (s *Session) RTT() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rtt
}

// LastStats returns the latest STATS report from the phone.
func (s *Session) LastStats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastS
}

// ---- stream ----

type stream struct {
	sess *Session
	id   uint32
	dst  DialRequest

	mu     sync.Mutex
	cond   *sync.Cond
	inQ    [][]byte
	inLen  int
	closed bool
	cerr   uint8

	tokens chan struct{}
	winSz  uint32
}

type errOpen uint8

func (e errOpen) Error() string { return fmt.Sprintf("phone dial failed: code %d", uint8(e)) }

func openResultErr(code uint8) error {
	if code == 0 {
		return nil
	}
	return errOpen(code)
}

func (f *Frame) closeCode() uint8 {
	if len(f.Payload) == 1 {
		return f.Payload[0]
	}
	return 1
}

func newStream(s *Session, id uint32, d DialRequest) *stream {
	st := &stream{
		sess:   s,
		id:     id,
		dst:    d,
		winSz:  s.cfg.StreamWindow,
		tokens: make(chan struct{}, s.cfg.MaxStreamWin),
	}
	st.cond = sync.NewCond(&st.mu)
	for i := uint32(0); i < s.cfg.StreamWindow/1024; i++ {
		st.tokens <- struct{}{}
	}
	return st
}

func (st *stream) pushIn(b []byte) {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return
	}
	const capIn = 1 << 20 // server-side anti-abuse buffer per stream
	if st.inLen+len(b) > capIn {
		st.mu.Unlock()
		st.sess.writeAsync(&Frame{Type: TypeClose, StreamID: st.id, Payload: EncodeClose(4)})
		st.markClosed(4)
		return
	}
	cp := append([]byte(nil), b...)
	st.inQ = append(st.inQ, cp)
	st.inLen += len(cp)
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (st *stream) markClosed(code uint8) {
	st.mu.Lock()
	if !st.closed {
		st.closed = true
		st.cerr = code
	}
	st.cond.Broadcast()
	st.mu.Unlock()
}

// refill returns consumed window to the phone (WINDOW increments).
func (st *stream) refill(n uint32) {
	for i := uint32(0); i < n/1024 && i < st.winSz/1024; i++ {
		select {
		case st.tokens <- struct{}{}:
		default:
			return
		}
	}
}

func (st *stream) Read(p []byte) (int, error) {
	st.mu.Lock()
	for st.inLen == 0 && !st.closed {
		st.cond.Wait()
	}
	if st.inLen == 0 && st.closed {
		st.mu.Unlock()
		if st.cerr != 0 && st.cerr != 1 {
			return 0, fmt.Errorf("stream closed: code %d", st.cerr)
		}
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && len(st.inQ) > 0 {
		chunk := st.inQ[0]
		c := copy(p[n:], chunk)
		n += c
		if c == len(chunk) {
			st.inQ = st.inQ[1:]
		} else {
			st.inQ[0] = chunk[c:]
		}
		st.inLen -= c
		st.sess.mu.Lock()
		st.sess.outstand -= int64(c)
		st.sess.mu.Unlock()
	}
	st.mu.Unlock()
	if n > 0 {
		st.sess.writeAsync(&Frame{Type: TypeWindow, StreamID: st.id, Payload: EncodeWindow(uint32(n))})
	}
	return n, nil
}

func (st *stream) Write(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		select {
		case <-st.tokens:
		case <-st.sess.Done():
			return total, ErrClosed
		}
		st.mu.Lock()
		closed := st.closed
		st.mu.Unlock()
		if closed {
			return total, io.ErrClosedPipe
		}
		chunk := p[total:]
		if len(chunk) > MaxDataPayload {
			chunk = chunk[:MaxDataPayload]
		}
		errc := make(chan error, 1)
		st.sess.outq <- outItem{
			frame: &Frame{Type: TypeData, StreamID: st.id, Payload: append([]byte(nil), chunk...)},
			err:   errc,
		}
		if err := <-errc; err != nil {
			return total, err
		}
		st.sess.mu.Lock()
		st.sess.outstand += int64(len(chunk))
		st.sess.bout += uint64(len(chunk))
		st.sess.mu.Unlock()
		total += len(chunk)
	}
	return total, nil
}

func (st *stream) Close() error {
	st.markClosed(0)
	st.sess.writeAsync(&Frame{Type: TypeClose, StreamID: st.id, Payload: EncodeClose(0)})
	st.sess.dropStream(st.id)
	return nil
}

func (st *stream) LocalAddr() net.Addr  { return addrString("rrp-stream") }
func (st *stream) RemoteAddr() net.Addr { return addrString(st.dst.String()) }
func (st *stream) SetDeadline(t time.Time) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	// Best-effort: wake readers on deadline.
	if !t.IsZero() {
		time.AfterFunc(time.Until(t), st.cond.Broadcast)
	}
	return nil
}
func (st *stream) SetReadDeadline(t time.Time) error  { return st.SetDeadline(t) }
func (st *stream) SetWriteDeadline(t time.Time) error { return nil }

type addrString string

func (a addrString) Network() string { return "rrp" }
func (a addrString) String() string  { return string(a) }

func listPush(l *list.List, v Stats) *list.List {
	if l == nil {
		l = list.New()
	}
	l.PushBack(v)
	for l.Len() > 32 {
		l.Remove(l.Front())
	}
	return l
}
