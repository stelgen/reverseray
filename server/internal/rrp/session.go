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
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/stelgen/reverseray/server/internal/apimasq"
)

// SessionConfig tunes a server-side tunnel session.
type SessionConfig struct {
	MaxStreams   int           // max concurrent streams on this tunnel
	StreamWindow uint32        // initial per-stream window (server->phone), bytes
	MaxStreamWin uint32        // max window after WINDOW increments
	Budget       int64         // total outstanding bytes cap on this session
	IdleTimeout  time.Duration // no frames -> close
	PingInterval time.Duration // server-side keepalive
	// Protocol — согласованный id протокола сессии (см. protocol.go).
	Protocol string
	// ProbeDialer — исходящий диал для PROBE-валидации (реальный трафик до
	// реальных хостов перед переключением протокола). nil — PROBE отключён.
	ProbeDialer func(ctx context.Context, target string, timeout time.Duration) error
	// KeyPlan — обмен ключами протокола после READY (v0.9.2): KEY_REQ уходит
	// из СЕССИИ (единственный читатель — Run), KEY_RESP читается в handle().
	// nil — протокол без обмена ключами (rrp1). Подробности — rrp/crypto.go.
	KeyPlan KeyPlan
	// Logf — журнал сессии (обмен ключами). nil — тихо.
	Logf func(format string, args ...any)
	// NoiseHook — учёт камуфляжа «API Mask» (v0.8.2): вызываетсь на каждый
	// обработанный NOISE (req, resp) — метрики сервера. nil — без учёта.
	NoiseHook func(req, resp int)
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
	Proto  string

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
	udpChans map[uint32]*UdpChannel
	closed   bool
	err      error

	rtt    int64 // ms, atomic read via mu
	bin    uint64
	bout   uint64
	pingAt time.Time
	pingCh chan []byte

	// v0.8.2: камуфляж «API Mask» — rate-limit ответов NOISE (анти-амплификация:
	// не больше noiseRate ответов в минуту на сессию) и последний сброс окна.
	noiseWinStart time.Time
	noiseCount    int

	noiseRnd *rand.Rand // генератор тел NOISE (не секретно — декоративные)

	stats *list.List // recent Stats reports
	lastS Stats

	// v0.9.2: крипто-контекст протокола (mtproto2) — включается на лету после
	// KEY_RESP. Доступ строго под s.mu (handle/writeLoop/keyTimer).
	crypto   PayloadCrypto
	keyPlan  KeyPlan
	keyTimer *time.Timer

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

// ErrUdpBacklog: очередь записи переполнена — дейтаграмма отброшена (UDP semantics).
var ErrUdpBacklog = errors.New("rrp: udp backlog, datagram dropped")

// NewSession wraps a framed transport. Call Run once.
func NewSession(id, device string, conn io.ReadWriteCloser, cfg SessionConfig) *Session {
	if cfg.MaxStreams <= 0 {
		cfg = DefaultSessionConfig()
	}
	s := &Session{
		noiseRnd: rand.New(rand.NewSource(time.Now().UnixNano() ^ int64(len(device)))),
		ID:       id,
		Device:   device,
		Proto:    cfg.Protocol,
		cfg:      cfg,
		keyPlan:  cfg.KeyPlan,
		wc:       conn,
		outq:     make(chan outItem, 256),
		streams:  make(map[uint32]*stream),
		pending:  make(map[uint32]*openWait),
		udpChans: make(map[uint32]*UdpChannel),
		pingCh:   make(chan []byte, 4),
		done:     make(chan struct{}),
	}
	s.cond = sync.NewCond(&s.mu)
	// Random stream ID base avoids cross-session ID confusion after reconnect.
	var nb [4]byte
	_, _ = crand.Read(nb[:])
	s.nextID = binary.BigEndian.Uint32(nb[:])%0xFFFF + 1
	return s
}

// Run pumps frames until the transport or the session dies.
// v0.9.2: обмен ключами протокола (mtproto2) стартует отсюда — KEY_REQ
// уходит через очередь записи, KEY_RESP читается в handle() наравне с
// PROBE/PING. Гонка «апгрейд против PROBE» невозможна by design.
func (s *Session) Run() {
	go s.writeLoop()
	go s.pingLoop()
	if s.keyPlan != nil {
		req, err := s.keyPlan.RequestPayload()
		if err == nil {
			errc := make(chan error, 1)
			s.outq <- outItem{frame: &Frame{Type: TypeKeyReq, Payload: req}, err: errc}
			err = <-errc
		}
		if err != nil {
			s.logf("rrp: key request failed: %v", err)
			s.shutdown(err)
			return
		}
		s.startKeyDeadline()
		s.logf("rrp: key exchange started (session %s)", s.ID)
	}
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
		// v0.9.2: крипто-конверт (mtproto2) — расшифровка payload на входе.
		// Битый конверт = нарушение протокола (DATA всегда идут конвертом).
		plain, err := s.decryptDown(f.Payload)
		if err != nil {
			return fmt.Errorf("payload decrypt: %w", err)
		}
		f.Payload = plain
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
		// v0.9.3 (дедлок-фикс, найден тестом многоканальности под -race):
		// markClosed берёт st.mu — раньше он вызывался ПОД s.mu, а stream.Read
		// держит st.mu и берёт s.mu (учёт outstand) → классический AB-BA:
		// handle(s.mu→st.mu) vs Read(st.mu→s.mu). Канон порядка блокировок:
		// st.mu → s.mu и НИКОГДА наоборот. markClosed не требует s.mu —
		// вызываем после Unlock (идемпотентен, сериализуется своим st.mu).
		s.mu.Lock()
		st := s.streams[f.StreamID]
		w := s.pending[f.StreamID]
		if w != nil {
			delete(s.pending, f.StreamID)
		}
		s.mu.Unlock()
		if st != nil {
			st.markClosed(f.closeCode())
		}
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
	case TypeUdpData:
		plain, err := s.decryptDown(f.Payload)
		if err != nil {
			return fmt.Errorf("udp payload decrypt: %w", err)
		}
		s.routeUdp(&Frame{Type: TypeUdpData, Flags: f.Flags, StreamID: f.StreamID, Payload: plain})
		return nil
	case TypeProbe:
		s.handleProbe(f)
		return nil
	case TypeKeyResp:
		s.handleKeyResp(f)
		return nil
	case TypeKeyReq:
		// KEY_REQ инициирует только сервер; от телефона — нарушение порядка.
		return ErrProtocolOrder
	case TypeNoise:
		s.handleNoise(f)
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
	case TypeHello, TypeAuth, TypeHelloOK, TypeReady, TypeOpen, TypeUdpAssoc:
		// UDP_ASSOC всегда инициирует сервер (S→C); от телефона — нарушение порядка.
		return ErrProtocolOrder
	case TypeError:
		errCode, msg := DecodeError(f.Payload)
		return fmt.Errorf("peer error %d: %s", errCode, msg)
	default:
		return ErrUnknownType
	}
}

// ---- PROBE (v0.7.4): валидация реального egress для смены протокола ----

type probeRequest struct {
	Target    string `json:"target"`
	TimeoutMs int64  `json:"timeout_ms"`
}

type probeResponse struct {
	OK    bool   `json:"ok"`
	Err   string `json:"err"`
	Proto string `json:"proto"`
}

// handleProbe диалит цель с сервера (егресс сервера = егресс туннеля) и
// отвечает результатом. Клиент использует это как доказательство «туннель
// реально возит трафик до реальных хостов» перед коммитом смены протокола.
func (s *Session) handleProbe(f *Frame) {
	resp := probeResponse{OK: false, Err: "probe disabled", Proto: s.cfg.Protocol}
	defer func() {
		b, _ := json.Marshal(resp)
		s.writeAsync(&Frame{Type: TypeProbe, Payload: b})
	}()
	if s.cfg.ProbeDialer == nil {
		return
	}
	var req probeRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		resp.Err = "bad probe json"
		return
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if timeout > 15*time.Second {
		timeout = 15 * time.Second
	}
	_, _, err := net.SplitHostPort(req.Target)
	if err != nil {
		resp.Err = "bad probe target"
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := s.cfg.ProbeDialer(ctx, req.Target, timeout); err != nil {
		resp.Err = err.Error()
		return
	}
	resp.OK = true
	resp.Err = ""
}

// isPayloadFrame — кадры, чьи payload'ы идут через крипто-конверт.
func isPayloadFrame(t uint8) bool { return t == TypeData || t == TypeUdpData }

// ---- NOISE (v0.8.2, модуль камуфляжа «API Mask») ----

// noiseRate — максимум ответов NOISE в минуту на сессию (анти-амплификация).
const noiseRate = 30

// noiseAllows — решение rate-limit камуфляжа (чистая логика для тестов):
// скользящее минутное окно, не больше noiseRate ответов за окно.
// Вызывается под s.mu.
func (s *Session) noiseAllows(now time.Time) bool {
	if s.noiseWinStart.IsZero() || now.Sub(s.noiseWinStart) >= time.Minute {
		s.noiseWinStart = now
		s.noiseCount = 0
	}
	s.noiseCount++
	return s.noiseCount <= noiseRate
}

// handleNoise отвечает на кадр камуфляжа: валидный JSON-запрос →
// сгенерированный JSON-ответ (API-профиль). Мусор игнорируется тихо
// (сессию НЕ рвём: шум декоративный, а рвать сессию по нему — вектор DoS).
func (s *Session) handleNoise(f *Frame) {
	if !apimasq.Valid(f.Payload) {
		return
	}
	now := time.Now()
	s.mu.Lock()
	allowed := s.noiseAllows(now)
	s.mu.Unlock()
	if !allowed {
		return
	}
	resp := apimasq.Response(s.noiseRnd, now)
	if !apimasq.Valid(resp) {
		return
	}
	// УЧЁТ ДО отправки: метрики/хук синхронны с обработкой кадра — иначе
	// наблюдатель (тест/метрики) может увидеть ответ раньше счётчика (CI-флейк).
	if s.cfg.NoiseHook != nil {
		s.cfg.NoiseHook(len(f.Payload), len(resp))
	}
	s.writeAsync(&Frame{Type: TypeNoise, Payload: resp})
}

// Protocol returns the negotiated protocol id for this session.
func (s *Session) Protocol() string { return s.cfg.Protocol }

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
	payload := EncodeUdpData(atyp, addr, port, data)
	if len(payload) > MaxDataPayload {
		return ErrFrameTooLarge
	}
	select {
	case <-c.sess.done:
		return ErrClosed
	default:
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
			err := s.emit(it.frame)
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

// emit — один кадр наружу: payload-кадры (DATA/UDP_DATA) при включённой
// крипте шифруются (конверт добавляет заголовки — открытый DATA режется на
// чанки ≤ MaxPlainData; слишком большой UDP_DATA дропается — семантика UDP).
// Вызывается только из writeLoop (горутин-эксклюзивно).
func (s *Session) emit(f *Frame) error {
	s.mu.Lock()
	crypto := s.crypto
	s.mu.Unlock()
	if crypto == nil || !isPayloadFrame(f.Type) {
		return WriteFrame(s.wc, f.Type, f.Flags, f.StreamID, f.Payload)
	}
	if f.Type == TypeUdpData {
		if len(f.Payload) > crypto.MaxPlainData() {
			return nil // дроп, UDP — без гарантий (как в mtproto wrapper)
		}
		env, err := crypto.EncryptUp(f.Payload)
		if err != nil {
			return err
		}
		return WriteFrame(s.wc, f.Type, f.Flags, f.StreamID, env)
	}
	payload := f.Payload
	max := crypto.MaxPlainData()
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > max {
			chunk = chunk[:max]
		}
		payload = payload[len(chunk):]
		env, err := crypto.EncryptUp(chunk)
		if err != nil {
			return err
		}
		if err := WriteFrame(s.wc, f.Type, f.Flags, f.StreamID, env); err != nil {
			return err
		}
	}
	return nil
}

// decryptDown расшифровывает входящий payload-кадр (если крипта включена).
// До завершения обмена ключами крипто nil — кадры идут открытыми.
func (s *Session) decryptDown(payload []byte) ([]byte, error) {
	s.mu.Lock()
	crypto := s.crypto
	s.mu.Unlock()
	if crypto == nil || len(payload) == 0 {
		return payload, nil
	}
	return crypto.DecryptDown(payload)
}

// ---- обмен ключами протокола (v0.9.2, внутри сессии) ----

// handleKeyResp: KEY_RESP от телефона → Complete → крипто включена.
// Вызывается из Run (единственный читатель) — гонок нет.
func (s *Session) handleKeyResp(f *Frame) {
	s.mu.Lock()
	if s.crypto != nil || s.keyPlan == nil {
		s.mu.Unlock()
		return // повторный/неожиданный KEY_RESP — игнор (анти-мусор)
	}
	crypto, err := s.keyPlan.Complete(f.Payload)
	if err != nil {
		s.mu.Unlock()
		s.logf("rrp: key exchange failed: %v", err)
		s.shutdown(fmt.Errorf("key exchange: %w", err))
		return
	}
	s.crypto = crypto
	if s.keyTimer != nil {
		s.keyTimer.Stop()
		s.keyTimer = nil
	}
	s.mu.Unlock()
	s.logf("rrp: payload crypto engaged (session %s, proto %s)", s.ID, s.Proto)
}

// startKeyDeadline: жёсткий дедлайн обмена ключами (битый клиент не висит
// сессией вечно — idle-таймаут слишком долгий для рукопожатия).
func (s *Session) startKeyDeadline() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyTimer = time.AfterFunc(KeyExchangeTimeout, func() {
		s.mu.Lock()
		crypto := s.crypto
		s.mu.Unlock()
		if crypto == nil {
			s.logf("rrp: key exchange timeout (%s) — closing", s.ID)
			s.shutdown(fmt.Errorf("key exchange timeout"))
		}
	})
}

func (s *Session) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
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
	udp := make([]*UdpChannel, 0, len(s.udpChans))
	for _, ch := range s.udpChans {
		udp = append(udp, ch)
	}
	s.udpChans = map[uint32]*UdpChannel{}
	for _, ch := range udp {
		ch.closeChan()
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
