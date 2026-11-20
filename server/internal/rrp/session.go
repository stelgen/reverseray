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
)

// SessionConfig tunes a server-side tunnel session.
type SessionConfig struct {
	MaxStreams   int    // max concurrent streams on this tunnel
	StreamWindow uint32 // initial per-stream window (server->phone), bytes
	MaxStreamWin uint32 // max window after WINDOW increments
	Budget       int64  // total outstanding bytes cap on this session
	// v1.2.0: стартовый грант телефону на отправку — то же значение, что уходит
	// в HELLO_OK/READY tunnel_window. 0 → StreamWindow*2 (дефолт serverapp).
	TunnelWindow uint32
	// v1.3.0 «буфер трафика»: клиент объявил HELLO caps «stream-resume» —
	// сервер выдаёт RESUME_TOKEN и умеет OPEN_RESUME после реконнекта.
	ResumeCapable bool
	IdleTimeout   time.Duration // no frames -> close
	PingInterval  time.Duration // server-side keepalive
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
	// CamCtl — клиент выключил/включил камуфляж для своего устройства
	// (v0.9.5, кадр 0x2A). Вызывается из handle() (поток Run). nil — без
	// персистенции (сервер без state). Выбор хранится ПЕРМАНЕНТНО на сервере:
	// действует для будущих сессий, переживает офлайн клиента.
	CamCtl func(enabled bool)
	// v0.10: бесшовная смена протокола в живой сессии (кадр 0x2C).
	// TokenHash — хеш токена устройства (32 Б) для планов wg/bt;
	// SwitchPlanner — фабрика планов (живёт в serverapp: импортирует
	// mtproto/wg/bt; rrp не может — цикл импорта); Switchable — гейт.
	TokenHash     []byte
	SwitchPlanner func(proto string) (KeyPlan, error)
	Switchable    bool
	// v1.8.1: C→S OPEN — телефон инициирует стрим (E2E-пробник полезной
	// нагрузки ловит сигнатурную блокировку payload-кадров). Сервер диалит
	// цель своим egress, релей — канонный flow-control (stream.Write/pushIn).
	// false (zero-value) — Open от телефона отвечает OpenOk(err=1).
	PhoneOpenAllowed bool
}

func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		PhoneOpenAllowed: true, // v1.8.1: E2E-пробник клиента легален
		MaxStreams:       256,
		StreamWindow:     512 * 1024,
		MaxStreamWin:     4 * 1024 * 1024,
		Budget:           16 * 1024 * 1024,
		TunnelWindow:     1024 * 1024,
		IdleTimeout:      180 * time.Second,
		PingInterval:     60 * time.Second,
	}
}

// initialGrant — окно, которым телефон реально располагает на отправку
// (download-направление phone→server) на момент открытия стрима.
func (c SessionConfig) initialGrant() int64 {
	tw := c.TunnelWindow
	if tw == 0 {
		tw = c.StreamWindow * 2 // совместимость: serverapp шлёт StreamWindow*2
	}
	return int64(tw)
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
	// v1.2.0: наблюдаемость/гейты autotune-окон и отказов диала.
	grantedTotal int64  // суммарный прирост окон сверх стартовых (≤ Budget)
	windowGrow   uint64 // байтов autotune-прироста выдано телефону
	openErrs     uint64 // отказов диала со стороны телефона (OPEN_OK err != 0)
	pending      map[uint32]*openWait
	udpChans     map[uint32]*UdpChannel
	closed       bool
	err          error

	rtt    int64 // ms, atomic read via mu
	bin    uint64
	bout   uint64
	pingAt time.Time
	pingCh chan []byte

	// v0.8.2: камуфляж «API Mask» — rate-limit ответов NOISE (анти-амплификация:
	// не больше noiseRate ответов в минуту на сессию) и последний сброс окна.
	noiseWinStart time.Time
	noiseCount    int

	// v0.9.5: счётчики сессии для дашборда /ui (под s.mu):
	// rIn/rOut — байты payload'ов, udpDg — дейтаграммы, dnsHits —
	// запросы к порту 53 (TCP+UDP), connectedAt — время старта сессии.
	rIn         uint64
	udpDg       uint64
	dnsHits     uint64
	connectedAt time.Time

	noiseRnd *rand.Rand // генератор тел NOISE (не секретно — декоративные)

	stats *list.List // recent Stats reports
	lastS Stats

	// v0.9.2: крипто-контекст протокола (mtproto2) — включается на лету после
	// KEY_RESP. Доступ строго под s.mu (handle/writeLoop/keyTimer).
	crypto   PayloadCrypto
	keyPlan  KeyPlan
	keyTimer *time.Timer

	// v0.10: бесшовная смена протокола: пока смена идёт,
	// payload-кадры паркуются (writeAsync ждёт снятия), контрольные кадры
	// хендшейка идут свободно; pendingProto коммитится вместе с crypto.
	parked       bool
	parkGate     chan struct{}
	pendingProto string
	// v1.8.3: момент старта смены (наблюдаемость: длительность смены в
	// commitCrypto). Ставится в handleProtoSwitch, читается там же.
	switchStartedAt time.Time

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
		s.mu.Lock()
		if s.connectedAt.IsZero() {
			s.connectedAt = time.Now()
		}
		s.mu.Unlock()
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
			s.mu.Lock()
			s.rIn += uint64(len(f.Payload))
			s.mu.Unlock()
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
		if code != 0 {
			// v1.2.0: телефон не смог дial-ить таргет (недоступен с его сети,
			// blocked carrier'ом и т.п.) — считаем для наблюдаемости.
			s.openErrs++
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
		// v1.2.0: WINDOW от телефона подтверждает наши DATA (upload-направление)
		// — снимаем байты с in-flight, иначе outstand течёт вверх.
		s.outstand -= int64(inc)
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
		s.mu.Lock()
		s.udpDg++
		s.rIn += uint64(len(plain))
		s.mu.Unlock()
		s.routeUdp(&Frame{Type: TypeUdpData, Flags: f.Flags, StreamID: f.StreamID, Payload: plain})
		return nil
	case TypeWgInit:
		s.handleWgInit(f)
		return nil
	case TypeBtInit:
		s.handleBtInit(f)
		return nil
	case TypeProtoSwitch:
		s.handleProtoSwitch(f)
		return nil
	case TypeCamCtl:
		s.handleCamCtl(f)
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
	case TypeOpen:
		// v1.8.1: C→S OPEN — телефон инициирует стрим (E2E-пробник полезной
		// нагрузки). До этого — ErrProtocolOrder (регрессия v1.8.0: клиент с
		// E2E-пробником рвал сессию каждые ~5 с).
		return s.handlePhoneOpen(f)
	case TypeHello, TypeAuth, TypeHelloOK, TypeReady, TypeUdpAssoc:
		// UDP_ASSOC всегда инициирует сервер (S→C); от телефона — нарушение порядка.
		return ErrProtocolOrder
	case TypeError:
		errCode, msg := DecodeError(f.Payload)
		return fmt.Errorf("peer error %d: %s", errCode, msg)
	default:
		return ErrUnknownType
	}
}

// Protocol returns the negotiated protocol id for this session.
func (s *Session) Protocol() string { return s.cfg.Protocol }

// ---- обмен ключами протокола (v0.9.2, внутри сессии) ----

// handleKeyResp: KEY_RESP от телефона → Complete → крипто включена.
// Вызывается из Run (единственный читатель) — гонок нет.
func (s *Session) handleKeyResp(f *Frame) {
	s.mu.Lock()
	// Внутри бесшовной смены протокола (pendingProto != "") целевой обмен
	// ключами приходит ПРИ ещё живой старой крипте — KEY_RESP и есть коммит.
	if (s.crypto != nil && s.pendingProto == "") || s.keyPlan == nil {
		s.mu.Unlock()
		return // повторный/неожиданный KEY_RESP вне смены — игнор (анти-мусор)
	}
	crypto, err := s.keyPlan.Complete(f.Payload)
	if err != nil {
		s.mu.Unlock()
		s.logf("rrp: key exchange failed: %v", err)
		s.shutdown(fmt.Errorf("key exchange: %w", err))
		return
	}
	s.mu.Unlock()
	s.commitCrypto(crypto)
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
	return s.openStream(ctx, d, TypeOpen, EncodeOpen(d.ATYP, d.Addr, d.Port))
}

// OpenResume (v1.3.0 «буфер трафика») просит телефон привязать запаркованный
// сокет (телефон НЕ закрыл его при потере связи) к НОВОМУ стриму. Ответ —
// обычный OPEN_OK: 0 = привязано, 5 = сокет уже не дожил (TTL телефона) —
// тогда браузерную сторону закрываем штатно.
func (s *Session) OpenResume(ctx context.Context, token [16]byte, d DialRequest) (net.Conn, error) {
	return s.openStream(ctx, d, TypeOpenResume, append([]byte(nil), token[:]...))
}

func (s *Session) openStream(ctx context.Context, d DialRequest, ft uint8, payload []byte) (net.Conn, error) {
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
		// v1.2.0: чек снова работает — учёт outstand починен (раньше счётчик
		// уезжал в минус и бюджет не защищал память).
		return nil, errors.New("rrp: device window budget exhausted")
	}
	if d.Port == 53 {
		s.dnsHits++ // v0.9.5: счётчик DNS для дашборда
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

	errc := make(chan error, 1)
	s.outq <- outItem{frame: &Frame{Type: ft, StreamID: id, Payload: payload}, err: errc}
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
		// v1.3.0: токен резюме уходит сразу после успешного диала — телефон
		// привязывает его к своему сокету таргета (кадр только для новых клиентов).
		if ft == TypeOpen && st.hasToken {
			s.writeAsync(&Frame{Type: TypeResumeToken, StreamID: id, Payload: append([]byte(nil), st.token[:]...)})
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

// Err — причина закрытия сессии (nil, если ещё жива). Для наблюдаемости:
// сервер обязан логировать, ПОЧЕМУ туннель умер (v1.8.4).
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
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
	streams := make([]*stream, 0, len(ids))
	for _, id := range ids {
		streams = append(streams, s.streams[id])
		delete(s.streams, id)
	}
	udp := make([]*UdpChannel, 0, len(s.udpChans))
	for _, ch := range s.udpChans {
		udp = append(udp, ch)
	}
	s.udpChans = map[uint32]*UdpChannel{}
	pendings := make(map[uint32]*openWait, len(s.pending))
	for id, w := range s.pending {
		pendings[id] = w
		delete(s.pending, id)
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	// v1.2.0 (дедлок, найден тестом нарушителя под -race): markClosed теперь
	// берёт st.mu → s.mu (возврат autotune-гранта в бюджет) — вызывать его ПОД
	// s.mu нельзя (AB-BA с stream.Read, который держит st.mu и ждёт s.mu).
	// Канон порядка блокировок: st.mu → s.mu и НИКОГДА наоборот.
	for _, st := range streams {
		st.markClosed(1)
	}
	for _, ch := range udp {
		ch.closeChan()
	}
	for _, w := range pendings {
		w.ch <- ErrClosed
	}
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

// handleWgInit: бинарный кадр WG_INIT (v0.9.5, wireguard) — маршрутизация
// ---- stream ----
