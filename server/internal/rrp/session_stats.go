package rrp

import (
	"time"
)

// ---- v0.9.5: счётчики для дашборда /ui (под s.mu) ----

// Relayed — байты payload'ов сессии: fromPhone (к клиентам), toPhone.
func (s *Session) Relayed() (fromPhone uint64, toPhone uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rIn, s.bout
}

// StreamsOpen — открытых стримов прямо сейчас.
func (s *Session) StreamsOpen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams)
}

// ConnectedAt — момент первого кадра сессии.
func (s *Session) ConnectedAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connectedAt
}

// MTActive — включён ли крипто-конверт протокола (mtproto2/wireguard).
func (s *Session) MTActive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.crypto != nil
}

// UdpDatagrams — дейтаграмм принято от телефона.
func (s *Session) UdpDatagrams() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udpDg
}

// DnsHits — запросы к порту 53 в этой сессии (TCP Open + UDP Send).
func (s *Session) DnsHits() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dnsHits
}

// OpenErrors — отказов диала со стороны телефона за жизнь сессии
// (v1.2.0: недоступные/заблокированные egress-сетью телефона таргеты).
func (s *Session) OpenErrors() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openErrs
}

// WindowGrowTotal — сколько байтов autotune-прироста окна выдано (v1.2.0).
func (s *Session) WindowGrowTotal() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.windowGrow
}

// WindowGrantTotal — суммарное окно, выданное телефону сейчас, все стримы
// (v1.2.0, наблюдаемость autotune). Порядок блокировок канонический:
// s.mu → (unlock) → st.mu — никогда не наоборот.
func (s *Session) WindowGrantTotal() int64 {
	s.mu.Lock()
	sts := make([]*stream, 0, len(s.streams))
	for _, st := range s.streams {
		sts = append(sts, st)
	}
	s.mu.Unlock()
	var t int64
	for _, st := range sts {
		st.mu.Lock()
		t += st.grant
		st.mu.Unlock()
	}
	return t
}
