// v1.9.0: зона «жизненный цикл сессии» вынесена из session.go (транш-2):
// Err/shutdown/Close/Done, счётчики Outstanding/RTT/LastStats.
package rrp

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
