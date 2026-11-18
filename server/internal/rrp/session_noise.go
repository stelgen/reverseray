package rrp

import (
	"time"

	"github.com/stelgen/reverseray/server/internal/apimasq"
)

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
