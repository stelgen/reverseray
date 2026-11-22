// session_rekey.go — самовосстановление крипто-конверта сессии (v1.9.9,
// «коннектор» уровень rrp: протокол-агностик, работает для mtproto2/wg/bt).
//
// Проблема (бой, 2026-11-21, sid bc3ef5d6): битый payload-конверт убивал
// сессию ("payload decrypt: bt: bad envelope") → паркинг → цикл реконнектов.
// Причина рассинхрона — телефонная сторона (гонка seal у per-stream помп),
// но сервер обязан переживать ЕДИНИЧНЫЙ сбой конверта, а не хоронить сессию
// вместе со всеми стримами.
//
// Механика:
//  1. decryptDown фейлится → кадр дропается, счётчик fails++, НЕ shutdown.
//  2. При первом фейле запускается ре-кей: свежий KEY_REQ (план генерирует
//     новый DH), телефон перестраивает конверт (BT_INIT/WG_INIT/KEY_RESP).
//  3. До коммита новой крипты старая остаётся в prev-окне (grace): кадры,
//     запечатанные телефоном до получения RESP, декодируются старым конвертом.
//  4. Лимиты: ≤ rekeyMax ре-кеев на сессию, cooldown, key-deadline. Всё
//     исчерпано — честный shutdown (как раньше), битый клиент не висит.
//
// Безопасность: KEY_REQ/INIT идут внутри TLS 1.3 + SPKI-pin + HMAC-AUTH;
// ре-кей не расширяет поверхность — это тот же обмен ключами, что при
// первичном подключении, инициированный самим сервером.
package rrp

import (
	"fmt"
	"time"
)

const (
	// RekeyMax — максимум ре-кеев на сессию: защита от цикла с битым пиром.
	RekeyMax = 3
	// rekeyCooldown — пауза между ре-кеями (один обмен ≈ RTT; чаще — мусор).
	rekeyCooldown = 2 * time.Second
	// prevGrace — сколько старый конверт остаётся валидным на приёме после
	// коммита нового (кадры в полёте, запечатанные до RESP).
	prevGrace = 15 * time.Second
	// rekeyNoiseTolerance — сколько подряд битых кадров дропаем молча, пока
	// ре-кей в полёте (мусор может прийти пачкой до достижения ключа).
	rekeyNoiseTolerance = 64
)

// onDecryptFail — реакция на битый payload-конверт. Возвращает nil, если
// сессия продолжает жить (кадр дропнут, ре-кей запущен/уже идёт), и ошибку —
// если лимиты исчерпаны (caller делает shutdown как раньше).
// Вызывается из Run (единственный читатель) — гонок нет.
func (s *Session) onDecryptFail(kind string, derr error) error {
	s.mu.Lock()
	s.fails++
	if s.rekeying {
		// Ре-кей уже в полёте: мусор до прихода ключа дропаем молча
		// (лимит по кадрам — защита от бесконечного мусоропада).
		if s.fails <= rekeyNoiseTolerance {
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		s.logf("warn", "rrp: %s: %v — re-key noise limit, session down", kind, derr)
		return fmt.Errorf("payload decrypt: %w (re-key noise limit)", derr)
	}
	now := time.Now()
	if s.rekeys >= RekeyMax || now.Sub(s.lastRekey) < rekeyCooldown {
		s.mu.Unlock()
		s.logf("warn", "rrp: %s: %v — payload decrypt failures persist, session down", kind, derr)
		return fmt.Errorf("payload decrypt: %w", derr)
	}
	s.lastRekey = now
	s.rekeys++
	s.rekeying = true
	s.mu.Unlock()

	s.logf("warn", "rrp: %s: %v — payload decrypt failed, re-key #%d (self-heal)", kind, derr, s.rekeys)
	go s.runRekey()
	return nil
}

// runRekey — повторный обмен ключами в живой сессии: свежий KEY_REQ через
// план (новый DH-секрет), телефон отвечает INIT/KEY_RESP, обработчики в
// session_handshake.go коммитят крипту и ретирят старую в prev-окно.
func (s *Session) runRekey() {
	if s.keyPlan == nil {
		s.mu.Lock()
		s.rekeying = false
		s.mu.Unlock()
		return
	}
	req, err := s.keyPlan.RequestPayload()
	if err == nil {
		erc := make(chan error, 1)
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		s.outq <- outItem{frame: &Frame{Type: TypeKeyReq, Payload: req}, err: erc}
		err = <-erc
	}
	if err != nil {
		s.mu.Lock()
		s.rekeying = false
		s.mu.Unlock()
		// Сессию не убиваем: следующим фейлом конверта решит лимит.
		s.logf("warn", "rrp: re-key request failed: %v", err)
		return
	}
	s.startKeyDeadline()
	s.logf("rrp: re-key exchange started (session %s)", s.ID)
}

// rekeyAccept — разрешить INIT/KEY_RESP при живой крипте ТОЛЬКО если это
// ожидаемый ре-кей (мы сами послали KEY_REQ и ждём ответ).
func (s *Session) rekeyAccept() bool {
	if s.crypto == nil {
		return true // первичный обмен — всегда разрешён
	}
	return s.rekeying
}

// retireCrypto — ретир активного конверта в prev-окно (grace на приёме).
func (s *Session) retireCrypto() {
	if s.crypto != nil {
		s.cryptoPrev = s.crypto
		s.prevUntil = time.Now().Add(prevGrace)
	}
	s.crypto = nil
}
