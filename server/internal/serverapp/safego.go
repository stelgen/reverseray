// safego.go — panic-safety (v0.8): ни одна горутина, обрабатывающая
// недоверенный ввод, не может уронить процесс. Паника логируется и
// гасится; соединение закрывается.
package serverapp

import (
	"net/http"
	"runtime/debug"
)

// recoverGoroutine — defer в горутине: гасит панику, логирует стектрейс.
func (a *App) recoverGoroutine(where string) {
	if r := recover(); r != nil {
		a.log.Error("panic recovered", "where", where, "panic", r, "stack", string(debug.Stack()))
	}
}

// safeHandler — HTTP-мидлварь: паника внутри обработчика → 500 без утечки
// деталей (текст ошибки НЕ возвращается клиенту — только в лог).
func (a *App) safeHandler(name string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				a.log.Error("panic in admin handler", "handler", name, "panic", rec, "stack", string(debug.Stack()))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	}
}

// secureHeaders — минимум заголовков для admin-эндпоинтов (включая /ui):
// noindex уже стоит на /ui и /status, добавляем остальное.
func secureHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	}
}
