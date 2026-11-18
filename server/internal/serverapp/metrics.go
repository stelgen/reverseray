package serverapp

import (
	"fmt"
	"net/http"
)

// metricsHandler — рендер /metrics (Prometheus text format).
// v1.8.0: вынесен из server.go (дробление по зонам ответственности);
// pure move — имена/порядок метрик не менялись (после apimask-канона v1.8.0).
func (a *App) metricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		m := a.met
		fmt.Fprintf(w, "# HELP reverseray_tunnels_up active tunnels\n# TYPE reverseray_tunnels_up gauge\nreverseray_tunnels_up %d\n", m.TunnelsUp.Load())
		fmt.Fprintf(w, "# HELP reverseray_streams_open open streams\n# TYPE reverseray_streams_open gauge\nreverseray_streams_open %d\n", m.StreamsOpen.Load())
		fmt.Fprintf(w, "# HELP reverseray_auth_failures_total auth failures\n# TYPE reverseray_auth_failures_total counter\nreverseray_auth_failures_total %d\n", m.AuthFailures.Load())
		fmt.Fprintf(w, "# HELP reverseray_auth_ok_total successful auths\n# TYPE reverseray_auth_ok_total counter\nreverseray_auth_ok_total %d\n", m.AuthOK.Load())
		fmt.Fprintf(w, "# HELP reverseray_inbound_conns_total inbound connections\n# TYPE reverseray_inbound_conns_total counter\nreverseray_inbound_conns_total %d\n", m.InboundConns.Load())
		fmt.Fprintf(w, "# HELP reverseray_reconnects_total tunnel connects\n# TYPE reverseray_reconnects_total counter\nreverseray_reconnects_total %d\n", m.Reconnects.Load())
		fmt.Fprintf(w, "# HELP reverseray_udp_datagrams_total udp datagrams through tunnel\n# TYPE reverseray_udp_datagrams_total counter\nreverseray_udp_datagrams_total %d\n", a.udpDatagrams())
		fmt.Fprintf(w, "# HELP reverseray_ws_tunnels active websocket tunnels\n# TYPE reverseray_ws_tunnels gauge\nreverseray_ws_tunnels %d\n", m.WsTunnels.Load())
		// v0.8: hardening (анти-скан) и модули — наблюдаемость WAN-защиты
		fmt.Fprintf(w, "# HELP reverseray_hardening_scans_total non-TLS probes classified as scans\n# TYPE reverseray_hardening_scans_total counter\nreverseray_hardening_scans_total %d\n", m.HardeningScans.Load())
		fmt.Fprintf(w, "# HELP reverseray_hardening_dropped_total non-TLS probes tarpitted/closed silently\n# TYPE reverseray_hardening_dropped_total counter\nreverseray_hardening_dropped_total %d\n", m.HardeningDropped.Load())
		fmt.Fprintf(w, "# HELP reverseray_hardening_limited_total connections rejected by concurrency limits\n# TYPE reverseray_hardening_limited_total counter\nreverseray_hardening_limited_total %d\n", m.HardeningLimited.Load())
		fmt.Fprintf(w, "# HELP reverseray_proto_sessions_non_default sessions on non-default protocol\n# TYPE reverseray_proto_sessions_non_default gauge\nreverseray_proto_sessions_non_default %d\n", m.ProtoSessions.Load())
		// v1.8.0: apimask — протокол: нейтральные имена метрик (пары/байты NOISE)
		fmt.Fprintf(w, "# HELP reverseray_apimask_protocol_pairs_total apimask protocol request/response pairs\n# TYPE reverseray_apimask_protocol_pairs_total counter\nreverseray_apimask_protocol_pairs_total %d\n", m.ApimaskPairs.Load())
		fmt.Fprintf(w, "# HELP reverseray_apimask_protocol_bytes_total apimask protocol payload bytes\n# TYPE reverseray_apimask_protocol_bytes_total counter\nreverseray_apimask_protocol_bytes_total %d\n", m.ApimaskBytes.Load())
		// v1.2.0: observability скорости — autotune-прирост окон и отказы диала
		// со стороны телефона (недоступные с его сети таргеты).
		var openErrs, winGrow uint64
		if a.hub != nil {
			for _, sm := range a.hub.Snapshot() {
				if v, ok := sm["open_errors"].(uint64); ok {
					openErrs += v
				}
				if v, ok := sm["window_grow"].(uint64); ok {
					winGrow += v
				}
			}
		}
		fmt.Fprintf(w, "# HELP reverseray_open_errors_total phone-side dial failures (target unreachable from phone network)\n# TYPE reverseray_open_errors_total counter\nreverseray_open_errors_total %d\n", openErrs)
		fmt.Fprintf(w, "# HELP reverseray_window_growth_total autotune window growth bytes granted\n# TYPE reverseray_window_growth_total counter\nreverseray_window_growth_total %d\n", winGrow)
		if a.modSync != nil {
			fmt.Fprintf(w, "# HELP reverseray_modules_version modules manifest version\n# TYPE reverseray_modules_version gauge\nreverseray_modules_version{version=%q} 1\n", a.modSync.ActiveVersion())
			fmt.Fprintf(w, "# HELP reverseray_modules_last_check_success last modules sync ok\n# TYPE reverseray_modules_last_check_success gauge\nreverseray_modules_last_check_success %d\n", boolToInt(a.modSync.LastCheckOK()))
		}
	}
}
