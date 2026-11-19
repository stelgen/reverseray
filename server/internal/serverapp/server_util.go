// Package serverapp — зона «Утилиты» (remoteIP, readJSON, writeJSONTyped, tokenHashHex). Pure move из server.go (v1.8.3).
package serverapp

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

// ---- helpers ----

func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

func readJSON[T any](r interface{ Read([]byte) (int, error) }) (T, error) {
	var zero T
	f, err := rrp.ReadFrame(r)
	if err != nil {
		return zero, err
	}
	if f.Type != rrp.TypeHello && f.Type != rrp.TypeAuth {
		return zero, rrp.ErrProtocolOrder
	}
	var v T
	if err := json.Unmarshal(f.Payload, &v); err != nil {
		return zero, fmt.Errorf("json: %w", err)
	}
	return v, nil
}

func writeJSONTyped(w interface{ Write([]byte) (int, error) }, t uint8, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return rrp.WriteFrame(w, t, 0, 0, b)
}
