package rrp

import "testing"

// v1.6.0: apimask — камуфляж «API Mask» как полноценный протокол:
// согласуется по proto=apimask, нормализуется без сюрпризов, присутствует
// в реестре/исполняемых. Старые сборки (без apimask в реестре) честно
// согласуют его в дефолт rrp1 — совместимость не ломается.
func TestApimaskProtocolNegotiation(t *testing.T) {
	if got := Negotiate("apimask", nil, DefaultProtocolID); got != "apimask" {
		t.Fatalf("Negotiate(apimask) = %q, want apimask", got)
	}
	if got := Negotiate("APIMASK ", nil, DefaultProtocolID); got != DefaultProtocolID {
		t.Fatalf("Negotiate(non-canonical case) = %q, want default %q (мусор → дефолт, канон)", got, DefaultProtocolID)
	}
	if got := Negotiate("unknown-proto-xyz", nil, DefaultProtocolID); got != DefaultProtocolID {
		t.Fatalf("Negotiate(unknown) = %q, want default %q", got, DefaultProtocolID)
	}
	if got := Negotiate("", []string{"nope", "apimask"}, DefaultProtocolID); got != "apimask" {
		t.Fatalf("Negotiate(auto offers) = %q, want apimask", got)
	}
	if !IsExecutable("apimask") {
		t.Fatal("apimask must be executable on server")
	}
	found := false
	for _, id := range SupportedIDs() {
		if id == "apimask" {
			found = true
		}
	}
	if !found {
		t.Fatal("apimask missing from SupportedIDs")
	}
}
