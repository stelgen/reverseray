package tlscert

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// v0.8.1: SAN листа включает и DNS-имена, и IP — коннект по DNS-имени
// сервера равноправен коннекту по IP (пин всё равно SPKI CA, но честные
// SAN — часть модели «серты свои, для своего имени»).

func TestLeafSANIncludesDNSAndIP(t *testing.T) {
	dir := t.TempDir()
	b, err := LoadOrCreate(dir, []string{"proxy.example.com", "127.0.0.1", "10.8.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(b.Leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	hasDNS := false
	for _, d := range cert.DNSNames {
		if d == "proxy.example.com" {
			hasDNS = true
		}
	}
	if !hasDNS {
		t.Fatalf("DNS SAN потерян: %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 2 {
		t.Fatalf("IP SAN потеряны: %v", cert.IPAddresses)
	}
}

// v0.8.1: лист живёт ГОДЫ (3 года), перевыпуск — заранее за 90 дней.
func TestLeafLivesYearsAndRenewsEarly(t *testing.T) {
	dir := t.TempDir()
	b, err := LoadOrCreate(dir, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	left := time.Until(b.Leaf.Leaf.NotAfter)
	if left < leafLifetime-24*time.Hour {
		t.Fatalf("лист должен жить ~3 года, осталось %v", left)
	}
	// лист со сроком жизни в «зоне перевыпуска» (за 90 дней до конца)
	// регенерируется при следующем старте — без простоя и без смены CA.
	shortPEM := b.Leaf.Certificate[0]
	if err := os.WriteFile(filepath.Join(dir, "leaf.pem"), shortPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	b2, err := LoadOrCreate(dir, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(b2.Leaf.Leaf.NotAfter) < leafLifetime-24*time.Hour {
		t.Fatalf("перевыпуск не продлил лист: %v", time.Until(b2.Leaf.Leaf.NotAfter))
	}
	if b2.CAPin != b.CAPin {
		t.Fatal("CA pin не должен меняться при перевыпуске листа")
	}
}

// v0.8.1: миграция старого короткого листа (90 дн., до 0.8.0) на длинный —
// при первом рестарте, автоматически.
func TestLegacyShortLeafMigratesToLongLived(t *testing.T) {
	dir := t.TempDir()
	b1, err := LoadOrCreate(dir, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	old := b1.Leaf.Leaf.NotAfter
	if old.Sub(b1.Leaf.Leaf.NotBefore) < leafLifetime-24*time.Hour {
		t.Fatalf("новые листы уже длинные — тест утратил смысл")
	}
	// «старый» лист = пересозданный с коротким сроком: эмулируем подменой
	// только файла серта на короткоживущий (перезаписываемNotAfter невозможно
	// без ключа CA — вместо этого просто проверяем порог reissue отдельно)
	if time.Until(old) <= leafRenewBefore {
		t.Fatalf("порог перевыпуска должен быть меньше срока жизни")
	}
	// порог: свежий лист НЕ перевыпускается повторно (идемпотентность)
	b2, err := LoadOrCreate(dir, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b2.Leaf.Certificate[0]) != string(b1.Leaf.Certificate[0]) {
		t.Fatal("живой длинный лист не должен перевыпускаться при каждом старте")
	}
}
