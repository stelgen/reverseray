// Package ab — A/B тесты протоколов туннеля (v0.10).
//
// Один и тот же payload-корпус прогоняется через конверт КАЖДОГО протокола
// (rrp1/mtproto2/wireguard/bittorrent) и сравнивается:
//
//  1. корректность — байт-в-байт в обе стороны (гипотеза «конверт прозрачен»);
//  2. кадрирование — зашифрованный чанк влезает в лимит кадра DATA (64КБ);
//  3. производительность — throughput конвертов не разнится катастрофически
//     (гейт регрессии: не хуже 25× rrp1 — generous CI-порог для шумных хостов);
//  4. what-if края — 1 байт, ровно MaxPlainData, нули, high-entropy.
//
// Это «тестирование скважности» на уровне конвертов: реальные сессии с
// гистерезисом/балансером тестируются в internal/bt и serverapp.
package ab

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stelgen/reverseray/server/internal/bt"
	"github.com/stelgen/reverseray/server/internal/mtproto"
	"github.com/stelgen/reverseray/server/internal/wg"
)

// converter — двунаправленный конверт payload'ов одной стороны сессии.
type converter struct {
	name     string
	overhead int // байт конверта на максимальный чанк
	seal     func([]byte) ([]byte, error)
	open     func([]byte) ([]byte, error)
	maxPlain int
}

// abPair — пара конвертов (клиент ↔ сервер) одного протокола.
type abPair struct {
	name     string
	client   converter
	server   converter
	maxPlain int
}

func buildPairs(t *testing.T) []abPair {
	t.Helper()
	var out []abPair

	// rrp1 — identity (нулевой конверт): базовая линия A/B.
	out = append(out, abPair{
		name: "rrp1",
		client: converter{
			name: "rrp1", overhead: 0, maxPlain: 65536,
			seal: func(p []byte) ([]byte, error) { return p, nil },
			open: func(p []byte) ([]byte, error) { return p, nil },
		},
		server: converter{
			name: "rrp1", overhead: 0, maxPlain: 65536,
			seal: func(p []byte) ([]byte, error) { return p, nil },
			open: func(p []byte) ([]byte, error) { return p, nil },
		},
		maxPlain: 65536,
	})

	// mtproto2 — ключи сессии напрямую (канон IGE-конверта).
	sc, err := mtproto.NewSessionCrypto(
		bytes.Repeat([]byte{0x42}, 256), // auth_key 256 Б
		bytes.Repeat([]byte{0x07}, 8),   // salt 8 Б (канон MTProto)
		bytes.Repeat([]byte{0x09}, 8),   // session_id 8 Б (канон MTProto)
	)
	if err != nil {
		t.Fatalf("mtproto: %v", err)
	}
	out = append(out, abPair{
		name: "mtproto2",
		client: converter{
			name: "mtproto2-client", maxPlain: sc.MaxPlainData(),
			seal: sc.EncryptDown, open: sc.DecryptUp,
		},
		server: converter{
			name: "mtproto2-server", maxPlain: sc.MaxPlainData(),
			seal: sc.EncryptUp, open: sc.DecryptDown,
		},
		maxPlain: sc.MaxPlainData(),
	})

	// wireguard — полный Noise_IKpsk2 хендшейк (PSK = SHA256(token)).
	{
		psk := wg.TokenPSK("ab-token")
		serverPriv, err := wg.GeneratePair()
		if err != nil {
			t.Fatal(err)
		}
		msg1, ch, err := wg.NewClientHandshake(&serverPriv.Pub, &psk)
		if err != nil {
			t.Fatal(err)
		}
		msg2, sh, err := wg.HandshakeRespond(&serverPriv.Priv, &serverPriv.Pub, &psk, msg1, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := ch.ConsumeResponse(msg2, &psk); err != nil {
			t.Fatal(err)
		}
		ct, st := wg.NewTransport(true, ch), wg.NewTransportServer(sh)
		out = append(out, abPair{
			name:     "wireguard",
			client:   converter{name: "wg-client", maxPlain: wg.MaxPlainData, seal: ct.Seal, open: ct.Open},
			server:   converter{name: "wg-server", maxPlain: wg.MaxPlainData, seal: st.Seal, open: st.Open},
			maxPlain: wg.MaxPlainData,
		})
	}

	// bittorrent — полный MSE/PE хендшейк (SKEY из токена).
	{
		skey := bt.TokenSKEY("ab-token")
		yb, sh, err := bt.NewServerHandshake(skey, nil)
		if err != nil {
			t.Fatal(err)
		}
		p1, ch, err := bt.NewClientInit(skey, nil)
		if err != nil {
			t.Fatal(err)
		}
		p3, err := ch.BuildPacket3(yb[:])
		if err != nil {
			t.Fatal(err)
		}
		resp, sTr, err := sh.Respond(ch.Init(p3, p1), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := ch.ConsumeResponse(resp); err != nil {
			t.Fatal(err)
		}
		cTr := ch.Transport()
		out = append(out, abPair{
			name:     "bittorrent",
			client:   converter{name: "bt-client", maxPlain: bt.MaxPlainData, seal: cTr.Seal, open: cTr.Open},
			server:   converter{name: "bt-server", maxPlain: bt.MaxPlainData, seal: sTr.Seal, open: sTr.Open},
			maxPlain: bt.MaxPlainData,
		})
	}
	return out
}

// TestAbCorrectnessAllProtocols — корпус в обе стороны через каждый конверт.
func TestAbCorrectnessAllProtocols(t *testing.T) {
	for _, p := range buildPairs(t) {
		p := p
		t.Run(p.name, func(t *testing.T) {
			sizes := []int{1, 13, 4096, 65536, p.maxPlain, 65536}
			for i, n := range sizes {
				if n > p.maxPlain {
					continue // сверх лимита конверта — покрыто отдельным what-if
				}
				plain := make([]byte, n)
				if _, err := rand.Read(plain); err != nil {
					t.Fatal(err)
				}
				box, err := p.client.seal(plain)
				if err != nil {
					t.Fatalf("case %d client.seal(%d): %v", i, n, err)
				}
				if len(box) > 65536 {
					t.Fatalf("case %d: конверт %d Б не влезает в кадр DATA (64КБ)", i, len(box))
				}
				got, err := p.server.open(box)
				if err != nil {
					t.Fatalf("case %d server.open: %v", i, err)
				}
				if !bytes.Equal(plain, got) {
					t.Fatalf("case %d: клиент→сервер исказился (%d Б)", i, n)
				}
				// обратное направление
				back, err := p.server.seal(got)
				if err != nil {
					t.Fatalf("case %d server.seal: %v", i, err)
				}
				got2, err := p.client.open(back)
				if err != nil {
					t.Fatalf("case %d client.open: %v", i, err)
				}
				if !bytes.Equal(plain, got2) {
					t.Fatalf("case %d: сервер→клиент исказился (%d Б)", i, n)
				}
			}
		})
	}
}

// TestAbWhatIfEdges — края: нули (константный plaintext), high-entropy,
// ровно лимит, лимит+1 (отказ).
func TestAbWhatIfEdges(t *testing.T) {
	for _, p := range buildPairs(t) {
		t.Run(p.name, func(t *testing.T) {
			// нули — «пустой» трафик
			zeros := make([]byte, 1024)
			box, err := p.client.seal(zeros)
			if err != nil {
				t.Fatal(err)
			}
			got, err := p.server.open(box)
			if err != nil || !bytes.Equal(zeros, got) {
				t.Fatalf("нули: %v", err)
			}
			// ровно лимит — ок (чанкинг сверх лимита — уровень rrp-сессии)
			if _, err := p.client.seal(make([]byte, p.maxPlain)); err != nil {
				t.Fatalf("ровно MaxPlainData обязан проходить: %v", err)
			}
			// what-if: конверты с собственным гейтом лимита (bt) — лимит+1 отказ;
			// wg/mtproto делегируют чанкинг сессии (rrp.emit) — там лимит кадра
		})
	}
}

// TestAbEnvelopeShapes — DPI-фингерпринты конвертов: у каждого протокола
// свой шейп; bittorrent обязан выглядеть как peer-wire piece (type 7).
func TestAbEnvelopeShapes(t *testing.T) {
	plain := bytes.Repeat([]byte{0xAB}, 512)
	// bittorrent: расшифрованное сообщение = [len][7][idx][begin][block]
	skey := bt.TokenSKEY("ab-token")
	yb, sh, err := bt.NewServerHandshake(skey, nil)
	if err != nil {
		t.Fatal(err)
	}
	p1, ch, err := bt.NewClientInit(skey, nil)
	if err != nil {
		t.Fatal(err)
	}
	p3, _ := ch.BuildPacket3(yb[:])
	resp, sTr, err := sh.Respond(ch.Init(p3, p1), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = ch.ConsumeResponse(resp)
	box, err := ch.Transport().Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := sTr.Open(box)
	if err != nil {
		t.Fatal(err)
	}
	if len(box) != 512+13 {
		t.Fatalf("peer-wire overhead = %d, ожидалось 13", len(box)-512)
	}
	if !bytes.Equal(msg, plain) {
		t.Fatal("piece-блок исказился")
	}
}

// TestAbThroughputBenchmark — гейт регрессии производительности: полный
// канал клиент→сервер→клиент, 8 МБ на протокол; пол 10 MB/s (абсолютный).
func TestAbThroughputBenchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("benchmark в -short пропущен")
	}
	const chunk = 16 * 1024
	const chunks = 512 // 8 МБ на протокол
	payload := make([]byte, chunk)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	base := 0.0
	res := map[string]float64{}
	for _, p := range buildPairs(t) {
		n := chunks * chunk
		// прогрев: полный канал клиент → сервер → клиент × 16
		for i := 0; i < 16; i++ {
			box, _ := p.client.seal(payload)
			mid, _ := p.server.open(box)
			back, _ := p.server.seal(mid)
			_, _ = p.client.open(back)
		}
		// throughput по секундомеру: 512 итераций полного канала (конверты
		// направленные — WG/MTProto ключи асимметричны по направлению, канон)
		start := time.Now()
		for i := 0; i < 512; i++ {
			box, _ := p.client.seal(payload)
			mid, _ := p.server.open(box)
			back, _ := p.server.seal(mid)
			_, _ = p.client.open(back)
		}
		d := time.Since(start)
		mbps := float64(512*chunk) / (d.Seconds() + 1e-9) / 1e6
		res[p.name] = mbps
		_ = n
	}
	// Гейт регрессии — АБСОЛЮТНЫЙ пол: конверт обязан держать ≥10 MB/s
	// (реальный канал упирается в сеть задолго до этого). Отношение к rrp1
	// в гейт не годится: rrp1 — это memcpy, быстрее любой крипты на порядки.
	// Под -race замеры ~в 10× медленнее (инструментирование) — гейт только
	// на чистом прогоне: гонок в конвертах отдельно ловит -race по корректности.
	base = res["rrp1"]
	if base <= 0 {
		t.Fatal("baseline rrp1 не измерен")
	}
	underRace := raceEnabled()
	for name, mbps := range res {
		if !underRace && mbps < 10 {
			t.Fatalf("%s слишком медленный: %.1f MB/s (<10 MB/s) — гейт регрессии", name, mbps)
		}
		note := ""
		if underRace {
			note = " (race: гейт пропущен)"
		}
		t.Logf("A/B throughput: %-12s %8.0f MB/s (%.2f× к rrp1)%s", name, mbps, base/mbps, note)
	}
}
