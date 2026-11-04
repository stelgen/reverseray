// protoswitch.go — фабрика планов обмена ключами для бесшовной смены
// протокола (v0.10, кадр 0x2C) и учёт метрик свитчей.
//
// Фабрика живёт в serverapp: rrp не может импортировать mtproto/wg/bt
// (цикл импорта), а Session получает план через SessionConfig.SwitchPlanner.
// Целевой протокол обязан быть исполняемым этой сборкой (rrp.IsExecutable) —
// сессия никогда не «притворяется» нереализованным протоколом.
package serverapp

import (
	"fmt"

	"github.com/stelgen/reverseray/server/internal/bt"
	"github.com/stelgen/reverseray/server/internal/mtproto"
	"github.com/stelgen/reverseray/server/internal/rrp"
	"github.com/stelgen/reverseray/server/internal/wg"
)

// switchKeyPlan — план обмена ключами целевого протокола.
// Каждый вызов возвращает СВЕЖИЙ план (новые эфемерные ключи на каждый свитч).
func (a *App) switchKeyPlan(sid, device, target string) (rrp.KeyPlan, error) {
	if !rrp.IsExecutable(target) {
		return nil, fmt.Errorf("protocol %q not executable", target)
	}
	th := a.store.HashOf(device)
	switch target {
	case mtproto.ProtoID:
		return mtproto.NewServerPlan(sid, a.log), nil
	case wg.ProtoID:
		if len(th) != 32 {
			return nil, fmt.Errorf("%w: no token hash for %s", rrp.ErrKeyPlan, device)
		}
		return wg.NewServerPlan(sid, th, a.log)
	case bt.ProtoID:
		if len(th) != 32 {
			return nil, fmt.Errorf("%w: no token hash for %s", rrp.ErrKeyPlan, device)
		}
		return bt.NewServerPlan(sid, th, a.log)
	default:
		return nil, fmt.Errorf("unsupported switch target %q", target)
	}
}
