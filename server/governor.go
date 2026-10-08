package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// v0.8.3: restart-governor БЕЗ busybox и шеллов (канон: distroless не содержит
// ни утилит, ни интерпретаторов). Прежний вариант (docker-entrypoint.sh +
// /bin/busybox из alpine) ломал запуск образа на проде: busybox в alpine —
// динамический PIE с интерпретатором /lib/ld-musl-x86_64.so.1, которого в
// distroless нет → «exec /bin/busybox: no such file or directory».
// CI это не ловил: docker-джоба гоняла образ с --entrypoint /reverseray,
// минуя губернатора. Теперь supervisor — подкоманда самого статического
// бинаря /reverseray: exec невозможен мимо существующего файла.
//
// Семантика прежняя (v0.8):
//   - чистый выход ребёнка (код 0) → governor завершается с 0;
//   - падение → рестарт не чаще RR_RESTART_DELAY секунд (по умолчанию 30);
//   - RR_RESTART_MAX падений ПОДРЯД (по умолчанию 20) → governor выходит
//     с кодом последнего падения: Docker видит умерший контейнер,
//     а не бесконечный crash-loop.
//   - SIGTERM/SIGINT (docker stop) → проброс ребёнку, чистый выход 0.

const (
	govDefaultDelay = 30
	govDefaultMax   = 20
	// Сколько ждём ребёнка после проброса SIGTERM, прежде чем убить (docker
	// сам жёстко прибивает через SIGKILL по своему таймауту).
	govKillGrace = 10 * time.Second
)

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

func cmdGovernor(args []string) error {
	delay := envInt("RR_RESTART_DELAY", govDefaultDelay)
	maxFails := envInt("RR_RESTART_MAX", govDefaultMax)
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = os.Args[0]
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	if code := runSupervised(exe, args, delay, maxFails, sig, govKillGrace); code != 0 {
		return fmt.Errorf("governor: выход с кодом %d", code)
	}
	return nil
}

// runSupervised — ядро губернатора, изолировано от глобального состояния
// (exe/args/сигналы — параметры) и тестируется в governor_test.go через
// вспомогательный процесс без Docker.
func runSupervised(exe string, childArgs []string, delay, maxFails int, sig <-chan os.Signal, grace time.Duration) int {
	fails := 0
	for {
		cmd := exec.Command(exe, childArgs...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "governor: не удалось запустить %s: %v\n", exe, err)
			fails++
			if maxFails > 0 && fails >= maxFails {
				return 127
			}
			govSleep(delay)
			continue
		}
		done := make(chan int, 1)
		go func() {
			waitErr := cmd.Wait()
			code := 0
			if waitErr != nil {
				if ee, ok := waitErr.(*exec.ExitError); ok {
					code = ee.ExitCode()
				} else {
					code = 1
				}
			}
			done <- code
		}()

		select {
		case code := <-done:
			if code == 0 {
				fmt.Fprintln(os.Stderr, "governor: reverseray завершился чисто (0)")
				return 0
			}
			fails++
			if maxFails > 0 && fails >= maxFails {
				fmt.Fprintf(os.Stderr, "governor: FATAL — %d падений подряд; отдаём контейнер Docker (не крутим бесконечный цикл)\n", fails)
				return code
			}
			fmt.Fprintf(os.Stderr, "governor: reverseray упал (код %d, подряд %d/%d) — рестарт через %d с\n", code, fails, maxFails, delay)
			govSleep(delay)
		case s := <-sig:
			fmt.Fprintf(os.Stderr, "governor: получен сигнал %s — передаю ребёнку и выхожу чисто\n", s)
			_ = cmd.Process.Signal(s)
			select {
			case <-done:
			case <-time.After(grace):
				_ = cmd.Process.Kill()
				<-done
			}
			return 0
		}
	}
}

func govSleep(seconds int) {
	if seconds > 0 {
		time.Sleep(time.Duration(seconds) * time.Second)
	}
}
