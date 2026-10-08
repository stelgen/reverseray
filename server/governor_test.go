package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Вспомогательный процесс для тестов runSupervised: тестовый бинарник
// запускает сам себя с -test.run=TestGovernorHelperProcess и env-маркером.
func TestGovernorHelperProcess(t *testing.T) {
	switch os.Getenv("RR_GOV_HELPER") {
	case "":
		return // обычный запуск тестов — пропускаем
	case "exit0":
		os.Exit(0)
	case "exit7":
		os.Exit(7)
	case "fail2":
		// два раза код 7, на третий — 0 (счётчик в файле)
		n := 0
		if b, err := os.ReadFile(os.Getenv("RR_GOV_COUNTER")); err == nil {
			n, _ = strconv.Atoi(string(b))
		}
		_ = os.WriteFile(os.Getenv("RR_GOV_COUNTER"), []byte(strconv.Itoa(n+1)), 0o600)
		if n < 2 {
			os.Exit(7)
		}
		os.Exit(0)
	case "sleep":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	default:
		os.Exit(99)
	}
}

// helperArgs — argv ребёнка: тестовый бинарник в режиме helper-процесса.
func helperArgs() []string {
	return []string{"-test.run=TestGovernorHelperProcess", "-test.count=1"}
}

// Несуществующий exe считается падением: maxFails исчерпан → 127.
func TestRunSupervisedSpawnErrorMaxFails(t *testing.T) {
	code := runSupervised("/nonexistent/reverseray-test", nil, 0, 3, nil, time.Second)
	if code != 127 {
		t.Fatalf("код = %d, хочу 127 (spawn-ошибка после maxFails)", code)
	}
}

// Чистый выход ребёнка → governor 0.
func TestRunSupervisedChildCleanExit(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("нет os.Executable")
	}
	t.Setenv("RR_GOV_HELPER", "exit0")
	code := runSupervised(exe, helperArgs(), 0, 5, nil, time.Second)
	if code != 0 {
		t.Fatalf("governor код = %d, хочу 0 (clean exit)", code)
	}
}

// Два падения, потом успех → governor 0 (рестарт работает, delay учитан).
func TestRunSupervisedRestartAfterFailures(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip()
	}
	dir := t.TempDir()
	t.Setenv("RR_GOV_HELPER", "fail2")
	t.Setenv("RR_GOV_COUNTER", filepath.Join(dir, "n"))
	code := runSupervised(exe, helperArgs(), 0, 5, nil, time.Second)
	if code != 0 {
		t.Fatalf("governor код = %d, хочу 0 (2 падения → успех)", code)
	}
}

// maxFails исчерпан → governor возвращает ненулевой код падения.
func TestRunSupervisedMaxFails(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip()
	}
	t.Setenv("RR_GOV_HELPER", "exit7")
	code := runSupervised(exe, helperArgs(), 0, 2, nil, time.Second)
	if code == 0 || code == -1 {
		t.Fatalf("governor код = %d, хочу ненулевой код падения", code)
	}
}

// SIGTERM → проброс ребёнку, governor 0, ребёнок завершён.
func TestRunSupervisedSignalForward(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip()
	}
	t.Setenv("RR_GOV_HELPER", "sleep")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sig)

	go func() {
		time.Sleep(300 * time.Millisecond)
		sig <- syscall.SIGTERM
	}()

	done := make(chan int, 1)
	go func() {
		done <- runSupervised(exe, helperArgs(), 0, 5, sig, 3*time.Second)
	}()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("governor после SIGTERM код = %d, хочу 0", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("governor не ответил на сигнал за 10 с")
	}
}

// envInt: мусор/отрицательное → дефолт; корректные значения читаются.
func TestEnvInt(t *testing.T) {
	if got := envInt("RR_NOPE", 30); got != 30 {
		t.Fatalf("envInt default = %d", got)
	}
	t.Setenv("RR_TEST_NUM", "7")
	if got := envInt("RR_TEST_NUM", 30); got != 7 {
		t.Fatalf("envInt = %d, хочу 7", got)
	}
	t.Setenv("RR_TEST_NUM", "abc")
	if got := envInt("RR_TEST_NUM", 30); got != 30 {
		t.Fatalf("envInt мусор = %d, хочу дефолт 30", got)
	}
	t.Setenv("RR_TEST_NUM", "-5")
	if got := envInt("RR_TEST_NUM", 30); got != 30 {
		t.Fatalf("envInt отрицательное = %d, хочу дефолт 30", got)
	}
}
