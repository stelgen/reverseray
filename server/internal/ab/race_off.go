//go:build !race

package ab

// raceEnabled — чистая сборка (см. ab_test.go: throughput-гейт активен).
func raceEnabled() bool { return false }
