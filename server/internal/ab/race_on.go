//go:build race

package ab

// raceEnabled — сборка с -race (см. ab_test.go: throughput-гейт только на чистом прогоне).
func raceEnabled() bool { return true }
