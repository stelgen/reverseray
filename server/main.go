// Command reverseray is the server side of ReverseRay: a SOCKS5/HTTP proxy
// whose egress is a phone connected via the RRP/1 reverse tunnel.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/stelgen/reverseray/server/internal/config"
	"github.com/stelgen/reverseray/server/internal/serverapp"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "healthcheck":
		err = cmdHealthcheck(os.Args[2:])
	case "enroll":
		err = cmdEnroll(os.Args[2:])
	case "version", "--version":
		fmt.Println("reverseray", version)
	case "help", "--help", "-h":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `reverseray — reverse-proxy server (phone = egress node)

Usage:
  reverseray run [-config CONFIG.json]
  reverseray enroll [-state-dir DIR] -name DEVICE -host HOST [-port 443]
  reverseray healthcheck [-url http://127.0.0.1:9090/healthz]
  reverseray version
`)
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config.json")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	app, err := serverapp.New(cfg, log)
	if err != nil {
		return err
	}
	return app.Run(context.Background())
}

func cmdHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:9090/healthz", "admin healthz URL")
	_ = fs.Parse(args)
	return healthzHTTP(*url)
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "server state dir (default from config or /var/lib/reverseray)")
	name := fs.String("name", "", "device name")
	host := fs.String("host", "", "public host or IP of the server")
	port := fs.String("port", "443", "tunnel port (or comma list)")
	_ = fs.Parse(args)
	if *name == "" || *host == "" {
		return fmt.Errorf("enroll: -name and -host are required")
	}
	if *stateDir == "" {
		*stateDir = os.Getenv("RR_STATE_DIR")
	}
	if *stateDir == "" {
		*stateDir = "/var/lib/reverseray"
	}

	raw := make([]byte, 32)
	if _, err := cryptoRead(raw); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	hashB64 := base64.RawURLEncoding.EncodeToString(sum[:])

	pin := ""
	pinPath := filepath.Join(*stateDir, "ca.pem")
	if b, err := os.ReadFile(pinPath); err == nil {
		pin = caPinFromPEM(b)
	}

	doc := map[string]string{
		"device":        *name,
		"sha256_b64url": hashB64,
	}
	inst, _ := json.MarshalIndent(doc, "", "  ")
	fmt.Printf("# 1) Add to %s in \"devices\" and send SIGHUP (or POST /tokens/reload):\n%s\n\n",
		filepath.Join(*stateDir, "tokens.json"), inst)
	fmt.Printf("# 2) Client config string (scan/import in the app):\n")
	fmt.Printf("rrp://%s@%s:%s/?pin=%s&name=%s\n", token, *host, *port, pin, *name)
	return nil
}
