package tlscert

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOrCreateRoundtrip(t *testing.T) {
	dir := t.TempDir()
	b1, err := LoadOrCreate(dir, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if b1.CA == nil || len(b1.CAPin) != 43 {
		t.Fatalf("bad CA pin %q", b1.CAPin)
	}
	// Reload: same CA (pinned identity stable), same leaf.
	b2, err := LoadOrCreate(dir, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if b2.CAPin != b1.CAPin {
		t.Fatal("CA pin must be stable across reloads")
	}
	if string(b2.Leaf.Certificate[0]) != string(b1.Leaf.Certificate[0]) {
		t.Fatal("fresh leaf must be reused")
	}
	// Files exist with tight perms.
	for _, f := range []string{"ca.pem", "ca.key", "leaf.pem", "leaf.key", "leaf-ecdsa.pem"} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("%s perms: %v", f, st.Mode())
		}
	}
}

func TestLeafRotation(t *testing.T) {
	dir := t.TempDir()
	b1, err := LoadOrCreate(dir, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an old leaf: rewrite NotAfter in the past by replacing file.
	old := make([]byte, len(b1.Leaf.Certificate[0]))
	copy(old, b1.Leaf.Certificate[0])
	_ = old
	// Corrupt the leaf to force reissue (chain check fails).
	if err := os.WriteFile(filepath.Join(dir, "leaf.pem"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	b2, err := LoadOrCreate(dir, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b2.Leaf.Certificate[0]) == string(b1.Leaf.Certificate[0]) {
		t.Fatal("leaf must be reissued when invalid")
	}
	if b2.CAPin != b1.CAPin {
		t.Fatal("CA must survive leaf rotation")
	}
}

func TestLeafServesTLS(t *testing.T) {
	dir := t.TempDir()
	b, err := LoadOrCreate(dir, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{b.Leaf},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"reverseray/1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			tc := c.(*tls.Conn)
			_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
			_ = tc.Handshake()
			time.Sleep(100 * time.Millisecond)
			c.Close()
		}
	}()
	cl, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"reverseray/1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if cs := cl.ConnectionState(); cs.NegotiatedProtocol != "reverseray/1" {
		t.Fatal("ALPN must negotiate reverseray/1")
	}
	if time.Until(b.Leaf.Leaf.NotAfter) < 60*24*time.Hour {
		t.Fatal("leaf lifetime must be ~90d")
	}
}
