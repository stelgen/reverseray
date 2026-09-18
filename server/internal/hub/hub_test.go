package hub

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stelgen/reverseray/server/internal/rrp"
)

type rwCloser struct{ net.Conn }

func TestAttachDialDetach(t *testing.T) {
	h := New()
	c1, c2 := net.Pipe()
	defer c2.Close()
	sess := rrp.NewSession("s1", "phone-1", rwCloser{c1}, rrp.DefaultSessionConfig())
	go sess.Run()
	if err := h.Attach("phone-1", sess, 8); err != nil {
		t.Fatal(err)
	}
	if err := h.Attach("phone-1", sess, 1); err == nil {
		t.Fatal("tunnel cap must be enforced")
	}

	// Phone side answers OPEN with success + echo.
	go func() {
		for {
			f, err := rrp.ReadFrame(c2)
			if err != nil {
				return
			}
			switch f.Type {
			case rrp.TypeOpen:
				rrp.WriteFrame(c2, rrp.TypeOpenOK, 0, f.StreamID, []byte{0})
			case rrp.TypeData:
				rrp.WriteFrame(c2, rrp.TypeData, 0, f.StreamID, f.Payload)
			}
		}
	}()

	conn, err := h.Dial(context.Background(), rrp.ATYPDomain, []byte("example.com"), 443, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	if len(h.Snapshot()) != 1 {
		t.Fatal("snapshot must show one session")
	}
	if h.Kick("phone-1") != 1 {
		t.Fatal("kick must terminate one session")
	}
	if _, err := h.Dial(context.Background(), 1, []byte{1, 2, 3, 4}, 80, time.Second); err == nil {
		t.Fatal("dial after kick must fail")
	}
	if h.Kick("ghost") != 0 {
		t.Fatal("kick unknown device = 0")
	}
}
