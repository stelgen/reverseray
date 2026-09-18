package serverapp

import "testing"

func TestToU32ClampsValues(t *testing.T) {
	cases := []struct {
		in   int
		want uint32
	}{
		{-1, 0},
		{0, 0},
		{1, 1},
		{512 * 1024, 512 * 1024},
		{1 << 40, ^uint32(0)}, // huge value on 64-bit int -> capped
	}
	for _, c := range cases {
		if got := toU32(c.in); got != c.want {
			t.Fatalf("toU32(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
