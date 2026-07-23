package scanner

import (
	"strings"
	"testing"
)

func TestMutateIsBoundedDeterministicAndContextAware(t *testing.T) {
	left, err := Mutate(`a b"c`, "auto", 7)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Mutate(`a b"c`, "auto", 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 7 || strings.Join(left, "\x00") != strings.Join(right, "\x00") {
		t.Fatalf("mutations are not deterministic and bounded: %#v %#v", left, right)
	}
	if _, err := Mutate("probe", "unknown", 10); err == nil {
		t.Fatal("unknown strategy was accepted")
	}
	if _, err := Mutate(strings.Repeat("x", 64*1024+1), "auto", 10); err == nil {
		t.Fatal("oversized payload was accepted")
	}
}
