package commands

import "testing"

func TestUNC(t *testing.T) {
	if got := unc("10.0.0.1", `\share\f`); got != `\\10.0.0.1\share\f` {
		t.Fatalf("unc = %q", got)
	}
}

func TestCoercersCoverAllVectors(t *testing.T) {
	want := map[string]bool{"efsr": true, "rprn": true, "dfsnm": true, "fsrvp": true}
	if len(coercers) != len(want) {
		t.Fatalf("got %d coercers, want %d", len(coercers), len(want))
	}
	for _, c := range coercers {
		if !want[c.name] || c.fire == nil {
			t.Fatalf("unexpected or incomplete coercer %q", c.name)
		}
	}
}
