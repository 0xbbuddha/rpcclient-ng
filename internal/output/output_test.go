package output

import (
	"io"
	"os"
	"strings"
	"testing"
)

// capture swaps os.Stdout for a pipe, runs f, and returns what it wrote.
func capture(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = orig
	b, _ := io.ReadAll(r)
	return string(b)
}

func TestTableNoColorPlain(t *testing.T) {
	p := &Printer{} // color off
	out := capture(t, func() { p.Table([]string{"RID", "Name"}, [][]string{{"500", "administrator"}}) })
	if strings.Contains(out, "\x1b[") || strings.Contains(out, "\xff") {
		t.Fatalf("plain output leaked escape bytes: %q", out)
	}
	if !strings.Contains(out, "RID") || !strings.Contains(out, "administrator") {
		t.Fatalf("missing content: %q", out)
	}
}

func TestTableColorAligns(t *testing.T) {
	p := &Printer{color: true}
	out := capture(t, func() {
		p.Table([]string{"RID", "Name"}, [][]string{{"500", "administrator"}, {"1104", "svc"}})
	})
	if strings.Contains(out, "\xff") {
		t.Fatalf("StripEscape markers leaked into output: %q", out)
	}
	if !strings.Contains(out, "\x1b[1;36m") {
		t.Fatalf("header color missing: %q", out)
	}
	// Column alignment: the "Name" values must start at the same screen column
	// on every data row (escape codes must not shift it).
	lines := strings.Split(strings.ReplaceAll(out, "\x1b[0m", ""), "\n")
	var cols []int
	for _, l := range lines {
		l = stripSGR(l)
		if i := strings.Index(l, "administrator"); i >= 0 {
			cols = append(cols, i)
		}
		if i := strings.Index(l, "svc"); i >= 0 {
			cols = append(cols, i)
		}
	}
	if len(cols) != 2 || cols[0] != cols[1] {
		t.Fatalf("second column misaligned: %v in %q", cols, out)
	}
}

func TestSemanticLines(t *testing.T) {
	p := &Printer{color: true}
	if got := capture(t, func() { p.Section("== X ==") }); !strings.Contains(got, "\x1b[1;36m== X ==") {
		t.Fatalf("Section color wrong: %q", got)
	}
	if got := capture(t, func() { p.Dangerf("admin") }); !strings.Contains(got, "\x1b[31madmin") {
		t.Fatalf("Dangerf color wrong: %q", got)
	}
	j := &Printer{JSON: true}
	if got := capture(t, func() { j.Section("h"); j.Dangerf("d") }); got != "" {
		t.Fatalf("JSON mode must suppress Section/Dangerf, got %q", got)
	}
}

// stripSGR removes any remaining \x1b[...m sequences so Index gives the visible column.
func stripSGR(s string) string {
	for {
		i := strings.Index(s, "\x1b[")
		if i < 0 {
			return s
		}
		j := strings.IndexByte(s[i:], 'm')
		if j < 0 {
			return s
		}
		s = s[:i] + s[i+j+1:]
	}
}
