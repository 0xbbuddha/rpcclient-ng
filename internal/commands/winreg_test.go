package commands

import (
	"testing"

	winreg "github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
)

func TestWinregData(t *testing.T) {
	cases := []struct {
		name string
		typ  uint32
		data []byte
		want string
	}{
		{"dword little-endian", winreg.RegDword, []byte{0x2a, 0, 0, 0}, "42"},
		{"qword", winreg.RegQword, []byte{1, 0, 0, 0, 0, 0, 0, 0}, "1"},
		{"sz strips utf-16 nulls", winreg.RegString, []byte{'c', 0, ':', 0}, "c:"},
		{"multi_sz splits on nulls", winreg.RegMultistring, []byte{'a', 0, 0, 'b', 0, 0, 0}, "a, b"},
		{"binary falls back to hex", winreg.RegBinary, []byte{0xde, 0xad}, "dead"},
		{"none is empty", winreg.RegNone, []byte{1, 2}, ""},
		{"dword too short falls back to hex", winreg.RegDword, []byte{0x01}, "01"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := winregData(c.typ, c.data); got != c.want {
				t.Errorf("winregData(%s) = %q, want %q", c.name, got, c.want)
			}
		})
	}
}

func TestWinregTypeName(t *testing.T) {
	if got := winregTypeName(winreg.RegString); got != "REG_SZ" {
		t.Errorf("REG_SZ name = %q", got)
	}
	if got := winregTypeName(0x1234); got != "0x1234" {
		t.Errorf("unknown type name = %q, want 0x1234", got)
	}
}
