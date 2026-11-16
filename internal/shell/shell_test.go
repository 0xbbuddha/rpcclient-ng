package shell

import (
	"reflect"
	"testing"
)

func TestTokenize(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"enumdomusers", []string{"enumdomusers"}},
		{"addgroupmem 512 1103", []string{"addgroupmem", "512", "1103"}},
		{"addgroupmem 'Domain Admins' j.doe", []string{"addgroupmem", "Domain Admins", "j.doe"}},
		{`addgroupmem "Domain Admins" j.doe`, []string{"addgroupmem", "Domain Admins", "j.doe"}},
		{"  spaced   out  args ", []string{"spaced", "out", "args"}},
		{`a"b"c d`, []string{"abc", "d"}},
		{`createdomuser ""`, []string{"createdomuser", ""}},
	}
	for _, c := range cases {
		if got := Tokenize(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("Tokenize(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func TestSplitStatements(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"enumdomusers", []string{"enumdomusers"}},
		{"enumdomusers; enumdomgroups", []string{"enumdomusers", "enumdomgroups"}},
		{"a\nb\n\nc", []string{"a", "b", "c"}},
		{"# comment\nenumdomusers", []string{"enumdomusers"}},
		// ';' inside quotes must not split.
		{`createdomuser 'a;b'`, []string{`createdomuser 'a;b'`}},
		{`querygroupmem "Domain Admins"; queryuser j.doe`, []string{`querygroupmem "Domain Admins"`, "queryuser j.doe"}},
		{"  ;  ;  ", nil},
	}
	for _, c := range cases {
		if got := SplitStatements(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("SplitStatements(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}
