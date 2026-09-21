package commands

import (
	"testing"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
)

func TestDecodeTrustDirection(t *testing.T) {
	cases := map[uint32]string{
		0x00: "DISABLED",
		0x01: "INBOUND",
		0x02: "OUTBOUND",
		0x03: "BIDIRECTIONAL",
		0x09: "0x9",
	}
	for in, want := range cases {
		if got := decodeTrustDirection(in); got != want {
			t.Errorf("decodeTrustDirection(0x%x) = %q, want %q", in, got, want)
		}
	}
}

func TestDecodeTrustType(t *testing.T) {
	cases := map[uint32]string{
		0x01: "DOWNLEVEL",
		0x02: "UPLEVEL",
		0x03: "MIT",
		0x04: "DCE",
		0x07: "0x7",
	}
	for in, want := range cases {
		if got := decodeTrustType(in); got != want {
			t.Errorf("decodeTrustType(0x%x) = %q, want %q", in, got, want)
		}
	}
}

func TestDecodeTrustAttributes(t *testing.T) {
	cases := map[uint32]string{
		0x00000000: "-",
		0x00000008: "FOREST_TRANSITIVE",
		0x00000020: "WITHIN_FOREST",
		0x00000009: "NON_TRANSITIVE,FOREST_TRANSITIVE",
		0x00000024: "QUARANTINED_DOMAIN,WITHIN_FOREST",
		// An unknown bit is reported as a hex remainder next to known names.
		0x00010001: "NON_TRANSITIVE,0x10000",
		0x00010000: "0x10000",
	}
	for in, want := range cases {
		if got := decodeTrustAttributes(in); got != want {
			t.Errorf("decodeTrustAttributes(0x%x) = %q, want %q", in, got, want)
		}
	}
}

func TestDecodeServerType(t *testing.T) {
	cases := map[uint32]string{
		0x00000000: "-",
		0x00000008: "DOMAIN_CTRL",
		// The live value observed on a Windows Server 2022 DC running SQL Express.
		0x0080102f: "WORKSTATION,SERVER,SQLSERVER,DOMAIN_CTRL,TIME_SOURCE,NT,DFS",
		0x08000000: "0x8000000",
	}
	for in, want := range cases {
		if got := decodeServerType(in); got != want {
			t.Errorf("decodeServerType(0x%x) = %q, want %q", in, got, want)
		}
	}
}

func TestDecodePlatformID(t *testing.T) {
	cases := map[uint32]string{
		500: "NT (500)",
		300: "DOS (300)",
		42:  "42",
	}
	for in, want := range cases {
		if got := decodePlatformID(in); got != want {
			t.Errorf("decodePlatformID(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestDecodeShareType(t *testing.T) {
	cases := map[uint32]string{
		0x00000000: "DISK",
		0x00000001: "PRINTQ",
		0x00000003: "IPC",
		0x80000000: "DISK (SPECIAL)",
		0x80000003: "IPC (SPECIAL)",
		0xc0000000: "DISK (SPECIAL,TEMPORARY)",
	}
	for in, want := range cases {
		if got := decodeShareType(in); got != want {
			t.Errorf("decodeShareType(0x%x) = %q, want %q", in, got, want)
		}
	}
}

func TestDecodeSessFlags(t *testing.T) {
	cases := map[uint32]string{
		0x0: "-",
		0x1: "GUEST",
		0x2: "NOENCRYPTION",
		0x3: "GUEST,NOENCRYPTION",
		0x8: "0x8",
	}
	for in, want := range cases {
		if got := decodeSessFlags(in); got != want {
			t.Errorf("decodeSessFlags(0x%x) = %q, want %q", in, got, want)
		}
	}
}

func TestSecs(t *testing.T) {
	cases := map[uint32]string{
		0:    "0s",
		59:   "59s",
		90:   "1m30s",
		3661: "1h1m1s",
	}
	for in, want := range cases {
		if got := secs(in); got != want {
			t.Errorf("secs(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestLUID(t *testing.T) {
	if got := luid(nil); got != "" {
		t.Errorf("luid(nil) = %q, want empty", got)
	}
	// SeChangeNotifyPrivilege as reported by a live DC.
	if got, want := luid(&dtyp.LUID{LowPart: 0x17}), "0x0:0x17"; got != want {
		t.Errorf("luid = %q, want %q", got, want)
	}
	if got, want := luid(&dtyp.LUID{LowPart: 0xdead, HighPart: 0x1}), "0x1:0xdead"; got != want {
		t.Errorf("luid = %q, want %q", got, want)
	}
}

func TestQualify(t *testing.T) {
	cases := []struct {
		domain, name, want string
	}{
		{"SCAFFOLD", "j.harris", "SCAFFOLD\\j.harris"},
		{"", "j.harris", "j.harris"},
		{"SCAFFOLD", "", ""},
	}
	for _, c := range cases {
		if got := qualify(c.domain, c.name); got != c.want {
			t.Errorf("qualify(%q, %q) = %q, want %q", c.domain, c.name, got, c.want)
		}
	}
}

func TestLevelErr(t *testing.T) {
	base := errAccessDeniedStub("denied")
	// The higher level's error is dropped when it duplicates the fallback's.
	if got, want := levelErr("session enum", base, errAccessDeniedStub("denied"), 502).Error(), "session enum: denied"; got != want {
		t.Errorf("levelErr = %q, want %q", got, want)
	}
	if got, want := levelErr("session enum", base, errAccessDeniedStub("bad level"), 502).Error(),
		"session enum: denied (level 502: bad level)"; got != want {
		t.Errorf("levelErr = %q, want %q", got, want)
	}
	if got, want := levelErr("session enum", base, nil, 502).Error(), "session enum: denied"; got != want {
		t.Errorf("levelErr = %q, want %q", got, want)
	}
}

type errAccessDeniedStub string

func (e errAccessDeniedStub) Error() string { return string(e) }
