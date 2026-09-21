package commands

import (
	"testing"

	lsat "github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
)

func TestDecodeACB(t *testing.T) {
	cases := map[uint32]string{
		0:                         "-",
		acbDisabled:               "DISABLED",
		acbDontReqPreauth:         "AS-REP_ROASTABLE",
		acbPwNoExp:                "PWD_NEVER_EXPIRES",
		acbDisabled | acbPwNoExp:  "DISABLED,PWD_NEVER_EXPIRES",
		acbPwNotReq | acbAutoLock: "LOCKED,PASSWD_NOT_REQD",
		acbTrustedForDeleg:        "TRUSTED_FOR_DELEG",
		acbTrustedToAuthForDeleg:  "CONSTRAINED_DELEG",
	}
	for in, want := range cases {
		if got := decodeACB(in); got != want {
			t.Errorf("decodeACB(0x%x) = %q, want %q", in, got, want)
		}
	}
}

func TestUseName(t *testing.T) {
	cases := map[lsat.SIDNameUse]string{
		lsat.SIDNameUseTypeUser:    "User",
		lsat.SIDNameUseTypeGroup:   "Group",
		lsat.SIDNameUseTypeAlias:   "Alias",
		lsat.SIDNameUseTypeUnknown: "Unknown",
	}
	for in, want := range cases {
		if got := useName(in); got != want {
			t.Errorf("useName(%v) = %q, want %q", in, got, want)
		}
	}
}
