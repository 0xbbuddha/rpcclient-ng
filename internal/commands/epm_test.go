package commands

import (
	"testing"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	"github.com/oiweiwei/go-msrpc/msrpc/well_known"
)

func TestIfaceLabel(t *testing.T) {
	known := well_known.MSRPCEEndpointMapper // a UUID the well-known table names
	unknown := uuid.UUID{TimeLow: 0xdeadbeef, TimeMid: 0x1111, TimeHiAndVersion: 0x2222,
		ClockSeqHiAndReserved: 0x33, ClockSeqLow: 0x44, Node: [6]uint8{0x55, 0x66, 0x77, 0x88, 0x99, 0xaa}}

	cases := []struct {
		name        string
		b           *dcerpc.Binding
		wantName    string
		wantVersion string
	}{
		{
			name:        "known uuid resolves to its well-known name",
			b:           &dcerpc.Binding{SyntaxID: dcerpc.SyntaxID{IfUUID: &known, IfVersionMajor: 3, IfVersionMinor: 0}},
			wantName:    well_known.UUID(known).Name(),
			wantVersion: "v3.0",
		},
		{
			name:        "unknown uuid falls back to the raw uuid string",
			b:           &dcerpc.Binding{SyntaxID: dcerpc.SyntaxID{IfUUID: &unknown, IfVersionMajor: 1, IfVersionMinor: 0}},
			wantName:    unknown.String(),
			wantVersion: "v1.0",
		},
		{
			name:        "nil uuid does not panic and yields no version",
			b:           &dcerpc.Binding{SyntaxID: dcerpc.SyntaxID{IfUUID: nil}},
			wantName:    "<unknown>",
			wantVersion: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			name, version := ifaceLabel(c.b)
			if name != c.wantName {
				t.Errorf("name = %q, want %q", name, c.wantName)
			}
			if version != c.wantVersion {
				t.Errorf("version = %q, want %q", version, c.wantVersion)
			}
		})
	}

	if well_known.UUID(known).Name() == "" {
		t.Fatal("precondition: expected MSRPCEEndpointMapper to have a well-known name")
	}
}
