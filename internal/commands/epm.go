package commands

import (
	"fmt"
	"sort"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	epm "github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/well_known"
)

// ifaceLabel names the interface a binding exposes: its well-known name when
// known, otherwise the raw UUID, plus the "vMAJ.MIN" version. A binding with no
// interface UUID (some tower floors carry none) yields "<unknown>" and no
// version rather than dereferencing a nil UUID.
func ifaceLabel(b *dcerpc.Binding) (name, version string) {
	id := b.SyntaxID.IfUUID
	if id == nil {
		return "<unknown>", ""
	}
	if n := well_known.UUID(*id).Name(); n != "" {
		name = n
	} else {
		name = id.String()
	}
	return name, fmt.Sprintf("v%d.%d", b.SyntaxID.IfVersionMajor, b.SyntaxID.IfVersionMinor)
}

// rpcDumpAllElts is the EPM inquiry type RPC_C_EP_ALL_ELTS: return every
// registered endpoint rather than only those matching an interface.
const rpcDumpAllElts = 0x00000000

var rpcDumpCmd = &Command{
	Name:    "rpcdump",
	Aliases: []string{"epmdump"},
	Usage:   "rpcdump",
	Help:    "Dump every RPC endpoint registered with the endpoint mapper (EPM ept_lookup over TCP/135).",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		cli, conn, err := s.EPMClient()
		if err != nil {
			return err
		}
		defer conn.Close(s.Context())

		resp, err := cli.Lookup(s.Context(), &epm.LookupRequest{
			InquiryType: rpcDumpAllElts,
			MaxEntries:  500,
		})
		if err != nil {
			return fmt.Errorf("ept_lookup: %w", err)
		}

		rows := make([][]string, 0, len(resp.Entries))
		for _, e := range resp.Entries {
			if e.Tower == nil {
				continue
			}
			b := e.Tower.Binding()
			iface, version := ifaceLabel(b)
			rows = append(rows, []string{iface, version, e.Annotation, b.StringBinding.String()})
		}

		// Group related endpoints (same interface) together for readability.
		sort.SliceStable(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })

		out.Table([]string{"Interface", "Version", "Annotation", "Binding"}, rows)
		return nil
	},
}
