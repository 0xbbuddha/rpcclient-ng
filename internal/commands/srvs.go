package commands

import (
	"fmt"
	"strings"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	srvsvc "github.com/oiweiwei/go-msrpc/msrpc/srvs/srvsvc/v3"
)

// SHARE_TYPE (STYPE_*) flags from MS-SRVS.
const (
	stypeDisktree = 0x00000000
	stypePrintq   = 0x00000001
	stypeDevice   = 0x00000002
	stypeIPC      = 0x00000003
	stypeMask     = 0x0000000f
	stypeTemp     = 0x40000000
	stypeSpecial  = 0x80000000
)

func decodeShareType(t uint32) string {
	var base string
	switch t & stypeMask {
	case stypeDisktree:
		base = "DISK"
	case stypePrintq:
		base = "PRINTQ"
	case stypeDevice:
		base = "DEVICE"
	case stypeIPC:
		base = "IPC"
	default:
		base = fmt.Sprintf("0x%x", t&stypeMask)
	}
	var flags []string
	if t&stypeSpecial != 0 {
		flags = append(flags, "SPECIAL")
	}
	if t&stypeTemp != 0 {
		flags = append(flags, "TEMPORARY")
	}
	if len(flags) > 0 {
		return base + " (" + strings.Join(flags, ",") + ")"
	}
	return base
}

var netShareEnumCmd = &Command{
	Name:    "netshareenum",
	Aliases: []string{"shares"},
	Usage:   "netshareenum",
	Help:    "Enumerate the shared resources on the target (srvsvc NetrShareEnum, level 1).",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		cli, err := s.SRVS()
		if err != nil {
			return err
		}
		resp, err := cli.ShareEnum(s.Context(), &srvsvc.ShareEnumRequest{
			Info: &srvsvc.ShareEnum{
				Level: 1,
				ShareInfo: &srvsvc.ShareEnumUnion{
					Value: &srvsvc.ShareEnumUnion_Level1{Level1: &srvsvc.ShareInfo1Container{}},
				},
			},
			PreferredMaximumLength: 0xffffffff,
		})
		if err != nil {
			return fmt.Errorf("share enum: %w", err)
		}
		rows := [][]string{}
		if resp.Info != nil && resp.Info.ShareInfo != nil {
			if c, ok := resp.Info.ShareInfo.GetValue().(*srvsvc.ShareInfo1Container); ok {
				for _, sh := range c.Buffer {
					rows = append(rows, []string{
						sh.NetworkName,
						decodeShareType(sh.Type),
						sh.Remark,
					})
				}
			}
		}
		out.Table([]string{"Share", "Type", "Remark"}, rows)
		return nil
	},
}
