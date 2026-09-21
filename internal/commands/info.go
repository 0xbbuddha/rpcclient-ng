package commands

import (
	"fmt"
	"strings"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	srvsvc "github.com/oiweiwei/go-msrpc/msrpc/srvs/srvsvc/v3"
	wkssvc "github.com/oiweiwei/go-msrpc/msrpc/wkst/wkssvc/v1"
)

// SV_TYPE_* server type flags from MS-SRVS.
var serverTypeNames = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "WORKSTATION"},
	{0x00000002, "SERVER"},
	{0x00000004, "SQLSERVER"},
	{0x00000008, "DOMAIN_CTRL"},
	{0x00000010, "DOMAIN_BAKCTRL"},
	{0x00000020, "TIME_SOURCE"},
	{0x00000040, "AFP"},
	{0x00000080, "NOVELL"},
	{0x00000100, "DOMAIN_MEMBER"},
	{0x00000200, "PRINTQ_SERVER"},
	{0x00000400, "DIALIN_SERVER"},
	{0x00000800, "XENIX_SERVER"},
	{0x00001000, "NT"},
	{0x00002000, "WFW"},
	{0x00004000, "SERVER_MFPN"},
	{0x00008000, "SERVER_NT"},
	{0x00010000, "POTENTIAL_BROWSER"},
	{0x00020000, "BACKUP_BROWSER"},
	{0x00040000, "MASTER_BROWSER"},
	{0x00080000, "DOMAIN_MASTER"},
	{0x00100000, "SERVER_OSF"},
	{0x00200000, "SERVER_VMS"},
	{0x00400000, "WINDOWS"},
	{0x00800000, "DFS"},
	{0x01000000, "CLUSTER_NT"},
	{0x02000000, "TERMINALSERVER"},
	{0x04000000, "CLUSTER_VS_NT"},
	{0x10000000, "DCE"},
	{0x20000000, "ALTERNATE_XPORT"},
	{0x40000000, "LOCAL_LIST_ONLY"},
	{0x80000000, "DOMAIN_ENUM"},
}

func decodeServerType(t uint32) string {
	if t == 0 {
		return "-"
	}
	var names []string
	var known uint32
	for _, f := range serverTypeNames {
		if t&f.bit != 0 {
			names = append(names, f.name)
			known |= f.bit
		}
	}
	if rest := t & ^known; rest != 0 {
		names = append(names, fmt.Sprintf("0x%x", rest))
	}
	return strings.Join(names, ",")
}

// decodePlatformID renders a PLATFORM_ID_* value from MS-SRVS.
func decodePlatformID(id uint32) string {
	switch id {
	case 300:
		return "DOS (300)"
	case 400:
		return "OS2 (400)"
	case 500:
		return "NT (500)"
	case 600:
		return "OSF (600)"
	case 700:
		return "VMS (700)"
	default:
		return fmt.Sprint(id)
	}
}

var netServerGetInfoCmd = &Command{
	Name:    "netservergetinfo",
	Aliases: []string{"serverinfo"},
	Usage:   "netservergetinfo",
	Help:    "Show the target's server identity, OS version and server type flags (srvsvc NetrServerGetInfo, level 101).",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		cli, err := s.SRVS()
		if err != nil {
			return err
		}
		resp, err := cli.GetInfo(s.Context(), &srvsvc.GetInfoRequest{Level: 101})
		if err != nil {
			return fmt.Errorf("server get info: %w", err)
		}
		if resp.Info == nil {
			return fmt.Errorf("no server information returned")
		}
		i, ok := resp.Info.GetValue().(*dtyp.ServerInfo101)
		if !ok || i == nil {
			return fmt.Errorf("unexpected server info level %d", resp.Level)
		}
		out.KeyValues([][2]string{
			{"Name", i.Name},
			{"Platform", decodePlatformID(i.PlatformID)},
			{"OS version", fmt.Sprintf("%d.%d", i.VersionMajor, i.VersionMinor)},
			{"Server type", decodeServerType(i.VersionType)},
			{"Comment", i.Comment},
		})
		return nil
	},
}

var wkstaGetInfoCmd = &Command{
	Name:    "wkstagetinfo",
	Aliases: []string{"wkstainfo"},
	Usage:   "wkstagetinfo",
	Help:    "Show the target's workstation identity: computer name, LAN group and version (wkssvc NetrWkstaGetInfo, level 100).",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		cli, err := s.WKST()
		if err != nil {
			return err
		}
		resp, err := cli.GetInfo(s.Context(), &wkssvc.GetInfoRequest{Level: 100})
		if err != nil {
			return fmt.Errorf("wksta get info: %w", err)
		}
		if resp.WorkstationInfo == nil {
			return fmt.Errorf("no workstation information returned")
		}
		i, ok := resp.WorkstationInfo.GetValue().(*wkssvc.WorkstationInfo100)
		if !ok || i == nil {
			return fmt.Errorf("unexpected workstation info level %d", resp.Level)
		}
		out.KeyValues([][2]string{
			{"Computer name", i.ComputerName},
			{"LAN group", i.LANGroup},
			{"Platform", decodePlatformID(i.PlatformID)},
			{"OS version", fmt.Sprintf("%d.%d", i.VerMajor, i.VerMinor)},
		})
		return nil
	},
}
