package commands

import (
	"fmt"
	"strings"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	lsad "github.com/oiweiwei/go-msrpc/msrpc/lsad/lsarpc/v0"
)

// TRUST_DIRECTION values from MS-ADTS.
const (
	trustDirDisabled      = 0x00000000
	trustDirInbound       = 0x00000001
	trustDirOutbound      = 0x00000002
	trustDirBidirectional = 0x00000003
)

// TRUST_TYPE values from MS-ADTS.
const (
	trustTypeDownlevel = 0x00000001 // NT 4.0 domain
	trustTypeUplevel   = 0x00000002 // Active Directory domain
	trustTypeMIT       = 0x00000003 // MIT Kerberos realm
	trustTypeDCE       = 0x00000004
)

// TRUST_ATTRIBUTE flags from MS-ADTS.
var trustAttrNames = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "NON_TRANSITIVE"},
	{0x00000002, "UPLEVEL_ONLY"},
	{0x00000004, "QUARANTINED_DOMAIN"}, // SID filtering enabled
	{0x00000008, "FOREST_TRANSITIVE"},
	{0x00000010, "CROSS_ORGANIZATION"},
	{0x00000020, "WITHIN_FOREST"},
	{0x00000040, "TREAT_AS_EXTERNAL"},
	{0x00000080, "USES_RC4_ENCRYPTION"},
	{0x00000200, "CROSS_ORGANIZATION_NO_TGT_DELEGATION"},
	{0x00000400, "PIM_TRUST"},
	{0x00000800, "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"},
}

func decodeTrustDirection(d uint32) string {
	switch d {
	case trustDirDisabled:
		return "DISABLED"
	case trustDirInbound:
		return "INBOUND"
	case trustDirOutbound:
		return "OUTBOUND"
	case trustDirBidirectional:
		return "BIDIRECTIONAL"
	default:
		return fmt.Sprintf("0x%x", d)
	}
}

func decodeTrustType(t uint32) string {
	switch t {
	case trustTypeDownlevel:
		return "DOWNLEVEL"
	case trustTypeUplevel:
		return "UPLEVEL"
	case trustTypeMIT:
		return "MIT"
	case trustTypeDCE:
		return "DCE"
	default:
		return fmt.Sprintf("0x%x", t)
	}
}

func decodeTrustAttributes(a uint32) string {
	if a == 0 {
		return "-"
	}
	var names []string
	var known uint32
	for _, f := range trustAttrNames {
		if a&f.bit != 0 {
			names = append(names, f.name)
			known |= f.bit
		}
	}
	if rest := a & ^known; rest != 0 {
		names = append(names, fmt.Sprintf("0x%x", rest))
	}
	return strings.Join(names, ",")
}

var lsaEnumTrustDomCmd = &Command{
	Name:    "lsaenumtrustdom",
	Aliases: []string{"trusts", "enumtrust"},
	Usage:   "lsaenumtrustdom",
	Help:    "Enumerate trusted domains with direction, type and attributes (LSA EnumerateTrustedDomainsEx).",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		cli, pol, err := s.LSAD()
		if err != nil {
			return err
		}
		rows := [][]string{}
		for enum := uint32(0); ; {
			resp, err := cli.EnumerateTrustedDomainsEx(s.Context(), &lsad.EnumerateTrustedDomainsExRequest{
				Policy:                 pol,
				EnumerationContext:     enum,
				PreferredMaximumLength: 0x00001000,
			})
			if err != nil {
				// An empty trust list answers STATUS_NO_MORE_ENTRIES rather than
				// returning zero entries, which is not an error for us.
				if strings.Contains(err.Error(), "STATUS_NO_MORE_ENTRIES") {
					break
				}
				return fmt.Errorf("enumerate trusted domains: %w", err)
			}
			if resp.EnumerationBuffer == nil || len(resp.EnumerationBuffer.EnumerationBuffer) == 0 {
				break
			}
			for _, t := range resp.EnumerationBuffer.EnumerationBuffer {
				if t == nil {
					continue
				}
				sid := ""
				if t.SID != nil {
					sid = t.SID.String()
				}
				rows = append(rows, []string{
					ustr(t.Name),
					ustr(t.FlatName),
					sid,
					decodeTrustDirection(t.TrustDirection),
					decodeTrustType(t.TrustType),
					decodeTrustAttributes(t.TrustAttributes),
				})
			}
			if enum = resp.EnumerationContext; enum == 0 {
				break
			}
		}
		out.Table([]string{"Name", "FlatName", "SID", "Direction", "Type", "Attributes"}, rows)
		return nil
	},
}
