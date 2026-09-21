package commands

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	lsat "github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
	samr "github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
)

const samrRead = dtyp.AccessMaskMaximumAllowed

var enumDomainsCmd = &Command{
	Name:  "enumdomains",
	Usage: "enumdomains",
	Help:  "List the SAM domains hosted by the server and their SIDs.",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		rows := [][]string{}
		for _, d := range s.Domains() {
			marker := ""
			if d.Name == s.CurrentDomain() {
				marker = "*"
			}
			rows = append(rows, []string{marker, d.Name, d.SID.String()})
		}
		out.Table([]string{"", "Domain", "SID"}, rows)
		return nil
	},
}

var useDomainCmd = &Command{
	Name:  "use",
	Usage: "use <domain>",
	Help:  "Set the active domain used by enumeration commands.",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: use <domain>")
		}
		if err := s.SetCurrentDomain(args[0]); err != nil {
			return err
		}
		out.Infof("active domain: %s", s.CurrentDomain())
		return nil
	},
}

// enumEntries iterates a RID-enumeration SAMR call and returns all entries.
func enumEntries(
	s *session.Session,
	call func(enum uint32) ([]*samr.RIDEnumeration, uint32, uint32, error),
) ([]*samr.RIDEnumeration, error) {
	var all []*samr.RIDEnumeration
	for enum := uint32(0); ; {
		batch, next, count, err := call(enum)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if enum = next; enum == 0 || count == 0 {
			break
		}
	}
	return all, nil
}

func principalTable(s *session.Session, out *output.Printer, entries []*samr.RIDEnumeration, sid *dtyp.SID) {
	rows := make([][]string, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, []string{
			strconv.FormatUint(uint64(e.RelativeID), 10),
			e.Name.Buffer,
			sid.AddRelativeID(e.RelativeID).String(),
		})
	}
	principalTableRows(out, rows)
}

func principalTableRows(out *output.Printer, rows [][]string) {
	out.Table([]string{"RID", "Name", "SID"}, rows)
}

// userFallbackStart/End bound the LSAT RID sweep used when SAMR user
// enumeration is denied by the server.
const (
	userFallbackStart = 500
	userFallbackEnd   = 1500
)

var enumDomUsersCmd = &Command{
	Name:    "enumdomusers",
	Aliases: []string{"enumusers"},
	Usage:   "enumdomusers",
	Help:    "Enumerate user accounts; falls back to LSAT RID cycling if SAMR enumeration is denied.",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		h, sid, err := s.OpenCurrentDomain()
		if err != nil {
			return err
		}
		entries, err := enumEntries(s, func(enum uint32) ([]*samr.RIDEnumeration, uint32, uint32, error) {
			resp, err := s.Samr().EnumerateUsersInDomain(s.Context(), &samr.EnumerateUsersInDomainRequest{
				Domain:             h,
				EnumerationContext: enum,
			})
			if err != nil {
				return nil, 0, 0, err
			}
			return resp.Buffer.Buffer, resp.EnumerationContext, resp.CountReturned, nil
		})
		if err == nil {
			principalTable(s, out, entries, sid)
			return nil
		}
		if !isAccessDenied(err) {
			return err
		}

		out.Infof("[!] SAMR user enumeration denied by server; falling back to LSAT RID cycling (%d-%d)",
			userFallbackStart, userFallbackEnd)
		results, ferr := CycleRIDs(s, userFallbackStart, userFallbackEnd)
		if ferr != nil {
			return fmt.Errorf("samr denied and RID cycling failed: %w", ferr)
		}
		rows := [][]string{}
		for _, r := range results {
			if r.Use != lsat.SIDNameUseTypeUser {
				continue
			}
			rows = append(rows, []string{
				strconv.FormatUint(uint64(r.RID), 10),
				r.Name,
				sid.AddRelativeID(r.RID).String(),
			})
		}
		principalTableRows(out, rows)
		return nil
	},
}

func isAccessDenied(err error) bool {
	return err != nil && strings.Contains(err.Error(), "STATUS_ACCESS_DENIED")
}

var enumDomGroupsCmd = &Command{
	Name:    "enumdomgroups",
	Aliases: []string{"enumgroups"},
	Usage:   "enumdomgroups",
	Help:    "Enumerate groups in the active domain.",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		h, sid, err := s.OpenCurrentDomain()
		if err != nil {
			return err
		}
		entries, err := enumEntries(s, func(enum uint32) ([]*samr.RIDEnumeration, uint32, uint32, error) {
			resp, err := s.Samr().EnumerateGroupsInDomain(s.Context(), &samr.EnumerateGroupsInDomainRequest{
				Domain:             h,
				EnumerationContext: enum,
			})
			if err != nil {
				return nil, 0, 0, err
			}
			return resp.Buffer.Buffer, resp.EnumerationContext, resp.CountReturned, nil
		})
		if err != nil {
			return err
		}
		principalTable(s, out, entries, sid)
		return nil
	},
}

var enumDomAliasesCmd = &Command{
	Name:    "enumdomaliases",
	Aliases: []string{"enumaliases"},
	Usage:   "enumdomaliases",
	Help:    "Enumerate aliases (local groups) in the active domain.",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		h, sid, err := s.OpenCurrentDomain()
		if err != nil {
			return err
		}
		entries, err := enumEntries(s, func(enum uint32) ([]*samr.RIDEnumeration, uint32, uint32, error) {
			resp, err := s.Samr().EnumerateAliasesInDomain(s.Context(), &samr.EnumerateAliasesInDomainRequest{
				Domain:             h,
				EnumerationContext: enum,
			})
			if err != nil {
				return nil, 0, 0, err
			}
			return resp.Buffer.Buffer, resp.EnumerationContext, resp.CountReturned, nil
		})
		if err != nil {
			return err
		}
		principalTable(s, out, entries, sid)
		return nil
	},
}

var queryUserCmd = &Command{
	Name:  "queryuser",
	Usage: "queryuser <rid|name>",
	Help:  "Show general information for a user account, by RID or account name.",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: queryuser <rid|name>")
		}
		h, sid, err := s.OpenCurrentDomain()
		if err != nil {
			return err
		}
		rid, err := resolvePrincipalRID(s, h, args[0])
		if err != nil {
			return err
		}
		open, err := s.Samr().OpenUser(s.Context(), &samr.OpenUserRequest{
			Domain:        h,
			DesiredAccess: samrRead,
			UserID:        rid,
		})
		if err != nil {
			return fmt.Errorf("open user %d: %w", rid, err)
		}
		info, err := s.Samr().QueryInformationUser(s.Context(), &samr.QueryInformationUserRequest{
			UserHandle:           open.UserHandle,
			UserInformationClass: samr.UserInformationClassGeneralInformation,
		})
		if err != nil {
			return fmt.Errorf("query user %d: %w", rid, err)
		}
		g, ok := info.Buffer.GetValue().(*samr.UserGeneralInformation)
		if !ok || g == nil {
			return fmt.Errorf("unexpected user info payload %T", info.Buffer.GetValue())
		}
		pairs := [][2]string{
			{"RID", strconv.FormatUint(uint64(rid), 10)},
			{"SID", sid.AddRelativeID(rid).String()},
			{"Username", ustr(g.UserName)},
			{"Full name", ustr(g.FullName)},
			{"Primary group", strconv.FormatUint(uint64(g.PrimaryGroupID), 10)},
			{"Admin comment", ustr(g.AdminComment)},
			{"User comment", ustr(g.UserComment)},
		}
		// Best-effort: pull the account-control (ACB) flags via the Control level.
		if ctl, err := s.Samr().QueryInformationUser(s.Context(), &samr.QueryInformationUserRequest{
			UserHandle:           open.UserHandle,
			UserInformationClass: samr.UserInformationClassControlInformation,
		}); err == nil {
			if c, ok := ctl.Buffer.GetValue().(*samr.UserControlInformation); ok {
				pairs = append(pairs, [2]string{"Flags", decodeACB(c.UserAccountControl)})
			}
		}
		out.KeyValues(pairs)
		return nil
	},
}

var getDomPwInfoCmd = &Command{
	Name:    "getdompwinfo",
	Aliases: []string{"getpwpolicy"},
	Usage:   "getdompwinfo",
	Help:    "Show the domain password policy (minimum length and properties).",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		resp, err := s.Samr().GetDomainPasswordInformation(s.Context(), &samr.GetDomainPasswordInformationRequest{})
		if err != nil {
			return fmt.Errorf("get password info: %w", err)
		}
		pw := resp.PasswordInformation
		out.KeyValues([][2]string{
			{"Minimum password length", strconv.FormatUint(uint64(pw.MinPasswordLength), 10)},
			{"Password properties", fmt.Sprintf("0x%08x", pw.PasswordProperties)},
			{"Complexity enabled", yesNo(pw.PasswordProperties&0x1 != 0)},
		})
		return nil
	},
}

func ustr(u *dtyp.UnicodeString) string {
	if u == nil {
		return ""
	}
	return u.Buffer
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
