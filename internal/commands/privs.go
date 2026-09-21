package commands

import (
	"fmt"
	"strings"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	lsad "github.com/oiweiwei/go-msrpc/msrpc/lsad/lsarpc/v0"
	lsat "github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
)

var lsaEnumPrivsCmd = &Command{
	Name:    "lsaenumprivs",
	Aliases: []string{"enumprivs"},
	Usage:   "lsaenumprivs",
	Help:    "Enumerate the privileges known to the target's LSA, with their local LUIDs.",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		cli, pol, err := s.LSAD()
		if err != nil {
			return err
		}
		rows := [][]string{}
		for enum := uint32(0); ; {
			resp, err := cli.EnumeratePrivileges(s.Context(), &lsad.EnumeratePrivilegesRequest{
				Policy:                 pol,
				EnumerationContext:     enum,
				PreferredMaximumLength: 0x00001000,
			})
			if err != nil {
				if strings.Contains(err.Error(), "STATUS_NO_MORE_ENTRIES") {
					break
				}
				return fmt.Errorf("enumerate privileges: %w", err)
			}
			if resp.EnumerationBuffer == nil || len(resp.EnumerationBuffer.Privileges) == 0 {
				break
			}
			for _, p := range resp.EnumerationBuffer.Privileges {
				if p == nil {
					continue
				}
				rows = append(rows, []string{ustr(p.Name), luid(p.LocalValue)})
			}
			if next := resp.EnumerationContext; next == enum || next == 0 {
				break
			} else {
				enum = next
			}
		}
		out.Table([]string{"Privilege", "LUID"}, rows)
		return nil
	},
}

var lsaEnumAccountsCmd = &Command{
	Name:    "lsaenumaccounts",
	Aliases: []string{"enumaccounts"},
	Usage:   "lsaenumaccounts",
	Help:    "Enumerate the accounts holding LSA privileges or rights, resolved to names.",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		cli, pol, err := s.LSAD()
		if err != nil {
			return err
		}
		var sids []*dtyp.SID
		for enum := uint32(0); ; {
			resp, err := cli.EnumerateAccounts(s.Context(), &lsad.EnumerateAccountsRequest{
				Policy:                 pol,
				EnumerationContext:     enum,
				PreferredMaximumLength: 0x00001000,
			})
			if err != nil {
				if strings.Contains(err.Error(), "STATUS_NO_MORE_ENTRIES") {
					break
				}
				return fmt.Errorf("enumerate accounts: %w", err)
			}
			if resp.EnumerationBuffer == nil || len(resp.EnumerationBuffer.Information) == 0 {
				break
			}
			for _, a := range resp.EnumerationBuffer.Information {
				if a != nil && a.SID != nil {
					sids = append(sids, a.SID)
				}
			}
			if next := resp.EnumerationContext; next == enum || next == 0 {
				break
			} else {
				enum = next
			}
		}

		rows := make([][]string, 0, len(sids))
		// Resolve in batches; a batch that maps nothing is not fatal.
		const batch = 64
		for lo := 0; lo < len(sids); lo += batch {
			hi := lo + batch
			if hi > len(sids) {
				hi = len(sids)
			}
			chunk := sids[lo:hi]
			resp, err := resolveSIDs(s, chunk)
			if err != nil {
				return err
			}
			for i, sid := range chunk {
				name, use := "<unmapped>", ""
				if resp != nil && resp.TranslatedNames != nil && i < len(resp.TranslatedNames.Names) {
					if tn := resp.TranslatedNames.Names[i]; tn != nil && tn.Name != nil && tn.Name.Buffer != "" {
						name = qualify(domainName(resp.ReferencedDomains, tn.DomainIndex), tn.Name.Buffer)
						use = useName(tn.Use)
					}
				}
				rows = append(rows, []string{sid.String(), name, use})
			}
		}
		out.Table([]string{"SID", "Name", "Type"}, rows)
		return nil
	},
}

var lsaEnumAcctRightsCmd = &Command{
	Name:    "lsaenumacctrights",
	Aliases: []string{"acctrights"},
	Usage:   "lsaenumacctrights <sid|name>",
	Help:    "List the privileges and system-access rights held by one account (LSA EnumerateAccountRights).",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: lsaenumacctrights <sid|name>")
		}
		sid, err := principalSID(s, args[0])
		if err != nil {
			return err
		}
		cli, pol, err := s.LSAD()
		if err != nil {
			return err
		}
		resp, err := cli.EnumerateAccountRights(s.Context(), &lsad.EnumerateAccountRightsRequest{
			Policy:     pol,
			AccountSID: sid,
		})
		if err != nil {
			// LSA has no account object for principals that hold no rights.
			if strings.Contains(err.Error(), "STATUS_OBJECT_NAME_NOT_FOUND") {
				out.Infof("%s holds no LSA rights", sid)
				return nil
			}
			return fmt.Errorf("enumerate account rights: %w", err)
		}
		rows := [][]string{}
		if resp.UserRights != nil {
			for _, r := range resp.UserRights.UserRights {
				rows = append(rows, []string{ustr(r)})
			}
		}
		out.Infof("account: %s", sid)
		out.Table([]string{"Right"}, rows)
		return nil
	},
}

// principalSID parses arg as a SID, falling back to an LSAT name lookup.
func principalSID(s *session.Session, arg string) (*dtyp.SID, error) {
	if sid, err := dtyp.ParseSID(arg); err == nil {
		return sid, nil
	}
	cli, pol, err := s.LSAT()
	if err != nil {
		return nil, err
	}
	resp, err := cli.LookupNames(s.Context(), &lsat.LookupNamesRequest{
		Policy:      pol,
		Count:       1,
		Names:       []*dtyp.UnicodeString{{Buffer: arg}},
		LookupLevel: lsat.LookupLevelWorkstation,
	})
	if err != nil {
		return nil, fmt.Errorf("lookup %q: %w", arg, err)
	}
	if resp.TranslatedSIDs == nil || len(resp.TranslatedSIDs.SIDs) == 0 {
		return nil, fmt.Errorf("could not resolve %q", arg)
	}
	ts := resp.TranslatedSIDs.SIDs[0]
	if ts == nil || ts.Use == lsat.SIDNameUseTypeUnknown {
		return nil, fmt.Errorf("could not resolve %q", arg)
	}
	dsid := domainSID(resp.ReferencedDomains, ts.DomainIndex)
	if dsid == nil {
		return nil, fmt.Errorf("could not resolve %q: no referenced domain", arg)
	}
	return dsid.AddRelativeID(ts.RelativeID), nil
}

// luid renders a LUID as the conventional high:low hex pair.
func luid(l *dtyp.LUID) string {
	if l == nil {
		return ""
	}
	return fmt.Sprintf("0x%x:0x%x", uint32(l.HighPart), l.LowPart)
}
