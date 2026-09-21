package commands

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	lsat "github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
)

// resolveSIDs translates a batch of SIDs to names via LSAT. A batch where no
// SID maps returns STATUS_NONE_MAPPED, which we treat as an empty (non-fatal)
// result so RID-cycling sweeps can continue past gaps.
func resolveSIDs(s *session.Session, sids []*dtyp.SID) (*lsat.LookupSIDsResponse, error) {
	cli, pol, err := s.LSAT()
	if err != nil {
		return nil, err
	}
	info := make([]*lsat.SIDInformation, 0, len(sids))
	for _, sid := range sids {
		info = append(info, &lsat.SIDInformation{SID: sid})
	}
	resp, err := cli.LookupSIDs(s.Context(), &lsat.LookupSIDsRequest{
		Policy:          pol,
		SIDEnumBuffer:   &lsat.SIDEnumBuffer{Entries: uint32(len(info)), SIDInfo: info},
		TranslatedNames: &lsat.TranslatedNames{},
		LookupLevel:     lsat.LookupLevelWorkstation,
	})
	if err != nil {
		if strings.Contains(err.Error(), "STATUS_NONE_MAPPED") {
			return resp, nil
		}
		return nil, err
	}
	return resp, nil
}

func domainName(refs *lsat.ReferencedDomainList, idx int32) string {
	if refs == nil || idx < 0 || int(idx) >= len(refs.Domains) {
		return ""
	}
	d := refs.Domains[idx]
	if d == nil || d.Name == nil {
		return ""
	}
	return d.Name.Buffer
}

func qualify(domain, name string) string {
	if domain != "" && name != "" {
		return domain + "\\" + name
	}
	return name
}

var lookupSidsCmd = &Command{
	Name:  "lookupsids",
	Usage: "lookupsids <sid> [sid...]",
	Help:  "Translate one or more SIDs to account names (LSAT).",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("usage: lookupsids <sid> [sid...]")
		}
		sids := make([]*dtyp.SID, 0, len(args))
		for _, a := range args {
			sid, err := dtyp.ParseSID(a)
			if err != nil {
				return fmt.Errorf("invalid sid %q: %w", a, err)
			}
			sids = append(sids, sid)
		}
		resp, err := resolveSIDs(s, sids)
		if err != nil {
			return err
		}
		rows := [][]string{}
		for i, sid := range sids {
			name, use := "<unmapped>", ""
			if resp.TranslatedNames != nil && i < len(resp.TranslatedNames.Names) {
				tn := resp.TranslatedNames.Names[i]
				if tn != nil && tn.Name != nil && tn.Name.Buffer != "" {
					name = qualify(domainName(resp.ReferencedDomains, tn.DomainIndex), tn.Name.Buffer)
					use = useName(tn.Use)
				}
			}
			rows = append(rows, []string{sid.String(), name, use})
		}
		out.Table([]string{"SID", "Name", "Type"}, rows)
		return nil
	},
}

var lookupNamesCmd = &Command{
	Name:  "lookupnames",
	Usage: "lookupnames <name> [name...]",
	Help:  "Translate one or more account names to SIDs (LSAT).",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("usage: lookupnames <name> [name...]")
		}
		cli, pol, err := s.LSAT()
		if err != nil {
			return err
		}
		names := make([]*dtyp.UnicodeString, 0, len(args))
		for _, a := range args {
			names = append(names, &dtyp.UnicodeString{Buffer: a})
		}
		resp, err := cli.LookupNames(s.Context(), &lsat.LookupNamesRequest{
			Policy:      pol,
			Count:       uint32(len(names)),
			Names:       names,
			LookupLevel: lsat.LookupLevelWorkstation,
		})
		if err != nil {
			return err
		}
		rows := [][]string{}
		for i, a := range args {
			sidStr, use := "<unmapped>", ""
			if resp.TranslatedSIDs != nil && i < len(resp.TranslatedSIDs.SIDs) {
				ts := resp.TranslatedSIDs.SIDs[i]
				if ts != nil && ts.Use != lsat.SIDNameUseTypeUnknown {
					use = useName(ts.Use)
					if dsid := domainSID(resp.ReferencedDomains, ts.DomainIndex); dsid != nil {
						sidStr = dsid.AddRelativeID(ts.RelativeID).String()
					}
				}
			}
			rows = append(rows, []string{a, sidStr, use})
		}
		out.Table([]string{"Name", "SID", "Type"}, rows)
		return nil
	},
}

func domainSID(refs *lsat.ReferencedDomainList, idx int32) *dtyp.SID {
	if refs == nil || idx < 0 || int(idx) >= len(refs.Domains) {
		return nil
	}
	d := refs.Domains[idx]
	if d == nil {
		return nil
	}
	return d.SID
}

// RIDResult is a single resolved principal from a RID-cycling sweep.
type RIDResult struct {
	RID  uint32
	Name string
	Use  lsat.SIDNameUse
}

// CycleRIDs resolves every RID in [start,end] against the active domain SID via
// LSAT and returns the ones that map to a real principal.
func CycleRIDs(s *session.Session, start, end uint32) ([]RIDResult, error) {
	d, ok := currentDomainSID(s)
	if !ok {
		return nil, fmt.Errorf("no domain selected")
	}
	const batch = 128
	var results []RIDResult
	for lo := start; lo <= end; lo += batch {
		hi := lo + batch - 1
		if hi > end || hi < lo { // clamp and guard uint32 wrap
			hi = end
		}
		sids := make([]*dtyp.SID, 0, batch)
		rids := make([]uint32, 0, batch)
		for rid := lo; rid <= hi; rid++ {
			sids = append(sids, d.AddRelativeID(rid))
			rids = append(rids, rid)
			if rid == hi {
				break
			}
		}
		resp, err := resolveSIDs(s, sids)
		if err != nil {
			return nil, err
		}
		if resp.TranslatedNames != nil {
			for i := range sids {
				if i >= len(resp.TranslatedNames.Names) {
					break
				}
				tn := resp.TranslatedNames.Names[i]
				if tn == nil || tn.Name == nil || tn.Name.Buffer == "" {
					continue
				}
				results = append(results, RIDResult{
					RID:  rids[i],
					Name: qualify(domainName(resp.ReferencedDomains, tn.DomainIndex), tn.Name.Buffer),
					Use:  tn.Use,
				})
			}
		}
		if hi == end {
			break
		}
	}
	return results, nil
}

var ridCycleCmd = &Command{
	Name:  "ridcycle",
	Usage: "ridcycle [start] [end]",
	Help:  "Brute-force RIDs against the active domain SID and resolve them via LSAT (default 500-1100).",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		start, end := uint64(500), uint64(1100)
		var err error
		if len(args) >= 1 {
			if start, err = strconv.ParseUint(args[0], 10, 32); err != nil {
				return fmt.Errorf("invalid start rid %q", args[0])
			}
		}
		if len(args) >= 2 {
			if end, err = strconv.ParseUint(args[1], 10, 32); err != nil {
				return fmt.Errorf("invalid end rid %q", args[1])
			}
		}
		if end < start {
			return fmt.Errorf("end rid must be >= start rid")
		}

		results, err := CycleRIDs(s, uint32(start), uint32(end))
		if err != nil {
			return err
		}
		rows := make([][]string, 0, len(results))
		for _, r := range results {
			rows = append(rows, []string{
				strconv.FormatUint(uint64(r.RID), 10),
				r.Name,
				useName(r.Use),
			})
		}
		out.Table([]string{"RID", "Name", "Type"}, rows)
		return nil
	},
}

func currentDomainSID(s *session.Session) (*dtyp.SID, bool) {
	for _, d := range s.Domains() {
		if d.Name == s.CurrentDomain() {
			return d.SID, true
		}
	}
	return nil, false
}

// useName renders a SID_NAME_USE without the verbose "SIDNameUseType" prefix.
func useName(u lsat.SIDNameUse) string {
	return strings.TrimPrefix(u.String(), "SIDNameUseType")
}
