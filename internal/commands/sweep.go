package commands

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	samr "github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
	srvsvc "github.com/oiweiwei/go-msrpc/msrpc/srvs/srvsvc/v3"
)

// privilegedGroups are the account-domain RIDs worth surfacing membership for.
var privilegedGroups = []struct {
	RID  uint32
	Name string
}{
	{512, "Domain Admins"},
	{519, "Enterprise Admins"},
	{518, "Schema Admins"},
	{520, "Group Policy Creator Owners"},
	{525, "Protected Users"},
}

var driveShare = regexp.MustCompile(`^[A-Za-z]\$$`)

func isDefaultShare(name string) bool {
	switch strings.ToUpper(name) {
	case "ADMIN$", "IPC$", "PRINT$", "NETLOGON", "SYSVOL", "REMINST":
		return true
	}
	return driveShare.MatchString(name)
}

// sweepReport is the structured result emitted in JSON mode.
type sweepReport struct {
	Domain               string              `json:"domain"`
	SID                  string              `json:"sid"`
	MinPasswordLength    uint16              `json:"min_password_length"`
	PasswordComplexity   bool                `json:"password_complexity"`
	UserCount            int                 `json:"user_count"`
	ASREPRoastable       []string            `json:"asrep_roastable"`
	PasswordNotRequired  []string            `json:"password_not_required"`
	TrustedForDelegation []string            `json:"trusted_for_delegation"`
	Disabled             []string            `json:"disabled"`
	Descriptions         map[string]string   `json:"descriptions"`
	PrivilegedGroups     map[string][]string `json:"privileged_groups"`
	NonDefaultShares     []string            `json:"non_default_shares"`
}

var sweepCmd = &Command{
	Name:    "sweep",
	Aliases: []string{"audit"},
	Usage:   "sweep",
	Help:    "Run a full recon sweep and highlight high-value findings (risky accounts, privileged group members, non-default shares).",
	Run:     sweepRun,
}

func sweepRun(s *session.Session, out *output.Printer, _ []string) error {
	rep := sweepReport{
		Domain:           s.CurrentDomain(),
		Descriptions:     map[string]string{},
		PrivilegedGroups: map[string][]string{},
	}
	if sid, ok := currentDomainSID(s); ok && sid != nil {
		rep.SID = sid.String()
	}

	// Password policy (best-effort).
	if resp, err := s.Samr().GetDomainPasswordInformation(s.Context(), &samr.GetDomainPasswordInformationRequest{}); err == nil && resp.PasswordInformation != nil {
		rep.MinPasswordLength = resp.PasswordInformation.MinPasswordLength
		rep.PasswordComplexity = resp.PasswordInformation.PasswordProperties&0x1 != 0
	}

	// Users via display info, falling back to LSAT RID cycling.
	users, uerr := collectDisplayUsers(s)
	usedFallback := false
	if uerr != nil || len(users) == 0 {
		usedFallback = true
		if results, ferr := CycleRIDs(s, userFallbackStart, userFallbackEnd); ferr == nil {
			for _, r := range results {
				name := r.Name
				if i := strings.LastIndexByte(name, '\\'); i >= 0 {
					name = name[i+1:]
				}
				users = append(users, DisplayUser{RID: r.RID, Name: name})
			}
		}
	}
	rep.UserCount = len(users)
	for _, u := range users {
		if u.ACB&acbDontReqPreauth != 0 {
			rep.ASREPRoastable = append(rep.ASREPRoastable, u.Name)
		}
		if u.ACB&acbPwNotReq != 0 {
			rep.PasswordNotRequired = append(rep.PasswordNotRequired, u.Name)
		}
		if u.ACB&(acbTrustedForDeleg|acbTrustedToAuthForDeleg) != 0 {
			rep.TrustedForDelegation = append(rep.TrustedForDelegation, u.Name)
		}
		if u.ACB&acbDisabled != 0 {
			rep.Disabled = append(rep.Disabled, u.Name)
		}
		if d := strings.TrimSpace(u.Description); d != "" {
			rep.Descriptions[u.Name] = d
		}
	}

	// Privileged group membership.
	if h, _, err := s.OpenCurrentDomain(); err == nil {
		for _, g := range privilegedGroups {
			members, err := sweepGroupMembers(s, h, g.RID)
			if err != nil || len(members) == 0 {
				continue
			}
			rep.PrivilegedGroups[g.Name] = members
		}
	}

	// Non-default shares (best-effort).
	if shares, err := sweepShares(s); err == nil {
		for _, sh := range shares {
			if !isDefaultShare(sh) {
				rep.NonDefaultShares = append(rep.NonDefaultShares, sh)
			}
		}
	}

	if out.JSON {
		out.JSONValue(rep)
		return nil
	}
	renderSweep(out, rep, usedFallback)
	return nil
}

func sweepGroupMembers(s *session.Session, h *samr.Handle, rid uint32) ([]string, error) {
	open, err := s.Samr().OpenGroup(s.Context(), &samr.OpenGroupRequest{
		Domain:        h,
		DesiredAccess: samrRead,
		GroupID:       rid,
	})
	if err != nil {
		return nil, err
	}
	mem, err := s.Samr().GetMembersInGroup(s.Context(), &samr.GetMembersInGroupRequest{
		GroupHandle: open.GroupHandle,
	})
	if err != nil {
		return nil, err
	}
	var rids []uint32
	if mem.Members != nil {
		rids = mem.Members.Members
	}
	names, err := resolveRIDs(s, h, rids)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rids))
	for _, r := range rids {
		if n := names[r]; n != "" {
			out = append(out, n)
		} else {
			out = append(out, strconv.FormatUint(uint64(r), 10))
		}
	}
	return out, nil
}

func sweepShares(s *session.Session) ([]string, error) {
	cli, err := s.SRVS()
	if err != nil {
		return nil, err
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
		return nil, err
	}
	var shares []string
	if resp.Info != nil && resp.Info.ShareInfo != nil {
		if c, ok := resp.Info.ShareInfo.GetValue().(*srvsvc.ShareInfo1Container); ok {
			for _, sh := range c.Buffer {
				shares = append(shares, sh.NetworkName)
			}
		}
	}
	return shares, nil
}

func renderSweep(out *output.Printer, rep sweepReport, usedFallback bool) {
	out.Infof("== Domain ==")
	out.KeyValues([][2]string{
		{"Domain", rep.Domain},
		{"SID", rep.SID},
		{"Min password length", strconv.FormatUint(uint64(rep.MinPasswordLength), 10)},
		{"Password complexity", yesNo(rep.PasswordComplexity)},
	})

	out.Infof("\n== Users (%d) ==", rep.UserCount)
	if usedFallback {
		out.Infof("[!] display info denied; names via LSAT RID cycling (account-control flags unavailable)")
	}
	sweepList(out, "AS-REP roastable", rep.ASREPRoastable)
	sweepList(out, "Password not required", rep.PasswordNotRequired)
	sweepList(out, "Trusted for delegation", rep.TrustedForDelegation)
	if len(rep.Descriptions) > 0 {
		out.Infof("Descriptions set (check for secrets):")
		names := make([]string, 0, len(rep.Descriptions))
		for n := range rep.Descriptions {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			out.Infof("  %s: %s", n, rep.Descriptions[n])
		}
	}

	out.Infof("\n== Privileged group members ==")
	if len(rep.PrivilegedGroups) == 0 {
		out.Infof("  (none readable)")
	} else {
		for _, g := range privilegedGroups {
			if m, ok := rep.PrivilegedGroups[g.Name]; ok {
				out.Infof("  %s: %s", g.Name, strings.Join(m, ", "))
			}
		}
	}

	out.Infof("\n== Non-default shares ==")
	if len(rep.NonDefaultShares) == 0 {
		out.Infof("  (none)")
	} else {
		out.Infof("  %s", strings.Join(rep.NonDefaultShares, ", "))
	}
}

func sweepList(out *output.Printer, label string, items []string) {
	if len(items) == 0 {
		return
	}
	out.Infof("%s: %s", label, strings.Join(items, ", "))
}
