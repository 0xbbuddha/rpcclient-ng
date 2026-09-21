package commands

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	samr "github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
)

// SAMR account-control (ACB_*) bit flags. Note: SamrQueryDisplayInformation and
// the SAM user objects report ACB_* flags, NOT the LDAP userAccountControl bits.
const (
	acbDisabled              = 0x00000001
	acbPwNotReq              = 0x00000004
	acbNormal                = 0x00000010
	acbPwNoExp               = 0x00000200
	acbAutoLock              = 0x00000400
	acbSmartcardReq          = 0x00001000
	acbTrustedForDeleg       = 0x00002000
	acbNotDelegated          = 0x00004000
	acbUseDESKeyOnly         = 0x00008000
	acbDontReqPreauth        = 0x00010000
	acbPwExpired             = 0x00020000
	acbTrustedToAuthForDeleg = 0x00040000
)

// decodeACB renders the security-relevant account-control flags as short tags.
func decodeACB(acb uint32) string {
	var tags []string
	add := func(bit uint32, tag string) {
		if acb&bit != 0 {
			tags = append(tags, tag)
		}
	}
	add(acbDisabled, "DISABLED")
	add(acbAutoLock, "LOCKED")
	add(acbPwNotReq, "PASSWD_NOT_REQD")
	add(acbPwNoExp, "PWD_NEVER_EXPIRES")
	add(acbPwExpired, "PWD_EXPIRED")
	add(acbSmartcardReq, "SMARTCARD_REQD")
	add(acbDontReqPreauth, "AS-REP_ROASTABLE")
	add(acbUseDESKeyOnly, "DES_ONLY")
	add(acbTrustedForDeleg, "TRUSTED_FOR_DELEG")
	add(acbTrustedToAuthForDeleg, "CONSTRAINED_DELEG")
	add(acbNotDelegated, "NOT_DELEGATED")
	if len(tags) == 0 {
		return "-"
	}
	return strings.Join(tags, ",")
}

// DisplayUser is one account from SamrQueryDisplayInformation.
type DisplayUser struct {
	RID         uint32
	Name        string
	Description string
	ACB         uint32
}

// collectDisplayUsers pages through SamrQueryDisplayInformation for all users.
func collectDisplayUsers(s *session.Session) ([]DisplayUser, error) {
	h, _, err := s.OpenCurrentDomain()
	if err != nil {
		return nil, err
	}
	var users []DisplayUser
	index := uint32(0)
	for {
		resp, err := s.Samr().QueryDisplayInformation(s.Context(), &samr.QueryDisplayInformationRequest{
			Domain:                  h,
			DisplayInformationClass: samr.DomainDisplayInformationUser,
			Index:                   index,
			EntryCount:              1000,
			PreferredMaximumLength:  0xffffffff,
		})
		if err != nil {
			return nil, fmt.Errorf("query display info: %w", err)
		}
		if resp.Buffer == nil {
			break
		}
		val := resp.Buffer.GetValue()
		buf, ok := val.(*samr.DomainDisplayUserBuffer)
		if !ok {
			return nil, fmt.Errorf("unexpected display buffer arm %T", val)
		}
		if len(buf.Buffer) == 0 {
			break
		}
		for _, u := range buf.Buffer {
			users = append(users, DisplayUser{
				RID:         u.RID,
				Name:        ustr(u.AccountName),
				Description: ustr(u.AdminComment),
				ACB:         u.AccountControl,
			})
		}
		index += uint32(len(buf.Buffer))
		if uint32(len(users)) >= resp.TotalAvailable {
			break
		}
	}
	return users, nil
}

var queryDispInfoCmd = &Command{
	Name:    "querydispinfo",
	Aliases: []string{"dispinfo"},
	Usage:   "querydispinfo",
	Help:    "List users with description and decoded account-control flags (often works when enumdomusers is denied).",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		users, err := collectDisplayUsers(s)
		if err != nil {
			return err
		}
		if len(users) == 0 {
			out.Infof("[!] querydispinfo returned no entries; the DC likely restricts display info for this account; try 'enumdomusers' (LSAT fallback)")
		}
		rows := make([][]string, 0, len(users))
		for _, u := range users {
			rows = append(rows, []string{
				strconv.FormatUint(uint64(u.RID), 10),
				u.Name,
				u.Description,
				decodeACB(u.ACB),
			})
		}
		out.Table([]string{"RID", "Name", "Description", "Flags"}, rows)
		return nil
	},
}

// resolveRIDs maps a set of RIDs to account names within the given domain.
func resolveRIDs(s *session.Session, domainH *samr.Handle, rids []uint32) (map[uint32]string, error) {
	names := map[uint32]string{}
	if len(rids) == 0 {
		return names, nil
	}
	resp, err := s.Samr().LookupIDsInDomain(s.Context(), &samr.LookupIDsInDomainRequest{
		Domain:      domainH,
		Count:       uint32(len(rids)),
		RelativeIDs: rids,
	})
	if err != nil {
		return nil, fmt.Errorf("lookup rids: %w", err)
	}
	if resp.Names != nil {
		for i, rid := range rids {
			if i < len(resp.Names.Element) && resp.Names.Element[i] != nil {
				names[rid] = resp.Names.Element[i].Buffer
			}
		}
	}
	return names, nil
}

var queryGroupMemCmd = &Command{
	Name:  "querygroupmem",
	Usage: "querygroupmem <rid>",
	Help:  "List the members (RID and name) of a group.",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: querygroupmem <rid>")
		}
		rid, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid rid %q", args[0])
		}
		h, _, err := s.OpenCurrentDomain()
		if err != nil {
			return err
		}
		open, err := s.Samr().OpenGroup(s.Context(), &samr.OpenGroupRequest{
			Domain:        h,
			DesiredAccess: samrRead,
			GroupID:       uint32(rid),
		})
		if err != nil {
			return fmt.Errorf("open group %d: %w", rid, err)
		}
		mem, err := s.Samr().GetMembersInGroup(s.Context(), &samr.GetMembersInGroupRequest{
			GroupHandle: open.GroupHandle,
		})
		if err != nil {
			return fmt.Errorf("get members: %w", err)
		}
		var rids []uint32
		if mem.Members != nil {
			rids = mem.Members.Members
		}
		names, err := resolveRIDs(s, h, rids)
		if err != nil {
			return err
		}
		rows := make([][]string, 0, len(rids))
		for _, r := range rids {
			rows = append(rows, []string{strconv.FormatUint(uint64(r), 10), names[r]})
		}
		out.Table([]string{"RID", "Member"}, rows)
		return nil
	},
}

var queryUserGroupsCmd = &Command{
	Name:  "queryusergroups",
	Usage: "queryusergroups <rid>",
	Help:  "List the groups a user is a member of.",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: queryusergroups <rid>")
		}
		rid, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid rid %q", args[0])
		}
		h, _, err := s.OpenCurrentDomain()
		if err != nil {
			return err
		}
		open, err := s.Samr().OpenUser(s.Context(), &samr.OpenUserRequest{
			Domain:        h,
			DesiredAccess: samrRead,
			UserID:        uint32(rid),
		})
		if err != nil {
			return fmt.Errorf("open user %d: %w", rid, err)
		}
		g, err := s.Samr().GetGroupsForUser(s.Context(), &samr.GetGroupsForUserRequest{
			UserHandle: open.UserHandle,
		})
		if err != nil {
			return fmt.Errorf("get groups: %w", err)
		}
		var rids []uint32
		if g.Groups != nil {
			for _, gm := range g.Groups.Groups {
				rids = append(rids, gm.RelativeID)
			}
		}
		names, err := resolveRIDs(s, h, rids)
		if err != nil {
			return err
		}
		rows := make([][]string, 0, len(rids))
		for _, r := range rids {
			rows = append(rows, []string{strconv.FormatUint(uint64(r), 10), names[r]})
		}
		out.Table([]string{"RID", "Group"}, rows)
		return nil
	},
}

// resolvePrincipalRID accepts either a numeric RID or an account name and
// returns the RID, resolving names via SamrLookupNamesInDomain.
func resolvePrincipalRID(s *session.Session, domainH *samr.Handle, arg string) (uint32, error) {
	if rid, err := strconv.ParseUint(arg, 10, 32); err == nil {
		return uint32(rid), nil
	}
	resp, err := s.Samr().LookupNamesInDomain(s.Context(), &samr.LookupNamesInDomainRequest{
		Domain: domainH,
		Count:  1,
		Names:  []*dtyp.UnicodeString{{Buffer: arg}},
	})
	if err != nil {
		return 0, fmt.Errorf("lookup name %q: %w", arg, err)
	}
	if resp.RelativeIDs == nil || len(resp.RelativeIDs.Element) == 0 {
		return 0, fmt.Errorf("name %q not found", arg)
	}
	return resp.RelativeIDs.Element[0], nil
}
