package commands

import (
	"fmt"
	"strconv"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	samr "github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
)

const (
	userNormalAccount = 0x00000010 // ACB_NORMAL account type for SamrCreateUser2
	groupMemberAttrs  = 0x00000007 // SE_GROUP_MANDATORY|ENABLED_BY_DEFAULT|ENABLED
)

var createDomUserCmd = &Command{
	Name:  "createdomuser",
	Usage: "createdomuser <name>",
	Help:  "Create a user account in the active domain (created disabled and without a password).",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: createdomuser <name>")
		}
		h, sid, err := s.OpenCurrentDomain()
		if err != nil {
			return err
		}
		resp, err := s.Samr().CreateUser2InDomain(s.Context(), &samr.CreateUser2InDomainRequest{
			Domain:        h,
			Name:          &dtyp.UnicodeString{Buffer: args[0]},
			AccountType:   userNormalAccount,
			DesiredAccess: dtyp.AccessMaskMaximumAllowed,
		})
		if err != nil {
			return fmt.Errorf("create user %q: %w", args[0], err)
		}
		out.KeyValues([][2]string{
			{"Created", args[0]},
			{"RID", strconv.FormatUint(uint64(resp.RelativeID), 10)},
			{"SID", sid.AddRelativeID(resp.RelativeID).String()},
			{"Note", "account is disabled and has no password until set"},
		})
		return nil
	},
}

var delDomUserCmd = &Command{
	Name:  "deldomuser",
	Usage: "deldomuser <rid|name>",
	Help:  "Delete a user account, given its RID or account name.",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: deldomuser <rid|name>")
		}
		rid, err := resolveRID(s, args[0])
		if err != nil {
			return err
		}
		h, _, err := s.OpenCurrentDomain()
		if err != nil {
			return err
		}
		open, err := s.Samr().OpenUser(s.Context(), &samr.OpenUserRequest{
			Domain:        h,
			DesiredAccess: dtyp.AccessMaskMaximumAllowed,
			UserID:        uint32(rid),
		})
		if err != nil {
			return fmt.Errorf("open user %d: %w", rid, err)
		}
		if _, err := s.Samr().DeleteUser(s.Context(), &samr.DeleteUserRequest{
			UserHandle: open.UserHandle,
		}); err != nil {
			return fmt.Errorf("delete user %d: %w", rid, err)
		}
		out.Infof("deleted user RID %d", rid)
		return nil
	},
}

// openGroupForWrite opens a group handle with write access.
func openGroupForWrite(s *session.Session, groupRID uint32) (*samr.Handle, error) {
	h, _, err := s.OpenCurrentDomain()
	if err != nil {
		return nil, err
	}
	open, err := s.Samr().OpenGroup(s.Context(), &samr.OpenGroupRequest{
		Domain:        h,
		DesiredAccess: dtyp.AccessMaskMaximumAllowed,
		GroupID:       groupRID,
	})
	if err != nil {
		return nil, fmt.Errorf("open group %d: %w", groupRID, err)
	}
	return open.GroupHandle, nil
}

var addGroupMemCmd = &Command{
	Name:  "addgroupmem",
	Usage: "addgroupmem <group-rid|name> <user-rid|name>",
	Help:  "Add a user to a domain group. Both the group and the user may be given as a RID or an account name (resolved in the current domain).",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		groupRID, userRID, err := twoAccountRIDs(s, args)
		if err != nil {
			return err
		}
		gh, err := openGroupForWrite(s, groupRID)
		if err != nil {
			return err
		}
		if _, err := s.Samr().AddMemberToGroup(s.Context(), &samr.AddMemberToGroupRequest{
			GroupHandle: gh,
			MemberID:    userRID,
			Attributes:  groupMemberAttrs,
		}); err != nil {
			return fmt.Errorf("add member: %w", err)
		}
		out.Infof("added RID %d to group RID %d", userRID, groupRID)
		return nil
	},
}

var delGroupMemCmd = &Command{
	Name:  "delgroupmem",
	Usage: "delgroupmem <group-rid|name> <user-rid|name>",
	Help:  "Remove a user from a domain group. Both the group and the user may be given as a RID or an account name (resolved in the current domain).",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		groupRID, userRID, err := twoAccountRIDs(s, args)
		if err != nil {
			return err
		}
		gh, err := openGroupForWrite(s, groupRID)
		if err != nil {
			return err
		}
		if _, err := s.Samr().RemoveMemberFromGroup(s.Context(), &samr.RemoveMemberFromGroupRequest{
			GroupHandle: gh,
			MemberID:    userRID,
		}); err != nil {
			return fmt.Errorf("remove member: %w", err)
		}
		out.Infof("removed RID %d from group RID %d", userRID, groupRID)
		return nil
	},
}

// openAlias opens an alias (local group) by RID in the current domain. Aliases
// for the well-known builtins (e.g. Administrators, RID 544) live in the
// BUILTIN domain, so `use BUILTIN` must precede the call for those.
func openAlias(s *session.Session, aliasRID uint32, access uint32) (*samr.Handle, error) {
	h, _, err := s.OpenCurrentDomain()
	if err != nil {
		return nil, err
	}
	open, err := s.Samr().OpenAlias(s.Context(), &samr.OpenAliasRequest{
		Domain:        h,
		DesiredAccess: access,
		AliasID:       aliasRID,
	})
	if err != nil {
		return nil, fmt.Errorf("open alias %d: %w", aliasRID, err)
	}
	return open.AliasHandle, nil
}

var addAliasMemCmd = &Command{
	Name:  "addaliasmem",
	Usage: "addaliasmem <alias-rid> <member-sid|rid|name>",
	Help:  "Add a member to an alias/local group (e.g. Builtin Administrators). The member may be a full SID, a bare RID (expanded against the current domain), or an account name.",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("usage: addaliasmem <alias-rid> <member-sid|rid|name>")
		}
		aliasRID, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid alias rid %q", args[0])
		}
		memberSID, err := resolveMemberSID(s, args[1])
		if err != nil {
			return err
		}
		ah, err := openAlias(s, uint32(aliasRID), dtyp.AccessMaskMaximumAllowed)
		if err != nil {
			return err
		}
		if _, err := s.Samr().AddMemberToAlias(s.Context(), &samr.AddMemberToAliasRequest{
			AliasHandle: ah,
			MemberID:    memberSID,
		}); err != nil {
			return fmt.Errorf("add alias member: %w", err)
		}
		out.Infof("added %s to alias RID %d", memberSID.String(), aliasRID)
		return nil
	},
}

var delAliasMemCmd = &Command{
	Name:  "delaliasmem",
	Usage: "delaliasmem <alias-rid> <member-sid|rid|name>",
	Help:  "Remove a member from an alias/local group. The member may be a full SID, a bare RID (expanded against the current domain), or an account name.",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("usage: delaliasmem <alias-rid> <member-sid|rid|name>")
		}
		aliasRID, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid alias rid %q", args[0])
		}
		memberSID, err := resolveMemberSID(s, args[1])
		if err != nil {
			return err
		}
		ah, err := openAlias(s, uint32(aliasRID), dtyp.AccessMaskMaximumAllowed)
		if err != nil {
			return err
		}
		if _, err := s.Samr().RemoveMemberFromAlias(s.Context(), &samr.RemoveMemberFromAliasRequest{
			AliasHandle: ah,
			MemberID:    memberSID,
		}); err != nil {
			return fmt.Errorf("remove alias member: %w", err)
		}
		out.Infof("removed %s from alias RID %d", memberSID.String(), aliasRID)
		return nil
	},
}

// twoAccountRIDs resolves a <group> <user> pair, each given as a RID or an
// account name, to their RIDs in the current domain.
func twoAccountRIDs(s *session.Session, args []string) (uint32, uint32, error) {
	if len(args) != 2 {
		return 0, 0, fmt.Errorf("usage: <group-rid|name> <user-rid|name>")
	}
	g, err := resolveRID(s, args[0])
	if err != nil {
		return 0, 0, fmt.Errorf("group %q: %w", args[0], err)
	}
	u, err := resolveRID(s, args[1])
	if err != nil {
		return 0, 0, fmt.Errorf("user %q: %w", args[1], err)
	}
	return g, u, nil
}
