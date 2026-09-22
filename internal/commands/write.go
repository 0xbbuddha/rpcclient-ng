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
	Usage: "deldomuser <rid>",
	Help:  "Delete a user account by RID.",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: deldomuser <rid>")
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
	Usage: "addgroupmem <group-rid> <user-rid>",
	Help:  "Add a user (by RID) to a domain group (by RID).",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		groupRID, userRID, err := twoRIDs(args)
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
	Usage: "delgroupmem <group-rid> <user-rid>",
	Help:  "Remove a user (by RID) from a domain group (by RID).",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		groupRID, userRID, err := twoRIDs(args)
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

var addAliasMemCmd = &Command{
	Name:  "addaliasmem",
	Usage: "addaliasmem <alias-rid> <member-sid>",
	Help:  "Add a member (by full SID) to an alias/local group, e.g. Builtin Administrators.",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("usage: addaliasmem <alias-rid> <member-sid>")
		}
		aliasRID, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid alias rid %q", args[0])
		}
		memberSID, err := dtyp.ParseSID(args[1])
		if err != nil {
			return fmt.Errorf("invalid member sid %q: %w", args[1], err)
		}
		h, _, err := s.OpenCurrentDomain()
		if err != nil {
			return err
		}
		open, err := s.Samr().OpenAlias(s.Context(), &samr.OpenAliasRequest{
			Domain:        h,
			DesiredAccess: dtyp.AccessMaskMaximumAllowed,
			AliasID:       uint32(aliasRID),
		})
		if err != nil {
			return fmt.Errorf("open alias %d: %w", aliasRID, err)
		}
		if _, err := s.Samr().AddMemberToAlias(s.Context(), &samr.AddMemberToAliasRequest{
			AliasHandle: open.AliasHandle,
			MemberID:    memberSID,
		}); err != nil {
			return fmt.Errorf("add alias member: %w", err)
		}
		out.Infof("added %s to alias RID %d", memberSID.String(), aliasRID)
		return nil
	},
}

func twoRIDs(args []string) (uint32, uint32, error) {
	if len(args) != 2 {
		return 0, 0, fmt.Errorf("usage: <group-rid> <user-rid>")
	}
	g, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid group rid %q", args[0])
	}
	u, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid user rid %q", args[1])
	}
	return uint32(g), uint32(u), nil
}
