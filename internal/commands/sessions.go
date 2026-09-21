package commands

import (
	"fmt"
	"time"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	srvsvc "github.com/oiweiwei/go-msrpc/msrpc/srvs/srvsvc/v3"
	wkssvc "github.com/oiweiwei/go-msrpc/msrpc/wkst/wkssvc/v1"
)

// SESS_GUEST / SESS_NOENCRYPTION user flags from MS-SRVS.
const (
	sessGuest        = 0x00000001
	sessNoEncryption = 0x00000002
	prefMaxLengthAll = 0xffffffff
	sessEnumLevel502 = 502
	sessEnumLevel10  = 10
	wkstaEnumLevel1  = 1
	wkstaEnumLevel0  = 0
)

// secs renders a MS-SRVS duration in seconds as a compact human string.
func secs(v uint32) string {
	if v == 0 {
		return "0s"
	}
	return (time.Duration(v) * time.Second).String()
}

func decodeSessFlags(f uint32) string {
	switch {
	case f&sessGuest != 0 && f&sessNoEncryption != 0:
		return "GUEST,NOENCRYPTION"
	case f&sessGuest != 0:
		return "GUEST"
	case f&sessNoEncryption != 0:
		return "NOENCRYPTION"
	case f == 0:
		return "-"
	default:
		return fmt.Sprintf("0x%x", f)
	}
}

var netSessEnumCmd = &Command{
	Name:    "netsessenum",
	Aliases: []string{"sessions", "netsessions"},
	Usage:   "netsessenum",
	Help:    "Enumerate the SMB sessions open on the target, with client, user and idle time (srvsvc NetrSessionEnum).",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		cli, err := s.SRVS()
		if err != nil {
			return err
		}

		// Level 502 carries transport and client type; fall back to the
		// less-privileged level 10 when the server refuses it.
		resp, err := cli.SessionEnum(s.Context(), &srvsvc.SessionEnumRequest{
			Info: &srvsvc.SessionEnum{
				Level: sessEnumLevel502,
				SessionInfo: &srvsvc.SessionEnumUnion{
					Value: &srvsvc.SessionEnumUnion_Level502{Level502: &srvsvc.SessionInfo502Container{}},
				},
			},
			PreferredMaximumLength: prefMaxLengthAll,
		})
		if err == nil && resp.Info != nil && resp.Info.SessionInfo != nil {
			if c, ok := resp.Info.SessionInfo.GetValue().(*srvsvc.SessionInfo502Container); ok {
				rows := make([][]string, 0, len(c.Buffer))
				for _, se := range c.Buffer {
					if se == nil {
						continue
					}
					rows = append(rows, []string{
						se.ClientName,
						se.UserName,
						fmt.Sprint(se.NumOpens),
						secs(se.Time),
						secs(se.IdleTime),
						se.ClientTypeName,
						se.Transport,
						decodeSessFlags(se.UserFlags),
					})
				}
				out.Table([]string{"Client", "User", "Opens", "Active", "Idle", "ClientType", "Transport", "Flags"}, rows)
				return nil
			}
		}
		firstErr := err

		resp10, err := cli.SessionEnum(s.Context(), &srvsvc.SessionEnumRequest{
			Info: &srvsvc.SessionEnum{
				Level: sessEnumLevel10,
				SessionInfo: &srvsvc.SessionEnumUnion{
					Value: &srvsvc.SessionEnumUnion_Level10{Level10: &srvsvc.SessionInfo10Container{}},
				},
			},
			PreferredMaximumLength: prefMaxLengthAll,
		})
		if err != nil {
			return levelErr("session enum", err, firstErr, 502)
		}
		rows := [][]string{}
		if resp10.Info != nil && resp10.Info.SessionInfo != nil {
			if c, ok := resp10.Info.SessionInfo.GetValue().(*srvsvc.SessionInfo10Container); ok {
				for _, se := range c.Buffer {
					if se == nil {
						continue
					}
					rows = append(rows, []string{se.ClientName, se.UserName, secs(se.Time), secs(se.IdleTime)})
				}
			}
		}
		out.Table([]string{"Client", "User", "Active", "Idle"}, rows)
		return nil
	},
}

var netWkstaUserEnumCmd = &Command{
	Name:    "netwkstauserenum",
	Aliases: []string{"loggedon", "wkstauser"},
	Usage:   "netwkstauserenum",
	Help:    "Enumerate the users logged on interactively at the target (wkssvc NetrWkstaUserEnum, admin-only).",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		cli, err := s.WKST()
		if err != nil {
			return err
		}

		// Level 1 adds the logon domain and server; level 0 is the fallback.
		resp, err := cli.UserEnum(s.Context(), &wkssvc.UserEnumRequest{
			UserInfo: &wkssvc.WorkstationUserEnum{
				Level: wkstaEnumLevel1,
				WorkstationUserInfo: &wkssvc.WorkstationUserEnum_WorkstationUserInfo{
					Value: &wkssvc.WorkstationUserInfo_Level1{Level1: &wkssvc.WorkstationUserInfo1Container{}},
				},
			},
			PreferredMaximumLength: prefMaxLengthAll,
		})
		if err == nil && resp.UserInfo != nil && resp.UserInfo.WorkstationUserInfo != nil {
			if c, ok := resp.UserInfo.WorkstationUserInfo.GetValue().(*wkssvc.WorkstationUserInfo1Container); ok {
				rows := make([][]string, 0, len(c.Buffer))
				for _, u := range c.Buffer {
					if u == nil {
						continue
					}
					rows = append(rows, []string{
						qualify(u.LogonDomain, u.UserName),
						u.LogonServer,
						u.OtherDomains,
					})
				}
				out.Table([]string{"User", "LogonServer", "OtherDomains"}, rows)
				return nil
			}
		}
		firstErr := err

		resp0, err := cli.UserEnum(s.Context(), &wkssvc.UserEnumRequest{
			UserInfo: &wkssvc.WorkstationUserEnum{
				Level: wkstaEnumLevel0,
				WorkstationUserInfo: &wkssvc.WorkstationUserEnum_WorkstationUserInfo{
					Value: &wkssvc.WorkstationUserInfo_Level0{Level0: &wkssvc.WorkstationUserInfo0Container{}},
				},
			},
			PreferredMaximumLength: prefMaxLengthAll,
		})
		if err != nil {
			return levelErr("wksta user enum", err, firstErr, 1)
		}
		rows := [][]string{}
		if resp0.UserInfo != nil && resp0.UserInfo.WorkstationUserInfo != nil {
			if c, ok := resp0.UserInfo.WorkstationUserInfo.GetValue().(*wkssvc.WorkstationUserInfo0Container); ok {
				for _, u := range c.Buffer {
					if u != nil {
						rows = append(rows, []string{u.UserName})
					}
				}
			}
		}
		out.Table([]string{"User"}, rows)
		return nil
	},
}

// levelErr reports a failed enumeration that was tried at two info levels. The
// higher level's error is only worth repeating when it differs from the
// fallback's, which it usually does not (both are typically access denied).
func levelErr(what string, err, higherErr error, higherLevel int) error {
	if higherErr != nil && higherErr.Error() != err.Error() {
		return fmt.Errorf("%s: %w (level %d: %v)", what, err, higherLevel, higherErr)
	}
	return fmt.Errorf("%s: %w", what, err)
}
