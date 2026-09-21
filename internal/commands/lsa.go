package commands

import (
	"fmt"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	lsad "github.com/oiweiwei/go-msrpc/msrpc/lsad/lsarpc/v0"
	lsat "github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
)

var getUserNameCmd = &Command{
	Name:    "getusername",
	Aliases: []string{"whoami"},
	Usage:   "getusername",
	Help:    "Show the account name and domain of the authenticated user (LSA).",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		cli, _, err := s.LSAT()
		if err != nil {
			return err
		}
		resp, err := cli.GetUserName(s.Context(), &lsat.GetUserNameRequest{})
		if err != nil {
			return fmt.Errorf("get user name: %w", err)
		}
		// LsarGetUserName often returns only the account name; fill the domain
		// from the session's discovered domain when the server omits it.
		domain := ustr(resp.DomainName)
		if domain == "" {
			domain = s.CurrentDomain()
		}
		out.KeyValues([][2]string{
			{"Domain", domain},
			{"Username", ustr(resp.UserName)},
			{"Qualified", qualify(domain, ustr(resp.UserName))},
		})
		return nil
	},
}

var lsaQueryCmd = &Command{
	Name:  "lsaquery",
	Usage: "lsaquery",
	Help:  "Query LSA policy for account and DNS domain information (name, SID, forest).",
	Run: func(s *session.Session, out *output.Printer, _ []string) error {
		cli, pol, err := s.LSAD()
		if err != nil {
			return err
		}
		pairs := [][2]string{}

		if resp, err := cli.QueryInformationPolicy2(s.Context(), &lsad.QueryInformationPolicy2Request{
			Policy:           pol,
			InformationClass: lsad.PolicyInformationClassAccountDomainInformation,
		}); err == nil && resp.PolicyInformation != nil {
			if ad, ok := resp.PolicyInformation.GetValue().(*lsad.PolicyAccountDomInfo); ok {
				pairs = append(pairs, [2]string{"Account domain", ustr(ad.DomainName)})
				if ad.DomainSID != nil {
					pairs = append(pairs, [2]string{"Account domain SID", ad.DomainSID.String()})
				}
			}
		}

		if resp, err := cli.QueryInformationPolicy2(s.Context(), &lsad.QueryInformationPolicy2Request{
			Policy:           pol,
			InformationClass: lsad.PolicyInformationClassDNSDomainInformation,
		}); err == nil && resp.PolicyInformation != nil {
			if dd, ok := resp.PolicyInformation.GetValue().(*lsad.PolicyDNSDomainInfo); ok {
				pairs = append(pairs, [2]string{"NetBIOS name", ustr(dd.Name)})
				pairs = append(pairs, [2]string{"DNS domain", ustr(dd.DNSDomainName)})
				pairs = append(pairs, [2]string{"DNS forest", ustr(dd.DNSForestName)})
				if dd.SID != nil {
					pairs = append(pairs, [2]string{"Domain SID", dd.SID.String()})
				}
			}
		}

		if len(pairs) == 0 {
			return fmt.Errorf("no policy information returned")
		}
		out.KeyValues(pairs)
		return nil
	},
}
