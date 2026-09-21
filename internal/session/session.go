package session

import (
	"context"
	"fmt"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	lsad "github.com/oiweiwei/go-msrpc/msrpc/lsad/lsarpc/v0"
	lsat "github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
	samr "github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
	srvsvc "github.com/oiweiwei/go-msrpc/msrpc/srvs/srvsvc/v3"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
)

// LSA policy access rights.
const (
	policyLookupNames   = 0x00000800 // POLICY_LOOKUP_NAMES
	policyViewLocalInfo = 0x00000001 // POLICY_VIEW_LOCAL_INFORMATION
)

// Config carries the connection parameters for a session.
type Config struct {
	Target   string
	Username string
	Password string
	NTHash   string
	Domain   string
	Seal     bool
}

// Domain is a discovered SAM domain and its SID.
type Domain struct {
	Name string
	SID  *dtyp.SID
}

// Session holds the live RPC clients and cached handles for a target.
type Session struct {
	cfg Config
	ctx context.Context

	samr        samr.SamrClient
	samrServer  *samr.Handle
	domains     []Domain
	domainH     map[string]*samr.Handle // domain name -> open handle
	currentName string

	lsat       lsat.LsarpcClient
	lsatPolicy *lsat.Handle

	lsad       lsad.LsarpcClient
	lsadPolicy *lsad.Handle

	srvs srvsvc.SrvsvcClient
}

// New builds a session from the given config.
func New(cfg Config) *Session {
	return &Session{cfg: cfg, domainH: map[string]*samr.Handle{}}
}

// Config returns the session configuration.
func (s *Session) Config() Config { return s.cfg }

// Samr exposes the raw SAMR client.
func (s *Session) Samr() samr.SamrClient { return s.samr }

// Context returns the security context.
func (s *Session) Context() context.Context { return s.ctx }

// Connect authenticates and binds the SAMR interface.
func (s *Session) Connect() error {
	var cred any
	switch {
	case s.cfg.NTHash != "":
		cred = credential.NewFromNTHash(s.principal(), s.cfg.NTHash)
	default:
		cred = credential.NewFromPassword(s.principal(), s.cfg.Password)
	}

	gssapi.AddCredential(cred)
	gssapi.AddMechanism(ssp.SPNEGO)
	gssapi.AddMechanism(ssp.NTLM)

	s.ctx = gssapi.NewSecurityContext(context.Background())

	opts := []dcerpc.Option{}
	if s.cfg.Seal {
		opts = append(opts, dcerpc.WithSeal())
	}

	cc, err := dcerpc.Dial(s.ctx, s.cfg.Target, dcerpc.WithEndpoint("ncacn_np:[samr]"))
	if err != nil {
		return fmt.Errorf("dial samr: %w", err)
	}

	s.samr, err = samr.NewSamrClient(s.ctx, cc, opts...)
	if err != nil {
		return fmt.Errorf("bind samr: %w", err)
	}

	conn, err := s.samr.Connect(s.ctx, &samr.ConnectRequest{
		DesiredAccess: dtyp.AccessMaskMaximumAllowed,
	})
	if err != nil {
		return fmt.Errorf("samr connect: %w", err)
	}
	s.samrServer = conn.Server

	return s.loadDomains()
}

func (s *Session) principal() string {
	if s.cfg.Domain != "" {
		return s.cfg.Domain + "\\" + s.cfg.Username
	}
	return s.cfg.Username
}

// loadDomains enumerates the SAM domains and resolves their SIDs.
func (s *Session) loadDomains() error {
	var names []string
	for enum := uint32(0); ; {
		resp, err := s.samr.EnumerateDomainsInSAMServer(s.ctx, &samr.EnumerateDomainsInSAMServerRequest{
			Server:             s.samrServer,
			EnumerationContext: enum,
		})
		if err != nil {
			return fmt.Errorf("enumerate domains: %w", err)
		}
		for _, d := range resp.Buffer.Buffer {
			names = append(names, d.Name.Buffer)
		}
		if enum = resp.EnumerationContext; enum == 0 || resp.CountReturned == 0 {
			break
		}
	}

	s.domains = s.domains[:0]
	for _, name := range names {
		resp, err := s.samr.LookupDomainInSAMServer(s.ctx, &samr.LookupDomainInSAMServerRequest{
			Server: s.samrServer,
			Name:   &dtyp.UnicodeString{Buffer: name},
		})
		if err != nil {
			return fmt.Errorf("lookup domain %q: %w", name, err)
		}
		s.domains = append(s.domains, Domain{Name: name, SID: resp.DomainID})
	}

	// Default the "current" domain to the first non-Builtin one.
	for _, d := range s.domains {
		if d.Name != "Builtin" {
			s.currentName = d.Name
			break
		}
	}
	if s.currentName == "" && len(s.domains) > 0 {
		s.currentName = s.domains[0].Name
	}
	return nil
}

// Domains returns the discovered domains.
func (s *Session) Domains() []Domain { return s.domains }

// CurrentDomain returns the active domain name.
func (s *Session) CurrentDomain() string { return s.currentName }

// SetCurrentDomain switches the active domain, validating it exists.
func (s *Session) SetCurrentDomain(name string) error {
	for _, d := range s.domains {
		if d.Name == name {
			s.currentName = name
			return nil
		}
	}
	return fmt.Errorf("unknown domain %q", name)
}

func (s *Session) lookupDomain(name string) (Domain, bool) {
	for _, d := range s.domains {
		if d.Name == name {
			return d, true
		}
	}
	return Domain{}, false
}

// OpenCurrentDomain returns an open handle to the active domain, caching it.
func (s *Session) OpenCurrentDomain() (*samr.Handle, *dtyp.SID, error) {
	d, ok := s.lookupDomain(s.currentName)
	if !ok {
		return nil, nil, fmt.Errorf("no domain selected")
	}
	if h, ok := s.domainH[d.Name]; ok {
		return h, d.SID, nil
	}
	resp, err := s.samr.OpenDomain(s.ctx, &samr.OpenDomainRequest{
		Server:        s.samrServer,
		DesiredAccess: dtyp.AccessMaskMaximumAllowed,
		DomainID:      d.SID,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("open domain %q: %w", d.Name, err)
	}
	s.domainH[d.Name] = resp.Domain
	return resp.Domain, d.SID, nil
}

// ensureLSAT lazily binds the LSA lookup interface.
func (s *Session) ensureLSAT() error {
	if s.lsat != nil {
		return nil
	}
	opts := []dcerpc.Option{}
	if s.cfg.Seal {
		opts = append(opts, dcerpc.WithSeal())
	}
	cc, err := dcerpc.Dial(s.ctx, s.cfg.Target, dcerpc.WithEndpoint("ncacn_np:[lsarpc]"))
	if err != nil {
		return fmt.Errorf("dial lsarpc: %w", err)
	}
	s.lsat, err = lsat.NewLsarpcClient(s.ctx, cc, opts...)
	if err != nil {
		return fmt.Errorf("bind lsarpc: %w", err)
	}
	pol, err := s.lsat.OpenPolicy2(s.ctx, &lsat.OpenPolicy2Request{
		ObjectAttributes: &lsat.ObjectAttributes{},
		DesiredAccess:    policyLookupNames,
	})
	if err != nil {
		return fmt.Errorf("open policy: %w", err)
	}
	s.lsatPolicy = pol.Policy
	return nil
}

// LSAT returns the bound LSA client and policy handle, binding on first use.
func (s *Session) LSAT() (lsat.LsarpcClient, *lsat.Handle, error) {
	if err := s.ensureLSAT(); err != nil {
		return nil, nil, err
	}
	return s.lsat, s.lsatPolicy, nil
}

// ensureLSAD lazily binds the LSA policy (lsad) interface for policy queries.
func (s *Session) ensureLSAD() error {
	if s.lsad != nil {
		return nil
	}
	opts := []dcerpc.Option{}
	if s.cfg.Seal {
		opts = append(opts, dcerpc.WithSeal())
	}
	cc, err := dcerpc.Dial(s.ctx, s.cfg.Target, dcerpc.WithEndpoint("ncacn_np:[lsarpc]"))
	if err != nil {
		return fmt.Errorf("dial lsarpc (lsad): %w", err)
	}
	s.lsad, err = lsad.NewLsarpcClient(s.ctx, cc, opts...)
	if err != nil {
		return fmt.Errorf("bind lsad: %w", err)
	}
	pol, err := s.lsad.OpenPolicy2(s.ctx, &lsad.OpenPolicy2Request{
		ObjectAttributes: &lsad.ObjectAttributes{},
		DesiredAccess:    policyViewLocalInfo,
	})
	if err != nil {
		return fmt.Errorf("open policy (lsad): %w", err)
	}
	s.lsadPolicy = pol.Policy
	return nil
}

// LSAD returns the bound LSA policy client and handle, binding on first use.
func (s *Session) LSAD() (lsad.LsarpcClient, *lsad.Handle, error) {
	if err := s.ensureLSAD(); err != nil {
		return nil, nil, err
	}
	return s.lsad, s.lsadPolicy, nil
}

// ensureSRVS lazily binds the Server Service (srvsvc) interface. Some srvsvc
// endpoints reject DCERPC-level sealing (the SMB session already authenticates
// the pipe), so fall back to an insecure bind on a bind failure.
func (s *Session) ensureSRVS() error {
	if s.srvs != nil {
		return nil
	}
	var lastErr error
	for _, sec := range s.securityAttempts() {
		cc, err := dcerpc.Dial(s.ctx, s.cfg.Target, dcerpc.WithEndpoint("ncacn_np:[srvsvc]"))
		if err != nil {
			lastErr = fmt.Errorf("dial srvsvc: %w", err)
			continue
		}
		cli, err := srvsvc.NewSrvsvcClient(s.ctx, cc, sec)
		if err != nil {
			lastErr = fmt.Errorf("bind srvsvc: %w", err)
			continue
		}
		s.srvs = cli
		return nil
	}
	return lastErr
}

// securityAttempts lists the DCERPC security options to try, in order. Sealing
// is preferred when enabled, with an insecure bind as a fallback.
func (s *Session) securityAttempts() []dcerpc.Option {
	if s.cfg.Seal {
		return []dcerpc.Option{dcerpc.WithSeal(), dcerpc.WithInsecure()}
	}
	return []dcerpc.Option{dcerpc.WithInsecure()}
}

// SRVS returns the bound Server Service client, binding on first use.
func (s *Session) SRVS() (srvsvc.SrvsvcClient, error) {
	if err := s.ensureSRVS(); err != nil {
		return nil, err
	}
	return s.srvs, nil
}
