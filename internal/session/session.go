package session

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/smb2"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"

	fcreds "github.com/oiweiwei/gokrb5.fork/v9/credentials"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	epm "github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	lsad "github.com/oiweiwei/go-msrpc/msrpc/lsad/lsarpc/v0"
	lsat "github.com/oiweiwei/go-msrpc/msrpc/lsat/lsarpc/v0"
	samr "github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
	srvsvc "github.com/oiweiwei/go-msrpc/msrpc/srvs/srvsvc/v3"
	wkssvc "github.com/oiweiwei/go-msrpc/msrpc/wkst/wkssvc/v1"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/ntstatus"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

// LSA policy access rights.
const (
	policyLookupNames   = 0x00000800 // POLICY_LOOKUP_NAMES
	policyViewLocalInfo = 0x00000001 // POLICY_VIEW_LOCAL_INFORMATION
)

// Config carries the connection parameters for a session.
type Config struct {
	Target      string
	Username    string
	Password    string
	NTHash      string
	Domain      string
	Seal        bool
	Kerberos    bool
	NullSession bool
	DCIP        string // network address to dial (target stays the SPN/name)
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
	wkst wkssvc.WkssvcClient

	dialExtra []dcerpc.Option // extra dial options (e.g. Kerberos SMB dialer)
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

// SessionKey returns the authentication session key negotiated during the bind,
// used to encrypt SAMR password buffers. It is populated for NTLM (password or
// pass-the-hash); Kerberos and null sessions do not expose one.
func (s *Session) SessionKey() ([]byte, error) {
	for _, attr := range []string{gssapi.AttributeSMBSessionKey, gssapi.AttributeSessionKey} {
		if v, ok := gssapi.GetAttribute(s.ctx, attr); ok {
			if key, ok := v.([]byte); ok && len(key) > 0 {
				return key, nil
			}
		}
	}
	return nil, fmt.Errorf("no session key available (password encryption needs NTLM auth; not supported for Kerberos or null sessions)")
}

// Connect sets up authentication and the security context. It does not bind any
// interface: SAMR (and the SAM domain list) is bound lazily on first use, so a
// command that needs only another interface — rpcdump over the endpoint mapper,
// LSA lookups, srvsvc shares — still works when SAMR is unreachable or denied.
func (s *Session) Connect() error {
	gssapi.AddMechanism(ssp.SPNEGO)
	switch {
	case s.cfg.NullSession:
		gssapi.AddCredential(credential.Anonymous())
		gssapi.AddMechanism(ssp.NTLM)
	case s.cfg.Kerberos:
		ccPath := ccachePath()
		if ccPath == "" {
			return fmt.Errorf("kerberos: set KRB5CCNAME to your credential cache")
		}
		cc, err := fcreds.LoadCCache(ccPath)
		if err != nil {
			return fmt.Errorf("kerberos: load ccache %q: %w", ccPath, err)
		}
		kcfg := krb5.NewConfig()
		kcfg.CCachePath = ccPath
		kcfg.DCEStyle = true // required for DCERPC over Kerberos
		gssapi.AddCredential(credential.NewFromCCacheV9(ccachePrincipal(cc), cc))
		gssapi.AddMechanism(gssapi.WithDefaultConfig(ssp.KRB5, kcfg))
		// Kerberos needs the full SMB service principal (cifs/<host>); go-msrpc
		// uses the target name verbatim as the SPN, so add the service class.
		dialer := smb2.NewDialer(smb2.WithSecurity(gssapi.WithTargetName("cifs/" + s.cfg.Target)))
		s.dialExtra = []dcerpc.Option{dcerpc.WithSMBDialer(dialer)}
	case s.cfg.NTHash != "":
		gssapi.AddCredential(credential.NewFromNTHash(s.principal(), s.cfg.NTHash))
		gssapi.AddMechanism(ssp.NTLM)
	default:
		gssapi.AddCredential(credential.NewFromPassword(s.principal(), s.cfg.Password))
		gssapi.AddMechanism(ssp.NTLM)
	}

	s.ctx = gssapi.NewSecurityContext(context.Background())
	return nil
}

// EnsureSAMR binds the SAMR interface and loads the SAM domain list on first
// use, returning any bind error so a command can surface it. It is idempotent.
func (s *Session) EnsureSAMR() error { return s.ensureSAMR() }

func (s *Session) ensureSAMR() error {
	if s.samr != nil {
		return nil
	}
	cc, err := s.dial("samr")
	if err != nil {
		return fmt.Errorf("dial samr: %w", err)
	}
	cli, err := samr.NewSamrClient(s.ctx, cc, s.secOpts()...)
	if err != nil {
		return fmt.Errorf("bind samr: %w", err)
	}
	conn, err := cli.Connect(s.ctx, &samr.ConnectRequest{
		DesiredAccess: dtyp.AccessMaskMaximumAllowed,
	})
	if err != nil {
		return fmt.Errorf("samr connect: %w", err)
	}
	s.samr = cli
	s.samrServer = conn.Server
	return s.loadDomains()
}

// EPMClient dials the endpoint mapper over ncacn_ip_tcp (TCP 135) and binds the
// EPM interface, returning the client and its connection for the caller to
// close. ept_lookup is queryable anonymously (as impacket's rpcdump does), so
// the bind is unauthenticated and works for every auth mode, null sessions
// included. The transport is TCP/135, independent of the SMB named pipes the
// other interfaces use.
func (s *Session) EPMClient() (epm.EpmClient, dcerpc.Conn, error) {
	cc, err := dcerpc.Dial(s.ctx, s.dialHost(), dcerpc.WithEndpoint("ncacn_ip_tcp:[135]"))
	if err != nil {
		return nil, nil, fmt.Errorf("dial epm (tcp/135): %w", err)
	}
	cli, err := epm.NewEpmClient(s.ctx, cc, dcerpc.WithInsecure())
	if err != nil {
		cc.Close(s.ctx)
		return nil, nil, fmt.Errorf("bind epm: %w", err)
	}
	return cli, cc, nil
}

// dial opens a DCERPC connection to the given named pipe, routing through the
// Kerberos-aware SMB dialer when one is configured.
func (s *Session) dial(pipe string) (dcerpc.Conn, error) {
	opts := []dcerpc.Option{dcerpc.WithEndpoint("ncacn_np:[" + pipe + "]")}
	opts = append(opts, s.dialExtra...)
	return dcerpc.Dial(s.ctx, s.dialHost(), opts...)
}

// BindPipe dials the named pipe and binds a client through newClient, trying the
// session's security ladder (sealed then insecure). It lets commands reach MS-RPC
// interfaces the session does not wrap itself (e.g. the coercion vectors).
func (s *Session) BindPipe(pipe string, newClient func(cc dcerpc.Conn, sec ...dcerpc.Option) error) error {
	var lastErr error
	for _, sec := range s.securityAttempts() {
		cc, err := s.dial(pipe)
		if err != nil {
			lastErr = fmt.Errorf("dial %s: %w", pipe, err)
			continue
		}
		if err := newClient(cc, sec...); err != nil {
			lastErr = fmt.Errorf("bind %s: %w", pipe, err)
			continue
		}
		return nil
	}
	return lastErr
}

// dialHost is the network address to connect to: the explicit --dc-ip when set,
// otherwise the target (which also serves as the Kerberos SPN name).
func (s *Session) dialHost() string {
	if s.cfg.DCIP != "" {
		return s.cfg.DCIP
	}
	return s.cfg.Target
}

// secOpts returns the DCERPC security options for client binds. Under Kerberos,
// the sealed bind runs its own AP exchange and needs the SMB service principal.
func (s *Session) secOpts() []dcerpc.Option {
	// A null session has no session key, so it cannot seal; bind unauthenticated.
	if s.cfg.NullSession {
		return []dcerpc.Option{dcerpc.WithInsecure()}
	}
	var opts []dcerpc.Option
	if s.cfg.Seal {
		opts = append(opts, dcerpc.WithSeal())
	}
	if s.cfg.Kerberos {
		opts = append(opts, dcerpc.WithTargetName("cifs/"+s.cfg.Target))
	}
	return opts
}

// ccachePath resolves the Kerberos credential cache from KRB5CCNAME, stripping
// the optional "FILE:" prefix. go-msrpc otherwise only checks KRB5_CCACHE.
func ccachePath() string {
	return strings.TrimPrefix(os.Getenv("KRB5CCNAME"), "FILE:")
}

// ccachePrincipal returns the ccache's default client principal as user@REALM.
func ccachePrincipal(cc *fcreds.CCache) string {
	p := cc.DefaultPrincipal
	if len(p.PrincipalName.NameString) == 0 {
		return ""
	}
	return p.PrincipalName.NameString[0] + "@" + p.Realm
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
		// The final iteration (end of enumeration) can return a nil Buffer
		// alongside CountReturned == 0; guard before ranging over it.
		if resp.Buffer != nil {
			for _, d := range resp.Buffer.Buffer {
				names = append(names, d.Name.Buffer)
			}
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

// Domains returns the discovered domains, binding SAMR on first use. It is
// best-effort: on a bind error it returns whatever is loaded (nothing), leaving
// callers that need to surface the error to use EnsureSAMR.
func (s *Session) Domains() []Domain {
	_ = s.ensureSAMR()
	return s.domains
}

// CurrentDomain returns the active domain name, binding SAMR on first use
// (best-effort, so the prompt degrades to empty rather than failing).
func (s *Session) CurrentDomain() string {
	_ = s.ensureSAMR()
	return s.currentName
}

// SetCurrentDomain switches the active domain, validating it exists.
func (s *Session) SetCurrentDomain(name string) error {
	if err := s.ensureSAMR(); err != nil {
		return err
	}
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
	if err := s.ensureSAMR(); err != nil {
		return nil, nil, err
	}
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
	cc, err := s.dial("lsarpc")
	if err != nil {
		return fmt.Errorf("dial lsarpc: %w", err)
	}
	s.lsat, err = lsat.NewLsarpcClient(s.ctx, cc, s.secOpts()...)
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
	cc, err := s.dial("lsarpc")
	if err != nil {
		return fmt.Errorf("dial lsarpc (lsad): %w", err)
	}
	s.lsad, err = lsad.NewLsarpcClient(s.ctx, cc, s.secOpts()...)
	if err != nil {
		return fmt.Errorf("bind lsad: %w", err)
	}
	// Ask for everything we are entitled to first: account-rights lookups need
	// more than POLICY_VIEW_LOCAL_INFORMATION, and a server that refuses the
	// broad open still answers the narrow one used by lsaquery.
	var lastErr error
	for _, access := range []uint32{dtyp.AccessMaskMaximumAllowed, policyViewLocalInfo} {
		pol, err := s.lsad.OpenPolicy2(s.ctx, &lsad.OpenPolicy2Request{
			ObjectAttributes: &lsad.ObjectAttributes{},
			DesiredAccess:    access,
		})
		if err != nil {
			lastErr = err
			continue
		}
		s.lsadPolicy = pol.Policy
		return nil
	}
	return fmt.Errorf("open policy (lsad): %w", lastErr)
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
		cc, err := s.dial("srvsvc")
		if err != nil {
			lastErr = fmt.Errorf("dial srvsvc: %w", err)
			continue
		}
		cli, err := srvsvc.NewSrvsvcClient(s.ctx, cc, sec...)
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
func (s *Session) securityAttempts() [][]dcerpc.Option {
	if s.cfg.NullSession {
		return [][]dcerpc.Option{{dcerpc.WithInsecure()}}
	}
	var krb []dcerpc.Option
	if s.cfg.Kerberos {
		krb = []dcerpc.Option{dcerpc.WithTargetName("cifs/" + s.cfg.Target)}
	}
	if s.cfg.Seal {
		return [][]dcerpc.Option{
			append([]dcerpc.Option{dcerpc.WithSeal()}, krb...),
			{dcerpc.WithInsecure()},
		}
	}
	return [][]dcerpc.Option{{dcerpc.WithInsecure()}}
}

// SRVS returns the bound Server Service client, binding on first use.
func (s *Session) SRVS() (srvsvc.SrvsvcClient, error) {
	if err := s.ensureSRVS(); err != nil {
		return nil, err
	}
	return s.srvs, nil
}

// ensureWKST lazily binds the Workstation Service (wkssvc) interface. Like
// srvsvc it may refuse a sealed bind, so reuse the same fallback ladder.
func (s *Session) ensureWKST() error {
	if s.wkst != nil {
		return nil
	}
	var lastErr error
	for _, sec := range s.securityAttempts() {
		cc, err := s.dial("wkssvc")
		if err != nil {
			lastErr = fmt.Errorf("dial wkssvc: %w", err)
			continue
		}
		cli, err := wkssvc.NewWkssvcClient(s.ctx, cc, sec...)
		if err != nil {
			lastErr = fmt.Errorf("bind wkssvc: %w", err)
			continue
		}
		s.wkst = cli
		return nil
	}
	return lastErr
}

// WKST returns the bound Workstation Service client, binding on first use.
func (s *Session) WKST() (wkssvc.WkssvcClient, error) {
	if err := s.ensureWKST(); err != nil {
		return nil, err
	}
	return s.wkst, nil
}
