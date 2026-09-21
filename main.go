package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"
	"github.com/0xbbuddha/rpcclient-ng/internal/shell"
)

const banner = `rpcclient-ng - a modern MS-RPC (SAMR/LSAT) client for Active Directory`

func main() {
	var (
		user    = flag.String("u", "", "username")
		pass    = flag.String("p", "", "password")
		hash    = flag.String("H", "", "NT hash for pass-the-hash (LM:NT or NT)")
		domain  = flag.String("d", "", "domain (NetBIOS or FQDN)")
		kerb    = flag.Bool("k", false, "use Kerberos auth from ccache (KRB5CCNAME); target must be the FQDN")
		noSeal  = flag.Bool("no-seal", false, "disable packet privacy (sealing)")
		asJSON  = flag.Bool("json", false, "emit output as JSON")
		oneShot = flag.String("c", "", "run a single command then exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n\nUsage: %s [flags] <target>\n\nFlags:\n", banner, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	target := flag.Arg(0)

	cfg := session.Config{
		Target:   target,
		Username: *user,
		Password: *pass,
		NTHash:   normalizeHash(*hash),
		Domain:   *domain,
		Seal:     !*noSeal,
		Kerberos: *kerb,
	}

	out := output.New(*asJSON)

	sess := session.New(cfg)
	if err := sess.Connect(); err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	out.Infof("%s", banner)
	out.Infof("connected to %s (domain: %s)", target, sess.CurrentDomain())

	if *oneShot != "" {
		if fields := strings.Fields(*oneShot); len(fields) > 0 {
			if err := shell.RunCommand(sess, out, fields[0], fields[1:]); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		return
	}

	if err := shell.New(sess, out).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "shell:", err)
		os.Exit(1)
	}
}

// normalizeHash accepts "LM:NT" or a bare NT hash and returns the NT portion.
func normalizeHash(h string) string {
	if h == "" {
		return ""
	}
	if i := strings.IndexByte(h, ':'); i >= 0 {
		return h[i+1:]
	}
	return h
}
