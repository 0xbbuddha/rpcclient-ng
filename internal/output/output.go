package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/mattn/go-isatty"
)

// ANSI SGR codes for the structural coloring applied to human-readable output.
const (
	cHeader = "1;36" // bold cyan
	cSep    = "2"    // dim
	cKey    = "36"   // cyan
	cInfo   = "33"   // yellow
	cError  = "31"   // red
	cOK     = "32"   // green
	cRID    = "1;35" // bold magenta
)

// riskyFlags are the account-control tags an attacker cares about; painted red
// when a Flags value is rendered.
var riskyFlags = map[string]bool{
	"DISABLED": true, "LOCKED": true, "PASSWD_NOT_REQD": true,
	"PWD_NEVER_EXPIRES": true, "PWD_EXPIRED": true, "AS-REP_ROASTABLE": true,
	"DES_ONLY": true, "TRUSTED_FOR_DELEG": true, "CONSTRAINED_DELEG": true,
}

// wellKnownRIDs are built-in privileged RIDs highlighted wherever they appear
// (Administrator, krbtgt, Domain/Enterprise/Schema Admins, builtin admins, ...).
var wellKnownRIDs = map[string]bool{
	"500": true, "502": true, "512": true, "516": true, "518": true,
	"519": true, "520": true, "544": true, "548": true, "549": true,
	"550": true, "551": true,
}

// esc brackets non-printing text so tabwriter (with StripEscape) ignores its
// width; without it, ANSI codes would misalign every column.
const esc = "\xff"

// Printer renders command output either as aligned tables or as JSON.
type Printer struct {
	JSON     bool
	color    bool // stdout is a color terminal
	colorErr bool // stderr is a color terminal
}

// New returns a printer in the given mode. Color is enabled per-stream only for
// a terminal (never in JSON mode, piped output, or when NO_COLOR is set).
func New(jsonMode bool) *Printer {
	on := !jsonMode && os.Getenv("NO_COLOR") == ""
	return &Printer{
		JSON:     jsonMode,
		color:    on && isatty.IsTerminal(os.Stdout.Fd()),
		colorErr: on && isatty.IsTerminal(os.Stderr.Fd()),
	}
}

// paint wraps s in an ANSI color for plain (non-tabwriter) output.
func (p *Printer) paint(code, s string) string {
	if !p.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// tpaint is paint for tabwriter cells: the color codes are bracketed with esc
// so they don't count toward column width.
func (p *Printer) tpaint(code, s string) string {
	if !p.color {
		return s
	}
	return esc + "\x1b[" + code + "m" + esc + s + esc + "\x1b[0m" + esc
}

func (p *Printer) tw() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', tabwriter.StripEscape)
}

// Table prints headers and rows aligned in columns. In JSON mode it emits an
// array of objects keyed by the (lowercased) headers instead.
func (p *Printer) Table(headers []string, rows [][]string) {
	if p.JSON {
		objs := make([]map[string]string, 0, len(rows))
		for _, row := range rows {
			obj := map[string]string{}
			for i, h := range headers {
				if i < len(row) {
					obj[h] = row[i]
				}
			}
			objs = append(objs, obj)
		}
		p.JSONValue(objs)
		return
	}

	tw := p.tw()
	for i, h := range headers {
		if i > 0 {
			fmt.Fprint(tw, "\t")
		}
		fmt.Fprint(tw, p.tpaint(cHeader, h))
	}
	fmt.Fprintln(tw)
	for i := range headers {
		if i > 0 {
			fmt.Fprint(tw, "\t")
		}
		fmt.Fprint(tw, p.tpaint(cSep, "----"))
	}
	fmt.Fprintln(tw)
	for _, row := range rows {
		for i := range headers {
			if i > 0 {
				fmt.Fprint(tw, "\t")
			}
			if i < len(row) {
				fmt.Fprint(tw, row[i])
			}
		}
		fmt.Fprintln(tw)
	}
	tw.Flush()
}

// JSONValue pretty-prints an arbitrary value as JSON.
func (p *Printer) JSONValue(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "json error:", err)
		return
	}
	fmt.Println(string(b))
}

// KeyValues prints a set of key/value pairs (record detail view).
func (p *Printer) KeyValues(pairs [][2]string) {
	if p.JSON {
		obj := map[string]string{}
		for _, kv := range pairs {
			obj[kv[0]] = kv[1]
		}
		p.JSONValue(obj)
		return
	}
	tw := p.tw()
	for _, kv := range pairs {
		fmt.Fprintf(tw, "%s:\t%s\n", p.tpaint(cKey, kv[0]), kv[1])
	}
	tw.Flush()
}

// Infof prints an informational line (suppressed in JSON mode).
func (p *Printer) Infof(format string, a ...any) {
	if p.JSON {
		return
	}
	fmt.Println(p.paint(cInfo, fmt.Sprintf(format, a...)))
}

// Flags paints known risky account-control tags red within a comma-separated
// flag string, for display in a table/KV cell (alignment preserved). Plain
// passthrough when color is off.
func (p *Printer) Flags(s string) string {
	if !p.color || s == "" {
		return s
	}
	parts := strings.Split(s, ",")
	for i, t := range parts {
		if riskyFlags[t] {
			parts[i] = p.tpaint(cError, t)
		}
	}
	return strings.Join(parts, ",")
}

// RID highlights a well-known privileged RID for a table/KV cell.
func (p *Printer) RID(s string) string {
	if !p.color || !wellKnownRIDs[s] {
		return s
	}
	return p.tpaint(cRID, s)
}

// Okf prints a success line (green, suppressed in JSON mode).
func (p *Printer) Okf(format string, a ...any) {
	if p.JSON {
		return
	}
	fmt.Println(p.paint(cOK, fmt.Sprintf(format, a...)))
}

// Section prints a section header (cyan, suppressed in JSON mode).
func (p *Printer) Section(format string, a ...any) {
	if p.JSON {
		return
	}
	fmt.Println(p.paint(cHeader, fmt.Sprintf(format, a...)))
}

// Dangerf prints a high-risk finding line (red, suppressed in JSON mode).
func (p *Printer) Dangerf(format string, a ...any) {
	if p.JSON {
		return
	}
	fmt.Println(p.paint(cError, fmt.Sprintf(format, a...)))
}

// Errorf prints an error line to stderr.
func (p *Printer) Errorf(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	if p.colorErr {
		s = "\x1b[" + cError + "m" + s + "\x1b[0m"
	}
	fmt.Fprintln(os.Stderr, s)
}
