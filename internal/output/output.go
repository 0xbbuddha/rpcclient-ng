package output

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
)

// Printer renders command output either as aligned tables or as JSON.
type Printer struct {
	JSON bool
}

// New returns a printer in the given mode.
func New(jsonMode bool) *Printer { return &Printer{JSON: jsonMode} }

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

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	for i, h := range headers {
		if i > 0 {
			fmt.Fprint(tw, "\t")
		}
		fmt.Fprint(tw, h)
	}
	fmt.Fprintln(tw)
	for i := range headers {
		if i > 0 {
			fmt.Fprint(tw, "\t")
		}
		fmt.Fprint(tw, "----")
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
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	for _, kv := range pairs {
		fmt.Fprintf(tw, "%s:\t%s\n", kv[0], kv[1])
	}
	tw.Flush()
}

// Infof prints an informational line (suppressed in JSON mode).
func (p *Printer) Infof(format string, a ...any) {
	if p.JSON {
		return
	}
	fmt.Printf(format+"\n", a...)
}

// Errorf prints an error line to stderr.
func (p *Printer) Errorf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}
