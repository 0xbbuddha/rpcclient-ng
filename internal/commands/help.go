package commands

import (
	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"
)

func helpCommand(r *Registry) *Command {
	return &Command{
		Name:    "help",
		Aliases: []string{"?"},
		Usage:   "help [command]",
		Help:    "List commands, or show detailed help for one command.",
		Run: func(_ *session.Session, out *output.Printer, args []string) error {
			if len(args) == 1 {
				if c, ok := r.Lookup(args[0]); ok {
					out.KeyValues([][2]string{
						{"Command", c.Name},
						{"Usage", c.Usage},
						{"Help", c.Help},
					})
					return nil
				}
			}
			rows := [][]string{}
			for _, c := range r.Commands() {
				rows = append(rows, []string{c.Usage, c.Help})
			}
			out.Table([]string{"Command", "Description"}, rows)
			return nil
		},
	}
}
