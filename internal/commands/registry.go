package commands

import (
	"sort"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"
)

// Command is a single interactive shell command.
type Command struct {
	Name    string
	Aliases []string
	Usage   string
	Help    string
	Run     func(s *session.Session, out *output.Printer, args []string) error
}

// Registry indexes commands by name and alias.
type Registry struct {
	order []*Command
	byKey map[string]*Command
}

// NewRegistry builds the full command registry.
func NewRegistry() *Registry {
	r := &Registry{byKey: map[string]*Command{}}
	for _, c := range allCommands() {
		r.add(c)
	}
	r.add(helpCommand(r))
	return r
}

func (r *Registry) add(c *Command) {
	r.order = append(r.order, c)
	r.byKey[c.Name] = c
	for _, a := range c.Aliases {
		r.byKey[a] = c
	}
}

// Lookup resolves a command by name or alias.
func (r *Registry) Lookup(name string) (*Command, bool) {
	c, ok := r.byKey[name]
	return c, ok
}

// Names returns all primary command names, sorted, for completion.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.order))
	for _, c := range r.order {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	return names
}

// Commands returns the commands in registration order.
func (r *Registry) Commands() []*Command { return r.order }

func allCommands() []*Command {
	return []*Command{
		enumDomainsCmd,
		useDomainCmd,
		enumDomUsersCmd,
		enumDomGroupsCmd,
		enumDomAliasesCmd,
		queryDispInfoCmd,
		queryUserCmd,
		queryUserGroupsCmd,
		queryGroupMemCmd,
		getDomPwInfoCmd,
		lsaQueryCmd,
		getUserNameCmd,
		netShareEnumCmd,
		lookupNamesCmd,
		lookupSidsCmd,
		ridCycleCmd,
	}
}
