package shell

import (
	"fmt"
	"io"
	"strings"

	"github.com/chzyer/readline"

	"github.com/0xbbuddha/rpcclient-ng/internal/commands"
	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"
)

// Shell is the interactive REPL over a connected session.
type Shell struct {
	sess *session.Session
	reg  *commands.Registry
	out  *output.Printer
}

// New builds a shell for the given session.
func New(sess *session.Session, out *output.Printer) *Shell {
	return &Shell{sess: sess, reg: commands.NewRegistry(), out: out}
}

// RunCommand executes a single command by name (used for -c one-shot mode).
func RunCommand(sess *session.Session, out *output.Printer, name string, args []string) error {
	reg := commands.NewRegistry()
	cmd, ok := reg.Lookup(name)
	if !ok {
		return fmt.Errorf("unknown command: %s", name)
	}
	return cmd.Run(sess, out, args)
}

func (sh *Shell) completer() *readline.PrefixCompleter {
	items := make([]readline.PrefixCompleterInterface, 0)
	for _, name := range sh.reg.Names() {
		items = append(items, readline.PcItem(name))
	}
	return readline.NewPrefixCompleter(items...)
}

func (sh *Shell) prompt() string {
	dom := sh.sess.CurrentDomain()
	if dom == "" {
		dom = sh.sess.Config().Target
	}
	return fmt.Sprintf("rpcclient-ng (%s)> ", dom)
}

// Run starts the read-eval-print loop until EOF or an exit command.
func (sh *Shell) Run() error {
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          sh.prompt(),
		AutoComplete:    sh.completer(),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		HistoryFile:     "",
	})
	if err != nil {
		return err
	}
	defer rl.Close()

	for {
		rl.SetPrompt(sh.prompt())
		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			continue
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name, args := fields[0], fields[1:]

		switch name {
		case "exit", "quit":
			return nil
		}

		cmd, ok := sh.reg.Lookup(name)
		if !ok {
			sh.out.Errorf("unknown command: %s (try 'help')", name)
			continue
		}
		if err := cmd.Run(sh.sess, sh.out, args); err != nil {
			sh.out.Errorf("%s: %v", name, err)
		}
	}
}
