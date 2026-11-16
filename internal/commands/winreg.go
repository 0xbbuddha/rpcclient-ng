package commands

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	winreg "github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
)

// registry access rights needed to read a key: query its values and list its
// subkeys.
const winregReadAccess = winreg.KeyQueryValue | winreg.KeyEnumerateSubKeys

// Buffer sizes for the out parameters of the enumeration calls: a key/value
// name and a value's data.
const (
	winregNameMax = 1024    // UTF-16 bytes for a name
	winregDataMax = 1 << 20 // 1 MiB for a value's data
)

// isNoMoreItems reports whether err is the server's end-of-enumeration marker,
// which terminates an index-based enum loop. The value is 0x103: Win32 labels
// it ERROR_NO_MORE_ITEMS, but Samba returns it as the NTSTATUS STATUS_PENDING,
// so match the shared code rather than the name.
func isNoMoreItems(err error) bool {
	return err != nil && strings.Contains(err.Error(), "0x00000103")
}

var winregQueryCmd = &Command{
	Name:    "winreg",
	Aliases: []string{"reg", "regquery"},
	Usage:   "winreg <HIVE[\\subkey]>",
	Help: "Read a remote registry key over MS-RRP: its values (name, type, data) and subkeys. " +
		"HIVE is HKLM, HKCU, HKU, HKCR or HKCC, e.g. winreg 'HKLM\\SYSTEM\\CurrentControlSet\\Control'.",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("usage: winreg <HIVE[\\subkey]>")
		}
		// Join so an unquoted path containing spaces (e.g. "Windows NT") still
		// arrives as a single key.
		path := strings.Join(args, " ")
		cli, err := s.WINREG()
		if err != nil {
			return err
		}

		rootName, subPath, _ := strings.Cut(path, "\\")
		root, err := winregOpenRoot(s, cli, rootName)
		if err != nil {
			return err
		}

		key := root
		if subPath != "" {
			open, err := cli.BaseRegOpenKey(s.Context(), &winreg.BaseRegOpenKeyRequest{
				Key:           root,
				SubKey:        &winreg.UnicodeString{Buffer: subPath + "\x00"},
				DesiredAccess: winregReadAccess,
			})
			if err != nil {
				return fmt.Errorf("open key %q: %w", subPath, err)
			}
			key = open.ResultKey
		}

		// Enumerate by index until the server reports no more items, rather
		// than relying on BaseRegQueryInfoKey (Samba's response trips the NDR
		// decoder with RPC_X_BAD_STUB_DATA). Fixed buffers size the out values.
		var subkeys []string
		for i := uint32(0); ; i++ {
			sub, err := cli.BaseRegEnumKey(s.Context(), &winreg.BaseRegEnumKeyRequest{
				Key:           key,
				Index:         i,
				NameIn:        &winreg.UnicodeString{MaximumLength: winregNameMax},
				ClassIn:       &winreg.UnicodeString{MaximumLength: winregNameMax},
				LastWriteTime: &dtyp.Filetime{},
			})
			if isNoMoreItems(err) {
				break
			}
			if err != nil {
				return fmt.Errorf("enum subkey %d: %w", i, err)
			}
			subkeys = append(subkeys, strings.TrimRight(sub.NameOut.Buffer, "\x00"))
		}

		type regValue struct {
			Name string `json:"name"`
			Type string `json:"type"`
			Data string `json:"data"`
		}
		var values []regValue
		for i := uint32(0); ; i++ {
			v, err := cli.BaseRegEnumValue(s.Context(), &winreg.BaseRegEnumValueRequest{
				Key:         key,
				Index:       i,
				ValueNameIn: &winreg.UnicodeString{MaximumLength: winregNameMax},
				DataLength:  winregDataMax,
			})
			if isNoMoreItems(err) {
				break
			}
			if err != nil {
				return fmt.Errorf("enum value %d: %w", i, err)
			}
			name := strings.TrimRight(v.ValueNameOut.Buffer, "\x00")
			if name == "" {
				name = "(Default)"
			}
			values = append(values, regValue{name, winregTypeName(v.Type), winregData(v.Type, v.Data)})
		}

		if out.JSON {
			out.JSONValue(map[string]any{"key": path, "subkeys": subkeys, "values": values})
			return nil
		}

		out.Section("%s", path)
		if len(subkeys) > 0 {
			rows := make([][]string, len(subkeys))
			for i, k := range subkeys {
				rows[i] = []string{k}
			}
			out.Table([]string{"Subkey"}, rows)
		}
		if len(values) > 0 {
			rows := make([][]string, len(values))
			for i, v := range values {
				rows[i] = []string{v.Name, v.Type, v.Data}
			}
			out.Table([]string{"Value", "Type", "Data"}, rows)
		}
		if len(subkeys) == 0 && len(values) == 0 {
			out.Infof("key is empty")
		}
		return nil
	},
}

// winregOpenRoot opens the requested predefined hive and returns its handle.
func winregOpenRoot(s *session.Session, cli winreg.WinregClient, name string) (*winreg.Key, error) {
	var key *winreg.Key
	var err error
	switch strings.ToUpper(name) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		var r *winreg.OpenLocalMachineResponse
		r, err = cli.OpenLocalMachine(s.Context(), &winreg.OpenLocalMachineRequest{DesiredAccess: winregReadAccess})
		if err == nil {
			key = r.Key
		}
	case "HKCU", "HKEY_CURRENT_USER":
		var r *winreg.OpenCurrentUserResponse
		r, err = cli.OpenCurrentUser(s.Context(), &winreg.OpenCurrentUserRequest{DesiredAccess: winregReadAccess})
		if err == nil {
			key = r.Key
		}
	case "HKU", "HKEY_USERS":
		var r *winreg.OpenUsersResponse
		r, err = cli.OpenUsers(s.Context(), &winreg.OpenUsersRequest{DesiredAccess: winregReadAccess})
		if err == nil {
			key = r.Key
		}
	case "HKCR", "HKEY_CLASSES_ROOT":
		var r *winreg.OpenClassesRootResponse
		r, err = cli.OpenClassesRoot(s.Context(), &winreg.OpenClassesRootRequest{DesiredAccess: winregReadAccess})
		if err == nil {
			key = r.Key
		}
	case "HKCC", "HKEY_CURRENT_CONFIG":
		var r *winreg.OpenCurrentConfigResponse
		r, err = cli.OpenCurrentConfig(s.Context(), &winreg.OpenCurrentConfigRequest{DesiredAccess: winregReadAccess})
		if err == nil {
			key = r.Key
		}
	default:
		return nil, fmt.Errorf("unknown hive %q (use HKLM, HKCU, HKU, HKCR or HKCC)", name)
	}
	if err != nil {
		return nil, fmt.Errorf("open hive %s: %w", strings.ToUpper(name), err)
	}
	return key, nil
}

func winregTypeName(t uint32) string {
	switch t {
	case winreg.RegNone:
		return "REG_NONE"
	case winreg.RegString:
		return "REG_SZ"
	case winreg.RegExpandString:
		return "REG_EXPAND_SZ"
	case winreg.RegBinary:
		return "REG_BINARY"
	case winreg.RegDword:
		return "REG_DWORD"
	case winreg.RegDwordBigEndian:
		return "REG_DWORD_BIG_ENDIAN"
	case winreg.RegMultistring:
		return "REG_MULTI_SZ"
	case winreg.RegQword:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("0x%x", t)
	}
}

// winregData renders a value's raw bytes per its type. String types are stored
// as UTF-16LE on the wire; stripping the null bytes recovers the ASCII-range
// text without a full UTF-16 decode, which is enough for recon.
func winregData(t uint32, data []byte) string {
	switch t {
	case winreg.RegDword: // RegDwordLittleEndian shares this value
		if len(data) >= 4 {
			return fmt.Sprintf("%d", binary.LittleEndian.Uint32(data))
		}
	case winreg.RegDwordBigEndian:
		if len(data) >= 4 {
			return fmt.Sprintf("%d", binary.BigEndian.Uint32(data))
		}
	case winreg.RegQword:
		if len(data) >= 8 {
			return fmt.Sprintf("%d", binary.LittleEndian.Uint64(data))
		}
	case winreg.RegString, winreg.RegExpandString:
		return strings.ReplaceAll(string(data), "\x00", "")
	case winreg.RegMultistring:
		var parts []string
		for _, p := range strings.Split(strings.ReplaceAll(string(data), "\x00", "\n"), "\n") {
			if p != "" {
				parts = append(parts, p)
			}
		}
		return strings.Join(parts, ", ")
	case winreg.RegNone:
		return ""
	}
	return hex.EncodeToString(data)
}
