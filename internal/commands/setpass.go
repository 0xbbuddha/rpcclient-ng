package commands

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/0xbbuddha/rpcclient-ng/internal/output"
	"github.com/0xbbuddha/rpcclient-ng/internal/session"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	samr "github.com/oiweiwei/go-msrpc/msrpc/samr/samr/v1"
)

// userPasswordBlob builds the 516-byte cleartext SAMPR_USER_PASSWORD: 512 bytes
// of buffer with the UTF-16LE password right-aligned at its end, followed by a
// little-endian uint32 length (in bytes). Unused space is filled with random
// bytes, per MS-SAMR 3.2.2.1.
func userPasswordBlob(password string) ([]byte, error) {
	pwd := utf16.Encode([]rune(password))
	pb := make([]byte, 2*len(pwd))
	for i, r := range pwd {
		binary.LittleEndian.PutUint16(pb[2*i:], r)
	}
	if len(pb) > 512 {
		return nil, fmt.Errorf("password too long (%d bytes encoded, max 512)", len(pb))
	}
	blob := make([]byte, 516)
	if _, err := rand.Read(blob[:512]); err != nil {
		return nil, err
	}
	copy(blob[512-len(pb):512], pb)
	binary.LittleEndian.PutUint32(blob[512:], uint32(len(pb)))
	return blob, nil
}

// rc4Clear encrypts the 516-byte cleartext password blob with RC4 under the
// given key.
func rc4Clear(key []byte, clear []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("rc4 key: %w", err)
	}
	ct := make([]byte, len(clear))
	c.XORKeyStream(ct, clear)
	return ct, nil
}

// encryptPasswordNew builds a SAMPR_ENCRYPTED_USER_PASSWORD_NEW buffer (532
// bytes): the 516-byte cleartext encrypted with RC4 keyed on MD5(salt ||
// sessionKey), followed by the 16-byte salt in clear (MS-SAMR 3.2.2.1).
func encryptPasswordNew(sessionKey []byte, password string) ([]byte, error) {
	clear, err := userPasswordBlob(password)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	h := md5.New()
	h.Write(salt)
	h.Write(sessionKey)
	ct, err := rc4Clear(h.Sum(nil), clear)
	if err != nil {
		return nil, err
	}
	return append(ct, salt...), nil
}

// encryptPasswordRC4 builds a SAMPR_ENCRYPTED_USER_PASSWORD buffer (516 bytes):
// the cleartext encrypted with RC4 keyed directly on the session key.
func encryptPasswordRC4(key []byte, password string) ([]byte, error) {
	clear, err := userPasswordBlob(password)
	if err != nil {
		return nil, err
	}
	return rc4Clear(key, clear)
}

// openUserForWrite resolves <rid|name> in the current domain and opens the user
// handle with maximum access.
func openUserForWrite(s *session.Session, arg string) (*samr.Handle, uint32, error) {
	h, _, err := s.OpenCurrentDomain()
	if err != nil {
		return nil, 0, err
	}
	rid, err := resolvePrincipalRID(s, h, arg)
	if err != nil {
		return nil, 0, err
	}
	open, err := s.Samr().OpenUser(s.Context(), &samr.OpenUserRequest{
		Domain:        h,
		DesiredAccess: dtyp.AccessMaskMaximumAllowed,
		UserID:        rid,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("open user %d: %w", rid, err)
	}
	return open.UserHandle, rid, nil
}

var setUserPassCmd = &Command{
	Name:    "setuserpass",
	Aliases: []string{"setpassword", "chgpasswd"},
	Usage:   "setuserpass <rid|name> <password>",
	Help:    "Set (reset) a user's password via SAMR SetInformationUser2, trying the salted buffer (level 26) then the plain one (level 24). Requires NTLM auth and a privileged account. Works against Windows DCs; Samba rejects it over a sealed connection.",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("usage: setuserpass <rid|name> <password>")
		}
		key, err := s.SessionKey()
		if err != nil {
			return err
		}
		uh, rid, err := openUserForWrite(s, args[0])
		if err != nil {
			return err
		}
		password := args[1]

		// Preferred: salted "New" buffer (level 26).
		newBlob, err := encryptPasswordNew(key, password)
		if err != nil {
			return err
		}
		_, errNew := s.Samr().SetInformationUser2(s.Context(), &samr.SetInformationUser2Request{
			UserHandle:           uh,
			UserInformationClass: samr.UserInformationClassInternal5InformationNew,
			Buffer: &samr.UserInfoBuffer{Value: &samr.UserInfoBuffer_Internal5New{
				Internal5New: &samr.UserInternal5InformationNew{
					UserPassword:    &samr.EncryptedUserPasswordNew{Buffer: newBlob},
					PasswordExpired: 0,
				},
			}},
		})
		if errNew == nil {
			out.Infof("password set for RID %d (level 26)", rid)
			return nil
		}

		// Fallback: RC4 (level 24).
		rc4Blob, err := encryptPasswordRC4(key, password)
		if err != nil {
			return err
		}
		_, errOld := s.Samr().SetInformationUser2(s.Context(), &samr.SetInformationUser2Request{
			UserHandle:           uh,
			UserInformationClass: samr.UserInformationClassInternal5Information,
			Buffer: &samr.UserInfoBuffer{Value: &samr.UserInfoBuffer_Internal5{
				Internal5: &samr.UserInternal5Information{
					UserPassword:    &samr.EncryptedUserPassword{Buffer: rc4Blob},
					PasswordExpired: 0,
				},
			}},
		})
		if errOld != nil {
			return setPassError(errNew, errOld)
		}
		out.Infof("password set for RID %d (level 24)", rid)
		return nil
	},
}

// setPassError wraps the two SetInformationUser2 failures. STATUS_WRONG_PASSWORD
// and STATUS_NO_USER_SESSION_KEY here are the signature of a server (notably
// Samba) that rejects the password buffer over a sealed RPC connection: the key
// it expects does not match the one carried on this bind. This operation is
// known to work against Windows DCs but not against Samba over a sealed bind.
func setPassError(errNew, errOld error) error {
	hint := ""
	if containsAny(errNew.Error(), "WRONG_PASSWORD", "NO_USER_SESSION_KEY") ||
		containsAny(errOld.Error(), "WRONG_PASSWORD", "NO_USER_SESSION_KEY") {
		hint = "\n  [!] the server rejected the encrypted password buffer on this sealed connection; " +
			"this path works against Windows DCs but not Samba (which needs an unsealed, SMB-authenticated bind)"
	}
	return fmt.Errorf("set password failed (level 26: %v; level 24: %v)%s", errNew, errOld, hint)
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// setAccountDisabled toggles the ACB_DISABLED bit, preserving the other
// account-control flags, and returns the user's RID and the new flag value.
func setAccountDisabled(s *session.Session, arg string, disabled bool) (uint32, uint32, error) {
	uh, rid, err := openUserForWrite(s, arg)
	if err != nil {
		return 0, 0, err
	}
	ctl, err := s.Samr().QueryInformationUser(s.Context(), &samr.QueryInformationUserRequest{
		UserHandle:           uh,
		UserInformationClass: samr.UserInformationClassControlInformation,
	})
	if err != nil {
		return 0, 0, fmt.Errorf("query control info: %w", err)
	}
	c, ok := ctl.Buffer.GetValue().(*samr.UserControlInformation)
	if !ok || c == nil {
		return 0, 0, fmt.Errorf("unexpected control payload %T", ctl.Buffer.GetValue())
	}
	flags := c.UserAccountControl
	if disabled {
		flags |= acbDisabled
	} else {
		flags &^= acbDisabled
	}
	if _, err := s.Samr().SetInformationUser2(s.Context(), &samr.SetInformationUser2Request{
		UserHandle:           uh,
		UserInformationClass: samr.UserInformationClassControlInformation,
		Buffer: &samr.UserInfoBuffer{Value: &samr.UserInfoBuffer_Control{
			Control: &samr.UserControlInformation{UserAccountControl: flags},
		}},
	}); err != nil {
		return 0, 0, fmt.Errorf("set control info: %w", err)
	}
	return rid, flags, nil
}

var enableDomUserCmd = &Command{
	Name:  "enabledomuser",
	Usage: "enabledomuser <rid|name>",
	Help:  "Enable a user account by clearing the ACB_DISABLED flag.",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: enabledomuser <rid|name>")
		}
		rid, flags, err := setAccountDisabled(s, args[0], false)
		if err != nil {
			return err
		}
		out.Infof("enabled RID %d (flags now %s)", rid, decodeACB(flags))
		return nil
	},
}

var disableDomUserCmd = &Command{
	Name:  "disabledomuser",
	Usage: "disabledomuser <rid|name>",
	Help:  "Disable a user account by setting the ACB_DISABLED flag.",
	Run: func(s *session.Session, out *output.Printer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: disabledomuser <rid|name>")
		}
		rid, flags, err := setAccountDisabled(s, args[0], true)
		if err != nil {
			return err
		}
		out.Infof("disabled RID %d (flags now %s)", rid, decodeACB(flags))
		return nil
	},
}
