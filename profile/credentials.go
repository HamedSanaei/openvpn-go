package profile

import (
	"bytes"
	"io"
	"os"
	"strings"

	"github.com/hamedsanaei/openvpn-go/client"
	"github.com/hamedsanaei/openvpn-go/internal/tlscontrol"
)

// ReadCredentialsFile reads a caller-authorized regular file containing an
// OpenVPN username and password on two lines. Errors omit the path and values.
func ReadCredentialsFile(path string) (*client.Credentials, error) {
	loc := location{name: "auth-user-pass"}
	before, err := os.Stat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, loc.diagnostic(CodeFile)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|nonblockingOpen, 0)
	if err != nil {
		return nil, loc.diagnostic(CodeFile)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) {
		return nil, loc.diagnostic(CodeFile)
	}
	const maxCredentialsFile = 8194
	raw, err := io.ReadAll(io.LimitReader(f, maxCredentialsFile+1))
	defer clear(raw)
	if err != nil {
		return nil, loc.diagnostic(CodeFile)
	}
	if len(raw) > maxCredentialsFile {
		return nil, loc.diagnostic(CodeLimit)
	}
	credentials, ok := splitCredentials(raw)
	if !ok || !validCredentials(credentials) {
		return nil, loc.diagnostic(CodeMaterial)
	}
	return &credentials, nil
}

func splitCredentials(raw []byte) (client.Credentials, bool) {
	user, rest, ok := bytes.Cut(raw, []byte{'\n'})
	pass, trailing, _ := bytes.Cut(rest, []byte{'\n'})
	if !ok || len(trailing) != 0 {
		return client.Credentials{}, false
	}
	return client.Credentials{
		Username: string(bytes.TrimSuffix(user, []byte{'\r'})),
		Password: string(bytes.TrimSuffix(pass, []byte{'\r'})),
	}, true
}

func validCredentials(credentials client.Credentials) bool {
	return tlscontrol.Credentials(credentials).Validate() == nil &&
		!strings.ContainsAny(credentials.Username, "\r\n") && !strings.ContainsAny(credentials.Password, "\r\n")
}
