package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hamedsanaei/openvpn-go/internal/testkit"
)

func TestInspectProfile(t *testing.T) {
	pki := testkit.NewPKI(t)
	head := "client\ndev tun\nremote sensitive-marker.test\nremote-random\nverb 3\n"
	text := head + fmt.Sprintf("<ca>\n%s</ca>\n<cert>\n%s</cert>\n<key>\n%s</key>\n",
		pki.CA, pki.Client.Certificate, pki.Client.PrivateKey)
	stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
	if code := run([]string{"-"}, strings.NewReader(text), stdout, stderr); code != 0 ||
		!strings.Contains(stdout.String(), "Remotes: 1") || !strings.Contains(stderr.String(), "ignored_directive (verb)") {
		t.Fatalf("inspect valid profile failed with exit %d, stdout %q and stderr %q", code, stdout, stderr)
	}
	if strings.Contains(stdout.String()+stderr.String(), "sensitive-marker") {
		t.Fatal("inspection exposed profile input")
	}

	root := t.TempDir()
	for name, data := range map[string][]byte{
		"ca": pki.CA, "cert": pki.Client.Certificate, "key": pki.Client.PrivateKey,
		"profile": []byte(head + "ca ca\ncert cert\nkey key\n"),
	} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "profile")
	if code := run([]string{path}, nil, stdout, stderr); code != 1 ||
		!strings.Contains(stderr.String(), "file_unavailable (ca)") {
		t.Fatalf("expected file references to require an explicit root: %d", code)
	}
	if code := run([]string{"-root", root, path}, nil, stdout, stderr); code != 0 {
		t.Fatalf("could not inspect profile with references: %d", code)
	}
}
